//! One-shot connectivity test for a custom outbound — "does traffic actually
//! egress through it?".
//!
//! Spins up a throwaway xray (an HTTP-proxy inbound routed to this outbound),
//! pushes the outbound over gRPC using the SAME proto builder the panel uses
//! live (`outbound_to_handler_config`) — so the test exercises the exact config
//! the panel would push, native encryption / Reality / `FinalMask` included — then
//! makes a real HTTPS request through it and reports whether it egressed, the
//! round-trip latency, and the exit IP/country, before tearing the temp xray
//! down. Nothing touches the panel's own running xray.

use std::path::Path;
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::json;
use ts_rs::TS;

use crate::models::CustomOutbound;
use crate::xray::grpc::XrayClient;
use crate::xray::orchestrator::outbound_to_handler_config;
use crate::xray::proto::xray::core::OutboundHandlerConfig;

const PROBE_TIMEOUT: Duration = Duration::from_secs(12);
/// Warm probes after the first. The DPI/TSPU filter inspects only the FIRST
/// packet of a new connection (so the cold request pays a one-time penalty);
/// reusing the keep-alive connection for a few more probes and taking the best
/// gives the real steady-state ping, the way a client app measures it.
const PING_SAMPLES: usize = 4;

#[derive(Debug, Serialize, TS)]
#[ts(export, export_to = "../../frontend/src/api/types/outbound.ts")]
pub struct OutboundTestResult {
    /// True when an HTTPS request egressed through the outbound and returned.
    pub ok: bool,
    #[ts(type = "number | null")]
    pub latency_ms: Option<u64>,
    /// Egress IP the test endpoint saw (i.e. where the outbound exits).
    pub exit_ip: Option<String>,
    /// Egress datacenter / country code (Cloudflare `loc=`).
    pub exit_loc: Option<String>,
    pub error: Option<String>,
}

impl OutboundTestResult {
    fn fail(msg: impl Into<String>) -> Self {
        Self {
            ok: false,
            latency_ms: None,
            exit_ip: None,
            exit_loc: None,
            error: Some(msg.into()),
        }
    }
}

fn free_port() -> std::io::Result<u16> {
    Ok(std::net::TcpListener::bind("127.0.0.1:0")?
        .local_addr()?
        .port())
}

/// Run the test. Never panics — any failure is surfaced as `ok: false` + an
/// `error` message the UI can show.
pub async fn test_outbound(
    binary: &Path,
    ob: &CustomOutbound,
    test_url: &str,
) -> OutboundTestResult {
    match run(binary, ob, test_url).await {
        Ok(r) => r,
        Err(e) => OutboundTestResult::fail(e.to_string()),
    }
}

async fn run(
    binary: &Path,
    ob: &CustomOutbound,
    test_url: &str,
) -> anyhow::Result<OutboundTestResult> {
    // Build the handler up front: a malformed config fails clearly before we
    // spawn anything. The tag must match the routing rule below.
    let mut test_ob = ob.clone();
    "test-ob".clone_into(&mut test_ob.tag);
    let handler = outbound_to_handler_config(&test_ob)?;

    let api_port = free_port()?;
    let http_port = free_port()?;
    let cfg = json!({
        "log": { "loglevel": "warning" },
        "api": { "tag": "api", "services": ["HandlerService"] },
        "inbounds": [
            { "tag": "api", "listen": "127.0.0.1", "port": api_port,
              "protocol": "dokodemo-door", "settings": { "address": "127.0.0.1" } },
            { "tag": "http-test", "listen": "127.0.0.1", "port": http_port,
              "protocol": "http", "settings": {} }
        ],
        // The outbound under test is pushed via gRPC as `test-ob`; the bootstrap
        // only needs `direct` for the API plane + a rule pinning the proxy
        // inbound to it (xray resolves the outboundTag at dispatch, after the
        // gRPC AddOutbound lands — the same pattern the live panel relies on).
        "outbounds": [{ "tag": "direct", "protocol": "freedom" }],
        "routing": { "rules": [
            { "type": "field", "inboundTag": ["api"], "outboundTag": "api" },
            { "type": "field", "inboundTag": ["http-test"], "outboundTag": "test-ob" }
        ]}
    });

    let cfg_path = std::env::temp_dir().join(format!("rxui-obtest-{}.json", ob.id));
    tokio::fs::write(&cfg_path, serde_json::to_vec(&cfg)?).await?;

    // The config embeds the upstream's secrets, so it must be removed on EVERY
    // exit path from here — including a spawn failure, which the old code left
    // on disk because tear-down was gated behind a successful spawn.
    let spawned = tokio::process::Command::new(binary)
        .arg("run")
        .arg("-config")
        .arg(&cfg_path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
    let mut child = match spawned {
        Ok(child) => child,
        Err(e) => {
            let _ = tokio::fs::remove_file(&cfg_path).await;
            return Err(e.into());
        }
    };

    // From here on, always tear down (kill + rm) regardless of outcome.
    let result = probe(api_port, http_port, handler, test_url).await;
    let _ = child.kill().await;
    let _ = tokio::fs::remove_file(&cfg_path).await;

    Ok(result.unwrap_or_else(|e| OutboundTestResult::fail(e.to_string())))
}

async fn probe(
    api_port: u16,
    http_port: u16,
    handler: OutboundHandlerConfig,
    test_url: &str,
) -> anyhow::Result<OutboundTestResult> {
    // Push the outbound into the temp xray (blocks until its API is reachable).
    let xray = XrayClient::new(format!("http://127.0.0.1:{api_port}"));
    xray.add_outbound(handler)
        .await
        .map_err(|e| anyhow::anyhow!("could not load outbound into test xray: {e}"))?;

    let http = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(format!(
            "http://127.0.0.1:{http_port}"
        ))?)
        .timeout(PROBE_TIMEOUT)
        // Keep the relay connection warm so the follow-up ping probes reuse it.
        .pool_max_idle_per_host(1)
        .build()?;
    measure(&http, test_url).await
}

/// Test a built-in `direct` outbound: a direct HTTPS request with NO proxy,
/// measuring the server's own egress IP + steady-state latency — the baseline
/// to compare a relay against. `ipv4_only` binds an IPv4 source to mirror the
/// `direct-ipv4` outbound (`domainStrategy: UseIPv4`). No xray involved.
pub async fn test_direct(ipv4_only: bool, test_url: &str) -> OutboundTestResult {
    let mut builder = reqwest::Client::builder()
        .timeout(PROBE_TIMEOUT)
        .pool_max_idle_per_host(1)
        // Ignore the machine's HTTP(S)_PROXY env (e.g. a personal client on
        // 127.0.0.1) — `direct` must be a genuinely direct connection, not
        // whatever system proxy happens to be set.
        .no_proxy();
    if ipv4_only {
        builder = builder.local_address(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
    }
    match builder.build() {
        Ok(http) => measure(&http, test_url)
            .await
            .unwrap_or_else(|e| OutboundTestResult::fail(e.to_string())),
        Err(e) => OutboundTestResult::fail(e.to_string()),
    }
}

/// Shared probe used by both the relay (proxy) and `direct` (no-proxy) paths:
/// one cold request that carries the connection setup + the DPI filter's
/// one-time first-packet cost (and yields the exit IP/country), then a few warm
/// probes over the reused keep-alive connection — report the best as the real
/// steady-state latency rather than the cold-start spike.
async fn measure(http: &reqwest::Client, test_url: &str) -> anyhow::Result<OutboundTestResult> {
    // The probe URL is entirely the operator's `xray_test_url` — no hardcoded
    // fallback. Blank means "not configured": a clear operator error, not
    // something to silently paper over with some third party's endpoint.
    let url = test_url.trim();
    if url.is_empty() {
        return Ok(OutboundTestResult::fail(
            "no test URL configured — set one in Settings (xray_test_url)",
        ));
    }
    let first = match http.get(url).send().await {
        Ok(r) if r.status().is_success() => r,
        Ok(r) => {
            return Ok(OutboundTestResult::fail(format!(
                "upstream returned HTTP {}",
                r.status().as_u16()
            )));
        }
        Err(e) => return Ok(OutboundTestResult::fail(format!("no egress: {e}"))),
    };
    let (exit_ip, exit_loc) = parse_trace(&first.text().await.unwrap_or_default());

    let mut best: Option<u64> = None;
    for _ in 0..PING_SAMPLES {
        let start = Instant::now();
        if let Ok(r) = http.get(url).send().await
            && r.status().is_success()
        {
            // Drain the body so the connection returns to the pool for reuse.
            let _ = r.bytes().await;
            let ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
            best = Some(best.map_or(ms, |b| b.min(ms)));
        }
    }

    Ok(OutboundTestResult {
        ok: true,
        latency_ms: best,
        exit_ip,
        exit_loc,
        error: None,
    })
}

/// Pull `ip=` / `loc=` out of Cloudflare's `cdn-cgi/trace` body. Falls back to
/// treating a bare single-line IP as the exit IP, so plain "what's my IP"
/// endpoints (`ifconfig.me/ip`, `api.ipify.org`, ...) also report the exit
/// address when set as `xray_test_url`. `loc` (country) stays trace-only.
fn parse_trace(body: &str) -> (Option<String>, Option<String>) {
    let mut ip = None;
    let mut loc = None;
    for line in body.lines() {
        if let Some(v) = line.strip_prefix("ip=") {
            ip = Some(v.trim().to_owned());
        } else if let Some(v) = line.strip_prefix("loc=") {
            loc = Some(v.trim().to_owned());
        }
    }
    if ip.is_none() {
        let trimmed = body.trim();
        if trimmed.lines().count() == 1 && trimmed.parse::<std::net::IpAddr>().is_ok() {
            ip = Some(trimmed.to_owned());
        }
    }
    (ip, loc)
}

#[cfg(test)]
mod tests {
    use super::parse_trace;

    #[test]
    fn parses_cloudflare_trace() {
        let (ip, loc) = parse_trace("fl=1f2\nip=203.0.113.7\nts=1\nloc=DE\ncolo=FRA\n");
        assert_eq!(ip.as_deref(), Some("203.0.113.7"));
        assert_eq!(loc.as_deref(), Some("DE"));
    }

    #[test]
    fn parses_bare_ip_endpoint() {
        // ifconfig.me/ip, api.ipify.org, ... return just the address.
        assert_eq!(
            parse_trace("198.51.100.42\n").0.as_deref(),
            Some("198.51.100.42")
        );
        // IPv6 bare address too; no country from a bare endpoint.
        let (ip6, loc) = parse_trace("2001:db8::1");
        assert_eq!(ip6.as_deref(), Some("2001:db8::1"));
        assert!(loc.is_none());
    }

    #[test]
    fn empty_or_non_ip_body_yields_nothing() {
        // generate_204 (the default xray_test_url) returns an empty body.
        assert_eq!(parse_trace(""), (None, None));
        // A multi-line non-trace body isn't mistaken for an IP.
        assert_eq!(
            parse_trace("<html>\n<body>hi</body>\n</html>"),
            (None, None)
        );
        // A single non-IP line isn't an IP.
        assert_eq!(parse_trace("hello"), (None, None));
    }
}
