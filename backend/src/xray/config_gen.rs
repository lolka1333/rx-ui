//! Bootstrap xray config.json generator.
//!
//! Produces the *static* config xray needs to come up with a working
//! `HandlerService` API listener. User-facing inbounds are NOT written
//! here — they are pushed into the running xray dynamically via
//! `HandlerService.AddInbound`. This file is therefore deliberately
//! tiny: only what xray refuses to start without.
//!
//! The validate-then-atomic-rename helper (`write_config_validated`)
//! is kept because boot still runs `xray run -test` on the bootstrap
//! config before handing it to the live process.

use crate::models::RoutingRule;
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use tokio::{fs, io::AsyncWriteExt, process::Command};

/// Build the bootstrap xray config. Minimum needed for a working
/// `HandlerService` + `StatsService` gRPC, plus a default outbound:
///
///   * `log.loglevel=warning`: xray emits HTTP/2 client-side cancels
///     (`stream error: stream ID N; CANCEL`) at INFO, one line per
///     dropped stream — a chatty noise floor that buries any real
///     event. The diagnostics we actually care about (Reality
///     handshake failures, TLS errors, real outbound failures) are
///     all WARN/ERROR, so `warning` keeps the signal and drops the
///     noise. `AddInbound` results are surfaced through the gRPC
///     response, not the log stream, so they're unaffected.
///   * `api` + dokodemo-door inbound on 127.0.0.1:62789: the gRPC entry
///     point. `HandlerService` for runtime inbound/user CRUD,
///     `StatsService` for the per-user traffic + online counters
///     surfaced on the Clients page.
///   * `stats: {}` + `policy.levels.0.statsUser*`: xray collects per-
///     user uplink / downlink / online counters only when the policy
///     opt-in is set. Without these the `StatsService` RPCs return empty.
///   * a `direct` (freedom) outbound + a `blocked` (blackhole) outbound.
///     Every dynamically-added inbound forwards through `direct`; the
///     freedom `domainStrategy` is operator-configurable (`freedom_strategy`)
///     so the egress can force IPv4/IPv6. `blocked` is the sink for the
///     block rules below.
///   * routing rules: the api-inbound pin (without it API calls fall through
///     to `direct` and bounce), then the operator's block / IPv4-force rules.
///     The routing block's `domainStrategy` (`routing_strategy`) decides
///     whether rules may match on the resolved destination IP.
///
/// All fields come from `panel_settings`, read by the caller (boot + xray
/// restart) — see `reload::write_bootstrap_config`.
pub struct BootstrapSettings {
    pub freedom_strategy: String,
    pub routing_strategy: String,
    pub block_bittorrent: bool,
    pub blocked_ips: Vec<String>,
    pub blocked_domains: Vec<String>,
    pub ipv4_domains: Vec<String>,
    /// Operator-defined rules, keyed by id; their order comes from `rule_order`.
    pub custom_rules: Vec<RoutingRule>,
    /// Full evaluation order: system tokens + custom rule ids, first-match-wins.
    pub rule_order: Vec<String>,
}

/// System rule tokens, in their natural default order. MUST stay in sync with
/// the frontend `SYS_KEYS` (frontend/src/components/RoutingRulesField.tsx) —
/// both run the same reconcile-then-emit over the saved `rule_order`.
const SYSTEM_TOKENS: &[&str] = &[
    "api",
    "bittorrent",
    "blocked_domains",
    "blocked_ips",
    "ipv4",
];

/// The xray rule JSON for a system token, or `None` when that token is inactive
/// for the current settings (so it contributes no rule).
fn system_rule(token: &str, s: &BootstrapSettings) -> Option<Value> {
    match token {
        "api" => Some(json!({ "type": "field", "inboundTag": ["api"], "outboundTag": "api" })),
        "bittorrent" if s.block_bittorrent => {
            Some(json!({ "type": "field", "protocol": ["bittorrent"], "outboundTag": "blocked" }))
        }
        "blocked_domains" if !s.blocked_domains.is_empty() => {
            Some(json!({ "type": "field", "domain": s.blocked_domains, "outboundTag": "blocked" }))
        }
        "blocked_ips" if !s.blocked_ips.is_empty() => {
            Some(json!({ "type": "field", "ip": s.blocked_ips, "outboundTag": "blocked" }))
        }
        "ipv4" if !s.ipv4_domains.is_empty() => {
            Some(json!({ "type": "field", "domain": s.ipv4_domains, "outboundTag": "direct-ipv4" }))
        }
        _ => None,
    }
}

/// Convert one custom rule into an xray routing-rule object. Empty matchers are
/// omitted; source/sourcePort/inboundTag/user map to xray's field names.
fn custom_rule(r: &RoutingRule) -> Value {
    let mut m = serde_json::Map::new();
    m.insert("type".into(), Value::String("field".into()));
    let arr = |v: &[String]| Value::Array(v.iter().map(|x| Value::String(x.clone())).collect());
    if !r.domain.is_empty() {
        m.insert("domain".into(), arr(&r.domain));
    }
    if !r.ip.is_empty() {
        m.insert("ip".into(), arr(&r.ip));
    }
    if !r.source_ip.is_empty() {
        m.insert("source".into(), arr(&r.source_ip));
    }
    if !r.port.trim().is_empty() {
        m.insert("port".into(), Value::String(r.port.trim().to_owned()));
    }
    if !r.source_port.trim().is_empty() {
        m.insert(
            "sourcePort".into(),
            Value::String(r.source_port.trim().to_owned()),
        );
    }
    if !r.network.is_empty() {
        m.insert("network".into(), arr(&r.network));
    }
    if !r.protocol.is_empty() {
        m.insert("protocol".into(), arr(&r.protocol));
    }
    if !r.inbound_tag.is_empty() {
        m.insert("inboundTag".into(), arr(&r.inbound_tag));
    }
    if !r.user.is_empty() {
        m.insert("user".into(), arr(&r.user));
    }
    m.insert("outboundTag".into(), Value::String(r.outbound_tag.clone()));
    Value::Object(m)
}

/// Built-in outbound tags the bootstrap config emits. The routing-rule-target
/// validator (`api::settings`) and the custom-outbound-tag validator
/// (`api::outbounds`) both source from this list, so a rename here can't
/// silently desync them.
pub const TAG_DIRECT: &str = "direct";
pub const TAG_BLOCKED: &str = "blocked";
pub const TAG_DIRECT_IPV4: &str = "direct-ipv4";
pub const BUILTIN_OUTBOUND_TAGS: &[&str] = &[TAG_DIRECT, TAG_BLOCKED, TAG_DIRECT_IPV4];

/// Tag of the internal gRPC control inbound (the dokodemo-door the panel talks
/// to xray through). Reserved: user inbounds are rejected from claiming it (see
/// `api::inbounds`), and the per-inbound traffic poller skips it so the panel's
/// own control-channel bytes never show up as user traffic.
pub const API_TAG: &str = "api";

/// Validate a tag that will enter xray's outbound-tag namespace — a custom
/// outbound's `tag`, or a client's `reverse_tag` (which becomes a routable
/// tunnel outbound once a bridge dials in). Rejects empty, reserved
/// (built-ins + `api`), and whitespace/control chars. Uniqueness / collision
/// with the OTHER tags in the namespace is the caller's job (it holds the set).
pub fn validate_routable_tag(tag: &str) -> Result<(), String> {
    let tag = tag.trim();
    if tag.is_empty() {
        return Err("tag must not be empty".to_owned());
    }
    if BUILTIN_OUTBOUND_TAGS.contains(&tag) || tag == API_TAG {
        return Err(format!("tag '{tag}' is reserved"));
    }
    if tag.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(format!(
            "tag '{tag}' must not contain spaces or control characters"
        ));
    }
    Ok(())
}

pub fn build_bootstrap_config(s: &BootstrapSettings) -> Value {
    // `direct` + `blocked` are always present. The `direct-ipv4` freedom
    // outbound is added when either the IPv4-force list OR any enabled custom
    // rule targets it — otherwise a rule's `outboundTag` would dangle.
    let needs_ipv4 = !s.ipv4_domains.is_empty()
        || s.custom_rules
            .iter()
            .any(|r| r.enabled && r.outbound_tag == TAG_DIRECT_IPV4);
    let mut outbounds = vec![
        json!({
            "tag": TAG_DIRECT,
            "protocol": "freedom",
            "settings": { "domainStrategy": s.freedom_strategy }
        }),
        json!({ "tag": TAG_BLOCKED, "protocol": "blackhole" }),
    ];
    if needs_ipv4 {
        outbounds.push(json!({
            "tag": TAG_DIRECT_IPV4,
            "protocol": "freedom",
            "settings": { "domainStrategy": "UseIPv4" }
        }));
    }

    // Build the evaluation order: honour `rule_order`, dropping tokens that no
    // longer exist, then slot in any active system tokens / custom ids not yet
    // listed (mirrors the frontend reconciliation). First-match-wins.
    let custom_by_id: HashMap<&str, &RoutingRule> =
        s.custom_rules.iter().map(|r| (r.id.as_str(), r)).collect();
    let active_sys: Vec<&str> = SYSTEM_TOKENS
        .iter()
        .copied()
        .filter(|t| system_rule(t, s).is_some())
        .collect();
    let valid: HashSet<&str> = active_sys
        .iter()
        .copied()
        .chain(custom_by_id.keys().copied())
        .collect();

    let mut order: Vec<String> = s
        .rule_order
        .iter()
        .filter(|t| valid.contains(t.as_str()))
        .cloned()
        .collect();
    // Insert missing active system tokens just after the last system token
    // already present (keeps new built-in blocks within the system group).
    let mut insert_at = 0;
    for (idx, tok) in order.iter().enumerate() {
        if SYSTEM_TOKENS.contains(&tok.as_str()) {
            insert_at = idx + 1;
        }
    }
    let missing_sys: Vec<&str> = active_sys
        .iter()
        .copied()
        .filter(|t| !order.iter().any(|o| o.as_str() == *t))
        .collect();
    for (offset, tok) in missing_sys.into_iter().enumerate() {
        order.insert(insert_at + offset, tok.to_owned());
    }
    // Append any custom rules not yet referenced (newly added).
    for r in &s.custom_rules {
        if !order.iter().any(|o| o == &r.id) {
            order.push(r.id.clone());
        }
    }

    // Emit rules in that order; disabled custom rules are skipped. Unmatched
    // traffic falls through to the first outbound (`direct`).
    let mut rules: Vec<Value> = Vec::new();
    for tok in &order {
        if SYSTEM_TOKENS.contains(&tok.as_str()) {
            if let Some(v) = system_rule(tok, s) {
                rules.push(v);
            }
        } else if let Some(r) = custom_by_id.get(tok.as_str())
            && r.enabled
        {
            rules.push(custom_rule(r));
        }
    }

    json!({
        "log": { "loglevel": "warning", "access": "" },
        "api": { "tag": API_TAG, "services": ["HandlerService", "StatsService"] },
        "stats": {},
        "policy": {
            "levels": {
                "0": {
                    "statsUserUplink": true,
                    "statsUserDownlink": true,
                    "statsUserOnline": true
                }
            },
            // Per-outbound / per-inbound traffic counters
            // (`{outbound,inbound}>>>{tag}>>>traffic>>>*`), surfaced on the
            // Outbounds / Inbounds pages so the operator sees how much flows
            // through each relay / built-in and each inbound. The inbound
            // counters give an accurate per-inbound split even when one client
            // (email) spans several inbounds — xray's per-user counters can't.
            "system": {
                "statsOutboundUplink": true,
                "statsOutboundDownlink": true,
                "statsInboundUplink": true,
                "statsInboundDownlink": true
            }
        },
        "inbounds": [{
            "tag": API_TAG,
            "listen": "127.0.0.1",
            "port": 62789,
            "protocol": "dokodemo-door",
            "settings": { "address": "127.0.0.1" }
        }],
        "outbounds": outbounds,
        "routing": { "domainStrategy": s.routing_strategy, "rules": rules }
    })
}

/// Atomically write `value` to `path` after validating it via `xray run -test`.
/// If validation fails the tmp file is removed and the existing `path` is left
/// untouched, so the panel never overwrites a working config with a broken one.
pub async fn write_config_validated(
    binary: &Path,
    path: &Path,
    value: &Value,
) -> anyhow::Result<()> {
    let tmp = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(value)?;
    {
        let mut f = fs::File::create(&tmp).await?;
        f.write_all(&bytes).await?;
        f.sync_all().await?;
    }

    // -format json: xray normally infers from extension (.json/.yaml/.toml)
    // but we hand it a .tmp file, so be explicit.
    let output = Command::new(binary)
        .arg("run")
        .arg("-test")
        .arg("-format")
        .arg("json")
        .arg("-config")
        .arg(&tmp)
        .output()
        .await;

    let output = match output {
        Ok(o) => o,
        Err(e) => {
            let _ = fs::remove_file(&tmp).await;
            anyhow::bail!("failed to invoke xray for config validation: {e}");
        }
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let _ = fs::remove_file(&tmp).await;
        anyhow::bail!(
            "xray rejected config: {}",
            // xray prints the failure to stderr; some builds use stdout.
            if stderr.trim().is_empty() {
                stdout.trim().to_string()
            } else {
                stderr.trim().to_string()
            }
        );
    }

    fs::rename(&tmp, path).await?;
    tracing::info!("xray config validated and written: {}", path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(id: &str, enabled: bool, target: &str) -> RoutingRule {
        RoutingRule {
            id: id.to_owned(),
            enabled,
            name: String::new(),
            domain: vec![],
            ip: vec![],
            source_ip: vec![],
            port: String::new(),
            source_port: String::new(),
            network: vec![],
            protocol: vec![],
            inbound_tag: vec![],
            user: vec![],
            outbound_tag: target.to_owned(),
        }
    }

    fn base(custom_rules: Vec<RoutingRule>, rule_order: Vec<&str>) -> BootstrapSettings {
        BootstrapSettings {
            freedom_strategy: "AsIs".into(),
            routing_strategy: "AsIs".into(),
            block_bittorrent: true,
            blocked_ips: vec!["10.0.0.0/8".into()],
            blocked_domains: vec![],
            ipv4_domains: vec![],
            custom_rules,
            rule_order: rule_order.into_iter().map(String::from).collect(),
        }
    }

    fn outbound_tags(cfg: &Value) -> Vec<String> {
        cfg["routing"]["rules"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["outboundTag"].as_str().unwrap().to_owned())
            .collect()
    }

    fn outbound_set(cfg: &Value) -> Vec<String> {
        cfg["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .map(|o| o["tag"].as_str().unwrap().to_owned())
            .collect()
    }

    #[test]
    fn custom_rule_maps_fields_and_omits_empties() {
        let mut r = rule("r1", true, "blocked");
        r.name = "panel label".into(); // must NOT appear in xray output
        r.domain = vec!["full:example.com".into()];
        r.source_ip = vec!["geoip:private".into()];
        r.port = " 443 ".into(); // trimmed on emit
        let v = custom_rule(&r);
        assert_eq!(v["type"], "field");
        assert_eq!(v["domain"][0], "full:example.com");
        assert_eq!(v["source"][0], "geoip:private"); // source_ip -> source
        assert_eq!(v["port"], "443");
        assert_eq!(v["outboundTag"], "blocked");
        // Omitted: empty matchers + the panel-only name.
        let obj = v.as_object().unwrap();
        assert!(!obj.contains_key("ip"));
        assert!(!obj.contains_key("sourcePort"));
        assert!(!obj.contains_key("network"));
        assert!(!obj.contains_key("name"));
    }

    #[test]
    fn empty_order_falls_back_to_defaults() {
        let cfg = build_bootstrap_config(&base(vec![rule("r1", true, "direct")], vec![]));
        // api -> bittorrent -> blocked_ips -> custom (default reconcile order).
        assert_eq!(
            outbound_tags(&cfg),
            vec!["api", "blocked", "blocked", "direct"]
        );
    }

    #[test]
    fn custom_order_interleaves_and_skips_disabled() {
        let mut r1 = rule("r1", true, "blocked");
        r1.domain = vec!["ads.example.com".into()];
        let mut r2 = rule("r2", true, "direct");
        r2.ip = vec!["8.8.8.8/32".into()];
        r2.network = vec!["tcp".into()];
        let mut r3 = rule("r3", true, "direct-ipv4");
        r3.domain = vec!["stream.example.com".into()];
        let r4 = rule("r4", false, "blocked"); // disabled -> skipped

        // r1 deliberately placed BEFORE the bittorrent/blocked-ip system rows.
        let s = base(
            vec![r1, r2, r3, r4],
            vec!["api", "r1", "bittorrent", "blocked_ips", "r2", "r3", "r4"],
        );
        let cfg = build_bootstrap_config(&s);
        assert_eq!(
            outbound_tags(&cfg),
            vec![
                "api",
                "blocked",
                "blocked",
                "blocked",
                "direct",
                "direct-ipv4"
            ]
        );
        // direct-ipv4 outbound is added because r3 targets it (ipv4_domains empty).
        assert!(outbound_set(&cfg).contains(&"direct-ipv4".to_owned()));
        // The disabled rule contributes nothing.
        assert_eq!(cfg["routing"]["rules"].as_array().unwrap().len(), 6);
    }

    #[test]
    fn unknown_and_stale_tokens_are_reconciled() {
        // Order references a deleted custom id ("gone") and omits an active
        // system token ("bittorrent"); generation must drop the stale one and
        // slot the missing system row back into the system block.
        let mut r1 = rule("r1", true, "blocked");
        r1.domain = vec!["x.example.com".into()];
        let s = base(vec![r1], vec!["api", "blocked_ips", "gone", "r1"]);
        let cfg = build_bootstrap_config(&s);
        // bittorrent re-inserted after the last system token present (blocked_ips).
        assert_eq!(
            outbound_tags(&cfg),
            vec!["api", "blocked", "blocked", "blocked"]
        );
    }

    #[test]
    fn routing_rule_serde_roundtrip() {
        let mut r = rule("abc", true, "blocked");
        r.domain = vec!["geosite:cn".into()];
        r.inbound_tag = vec!["inbound-1".into()];
        let json = serde_json::to_string(&r).unwrap();
        let back: RoutingRule = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, "abc");
        assert_eq!(back.outbound_tag, "blocked");
        assert_eq!(back.inbound_tag, vec!["inbound-1".to_owned()]);
        // A whole array parses too (the DB column shape).
        let arr: Vec<RoutingRule> = serde_json::from_str(&format!("[{json}]")).unwrap();
        assert_eq!(arr.len(), 1);
    }

    /// End-to-end: the generated config — with geo matchers and the full field
    /// set — must be accepted by the real xray binary. Gated on `XRAY_TEST_BIN`
    /// (path to xray) + `XRAY_TEST_ASSETS` (dir with geoip/geosite .dat), so it
    /// runs locally but self-skips in CI where xray isn't present.
    #[test]
    fn xray_accepts_generated_config() {
        let Ok(bin) = std::env::var("XRAY_TEST_BIN") else {
            eprintln!("skipping xray_accepts_generated_config: set XRAY_TEST_BIN to run");
            return;
        };

        let mut r1 = rule("r1", true, "blocked");
        r1.domain = vec!["geosite:telegram".into(), "full:example.com".into()];
        let mut r2 = rule("r2", true, "direct");
        r2.ip = vec!["geoip:ru".into(), "10.0.0.0/8".into()];
        r2.network = vec!["tcp".into(), "udp".into()];
        r2.protocol = vec!["http".into(), "tls".into()];
        let mut r3 = rule("r3", true, "direct-ipv4");
        r3.source_ip = vec!["geoip:private".into()];
        r3.port = "443,8080-8090".into();
        r3.user = vec!["user@example.com".into()];

        let s = BootstrapSettings {
            freedom_strategy: "AsIs".into(),
            routing_strategy: "IPIfNonMatch".into(),
            block_bittorrent: true,
            blocked_ips: vec!["geoip:cn".into(), "192.168.0.0/16".into()],
            blocked_domains: vec!["geosite:category-ads-all".into(), "ads.example.com".into()],
            ipv4_domains: vec!["geosite:netflix".into()],
            custom_rules: vec![r1, r2, r3, rule("r4", false, "blocked")],
            rule_order: vec![],
        };
        let cfg = build_bootstrap_config(&s);

        let path = std::env::temp_dir().join("rxui_routing_xraytest.json");
        std::fs::write(&path, serde_json::to_vec_pretty(&cfg).unwrap()).unwrap();

        let mut cmd = std::process::Command::new(bin);
        cmd.args(["run", "-test", "-format", "json", "-config"])
            .arg(&path);
        if let Ok(assets) = std::env::var("XRAY_TEST_ASSETS") {
            cmd.env("XRAY_LOCATION_ASSET", assets);
        }
        let out = cmd.output().expect("failed to run xray");
        assert!(
            out.status.success(),
            "xray rejected the generated config:\nSTDOUT: {}\nSTDERR: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
    }
}
