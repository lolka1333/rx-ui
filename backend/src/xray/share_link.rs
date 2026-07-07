//! Build a `vless://` share-link string for one client of one inbound.
//!
//! The format is the de-facto standard understood by v2rayN/NekoBox/Shadowrocket
//! et al. — `vless://UUID@host:port?TYPE&SECURITY&PBK&...#NAME`. Reality
//! adds `pbk` (server public key) and `sid` (short id); XHTTP adds `path`,
//! `host`, `mode`. No registry exists, so we follow the conventions seen in
//! 3x-ui / Marzban / `NekoBox` link parsers — easy to verify by pasting the
//! output into any of those clients.
//!
//! Host source: we don't know the server's public address from inside the
//! Rust process reliably (NAT, multiple interfaces) — the auto-detected
//! `ipv4` from the system monitor is the best heuristic. The caller passes
//! it in as `host`; a future settings-table override goes here too.
//!
//! Implementation: each stream layer (protocol/transport/security) owns
//! the params it contributes via its `share_link_params(...)` trait method.
//! This file just stitches the slices together in a stable order, URL-
//! encodes the result, and prepends the `vless://uuid@host:port?` /
//! appends the `#<inbound-tag>` fragment (the per-entry name in the client).

use crate::models::{Client, Inbound};
use crate::protocols::ProtocolConfig;
use crate::security::SecurityConfig;
use crate::transports::TransportConfig;
use crate::transports::finalmask::FinalMask;

/// Wrap an IPv6 literal in `[...]` per RFC 3986 so the URL's
/// `host:port` separator is unambiguous. IPv4 / DNS names pass
/// through unchanged. Detection is "contains a colon" — any host
/// with `:` is either IPv6 or already-bracketed, both correctly
/// handled because we only add brackets when the first char isn't
/// `[`.
fn url_host(host: &str) -> std::borrow::Cow<'_, str> {
    if host.contains(':') && !host.starts_with('[') {
        std::borrow::Cow::Owned(format!("[{host}]"))
    } else {
        std::borrow::Cow::Borrowed(host)
    }
}

/// Dispatch to the per-protocol share-link builder.
pub fn build_share_link(inbound: &Inbound, client: &Client, host: &str) -> anyhow::Result<String> {
    match &inbound.protocol {
        ProtocolConfig::Vless(_) => build_vless_share_link(inbound, client, host),
        ProtocolConfig::Hysteria2(_) => build_hysteria2_share_link(inbound, client, host),
    }
}

/// `hysteria2://AUTH@HOST:PORT/?sni=...&alpn=h3&insecure=0#NAME` per the
/// format every hysteria-compatible client (NekoBox/v2rayN/Stash) parses.
/// TLS is asserted again here because a row may have drifted past the
/// validator (e.g. operator deleted/reinserted security via direct DB).
pub fn build_hysteria2_share_link(
    inbound: &Inbound,
    client: &Client,
    host: &str,
) -> anyhow::Result<String> {
    let SecurityConfig::Tls(tls) = &inbound.security else {
        anyhow::bail!(
            "Hysteria 2 inbound {} is missing TLS security — share-link can't be built",
            inbound.tag
        );
    };

    let sni = tls.effective_sni(host);

    // alpn=h3 is fixed (xray's listener hard-codes it); insecure=0 is
    // emitted explicitly because some clients require the key to be
    // present even at its default.
    let mut params: Vec<(String, String)> = vec![
        ("alpn".to_owned(), "h3".to_owned()),
        ("insecure".to_owned(), "0".to_owned()),
    ];
    if !sni.is_empty() {
        params.insert(0, ("sni".to_owned(), sni.to_owned()));
    }
    // Self-signed cert: the fork removed `allowInsecure`, so instead of
    // `insecure=1` we hand clients the exact leaf fingerprint as `pinSHA256=`.
    // Fork clients (v2rayN) map it to `pinnedPeerCertSha256`; stock hysteria2
    // clients pin it directly — either way an exact-cert match replaces chain
    // validation, so a self-signed inbound connects with no per-client step.
    // Left off (and `insecure=0` kept) for a real CA cert, whose renewals would
    // otherwise break every pinned client.
    if tls.self_signed == Some(true) {
        // The operator flagged this cert as self-signed, so clients must pin it
        // (`insecure=1` is dead in this fork). If the pin can't be derived — a
        // `Path`-sourced cert we don't read here, or an unparseable PEM — the
        // link would be silently unusable (`insecure=0` against an untrusted
        // cert), so fail loudly instead of shipping a dead link.
        let pin = tls.cert_pin_sha256().ok_or_else(|| {
            anyhow::anyhow!(
                "hysteria2 inbound {} is marked self-signed but its cert fingerprint can't be \
                 derived — use an inline PEM certificate, not a file path",
                inbound.tag
            )
        })?;
        params.push(("pinSHA256".to_owned(), pin));
    }
    // NO `ech=` for hysteria2. Unlike the TCP/XHTTP TLS listener, xray's
    // hysteria2 QUIC handshake does not serve ECH, so advertising an ECH config
    // makes the client attempt Encrypted Client Hello against a server that
    // can't answer it — the QUIC/TLS handshake times out and the node shows dead
    // (v2rayN `-1`). Verified end-to-end against a live server: the inbound
    // connects with `ech` stripped and times out with it present. ECH stays on
    // the vless/TLS builders where the listener actually serves it.
    //
    // Obfuscation. Salamander is Hysteria 2's NATIVE obfs, so emit the standard
    // `obfs=salamander&obfs-password=…` — it lands in every hysteria2 client's
    // obfs field (xray or not). Any other FinalMask (noise/sudoku/…) is an
    // xray-specific wrapper and rides as `fm=`, same as the vless builder.
    match &inbound.finalmask {
        FinalMask::Salamander(p) if !p.password.trim().is_empty() => {
            params.push(("obfs".to_owned(), "salamander".to_owned()));
            params.push(("obfs-password".to_owned(), p.password.clone()));
        }
        _ => {
            if let Some(pair) = finalmask_share_link_param(&inbound.finalmask) {
                params.push(pair);
            }
        }
    }

    // Port hopping: carry the server's udp_hop port set as `mport=` (v2rayN /
    // NekoBox read it into their "port range" field) so the client rotates the
    // same ports. Without it the subscription hands out only the single listen
    // port and hopping is lost client-side.
    if let TransportConfig::Hysteria(ht) = &inbound.transport
        && let Some(hop) = ht.quic_params.as_ref().and_then(|q| q.udp_hop.as_ref())
        && !hop.ports.is_empty()
    {
        let ports = hop
            .ports
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(",");
        params.push(("mport".to_owned(), ports));
    }

    let query = params
        .iter()
        .map(|(k, v)| format!("{k}={}", urlencoding::encode(v)))
        .collect::<Vec<_>>()
        .join("&");
    // Fragment = the inbound tag, so subscription entries are named per inbound
    // (see the VLESS builder for the rationale).
    let name = urlencoding::encode(&inbound.tag);
    let auth_enc = urlencoding::encode(client.effective_hysteria_auth());

    Ok(format!(
        "hysteria2://{auth_enc}@{host}:{port}/?{query}#{name}",
        host = url_host(host),
        port = inbound.port,
    ))
}

/// Build the `vless://...` URL.
///
/// Returns an error only if the inbound is in Reality mode but a required
/// field (`server_names` or `public_key`) is empty — those would produce a
/// broken share-link silently otherwise. For `security=none` no Reality
/// material is needed.
pub fn build_vless_share_link(
    inbound: &Inbound,
    client: &Client,
    host: &str,
) -> anyhow::Result<String> {
    // Reject the historically-silent failures: Reality without any serverNames
    // (or without a public key) produces a `pbk=...&sni=` URL that clients
    // accept but xray immediately rejects on the first connection. Catch both
    // here so the operator sees a 4xx at share-link time, not a runtime
    // surprise. Both fields are required server-side.
    if let SecurityConfig::Reality(r) = &inbound.security {
        if r.server_names.is_empty() {
            anyhow::bail!("inbound {} has no reality server_names", inbound.tag);
        }
        if r.public_key.trim().is_empty() {
            anyhow::bail!("inbound {} has no reality public_key", inbound.tag);
        }
    }

    let fallback_host = transport_fallback_host(&inbound.transport);

    let mut params: Vec<(String, String)> = Vec::new();
    // Transport contributes `type=`, plus its own path/host/mode params.
    params.extend(inbound.transport.as_transport().share_link_params());
    // Protocol contributes `encryption=` and `flow=` (Vision only).
    params.extend(inbound.protocol.as_protocol().share_link_params(client));
    // Security contributes `security=` + its own SNI/ALPN/fp/pbk/sid.
    params.extend(
        inbound
            .security
            .as_security()
            .share_link_params(fallback_host),
    );
    // FinalMask, when active, rides along as `fm=` so the client app
    // configures the SAME wire-obfuscation symmetric to the server.
    // Inactive variants contribute nothing.
    if let Some(pair) = finalmask_share_link_param(&inbound.finalmask) {
        params.push(pair);
    }

    let query = params
        .iter()
        .map(|(k, v)| format!("{k}={}", urlencoding::encode(v)))
        .collect::<Vec<_>>()
        .join("&");

    // Fragment = friendly name shown by the client app. Use the INBOUND tag:
    // a subscription bundles one entry per inbound for the same user, so
    // naming each by its inbound (`reality-tcp`, `ws-cdn`, …) lets the client
    // tell them apart — the email is the same on every entry and useless here.
    let name = urlencoding::encode(&inbound.tag);

    Ok(format!(
        "vless://{uuid}@{host}:{port}?{query}#{name}",
        uuid = client.uuid,
        host = url_host(host),
        port = inbound.port,
    ))
}

/// Encode an active `FinalMask` as a `fm=<url-encoded-json>` URL parameter.
/// The convention was added in xray-core v26.3.27 (release notes:
/// "share-link standard adds fm, pcs, vcn"). The JSON shape mirrors
/// xray's `streamSettings.finalmask` exactly — v2rayN's parser
/// (`BaseFmt.cs`) URL-decodes the value and pipes it verbatim into the
/// generated client config:
///
/// ```json
/// {"tcp":[{"type":"sudoku","settings":{...}}],"udp":[{"type":"sudoku","settings":{...}}]}
/// ```
///
/// Per-variant scope: Sudoku populates both slots, Fragment only `tcp`,
/// Noise only `udp`. Empty arrays for the off-side keep the JSON shape
/// stable so clients don't have to handle missing keys. Inactive masks
/// return `None` and the caller skips the param.
fn finalmask_share_link_param(fm: &FinalMask) -> Option<(String, String)> {
    if !fm.is_active() {
        return None;
    }
    // Wire format mirrors xray-core's `streamSettings.finalmask` JSON
    // (`infra/conf/transport_internet.go` — fields `tcp` / `udp`, each a list
    // of `{type, settings}`). v2rayN URL-decodes `fm=` and pipes the JSON
    // verbatim into `streamSettings.finalmask`, so this layout is what
    // operator-side clients ultimately see. No base64 — the caller URL-
    // encodes the value when stitching the query string.
    let settings = match fm {
        FinalMask::None => unreachable!("filtered by is_active above"),
        FinalMask::Sudoku(p) => serde_json::json!({
            "password":     p.password,
            "ascii":        p.ascii,
            "customTable":  p.custom_table,
            "paddingMin":   p.padding_min.unwrap_or(0),
            "paddingMax":   p.padding_max.unwrap_or(0),
            "customTables": p.custom_tables,
        }),
        // Conf-shape required by xray's `infra/conf` FragmentMask (v26.6.22
        // #6334): `packets` is a string ("tlshello" | "" | "from-to");
        // `lengths` / `delays` are arrays of "min-max" Int32Range strings, one
        // per segment (the last entry repeats for further segments); `maxSplit`
        // is a single Int32Range. The proto field names (lengthsMin / … ) are
        // NOT recognised by the conf parser, and xray rejects a final `lengths`
        // entry whose min is 0. (packets 0/1 == the tlshello shortcut, matching
        // the gRPC path's packets_from=0/packets_to=1.)
        FinalMask::Fragment(p) => {
            let packets = match (p.packets_from.unwrap_or(0), p.packets_to.unwrap_or(0)) {
                (0, 1) => "tlshello".to_owned(),
                (0, 0) => String::new(),
                (from, to) => format!("{from}-{to}"),
            };
            let ranges = |mins: &[i64], maxs: &[i64]| -> Vec<String> {
                mins.iter()
                    .zip(maxs.iter())
                    .map(|(min, max)| format!("{min}-{max}"))
                    .collect()
            };
            serde_json::json!({
                "packets":  packets,
                "lengths":  ranges(&p.lengths_min, &p.lengths_max),
                "delays":   ranges(&p.delays_min, &p.delays_max),
                "maxSplit": format!("{}-{}", p.max_split_min.unwrap_or(0), p.max_split_max.unwrap_or(0)),
            })
        }
        // Conf-shape required by xray's NoiseMask: nested `{reset, noise:[Item]}`,
        // where each Item carries EITHER a `packet` (parsed per `type`) OR a
        // `rand` "min-max" range — xray errors when an item has both a packet
        // and rand.To > 0, so we emit one or the other. The previous flat
        // `{packetHex, randMin, …}` object parsed to an empty `noise:[]` — i.e.
        // a silent no-op, the client applied no obfuscation at all.
        FinalMask::Noise(p) => {
            // One conf `noise[]` entry per active item, matching the proto path
            // (literal XOR random) so the server the panel builds and the client
            // this `fm=` configures stay symmetric. Per-item `delay` (an
            // Int32Range "min-max" string) rides along only when the operator
            // set it, keeping the link compact for the common no-delay case.
            let noise: Vec<serde_json::Value> = p
                .items
                .iter()
                .filter(|it| it.is_active())
                .map(|it| {
                    let mut item = if it.has_literal() {
                        // Emit CANONICAL hex (0x/colons/whitespace stripped,
                        // even length) — xray's client parses `packet` with a
                        // strict `hex.DecodeString` that would reject the raw
                        // operator string and fail to load the whole node.
                        serde_json::json!({ "type": "hex", "packet": it.packet_hex_canonical() })
                    } else {
                        let (lo, hi) = it.rand_range();
                        serde_json::json!({ "rand": format!("{lo}-{hi}") })
                    };
                    if it.delay_min.is_some() || it.delay_max.is_some() {
                        let (lo, hi) = it.delay_range();
                        item["delay"] = serde_json::json!(format!("{lo}-{hi}"));
                    }
                    item
                })
                .collect();
            let (reset_lo, reset_hi) = p.reset_range();
            serde_json::json!({
                "reset": format!("{reset_lo}-{reset_hi}"),
                "noise": noise,
            })
        }
        // Salamander is a single password (packetSize left at xray default).
        FinalMask::Salamander(p) => serde_json::json!({ "password": p.password }),
    };
    let layer = serde_json::json!({ "type": fm.kind(), "settings": settings });
    // Sudoku applies to both sockets; Fragment is TCP-only; Noise is UDP-only.
    // Empty arrays for the other side keep the JSON shape stable so the
    // client-side parser doesn't choke on a missing key.
    let body = match fm {
        // `serde_json::json!` borrows the value, so the same `layer` reaches
        // both slots without a clone.
        FinalMask::Sudoku(_) => serde_json::json!({ "tcp": [layer], "udp": [layer] }),
        FinalMask::Fragment(_) => serde_json::json!({ "tcp": [layer], "udp": [] }),
        FinalMask::Noise(_) | FinalMask::Salamander(_) => {
            serde_json::json!({ "tcp": [], "udp": [layer] })
        }
        FinalMask::None => unreachable!("filtered by is_active above"),
    };
    let raw = serde_json::to_string(&body).ok()?;
    Some(("fm".to_owned(), raw))
}

/// SNI fallback for TLS-secured inbounds: when the operator left
/// `tls_server_name` empty, we pull the host from a transport-level
/// `host` field (WS upstream Host header, XHTTP Host). TCP has no
/// host setting; returns `""` and the TLS layer just omits `sni=`.
fn transport_fallback_host(transport: &TransportConfig) -> &str {
    match transport {
        TransportConfig::Ws(w) => w.host.as_deref().unwrap_or(""),
        TransportConfig::Xhttp(x) => x.host.as_deref().unwrap_or(""),
        // TCP has no host setting; Hysteria pulls SNI from the TLS layer
        // directly and uses its own hysteria2:// builder anyway, so this
        // branch is structurally unreachable. Both still need a return
        // arm to keep the match total.
        TransportConfig::Tcp(_) | TransportConfig::Hysteria(_) => "",
    }
}

#[cfg(test)]
mod tests {
    //! Snapshot-style tests for `build_vless_share_link`. The output is the
    //! single thing every client app parses, so semantic regressions
    //! (missing params, wrong encoding, wrong format) are user-visible
    //! breaks. Tests assert via `contains()` rather than full-string
    //! equality so a stable-but-different param order across the trait-
    //! composed layers stays a non-event for clients (they parse the
    //! query as a set).
    use super::*;
    use crate::models::Sniffing;
    use crate::protocols::ProtocolConfig;
    use crate::protocols::vless::{VlessEncryptionMode, VlessFlow, VlessProtocol, VlessXorMode};
    use crate::security::NoneSecurity;
    use crate::security::SecurityConfig;
    use crate::security::reality::RealitySecurity;
    use crate::security::tls::TlsSecurity;
    use crate::transports::TransportConfig;
    use crate::transports::tcp::TcpTransport;
    use crate::transports::ws::WsTransport;
    use crate::transports::xhttp::{XhttpMode, XhttpTransport};

    fn vless(flow: VlessFlow) -> ProtocolConfig {
        ProtocolConfig::Vless(VlessProtocol {
            flow,
            encryption_mode: VlessEncryptionMode::None,
            ..VlessProtocol::default()
        })
    }

    fn inbound(transport: TransportConfig, security: SecurityConfig) -> Inbound {
        Inbound {
            id: "id-x".into(),
            tag: "test-inbound".into(),
            enabled: true,
            listen: "0.0.0.0".into(),
            port: 8443,
            protocol: vless(VlessFlow::None),
            transport,
            security,
            sniffing: Sniffing::default(),
            finalmask: FinalMask::None,
            sockopt: crate::transports::sockopt::SocketOpt::default(),
            created_at: "now".into(),
            updated_at: "now".into(),
        }
    }

    fn base_client() -> Client {
        Client {
            id: "cid".into(),
            inbound_id: "id-x".into(),
            email: "alice@test".into(),
            uuid: "00000000-0000-0000-0000-000000000001".into(),
            auth: None,
            flow: None,
            enabled: true,
            note: None,
            traffic_limit_bytes: None,
            disabled_reason: None,
            expires_at: None,
            sub_token: "0000000000000000000000000000000a".into(),
            created_at: "now".into(),
            updated_at: "now".into(),
        }
    }

    #[test]
    fn tcp_plain_minimal_link() {
        let inb = inbound(
            TransportConfig::Tcp(TcpTransport {}),
            SecurityConfig::None(NoneSecurity {}),
        );
        let link = build_vless_share_link(&inb, &base_client(), "1.2.3.4").unwrap();
        assert!(link.starts_with("vless://00000000-0000-0000-0000-000000000001@1.2.3.4:8443?"));
        assert!(link.contains("type=tcp"));
        assert!(link.contains("encryption=none"));
        assert!(link.contains("security=none"));
        assert!(link.ends_with("#test-inbound"));
    }

    #[test]
    fn tcp_reality_vision_canonical_combo() {
        let mut inb = inbound(
            TransportConfig::Tcp(TcpTransport {}),
            SecurityConfig::Reality(RealitySecurity {
                dest: "www.cloudflare.com:443".into(),
                server_names: vec!["www.cloudflare.com".into()],
                private_key: String::new(),
                public_key: "9pZoIyb_-Ws8Y57RPT95smRBQga1690MT8O8FwMUQS4".into(),
                short_ids: vec!["324a8e7c".into()],
                fingerprint: "chrome".into(),
                xver: 0,
                spider_x: String::new(),
            }),
        );
        inb.protocol = vless(VlessFlow::XtlsRprxVision);
        let link = build_vless_share_link(&inb, &base_client(), "1.2.3.4").unwrap();
        assert!(link.contains("security=reality"));
        assert!(link.contains("pbk=9pZoIyb_-Ws8Y57RPT95smRBQga1690MT8O8FwMUQS4"));
        assert!(link.contains("sid=324a8e7c"));
        assert!(link.contains("fp=chrome"));
        assert!(link.contains("sni=www.cloudflare.com"));
        assert!(link.contains("flow=xtls-rprx-vision"));
    }

    #[test]
    fn reality_without_server_names_errs_loudly() {
        let inb = inbound(
            TransportConfig::Tcp(TcpTransport {}),
            SecurityConfig::Reality(RealitySecurity::default()),
        );
        let err = build_vless_share_link(&inb, &base_client(), "1.2.3.4")
            .unwrap_err()
            .to_string();
        assert!(err.contains("server_names"), "got: {err}");
    }

    #[test]
    fn ws_plain_emits_type_and_path() {
        let inb = inbound(
            TransportConfig::Ws(WsTransport {
                path: Some("/ws".into()),
                ..WsTransport::default()
            }),
            SecurityConfig::None(NoneSecurity {}),
        );
        let link = build_vless_share_link(&inb, &base_client(), "1.2.3.4").unwrap();
        assert!(link.contains("type=ws"));
        assert!(link.contains("path=%2Fws"), "got: {link}");
    }

    #[test]
    fn ws_empty_path_defaults_to_slash() {
        let inb = inbound(
            TransportConfig::Ws(WsTransport::default()),
            SecurityConfig::None(NoneSecurity {}),
        );
        let link = build_vless_share_link(&inb, &base_client(), "1.2.3.4").unwrap();
        assert!(link.contains("path=%2F"), "got: {link}");
    }

    #[test]
    fn ws_with_host_emits_host_param() {
        let inb = inbound(
            TransportConfig::Ws(WsTransport {
                path: Some("/ws".into()),
                host: Some("cdn.example.com".into()),
                ..WsTransport::default()
            }),
            SecurityConfig::None(NoneSecurity {}),
        );
        let link = build_vless_share_link(&inb, &base_client(), "1.2.3.4").unwrap();
        assert!(link.contains("host=cdn.example.com"), "got: {link}");
    }

    #[test]
    fn xhttp_plain_emits_path_host_mode() {
        let inb = inbound(
            TransportConfig::Xhttp(XhttpTransport {
                path: Some("/upload".into()),
                host: Some("cdn.test".into()),
                mode: Some(XhttpMode::PacketUp),
                ..XhttpTransport::default()
            }),
            SecurityConfig::None(NoneSecurity {}),
        );
        let link = build_vless_share_link(&inb, &base_client(), "1.2.3.4").unwrap();
        assert!(link.contains("type=xhttp"));
        assert!(link.contains("path=%2Fupload"));
        assert!(link.contains("host=cdn.test"));
        assert!(link.contains("mode=packet-up"));
    }

    #[test]
    fn xhttp_padding_obfs_rides_in_extra_param() {
        // Padding obfs is symmetric — the client must mirror it or the
        // connection breaks. It travels in xray's `extra` param.
        let inb = inbound(
            TransportConfig::Xhttp(XhttpTransport {
                path: Some("/x".into()),
                mode: Some(XhttpMode::Auto),
                x_padding_obfs_mode: Some(true),
                x_padding_key: Some("fullbrenched".into()),
                x_padding_header: Some("includedborders3".into()),
                x_padding_placement: Some("cookie".into()),
                x_padding_method: Some("tokenish".into()),
                ..XhttpTransport::default()
            }),
            SecurityConfig::None(NoneSecurity {}),
        );
        let link = build_vless_share_link(&inb, &base_client(), "1.2.3.4").unwrap();
        assert!(link.contains("extra="), "missing extra=: {link}");
        // Field names + values are url-safe, so they survive verbatim inside
        // the url-encoded JSON blob.
        for needle in [
            "xPaddingObfsMode",
            "fullbrenched",
            "includedborders3",
            "cookie",
            "tokenish",
        ] {
            assert!(link.contains(needle), "extra missing {needle}: {link}");
        }
    }

    #[test]
    fn xhttp_without_padding_obfs_omits_extra() {
        let inb = inbound(
            TransportConfig::Xhttp(XhttpTransport {
                path: Some("/x".into()),
                ..XhttpTransport::default()
            }),
            SecurityConfig::None(NoneSecurity {}),
        );
        let link = build_vless_share_link(&inb, &base_client(), "1.2.3.4").unwrap();
        assert!(!link.contains("extra="), "extra should be absent: {link}");
    }

    #[test]
    fn xhttp_session_id_rides_in_extra() {
        // sessionID placement/key are symmetric (server reads the id where the
        // client put it); table/length carry the operator's chosen id format.
        let inb = inbound(
            TransportConfig::Xhttp(XhttpTransport {
                path: Some("/x".into()),
                mode: Some(XhttpMode::Auto),
                session_id_placement: Some("cookie".into()),
                session_id_key: Some("sid".into()),
                session_id_table: Some("hex".into()),
                session_id_length: Some("8-16".into()),
                ..XhttpTransport::default()
            }),
            SecurityConfig::None(NoneSecurity {}),
        );
        let link = build_vless_share_link(&inb, &base_client(), "1.2.3.4").unwrap();
        assert!(link.contains("extra="), "missing extra=: {link}");
        for needle in [
            "sessionIDPlacement",
            "sessionIDKey",
            "sessionIDTable",
            "sessionIDLength",
            "cookie",
            "sid",
            "hex",
            "8-16",
        ] {
            assert!(link.contains(needle), "extra missing {needle}: {link}");
        }
        // padding obfs is off → no padding keys leak into the link
        assert!(
            !link.contains("xPadding"),
            "padding should be absent: {link}"
        );
    }

    #[test]
    fn xhttp_seq_uplink_and_framing_ride_in_extra() {
        // seq / uplink-data placement+key are symmetric wire contracts — the
        // client writes them where the server reads them, so a custom value must
        // reach the client or the server can't reassemble the stream.
        // uplinkHTTPMethod is the verb the client posts with; noGRPCHeader /
        // noSSEHeader are the downlink framing the client must parse the server's
        // way. None of these used to leave the panel.
        let inb = inbound(
            TransportConfig::Xhttp(XhttpTransport {
                path: Some("/x".into()),
                mode: Some(XhttpMode::PacketUp),
                seq_placement: Some("query".into()),
                seq_key: Some("s".into()),
                uplink_data_placement: Some("body".into()),
                uplink_data_key: Some("d".into()),
                uplink_http_method: Some("PUT".into()),
                no_sse_header: Some(true),
                no_grpc_header: Some(true),
                ..XhttpTransport::default()
            }),
            SecurityConfig::None(NoneSecurity {}),
        );
        let link = build_vless_share_link(&inb, &base_client(), "1.2.3.4").unwrap();
        assert!(link.contains("extra="), "missing extra=: {link}");
        for needle in [
            "seqPlacement",
            "seqKey",
            "uplinkDataPlacement",
            "uplinkDataKey",
            "uplinkHTTPMethod",
            "PUT",
            "noGRPCHeader",
            "noSSEHeader",
        ] {
            assert!(link.contains(needle), "extra missing {needle}: {link}");
        }
    }

    #[test]
    fn xhttp_uplink_fields_are_gated_to_packet_up_mode() {
        // xray rejects uplink-data cookie/header placement and a GET method
        // outside packet-up mode. The server builds via proto (no such check),
        // but the client parses the link through infra/conf and would refuse to
        // start — so a non-packet-up link must NOT advertise the uplink group.
        // seq + framing knobs are valid in every mode and still ride.
        let inb = inbound(
            TransportConfig::Xhttp(XhttpTransport {
                path: Some("/x".into()),
                mode: Some(XhttpMode::Auto),
                seq_placement: Some("query".into()),
                seq_key: Some("s".into()),
                uplink_data_placement: Some("cookie".into()),
                uplink_data_key: Some("d".into()),
                uplink_http_method: Some("GET".into()),
                no_sse_header: Some(true),
                ..XhttpTransport::default()
            }),
            SecurityConfig::None(NoneSecurity {}),
        );
        let link = build_vless_share_link(&inb, &base_client(), "1.2.3.4").unwrap();
        for present in ["seqPlacement", "seqKey", "noSSEHeader"] {
            assert!(link.contains(present), "extra missing {present}: {link}");
        }
        for absent in ["uplinkDataPlacement", "uplinkDataKey", "uplinkHTTPMethod"] {
            assert!(
                !link.contains(absent),
                "{absent} must be gated to packet-up mode: {link}"
            );
        }
    }

    #[test]
    fn tls_security_with_ech_config_list_emits_ech_param() {
        // When ECH config list is set on the inbound, the share-link
        // must carry it so clients can embed it in Client Hello without
        // an out-of-band copy-paste from the operator.
        let inb = inbound(
            TransportConfig::Tcp(TcpTransport {}),
            SecurityConfig::Tls(TlsSecurity {
                ech_config_list: Some(
                    "AGX+DQBhAAAgACAl7hyADPfqGyzc3A52Ick5u+Tutenwpn2Eu4m6bJqReQAk".into(),
                ),
                ..TlsSecurity::default()
            }),
        );
        let link = build_vless_share_link(&inb, &base_client(), "1.2.3.4").unwrap();
        assert!(
            link.contains("ech=AGX%2BDQBhAAAgACAl7hyADPfqGyzc3A52Ick5u%2BTutenwpn2Eu4m6bJqReQAk"),
            "missing url-encoded ech=...: {link}"
        );
    }

    #[test]
    fn tls_security_without_ech_omits_ech_param() {
        let inb = inbound(
            TransportConfig::Tcp(TcpTransport {}),
            SecurityConfig::Tls(TlsSecurity::default()),
        );
        let link = build_vless_share_link(&inb, &base_client(), "1.2.3.4").unwrap();
        assert!(!link.contains("ech="), "ech= must not appear: {link}");
    }

    #[test]
    fn tls_security_emits_alpn_sni_fp() {
        let inb = inbound(
            TransportConfig::Ws(WsTransport {
                path: Some("/ws".into()),
                host: Some("ws.example.com".into()),
                ..WsTransport::default()
            }),
            SecurityConfig::Tls(TlsSecurity {
                alpn: Some(vec!["http/1.1".into()]),
                ..TlsSecurity::default()
            }),
        );
        let link = build_vless_share_link(&inb, &base_client(), "1.2.3.4").unwrap();
        assert!(link.contains("security=tls"));
        assert!(link.contains("alpn=http%2F1.1"), "got: {link}");
        // SNI fallback: server_name empty → derived from ws.host.
        assert!(link.contains("sni=ws.example.com"), "got: {link}");
        assert!(link.contains("fp=chrome"));
    }

    #[test]
    fn encryption_none_always_present() {
        let inb = inbound(
            TransportConfig::Tcp(TcpTransport {}),
            SecurityConfig::None(NoneSecurity {}),
        );
        let link = build_vless_share_link(&inb, &base_client(), "1.2.3.4").unwrap();
        assert!(
            link.contains("encryption=none"),
            "missing encryption=none: {link}"
        );
    }

    #[test]
    fn encryption_mlkem_emits_full_dotted_format() {
        let inb = Inbound {
            protocol: ProtocolConfig::Vless(VlessProtocol {
                flow: VlessFlow::None,
                encryption_mode: VlessEncryptionMode::Mlkem768x25519Plus,
                encryption_xor_mode: Some(VlessXorMode::Native),
                encryption_client_key: Some("dDb65JyqgIkUHfWDhf7BgfaXzh55MtSM8yZI01F8pCF".into()),
                ..VlessProtocol::default()
            }),
            ..inbound(
                TransportConfig::Tcp(TcpTransport {}),
                SecurityConfig::None(NoneSecurity {}),
            )
        };
        let link = build_vless_share_link(&inb, &base_client(), "1.2.3.4").unwrap();
        // mlkem768x25519plus.<xor>.0rtt[.<padding>].<client_key>
        assert!(
            link.contains("encryption=mlkem768x25519plus.native.0rtt."),
            "got: {link}"
        );
        assert!(link.contains("dDb65JyqgIkUHfWDhf7BgfaXzh55MtSM8yZI01F8pCF"));
    }

    #[test]
    fn client_flow_overrides_inbound_flow() {
        let inb = inbound(
            TransportConfig::Tcp(TcpTransport {}),
            SecurityConfig::None(NoneSecurity {}),
        );
        let mut cli = base_client();
        cli.flow = Some("xtls-rprx-vision".into());
        let link = build_vless_share_link(&inb, &cli, "1.2.3.4").unwrap();
        assert!(link.contains("flow=xtls-rprx-vision"), "got: {link}");
    }

    #[test]
    fn inbound_tag_url_encoded_in_fragment() {
        // The fragment is the inbound tag; a tag with a space (or other
        // special char) must be URL-encoded so the link stays valid.
        let mut inb = inbound(
            TransportConfig::Tcp(TcpTransport {}),
            SecurityConfig::None(NoneSecurity {}),
        );
        inb.tag = "my inbound".into();
        let link = build_vless_share_link(&inb, &base_client(), "1.2.3.4").unwrap();
        assert!(link.ends_with("#my%20inbound"), "got: {link}");
    }

    // ====================================================================
    // Hysteria 2 share-link tests. Mirror the vless ones in spirit —
    // assert via `contains()` so param ordering can drift without breaking.
    // ====================================================================

    use crate::protocols::hysteria::HysteriaProtocol;
    use crate::security::tls::{TlsCertSource, TlsCertUsage, TlsCertificate};
    use crate::transports::hysteria::{HysteriaMasquerade, HysteriaTransport};

    fn hy_inbound(tls: TlsSecurity) -> Inbound {
        Inbound {
            id: "hy-id".into(),
            tag: "hy-test".into(),
            enabled: true,
            listen: "0.0.0.0".into(),
            port: 8443,
            protocol: ProtocolConfig::Hysteria2(HysteriaProtocol {}),
            transport: TransportConfig::Hysteria(HysteriaTransport {
                auth: None,
                udp_idle_timeout: None,
                masquerade: HysteriaMasquerade::NotFound,
                quic_params: None,
            }),
            security: SecurityConfig::Tls(tls),
            sniffing: Sniffing::default(),
            finalmask: FinalMask::None,
            sockopt: crate::transports::sockopt::SocketOpt::default(),
            created_at: "now".into(),
            updated_at: "now".into(),
        }
    }

    fn tls_with_sni(sni: &str) -> TlsSecurity {
        TlsSecurity {
            // Build_settings rejects an empty list; share-link reads
            // server_name without touching certs, so dummy entries are fine.
            certificates: vec![TlsCertificate {
                source: TlsCertSource::Inline,
                cert: "x".into(),
                key: "x".into(),
                usage: TlsCertUsage::Encipherment,
                ocsp_stapling: 0,
                build_chain: false,
                one_time_loading: true,
            }],
            server_name: Some(sni.to_owned()),
            ..TlsSecurity::default()
        }
    }

    #[test]
    fn hysteria2_basic_link_shape() {
        let inb = hy_inbound(tls_with_sni("hy.example.com"));
        let mut cli = base_client();
        cli.auth = Some("s3cret-pass".into());
        let link = build_share_link(&inb, &cli, "1.2.3.4").unwrap();
        assert!(
            link.starts_with("hysteria2://s3cret-pass@1.2.3.4:8443/?"),
            "got: {link}"
        );
        assert!(link.contains("sni=hy.example.com"), "got: {link}");
        assert!(link.contains("alpn=h3"), "got: {link}");
        assert!(link.contains("insecure=0"), "got: {link}");
        assert!(link.ends_with("#hy-test"), "got: {link}");
    }

    /// A real self-signed Ed25519 leaf (CN=hytest.local). Its DER SHA-256 is
    /// `SELF_SIGNED_PIN` — the same fingerprint verified end-to-end against a
    /// live hysteria2 client.
    const SELF_SIGNED_CERT_PEM: &str = concat!(
        "-----BEGIN CERTIFICATE-----\n",
        "MIIBXDCCAQ6gAwIBAgIUbBWShOjvjt7jprnNwbWfpLtoxZowBQYDK2VwMBcxFTAT\n",
        "BgNVBAMMDGh5dGVzdC5sb2NhbDAeFw0yNjA1MTkxODA2MDNaFw0yNzA1MTkxODA2\n",
        "MDNaMBcxFTATBgNVBAMMDGh5dGVzdC5sb2NhbDAqMAUGAytlcAMhAGF104FI56gI\n",
        "rXgDA4dHtbYzKHh0BSziSLNcX+XdmV6Qo2wwajAdBgNVHQ4EFgQU2wu3StN6KFgY\n",
        "kMLuLwA3ynjoj7EwHwYDVR0jBBgwFoAU2wu3StN6KFgYkMLuLwA3ynjoj7EwDwYD\n",
        "VR0TAQH/BAUwAwEB/zAXBgNVHREEEDAOggxoeXRlc3QubG9jYWwwBQYDK2VwA0EA\n",
        "4aAGEDBVVKSV/8feh9UGBOab9azgujSuUq5O5UxkIBZpYvYhwdFmm6xRq5EgOZnM\n",
        "JOPkdnV3coHkQCi2YXzJDg==\n",
        "-----END CERTIFICATE-----\n",
    );
    const SELF_SIGNED_PIN: &str =
        "ed4f0f4d9e6a17d06190557e3fd919bd0fb257c12abcdd758ef9400ea40d349d";

    fn tls_self_signed(sni: &str, flag: bool) -> TlsSecurity {
        TlsSecurity {
            certificates: vec![TlsCertificate {
                source: TlsCertSource::Inline,
                cert: SELF_SIGNED_CERT_PEM.into(),
                key: "-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----".into(),
                usage: TlsCertUsage::Encipherment,
                ocsp_stapling: 0,
                build_chain: false,
                one_time_loading: true,
            }],
            server_name: Some(sni.to_owned()),
            self_signed: Some(flag),
            ..TlsSecurity::default()
        }
    }

    #[test]
    fn hysteria2_self_signed_emits_cert_pin() {
        let inb = hy_inbound(tls_self_signed("hy.example.com", true));
        let link = build_share_link(&inb, &base_client(), "1.2.3.4").unwrap();
        assert!(
            link.contains(&format!("pinSHA256={SELF_SIGNED_PIN}")),
            "got: {link}"
        );
        // Pinning replaces chain validation — `insecure` stays 0.
        assert!(link.contains("insecure=0"), "got: {link}");
    }

    #[test]
    fn hysteria2_no_pin_without_self_signed_flag() {
        // Same cert, flag off → the pin is not distributed.
        let inb = hy_inbound(tls_self_signed("hy.example.com", false));
        let link = build_share_link(&inb, &base_client(), "1.2.3.4").unwrap();
        assert!(!link.contains("pinSHA256"), "got: {link}");
    }

    #[test]
    fn hysteria2_self_signed_path_cert_is_rejected() {
        // A `Path`-sourced cert isn't read here, so no pin can be derived.
        // Rather than ship a dead link (self-signed + insecure=0 with no pin,
        // which no client can verify), the builder fails loudly.
        let mut tls = tls_self_signed("hy.example.com", true);
        tls.certificates[0].source = TlsCertSource::Path;
        tls.certificates[0].cert = "/etc/xray/hy.crt".into();
        let err = build_share_link(&hy_inbound(tls), &base_client(), "1.2.3.4").unwrap_err();
        assert!(err.to_string().contains("self-signed"), "got: {err}");
    }

    #[test]
    fn hysteria2_salamander_rides_as_standard_obfs() {
        use crate::transports::finalmask::SalamanderParams;
        let mut inb = hy_inbound(tls_with_sni("hy.example.com"));
        inb.finalmask = FinalMask::Salamander(SalamanderParams {
            password: "obfs-pw".into(),
        });
        let link = build_share_link(&inb, &base_client(), "1.2.3.4").unwrap();
        // Salamander is Hysteria 2's native obfs → the standard params every
        // client reads, NOT the xray-specific `fm=`.
        assert!(link.contains("obfs=salamander"), "got: {link}");
        assert!(link.contains("obfs-password=obfs-pw"), "got: {link}");
        assert!(
            !link.contains("fm="),
            "salamander must not also emit fm=: {link}"
        );
    }

    #[test]
    fn hysteria2_noise_rides_as_fm_not_obfs() {
        use crate::transports::finalmask::{NoiseItem, NoiseParams};
        let mut inb = hy_inbound(tls_with_sni("hy.example.com"));
        inb.finalmask = FinalMask::Noise(NoiseParams {
            items: vec![NoiseItem {
                rand_min: Some(5),
                rand_max: Some(10),
                ..NoiseItem::default()
            }],
            ..NoiseParams::default()
        });
        let link = build_share_link(&inb, &base_client(), "1.2.3.4").unwrap();
        // Non-salamander masks stay xray-specific → `fm=`, no `obfs=`.
        assert!(link.contains("fm="), "got: {link}");
        assert!(!link.contains("obfs=salamander"), "got: {link}");
    }

    #[test]
    fn hysteria2_port_hopping_rides_as_mport() {
        use crate::transports::quic::{QuicParams, UdpHop};
        let mut inb = hy_inbound(tls_with_sni("hy.example.com"));
        let TransportConfig::Hysteria(ht) = &mut inb.transport else {
            unreachable!("hy_inbound builds a hysteria transport");
        };
        ht.quic_params = Some(QuicParams {
            udp_hop: Some(UdpHop {
                ports: vec![23929, 23931],
                interval_min: 30,
                interval_max: 30,
            }),
            ..QuicParams::default()
        });
        let link = build_share_link(&inb, &base_client(), "1.2.3.4").unwrap();
        // Ports joined by comma (url-encoded to %2C) → v2rayN's port-range field.
        assert!(link.contains("mport=23929%2C23931"), "got: {link}");
    }

    #[test]
    fn hysteria2_no_mport_without_port_hopping() {
        // The basic fixture has quic_params: None → no port hopping → no mport.
        let inb = hy_inbound(tls_with_sni("hy.example.com"));
        let link = build_share_link(&inb, &base_client(), "1.2.3.4").unwrap();
        assert!(!link.contains("mport="), "got: {link}");
    }

    #[test]
    fn hysteria2_falls_back_to_uuid_when_no_auth() {
        let inb = hy_inbound(tls_with_sni("hy.example.com"));
        // base_client has auth=None — should fall back to the uuid.
        let link = build_share_link(&inb, &base_client(), "1.2.3.4").unwrap();
        assert!(
            link.contains("hysteria2://00000000-0000-0000-0000-000000000001@"),
            "got: {link}"
        );
    }

    #[test]
    fn hysteria2_uses_host_when_sni_unset() {
        let inb = hy_inbound(TlsSecurity {
            certificates: vec![TlsCertificate {
                source: TlsCertSource::Inline,
                cert: "x".into(),
                key: "x".into(),
                usage: TlsCertUsage::Encipherment,
                ocsp_stapling: 0,
                build_chain: false,
                one_time_loading: true,
            }],
            server_name: None,
            ..TlsSecurity::default()
        });
        let link = build_share_link(&inb, &base_client(), "5.6.7.8").unwrap();
        assert!(link.contains("sni=5.6.7.8"), "got: {link}");
    }

    #[test]
    fn hysteria2_url_encodes_special_chars_in_auth() {
        let inb = hy_inbound(tls_with_sni("hy.example.com"));
        let mut cli = base_client();
        cli.auth = Some("p@ss w/rd".into());
        let link = build_share_link(&inb, &cli, "1.2.3.4").unwrap();
        // `@` becomes `%40`, space `%20`, `/` `%2F` — without encoding the
        // `@` in auth would collide with the user@host delimiter and break
        // every client parser.
        assert!(link.contains("hysteria2://p%40ss%20w%2Frd@"), "got: {link}");
    }

    #[test]
    fn hysteria2_errors_if_security_is_not_tls() {
        let mut inb = hy_inbound(tls_with_sni("hy.example.com"));
        inb.security = SecurityConfig::None(NoneSecurity {});
        let err = build_share_link(&inb, &base_client(), "1.2.3.4")
            .unwrap_err()
            .to_string();
        assert!(err.contains("TLS"), "got: {err}");
    }

    #[test]
    fn vless_dispatch_still_works_through_unified_builder() {
        // The unified `build_share_link` dispatches by protocol kind.
        // VLESS path must still produce the historical vless:// shape.
        let inb = inbound(
            TransportConfig::Tcp(TcpTransport {}),
            SecurityConfig::None(NoneSecurity {}),
        );
        let link = build_share_link(&inb, &base_client(), "1.2.3.4").unwrap();
        assert!(link.starts_with("vless://"), "got: {link}");
    }

    // ====================================================================
    // Coverage tests for combinations that were previously implicit.
    // Each one mirrors a realistic operator setup.
    // ====================================================================

    /// CDN-fronted WebSocket+TLS — the canonical "behind Cloudflare" combo.
    #[test]
    fn ws_tls_cdn_fronted_combo() {
        let inb = inbound(
            TransportConfig::Ws(WsTransport {
                path: Some("/api/stream".into()),
                host: Some("cdn.example.com".into()),
                ..WsTransport::default()
            }),
            SecurityConfig::Tls(TlsSecurity {
                server_name: Some("cdn.example.com".into()),
                alpn: Some(vec!["http/1.1".into()]),
                ..TlsSecurity::default()
            }),
        );
        let link = build_vless_share_link(&inb, &base_client(), "1.2.3.4").unwrap();
        assert!(link.contains("type=ws"));
        assert!(link.contains("path=%2Fapi%2Fstream"));
        assert!(link.contains("host=cdn.example.com"));
        assert!(link.contains("security=tls"));
        assert!(link.contains("sni=cdn.example.com"));
        assert!(link.contains("alpn=http%2F1.1"));
        assert!(link.contains("fp=chrome"));
    }

    /// XHTTP+Reality — the "modern Reality" deployment shape.
    #[test]
    fn xhttp_reality_combo() {
        let inb = inbound(
            TransportConfig::Xhttp(XhttpTransport {
                path: Some("/up".into()),
                host: Some("cdn.test".into()),
                mode: Some(XhttpMode::Auto),
                ..XhttpTransport::default()
            }),
            SecurityConfig::Reality(RealitySecurity {
                dest: "www.cloudflare.com:443".into(),
                server_names: vec!["www.cloudflare.com".into()],
                public_key: "pubkey-abc".into(),
                short_ids: vec!["aabbccdd".into()],
                fingerprint: "firefox".into(),
                ..RealitySecurity::default()
            }),
        );
        let link = build_vless_share_link(&inb, &base_client(), "1.2.3.4").unwrap();
        assert!(link.contains("type=xhttp"));
        assert!(link.contains("mode=auto"));
        assert!(link.contains("security=reality"));
        assert!(link.contains("sni=www.cloudflare.com"));
        assert!(link.contains("pbk=pubkey-abc"));
        assert!(link.contains("sid=aabbccdd"));
        assert!(link.contains("fp=firefox"));
    }

    /// XHTTP+TLS — XHTTP behind a real cert (without Reality).
    #[test]
    fn xhttp_tls_combo() {
        let inb = inbound(
            TransportConfig::Xhttp(XhttpTransport {
                path: Some("/up".into()),
                host: Some("real.example.com".into()),
                mode: Some(XhttpMode::StreamOne),
                ..XhttpTransport::default()
            }),
            SecurityConfig::Tls(TlsSecurity {
                alpn: Some(vec!["h2".into(), "http/1.1".into()]),
                ..TlsSecurity::default()
            }),
        );
        let link = build_vless_share_link(&inb, &base_client(), "1.2.3.4").unwrap();
        assert!(link.contains("type=xhttp"));
        assert!(link.contains("mode=stream-one"));
        assert!(link.contains("security=tls"));
        // alpn fallback host → real.example.com (xhttp host).
        assert!(link.contains("sni=real.example.com"));
        assert!(link.contains("alpn=h2%2Chttp%2F1.1"));
    }

    /// Reality with empty fingerprint falls back to "chrome" — the safe default.
    #[test]
    fn reality_empty_fingerprint_defaults_to_chrome() {
        let inb = inbound(
            TransportConfig::Tcp(TcpTransport {}),
            SecurityConfig::Reality(RealitySecurity {
                dest: "x:443".into(),
                server_names: vec!["x".into()],
                public_key: "pk".into(),
                short_ids: vec![],
                fingerprint: String::new(),
                ..RealitySecurity::default()
            }),
        );
        let link = build_vless_share_link(&inb, &base_client(), "1.2.3.4").unwrap();
        assert!(link.contains("fp=chrome"), "got: {link}");
        // Empty short_ids list → sid= with no value (xray-compatible).
        assert!(
            link.contains("sid=&") || link.ends_with("sid="),
            "got: {link}"
        );
    }

    /// Reality with multiple `short_ids`: only the first is emitted (xray
    /// clients accept a single sid per share-link).
    #[test]
    fn reality_multiple_short_ids_first_wins() {
        let inb = inbound(
            TransportConfig::Tcp(TcpTransport {}),
            SecurityConfig::Reality(RealitySecurity {
                dest: "x:443".into(),
                server_names: vec!["x".into(), "y".into()],
                public_key: "pk".into(),
                short_ids: vec!["aabb".into(), "ccdd".into(), "eeff".into()],
                fingerprint: "chrome".into(),
                ..RealitySecurity::default()
            }),
        );
        let link = build_vless_share_link(&inb, &base_client(), "1.2.3.4").unwrap();
        assert!(link.contains("sid=aabb"), "got: {link}");
        assert!(!link.contains("sid=ccdd"));
        // Same "first wins" for server_names → sni=.
        assert!(link.contains("sni=x"));
        assert!(!link.contains("sni=y"));
    }

    /// Reality with no spiderX configured emits the default `spx=/` (URL-
    /// encoded to `%2F`) — the value clients expect when none is set.
    #[test]
    fn reality_empty_spider_x_defaults_to_slash() {
        let inb = inbound(
            TransportConfig::Tcp(TcpTransport {}),
            SecurityConfig::Reality(RealitySecurity {
                dest: "x:443".into(),
                server_names: vec!["x".into()],
                public_key: "pk".into(),
                ..RealitySecurity::default()
            }),
        );
        let link = build_vless_share_link(&inb, &base_client(), "1.2.3.4").unwrap();
        assert!(link.contains("spx=%2F"), "got: {link}");
    }

    /// Operator-set spiderX rides through as `spx=`, URL-encoded.
    #[test]
    fn reality_custom_spider_x_is_emitted_encoded() {
        let inb = inbound(
            TransportConfig::Tcp(TcpTransport {}),
            SecurityConfig::Reality(RealitySecurity {
                dest: "x:443".into(),
                server_names: vec!["x".into()],
                public_key: "pk".into(),
                spider_x: "/crawl?a=b".into(),
                ..RealitySecurity::default()
            }),
        );
        let link = build_vless_share_link(&inb, &base_client(), "1.2.3.4").unwrap();
        assert!(link.contains("spx=%2Fcrawl%3Fa%3Db"), "got: {link}");
    }

    /// An operator-chosen uTLS fingerprint on the standard-TLS path
    /// overrides the historical hard-coded `fp=chrome`.
    #[test]
    fn tls_fingerprint_override_emits_chosen_fp() {
        let inb = inbound(
            TransportConfig::Tcp(TcpTransport {}),
            SecurityConfig::Tls(TlsSecurity {
                server_name: Some("real.example.com".into()),
                fingerprint: Some("firefox".into()),
                ..TlsSecurity::default()
            }),
        );
        let link = build_vless_share_link(&inb, &base_client(), "1.2.3.4").unwrap();
        assert!(link.contains("fp=firefox"), "got: {link}");
        assert!(!link.contains("fp=chrome"), "got: {link}");
    }

    /// TLS with no fingerprint set still defaults to `fp=chrome`,
    /// preserving the pre-existing behaviour for untouched inbounds.
    #[test]
    fn tls_no_fingerprint_defaults_to_chrome() {
        let inb = inbound(
            TransportConfig::Tcp(TcpTransport {}),
            SecurityConfig::Tls(TlsSecurity {
                server_name: Some("real.example.com".into()),
                ..TlsSecurity::default()
            }),
        );
        let link = build_vless_share_link(&inb, &base_client(), "1.2.3.4").unwrap();
        assert!(link.contains("fp=chrome"), "got: {link}");
    }

    /// VLESS Vision over plain TLS (not Reality). xray supports this combo
    /// even if Reality is more common with Vision in the wild.
    #[test]
    fn vless_vision_over_plain_tls() {
        let mut inb = inbound(
            TransportConfig::Tcp(TcpTransport {}),
            SecurityConfig::Tls(TlsSecurity {
                server_name: Some("real.example.com".into()),
                ..TlsSecurity::default()
            }),
        );
        inb.protocol = vless(VlessFlow::XtlsRprxVision);
        let link = build_vless_share_link(&inb, &base_client(), "1.2.3.4").unwrap();
        assert!(link.contains("type=tcp"));
        assert!(link.contains("security=tls"));
        assert!(link.contains("flow=xtls-rprx-vision"));
        assert!(link.contains("sni=real.example.com"));
    }

    /// ML-KEM encryption with operator-supplied padding string + xorpub mode.
    #[test]
    fn encryption_mlkem_with_padding_and_xorpub() {
        let inb = Inbound {
            protocol: ProtocolConfig::Vless(VlessProtocol {
                flow: VlessFlow::None,
                encryption_mode: VlessEncryptionMode::Mlkem768x25519Plus,
                encryption_xor_mode: Some(VlessXorMode::Xorpub),
                encryption_padding: Some("100-200".into()),
                encryption_client_key: Some("pubkey".into()),
                ..VlessProtocol::default()
            }),
            ..inbound(
                TransportConfig::Tcp(TcpTransport {}),
                SecurityConfig::None(NoneSecurity {}),
            )
        };
        let link = build_vless_share_link(&inb, &base_client(), "1.2.3.4").unwrap();
        assert!(
            link.contains("encryption=mlkem768x25519plus.xorpub.0rtt.100-200.pubkey"),
            "got: {link}"
        );
    }

    /// VLESS+TLS+ECH — the new feature should appear regardless of transport.
    #[test]
    fn vless_tls_with_ech() {
        let inb = inbound(
            TransportConfig::Ws(WsTransport {
                path: Some("/ws".into()),
                ..WsTransport::default()
            }),
            SecurityConfig::Tls(TlsSecurity {
                server_name: Some("h.example.com".into()),
                ech_config_list: Some("ECH_BYTES".into()),
                ..TlsSecurity::default()
            }),
        );
        let link = build_vless_share_link(&inb, &base_client(), "1.2.3.4").unwrap();
        assert!(link.contains("type=ws"));
        assert!(link.contains("security=tls"));
        assert!(link.contains("ech=ECH_BYTES"), "got: {link}");
    }

    /// Hysteria 2 must NOT advertise ECH even when the operator set it on the
    /// TLS layer: xray's hy2 QUIC listener doesn't serve ECH, so a client that
    /// honours `ech=` attempts Encrypted Client Hello against a server that can't
    /// answer and the node goes dead (v2rayN `-1`). Verified end-to-end against a
    /// live server. ECH stays on the vless/TLS builders where it works.
    #[test]
    fn hysteria2_omits_ech_config_list() {
        let inb = hy_inbound(TlsSecurity {
            server_name: Some("hy.example.com".into()),
            ech_config_list: Some("HY_ECH".into()),
            ..tls_with_sni("hy.example.com")
        });
        let link = build_share_link(&inb, &base_client(), "1.2.3.4").unwrap();
        assert!(!link.contains("ech="), "hy2 must not carry ech: {link}");
    }

    /// IPv6 host in vless:// URL must be bracketed per RFC 3986.
    #[test]
    fn vless_ipv6_host_is_bracketed() {
        let inb = inbound(
            TransportConfig::Tcp(TcpTransport {}),
            SecurityConfig::None(NoneSecurity {}),
        );
        let link = build_vless_share_link(&inb, &base_client(), "2001:db8::1").unwrap();
        assert!(
            link.starts_with("vless://00000000-0000-0000-0000-000000000001@[2001:db8::1]:8443?"),
            "got: {link}"
        );
    }

    /// Hysteria 2 IPv6 host — same bracketing rule.
    #[test]
    fn hysteria2_ipv6_host_is_bracketed() {
        let inb = hy_inbound(tls_with_sni("hy.example.com"));
        let mut cli = base_client();
        cli.auth = Some("pass".into());
        let link = build_share_link(&inb, &cli, "2001:db8::1").unwrap();
        assert!(
            link.starts_with("hysteria2://pass@[2001:db8::1]:8443/?"),
            "got: {link}"
        );
    }

    /// Already-bracketed host must not be re-wrapped.
    #[test]
    fn already_bracketed_ipv6_passes_through() {
        let inb = inbound(
            TransportConfig::Tcp(TcpTransport {}),
            SecurityConfig::None(NoneSecurity {}),
        );
        let link = build_vless_share_link(&inb, &base_client(), "[2001:db8::1]").unwrap();
        // Must NOT produce "[[2001:db8::1]]".
        assert!(link.contains("@[2001:db8::1]:"), "got: {link}");
        assert!(!link.contains("[["), "got: {link}");
    }

    /// IPv4 host stays unbracketed — `url_host` only wraps colon-containing hosts.
    #[test]
    fn ipv4_host_not_bracketed() {
        let inb = inbound(
            TransportConfig::Tcp(TcpTransport {}),
            SecurityConfig::None(NoneSecurity {}),
        );
        let link = build_vless_share_link(&inb, &base_client(), "203.0.113.5").unwrap();
        assert!(link.contains("@203.0.113.5:8443?"), "got: {link}");
        assert!(!link.contains('['), "got: {link}");
    }

    /// DNS host (no colons) also passes through unbracketed.
    #[test]
    fn dns_host_not_bracketed() {
        let inb = inbound(
            TransportConfig::Tcp(TcpTransport {}),
            SecurityConfig::None(NoneSecurity {}),
        );
        let link = build_vless_share_link(&inb, &base_client(), "vpn.example.com").unwrap();
        assert!(link.contains("@vpn.example.com:8443?"), "got: {link}");
        assert!(!link.contains('['), "got: {link}");
    }

    // ---- FinalMask `fm=` wire-format regression tests ----
    //
    // The shape must match xray-core's `streamSettings.finalmask` JSON
    // (`infra/conf/transport_internet.go`: `Tcp []Mask json:"tcp"`,
    // `Udp []Mask json:"udp"`). v2rayN (`BaseFmt.cs`) URL-decodes the
    // `fm=` value and writes it verbatim into the generated client
    // config. Any drift from `{tcp:[…],udp:[…]}` means subscriptions
    // silently lose FinalMask client-side and connections fail with
    // mysterious handshake mismatches.

    use crate::transports::finalmask::{
        FinalMask, FragmentParams, NoiseItem, NoiseParams, SudokuParams,
    };

    /// Pull the `fm=` parameter out of a share-link, URL-decode, and
    /// parse the embedded JSON. Returns the JSON body for assertions.
    fn extract_fm(link: &str) -> serde_json::Value {
        let q = link.split_once('?').expect("query").1;
        let q = q.split_once('#').map_or(q, |(q, _)| q);
        let raw = q
            .split('&')
            .find_map(|kv| kv.strip_prefix("fm="))
            .expect("fm= present");
        let decoded = urlencoding::decode(raw).expect("url-decode").into_owned();
        serde_json::from_str(&decoded).expect("valid JSON")
    }

    #[test]
    fn fm_fragment_emits_tcp_only_in_v2rayn_shape() {
        let mut inb = inbound(
            TransportConfig::Tcp(TcpTransport {}),
            SecurityConfig::None(NoneSecurity {}),
        );
        inb.finalmask = FinalMask::Fragment(FragmentParams {
            lengths_min: vec![100],
            lengths_max: vec![200],
            packets_from: Some(1),
            packets_to: Some(1),
            ..FragmentParams::default()
        });
        let link = build_vless_share_link(&inb, &base_client(), "1.2.3.4").unwrap();
        let v = extract_fm(&link);
        assert_eq!(v["tcp"][0]["type"], "fragment");
        // Conf-shape: `packets` string + `lengths`/`delays` arrays of "min-max"
        // strings, NOT proto field names. xray's FragmentMask parses these;
        // `lengthsMin`/`packetsFrom` would be ignored and the config rejected.
        // packets (1,1) → "1-1".
        assert_eq!(
            v["tcp"][0]["settings"]["lengths"],
            serde_json::json!(["100-200"])
        );
        assert_eq!(v["tcp"][0]["settings"]["packets"], "1-1");
        assert_eq!(v["tcp"][0]["settings"]["maxSplit"], "0-0");
        // The proto field names must be gone, or xray will choke on this config.
        assert!(v["tcp"][0]["settings"]["lengthsMin"].is_null());
        // Fragment is TCP-only — udp slot must be present but empty.
        assert_eq!(v["udp"], serde_json::json!([]));
    }

    #[test]
    fn fm_fragment_packets_0_1_maps_to_tlshello() {
        let mut inb = inbound(
            TransportConfig::Tcp(TcpTransport {}),
            SecurityConfig::None(NoneSecurity {}),
        );
        inb.finalmask = FinalMask::Fragment(FragmentParams {
            lengths_min: vec![5],
            lengths_max: vec![20],
            packets_from: Some(0),
            packets_to: Some(1),
            ..FragmentParams::default()
        });
        let link = build_vless_share_link(&inb, &base_client(), "1.2.3.4").unwrap();
        let v = extract_fm(&link);
        // packets (0,1) is the conf "tlshello" shortcut — the common DPI-bypass
        // mode that fragments only the TLS ClientHello.
        assert_eq!(v["tcp"][0]["settings"]["packets"], "tlshello");
        assert_eq!(
            v["tcp"][0]["settings"]["lengths"],
            serde_json::json!(["5-20"])
        );
    }

    #[test]
    fn fm_noise_emits_udp_only_in_v2rayn_shape() {
        let mut inb = inbound(
            TransportConfig::Tcp(TcpTransport {}),
            SecurityConfig::None(NoneSecurity {}),
        );
        inb.finalmask = FinalMask::Noise(NoiseParams {
            items: vec![NoiseItem {
                packet_hex: "deadbeef".into(),
                // rand is supplied too, but a packet wins: xray rejects an item
                // that carries both a packet and rand.To > 0, so we drop rand.
                rand_min: Some(5),
                rand_max: Some(10),
                ..NoiseItem::default()
            }],
            ..NoiseParams::default()
        });
        let link = build_vless_share_link(&inb, &base_client(), "1.2.3.4").unwrap();
        let v = extract_fm(&link);
        assert_eq!(v["tcp"], serde_json::json!([]));
        assert_eq!(v["udp"][0]["type"], "noise");
        // Conf-shape: nested {reset, noise:[Item]} — NOT a flat {packetHex,…}
        // object (which xray would parse to an empty noise list = no-op).
        assert_eq!(v["udp"][0]["settings"]["reset"], "0-0");
        assert_eq!(v["udp"][0]["settings"]["noise"][0]["type"], "hex");
        assert_eq!(v["udp"][0]["settings"]["noise"][0]["packet"], "deadbeef");
        // packet present → rand must be absent (mutually exclusive in xray).
        assert!(v["udp"][0]["settings"]["noise"][0]["rand"].is_null());
        assert!(v["udp"][0]["settings"]["packetHex"].is_null());
    }

    #[test]
    fn fm_noise_multi_item_emits_ordered_list_with_delay() {
        let mut inb = inbound(
            TransportConfig::Tcp(TcpTransport {}),
            SecurityConfig::None(NoneSecurity {}),
        );
        inb.finalmask = FinalMask::Noise(NoiseParams {
            items: vec![
                NoiseItem {
                    packet_hex: "deadbeef".into(),
                    delay_min: Some(1),
                    delay_max: Some(2),
                    ..NoiseItem::default()
                },
                // Blank draft row — dropped from the emitted list.
                NoiseItem::default(),
                NoiseItem {
                    rand_min: Some(4),
                    rand_max: Some(8),
                    ..NoiseItem::default()
                },
            ],
            ..NoiseParams::default()
        });
        let link = build_vless_share_link(&inb, &base_client(), "1.2.3.4").unwrap();
        let v = extract_fm(&link);
        let noise = &v["udp"][0]["settings"]["noise"];
        assert_eq!(
            noise.as_array().map(Vec::len),
            Some(2),
            "blank row dropped: {noise}"
        );
        // Item 0: literal + its delay.
        assert_eq!(noise[0]["type"], "hex");
        assert_eq!(noise[0]["packet"], "deadbeef");
        assert_eq!(noise[0]["delay"], "1-2");
        // Item 1: random mode, no delay key emitted.
        assert_eq!(noise[1]["rand"], "4-8");
        assert!(noise[1]["delay"].is_null(), "no delay set → no delay key");
    }

    #[test]
    fn fm_noise_rand_only_emits_rand_range() {
        let mut inb = inbound(
            TransportConfig::Tcp(TcpTransport {}),
            SecurityConfig::None(NoneSecurity {}),
        );
        inb.finalmask = FinalMask::Noise(NoiseParams {
            items: vec![NoiseItem {
                rand_min: Some(5),
                rand_max: Some(10),
                ..NoiseItem::default()
            }],
            reset_min: Some(3),
            reset_max: Some(7),
        });
        let link = build_vless_share_link(&inb, &base_client(), "1.2.3.4").unwrap();
        let v = extract_fm(&link);
        // No packet → the item carries a `rand` "min-max" range instead.
        assert_eq!(v["udp"][0]["settings"]["reset"], "3-7");
        assert_eq!(v["udp"][0]["settings"]["noise"][0]["rand"], "5-10");
        assert!(v["udp"][0]["settings"]["noise"][0]["packet"].is_null());
    }

    /// The operator may type `0x`, colons, commas or whitespace in a literal
    /// packet (the UI regex/tooltip invite it) and the server decodes it
    /// relaxed. The `fm=` MUST ship CANONICAL even-length hex — xray's client
    /// parses `packet` with a strict `hex.DecodeString` that rejects all of
    /// those and would fail to load the whole node.
    #[test]
    fn fm_noise_canonicalizes_literal_hex() {
        let mut inb = inbound(
            TransportConfig::Tcp(TcpTransport {}),
            SecurityConfig::None(NoneSecurity {}),
        );
        inb.finalmask = FinalMask::Noise(NoiseParams {
            items: vec![NoiseItem {
                packet_hex: "0xDE:ad be,ef".into(),
                ..NoiseItem::default()
            }],
            ..NoiseParams::default()
        });
        let link = build_vless_share_link(&inb, &base_client(), "1.2.3.4").unwrap();
        let v = extract_fm(&link);
        assert_eq!(
            v["udp"][0]["settings"]["noise"][0]["packet"], "deadbeef",
            "fm= must carry clean hex, not the raw operator string"
        );
    }

    /// A partially-filled random range (min set, max blank → 0) is sorted, so
    /// the `fm=` and the server proto agree instead of one emitting an empty
    /// datagram and the other real random bytes.
    #[test]
    fn fm_noise_partial_rand_range_is_sorted() {
        let mut inb = inbound(
            TransportConfig::Tcp(TcpTransport {}),
            SecurityConfig::None(NoneSecurity {}),
        );
        inb.finalmask = FinalMask::Noise(NoiseParams {
            items: vec![NoiseItem {
                rand_min: Some(5),
                rand_max: None,
                ..NoiseItem::default()
            }],
            ..NoiseParams::default()
        });
        let link = build_vless_share_link(&inb, &base_client(), "1.2.3.4").unwrap();
        let v = extract_fm(&link);
        assert_eq!(v["udp"][0]["settings"]["noise"][0]["rand"], "0-5");
    }

    #[test]
    fn fm_sudoku_emits_both_sides_same_layer() {
        let mut inb = inbound(
            TransportConfig::Tcp(TcpTransport {}),
            SecurityConfig::None(NoneSecurity {}),
        );
        inb.finalmask = FinalMask::Sudoku(SudokuParams {
            password: "secret".into(),
            ascii: "prefer_entropy".into(),
            ..SudokuParams::default()
        });
        let link = build_vless_share_link(&inb, &base_client(), "1.2.3.4").unwrap();
        let v = extract_fm(&link);
        assert_eq!(v["tcp"][0]["type"], "sudoku");
        assert_eq!(v["udp"][0]["type"], "sudoku");
        assert_eq!(v["tcp"][0]["settings"]["password"], "secret");
        assert_eq!(v["udp"][0]["settings"]["password"], "secret");
    }

    #[test]
    fn fm_none_omits_param_entirely() {
        let inb = inbound(
            TransportConfig::Tcp(TcpTransport {}),
            SecurityConfig::None(NoneSecurity {}),
        );
        let link = build_vless_share_link(&inb, &base_client(), "1.2.3.4").unwrap();
        assert!(!link.contains("fm="), "got: {link}");
    }

    /// Defence-in-depth: the legacy base64-encoded `{"type":"…"}` shape
    /// we used to emit would parse as JSON in v2rayN but xray-core would
    /// then ignore it (no `tcp`/`udp` keys). The decoded blob must be
    /// JSON with both top-level keys.
    #[test]
    fn fm_blob_is_canonical_finalmask_json() {
        let mut inb = inbound(
            TransportConfig::Tcp(TcpTransport {}),
            SecurityConfig::None(NoneSecurity {}),
        );
        inb.finalmask = FinalMask::Fragment(FragmentParams {
            lengths_min: vec![100],
            lengths_max: vec![200],
            ..FragmentParams::default()
        });
        let link = build_vless_share_link(&inb, &base_client(), "1.2.3.4").unwrap();
        // A `{tcp:..}` JSON URL-encodes to start with `%7B%22tcp%22`,
        // whereas base64-no-pad starts with `ey` (`{` → base64).
        let fm = link.split_once("fm=").unwrap().1.split('&').next().unwrap();
        assert!(
            fm.starts_with("%7B"),
            "fm should be url-encoded JSON, got: {fm}"
        );
        // Round-trip through URL-decode + JSON-parse to lock the shape: both
        // `tcp` and `udp` MUST exist as arrays, regardless of which one is
        // populated. A regression that drops a slot or wraps the payload
        // differently (e.g. raw protobuf) would fail one of these.
        let v = extract_fm(&link);
        assert!(v.is_object(), "not a JSON object: {v}");
        assert!(v["tcp"].is_array(), "tcp not array: {v}");
        assert!(v["udp"].is_array(), "udp not array: {v}");
        assert_eq!(v.as_object().unwrap().len(), 2, "extra top-level keys: {v}");
    }
}
