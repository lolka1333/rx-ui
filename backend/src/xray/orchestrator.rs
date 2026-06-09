//! Composes protocol + transport + security + sniffing into xray's
//! `InboundHandlerConfig` proto. Single entry point the API and the
//! reconciliation loop both go through when they need an `AddInbound`
//! payload.
//!
//! The orchestrator knows nothing about specific protocols/transports/
//! security layers — it just dispatches via the trait objects exposed
//! by `ProtocolConfig::as_protocol()` & friends. Adding a new variant
//! anywhere in the protocol/transport/security trees doesn't require
//! changes here.

use crate::models::{Client, Inbound, Sniffing};
use crate::transports::finalmask::FinalMaskScope;
use crate::xray::proto::xray::app::proxyman::{ReceiverConfig, SniffingConfig};
use crate::xray::proto::xray::common::geodata::{
    Cidr, CidrRule, Domain, DomainRule, IpRule, domain::Type as DomainType, domain_rule, ip_rule,
};
use crate::xray::proto::xray::common::net::{IpOrDomain, PortList, PortRange, ip_or_domain};
use crate::xray::proto::xray::common::serial::TypedMessage;
use crate::xray::proto::xray::core::InboundHandlerConfig;
use crate::xray::proto::xray::transport::internet::StreamConfig;

const TYPE_RECEIVER_CONFIG: &str = "xray.app.proxyman.ReceiverConfig";

/// Build the `InboundHandlerConfig` proto from an `Inbound` + its
/// enabled-only client list. Caller filters out disabled clients —
/// disabled rows stay in the panel DB but are absent from xray's
/// in-memory state, so disabling is effectively a soft-delete from
/// the wire perspective.
pub fn inbound_to_handler_config(
    inb: &Inbound,
    clients: &[Client],
) -> anyhow::Result<InboundHandlerConfig> {
    let protocol = inb.protocol.as_protocol();
    let transport = inb.transport.as_transport();
    let security = inb.security.as_security();

    // Per-user proto built once per client, then ownership-moved into
    // the protocol-specific proxy_settings message.
    let users = clients
        .iter()
        .filter(|c| c.enabled)
        .map(|c| protocol.build_user(c))
        .collect::<anyhow::Result<Vec<_>>>()?;

    // FinalMask wires the server's socket masks. Sudoku is a symmetric,
    // stateful cipher → it runs on both sides (fills both slots). Noise is
    // UDP-only. Fragment (the only Tcp-scope mask) is the odd one out: it is
    // *asymmetric*. The client fragments its own ClientHello (shipped via the
    // share-link's `fm=`); the server just reassembles over TCP, so a
    // server-side fragment wrapper is pointless — and under Reality it is
    // fatal: xray panics `*fragment.fragmentConn is not reality.CloseWriteConn`
    // because Reality type-asserts CloseWrite on the un-spliced server conn.
    // So Fragment never enters the server's tcpmasks; it is client-only.
    let (tcpmasks, udpmasks) = match inb.finalmask.to_typed_message() {
        Some((m, FinalMaskScope::Both)) => (vec![m.clone()], vec![m]),
        Some((m, FinalMaskScope::Udp)) => (Vec::new(), vec![m]),
        // Fragment (Tcp scope) is client-only — see the note above — so it
        // contributes no server-side mask, same as an inactive mask.
        Some((_, FinalMaskScope::Tcp)) | None => (Vec::new(), Vec::new()),
    };

    // Stream settings = transport + security composed.
    let stream_settings = StreamConfig {
        protocol_name: transport.xray_protocol_name().to_owned(),
        transport_settings: inb.transport.build_xray_transport_settings()?,
        security_type: security.xray_type_url().to_owned(),
        security_settings: security
            .build_settings()?
            .map_or_else(Vec::new, |msg| vec![msg]),
        // QUIC-based transports (Hysteria 2) populate this; others
        // return None from the trait default and leave it unset.
        quic_params: transport.quic_params_proto(),
        tcpmasks,
        udpmasks,
        // Socket options (trustedXForwardedFor / keepalive / mptcp).
        // `None` for an untouched inbound → no sockopt block, identical
        // wire output to before this field existed.
        socket_settings: inb.sockopt.to_proto(),
        ..StreamConfig::default()
    };

    let receiver = ReceiverConfig {
        port_list: Some(PortList {
            range: vec![PortRange {
                from: u32::from(inb.port),
                to: u32::from(inb.port),
            }],
        }),
        listen: Some(parse_listen_address(&inb.listen)),
        stream_settings: Some(stream_settings),
        receive_original_destination: false,
        sniffing_settings: Some(SniffingConfig {
            enabled: inb.sniffing.enabled,
            destination_override: inb.sniffing.dest_override.clone(),
            domains_excluded: build_domain_rules(&inb.sniffing.domains_excluded)?,
            ips_excluded: build_ip_rules(&inb.sniffing.ips_excluded)?,
            metadata_only: inb.sniffing.metadata_only,
            route_only: inb.sniffing.route_only,
        }),
    };

    let proxy = protocol.build_proxy_settings(users)?;
    let receiver_msg = TypedMessage {
        r#type: TYPE_RECEIVER_CONFIG.to_owned(),
        value: prost::Message::encode_to_vec(&receiver),
    };

    Ok(InboundHandlerConfig {
        tag: inb.tag.clone(),
        receiver_settings: Some(receiver_msg),
        proxy_settings: Some(proxy),
    })
}

/// Parse the `listen` column into xray's `IPOrDomain` oneof. Accepts
/// dotted-quad / IPv6 / domain — `parse::<IpAddr>` disambiguates. The
/// domain fallback can't fail, so this returns `IpOrDomain` directly
/// rather than wrapping in `Result`.
fn parse_listen_address(s: &str) -> IpOrDomain {
    use std::net::IpAddr;
    let address = match s.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => ip_or_domain::Address::Ip(v4.octets().to_vec()),
        Ok(IpAddr::V6(v6)) => ip_or_domain::Address::Ip(v6.octets().to_vec()),
        Err(_) => ip_or_domain::Address::Domain(s.to_owned()),
    };
    IpOrDomain {
        address: Some(address),
    }
}

/// Convert operator-entered sniffing domain-exclusion strings into xray
/// `DomainRule`s, mirroring xray's conf parser (`parseCustomDomainRule`,
/// default type = Substr). Recognises the `full:` / `domain:` / `regexp:` /
/// `keyword:` / `dotless:` prefixes; a bare value is a substring match.
/// `geosite:` / `ext:` external rules are rejected — validating them needs
/// geosite.dat loaded, which the panel doesn't do for sniffing exclusions.
fn build_domain_rules(domains: &[String]) -> anyhow::Result<Vec<DomainRule>> {
    domains.iter().map(|d| build_one_domain_rule(d)).collect()
}

fn build_one_domain_rule(raw: &str) -> anyhow::Result<DomainRule> {
    let r = raw.trim();
    anyhow::ensure!(!r.is_empty(), "empty domain exclusion");
    anyhow::ensure!(
        !(r.starts_with("geosite:") || r.starts_with("ext:") || r.starts_with("ext-domain:")),
        "geosite/ext domain rules aren't supported in sniffing exclusions: {r}"
    );
    let (ty, value) = if let Some(v) = r.strip_prefix("regexp:") {
        (DomainType::Regex, v.to_owned())
    } else if let Some(v) = r.strip_prefix("domain:") {
        (DomainType::Domain, v.to_owned())
    } else if let Some(v) = r.strip_prefix("full:") {
        (DomainType::Full, v.to_owned())
    } else if let Some(v) = r.strip_prefix("keyword:") {
        (DomainType::Substr, v.to_owned())
    } else if let Some(v) = r.strip_prefix("dotless:") {
        let value = if v.is_empty() {
            "^[^.]*$".to_owned()
        } else if v.contains('.') {
            anyhow::bail!("substr in dotless rule should not contain a dot: {r}");
        } else {
            format!("^[^.]*{v}[^.]*$")
        };
        (DomainType::Regex, value)
    } else {
        (DomainType::Substr, r.to_owned())
    };
    Ok(DomainRule {
        value: Some(domain_rule::Value::Custom(Domain {
            r#type: ty as i32,
            value,
            attribute: Vec::new(),
        })),
    })
}

/// Convert operator-entered sniffing IP-exclusion strings into xray `IpRule`s,
/// mirroring `parseCustomIPRule`: a CIDR (or bare IP, treated as /32 or /128)
/// with an optional leading `!` toggling reverse-match. `geoip:` / `ext:`
/// external rules are rejected (same reason as domains).
fn build_ip_rules(ips: &[String]) -> anyhow::Result<Vec<IpRule>> {
    ips.iter().map(|s| build_one_ip_rule(s)).collect()
}

fn build_one_ip_rule(raw: &str) -> anyhow::Result<IpRule> {
    let mut s = raw.trim();
    anyhow::ensure!(!s.is_empty(), "empty ip exclusion");
    // Leading `!`(s) toggle reverse-match — xray's `cutReversePrefix`.
    let mut reverse = false;
    while let Some(rest) = s.strip_prefix('!') {
        reverse = !reverse;
        s = rest;
    }
    anyhow::ensure!(
        !(s.starts_with("geoip:") || s.starts_with("ext:") || s.starts_with("ext-ip:")),
        "geoip/ext ip rules aren't supported in sniffing exclusions: {raw}"
    );
    Ok(IpRule {
        value: Some(ip_rule::Value::Custom(CidrRule {
            cidr: Some(parse_cidr(s)?),
            reverse_match: reverse,
        })),
    })
}

fn parse_cidr(s: &str) -> anyhow::Result<Cidr> {
    let (ip_str, prefix_str) = s.split_once('/').map_or((s, None), |(i, p)| (i, Some(p)));
    let ip: std::net::IpAddr = ip_str
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid IP address: {ip_str}"))?;
    let (bytes, max_prefix) = match ip {
        std::net::IpAddr::V4(v4) => (v4.octets().to_vec(), 32_u32),
        std::net::IpAddr::V6(v6) => (v6.octets().to_vec(), 128_u32),
    };
    let prefix = match prefix_str {
        None => max_prefix,
        Some(p) => {
            let parsed: u32 = p
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid CIDR prefix length: {p}"))?;
            anyhow::ensure!(
                parsed <= max_prefix,
                "CIDR prefix length {parsed} exceeds max {max_prefix}"
            );
            parsed
        }
    };
    Ok(Cidr { ip: bytes, prefix })
}

/// Validate the sniffing exclusion lists without building the whole handler
/// config. The API layer calls this BEFORE writing the inbound row so a bad
/// entry (e.g. a malformed CIDR) is rejected with a 4xx up front, instead of
/// passing the INSERT and only failing later at `AddInbound` — which would
/// leave a half-created inbound in the DB that breaks every reconcile. Runs
/// exactly the same conversion `inbound_to_handler_config` does.
pub fn validate_sniffing(sniffing: &Sniffing) -> anyhow::Result<()> {
    build_domain_rules(&sniffing.domains_excluded)?;
    build_ip_rules(&sniffing.ips_excluded)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    //! Verify the orchestrator threads the sniffing `route_only` flag into
    //! xray's `ReceiverConfig.SniffingConfig` (the field rides in the gRPC
    //! inbound config, not the share-link, so it needs its own coverage).
    use super::*;
    use crate::models::Sniffing;
    use crate::protocols::ProtocolConfig;
    use crate::protocols::vless::{VlessEncryptionMode, VlessFlow, VlessProtocol};
    use crate::security::{NoneSecurity, SecurityConfig};
    use crate::transports::TransportConfig;
    use crate::transports::finalmask::FinalMask;
    use crate::transports::sockopt::SocketOpt;
    use crate::transports::tcp::TcpTransport;
    use prost::Message as _;

    fn client() -> Client {
        Client {
            id: "cid".into(),
            inbound_id: "id-x".into(),
            email: "u@test".into(),
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

    fn inbound_with_sniffing(sniffing: Sniffing) -> Inbound {
        Inbound {
            id: "id-x".into(),
            tag: "t".into(),
            enabled: true,
            listen: "0.0.0.0".into(),
            port: 8443,
            protocol: ProtocolConfig::Vless(VlessProtocol {
                flow: VlessFlow::None,
                encryption_mode: VlessEncryptionMode::None,
                ..VlessProtocol::default()
            }),
            transport: TransportConfig::Tcp(TcpTransport {}),
            security: SecurityConfig::None(NoneSecurity {}),
            sniffing,
            finalmask: FinalMask::None,
            sockopt: SocketOpt::default(),
            created_at: "now".into(),
            updated_at: "now".into(),
        }
    }

    /// Decode the `ReceiverConfig` back out of the handler config and
    /// return its `SniffingConfig`.
    fn decoded_sniffing(inb: &Inbound) -> SniffingConfig {
        let cfg = inbound_to_handler_config(inb, &[client()]).unwrap();
        let msg = cfg.receiver_settings.unwrap();
        let receiver = ReceiverConfig::decode(&msg.value[..]).unwrap();
        receiver.sniffing_settings.unwrap()
    }

    #[test]
    fn sniffing_options_reach_receiver_config() {
        let sniff = decoded_sniffing(&inbound_with_sniffing(Sniffing {
            enabled: true,
            dest_override: vec!["tls".to_owned()],
            route_only: true,
            metadata_only: true,
            domains_excluded: vec!["dest.example.com".to_owned()],
            ips_excluded: vec!["10.0.0.0/8".to_owned()],
        }));
        assert!(sniff.enabled);
        assert!(
            sniff.route_only,
            "route_only must propagate into xray's SniffingConfig"
        );
        assert!(
            sniff.metadata_only,
            "metadata_only must propagate into xray's SniffingConfig"
        );
        // Bare domain → a custom Substr (keyword) rule.
        assert_eq!(sniff.domains_excluded.len(), 1);
        let Some(domain_rule::Value::Custom(d)) = &sniff.domains_excluded[0].value else {
            panic!("expected a custom domain rule");
        };
        assert_eq!(d.value, "dest.example.com");
        assert_eq!(d.r#type, DomainType::Substr as i32);
        // CIDR → a custom CidrRule with 4-byte IP + prefix, reverse off.
        assert_eq!(sniff.ips_excluded.len(), 1);
        let Some(ip_rule::Value::Custom(c)) = &sniff.ips_excluded[0].value else {
            panic!("expected a custom ip rule");
        };
        let cidr = c.cidr.as_ref().expect("cidr present");
        assert_eq!(cidr.ip, vec![10, 0, 0, 0]);
        assert_eq!(cidr.prefix, 8);
        assert!(!c.reverse_match);
    }

    #[test]
    fn domain_rule_prefixes_map_to_xray_types() {
        let cases = [
            ("full:api.example.com", DomainType::Full, "api.example.com"),
            ("domain:example.com", DomainType::Domain, "example.com"),
            ("regexp:^x.*$", DomainType::Regex, "^x.*$"),
            ("keyword:track", DomainType::Substr, "track"),
            ("plain.example", DomainType::Substr, "plain.example"),
        ];
        for (input, want_ty, want_val) in cases {
            let rule = build_one_domain_rule(input).unwrap();
            let Some(domain_rule::Value::Custom(d)) = rule.value else {
                panic!("expected custom rule for {input}");
            };
            assert_eq!(d.r#type, want_ty as i32, "type for {input}");
            assert_eq!(d.value, want_val, "value for {input}");
        }
        // geosite/ext are rejected; dotless without a dot becomes a regex.
        assert!(build_one_domain_rule("geosite:google").is_err());
        let Some(domain_rule::Value::Custom(d)) =
            build_one_domain_rule("dotless:cn").unwrap().value
        else {
            panic!("expected custom dotless rule");
        };
        assert_eq!(d.r#type, DomainType::Regex as i32);
        assert_eq!(d.value, "^[^.]*cn[^.]*$");
    }

    #[test]
    fn ip_rule_parses_cidr_and_reverse() {
        // IPv6 /64.
        let Some(ip_rule::Value::Custom(c)) = build_one_ip_rule("2001:db8::/64").unwrap().value
        else {
            panic!("expected custom ipv6 rule");
        };
        assert_eq!(c.cidr.as_ref().unwrap().prefix, 64);
        assert_eq!(c.cidr.as_ref().unwrap().ip.len(), 16);
        // Leading `!` flips reverse-match; bare IP defaults to /32.
        let Some(ip_rule::Value::Custom(c)) = build_one_ip_rule("!192.168.1.1").unwrap().value
        else {
            panic!("expected custom reverse rule");
        };
        assert!(c.reverse_match);
        assert_eq!(c.cidr.as_ref().unwrap().prefix, 32);
        // Garbage and geoip are rejected.
        assert!(build_one_ip_rule("not-an-ip").is_err());
        assert!(build_one_ip_rule("10.0.0.0/40").is_err());
        assert!(build_one_ip_rule("geoip:cn").is_err());
    }

    #[test]
    fn sniffing_options_default_off() {
        let sniff = decoded_sniffing(&inbound_with_sniffing(Sniffing::default()));
        assert!(
            !sniff.route_only && !sniff.metadata_only,
            "default Sniffing keeps route_only/metadata_only off (behaviour-preserving)"
        );
        assert!(sniff.domains_excluded.is_empty() && sniff.ips_excluded.is_empty());
    }
}
