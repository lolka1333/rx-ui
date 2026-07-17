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

use crate::models::{Client, CustomOutbound, Inbound, OutboundProtocolConfig, Sniffing};
use crate::protocols::vless::vless_client_encryption_fields;
use crate::xray::proto::xray::app::proxyman::{
    MultiplexingConfig, ReceiverConfig, SenderConfig, SniffingConfig,
};
use crate::xray::proto::xray::common::geodata::{
    Cidr, CidrRule, Domain, DomainRule, GeoIpRule, GeoSiteRule, IpRule, domain::Type as DomainType,
    domain_rule, ip_rule,
};
use crate::xray::proto::xray::common::net::{IpOrDomain, PortList, PortRange, ip_or_domain};
use crate::xray::proto::xray::common::protocol::{ServerEndpoint, User};
use crate::xray::proto::xray::common::serial::TypedMessage;
use crate::xray::proto::xray::core::{InboundHandlerConfig, OutboundHandlerConfig};
use crate::xray::proto::xray::proxy::hysteria::ClientConfig as HysteriaClientConfig;
use crate::xray::proto::xray::proxy::vless::outbound::Config as VlessOutboundConfig;
use crate::xray::proto::xray::proxy::vless::{Account as VlessAccount, Reverse as VlessReverse};
use crate::xray::proto::xray::transport::internet::{ProxyConfig, StreamConfig};

const TYPE_RECEIVER_CONFIG: &str = "xray.app.proxyman.ReceiverConfig";
const TYPE_SENDER_CONFIG: &str = "xray.app.proxyman.SenderConfig";
const TYPE_VLESS_OUTBOUND: &str = "xray.proxy.vless.outbound.Config";
const TYPE_VLESS_ACCOUNT: &str = "xray.proxy.vless.Account";
const TYPE_HYSTERIA_OUTBOUND: &str = "xray.proxy.hysteria.ClientConfig";

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

    // Server-side socket masks. `client_side = false` drops Fragment (it is
    // client-only — see `FinalMask::masks`); Sudoku/Noise fill their slots.
    let (tcpmasks, udpmasks) = inb.finalmask.masks(false);

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
            domains_excluded: build_domain_rules(&inb.sniffing.domains_excluded, false)?,
            ips_excluded: build_ip_rules(&inb.sniffing.ips_excluded, false)?,
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

/// Build the `OutboundHandlerConfig` proto from a `CustomOutbound`, ready for
/// `HandlerService.AddOutbound`. Mirrors `inbound_to_handler_config` but emits
/// a `SenderConfig` (dialer side: stream + mux + chaining + sendThrough) wrapped
/// around the same `StreamConfig` building — only the security layer differs
/// (client variant: no certs / Reality client fields), and there are no users
/// or sniffing.
pub fn outbound_to_handler_config(ob: &CustomOutbound) -> anyhow::Result<OutboundHandlerConfig> {
    let transport = ob.transport.as_transport();
    let security = ob.security.as_security();

    // Client-side socket masks, mirrored to the upstream so a symmetric Sudoku
    // (or UDP Noise) lines up — without it the server drops the connection.
    // `client_side = true` puts Fragment in the TCP slot: the dialer fragments
    // its OWN ClientHello (the asymmetric half the inbound deliberately omits).
    let (tcpmasks, udpmasks) = ob.finalmask.masks(true);

    // Same StreamConfig as inbounds, but the client-side security variant.
    let stream_settings = StreamConfig {
        protocol_name: transport.xray_protocol_name().to_owned(),
        transport_settings: ob.transport.build_xray_transport_settings()?,
        security_type: security.xray_type_url().to_owned(),
        security_settings: security
            .build_client_settings()?
            .map_or_else(Vec::new, |msg| vec![msg]),
        quic_params: transport.quic_params_proto(),
        tcpmasks,
        udpmasks,
        ..StreamConfig::default()
    };

    // Protocol-specific outbound proxy settings.
    let proxy = match &ob.protocol {
        OutboundProtocolConfig::Vless(v) => {
            // Mirror the upstream server's application-layer cipher. For native
            // (mlkem768x25519plus) this sets encryption(=key)/xor_mode/seconds/
            // padding exactly as the inbound's `build_user` does — a verbatim
            // string copy would make xray reject the key ("invalid seed length").
            let (encryption, xor_mode, seconds, padding) = vless_client_encryption_fields(
                v.encryption_mode,
                v.encryption_xor_mode,
                v.encryption_client_key.as_deref(),
                v.encryption_padding.as_deref(),
            );
            // VLESS Reverse Proxy: a non-empty tag makes this outbound a bridge
            // (dials the portal with the reverse command, offers the tunnel).
            let reverse = (!v.reverse_tag.trim().is_empty()).then(|| VlessReverse {
                tag: v.reverse_tag.trim().to_owned(),
                sniffing: None,
            });
            let account = VlessAccount {
                id: v.id.clone(),
                flow: v.flow.clone(),
                encryption,
                xor_mode,
                seconds,
                padding,
                reverse,
                ..VlessAccount::default()
            };
            let user = User {
                level: 0,
                email: String::new(),
                account: Some(TypedMessage {
                    r#type: TYPE_VLESS_ACCOUNT.to_owned(),
                    value: prost::Message::encode_to_vec(&account),
                }),
            };
            let endpoint = ServerEndpoint {
                address: Some(parse_listen_address(&v.address)),
                port: u32::from(v.port),
                user: Some(user),
            };
            let cfg = VlessOutboundConfig {
                vnext: Some(endpoint),
            };
            TypedMessage {
                r#type: TYPE_VLESS_OUTBOUND.to_owned(),
                value: prost::Message::encode_to_vec(&cfg),
            }
        }
        OutboundProtocolConfig::Hysteria(h) => {
            // `protocol: "hysteria"` carries only the endpoint — version + the
            // server address/port. The password (`auth`) lives on the paired
            // hysteria TRANSPORT (xray's dialer reads it as RequestHeaderAuth),
            // and client TLS on the security block, both built generically above.
            let cfg = HysteriaClientConfig {
                server: Some(ServerEndpoint {
                    address: Some(parse_listen_address(&h.address)),
                    port: u32::from(h.port),
                    user: None,
                }),
            };
            TypedMessage {
                r#type: TYPE_HYSTERIA_OUTBOUND.to_owned(),
                value: prost::Message::encode_to_vec(&cfg),
            }
        }
    };

    let multiplex_settings = ob.mux.enabled.then(|| MultiplexingConfig {
        enabled: true,
        concurrency: ob.mux.concurrency,
        ..MultiplexingConfig::default()
    });

    // proxySettings.tag — chain through another outbound.
    let proxy_settings = (!ob.proxy_tag.trim().is_empty()).then(|| ProxyConfig {
        tag: ob.proxy_tag.trim().to_owned(),
        ..ProxyConfig::default()
    });

    // sendThrough: an IP literal binds `via`; anything else (CIDR / origin /
    // srcip) rides in `via_cidr`.
    let (via, via_cidr) = parse_send_through(&ob.send_through);

    let sender = SenderConfig {
        via,
        via_cidr,
        stream_settings: Some(stream_settings),
        proxy_settings,
        multiplex_settings,
        // Outbound domainStrategy is not modeled — always AsIs (0).
        target_strategy: 0,
    };

    Ok(OutboundHandlerConfig {
        tag: ob.tag.clone(),
        sender_settings: Some(TypedMessage {
            r#type: TYPE_SENDER_CONFIG.to_owned(),
            value: prost::Message::encode_to_vec(&sender),
        }),
        proxy_settings: Some(proxy),
        expire: 0,
        comment: String::new(),
    })
}

/// `sendThrough` → (`via`, `via_cidr`): a bare IP binds the source address via
/// `via`; a CIDR or the `origin` / `srcip` keywords go to `via_cidr`.
fn parse_send_through(s: &str) -> (Option<IpOrDomain>, String) {
    let t = s.trim();
    if t.is_empty() {
        (None, String::new())
    } else if t.parse::<std::net::IpAddr>().is_ok() {
        (Some(parse_listen_address(t)), String::new())
    } else {
        (None, t.to_owned())
    }
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

/// Default geodata file names xray resolves `geosite:` / `geoip:` against
/// (`common/geodata/rule_parser.go`). We emit these as references; xray loads
/// the .dat at match time, so the panel never parses the files itself.
pub(super) const DEFAULT_GEOSITE_DAT: &str = "geosite.dat";
pub(super) const DEFAULT_GEOIP_DAT: &str = "geoip.dat";

/// Convert operator-entered domain strings into xray `DomainRule`s, mirroring
/// xray's conf parser (`parseCustomDomainRule`, default type = Substr).
/// Recognises the `full:` / `domain:` / `regexp:` / `keyword:` / `dotless:`
/// prefixes; a bare value is a substring match. When `allow_geo` is set,
/// `geosite:CODE[@attr]` becomes a `GeoSiteRule` reference (routing rules);
/// otherwise geosite/ext are rejected — sniffing exclusions have no .dat.
pub(super) fn build_domain_rules(
    domains: &[String],
    allow_geo: bool,
) -> anyhow::Result<Vec<DomainRule>> {
    domains
        .iter()
        .map(|d| build_one_domain_rule(d, allow_geo))
        .collect()
}

pub(super) fn build_one_domain_rule(raw: &str, allow_geo: bool) -> anyhow::Result<DomainRule> {
    let r = raw.trim();
    anyhow::ensure!(!r.is_empty(), "empty domain rule");
    if let Some(spec) = r.strip_prefix("geosite:") {
        anyhow::ensure!(
            allow_geo,
            "geosite/ext domain rules aren't supported here: {r}"
        );
        // `CODE` or `CODE@attr`; xray upper-cases the code, lower-cases attrs.
        let (code, attrs) = spec.split_once('@').unwrap_or((spec, ""));
        anyhow::ensure!(!code.is_empty(), "empty geosite code: {r}");
        return Ok(DomainRule {
            value: Some(domain_rule::Value::Geosite(GeoSiteRule {
                file: DEFAULT_GEOSITE_DAT.to_owned(),
                code: code.to_uppercase(),
                attrs: attrs.to_lowercase(),
            })),
        });
    }
    anyhow::ensure!(
        !(r.starts_with("ext:") || r.starts_with("ext-domain:") || r.starts_with("ext-site:")),
        "ext domain rules aren't supported: {r}"
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

/// Convert operator-entered IP strings into xray `IpRule`s, mirroring
/// `parseCustomIPRule`: a CIDR (or bare IP, treated as /32 or /128) with an
/// optional leading `!` toggling reverse-match. When `allow_geo` is set,
/// `geoip:CODE` becomes a `GeoIpRule` reference (routing rules); otherwise
/// geoip/ext are rejected (sniffing exclusions have no .dat).
pub(super) fn build_ip_rules(ips: &[String], allow_geo: bool) -> anyhow::Result<Vec<IpRule>> {
    ips.iter()
        .map(|s| build_one_ip_rule(s, allow_geo))
        .collect()
}

pub(super) fn build_one_ip_rule(raw: &str, allow_geo: bool) -> anyhow::Result<IpRule> {
    let mut s = raw.trim();
    anyhow::ensure!(!s.is_empty(), "empty ip rule");
    // Leading `!`(s) toggle reverse-match — xray's `cutReversePrefix`.
    let mut reverse = false;
    while let Some(rest) = s.strip_prefix('!') {
        reverse = !reverse;
        s = rest;
    }
    if let Some(code) = s.strip_prefix("geoip:") {
        anyhow::ensure!(allow_geo, "geoip/ext ip rules aren't supported here: {raw}");
        // A `!` may also sit inside the code (`geoip:!cn`) — xray's second
        // cutReversePrefix — so re-strip and toggle again.
        let (code, inner_rev) = code.strip_prefix('!').map_or((code, false), |c| (c, true));
        reverse ^= inner_rev;
        anyhow::ensure!(!code.is_empty(), "empty geoip code: {raw}");
        return Ok(IpRule {
            value: Some(ip_rule::Value::Geoip(GeoIpRule {
                file: DEFAULT_GEOIP_DAT.to_owned(),
                code: code.to_uppercase(),
                reverse_match: reverse,
            })),
        });
    }
    anyhow::ensure!(
        !(s.starts_with("ext:") || s.starts_with("ext-ip:")),
        "ext ip rules aren't supported: {raw}"
    );
    Ok(IpRule {
        value: Some(ip_rule::Value::Custom(CidrRule {
            cidr: Some(parse_cidr(s)?),
            reverse_match: reverse,
        })),
    })
}

pub(super) fn parse_cidr(s: &str) -> anyhow::Result<Cidr> {
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
    build_domain_rules(&sniffing.domains_excluded, false)?;
    build_ip_rules(&sniffing.ips_excluded, false)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    //! Orchestrator `inbound_to_handler_config` coverage: the sniffing
    //! `route_only` flag threading into xray's `ReceiverConfig.SniffingConfig`,
    //! hysteria outbound building, and the TLS-certificate build gate (an
    //! un-buildable config must fail so create/update reject it pre-commit).
    use super::*;
    use crate::models::{HysteriaOutbound, OutboundMux, Sniffing};
    use crate::protocols::ProtocolConfig;
    use crate::protocols::hysteria::HysteriaProtocol;
    use crate::protocols::vless::{VlessEncryptionMode, VlessFlow, VlessProtocol};
    use crate::security::tls::{TlsCertSource, TlsCertUsage, TlsCertificate, TlsSecurity};
    use crate::security::{NoneSecurity, SecurityConfig};
    use crate::transports::TransportConfig;
    use crate::transports::finalmask::FinalMask;
    use crate::transports::hysteria::{HysteriaMasquerade, HysteriaTransport};
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
            reverse_tag: None,
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
            let rule = build_one_domain_rule(input, false).unwrap();
            let Some(domain_rule::Value::Custom(d)) = rule.value else {
                panic!("expected custom rule for {input}");
            };
            assert_eq!(d.r#type, want_ty as i32, "type for {input}");
            assert_eq!(d.value, want_val, "value for {input}");
        }
        // geosite/ext are rejected; dotless without a dot becomes a regex.
        assert!(build_one_domain_rule("geosite:google", false).is_err());
        let Some(domain_rule::Value::Custom(d)) =
            build_one_domain_rule("dotless:cn", false).unwrap().value
        else {
            panic!("expected custom dotless rule");
        };
        assert_eq!(d.r#type, DomainType::Regex as i32);
        assert_eq!(d.value, "^[^.]*cn[^.]*$");
    }

    #[test]
    fn ip_rule_parses_cidr_and_reverse() {
        // IPv6 /64.
        let Some(ip_rule::Value::Custom(c)) =
            build_one_ip_rule("2001:db8::/64", false).unwrap().value
        else {
            panic!("expected custom ipv6 rule");
        };
        assert_eq!(c.cidr.as_ref().unwrap().prefix, 64);
        assert_eq!(c.cidr.as_ref().unwrap().ip.len(), 16);
        // Leading `!` flips reverse-match; bare IP defaults to /32.
        let Some(ip_rule::Value::Custom(c)) =
            build_one_ip_rule("!192.168.1.1", false).unwrap().value
        else {
            panic!("expected custom reverse rule");
        };
        assert!(c.reverse_match);
        assert_eq!(c.cidr.as_ref().unwrap().prefix, 32);
        // Garbage and geoip are rejected.
        assert!(build_one_ip_rule("not-an-ip", false).is_err());
        assert!(build_one_ip_rule("10.0.0.0/40", false).is_err());
        assert!(build_one_ip_rule("geoip:cn", false).is_err());
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

    fn hysteria_outbound() -> CustomOutbound {
        CustomOutbound {
            id: "ob1".into(),
            tag: "hy".into(),
            enabled: true,
            protocol: OutboundProtocolConfig::Hysteria(HysteriaOutbound {
                address: "example.com".into(),
                port: 443,
            }),
            transport: TransportConfig::Hysteria(HysteriaTransport {
                auth: Some("secret".into()),
                udp_idle_timeout: None,
                masquerade: HysteriaMasquerade::default(),
                quic_params: None,
            }),
            security: SecurityConfig::None(NoneSecurity {}),
            finalmask: FinalMask::None,
            mux: OutboundMux::default(),
            send_through: String::new(),
            proxy_tag: String::new(),
            created_at: "now".into(),
            updated_at: "now".into(),
        }
    }

    #[test]
    fn hysteria_outbound_builds_client_config_and_transport() {
        let cfg = outbound_to_handler_config(&hysteria_outbound()).unwrap();

        // Protocol settings = xray's hysteria ClientConfig: just the endpoint
        // (`server` at field 1), NO user — the password rides on the transport.
        // The fork's ClientConfig has no `version` field; encoding one would
        // shift `server` and xray would reject it with "no target server found".
        let proxy = cfg.proxy_settings.expect("proxy settings");
        assert_eq!(proxy.r#type, "xray.proxy.hysteria.ClientConfig");
        let client = HysteriaClientConfig::decode(&proxy.value[..]).unwrap();
        let server = client.server.expect("server endpoint");
        assert_eq!(server.port, 443);
        assert!(
            server.user.is_none(),
            "hysteria auth lives on the transport, not the protocol user"
        );

        // The stream rides the hysteria transport.
        let sender = SenderConfig::decode(&cfg.sender_settings.unwrap().value[..]).unwrap();
        let stream = sender.stream_settings.expect("stream settings");
        assert_eq!(stream.protocol_name, "hysteria");
    }

    // === TLS cert presence gates the build (create → 400, not a phantom row) ==
    fn hysteria2_tls_inbound(certificates: Vec<TlsCertificate>) -> Inbound {
        Inbound {
            id: "id-hy".into(),
            tag: "hy".into(),
            enabled: true,
            listen: "0.0.0.0".into(),
            port: 8443,
            protocol: ProtocolConfig::Hysteria2(HysteriaProtocol {}),
            transport: TransportConfig::Hysteria(HysteriaTransport::default()),
            security: SecurityConfig::Tls(TlsSecurity {
                certificates,
                ..TlsSecurity::default()
            }),
            sniffing: Sniffing::default(),
            finalmask: FinalMask::None,
            sockopt: SocketOpt::default(),
            created_at: "now".into(),
            updated_at: "now".into(),
        }
    }

    fn inline_cert() -> TlsCertificate {
        TlsCertificate {
            source: TlsCertSource::Inline,
            cert: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----".into(),
            key: "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----".into(),
            usage: TlsCertUsage::Encipherment,
            ocsp_stapling: 0,
            build_chain: false,
            one_time_loading: false,
        }
    }

    #[test]
    fn tls_inbound_without_cert_fails_to_build() {
        // `security=tls` with an empty certificate list must fail
        // `inbound_to_handler_config` so the create handler rejects it with a
        // 400 BEFORE the DB insert. Otherwise the committed row survives while
        // xray never loads the inbound — a phantom enabled inbound in the list
        // (the reconcile loop skips un-buildable rows with only a warn-level log).
        let err = inbound_to_handler_config(&hysteria2_tls_inbound(vec![]), &[])
            .expect_err("TLS with no certificate must not build");
        assert!(
            err.to_string().contains("certificate"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn tls_inbound_with_cert_builds() {
        // The fix must not over-reject: one certificate is enough to build.
        assert!(
            inbound_to_handler_config(&hysteria2_tls_inbound(vec![inline_cert()]), &[]).is_ok(),
            "TLS with one certificate should build"
        );
    }
}
