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

use crate::models::{Client, Inbound};
use crate::transports::finalmask::FinalMaskScope;
use crate::xray::proto::xray::app::proxyman::{ReceiverConfig, SniffingConfig};
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

    // FinalMask wraps the socket bytes AFTER TLS/Reality. Sudoku fills
    // both slots (xray dispatches by socket type at handshake); Fragment
    // is TCP-only; Noise is UDP-only. Inactive variants leave both empty.
    let (tcpmasks, udpmasks) = match inb.finalmask.to_typed_message() {
        Some((m, FinalMaskScope::Both)) => (vec![m.clone()], vec![m]),
        Some((m, FinalMaskScope::Tcp)) => (vec![m], Vec::new()),
        Some((m, FinalMaskScope::Udp)) => (Vec::new(), vec![m]),
        None => (Vec::new(), Vec::new()),
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
            domains_excluded: Vec::new(),
            ips_excluded: Vec::new(),
            metadata_only: false,
            route_only: false,
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
