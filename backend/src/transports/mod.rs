//! Wire-transport modules — each transport (TCP, WebSocket, XHTTP, future
//! gRPC/QUIC) lives in its own file behind a small `Transport` trait. The
//! orchestrator that builds xray's `InboundHandlerConfig` (see
//! `xray::orchestrator`) composes one transport + one security + one
//! protocol without knowing which concrete variants are in play.
//!
//! Adding a new transport (e.g. gRPC) means: drop a new `grpc.rs` next
//! to the others, implement `Transport` on its config struct, register
//! it in `TransportConfig` enum, done — no edits anywhere else in the
//! backend tree.

use crate::xray::proto::xray::common::serial::TypedMessage;
use crate::xray::proto::xray::transport::internet::{
    QuicParams as XrayQuicParams, TransportConfig as XrayTransportConfig,
};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

pub mod finalmask;
pub mod hysteria;
pub mod quic;
pub mod sockopt;
pub mod tcp;
pub mod ws;
pub mod xhttp;

/// Discriminator used in the persisted JSON blob (`inbounds.transport_config`)
/// and on the wire to identify which variant of `TransportConfig` follows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "lowercase")]
#[ts(export, export_to = "../../frontend/src/api/types/transport.ts")]
pub enum TransportKind {
    Tcp,
    Ws,
    Xhttp,
    Hysteria,
}

impl TransportKind {
    pub const fn as_db_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Ws => "ws",
            Self::Xhttp => "xhttp",
            Self::Hysteria => "hysteria",
        }
    }
}

/// Implemented by every concrete transport (TCP, WebSocket, XHTTP, …).
/// The trait stays small on purpose — `build_settings` is the only
/// "give xray your bytes" call; everything else is metadata.
pub trait Transport: Send + Sync {
    /// Lowercase kebab-case kind tag — what goes in the URL `type=` param
    /// and in the panel's serialized JSON discriminator. Drives the
    /// default `share_link_params` impl below.
    fn kind(&self) -> TransportKind;

    /// Value xray expects in `StreamConfig.protocol_name`. Usually the
    /// same as `kind()` but not always — e.g. XHTTP's wire name is
    /// `splithttp` inside xray for historical reasons.
    fn xray_protocol_name(&self) -> &'static str;

    /// Build the transport-specific proto message ready to be wrapped
    /// in `TypedMessage` and placed in `StreamConfig.transport_settings[0]`.
    fn build_settings(&self) -> anyhow::Result<TypedMessage>;

    /// Stream-level QUIC tuning. Only QUIC-based transports return
    /// `Some` — others rely on the default `None`. The orchestrator
    /// drops the value into `StreamConfig.quic_params`.
    fn quic_params_proto(&self) -> Option<XrayQuicParams> {
        None
    }

    /// Key/value pairs this transport contributes to the share-link
    /// URL. The orchestrator collects pairs from all three layers
    /// (protocol + transport + security), then assembles the final
    /// vless:// URL. Default impl returns just `type=<kind>` — every
    /// transport that needs more (path, host, mode) overrides.
    fn share_link_params(&self) -> Vec<(String, String)> {
        vec![("type".to_owned(), self.kind().as_db_str().to_owned())]
    }
}

/// Tagged-union of every transport variant. Lives on `Inbound` as the
/// `transport` field and serializes to a single JSON blob in the DB.
/// `#[serde(tag = "kind")]` produces `{"kind": "ws", "path": "/"}` —
/// matches what TypeScript's discriminated union expects.
///
/// `Xhttp` is ~640 B vs ~104 B for `Ws` and ~16 B for `Tcp`, which
/// clippy flags as `large_enum_variant`. Boxing the big variant would
/// trade an extra heap allocation per inbound for a smaller stack
/// footprint and risk a ts-rs serialization surprise (Box transparency
/// isn't guaranteed across versions). The panel holds at most a
/// double-digit number of inbounds in memory, so the stack-size win
/// isn't worth either cost — silence the lint with an explicit rationale.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(tag = "kind", rename_all = "lowercase")]
#[ts(export, export_to = "../../frontend/src/api/types/transport.ts")]
pub enum TransportConfig {
    Tcp(tcp::TcpTransport),
    Ws(ws::WsTransport),
    Xhttp(xhttp::XhttpTransport),
    Hysteria(hysteria::HysteriaTransport),
}

impl TransportConfig {
    /// Dispatch to the concrete `Transport` impl. Returns a reference
    /// to avoid the cost of dyn-dispatch when the caller has the enum.
    pub fn as_transport(&self) -> &dyn Transport {
        match self {
            Self::Tcp(t) => t,
            Self::Ws(t) => t,
            Self::Xhttp(t) => t,
            Self::Hysteria(t) => t,
        }
    }

    /// Build the full `TransportConfig` list ready for `StreamConfig.transport_settings`.
    pub fn build_xray_transport_settings(&self) -> anyhow::Result<Vec<XrayTransportConfig>> {
        let t = self.as_transport();
        Ok(vec![XrayTransportConfig {
            protocol_name: t.xray_protocol_name().to_owned(),
            settings: Some(t.build_settings()?),
        }])
    }
}
