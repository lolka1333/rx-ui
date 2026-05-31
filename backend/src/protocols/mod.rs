//! Proxy-protocol layer — VLESS today, VMess/Trojan later. Each protocol
//! owns its `proxy_settings` shape + per-user serialization + share-link
//! parameter contribution. The orchestrator (`xray::orchestrator`)
//! composes one protocol + one transport + one security per inbound.
//!
//! Adding `VMess` = drop `protocols/vmess/` next to `vless/`, implement
//! `Protocol` on its config struct, register it in `ProtocolConfig`
//! enum. Zero edits elsewhere in the backend tree (orchestrator
//! dispatches dynamically via `as_protocol()`).

use crate::models::Client;
use crate::security::SecurityKind;
use crate::transports::TransportKind;
use crate::xray::proto::xray::common::protocol::User;
use crate::xray::proto::xray::common::serial::TypedMessage;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

/// Cross-layer compatibility for a single protocol. The API handler
/// reads this to gate inbound create/update without hard-coding rules
/// per protocol — a new protocol just declares its allowed sets in
/// `ProtocolConfig::compat` and the validator does the rest.
pub struct ProtocolCompat {
    pub allowed_transports: &'static [TransportKind],
    pub allowed_securities: &'static [SecurityKind],
}

pub mod hysteria;
pub mod vless;

/// Each protocol implements this trait. `build_proxy_settings` is the
/// inbound-side proxy config xray expects; `build_user` produces the
/// per-client User proto that goes into `proxy_settings.users[]`.
pub trait Protocol: Send + Sync {
    /// Build the `proxy_settings` `TypedMessage` for the inbound handler.
    /// Receives the list of pre-built users so the protocol doesn't
    /// re-iterate clients.
    fn build_proxy_settings(&self, users: Vec<User>) -> anyhow::Result<TypedMessage>;

    /// Build a single User proto for one client. Used both by initial
    /// inbound push and by runtime `AddUser` gRPC mutation.
    fn build_user(&self, client: &Client) -> anyhow::Result<User>;

    /// Key/value pairs this protocol contributes to a per-client share-link.
    /// Default impl is empty — Reality-style protocols may stay quiet here
    /// because everything user-facing lives on the security layer; VLESS
    /// overrides to emit `encryption=` (always) and `flow=` (Vision only).
    fn share_link_params(&self, client: &Client) -> Vec<(String, String)> {
        let _ = client;
        Vec::new()
    }
}

/// Tagged-union of every protocol variant. Lives on `Inbound` as the
/// `protocol` field; serializes to a single JSON blob in the DB.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(tag = "kind", rename_all = "lowercase")]
#[ts(export, export_to = "../../frontend/src/api/types/protocol.ts")]
pub enum ProtocolConfig {
    Vless(vless::VlessProtocol),
    Hysteria2(hysteria::HysteriaProtocol),
}

impl ProtocolConfig {
    pub fn as_protocol(&self) -> &dyn Protocol {
        match self {
            Self::Vless(p) => p,
            Self::Hysteria2(p) => p,
        }
    }

    /// Operator-visible name — used in 4xx messages.
    pub const fn display_name(&self) -> &'static str {
        match self {
            Self::Vless(_) => "VLESS",
            Self::Hysteria2(_) => "Hysteria 2",
        }
    }

    /// Per-protocol cross-layer rules. See `ProtocolCompat`.
    pub const fn compat(&self) -> ProtocolCompat {
        match self {
            Self::Vless(_) => ProtocolCompat {
                allowed_transports: &[TransportKind::Tcp, TransportKind::Ws, TransportKind::Xhttp],
                allowed_securities: &[SecurityKind::None, SecurityKind::Tls, SecurityKind::Reality],
            },
            Self::Hysteria2(_) => ProtocolCompat {
                allowed_transports: &[TransportKind::Hysteria],
                allowed_securities: &[SecurityKind::Tls],
            },
        }
    }
}
