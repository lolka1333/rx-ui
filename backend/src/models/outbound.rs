//! Operator-defined OUTBOUNDS (egress / relay through another server).
//!
//! Applied the same way as inbounds: pushed into the live xray over gRPC
//! (`HandlerService.AddOutbound`) with no restart, and re-pushed on boot /
//! after a restart by `api::outbounds::reconcile_outbounds_with_xray`. The
//! proto `OutboundHandlerConfig` (sender + stream + protocol) is built in
//! `xray::orchestrator::outbound_to_handler_config`.
//!
//! The `transport` and `security` fields REUSE the inbound model's
//! `TransportConfig` / `SecurityConfig` enums — those structs already carry
//! the client-facing fields (serverName, fingerprint, reality publicKey /
//! shortId, …) because the share-link builder needs them. The orchestrator
//! builds the transport proto as-is and the *client* variant of the security
//! proto (`Security::build_client_settings`).
//!
//! v1 protocol scope: VLESS (the protocols the panel models). Hysteria is an
//! additive variant to follow.

use crate::protocols::vless::{VlessEncryptionMode, VlessXorMode};
use crate::security::SecurityConfig;
use crate::transports::TransportConfig;
use crate::transports::finalmask::FinalMask;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

/// One custom outbound. Its `tag` is the routing-rule target; reject the
/// reserved tags (direct / blocked / direct-ipv4 / api) at save time.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../frontend/src/api/types/outbound.ts")]
pub struct CustomOutbound {
    pub id: String,
    pub tag: String,
    pub enabled: bool,
    pub protocol: OutboundProtocolConfig,
    /// Wire transport (tcp / ws / xhttp / hysteria) — reused from inbounds.
    pub transport: TransportConfig,
    /// Stream security (none / tls / reality) — reused; the client-facing
    /// fields are emitted (serverName/fingerprint/publicKey/shortId).
    pub security: SecurityConfig,
    /// Wire-level socket obfuscation to MIRROR the upstream. Sudoku is a
    /// symmetric/stateful cipher — a relay to a Sudoku inbound MUST run the
    /// identical config or the server drops it. `#[serde(default)]` keeps
    /// rows written before this field landed deserializing.
    #[serde(default)]
    pub finalmask: FinalMask,
    /// Connection multiplexing (optional).
    #[serde(default)]
    pub mux: OutboundMux,
    /// `sendThrough` — source bind: "" | IP | CIDR | "origin" | "srcip".
    #[serde(default)]
    pub send_through: String,
    /// `proxySettings.tag` — chain this outbound through another outbound by
    /// tag. "" = no chaining.
    #[serde(default)]
    pub proxy_tag: String,
    pub created_at: String,
    pub updated_at: String,
}

/// Protocol-specific outbound settings. Tagged enum mirrors the inbound
/// `ProtocolConfig` shape so the frontend form can dispatch the same way.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(tag = "kind", rename_all = "lowercase")]
#[ts(export, export_to = "../../frontend/src/api/types/outbound.ts")]
pub enum OutboundProtocolConfig {
    Vless(VlessOutbound),
    // Hysteria(HysteriaOutbound) — follow-up.
}

/// VLESS client settings → xray `settings.vnext[0]`. One endpoint, one user.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../frontend/src/api/types/outbound.ts")]
pub struct VlessOutbound {
    /// Remote server address (domain or IP).
    pub address: String,
    /// Remote server port.
    pub port: u16,
    /// User UUID.
    pub id: String,
    /// XTLS flow: "" or "xtls-rprx-vision".
    #[serde(default)]
    pub flow: String,
    /// Application-layer encryption to MATCH the upstream server. `None` =
    /// plain VLESS (the common case). `mlkem768x25519plus` is the
    /// post-quantum cipher — it needs the server's public `client_key` plus
    /// the same xor mode / padding the server advertises. The orchestrator
    /// turns these into the `Account.{encryption,xor_mode,seconds,padding}`
    /// proto fields via the shared `vless_client_encryption_fields`.
    #[serde(default)]
    pub encryption_mode: VlessEncryptionMode,
    #[serde(default)]
    pub encryption_xor_mode: Option<VlessXorMode>,
    /// The upstream's PUBLIC `client_key` (base64-url) — the same value the
    /// server embeds in its share-links, NOT the server's private key.
    #[serde(default)]
    pub encryption_client_key: Option<String>,
    #[serde(default)]
    pub encryption_padding: Option<String>,
}

/// Mux settings → xray `mux`. Disabled by default.
#[derive(Debug, Clone, Default, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../frontend/src/api/types/outbound.ts")]
pub struct OutboundMux {
    pub enabled: bool,
    /// `concurrency`: <0 disables, 0 = xray default (8), >0 custom.
    #[serde(default)]
    pub concurrency: i32,
}
