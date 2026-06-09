//! Inbound model. Composed of three typed layer-configs (protocol /
//! transport / security) plus a sniffing block — each one a tagged
//! enum that lives in its own module under `protocols/`, `transports/`,
//! `security/`. The DB persists the layers as JSON blobs in the
//! `protocol_config / transport_config / security_config /
//! sniffing_config` columns; the orchestrator and share-link builder
//! consume them via the per-layer trait objects.
//!
//! Adding a new protocol or transport is now a Rust-level change with
//! zero schema work: drop a file into the appropriate sub-tree and add
//! a variant to the corresponding `*Config` enum.

use crate::protocols::ProtocolConfig;
use crate::security::SecurityConfig;
use crate::transports::TransportConfig;
use crate::transports::finalmask::FinalMask;
use crate::transports::sockopt::SocketOpt;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

/// One inbound row. Serialized 1:1 to the frontend; persisted with the
/// three layer blobs sitting in their own DB columns so `SQLite`'s JSON1
/// functions can poke at them when needed (admin shell debugging,
/// future migrations).
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../frontend/src/api/types/inbound.ts")]
pub struct Inbound {
    pub id: String,
    pub tag: String,
    pub enabled: bool,
    pub listen: String,
    pub port: u16,

    pub protocol: ProtocolConfig,
    pub transport: TransportConfig,
    pub security: SecurityConfig,
    pub sniffing: Sniffing,
    /// Wire-level last-stage obfuscation. `FinalMask::None` (default)
    /// means the column's JSON blob is `{"kind":"none"}` — xray gets
    /// no `streamSettings.finalmask` and the share-link gets no `fm=`
    /// param. Active variants must be configured symmetrically in the
    /// client app (subscription bundle carries the settings).
    #[serde(default)]
    pub finalmask: FinalMask,
    /// Socket-level options (`streamSettings.sockopt`). Default (all
    /// fields empty) emits no sockopt block, so the wire output is
    /// unchanged for inbounds that never touch it. Most relevant field
    /// is `trusted_x_forwarded_for`, which xray now warns about on
    /// XHTTP/WS/HttpUpgrade inbounds (xray-core #6159).
    #[serde(default)]
    pub sockopt: SocketOpt,

    pub created_at: String,
    pub updated_at: String,
}

/// Sniffing config — when xray inspects payload to derive
/// SNI / HTTP-host / etc. for routing decisions.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../frontend/src/api/types/inbound.ts")]
pub struct Sniffing {
    pub enabled: bool,
    /// Subset of `["http", "tls", "fakedns", "quic"]`. Empty array is
    /// equivalent to `enabled == false`.
    pub dest_override: Vec<String>,
    /// When true, the sniffed domain feeds routing decisions ONLY and the
    /// connection's destination is left untouched (xray's `routeOnly`).
    /// When false (default), xray rewrites the destination to the sniffed
    /// domain. `#[serde(default)]` keeps inbound rows whose stored JSON
    /// predates this field deserializing to `false`, preserving their
    /// existing on-wire behaviour.
    #[serde(default)]
    pub route_only: bool,
    /// When true, sniff from connection metadata without waiting for the
    /// client's first payload packet (xray's `metadataOnly`). Needed for
    /// server-speaks-first protocols; off by default.
    #[serde(default)]
    pub metadata_only: bool,
    /// Domains excluded from sniff-based destination override — traffic to
    /// these is never rewritten to the sniffed host (e.g. exclude your own
    /// decoy/dest domain). Empty = exclude nothing.
    #[serde(default)]
    pub domains_excluded: Vec<String>,
    /// IPs / CIDRs excluded from sniff-based destination override. Empty =
    /// exclude nothing.
    #[serde(default)]
    pub ips_excluded: Vec<String>,
}

impl Default for Sniffing {
    /// Sensible defaults for a fresh inbound — sniff HTTP, TLS, and
    /// fakedns so routing rules that match on sniffed host work out
    /// of the box. Operator can narrow or disable from the UI.
    fn default() -> Self {
        Self {
            enabled: true,
            dest_override: vec!["http".to_owned(), "tls".to_owned(), "fakedns".to_owned()],
            // Behaviour-preserving default: xray rewrites dest to the
            // sniffed domain. Operators flip this on from the UI when they
            // want the original destination kept on the wire.
            route_only: false,
            // Wait for the first payload (default) and exclude nothing —
            // operators opt into these from the UI.
            metadata_only: false,
            domains_excluded: Vec::new(),
            ips_excluded: Vec::new(),
        }
    }
}

/// Body for `POST /api/inbounds`. The three layer blocks are required;
/// `listen` falls back to `0.0.0.0` and `sniffing` to its default when
/// omitted so the frontend's create modal stays terse.
#[derive(Debug, Deserialize, TS)]
#[ts(export, export_to = "../../frontend/src/api/types/inbound.ts")]
pub struct InboundCreate {
    pub tag: String,
    /// Optional; defaults to "0.0.0.0".
    pub listen: Option<String>,
    pub port: u16,
    pub protocol: ProtocolConfig,
    pub transport: TransportConfig,
    pub security: SecurityConfig,
    /// Optional; defaults to `Sniffing::default()`.
    pub sniffing: Option<Sniffing>,
    /// Optional; defaults to `FinalMask::None` (no obfuscation).
    pub finalmask: Option<FinalMask>,
    /// Optional; defaults to an empty (inactive) `SocketOpt`.
    pub sockopt: Option<SocketOpt>,
}

/// Body for `PATCH /api/inbounds/{id}`. Each layer is independently
/// replaceable — sending `transport: { ... }` swaps the whole transport
/// block; omitting it leaves the existing column untouched. There's no
/// merge-at-field-level semantic: callers that need it (e.g. flip one
/// `ws_path`) read the inbound, mutate the relevant layer in JS, and
/// PATCH the whole layer back.
#[derive(Debug, Deserialize, TS)]
#[ts(export, export_to = "../../frontend/src/api/types/inbound.ts")]
pub struct InboundUpdate {
    pub tag: Option<String>,
    pub enabled: Option<bool>,
    pub listen: Option<String>,
    pub port: Option<u16>,
    pub protocol: Option<ProtocolConfig>,
    pub transport: Option<TransportConfig>,
    pub security: Option<SecurityConfig>,
    pub sniffing: Option<Sniffing>,
    pub finalmask: Option<FinalMask>,
    pub sockopt: Option<SocketOpt>,
}
