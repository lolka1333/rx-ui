use serde::{Deserialize, Serialize};
use ts_rs::TS;

/// One operator-defined routing rule. Stored (by id) in `xray_custom_rules`;
/// its position in the evaluation order is held separately in
/// `xray_rule_order`. All matchers are AND-ed; an empty matcher is omitted.
/// v1 target is a single `outbound_tag` (direct / blocked / direct-ipv4).
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../frontend/src/api/types/settings.ts")]
pub struct RoutingRule {
    pub id: String,
    pub enabled: bool,
    /// Panel-only label; not emitted to xray.
    pub name: String,
    pub domain: Vec<String>,
    pub ip: Vec<String>,
    pub source_ip: Vec<String>,
    pub port: String,
    pub source_port: String,
    pub network: Vec<String>,
    pub protocol: Vec<String>,
    pub inbound_tag: Vec<String>,
    pub user: Vec<String>,
    pub outbound_tag: String,
}

/// Runtime configuration the panel reads from DB at boot. Holds the
/// values an operator can change from the UI without editing the env
/// file: TCP port + URL prefix the panel binds to, plus subscription
/// knobs that shape what `/sub/{token}` returns to client apps. Panel
/// access fields are applied live (port via dual-listener swap, base
/// path via router rebuild); subscription fields are read on every
/// subscription request, so they take effect immediately.
// A flat settings DTO mirroring the panel_settings columns 1:1 — the bool
// fields are independent toggles, not a state machine, so the "refactor into
// enums" advice doesn't apply here.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../frontend/src/api/types/settings.ts")]
pub struct PanelSettings {
    /// Port number; clamped to [1, 65535] at write time.
    pub panel_port: i32,
    /// URL prefix the panel mounts under (e.g. `/secret-admin`).
    /// Stored with leading slash, no trailing slash; empty string
    /// means "mount at root" (the historical behaviour).
    pub panel_base_path: String,
    /// Global kill-switch for `/sub/{token}`. False → every subscription
    /// URL 404s (same response as an invalid token, so the surface is
    /// indistinguishable from "not configured"). Individual share-links
    /// generated from the panel UI keep working.
    pub sub_enabled: bool,
    /// Optional hostname to substitute for the auto-detected IPv4 / IPv6
    /// inside every share-link in the subscription bundle — i.e. the server
    /// address clients dial. Empty ≡ keep auto-detect (the panel's outbound
    /// IP). Distinct from `sub_link_host`, which is the host of the
    /// subscription URL itself.
    pub sub_host_override: String,
    /// Optional host for the subscription URL itself (the `/sub/{token}`
    /// link the operator shares), independent of `sub_host_override` (the
    /// server address baked into the configs). Empty ≡ the panel's own
    /// address (the origin the admin opens). Lets the shareable link point
    /// at the panel domain while the configs dial a separate tunnel / CDN.
    pub sub_link_host: String,
    /// Hours emitted as `Profile-Update-Interval` so client apps refresh
    /// the subscription on their own. Default 12, range [1, 168].
    pub sub_update_interval_hours: i32,
    /// Operator-set service name shown in the public subscription
    /// landing page header. Empty string ≡ no override → the landing
    /// falls back to a neutral generic ("Подписка"). Validation
    /// strips control characters and caps at 60 chars.
    pub sub_brand_name: String,
    /// Operator-set URL of the main service (landing, support chat,
    /// telegram bot…) shown as a "Перейти на сервис" button in the
    /// subscription page header. Empty ≡ button hidden. Validated as
    /// `http(s)://...` only, no other schemes.
    pub sub_service_url: String,
    /// Optional dedicated TCP port for the public /sub/{token} endpoint.
    /// `0` ≡ disabled (only the main panel port serves subscriptions).
    /// Non-zero spins a second axum listener with the admin /api/*
    /// routes stripped — useful for putting the public endpoint behind
    /// a separate firewall rule / CDN without exposing the admin API.
    pub sub_port: i32,
    /// `domainStrategy` of the freedom (`direct`) outbound: `AsIs`,
    /// `UseIP*`, or `ForceIP*`. Lives in the bootstrap config, so a
    /// change only applies on the next xray restart.
    pub xray_freedom_strategy: String,
    /// `domainStrategy` of the routing block: `AsIs`, `IPIfNonMatch`,
    /// or `IPOnDemand`. Same restart-to-apply rule as above.
    pub xray_routing_strategy: String,
    /// URL the "test outbound" button fetches from the server to confirm
    /// the egress reaches the internet. Stored only; not part of the xray
    /// config (a single freedom outbound needs no observatory).
    pub xray_test_url: String,
    /// Block the sniffed `bittorrent` protocol via a blackhole outbound
    /// (needs inbound sniffing enabled to detect it).
    pub xray_block_bittorrent: bool,
    /// Destinations blackholed. Each entry is a domain, IP/CIDR, or a
    /// `geoip:`/`geosite:`/`ext:` matcher xray understands. Stored as a JSON
    /// array in the DB; surfaced here as a list.
    pub xray_blocked_ips: Vec<String>,
    pub xray_blocked_domains: Vec<String>,
    /// Domains forced out over IPv4 (routed to a freedom `UseIPv4` outbound).
    pub xray_ipv4_domains: Vec<String>,
    /// Operator-defined ordered routing rules, applied after the built-in ones.
    pub xray_custom_rules: Vec<RoutingRule>,
    /// Full evaluation order as tokens (system keys + custom rule ids).
    pub xray_rule_order: Vec<String>,
    /// Whether the panel serves its own port over HTTPS using an
    /// operator-provided cert+key. TLS binds at process start, so a change
    /// applies on the next panel restart.
    pub panel_tls_enabled: bool,
    /// PEM certificate (chain) for the panel HTTPS listener. Public material,
    /// round-tripped to the UI so the operator can review and replace it.
    pub panel_tls_cert: String,
    /// Whether a private key is stored. The key itself is never returned to the
    /// client — the UI shows a "key configured" state and only transmits a key
    /// when the operator pastes a replacement.
    pub panel_tls_key_set: bool,
}

/// Body for `PUT /api/settings/panel`. Same shape as the read view —
/// kept as a separate type because future writable settings (CORS
/// allowlist, log level, etc.) may carry different validation than
/// the read response.
#[derive(Debug, Deserialize, TS)]
#[ts(export, export_to = "../../frontend/src/api/types/settings.ts")]
pub struct PanelSettingsUpdate {
    pub panel_port: i32,
    pub panel_base_path: String,
    pub sub_enabled: bool,
    pub sub_host_override: String,
    #[serde(default)]
    pub sub_link_host: String,
    pub sub_update_interval_hours: i32,
    pub sub_brand_name: String,
    pub sub_service_url: String,
    pub sub_port: i32,
    pub xray_freedom_strategy: String,
    pub xray_routing_strategy: String,
    pub xray_test_url: String,
    pub xray_block_bittorrent: bool,
    pub xray_blocked_ips: Vec<String>,
    pub xray_blocked_domains: Vec<String>,
    pub xray_ipv4_domains: Vec<String>,
    #[serde(default)]
    pub xray_custom_rules: Vec<RoutingRule>,
    #[serde(default)]
    pub xray_rule_order: Vec<String>,
    #[serde(default)]
    pub panel_tls_enabled: bool,
    #[serde(default)]
    pub panel_tls_cert: String,
    /// New private key (PEM). Empty string ≡ keep the stored key — so saving any
    /// other settings section doesn't wipe it and the key need only be pasted
    /// once. A non-empty value replaces the stored key.
    #[serde(default)]
    pub panel_tls_key: String,
}

#[derive(Debug, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../frontend/src/api/types/settings.ts")]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../frontend/src/api/types/settings.ts")]
pub struct LoginResponse {
    pub token: String,
    pub user: UserView,
}

#[derive(Debug, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../frontend/src/api/types/settings.ts")]
pub struct UserView {
    pub id: String,
    pub username: String,
    pub is_admin: bool,
}

/// Body for `POST /api/auth/credentials`.
///
/// `current_password` is always required — proves the caller actually
/// knows the existing password, not just that they hold a still-valid
/// session token (a token can outlive the admin's awareness of it).
/// `new_username` / `new_password` are individually optional so the
/// operator can change either one without re-typing the other; an
/// empty / whitespace-only string is treated the same as "not set".
/// The handler rejects bodies where neither new field carries a value.
#[derive(Debug, Deserialize, TS)]
#[ts(export, export_to = "../../frontend/src/api/types/settings.ts")]
pub struct ChangeCredentialsRequest {
    pub current_password: String,
    pub new_username: Option<String>,
    pub new_password: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub username: String,
    pub is_admin: bool,
    /// Snapshot of `users.token_version` at the time the token was issued.
    /// Every authenticated request re-fetches this column from the DB and
    /// rejects the token if it doesn't match — that's how "logout everywhere"
    /// / "rotate after password change" will be implemented without an
    /// in-memory blocklist.
    pub tv: i64,
    // u64 (not usize) so the type is stable across 32/64-bit targets and the
    // sign-checked conversion in `create_token` errors loudly instead of
    // silently producing a 0-valued (= already-expired or eternal) token.
    pub exp: u64,
    pub iat: u64,
}
