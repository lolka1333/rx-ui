use serde::{Deserialize, Serialize};
use ts_rs::TS;

/// Runtime configuration the panel reads from DB at boot. Holds the
/// values an operator can change from the UI without editing the env
/// file: TCP port + URL prefix the panel binds to, plus subscription
/// knobs that shape what `/sub/{token}` returns to client apps. Panel
/// access fields are applied live (port via dual-listener swap, base
/// path via router rebuild); subscription fields are read on every
/// subscription request, so they take effect immediately.
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
    /// inside every share-link in the subscription bundle. Empty ≡ keep
    /// auto-detect (the panel's outbound IP).
    pub sub_host_override: String,
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
    pub sub_update_interval_hours: i32,
    pub sub_brand_name: String,
    pub sub_service_url: String,
    pub sub_port: i32,
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
