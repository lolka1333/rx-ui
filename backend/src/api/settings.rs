//! Runtime panel settings — listener (port, URL prefix, TLS), subscription
//! delivery, and the xray routing/Freedom knobs — plus the machinery to apply
//! them without restarting the process. Routing rules are pushed into the live
//! xray (see `xray::reload::hot_apply_routing`); the two listener fields are
//! applied here.
//!
//! Port and prefix are applied by rebuilding the router (`build_router`, which
//! mounts the prefix as a static `nest`) and swapping the `TcpListener`:
//!
//! * **Port change** — a single `TcpListener` is bound to exactly one
//!   socket address, so we spawn a *new* listener on the new port and let
//!   the old one keep serving for a grace period, so the in-flight PUT
//!   response makes it out before the old socket goes away. After the
//!   grace window the old listener drains via its oneshot shutdown signal.
//!
//! * **Prefix change** (same port) — the nest is static, so we tear the
//!   old listener down, wait a short beat for the OS to release the socket
//!   (Windows otherwise returns EADDRINUSE on the immediate re-bind), then
//!   bind a freshly-built router on the same port. A ~100ms unbound
//!   window; the UI reconnects — by redirecting after the save, or, when it has
//!   a routing warning to show first, by handing the operator the new address.

use crate::{
    AppState,
    auth::AuthUser,
    build_router,
    error::{AppError, AppResult},
    models::{PanelSettings, PanelSettingsUpdate, RoutingRule},
};
use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    routing::{get, post},
};
use axum_server::{Handle, tls_rustls::RustlsConfig};
use std::{net::TcpListener as StdTcpListener, sync::atomic::Ordering, time::Duration};
use tokio::{net::TcpListener, sync::oneshot};

/// How long we keep the old listener alive after a port change. Five
/// seconds easily covers the in-flight PUT response + a couple of
/// retries on top — anything longer just keeps a stale socket
/// open without serving useful traffic.
const PORT_SWAP_GRACE: Duration = Duration::from_secs(5);

/// xray freedom-outbound `domainStrategy` values the panel accepts. xray
/// would reject anything else at config-validate time anyway; checking here
/// turns a would-be failed restart into a clean 400 at save time.
const FREEDOM_STRATEGIES: &[&str] = &[
    "AsIs",
    "UseIP",
    "UseIPv4",
    "UseIPv6",
    "UseIPv4v6",
    "UseIPv6v4",
    "ForceIP",
    "ForceIPv4",
    "ForceIPv6",
    "ForceIPv4v6",
    "ForceIPv6v4",
];
/// xray routing-block `domainStrategy` values.
const ROUTING_STRATEGIES: &[&str] = &["AsIs", "IPIfNonMatch", "IPOnDemand"];

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/panel", get(get_panel).put(update_panel))
        .route("/panel/restart", post(restart_panel))
}

/// Operator-provided TLS material for the panel's own HTTPS listener.
/// Both blobs are PEM. Validity is checked when a listener is bound
/// (`RustlsConfig::from_pem`); a malformed pair is rejected at save time and
/// falls back to plain HTTP at boot.
#[derive(Clone)]
pub struct PanelTls {
    pub cert_pem: String,
    pub key_pem: String,
}

async fn get_panel(
    _user: AuthUser,
    State(state): State<AppState>,
) -> AppResult<Json<PanelSettings>> {
    Ok(Json(load_panel_settings(&state.db).await?))
}

/// Load the whole `panel_settings` row into `PanelSettings`. Shared by the GET
/// handler and callers that need one stored value — e.g. the outbound
/// connectivity test reading `xray_test_url`. Kept as the single whole-row
/// SELECT (rather than a second narrow single-column query) so no extra sqlx
/// offline-cache entry is needed — a real constraint in this repo, where
/// regenerating that cache is fragile.
pub async fn load_panel_settings(db: &crate::db::DbPool) -> AppResult<PanelSettings> {
    let row = sqlx::query!(
        "SELECT panel_port, panel_base_path,
                sub_enabled, sub_host_override, sub_link_host,
                sub_update_interval_hours,
                sub_brand_name, sub_service_url, sub_port,
                xray_freedom_strategy, xray_routing_strategy, xray_test_url,
                xray_block_bittorrent, xray_blocked_ips, xray_blocked_domains,
                xray_ipv4_domains, xray_custom_rules, xray_rule_order,
                panel_tls_enabled, panel_tls_cert, panel_tls_key,
                sub_tls_mode, sub_cert_pem, sub_key_pem
            FROM panel_settings WHERE id = 1"
    )
    .fetch_one(db)
    .await?;
    // JSON-array / JSON-object columns; a parse failure (hand-edited DB)
    // degrades to an empty value rather than a 500.
    let list = |s: &str| serde_json::from_str::<Vec<String>>(s).unwrap_or_default();
    let xray_custom_rules =
        serde_json::from_str::<Vec<RoutingRule>>(&row.xray_custom_rules).unwrap_or_default();
    Ok(PanelSettings {
        panel_port: i32::try_from(row.panel_port).unwrap_or(8080),
        panel_base_path: row.panel_base_path,
        sub_enabled: row.sub_enabled != 0,
        sub_host_override: row.sub_host_override,
        sub_link_host: row.sub_link_host,
        sub_update_interval_hours: i32::try_from(row.sub_update_interval_hours).unwrap_or(12),
        sub_brand_name: row.sub_brand_name,
        sub_service_url: row.sub_service_url,
        sub_port: i32::try_from(row.sub_port).unwrap_or(0),
        xray_freedom_strategy: row.xray_freedom_strategy,
        xray_routing_strategy: row.xray_routing_strategy,
        xray_test_url: row.xray_test_url,
        xray_block_bittorrent: row.xray_block_bittorrent != 0,
        xray_blocked_ips: list(&row.xray_blocked_ips),
        xray_blocked_domains: list(&row.xray_blocked_domains),
        xray_ipv4_domains: list(&row.xray_ipv4_domains),
        xray_custom_rules,
        xray_rule_order: list(&row.xray_rule_order),
        panel_tls_enabled: row.panel_tls_enabled != 0,
        panel_tls_cert: row.panel_tls_cert,
        // Never echo the private key back to the client — only whether one is set.
        panel_tls_key_set: !row.panel_tls_key.trim().is_empty(),
        sub_tls_mode: row.sub_tls_mode,
        sub_cert_pem: row.sub_cert_pem,
        sub_key_set: !row.sub_key_pem.trim().is_empty(),
    })
}

async fn update_panel(
    _user: AuthUser,
    State(state): State<AppState>,
    Json(body): Json<PanelSettingsUpdate>,
) -> AppResult<Json<serde_json::Value>> {
    let NormalizedPanel {
        new_port,
        base_path: normalised,
        sub_host,
        sub_link_host,
        sub_brand,
        sub_service_url,
        xray_freedom_strategy,
        xray_routing_strategy,
        xray_test_url,
        xray_block_bittorrent,
        xray_blocked_ips,
        xray_blocked_domains,
        xray_ipv4_domains,
    } = validate_panel_update(&body)?;
    // Validate custom rules + order up front, so a bad rule aborts before any
    // DB write. Valid targets = the reserved built-ins ∪ the tags of currently-
    // enabled custom outbounds (a rule may route to an operator's relay).
    let valid_targets = valid_rule_targets(&state.db).await?;
    let (custom_rules_json, rule_order_json) = validate_custom_routing(&body, &valid_targets)?;

    // Panel HTTPS: validate + resolve the cert/key (an empty incoming key keeps
    // the stored one) before persisting — a bad pair fails here as a clean 400
    // the operator sees in the form, not as a failed restart later.
    let (tls_enabled_i, tls_cert, tls_key) = resolve_panel_tls(&state.db, &body).await?;
    // Subscription TLS is independent of the panel's: validate the mode + (for
    // `custom`) the separate cert/key pair, keeping the stored key when the
    // incoming one is blank — same convention as the panel cert above.
    let (sub_tls_mode, sub_cert, sub_key, sub_tls_changed) =
        resolve_sub_tls(&state.db, &body).await?;

    // Snapshot routing-relevant fields BEFORE the UPDATE, so we only hot-apply
    // routing when it actually changed. An unrelated save (brand / TLS / sub
    // port) must not touch the live router or risk a recovery restart.
    let routing_changed = routing_fields_changed(
        &state.db,
        &custom_rules_json,
        &rule_order_json,
        &xray_blocked_ips,
        &xray_blocked_domains,
        &xray_ipv4_domains,
        xray_block_bittorrent,
    )
    .await?;

    let sub_enabled_i = i64::from(body.sub_enabled);
    let xray_bittorrent_i = i64::from(xray_block_bittorrent);
    sqlx::query!(
        "UPDATE panel_settings
            SET panel_port = ?,
                panel_base_path = ?,
                sub_enabled = ?,
                sub_host_override = ?,
                sub_link_host = ?,
                sub_update_interval_hours = ?,
                sub_brand_name = ?,
                sub_service_url = ?,
                sub_port = ?,
                xray_freedom_strategy = ?,
                xray_routing_strategy = ?,
                xray_test_url = ?,
                xray_block_bittorrent = ?,
                xray_blocked_ips = ?,
                xray_blocked_domains = ?,
                xray_ipv4_domains = ?,
                xray_custom_rules = ?,
                xray_rule_order = ?,
                panel_tls_enabled = ?,
                panel_tls_cert = ?,
                panel_tls_key = ?,
                sub_tls_mode = ?,
                sub_cert_pem = ?,
                sub_key_pem = ?,
                updated_at = datetime('now')
            WHERE id = 1",
        body.panel_port,
        normalised,
        sub_enabled_i,
        sub_host,
        sub_link_host,
        body.sub_update_interval_hours,
        sub_brand,
        sub_service_url,
        body.sub_port,
        xray_freedom_strategy,
        xray_routing_strategy,
        xray_test_url,
        xray_bittorrent_i,
        xray_blocked_ips,
        xray_blocked_domains,
        xray_ipv4_domains,
        custom_rules_json,
        rule_order_json,
        tls_enabled_i,
        tls_cert,
        tls_key,
        sub_tls_mode,
        sub_cert,
        sub_key,
    )
    .execute(&state.db)
    .await?;

    // Hot-apply the just-persisted routing rules (no restart) — only when they
    // actually changed; see docs on hot_apply_routing. Done BEFORE the listener
    // rebind: the UPDATE has already committed and routing doesn't depend on
    // listener state, so a rebind failure must not strand the rule change (the
    // change-gate would see no delta on the operator's retry).
    // Re-push when a previous attempt left the router out of step, even if this
    // save changes nothing routing-related: without it the operator's retry is
    // silently a no-op.
    let routing_changed = routing_changed || state.routing_out_of_sync.load(Ordering::Relaxed);
    let routing = if routing_changed {
        Some(crate::xray::reload::hot_apply_routing(&state).await)
    } else {
        None
    };

    apply_listener_changes(&state, &body, new_port, &normalised, sub_tls_changed).await?;
    // When this save didn't push, the router can still be stale from an earlier
    // one that failed in a way not worth retrying — report that rather than let
    // the save read as clean.
    let lingering = state.routing_stale.read().await.clone();
    Ok(Json(routing_body(routing, lingering)))
}

/// Report what happened to the live router. The row is committed either way, so
/// this is never an error status — but it must not read as "done" when the
/// running xray never took the rules, which is all the UI has to go on.
fn routing_body(
    routing: Option<crate::xray::reload::RoutingApply>,
    lingering: Option<String>,
) -> serde_json::Value {
    // Nothing pushed this time: still say so if a previous attempt left the
    // router behind the DB. Silence here is what makes a stale router look like
    // a clean save on every subsequent edit.
    let Some(applied) = routing else {
        return lingering.map_or_else(
            || serde_json::json!({}),
            |detail| serde_json::json!({ "routing_live": false, "routing_detail": detail }),
        );
    };
    applied.detail().map_or_else(
        // Live — but say whether it cost a restart, so the UI can't tell an
        // operator "no restart needed" right after their tunnels dropped.
        || {
            serde_json::json!({
                "routing_live": true,
                "routing_restarted": applied.dropped_connections(),
            })
        },
        |detail| serde_json::json!({ "routing_live": false, "routing_detail": detail }),
    )
}

/// Whether a settings update touches anything the router cares about (rules,
/// order, block/ipv4 lists, bittorrent), compared against the currently-stored
/// values. Lets the caller skip the live-router push on unrelated saves.
async fn routing_fields_changed(
    db: &crate::db::DbPool,
    custom_rules_json: &str,
    rule_order_json: &str,
    blocked_ips: &str,
    blocked_domains: &str,
    ipv4_domains: &str,
    block_bittorrent: bool,
) -> AppResult<bool> {
    let old = sqlx::query!(
        r#"SELECT xray_custom_rules AS "xray_custom_rules!: String",
                  xray_rule_order AS "xray_rule_order!: String",
                  xray_blocked_ips AS "xray_blocked_ips!: String",
                  xray_blocked_domains AS "xray_blocked_domains!: String",
                  xray_ipv4_domains AS "xray_ipv4_domains!: String",
                  xray_block_bittorrent
             FROM panel_settings WHERE id = 1"#
    )
    .fetch_one(db)
    .await?;
    Ok(old.xray_custom_rules != custom_rules_json
        || old.xray_rule_order != rule_order_json
        || old.xray_blocked_ips != blocked_ips
        || old.xray_blocked_domains != blocked_domains
        || old.xray_ipv4_domains != ipv4_domains
        || (old.xray_block_bittorrent != 0) != block_bittorrent)
}

/// Rebind the sub + panel listeners after a settings write. The sub listener
/// goes first — it's independent of the panel listener, so a panel-swap failure
/// must not skip an already-persisted sub-TLS / sub-port change (the next save
/// would see no delta and never apply it).
async fn apply_listener_changes(
    state: &AppState,
    body: &PanelSettingsUpdate,
    new_port: u16,
    normalised: &str,
    sub_tls_changed: bool,
) -> AppResult<()> {
    let current_sub_port = state.current_sub_port.load(Ordering::Relaxed);
    let new_sub_port = u16::try_from(body.sub_port).unwrap_or(0);
    swap_sub_listener(state, new_sub_port, current_sub_port, sub_tls_changed).await?;

    // Snapshot the previous prefix BEFORE installing the new one — the
    // rebind-on-path-change branch needs to know whether the path actually
    // moved, and once the RwLock is updated we'd compare the value with itself.
    let previous_prefix = {
        let mut guard = state.base_path.write().await;
        std::mem::replace(&mut *guard, normalised.to_owned())
    };
    let current_port = state.current_port.load(Ordering::Relaxed);
    let prefix_changed = previous_prefix != normalised;
    swap_panel_listener(
        state,
        new_port,
        current_port,
        prefix_changed,
        &previous_prefix,
        normalised,
    )
    .await
}

/// Resolve + validate the panel TLS fields for a settings write. An empty
/// incoming key keeps the stored one (so saving any other section can't wipe
/// it); enabling HTTPS requires both halves and that they form a usable pair.
/// Returns `(enabled_flag, cert_pem, key_pem)` ready to bind into the UPDATE.
async fn resolve_panel_tls(
    db: &crate::db::DbPool,
    body: &PanelSettingsUpdate,
) -> AppResult<(i64, String, String)> {
    let stored_key: String = sqlx::query_scalar!(
        r#"SELECT panel_tls_key AS "panel_tls_key!: String" FROM panel_settings WHERE id = 1"#
    )
    .fetch_one(db)
    .await?;
    let cert = body.panel_tls_cert.trim().to_owned();
    let key = if body.panel_tls_key.trim().is_empty() {
        stored_key
    } else {
        body.panel_tls_key.trim().to_owned()
    };
    if body.panel_tls_enabled {
        if cert.is_empty() || key.is_empty() {
            return Err(AppError::BadRequest(
                "HTTPS requires both a certificate and a private key".to_owned(),
            ));
        }
        RustlsConfig::from_pem(cert.clone().into_bytes(), key.clone().into_bytes())
            .await
            .map_err(|e| {
                AppError::BadRequest(format!("invalid TLS certificate or private key: {e}"))
            })?;
    }
    Ok((i64::from(body.panel_tls_enabled), cert, key))
}

/// Resolve + validate the subscription TLS fields. Mode is normalised to
/// `inherit` | `off` | `custom` (anything else ≡ `inherit`). An empty incoming
/// cert OR key keeps the stored one — the custom-cert form fields are unmounted
/// outside `custom` mode (so a save from another section, or in inherit/off,
/// sends them empty and must not wipe a stored pair). `custom` requires both
/// halves and a usable pair. Returns `(mode, cert_pem, key_pem, changed)`, where
/// `changed` (any of mode/cert/key differs from stored) drives the live
/// force-rebind of the sub listener.
async fn resolve_sub_tls(
    db: &crate::db::DbPool,
    body: &PanelSettingsUpdate,
) -> AppResult<(String, String, String, bool)> {
    let stored = sqlx::query!(
        r#"SELECT sub_tls_mode AS "sub_tls_mode!: String",
                  sub_cert_pem AS "sub_cert_pem!: String",
                  sub_key_pem  AS "sub_key_pem!: String"
            FROM panel_settings WHERE id = 1"#
    )
    .fetch_one(db)
    .await?;
    let mode = match body.sub_tls_mode.trim() {
        "off" => "off",
        "custom" => "custom",
        _ => "inherit",
    }
    .to_owned();
    let cert = if body.sub_cert_pem.trim().is_empty() {
        stored.sub_cert_pem.clone()
    } else {
        body.sub_cert_pem.trim().to_owned()
    };
    let key = if body.sub_key_pem.trim().is_empty() {
        stored.sub_key_pem.clone()
    } else {
        body.sub_key_pem.trim().to_owned()
    };
    if mode == "custom" {
        if cert.is_empty() || key.is_empty() {
            return Err(AppError::BadRequest(
                "custom subscription TLS requires both a certificate and a private key".to_owned(),
            ));
        }
        RustlsConfig::from_pem(cert.clone().into_bytes(), key.clone().into_bytes())
            .await
            .map_err(|e| {
                AppError::BadRequest(format!(
                    "invalid subscription certificate or private key: {e}"
                ))
            })?;
    }
    // The sub listener binds its TLS once at spawn, so any change here needs a
    // live rebind even when the port is unchanged — signal it to the caller.
    let changed =
        mode != stored.sub_tls_mode || cert != stored.sub_cert_pem || key != stored.sub_key_pem;
    Ok((mode, cert, key, changed))
}

/// Validated + normalised form of a `PanelSettingsUpdate`. Owns its
/// strings so the caller can bind them straight into the UPDATE.
struct NormalizedPanel {
    new_port: u16,
    base_path: String,
    sub_host: String,
    sub_link_host: String,
    sub_brand: String,
    sub_service_url: String,
    xray_freedom_strategy: String,
    xray_routing_strategy: String,
    xray_test_url: String,
    xray_block_bittorrent: bool,
    // The three match lists, cleaned + serialized as JSON arrays for storage.
    xray_blocked_ips: String,
    xray_blocked_domains: String,
    xray_ipv4_domains: String,
}

/// Canonicalise the panel base path: empty OR leading-slash + no trailing
/// slash, restricted to URL-safe chars. Single "/" collapses to "" so two
/// stored values can't mean the same mount point.
fn normalize_base_path(raw: &str) -> AppResult<String> {
    let prefix_raw = raw.trim();
    if prefix_raw.is_empty() || prefix_raw == "/" {
        return Ok(String::new());
    }
    let trimmed = prefix_raw.trim_matches('/');
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '/')
    {
        return Err(AppError::BadRequest(
            "panel_base_path may only contain letters, digits, '-', '_', '/'".to_owned(),
        ));
    }
    Ok(format!("/{trimmed}"))
}

/// Validate and normalise an incoming panel-settings PATCH. Pure (no DB,
/// no listener state) — every bound here is an operator mistake the OS or
/// the share-link builder would otherwise choke on.
fn validate_panel_update(body: &PanelSettingsUpdate) -> AppResult<NormalizedPanel> {
    // Port must fit a real TCP port. Anything outside [1, 65535] is a
    // definite operator mistake the OS would refuse to bind anyway — fail
    // loud here so the operator sees it in the form, not in tomorrow's log.
    if !(1..=65535).contains(&body.panel_port) {
        return Err(AppError::BadRequest(
            "panel_port must be between 1 and 65535".to_owned(),
        ));
    }
    let new_port = u16::try_from(body.panel_port).expect("range-checked above");

    let base_path = normalize_base_path(&body.panel_base_path)?;

    // Two subscription hosts, same shape (bare hostname / IPv4 / bracketed
    // IPv6, no scheme/path/spaces): `sub_host_override` is the server address
    // spliced into each config as an `@host:port` chunk; `sub_link_host` is
    // the host of the subscription URL itself. A stray `https://` or `/foo`
    // in either breaks the link, so both are validated the same way.
    let sub_host = validate_optional_host(&body.sub_host_override, "sub_host_override")?;
    let sub_link_host = validate_optional_host(&body.sub_link_host, "sub_link_host")?;

    // Update interval: <1h hammers the panel; >1week stalls config
    // rotation. Bounds mirror what v2rayN / Hiddify actually honour.
    if !(1..=168).contains(&body.sub_update_interval_hours) {
        return Err(AppError::BadRequest(
            "sub_update_interval_hours must be between 1 and 168 (one week)".to_owned(),
        ));
    }

    // Brand name: strip control chars, cap at 60. Empty = "no override".
    // The strict filter keeps it safe to embed in both a response header
    // and the React hero text without per-site escaping.
    let sub_brand = body
        .sub_brand_name
        .trim()
        .chars()
        .filter(|c| !c.is_control())
        .collect::<String>();
    if sub_brand.chars().count() > 60 {
        return Err(AppError::BadRequest(
            "sub_brand_name is too long (max 60 chars)".to_owned(),
        ));
    }

    // Service URL: empty OR `http(s)://` + content. Restricting the scheme
    // blocks `javascript:` / `data:` payloads from the landing page's `<a href>`.
    let sub_service_url = validate_optional_http_url(&body.sub_service_url, "sub_service_url")?;

    // Sub-port: 0 = disabled OR valid TCP port, and must differ from the
    // panel port (binding the same port twice conflicts AND lets the full
    // API listener shadow the sub-only router — the opposite of intent).
    if body.sub_port != 0 && !(1..=65535).contains(&body.sub_port) {
        return Err(AppError::BadRequest(
            "sub_port must be 0 (disabled) or a valid TCP port (1..=65535)".to_owned(),
        ));
    }
    if body.sub_port != 0 && body.sub_port == body.panel_port {
        return Err(AppError::BadRequest(
            "sub_port must differ from panel_port".to_owned(),
        ));
    }

    let (xray_freedom_strategy, xray_routing_strategy, xray_test_url) =
        validate_xray_settings(body)?;
    let (xray_block_bittorrent, xray_blocked_ips, xray_blocked_domains, xray_ipv4_domains) =
        validate_xray_routing(body)?;

    Ok(NormalizedPanel {
        new_port,
        base_path,
        sub_host,
        sub_link_host,
        sub_brand,
        sub_service_url,
        xray_freedom_strategy,
        xray_routing_strategy,
        xray_test_url,
        xray_block_bittorrent,
        xray_blocked_ips,
        xray_blocked_domains,
        xray_ipv4_domains,
    })
}

/// Validate the xray engine settings (Freedom/routing `domainStrategy` + test
/// URL) and return the trimmed, validated trio. Split out of
/// `validate_panel_update` to keep that function under the line cap.
fn validate_xray_settings(body: &PanelSettingsUpdate) -> AppResult<(String, String, String)> {
    // Freedom / routing domainStrategy: only values xray accepts, else the
    // next restart's config-validate fails and leaves the engine down.
    let freedom = body.xray_freedom_strategy.trim();
    if !FREEDOM_STRATEGIES.contains(&freedom) {
        return Err(AppError::BadRequest(format!(
            "xray_freedom_strategy must be one of: {}",
            FREEDOM_STRATEGIES.join(", ")
        )));
    }
    let routing = body.xray_routing_strategy.trim();
    if !ROUTING_STRATEGIES.contains(&routing) {
        return Err(AppError::BadRequest(format!(
            "xray_routing_strategy must be one of: {}",
            ROUTING_STRATEGIES.join(", ")
        )));
    }

    // Test URL: empty OR `http(s)://` + content (same rule the test endpoint
    // enforces on use). Scheme restriction blocks file:// and the like.
    let test_url = validate_optional_http_url(&body.xray_test_url, "xray_test_url")?;

    Ok((freedom.to_owned(), routing.to_owned(), test_url))
}

/// Validate the routing block (the "basic connections" lists + bittorrent
/// toggle). Returns the toggle plus the three match lists, each cleaned and
/// serialized as a JSON array string ready to bind into the UPDATE.
fn validate_xray_routing(body: &PanelSettingsUpdate) -> AppResult<(bool, String, String, String)> {
    Ok((
        body.xray_block_bittorrent,
        validate_match_list(&body.xray_blocked_ips, "xray_blocked_ips")?,
        validate_match_list(&body.xray_blocked_domains, "xray_blocked_domains")?,
        validate_match_list(&body.xray_ipv4_domains, "xray_ipv4_domains")?,
    ))
}

/// Validate an optional bare-host field (hostname / IPv4 / bracketed IPv6):
/// empty is allowed; otherwise no scheme, path, query, or spaces, capped at
/// the DNS FQDN limit (253). Shared by both subscription host fields
/// (`sub_host_override`, `sub_link_host`). Returns the trimmed value ready to
/// store; `field` is spliced into the error so the messages name the culprit.
fn validate_optional_host(value: &str, field: &str) -> AppResult<String> {
    let host = value.trim();
    if !host.is_empty() {
        if host.contains("://") || host.contains('/') || host.contains('?') || host.contains(' ') {
            return Err(AppError::BadRequest(format!(
                "{field} must be a bare hostname or IP — no scheme, path, or spaces"
            )));
        }
        if host.len() > 253 {
            return Err(AppError::BadRequest(format!(
                "{field} is too long (max 253 chars)"
            )));
        }
    }
    Ok(host.to_owned())
}

/// Validate an optional `http(s)://` URL field. Empty is allowed; otherwise the
/// value must contain no control characters, start with `http://` or
/// `https://`, be at most 2048 chars, and parse as a URL with a non-empty host.
/// Returns the trimmed value ready to store. `field` is spliced into the error
/// messages so the sub-service and xray-test URL validators share one
/// implementation.
fn validate_optional_http_url(value: &str, field: &str) -> AppResult<String> {
    let url = value.trim();
    if !url.is_empty() {
        if url.chars().any(char::is_control) {
            return Err(AppError::BadRequest(format!(
                "{field} contains control characters"
            )));
        }
        if !url.starts_with("http://") && !url.starts_with("https://") {
            return Err(AppError::BadRequest(format!(
                "{field} must start with http:// or https://"
            )));
        }
        if url.len() > 2048 {
            return Err(AppError::BadRequest(format!(
                "{field} is too long (max 2048 chars)"
            )));
        }
        // Full parse, not just the prefix: a value like `http://` (no host) or
        // `http://a b` (space) passes the checks above but fails reqwest at
        // request time, where the outbound test would surface it as a
        // misattributed "no egress". Reject it here as a clear config error.
        let parsed = reqwest::Url::parse(url)
            .map_err(|e| AppError::BadRequest(format!("{field} is not a valid URL: {e}")))?;
        if parsed.host_str().is_none_or(str::is_empty) {
            return Err(AppError::BadRequest(format!("{field} has no host")));
        }
    }
    Ok(url.to_owned())
}

/// Caps shared by every routing match list (the basic block-lists and the
/// custom-rule matchers): max entries per list, max chars per entry.
const MAX_LIST_ENTRIES: usize = 500;
const MAX_ENTRY_LEN: usize = 256;

/// Per-entry sanity for a routing match list, shared by `validate_match_list`
/// (basic block-lists) and the custom-rule matchers: cap count + length and
/// reject control chars / internal whitespace — matcher tokens (domains,
/// CIDRs, `geoip:`/`geosite:` labels, ports) never contain spaces. Blank
/// entries are tolerated (callers drop them). The real syntax check is the
/// router-config builder on the hot-apply path, or `xray run -test` on the
/// restart path.
fn validate_list_entries(field: &str, list: &[String]) -> AppResult<()> {
    if list.len() > MAX_LIST_ENTRIES {
        return Err(AppError::BadRequest(format!(
            "{field} has too many entries (max {MAX_LIST_ENTRIES})"
        )));
    }
    for entry in list {
        let e = entry.trim();
        if e.is_empty() {
            continue;
        }
        if e.len() > MAX_ENTRY_LEN {
            return Err(AppError::BadRequest(format!(
                "{field} entry too long (max {MAX_ENTRY_LEN} chars): {e}"
            )));
        }
        if e.chars().any(|c| c.is_control() || c.is_whitespace()) {
            return Err(AppError::BadRequest(format!(
                "{field} entry must not contain spaces or control characters: {e}"
            )));
        }
    }
    Ok(())
}

/// Clean one basic-block match list: validate its entries, then return the
/// trimmed non-blank survivors serialized as a JSON array string ready to bind
/// into the UPDATE.
fn validate_match_list(list: &[String], field: &str) -> AppResult<String> {
    validate_list_entries(field, list)?;
    let cleaned: Vec<&str> = list
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();
    serde_json::to_string(&cleaned).map_err(|e| AppError::Internal(anyhow::anyhow!(e)))
}

/// The set of outbound tags a custom rule may target right now: the built-in
/// outbounds (`crate::xray::config_gen::BUILTIN_OUTBOUND_TAGS`) ∪ every enabled
/// custom outbound's tag. Anything else would dangle (no such outbound), so
/// it's rejected at save time.
async fn valid_rule_targets(
    db: &crate::db::DbPool,
) -> AppResult<std::collections::HashSet<String>> {
    let mut set: std::collections::HashSet<String> = crate::xray::config_gen::BUILTIN_OUTBOUND_TAGS
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    for ob in crate::api::outbounds::load_custom_outbounds(db).await? {
        // A reverse BRIDGE outbound (VLESS carrying a reverse_tag) can't be a
        // routing target: the portal rejects any non-reverse command from that
        // account, so traffic routed to a bridge's tag dead-ends on every
        // connection. Its tag is an inbound source, not a destination — skip it.
        let is_bridge = matches!(
            &ob.protocol,
            crate::models::OutboundProtocolConfig::Vless(v) if !v.reverse_tag.trim().is_empty()
        );
        if ob.enabled && !is_bridge {
            set.insert(ob.tag);
        }
    }
    // A client's reverse_tag (VLESS Reverse Proxy portal): when a bridge dials
    // in as that user, xray registers its tunnel as an outbound under the tag on
    // THIS server, so a routing rule may legally target it. Bridge-side tags
    // (custom outbound reverse_tag) are inbound sources, not targets — omitted.
    let reverse_tags = sqlx::query_scalar!(
        r#"SELECT DISTINCT reverse_tag AS "reverse_tag!: String"
           FROM clients
           WHERE reverse_tag IS NOT NULL AND reverse_tag <> ''"#
    )
    .fetch_all(db)
    .await?;
    set.extend(reverse_tags);
    Ok(set)
}

/// Trim entries and drop blanks from a matcher list. Both rule emitters must
/// see identical tokens: a blank entry is a match-everything `Substr("")` to
/// xray's JSON parser but a hard error to the proto builder.
fn clean_entries(v: &[String]) -> Vec<String> {
    v.iter()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Parse a port spec and return it CANONICALISED ("443", "1024-65535", joined by
/// commas) plus whether it yields any range at all. Storing the canonical form
/// keeps the JSON bootstrap and proto hot-apply paths byte-identical: xray's own
/// JSON parser does not trim around a range dash, so "1024 - 65535" would parse
/// here and be rejected by xray, silently blocking every later config write.
fn canonical_port_spec(field: &str, spec: &str, rule_name: &str) -> AppResult<(String, bool)> {
    let list = crate::xray::router_rules::parse_port_list(spec).map_err(|e| {
        AppError::BadRequest(format!(
            "custom rule '{rule_name}': invalid {field} '{spec}' ({e})"
        ))
    })?;
    let Some(list) = list else {
        return Ok((String::new(), false));
    };
    let text = list
        .range
        .iter()
        .map(|r| {
            if r.from == r.to {
                r.from.to_string()
            } else {
                format!("{}-{}", r.from, r.to)
            }
        })
        .collect::<Vec<_>>()
        .join(",");
    Ok((text, true))
}

/// Validate one operator rule and return it normalised (entries trimmed, blanks
/// dropped, ports canonicalised) — the form both emitters serialise and read, so
/// the JSON bootstrap and proto hot-apply paths always see identical tokens.
fn validate_and_clean_rule(
    r: &RoutingRule,
    valid_targets: &std::collections::HashSet<String>,
) -> AppResult<RoutingRule> {
    let id = r.id.trim();
    if id.is_empty() {
        return Err(AppError::BadRequest(
            "custom rule id must not be empty".to_owned(),
        ));
    }
    // Rule ids share the `rule_order` namespace with the system tokens, and
    // both emitters match the system arm first — an id like "ipv4" would make
    // the operator's rule silently vanish. Same size/control guard the order
    // tokens get; the id also ships as the proto rule_tag.
    if crate::xray::config_gen::SYSTEM_TOKENS.contains(&id) {
        return Err(AppError::BadRequest(format!(
            "custom rule id '{id}' is reserved"
        )));
    }
    if id.len() > 128 || id.chars().any(char::is_control) {
        return Err(AppError::BadRequest(format!(
            "invalid custom rule id '{id}'"
        )));
    }
    if !valid_targets.contains(&r.outbound_tag) {
        let mut known: Vec<&str> = valid_targets.iter().map(String::as_str).collect();
        known.sort_unstable();
        return Err(AppError::BadRequest(format!(
            "custom rule target '{}' is not a known outbound (valid: {})",
            r.outbound_tag,
            known.join(", ")
        )));
    }
    if r.name.chars().count() > 80 {
        return Err(AppError::BadRequest(
            "custom rule name too long (max 80 chars)".to_owned(),
        ));
    }
    validate_list_entries("domain", &r.domain)?;
    validate_list_entries("ip", &r.ip)?;
    validate_list_entries("source_ip", &r.source_ip)?;
    validate_list_entries("network", &r.network)?;
    validate_list_entries("protocol", &r.protocol)?;
    validate_list_entries("inbound_tag", &r.inbound_tag)?;
    validate_list_entries("user", &r.user)?;
    check_port_field("port", &r.port)?;
    check_port_field("source_port", &r.source_port)?;
    // Normalise matcher lists (trim, drop blanks) before anything else sees
    // them: a blank entry means "match everything" to xray's JSON parser but
    // is a hard error to the proto builder, so leaving it in would make the
    // restart and hot-apply paths behave differently.
    // Ports are stored CANONICALISED (rebuilt from the parse result), not as
    // typed. The two emitters disagree on whitespace: parse_port_list trims
    // both sides of a range, xray's JSON parser trims only around commas and
    // hands " 65535" straight to ParseUint, which rejects it. Storing the
    // canonical form makes both serialise the identical, xray-parsable spec.
    let (port, port_has_range) = canonical_port_spec("port", &r.port, &r.name)?;
    let (source_port, source_port_has_range) =
        canonical_port_spec("source_port", &r.source_port, &r.name)?;
    let has_port_matcher = port_has_range || source_port_has_range;
    let cleaned_rule = crate::models::RoutingRule {
        id: r.id.clone(),
        enabled: r.enabled,
        name: r.name.clone(),
        domain: clean_entries(&r.domain),
        ip: clean_entries(&r.ip),
        source_ip: clean_entries(&r.source_ip),
        port,
        source_port,
        network: clean_entries(&r.network),
        protocol: clean_entries(&r.protocol),
        inbound_tag: clean_entries(&r.inbound_tag),
        user: clean_entries(&r.user),
        outbound_tag: r.outbound_tag.clone(),
    };
    // Only tcp/udp (what the UI offers) may reach the router. Anything else
    // means different things on the two paths — the JSON emitter passes it
    // through as an inert matcher (rule never fires) while the proto builder
    // drops it (rule fires on everything) — so reject it outright.
    for n in &cleaned_rule.network {
        if !matches!(n.to_ascii_lowercase().as_str(), "tcp" | "udp") {
            return Err(AppError::BadRequest(format!(
                "custom rule '{}': unsupported network '{n}' (use tcp or udp)",
                cleaned_rule.name
            )));
        }
    }
    // A rule with no matcher (only an outbound_tag) is rejected by xray at
    // router build ("this rule has no effective fields"), which fails the
    // config `-test` and bricks the next restart. Checked on the CLEANED
    // rule so a matcher that was only blank entries counts as absent.
    let has_matcher = !cleaned_rule.domain.is_empty()
        || !cleaned_rule.ip.is_empty()
        || !cleaned_rule.source_ip.is_empty()
        || !cleaned_rule.network.is_empty()
        || !cleaned_rule.protocol.is_empty()
        || !cleaned_rule.inbound_tag.is_empty()
        || !cleaned_rule.user.is_empty()
        || has_port_matcher;
    if !has_matcher {
        return Err(AppError::BadRequest(format!(
            "custom rule '{}' has no match conditions — add at least one \
             (e.g. a network or domain); xray rejects a condition-less rule",
            cleaned_rule.name
        )));
    }
    Ok(cleaned_rule)
}

/// Validate the operator's custom routing rules + order tokens, returning the
/// pair of JSON strings ready to bind into the UPDATE (rules normalised via
/// `validate_and_clean_rule`). Light validation only — the router-config builder
/// (hot-apply) or `xray run -test` (restart) is the real syntax check; this
/// stops obviously-broken input (bad target, control chars, runaway sizes).
fn validate_custom_routing(
    body: &PanelSettingsUpdate,
    valid_targets: &std::collections::HashSet<String>,
) -> AppResult<(String, String)> {
    if body.xray_custom_rules.len() > 200 {
        return Err(AppError::BadRequest(
            "too many custom rules (max 200)".to_owned(),
        ));
    }
    let mut cleaned: Vec<crate::models::RoutingRule> =
        Vec::with_capacity(body.xray_custom_rules.len());
    for r in &body.xray_custom_rules {
        cleaned.push(validate_and_clean_rule(r, valid_targets)?);
    }
    // Ids key the evaluation order, and that order is de-duplicated — a repeated
    // id would silently drop one of the rules instead of applying both.
    let mut ids = std::collections::HashSet::with_capacity(cleaned.len());
    for r in &cleaned {
        if !ids.insert(r.id.as_str()) {
            return Err(AppError::BadRequest(format!(
                "duplicate custom rule id '{}'",
                r.id
            )));
        }
    }

    if body.xray_rule_order.len() > 1000 {
        return Err(AppError::BadRequest("rule order is too long".to_owned()));
    }
    for tok in &body.xray_rule_order {
        if tok.len() > 128 || tok.chars().any(char::is_control) {
            return Err(AppError::BadRequest("invalid rule order token".to_owned()));
        }
    }

    let custom =
        serde_json::to_string(&cleaned).map_err(|e| AppError::Internal(anyhow::anyhow!(e)))?;
    let order = serde_json::to_string(&body.xray_rule_order)
        .map_err(|e| AppError::Internal(anyhow::anyhow!(e)))?;
    Ok((custom, order))
}

/// A port / sourcePort field: free-form ("443", "1024-65535", "80, 443") — a
/// size + control-char guard only. `canonical_port_spec` is the syntax
/// authority and rewrites the value into its canonical form. Empty means
/// "any port".
fn check_port_field(field: &str, value: &str) -> AppResult<()> {
    let t = value.trim();
    if t.is_empty() {
        return Ok(());
    }
    if t.len() > 128 {
        return Err(AppError::BadRequest(format!("{field} is too long")));
    }
    if t.chars().any(char::is_control) {
        return Err(AppError::BadRequest(format!(
            "{field} must not contain control characters: {t}"
        )));
    }
    // Interior spaces are fine — the port input's own placeholder shows
    // "443, 1024-65535", and both consumers trim each part. `parse_port_list`
    // (called on the cleaned rule) is the actual syntax authority.
    Ok(())
}

/// Hot-swap the main panel listener after a settings change. Two cases:
///   * port changed → dual-listener: bind the new port, then drain the old
///     listener after `PORT_SWAP_GRACE` so the in-flight PUT response still
///     leaves on the old socket. (`path-only` or `port+path` walk here as
///     long as the new port differs from the running one.)
///   * port same, only the prefix moved → close-then-rebind on the same
///     port. ~10ms unbound window; the old prefix stops being served at once, so
///     the UI must send the operator to the new address (it redirects, or shows
///     the address when a routing warning has to stay on screen).
async fn swap_panel_listener(
    state: &AppState,
    new_port: u16,
    current_port: u16,
    prefix_changed: bool,
    previous_prefix: &str,
    normalised: &str,
) -> AppResult<()> {
    // Preserve the current HTTPS state across a listener rebind — a port or
    // prefix change shouldn't silently drop TLS until the next restart.
    let tls = load_tls_for_boot(&state.db).await;
    if new_port != current_port {
        let app = build_router(state.clone()).await;
        let new_tx = spawn_listener("0.0.0.0", new_port, app, tls)
            .await
            .map_err(|e| {
                AppError::Internal(anyhow::anyhow!(
                    "failed to bind new listener on port {new_port}: {e}"
                ))
            })?;
        let old_tx = {
            let mut guard = state.listener_shutdown.write().await;
            guard.replace(new_tx)
        };
        state.current_port.store(new_port, Ordering::Relaxed);
        tracing::info!(
            "panel listener swapped {current_port} → {new_port} \
             (old listener drains in {}s)",
            PORT_SWAP_GRACE.as_secs()
        );
        if let Some(old_tx) = old_tx {
            tokio::spawn(async move {
                tokio::time::sleep(PORT_SWAP_GRACE).await;
                let _ = old_tx.send(());
            });
        }
    } else if prefix_changed {
        // Same port, new prefix: tear the old listener down, then bind a fresh
        // one on the same port. We have to drop the old socket first (a second
        // listener can't share the port), so the re-bind races the OS releasing
        // it — `rebind_with_retry` retries through that window. CRITICAL: once
        // the old listener is gone, a re-bind failure would leave the panel with
        // nothing bound and unreachable until a manual restart, so the bind must
        // not be a single fallible attempt.
        let old_tx = {
            let mut guard = state.listener_shutdown.write().await;
            guard.take()
        };
        if let Some(old_tx) = old_tx {
            let _ = old_tx.send(());
        }
        let app = build_router(state.clone()).await;
        let new_tx = rebind_with_retry("0.0.0.0", current_port, app, tls).await?;
        *state.listener_shutdown.write().await = Some(new_tx);
        tracing::info!(
            "panel prefix swapped {previous_prefix:?} → {normalised:?} \
             on port {current_port} (re-bind complete)"
        );
    }
    Ok(())
}

/// Re-bind a listener on a just-freed port, retrying through the OS socket-
/// release window. The prefix-change swap has to drop the old same-port
/// listener *before* binding the new one, so the re-bind races the kernel
/// releasing the socket (Windows in particular returns EADDRINUSE for a short
/// window). A single attempt could therefore strand the panel with nothing
/// bound; retrying with a short beat between tries keeps a transient release
/// delay from taking the panel down. Carries the operator's TLS config so the
/// re-bound listener keeps serving HTTPS.
async fn rebind_with_retry(
    host: &str,
    port: u16,
    app: Router,
    tls: Option<PanelTls>,
) -> AppResult<oneshot::Sender<()>> {
    // ~4s total budget with escalating backoff (100ms → 500ms). The OS frees
    // the listening socket the moment the old listener drops it (axum-server
    // drops it on the graceful-shutdown signal, not after the connection
    // grace), so a single beat almost always suffices — the generous budget
    // just makes a transient release delay impossible to lose on.
    const ATTEMPTS: u32 = 10;
    let mut last_err: Option<std::io::Error> = None;
    for attempt in 1..=ATTEMPTS {
        tokio::time::sleep(Duration::from_millis(u64::from(attempt.min(5)) * 100)).await;
        match spawn_listener(host, port, app.clone(), tls.clone()).await {
            Ok(tx) => return Ok(tx),
            Err(e) => {
                tracing::warn!(
                    "panel re-bind on port {port} attempt {attempt}/{ATTEMPTS} failed: {e}"
                );
                last_err = Some(e);
            }
        }
    }
    // Exhausting the budget means the port is genuinely held by something else
    // (not our own just-closed socket) — unrecoverable without operator action.
    // Log loudly: the propagated 500 can't reach the operator (their request was
    // on the now-dead old listener), so the process log is the only signal.
    let detail = last_err.map_or_else(|| "unknown error".to_owned(), |e| e.to_string());
    tracing::error!(
        "panel listener could NOT be re-bound on port {port} after {ATTEMPTS} attempts \
         ({detail}); the panel is unreachable — restart the process to recover"
    );
    Err(AppError::Internal(anyhow::anyhow!(
        "failed to re-bind panel listener on port {port} after {ATTEMPTS} attempts: {detail}"
    )))
}

/// Sub-only listener swap, independent of the main listener. `new_sub_port`
/// of 0 ≡ tear down if running; any other value ≡ ensure listening there
/// (start fresh, or rebind if the current sub-port differs).
async fn swap_sub_listener(
    state: &AppState,
    new_sub_port: u16,
    current_sub_port: u16,
    force_rebind: bool,
) -> AppResult<()> {
    // Bind retries for the just-freed-port race (see the rebind loop below).
    const ATTEMPTS: u32 = 10;
    // `force_rebind` covers a TLS-config change at an unchanged port: the
    // listener binds its cert once at spawn, so it must be torn down and rebound
    // to pick up a new mode/cert even though the port didn't move.
    if new_sub_port == current_sub_port && !force_rebind {
        return Ok(());
    }
    let old_tx = state.sub_listener_shutdown.write().await.take();
    if let Some(tx) = old_tx {
        let _ = tx.send(());
    }
    if new_sub_port == 0 {
        state.current_sub_port.store(0, Ordering::Relaxed);
        // Only meaningful when something was actually running — a TLS change
        // while the sub port is 0 lands here too, and "disabled (was port 0)"
        // would read like a no-op event.
        if current_sub_port != 0 {
            tracing::info!("subscription listener disabled (was port {current_sub_port})");
        }
        return Ok(());
    }
    // A same-port TLS force-rebind (or a port swap) drops the old listener before
    // binding the new one, so it races the OS releasing the socket (transient
    // EADDRINUSE, worst on Windows). Retry through that window instead of a single
    // attempt; spawn_sub_listener keeps the bad-cert → plain-HTTP fallback. The
    // first attempt's sleep also serves as the socket-release grace.
    let app = crate::build_sub_router(state.clone());
    let mut last_err: Option<std::io::Error> = None;
    let mut bound = None;
    for attempt in 1..=ATTEMPTS {
        tokio::time::sleep(Duration::from_millis(u64::from(attempt.min(5)) * 100)).await;
        match spawn_sub_listener(state, "0.0.0.0", new_sub_port, app.clone()).await {
            Ok((tx, _is_https)) => {
                bound = Some(tx);
                break;
            }
            Err(e) => {
                tracing::warn!(
                    "subscription listener rebind on port {new_sub_port} attempt {attempt}/{ATTEMPTS} failed: {e}"
                );
                last_err = Some(e);
            }
        }
    }
    let Some(new_tx) = bound else {
        // Nothing is bound now (the old listener was shut down above). Record
        // port 0, not the stale old port, so a later swap back to it rebinds
        // instead of no-oping on new == current.
        state.current_sub_port.store(0, Ordering::Relaxed);
        let detail = last_err.map_or_else(|| "unknown error".to_owned(), |e| e.to_string());
        return Err(AppError::Internal(anyhow::anyhow!(
            "failed to bind subscription listener on port {new_sub_port} after {ATTEMPTS} attempts: {detail}"
        )));
    };
    *state.sub_listener_shutdown.write().await = Some(new_tx);
    state
        .current_sub_port
        .store(new_sub_port, Ordering::Relaxed);
    if current_sub_port == 0 {
        tracing::info!("subscription listener started on port {new_sub_port}");
    } else if current_sub_port == new_sub_port {
        tracing::info!("subscription listener reloaded on port {new_sub_port}");
    } else {
        tracing::info!("subscription listener swapped {current_sub_port} → {new_sub_port}");
    }
    Ok(())
}

/// Bind a TCP listener on `host:port` and start serving `app` on it in
/// a background task. Returns the oneshot sender that the caller can
/// use to trigger a graceful shutdown of that listener.
///
/// The serve task runs until either:
///   * the shutdown sender is fired (operator-initiated port swap or
///     process exit), or
///   * `axum::serve` returns an error (listener died, OOM, etc.) — in
///     which case the task quietly exits and the panel becomes
///     unreachable on that port. We log the failure but don't try to
///     auto-restart: the operator can hit the settings endpoint to
///     bring up a new listener.
pub async fn spawn_listener(
    host: &str,
    port: u16,
    app: Router,
    tls: Option<PanelTls>,
) -> std::io::Result<oneshot::Sender<()>> {
    let addr = format!("{host}:{port}");
    let (tx, rx) = oneshot::channel::<()>();
    if let Some(t) = tls {
        // Build the rustls config first so a bad cert/key surfaces as an
        // InvalidInput error here (caller can fall back to plain HTTP), not
        // silently inside the serve task.
        let config = RustlsConfig::from_pem(t.cert_pem.into_bytes(), t.key_pem.into_bytes())
            .await
            .map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("invalid panel TLS cert/key: {e}"),
                )
            })?;
        // Pre-bind a std listener so EADDRINUSE surfaces here too — parity with
        // the plain-HTTP path and the listener-swap error handling.
        let listener = StdTcpListener::bind(&addr)?;
        listener.set_nonblocking(true)?;
        let handle = Handle::new();
        let shutdown_handle = handle.clone();
        // axum-server 0.8: `from_tcp_rustls` returns `io::Result` (the std→tokio
        // listener conversion can fail). Build the server up front so that error
        // propagates to the caller too, before spawning the serve task.
        let server = axum_server::from_tcp_rustls(listener, config)?.handle(handle);
        tokio::spawn(async move {
            let _ = rx.await;
            shutdown_handle.graceful_shutdown(Some(Duration::from_secs(3)));
        });
        tokio::spawn(async move {
            if let Err(e) = server.serve(app.into_make_service()).await {
                tracing::warn!("axum HTTPS listener on {addr} exited: {e}");
            } else {
                tracing::info!("axum HTTPS listener on {addr} drained and stopped");
            }
        });
    } else {
        let listener = TcpListener::bind(&addr).await?;
        tokio::spawn(async move {
            let server = axum::serve(listener, app).with_graceful_shutdown(async move {
                let _ = rx.await;
            });
            if let Err(e) = server.await {
                tracing::warn!("axum listener on {addr} exited: {e}");
            } else {
                tracing::info!("axum listener on {addr} drained and stopped");
            }
        });
    }
    Ok(tx)
}

/// Bind the main panel listener at boot, honouring operator-provided HTTPS.
/// Falls back to plain HTTP — logging loudly — if the configured cert/key is
/// malformed, so a bad paste can never lock the operator out. Returns the
/// listener's shutdown handle plus whether TLS is actually being served.
pub async fn spawn_main_listener(
    state: &AppState,
    host: &str,
    port: u16,
    app: Router,
) -> std::io::Result<(oneshot::Sender<()>, bool)> {
    let tls = load_tls_for_boot(&state.db).await;
    let tls_requested = tls.is_some();
    match spawn_listener(host, port, app.clone(), tls).await {
        Ok(tx) => Ok((tx, tls_requested)),
        Err(e) if tls_requested => {
            tracing::error!(
                "panel HTTPS failed to start ({e}); falling back to plain HTTP on port {port}"
            );
            Ok((spawn_listener(host, port, app, None).await?, false))
        }
        Err(e) => Err(e),
    }
}

/// Bind the dedicated subscription listener, honouring `sub_tls_mode`
/// (`inherit` → panel cert, `off` → plain HTTP for a TLS-terminating CDN/tunnel,
/// `custom` → separate cert/key). Mirrors `spawn_main_listener`'s bad-cert
/// fallback: if HTTPS can't start we drop to plain HTTP so a malformed cert never
/// takes the sub endpoint down.
pub async fn spawn_sub_listener(
    state: &AppState,
    host: &str,
    port: u16,
    app: Router,
) -> std::io::Result<(oneshot::Sender<()>, bool)> {
    let tls = load_sub_tls_for_boot(&state.db).await;
    let tls_requested = tls.is_some();
    match spawn_listener(host, port, app.clone(), tls).await {
        // `bool` reports the scheme actually bound (true = HTTPS), so callers
        // log/report the real outcome rather than what was merely requested —
        // the fallback below drops to plain HTTP without the caller knowing.
        Ok(tx) => Ok((tx, tls_requested)),
        Err(e) if tls_requested => {
            tracing::error!(
                "subscription HTTPS failed to start ({e}); falling back to plain HTTP on port {port}"
            );
            Ok((spawn_listener(host, port, app, None).await?, false))
        }
        Err(e) => Err(e),
    }
}

/// Boot/runtime read of operator-provided panel TLS. Returns `Some` only when
/// HTTPS is enabled AND both PEM blobs are present; otherwise `None` (serve
/// plain HTTP). Validity of the pair is checked when the listener binds.
pub async fn load_tls_for_boot(db: &crate::db::DbPool) -> Option<PanelTls> {
    let row = sqlx::query!(
        r#"SELECT panel_tls_enabled,
                  panel_tls_cert AS "panel_tls_cert!: String",
                  panel_tls_key AS "panel_tls_key!: String"
            FROM panel_settings WHERE id = 1"#
    )
    .fetch_optional(db)
    .await
    .ok()
    .flatten()?;
    if row.panel_tls_enabled == 0
        || row.panel_tls_cert.trim().is_empty()
        || row.panel_tls_key.trim().is_empty()
    {
        return None;
    }
    Some(PanelTls {
        cert_pem: row.panel_tls_cert,
        key_pem: row.panel_tls_key,
    })
}

/// TLS for the dedicated subscription listener, honouring `sub_tls_mode`:
/// `off` → `None` (plain HTTP, TLS terminated by an upstream CDN/tunnel);
/// `custom` → the separate sub cert/key (`None` if either half is missing);
/// `inherit` (or anything unexpected) → the panel's own cert.
pub async fn load_sub_tls_for_boot(db: &crate::db::DbPool) -> Option<PanelTls> {
    let row = sqlx::query!(
        r#"SELECT sub_tls_mode AS "sub_tls_mode!: String",
                  sub_cert_pem AS "sub_cert_pem!: String",
                  sub_key_pem  AS "sub_key_pem!: String"
            FROM panel_settings WHERE id = 1"#
    )
    .fetch_optional(db)
    .await
    .ok()
    .flatten()?;
    match row.sub_tls_mode.trim() {
        "off" => None,
        "custom" => {
            if row.sub_cert_pem.trim().is_empty() || row.sub_key_pem.trim().is_empty() {
                return None;
            }
            Some(PanelTls {
                cert_pem: row.sub_cert_pem,
                key_pem: row.sub_key_pem,
            })
        }
        _ => load_tls_for_boot(db).await,
    }
}

/// Restart the panel process. TLS binds at startup, so flipping HTTPS on/off (or
/// swapping the cert) is applied by exiting and letting the supervisor respawn —
/// `restart: unless-stopped` under Docker, a unit under systemd. With no
/// supervisor the process simply stops and must be started again by hand. Exits
/// after a short beat so the 202 response reaches the UI first.
async fn restart_panel(_user: AuthUser) -> StatusCode {
    tracing::warn!("panel restart requested via API — exiting so the supervisor respawns");
    tokio::spawn(async {
        tokio::time::sleep(Duration::from_millis(300)).await;
        std::process::exit(0);
    });
    StatusCode::ACCEPTED
}

/// Boot-time read. Returns the canonical `(panel_port, base_path,
/// sub_port)` for the initial listeners + router mount. Falls back to
/// env-var defaults on any DB error so a broken settings row can't
/// lock the operator out — they can at least bring the panel up on
/// the default port and fix it through the UI. `sub_port` is an i32
/// (not u16) so caller can detect / log the out-of-range case.
pub async fn load_for_boot(db: &crate::db::DbPool) -> (u16, String, i32) {
    let row = sqlx::query!(
        "SELECT panel_port, panel_base_path, sub_port FROM panel_settings WHERE id = 1"
    )
    .fetch_optional(db)
    .await
    .ok()
    .flatten();
    match row {
        Some(r) => {
            let port = u16::try_from(r.panel_port).unwrap_or(8080);
            let sub_port = i32::try_from(r.sub_port).unwrap_or(0);
            (port, r.panel_base_path, sub_port)
        }
        None => (8080, String::new(), 0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ports are stored canonicalised because the two emitters disagree on
    /// whitespace: xray's own JSON parser does NOT trim around a range dash and
    /// would reject " 65535", which would then block every later config write
    /// (and stop xray from starting on a cold boot).
    fn targets(names: &[&str]) -> std::collections::HashSet<String> {
        names.iter().map(|s| (*s).to_string()).collect()
    }

    fn rule(id: &str) -> RoutingRule {
        RoutingRule {
            id: id.to_string(),
            enabled: true,
            name: String::new(),
            domain: vec![],
            ip: vec![],
            source_ip: vec![],
            port: String::new(),
            source_port: String::new(),
            network: vec!["tcp".to_string()],
            protocol: vec![],
            inbound_tag: vec![],
            user: vec![],
            outbound_tag: "direct".to_string(),
        }
    }

    /// This is the only gate between operator input and BOTH emitters (proto on
    /// the hot path, JSON on the restart path), and each guard below exists
    /// because the two disagree about the input it rejects. A rule that slips
    /// through here does not fail loudly — it either silently never matches, or
    /// it fails to build inside xray, which wipes the whole live rule set.
    #[test]
    fn rule_validation_rejects_what_the_emitters_disagree_on() {
        let ok = targets(&["direct", "blocked", "relay-jp"]);

        // A system token as an id is matched by the SYSTEM_TOKENS arm first in
        // both emitters, so the operator's rule would silently vanish.
        for reserved in crate::xray::config_gen::SYSTEM_TOKENS {
            let mut r = rule(reserved);
            r.outbound_tag = "direct".to_string();
            assert!(
                validate_and_clean_rule(&r, &ok).is_err(),
                "reserved id '{reserved}' must be rejected"
            );
        }

        // xray's JSON parser accepts these and turns them into Network_Unknown
        // (a rule that never fires); the proto path drops them, leaving a rule
        // with no conditions at all, which xray refuses outright.
        for bad in ["quic", "unix", "TCP,udp"] {
            let mut r = rule("r1");
            r.network = vec![bad.to_string()];
            assert!(
                validate_and_clean_rule(&r, &ok).is_err(),
                "network '{bad}' must be rejected"
            );
        }

        // A blank entry is a match-everything Substr to xray's JSON parser and
        // a hard error on the proto path.
        let mut r = rule("r1");
        r.domain = vec!["  ".to_string(), String::new()];
        r.network = vec![];
        assert!(
            validate_and_clean_rule(&r, &ok).is_err(),
            "a rule whose only matcher is blank has no conditions"
        );

        // Blanks are stripped rather than forwarded, and surviving entries trimmed.
        let mut r = rule("r1");
        r.domain = vec![" a.com ".to_string(), String::new(), "b.com".to_string()];
        let cleaned = validate_and_clean_rule(&r, &ok).unwrap();
        assert_eq!(
            cleaned.domain,
            vec!["a.com".to_string(), "b.com".to_string()]
        );

        // Ports are stored canonicalised, so the JSON emitter never sees the
        // interior whitespace it would reject.
        let mut r = rule("r1");
        r.port = " 443, 1024 - 65535 ".to_string();
        assert_eq!(
            validate_and_clean_rule(&r, &ok).unwrap().port,
            "443,1024-65535"
        );

        // An outbound that isn't there would dangle in the pushed rule set.
        let mut r = rule("r1");
        r.outbound_tag = "relay-de".to_string();
        assert!(validate_and_clean_rule(&r, &ok).is_err());
        r.outbound_tag = "relay-jp".to_string();
        assert!(validate_and_clean_rule(&r, &ok).is_ok());
    }

    #[test]
    fn port_specs_are_canonicalised_for_both_emitters() {
        let (spec, has_range) = canonical_port_spec("port", " 1024 - 65535 ", "r").unwrap();
        assert_eq!(spec, "1024-65535");
        assert!(has_range);

        let (spec, _) = canonical_port_spec("port", "443, 8080 - 8090", "r").unwrap();
        assert_eq!(spec, "443,8080-8090");

        // No ranges at all: not a matcher, and stored empty.
        let (spec, has_range) = canonical_port_spec("port", ",,", "r").unwrap();
        assert!(spec.is_empty());
        assert!(!has_range);

        assert!(canonical_port_spec("port", "70000", "r").is_err());
        assert!(canonical_port_spec("port", "abc", "r").is_err());
    }
}
