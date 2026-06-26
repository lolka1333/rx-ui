//! Runtime panel settings — port, URL prefix — plus the machinery to
//! apply them hot, without restarting the process.
//!
//! Both fields are applied by rebuilding the router (`build_router`, which
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
//!   window; the UI's redirect-after-save reconnects.

use crate::{
    AppState,
    auth::AuthUser,
    build_router,
    error::{AppError, AppResult},
    models::{PanelSettings, PanelSettingsUpdate, RoutingRule},
};
use axum::{Json, Router, extract::State, http::StatusCode, routing::get};
use std::{sync::atomic::Ordering, time::Duration};
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
    Router::new().route("/panel", get(get_panel).put(update_panel))
}

async fn get_panel(
    _user: AuthUser,
    State(state): State<AppState>,
) -> AppResult<Json<PanelSettings>> {
    let row = sqlx::query!(
        "SELECT panel_port, panel_base_path,
                sub_enabled, sub_host_override, sub_update_interval_hours,
                sub_brand_name, sub_service_url, sub_port,
                xray_freedom_strategy, xray_routing_strategy, xray_test_url,
                xray_block_bittorrent, xray_blocked_ips, xray_blocked_domains,
                xray_ipv4_domains, xray_custom_rules, xray_rule_order
            FROM panel_settings WHERE id = 1"
    )
    .fetch_one(&state.db)
    .await?;
    // JSON-array / JSON-object columns; a parse failure (hand-edited DB)
    // degrades to an empty value rather than a 500.
    let list = |s: &str| serde_json::from_str::<Vec<String>>(s).unwrap_or_default();
    let xray_custom_rules =
        serde_json::from_str::<Vec<RoutingRule>>(&row.xray_custom_rules).unwrap_or_default();
    Ok(Json(PanelSettings {
        panel_port: i32::try_from(row.panel_port).unwrap_or(8080),
        panel_base_path: row.panel_base_path,
        sub_enabled: row.sub_enabled != 0,
        sub_host_override: row.sub_host_override,
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
    }))
}

async fn update_panel(
    _user: AuthUser,
    State(state): State<AppState>,
    Json(body): Json<PanelSettingsUpdate>,
) -> AppResult<StatusCode> {
    let NormalizedPanel {
        new_port,
        base_path: normalised,
        sub_host,
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

    let sub_enabled_i = i64::from(body.sub_enabled);
    let xray_bittorrent_i = i64::from(xray_block_bittorrent);
    sqlx::query!(
        "UPDATE panel_settings
            SET panel_port = ?,
                panel_base_path = ?,
                sub_enabled = ?,
                sub_host_override = ?,
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
                updated_at = datetime('now')
            WHERE id = 1",
        body.panel_port,
        normalised,
        sub_enabled_i,
        sub_host,
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
    )
    .execute(&state.db)
    .await?;

    // Snapshot the previous prefix BEFORE we install the new one —
    // the rebind-on-path-change branch below needs to know whether
    // the path actually moved, and once we've updated the RwLock
    // we'd be comparing the new value against itself.
    let previous_prefix = {
        let mut guard = state.base_path.write().await;
        let old = guard.clone();
        (*guard).clone_from(&normalised);
        old
    };

    let current_port = state.current_port.load(Ordering::Relaxed);
    let prefix_changed = previous_prefix != normalised;
    swap_panel_listener(
        &state,
        new_port,
        current_port,
        prefix_changed,
        &previous_prefix,
        &normalised,
    )
    .await?;

    let current_sub_port = state.current_sub_port.load(Ordering::Relaxed);
    let new_sub_port = u16::try_from(body.sub_port).unwrap_or(0);
    swap_sub_listener(&state, new_sub_port, current_sub_port).await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Validated + normalised form of a `PanelSettingsUpdate`. Owns its
/// strings so the caller can bind them straight into the UPDATE.
struct NormalizedPanel {
    new_port: u16,
    base_path: String,
    sub_host: String,
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

    // Subscription host: empty OR a bare hostname / IPv4 / bracketed IPv6.
    // Reject schemes, paths, query strings — the share-link builder splices
    // this as an `@host:port` chunk, so a stray `https://` or `/foo` makes
    // every imported link malformed. 253 = DNS RFC 1035 FQDN cap.
    let sub_host = body.sub_host_override.trim();
    if !sub_host.is_empty() {
        if sub_host.contains("://")
            || sub_host.contains('/')
            || sub_host.contains('?')
            || sub_host.contains(' ')
        {
            return Err(AppError::BadRequest(
                "sub_host_override must be a bare hostname or IP — no scheme, path, or spaces"
                    .to_owned(),
            ));
        }
        if sub_host.len() > 253 {
            return Err(AppError::BadRequest(
                "sub_host_override is too long (max 253 chars)".to_owned(),
            ));
        }
    }

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
    // blocks `javascript:` / `data:` payloads from the landing page's
    // `<a href>`. 2048 = de-facto safe URL length. Cheapest checks first.
    let sub_service_url = body.sub_service_url.trim();
    if !sub_service_url.is_empty() {
        if sub_service_url.chars().any(char::is_control) {
            return Err(AppError::BadRequest(
                "sub_service_url contains control characters".to_owned(),
            ));
        }
        if !sub_service_url.starts_with("http://") && !sub_service_url.starts_with("https://") {
            return Err(AppError::BadRequest(
                "sub_service_url must start with http:// or https://".to_owned(),
            ));
        }
        if sub_service_url.len() > 2048 {
            return Err(AppError::BadRequest(
                "sub_service_url is too long (max 2048 chars)".to_owned(),
            ));
        }
    }

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
        sub_host: sub_host.to_owned(),
        sub_brand,
        sub_service_url: sub_service_url.to_owned(),
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
    let test_url = body.xray_test_url.trim();
    if !test_url.is_empty() {
        if test_url.chars().any(char::is_control) {
            return Err(AppError::BadRequest(
                "xray_test_url contains control characters".to_owned(),
            ));
        }
        if !test_url.starts_with("http://") && !test_url.starts_with("https://") {
            return Err(AppError::BadRequest(
                "xray_test_url must start with http:// or https://".to_owned(),
            ));
        }
        if test_url.len() > 2048 {
            return Err(AppError::BadRequest(
                "xray_test_url is too long (max 2048 chars)".to_owned(),
            ));
        }
    }

    Ok((freedom.to_owned(), routing.to_owned(), test_url.to_owned()))
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

/// Caps shared by every routing match list (the basic block-lists and the
/// custom-rule matchers): max entries per list, max chars per entry.
const MAX_LIST_ENTRIES: usize = 500;
const MAX_ENTRY_LEN: usize = 256;

/// Per-entry sanity for a routing match list, shared by `validate_match_list`
/// (basic block-lists) and the custom-rule matchers: cap count + length and
/// reject control chars / internal whitespace — matcher tokens (domains,
/// CIDRs, `geoip:`/`geosite:` labels, ports) never contain spaces. Blank
/// entries are tolerated (callers drop them). The real syntax check is the
/// `xray run -test` run before the config is swapped in.
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
        if ob.enabled {
            set.insert(ob.tag);
        }
    }
    Ok(set)
}

/// Validate the operator's custom routing rules + order tokens, returning the
/// pair of JSON strings ready to bind into the UPDATE. Light validation only —
/// `xray run -test` (on the next restart) is the real syntax check; this stops
/// obviously-broken input (bad target, control chars, runaway sizes).
fn validate_custom_routing(
    body: &PanelSettingsUpdate,
    valid_targets: &std::collections::HashSet<String>,
) -> AppResult<(String, String)> {
    if body.xray_custom_rules.len() > 200 {
        return Err(AppError::BadRequest(
            "too many custom rules (max 200)".to_owned(),
        ));
    }
    for r in &body.xray_custom_rules {
        if r.id.trim().is_empty() {
            return Err(AppError::BadRequest(
                "custom rule id must not be empty".to_owned(),
            ));
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
    }

    if body.xray_rule_order.len() > 1000 {
        return Err(AppError::BadRequest("rule order is too long".to_owned()));
    }
    for tok in &body.xray_rule_order {
        if tok.len() > 128 || tok.chars().any(char::is_control) {
            return Err(AppError::BadRequest("invalid rule order token".to_owned()));
        }
    }

    let custom = serde_json::to_string(&body.xray_custom_rules)
        .map_err(|e| AppError::Internal(anyhow::anyhow!(e)))?;
    let order = serde_json::to_string(&body.xray_rule_order)
        .map_err(|e| AppError::Internal(anyhow::anyhow!(e)))?;
    Ok((custom, order))
}

/// A port / sourcePort field: free-form ("443", "1024-65535", "80,443"), but no
/// spaces or control characters. Empty means "any port".
fn check_port_field(field: &str, value: &str) -> AppResult<()> {
    let t = value.trim();
    if t.is_empty() {
        return Ok(());
    }
    if t.len() > 128 {
        return Err(AppError::BadRequest(format!("{field} is too long")));
    }
    if t.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(AppError::BadRequest(format!(
            "{field} must not contain spaces or control characters: {t}"
        )));
    }
    Ok(())
}

/// Hot-swap the main panel listener after a settings change. Two cases:
///   * port changed → dual-listener: bind the new port, then drain the old
///     listener after `PORT_SWAP_GRACE` so the in-flight PUT response still
///     leaves on the old socket. (`path-only` or `port+path` walk here as
///     long as the new port differs from the running one.)
///   * port same, only the prefix moved → close-then-rebind on the same
///     port. ~10ms unbound window; the UI's redirect-after-save reconnects.
async fn swap_panel_listener(
    state: &AppState,
    new_port: u16,
    current_port: u16,
    prefix_changed: bool,
    previous_prefix: &str,
    normalised: &str,
) -> AppResult<()> {
    if new_port != current_port {
        let app = build_router(state.clone()).await;
        let new_tx = spawn_listener("0.0.0.0", new_port, app)
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
        // Same port, new prefix: tear down old listener first, then bind a
        // fresh one on the same port. The 100ms beat lets the OS release
        // the socket — without it Windows sometimes returns EADDRINUSE on
        // the immediate re-bind.
        let old_tx = {
            let mut guard = state.listener_shutdown.write().await;
            guard.take()
        };
        if let Some(old_tx) = old_tx {
            let _ = old_tx.send(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        let app = build_router(state.clone()).await;
        let new_tx = spawn_listener("0.0.0.0", current_port, app)
            .await
            .map_err(|e| {
                AppError::Internal(anyhow::anyhow!(
                    "failed to re-bind listener on port {current_port}: {e}"
                ))
            })?;
        *state.listener_shutdown.write().await = Some(new_tx);
        tracing::info!(
            "panel prefix swapped {previous_prefix:?} → {normalised:?} \
             on port {current_port} (re-bind complete)"
        );
    }
    Ok(())
}

/// Sub-only listener swap, independent of the main listener. `new_sub_port`
/// of 0 ≡ tear down if running; any other value ≡ ensure listening there
/// (start fresh, or rebind if the current sub-port differs).
async fn swap_sub_listener(
    state: &AppState,
    new_sub_port: u16,
    current_sub_port: u16,
) -> AppResult<()> {
    if new_sub_port == current_sub_port {
        return Ok(());
    }
    let old_tx = state.sub_listener_shutdown.write().await.take();
    if let Some(tx) = old_tx {
        let _ = tx.send(());
    }
    if new_sub_port == 0 {
        state.current_sub_port.store(0, Ordering::Relaxed);
        tracing::info!("subscription listener disabled (was port {current_sub_port})");
        return Ok(());
    }
    // OS socket-release grace — same as the main path-rebind. Skipped when
    // the old sub-port was 0 (nothing was bound).
    if current_sub_port != 0 {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let app = crate::build_sub_router(state.clone());
    let new_tx = spawn_listener("0.0.0.0", new_sub_port, app)
        .await
        .map_err(|e| {
            AppError::Internal(anyhow::anyhow!(
                "failed to bind subscription listener on port {new_sub_port}: {e}"
            ))
        })?;
    *state.sub_listener_shutdown.write().await = Some(new_tx);
    state
        .current_sub_port
        .store(new_sub_port, Ordering::Relaxed);
    if current_sub_port == 0 {
        tracing::info!("subscription listener started on port {new_sub_port}");
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
) -> std::io::Result<oneshot::Sender<()>> {
    let addr = format!("{host}:{port}");
    let listener = TcpListener::bind(&addr).await?;
    let (tx, rx) = oneshot::channel::<()>();
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
    Ok(tx)
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
