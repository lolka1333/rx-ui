//! Runtime panel settings — port, URL prefix — plus the machinery to
//! apply them hot, without restarting the process.
//!
//! Two distinct mechanisms cover the two fields:
//!
//! * **Path** is hot-swapped via a middleware (`prefix_strip_middleware`)
//!   that reads `state.base_path` on every request, strips the prefix
//!   from the URI if present, and 404s anything outside it. Saving a
//!   new prefix is a single `RwLock` write — the next request already
//!   sees the new value.
//!
//! * **Port** can't change in place (a single `TcpListener` is bound
//!   to exactly one socket address) but we can spawn a *new* listener
//!   on the new port, then let the old one keep serving for a grace
//!   period so the in-flight PUT response makes it out before the
//!   socket goes away. After the grace window the old listener
//!   gracefully drains and exits via its oneshot shutdown signal.

use crate::{
    AppState,
    auth::AuthUser,
    build_router,
    error::{AppError, AppResult},
    models::{PanelSettings, PanelSettingsUpdate},
};
// `prefix_strip` was retired — the running router is rebuilt from
// scratch on each port change via `build_router` (which mounts the
// nest statically). Kept the module placeholder below to keep the
// file's public surface stable.
use axum::{Json, Router, extract::State, http::StatusCode, routing::get};
use std::{sync::atomic::Ordering, time::Duration};
use tokio::{net::TcpListener, sync::oneshot};

/// How long we keep the old listener alive after a port change. Five
/// seconds easily covers the in-flight PUT response + a couple of
/// retries on top — anything longer just keeps a stale socket
/// open without serving useful traffic.
const PORT_SWAP_GRACE: Duration = Duration::from_secs(5);

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
                sub_brand_name, sub_service_url, sub_port
            FROM panel_settings WHERE id = 1"
    )
    .fetch_one(&state.db)
    .await?;
    Ok(Json(PanelSettings {
        panel_port: i32::try_from(row.panel_port).unwrap_or(8080),
        panel_base_path: row.panel_base_path,
        sub_enabled: row.sub_enabled != 0,
        sub_host_override: row.sub_host_override,
        sub_update_interval_hours: i32::try_from(row.sub_update_interval_hours).unwrap_or(12),
        sub_brand_name: row.sub_brand_name,
        sub_service_url: row.sub_service_url,
        sub_port: i32::try_from(row.sub_port).unwrap_or(0),
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
    } = validate_panel_update(&body)?;

    let sub_enabled_i = i64::from(body.sub_enabled);
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

    // Normalise the prefix to canonical form: empty OR leading-slash +
    // no trailing slash. Single "/" collapses to "" (same mount point) so
    // two stored values can't mean the same thing.
    let prefix_raw = body.panel_base_path.trim();
    let base_path = if prefix_raw.is_empty() || prefix_raw == "/" {
        String::new()
    } else {
        let trimmed = prefix_raw.trim_matches('/');
        if trimmed.is_empty() {
            String::new()
        } else if !trimmed
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '/')
        {
            return Err(AppError::BadRequest(
                "panel_base_path may only contain letters, digits, '-', '_', '/'".to_owned(),
            ));
        } else {
            format!("/{trimmed}")
        }
    };

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

    Ok(NormalizedPanel {
        new_port,
        base_path,
        sub_host: sub_host.to_owned(),
        sub_brand,
        sub_service_url: sub_service_url.to_owned(),
    })
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
