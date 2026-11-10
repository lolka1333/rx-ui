//! Rebinding the panel and subscription listeners after a settings save.
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

use super::store::{load_sub_tls_for_boot, load_tls_for_boot};
use crate::{
    AppState, build_router,
    error::{AppError, AppResult},
    models::PanelSettingsUpdate,
};
use axum::Router;
use axum_server::{Handle, tls_rustls::RustlsConfig};
use std::{net::TcpListener as StdTcpListener, sync::atomic::Ordering, time::Duration};
use tokio::{net::TcpListener, sync::oneshot};

/// How long we keep the old listener alive after a port change. Five
/// seconds easily covers the in-flight PUT response + a couple of
/// retries on top — anything longer just keeps a stale socket
/// open without serving useful traffic.
const PORT_SWAP_GRACE: Duration = Duration::from_secs(5);

/// Operator-provided TLS material for the panel's own HTTPS listener.
/// Both blobs are PEM. Validity is checked when a listener is bound
/// (`RustlsConfig::from_pem`); a malformed pair is rejected at save time and
/// falls back to plain HTTP at boot.
#[derive(Clone)]
pub(super) struct PanelTls {
    pub cert_pem: String,
    pub key_pem: String,
}

/// Rebind the sub + panel listeners after a settings write. The sub listener
/// goes first — it's independent of the panel listener, so a panel-swap failure
/// must not skip an already-persisted sub-TLS / sub-port change (the next save
/// would see no delta and never apply it).
pub(super) async fn apply_listener_changes(
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

/// Hot-swap the main panel listener after a settings change. Two cases:
///   * port changed → dual-listener: bind the new port, then drain the old
///     listener after `PORT_SWAP_GRACE` so the in-flight PUT response still
///     leaves on the old socket. (`path-only` or `port+path` walk here as
///     long as the new port differs from the running one.)
///   * port same, only the prefix moved → close-then-rebind on the same
///     port. ~100ms unbound window; the old prefix stops being served at once, so
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
        let new_tx = spawn_listener(&state.bind_host, new_port, app, tls)
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
        let new_tx = rebind_with_retry(&state.bind_host, current_port, app, tls).await?;
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
        match spawn_sub_listener(state, &state.bind_host, new_sub_port, app.clone()).await {
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
async fn spawn_listener(
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
    spawn_with_https_fallback(host, port, app, tls, "panel").await
}

/// Bind `app`, and if HTTPS was requested but wouldn't start, bind plain HTTP
/// instead rather than leaving the endpoint down. `what` names the listener in
/// the error log. The returned `bool` reports the scheme actually bound (true =
/// HTTPS), so callers report the real outcome rather than what was requested —
/// the fallback drops to plain HTTP without the caller knowing.
async fn spawn_with_https_fallback(
    host: &str,
    port: u16,
    app: Router,
    tls: Option<PanelTls>,
    what: &str,
) -> std::io::Result<(oneshot::Sender<()>, bool)> {
    let tls_requested = tls.is_some();
    match spawn_listener(host, port, app.clone(), tls).await {
        Ok(tx) => Ok((tx, tls_requested)),
        Err(e) if tls_requested => {
            tracing::error!(
                "{what} HTTPS failed to start ({e}); falling back to plain HTTP on port {port}"
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
    spawn_with_https_fallback(host, port, app, tls, "subscription").await
}
