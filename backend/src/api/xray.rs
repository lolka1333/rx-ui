use crate::{
    AppState,
    auth::AuthUser,
    error::{AppError, AppResult},
    xray::installer,
};
use axum::{
    Json, Router,
    extract::{Query, State},
    routing::{get, post},
};
use serde::Deserialize;
use std::time::{Duration, Instant};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/releases", get(list_releases))
        .route("/install", post(install))
        .route("/start", post(start))
        .route("/stop", post(stop))
        .route("/restart", post(restart))
        .route("/test-outbound", post(test_outbound))
}

#[derive(Deserialize)]
struct ReleasesQuery {
    #[serde(default = "default_limit")]
    limit: u32,
    /// Custom source link / `owner/repo` shorthand; empty ≡ default upstream.
    repo: Option<String>,
}
const fn default_limit() -> u32 {
    10
}

/// Resolve the operator-supplied source link to `owner/repo`, falling back to
/// the default upstream repo when none is given. A malformed link is a clean
/// 400, not a request to a bogus GitHub URL.
fn resolve_repo(link: Option<&str>) -> AppResult<String> {
    let Some(l) = link.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(installer::DEFAULT_REPO.to_owned());
    };
    installer::parse_repo(l)
        .ok_or_else(|| AppError::BadRequest(format!("invalid source link: {l}")))
}

async fn list_releases(
    _user: AuthUser,
    Query(q): Query<ReleasesQuery>,
) -> AppResult<Json<Vec<installer::XrayRelease>>> {
    let repo = resolve_repo(q.repo.as_deref())?;
    let releases = installer::fetch_releases(&repo, q.limit.clamp(1, 50))
        .await
        .map_err(AppError::Internal)?;
    Ok(Json(releases))
}

#[derive(Deserialize)]
struct InstallRequest {
    /// Either a tag like "v25.7.26" or the release object the UI got from
    /// `/releases` — we re-fetch by tag to make sure `asset_url` is fresh.
    tag: String,
    /// Source link the tag came from; empty ≡ default upstream repo. Must match
    /// the source the UI listed, or the tag won't be found.
    repo: Option<String>,
}

async fn install(
    _user: AuthUser,
    State(state): State<AppState>,
    Json(req): Json<InstallRequest>,
) -> AppResult<Json<serde_json::Value>> {
    // Refetch the release list so the asset_url is current — the panel can't
    // trust whatever URL the browser sent.
    let repo = resolve_repo(req.repo.as_deref())?;
    let releases = installer::fetch_releases(&repo, 50)
        .await
        .map_err(AppError::Internal)?;
    let release = releases
        .into_iter()
        .find(|r| r.tag == req.tag)
        .ok_or_else(|| AppError::BadRequest(format!("unknown release tag: {}", req.tag)))?;

    let install_dir = state
        .xray
        .binary
        .parent()
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("xray binary path has no parent")))?
        .to_path_buf();

    // Stop xray before swapping the binary on Windows (file lock); on Unix it's
    // not strictly required, but keeps behavior consistent. Log the error if
    // stop fails — on Windows the subsequent rename will then fail with a
    // less-helpful "file in use" error, and the stop-failure log is what
    // tells the operator what really went wrong.
    let was_running = state.xray.status().await.running;
    if was_running && let Err(e) = state.xray.stop().await {
        tracing::warn!("xray stop before install failed; proceeding anyway: {e}");
    }

    installer::install_release(&release, &install_dir)
        .await
        .map_err(AppError::Internal)?;

    if was_running {
        // Bring xray back up with the new binary using the existing on-disk
        // config. The panel no longer regenerates the config here — under the
        // gRPC-based design the bootstrap config is static (just the API
        // inbound + globals), and any user-facing inbounds get pushed to xray
        // dynamically via HandlerService.AddInbound after start.
        state.xray.start().await.map_err(AppError::Internal)?;
        // The new process starts with empty in-memory handlers and the
        // cached gRPC channel points at the old one — drop the channel and
        // re-push every enabled inbound so clients keep working without a
        // panel restart (otherwise AddUser later fails "handler not found").
        crate::resync_xray_state(&state).await;
    }

    Ok(Json(serde_json::json!({
        "installed": release.tag,
        "restarted": was_running,
    })))
}

async fn start(
    _user: AuthUser,
    State(state): State<AppState>,
) -> AppResult<Json<serde_json::Value>> {
    state.xray.start().await.map_err(AppError::Internal)?;
    crate::resync_xray_state(&state).await;
    Ok(Json(serde_json::json!({ "started": true })))
}

async fn stop(
    _user: AuthUser,
    State(state): State<AppState>,
) -> AppResult<Json<serde_json::Value>> {
    state.xray.stop().await.map_err(AppError::Internal)?;
    Ok(Json(serde_json::json!({ "stopped": true })))
}

async fn restart(
    _user: AuthUser,
    State(state): State<AppState>,
) -> AppResult<Json<serde_json::Value>> {
    // Regenerate the bootstrap config from current xray settings first, so a
    // Freedom/routing strategy change saved via /api/settings applies on this
    // restart (the live process reloads its config.json on start).
    crate::xray::reload::write_bootstrap_config(&state)
        .await
        .map_err(AppError::Internal)?;
    state.xray.restart().await.map_err(AppError::Internal)?;
    crate::resync_xray_state(&state).await;
    Ok(Json(serde_json::json!({ "restarted": true })))
}

#[derive(Deserialize)]
struct TestOutboundRequest {
    url: String,
}

/// Fetch the operator-supplied URL from the server a few times to confirm the
/// egress reaches the internet. The backend's own network path is the same one
/// xray's `freedom` outbound uses, so a success here means "the box can get
/// out". Returns the HTTP status + the best (minimum) round-trip latency over
/// the attempts; never errors the request itself (a failed fetch is a normal,
/// reportable result).
async fn test_outbound(
    _user: AuthUser,
    Json(req): Json<TestOutboundRequest>,
) -> AppResult<Json<serde_json::Value>> {
    const ATTEMPTS: usize = 4;

    let url = req.url.trim();
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err(AppError::BadRequest(
            "test URL must start with http:// or https://".to_owned(),
        ));
    }
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| AppError::Internal(anyhow::anyhow!(e)))?;

    // A single GET measures DNS + TCP + TLS + one round-trip, so its latency is
    // dominated by connection setup and isn't representative. Reuse one client
    // (it pools the connection) across a few requests and report the *minimum*:
    // the warm requests skip the handshake, and the min also drops the occasional
    // first packet that upstream filtering holds up.
    let mut best: Option<(u128, reqwest::StatusCode)> = None;
    let mut last_error: Option<String> = None;
    for _ in 0..ATTEMPTS {
        let started = Instant::now();
        match client.get(url).send().await {
            Ok(resp) => {
                // `send()` resolves on the response headers, so this is the
                // round-trip time, not the body download.
                let ms = started.elapsed().as_millis();
                let status = resp.status();
                // Drain the body so the connection returns to the pool and the
                // next attempt reuses it instead of doing a fresh handshake.
                let _ = resp.bytes().await;
                if best.is_none_or(|(b, _)| ms < b) {
                    best = Some((ms, status));
                }
            }
            Err(e) => last_error = Some(e.to_string()),
        }
    }

    match best {
        Some((ms, status)) => Ok(Json(serde_json::json!({
            "ok": status.is_success() || status.is_redirection(),
            "status": status.as_u16(),
            "latency_ms": ms,
        }))),
        None => Ok(Json(serde_json::json!({
            "ok": false,
            "status": 0,
            "latency_ms": 0,
            "error": last_error.unwrap_or_else(|| "request failed".to_owned()),
        }))),
    }
}
