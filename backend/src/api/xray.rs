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

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/releases", get(list_releases))
        .route("/install", post(install))
        .route("/start", post(start))
        .route("/stop", post(stop))
        .route("/restart", post(restart))
}

#[derive(Deserialize)]
struct ReleasesQuery {
    #[serde(default = "default_limit")]
    limit: u32,
}
const fn default_limit() -> u32 {
    10
}

async fn list_releases(
    _user: AuthUser,
    Query(q): Query<ReleasesQuery>,
) -> AppResult<Json<Vec<installer::XrayRelease>>> {
    let releases = installer::fetch_releases(q.limit.clamp(1, 50))
        .await
        .map_err(AppError::Internal)?;
    Ok(Json(releases))
}

#[derive(Deserialize)]
struct InstallRequest {
    /// Either a tag like "v25.7.26" or the release object the UI got from
    /// `/releases` — we re-fetch by tag to make sure `asset_url` is fresh.
    tag: String,
}

async fn install(
    _user: AuthUser,
    State(state): State<AppState>,
    Json(req): Json<InstallRequest>,
) -> AppResult<Json<serde_json::Value>> {
    // Refetch the release list so the asset_url is current — the panel can't
    // trust whatever URL the browser sent.
    let releases = installer::fetch_releases(50)
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
    state.xray.restart().await.map_err(AppError::Internal)?;
    Ok(Json(serde_json::json!({ "restarted": true })))
}
