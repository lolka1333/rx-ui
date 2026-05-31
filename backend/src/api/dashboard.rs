use crate::{
    AppState,
    auth::AuthUser,
    error::AppResult,
    models::{DashboardOverview, SystemStats, XrayStatus},
};
use axum::{Json, Router, extract::State, routing::get};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/overview", get(overview))
        .route("/system", get(system))
        .route("/xray", get(xray_status))
}

async fn overview(
    _user: AuthUser,
    State(state): State<AppState>,
) -> AppResult<Json<DashboardOverview>> {
    let system = state.host.snapshot().await;
    let xray = state.xray.status().await;

    let inb = sqlx::query!(
        "SELECT
            COUNT(*) as total,
            COALESCE(SUM(enabled), 0) as enabled
         FROM inbounds"
    )
    .fetch_one(&state.db)
    .await?;

    Ok(Json(DashboardOverview {
        system,
        xray,
        inbounds_total: u32::try_from(inb.total).unwrap_or(0),
        inbounds_enabled: u32::try_from(inb.enabled).unwrap_or(0),
    }))
}

async fn system(_user: AuthUser, State(state): State<AppState>) -> Json<SystemStats> {
    Json(state.host.snapshot().await)
}

async fn xray_status(_user: AuthUser, State(state): State<AppState>) -> Json<XrayStatus> {
    Json(state.xray.status().await)
}
