use crate::{AppState, auth::AuthUser, error::AppResult, logs::LogEntry};
use axum::{
    Json, Router,
    extract::{Query, State},
    routing::get,
};
use serde::Deserialize;

pub fn routes() -> Router<AppState> {
    Router::new().route("/", get(list))
}

#[derive(Deserialize)]
struct ListQuery {
    /// `info` | `warn` | `error`. Omitted = all levels.
    level: Option<String>,
    /// Max entries to return. Capped at the buffer capacity server-side.
    #[serde(default = "default_limit")]
    limit: usize,
}
const fn default_limit() -> usize {
    50
}

async fn list(
    _user: AuthUser,
    State(state): State<AppState>,
    Query(q): Query<ListQuery>,
) -> AppResult<Json<Vec<LogEntry>>> {
    let limit = q.limit.clamp(1, 500);
    Ok(Json(state.logs.snapshot(q.level.as_deref(), limit)))
}
