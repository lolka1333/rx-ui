use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("not found")]
    NotFound,

    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("unauthorized")]
    Unauthorized,

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("jwt error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),

    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    #[error("internal: {0}")]
    Internal(#[from] anyhow::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, msg) = match &self {
            Self::NotFound => (StatusCode::NOT_FOUND, "not found".to_string()),
            Self::BadRequest(m) => (StatusCode::BAD_REQUEST, m.clone()),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized".to_string()),
            Self::Conflict(m) => (StatusCode::CONFLICT, m.clone()),
            Self::Database(sqlx::Error::RowNotFound) => {
                (StatusCode::NOT_FOUND, "not found".to_string())
            }
            // A DB error can carry a query fragment, so it stays opaque to the
            // client and detailed in the log.
            Self::Database(e) => {
                tracing::error!("db error: {e:?}");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal".to_string())
            }
            // An internal error here is written by this codebase, for this
            // operator: "saved but not applied to xray: …", "failed to bind
            // the new listener on port …". Those sentences are the whole
            // diagnosis, and collapsing them into "internal" is why several
            // call sites had started returning 400 just to stay readable. The
            // panel has a single admin who can already read the log, so the
            // text ships with the 500 — `{:#}` keeps the whole cause chain,
            // which is where the actual reason usually sits.
            Self::Internal(e) => {
                tracing::error!("internal error: {e:?}");
                (StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}"))
            }
            other => {
                tracing::error!("internal error: {other:?}");
                (StatusCode::INTERNAL_SERVER_ERROR, other.to_string())
            }
        };
        (status, Json(json!({ "error": msg }))).into_response()
    }
}

pub type AppResult<T> = Result<T, AppError>;
