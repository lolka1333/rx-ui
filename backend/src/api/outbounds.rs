//! Custom outbounds — list / replace + live gRPC apply + boot reconciliation.
//!
//! Outbounds are stored as a JSON array in `panel_settings.xray_custom_outbounds`
//! and pushed into the running xray over gRPC (`HandlerService.AddOutbound`) —
//! the same "apply live, no restart" model as inbounds. On boot and after an
//! xray restart they are re-pushed by [`reconcile_outbounds_with_xray`], which
//! runs right after the inbound reconcile.
//!
//! The whole set is replaced in one PUT: the Outbounds page owns the full list
//! and saves it atomically. We validate, persist the column, then resync the
//! live handler set — drop every previously-pushed custom tag and add the new
//! enabled ones.

use crate::{
    AppState,
    auth::AuthUser,
    error::{AppError, AppResult},
    models::CustomOutbound,
    xray::orchestrator,
    xray::outbound_test::{OutboundTestResult, test_direct, test_outbound},
};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::get,
};

/// Defensive upper bound — far above any real deployment, but stops a malformed
/// payload from ballooning the column / gRPC churn.
const MAX_OUTBOUNDS: usize = 100;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(list).put(replace))
        .route("/stats", get(stats))
        .route("/{id}/test", axum::routing::post(test))
        .route("/builtin/{tag}/test", axum::routing::post(test_builtin))
}

/// Per-outbound lifetime traffic (`tag -> {uplink, downlink}`), including the
/// built-ins (direct/blocked/direct-ipv4). Cumulative totals persisted by the
/// [`crate::outbound_traffic`] poller — they survive xray restarts, unlike the
/// session-only counters xray exposes directly.
#[derive(Debug, Default, serde::Serialize, ts_rs::TS)]
#[ts(export, export_to = "../../frontend/src/api/types/outbound.ts")]
pub struct OutboundTraffic {
    #[ts(type = "number")]
    pub uplink: u64,
    #[ts(type = "number")]
    pub downlink: u64,
}

async fn stats(
    _user: AuthUser,
    State(state): State<AppState>,
) -> AppResult<Json<std::collections::HashMap<String, OutboundTraffic>>> {
    let rows = sqlx::query!(
        r#"SELECT tag            AS "tag!: String",
                  uplink_total   AS "uplink_total!: i64",
                  downlink_total AS "downlink_total!: i64"
           FROM outbound_traffic"#
    )
    .fetch_all(&state.db)
    .await?;
    #[allow(clippy::cast_sign_loss)]
    let out = rows
        .into_iter()
        .map(|r| {
            (
                r.tag,
                OutboundTraffic {
                    uplink: r.uplink_total.max(0) as u64,
                    downlink: r.downlink_total.max(0) as u64,
                },
            )
        })
        .collect();
    Ok(Json(out))
}

/// Read the stored custom outbounds (JSON array) from `panel_settings`. A
/// malformed / legacy value decodes to an empty list rather than erroring —
/// the column defaults to `'[]'` and is only ever written by [`replace`].
pub async fn load_custom_outbounds(db: &crate::db::DbPool) -> AppResult<Vec<CustomOutbound>> {
    // The `: String` override sidesteps a sqlx 0.9 + rustc ≥1.96 codegen bug
    // where a bare TEXT scalar infers `str` (unsized) instead of `String`.
    let json = sqlx::query_scalar!(
        r#"SELECT xray_custom_outbounds AS "x!: String" FROM panel_settings WHERE id = 1"#
    )
    .fetch_one(db)
    .await?;
    Ok(serde_json::from_str(&json).unwrap_or_default())
}

async fn list(
    _user: AuthUser,
    State(state): State<AppState>,
) -> AppResult<Json<Vec<CustomOutbound>>> {
    Ok(Json(load_custom_outbounds(&state.db).await?))
}

/// Connectivity test for one outbound: does traffic actually egress through it?
/// Runs a throwaway xray that relays a single HTTPS probe via this outbound
/// (see `xray::outbound_test`) and returns the verdict + exit IP/latency. The
/// panel's own xray is untouched.
async fn test(
    _user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> AppResult<Json<OutboundTestResult>> {
    let ob = load_custom_outbounds(&state.db)
        .await?
        .into_iter()
        .find(|o| o.id == id)
        .ok_or(AppError::NotFound)?;
    Ok(Json(test_outbound(&state.xray.binary, &ob).await))
}

/// Connectivity test for a built-in outbound. `direct` / `direct-ipv4` make a
/// direct (no-proxy) probe — the server's own egress baseline. `blocked` is a
/// blackhole (drops everything by design) so it isn't testable.
async fn test_builtin(
    _user: AuthUser,
    Path(tag): Path<String>,
) -> AppResult<Json<OutboundTestResult>> {
    let result = match tag.as_str() {
        "direct" => test_direct(false).await,
        "direct-ipv4" => test_direct(true).await,
        other => {
            return Err(AppError::BadRequest(format!("'{other}' is not testable")));
        }
    };
    Ok(Json(result))
}

async fn replace(
    _user: AuthUser,
    State(state): State<AppState>,
    Json(body): Json<Vec<CustomOutbound>>,
) -> AppResult<StatusCode> {
    validate_outbounds(&body)?;

    // Build every enabled handler up front: a malformed config (bad reality
    // key, etc.) aborts here with a 400 before we touch the DB or xray.
    let handlers = body
        .iter()
        .filter(|o| o.enabled)
        .map(|o| {
            orchestrator::outbound_to_handler_config(o)
                .map(|h| (o.tag.clone(), h))
                .map_err(|e| AppError::BadRequest(format!("outbound '{}': {e}", o.tag)))
        })
        .collect::<AppResult<Vec<_>>>()?;

    // Tags currently in xray (from the previous save) — removed before re-add.
    let old_tags: Vec<String> = load_custom_outbounds(&state.db)
        .await?
        .into_iter()
        .map(|o| o.tag)
        .collect();

    let json = serde_json::to_string(&body).map_err(|e| AppError::Internal(e.into()))?;
    sqlx::query!(
        "UPDATE panel_settings SET xray_custom_outbounds = ? WHERE id = 1",
        json
    )
    .execute(&state.db)
    .await?;

    // Resync the live handler set. Removes are best-effort (a tag may already
    // be gone after a restart). An add failure means "saved but not applied"
    // (surfaced as 500); the column is persisted, so the next reconcile fixes
    // it — mirrors the inbound create path.
    let new_tags: std::collections::HashSet<&str> =
        handlers.iter().map(|(t, _)| t.as_str()).collect();
    for tag in &old_tags {
        if !new_tags.contains(tag.as_str()) {
            let _ = state.xray_client.remove_outbound(tag).await;
        }
    }
    for (tag, handler) in handlers {
        // Idempotent: a tag kept across saves is replaced (config may differ).
        let _ = state.xray_client.remove_outbound(&tag).await;
        if let Err(e) = state.xray_client.add_outbound(handler).await {
            tracing::error!("outbound {tag} saved but xray AddOutbound failed: {e}");
            return Err(AppError::Internal(anyhow::anyhow!(
                "outbound '{tag}' saved but not applied to xray: {e}"
            )));
        }
    }
    Ok(StatusCode::NO_CONTENT)
}

/// Push every enabled custom outbound into a freshly-(re)started xray. Runs at
/// boot and after an xray restart, right after the inbound reconcile. Failures
/// are logged, never fatal — a single bad outbound must not abort the rest.
pub async fn reconcile_outbounds_with_xray(state: &AppState) -> anyhow::Result<()> {
    let enabled: Vec<CustomOutbound> = load_custom_outbounds(&state.db)
        .await
        .map_err(|e| anyhow::anyhow!("load custom outbounds: {e:?}"))?
        .into_iter()
        .filter(|o| o.enabled)
        .collect();
    let total = enabled.len();
    let mut pushed = 0usize;
    for ob in enabled {
        match orchestrator::outbound_to_handler_config(&ob) {
            Ok(handler) => {
                // Idempotent, like the replace() path: drop any stale handler
                // with this tag before adding, so a re-sync against a still-live
                // xray (where the tag survived) doesn't fail "existing tag found".
                let _ = state.xray_client.remove_outbound(&ob.tag).await;
                match state.xray_client.add_outbound(handler).await {
                    Ok(()) => pushed += 1,
                    Err(e) => tracing::warn!("reconcile add_outbound('{}') failed: {e}", ob.tag),
                }
            }
            Err(e) => tracing::warn!("reconcile build outbound '{}' failed: {e}", ob.tag),
        }
    }
    tracing::info!("xray reconciliation: pushed {pushed}/{total} enabled outbounds");
    Ok(())
}

/// Validate tags: non-empty, no reserved collisions, no whitespace/control
/// chars (tags are addressed by exact string from routing rules), unique.
fn validate_outbounds(outbounds: &[CustomOutbound]) -> AppResult<()> {
    if outbounds.len() > MAX_OUTBOUNDS {
        return Err(AppError::BadRequest(format!(
            "too many outbounds (max {MAX_OUTBOUNDS})"
        )));
    }
    let mut seen = std::collections::HashSet::new();
    for o in outbounds {
        let tag = o.tag.trim();
        if tag.is_empty() {
            return Err(AppError::BadRequest(
                "outbound tag must not be empty".into(),
            ));
        }
        if crate::xray::config_gen::BUILTIN_OUTBOUND_TAGS.contains(&tag) || tag == "api" {
            return Err(AppError::BadRequest(format!(
                "outbound tag '{tag}' is reserved"
            )));
        }
        if tag.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(AppError::BadRequest(format!(
                "outbound tag '{tag}' must not contain spaces or control characters"
            )));
        }
        if !seen.insert(tag.to_owned()) {
            return Err(AppError::BadRequest(format!(
                "duplicate outbound tag '{tag}'"
            )));
        }
    }
    Ok(())
}
