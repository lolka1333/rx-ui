//! Per-inbound client CRUD with xray `AlterInbound` sync.
//!
//! Endpoints are nested under `/api/inbounds/{inbound_id}/clients`:
//!   * `POST   /` → create + `AddUser` (auto-UUID if not supplied)
//!   * `GET    /` → list
//!   * `GET    /{id}` → fetch one
//!   * `PATCH  /{id}` → update; identity change (email/uuid/flow) ⇒ remove+add,
//!     toggle enabled ⇒ add or remove, metadata-only ⇒ DB only
//!   * `DELETE /{id}` → `RemoveUser` + DELETE
//!
//! The parent inbound has to exist and be enabled for the gRPC side-effects
//! to make sense; we still let the DB mutation through even if the inbound
//! is disabled (so the operator can pre-stage clients), and skip the xray
//! call when the inbound itself isn't currently registered with xray.

use crate::{
    AppState,
    auth::AuthUser,
    error::{AppError, AppResult},
    models::{
        Client, ClientBulkAssign, ClientBulkAssignResult, ClientBulkRemoved, ClientBulkXrayFailure,
        ClientCreate, ClientCreateGlobal, ClientUpdate,
    },
    xray::share_link,
};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::get,
};
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use uuid::Uuid;

/// Nested router mounted at `/api/inbounds/{inbound_id}/clients`. Used by
/// the inbound-modal Clients tab where the inbound is the context.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(list).post(create))
        .route("/{id}", get(get_one).patch(update).delete(delete))
        .route("/{id}/share-link", get(share_link_endpoint))
}

/// Top-level router mounted at `/api/clients`. Used by the sidebar Clients
/// page for cross-inbound listing, filtering, bulk operations, and global-id
/// CRUD that doesn't carry the `inbound_id` in the URL.
///
/// The endpoints here share the same DB rows and the same gRPC side-effects
/// as the nested ones — they just take `inbound_id` from query params (list)
/// or body (create) instead of the URL path.
pub fn routes_global() -> Router<AppState> {
    Router::new()
        .route("/", get(list_global).post(create_global))
        .route("/stats", get(stats_snapshot))
        .route(
            "/{id}",
            get(get_one_global)
                .patch(update_global)
                .delete(delete_global),
        )
        .route("/{id}/share-link", get(share_link_global))
        .route("/{id}/reset-traffic", axum::routing::post(reset_traffic))
        .route(
            "/{id}/rotate-sub-token",
            axum::routing::post(rotate_sub_token),
        )
        .route("/bulk-assign", axum::routing::post(bulk_assign))
}

/// "Give this user access to N inbounds in one operation." Takes the
/// email + a target set of `inbound_ids` + shared identity fields,
/// reconciles the existing per-inbound rows to match the set:
///
/// * present in target ∧ absent in DB → INSERT (new assignment)
/// * present in target ∧ present in DB → UPDATE (re-sync fields)
/// * absent  in target ∧ present in DB → DELETE (revoke access)
///
/// All DB writes go through one transaction so a mid-flight failure
/// leaves the user's assignment set intact. xray gRPC side-effects
/// happen *after* the commit — best-effort, with warnings on partial
/// failure — matching the per-row create / update / delete pattern.
async fn bulk_assign(
    _user: AuthUser,
    State(state): State<AppState>,
    Json(body): Json<ClientBulkAssign>,
) -> AppResult<Json<ClientBulkAssignResult>> {
    if body.email.trim().is_empty() {
        return Err(AppError::BadRequest("email is required".to_owned()));
    }
    if body.inbound_ids.is_empty() {
        return Err(AppError::BadRequest(
            "inbound_ids must contain at least one entry; \
             use DELETE /api/clients/{id} to fully remove a user"
                .to_owned(),
        ));
    }

    // Dedupe target inbounds — the frontend's multi-select should never
    // emit duplicates, but if a stale optimistic update leaks one
    // through we'd otherwise hit the unique (inbound_id, email)
    // constraint twice in the same tx.
    let mut target: Vec<String> = body.inbound_ids.clone();
    target.sort();
    target.dedup();

    // One round-trip for the whole target set — pulls full Inbound
    // structs so we have everything we need for `build_user` later
    // without a second per-row fetch. 404 if any id didn't resolve.
    let target_inbounds = super::inbounds::fetch_inbounds_batch(&state, &target).await?;
    if target_inbounds.len() != target.len() {
        return Err(AppError::NotFound);
    }

    // Validate the optional caller-supplied uuid once — if it's bad we
    // want to fail before we start mutating rows. (We don't pick the
    // fallback yet — that needs the existing-rows snapshot below so we
    // can prefer "keep the current uuid" over "generate a new one,"
    // which would silently invalidate every already-installed share-
    // link / subscription for this email.)
    let caller_uuid: Option<String> = match body
        .uuid
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(s) => {
            Uuid::parse_str(s).map_err(|e| AppError::BadRequest(format!("invalid uuid: {e}")))?;
            Some(s.to_owned())
        }
        None => None,
    };
    let shared_auth_explicit = body
        .auth
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    // Identity precedence (uuid + hysteria auth) — caller > existing >
    // fresh-mint. Without the "existing" leg, every "add another
    // inbound to this user" call would silently rotate the user's
    // credentials, breaking every already-installed share-link.
    let creds = resolve_shared_credentials(
        &state,
        &body.email,
        caller_uuid,
        shared_auth_explicit,
        &target_inbounds,
    )
    .await?;

    // Compute the DELETE set in-memory: existing assignments minus
    // target. Used by both the commit-tx (DELETE rows) and the post-
    // commit xray sync (RemoveUser calls).
    let target_set: std::collections::HashSet<&str> = target.iter().map(String::as_str).collect();
    let to_remove: Vec<(String, String)> = creds
        .existing_by_inbound
        .iter()
        .filter(|(inb, _)| !target_set.contains(inb.as_str()))
        .map(|(inb, id)| (id.clone(), inb.clone()))
        .collect();

    // DB tx — INSERT / UPDATE / DELETE in one shot. Returns the list
    // of (inbound_id, was_update) so the caller can drive xray sync
    // per row.
    let applied =
        commit_bulk_assign_tx(&state, &body, &target, &target_inbounds, &creds, &to_remove).await?;

    // Post-commit gRPC sync — best-effort. DB is consistent regardless;
    // failures are collected into `xray_failures` so the frontend can
    // surface a "Restart xray to apply" banner instead of silently
    // showing a 200 while the proxy state drifts.
    let removed: Vec<ClientBulkRemoved> = to_remove
        .into_iter()
        .map(|(id, inbound_id)| ClientBulkRemoved { id, inbound_id })
        .collect();
    let mut xray_failures = sync_xray_removed(&state, &body.email, &removed).await?;
    let (created, updated, mut apply_failures) =
        sync_xray_applied(&state, &body.email, &applied, &target_inbounds).await?;
    xray_failures.append(&mut apply_failures);

    Ok(Json(ClientBulkAssignResult {
        created,
        updated,
        removed,
        xray_failures,
    }))
}

/// Snapshot of identity bits + existing-row index used downstream by
/// every other bulk-assign helper. Built ONCE per request from a single
/// `SELECT id, inbound_id, uuid, auth FROM clients WHERE email = ?`.
struct SharedCredentials {
    /// uuid to write into every row (vless wire, hysteria storage).
    uuid: String,
    /// Auth secret to write into hysteria rows; `None` ≡ vless-only
    /// target set (the column stays NULL).
    hysteria_auth: Option<String>,
    /// `inbound_id → row_id` for the existing assignments under this
    /// email. Drives UPDATE-vs-INSERT and the DELETE set.
    existing_by_inbound: std::collections::HashMap<String, String>,
}

/// Lift the caller's preferences + existing-row defaults into one
/// `SharedCredentials`. Precedence order is explicit in the doc above
/// the call site; this function just executes it without re-deciding.
async fn resolve_shared_credentials(
    state: &AppState,
    email: &str,
    caller_uuid: Option<String>,
    shared_auth_explicit: Option<&str>,
    target_inbounds: &std::collections::HashMap<String, crate::models::Inbound>,
) -> AppResult<SharedCredentials> {
    let existing = sqlx::query!(
        "SELECT id, inbound_id, uuid, auth FROM clients WHERE email = ?",
        email,
    )
    .fetch_all(&state.db)
    .await?;
    let existing_uuid: Option<String> = existing.first().map(|r| r.uuid.clone());
    let existing_hysteria_auth: Option<String> = existing
        .iter()
        .find_map(|r| r.auth.clone().filter(|s| !s.is_empty()));
    let existing_by_inbound: std::collections::HashMap<String, String> =
        existing.into_iter().map(|r| (r.inbound_id, r.id)).collect();
    let uuid = caller_uuid
        .or(existing_uuid)
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    let any_hysteria = target_inbounds
        .values()
        .any(|i| matches!(&i.protocol, crate::protocols::ProtocolConfig::Hysteria2(_)));
    let hysteria_auth = shared_auth_explicit
        .map(str::to_owned)
        .or(existing_hysteria_auth)
        .or_else(|| any_hysteria.then(|| Uuid::new_v4().to_string()));
    Ok(SharedCredentials {
        uuid,
        hysteria_auth,
        existing_by_inbound,
    })
}

/// Apply the set math under one transaction. For UPDATE we keep the
/// existing `sub_token` (rotating it on every save would silently break
/// installed subscription URLs); INSERT mints a fresh one. Returns
/// `(inbound_id, was_update)` so the caller's gRPC sync knows whether
/// to issue a remove-then-add (UPDATE) or just an add (INSERT).
async fn commit_bulk_assign_tx(
    state: &AppState,
    body: &ClientBulkAssign,
    target: &[String],
    target_inbounds: &std::collections::HashMap<String, crate::models::Inbound>,
    creds: &SharedCredentials,
    to_remove: &[(String, String)],
) -> AppResult<Vec<(String, bool)>> {
    let mut tx = state.db.begin().await?;
    let mut applied: Vec<(String, bool)> = Vec::with_capacity(target.len());
    let expires_at = normalize_expiry(body.expires_at.clone())?;
    for inbound_id in target {
        let inbound = &target_inbounds[inbound_id];
        let is_hysteria = matches!(
            &inbound.protocol,
            crate::protocols::ProtocolConfig::Hysteria2(_)
        );
        // Vless rows hold `auth = NULL`. Stamping the shared value on
        // them would just be noise in the API output.
        let auth = if is_hysteria {
            creds.hysteria_auth.clone()
        } else {
            None
        };
        if let Some(existing_id) = creds.existing_by_inbound.get(inbound_id) {
            // `existing` was snapshotted OUTSIDE the tx — a parallel
            // admin tab could have deleted this row between then and
            // now. The UPDATE silently no-ops (rows_affected = 0) in
            // that case; surface it as Conflict for an explicit retry.
            let res = sqlx::query!(
                r#"UPDATE clients
                   SET uuid = ?, auth = ?, flow = ?, note = ?, traffic_limit_bytes = ?,
                       expires_at = ?, updated_at = datetime('now')
                   WHERE id = ?"#,
                creds.uuid,
                auth,
                body.flow,
                body.note,
                body.traffic_limit_bytes,
                expires_at.clone(),
                existing_id,
            )
            .execute(&mut *tx)
            .await?;
            if res.rows_affected() == 0 {
                return Err(AppError::Conflict(format!(
                    "client '{}' in inbound {} was deleted by another session — retry",
                    body.email, inbound_id
                )));
            }
            applied.push((inbound_id.clone(), true));
        } else {
            let new_id = Uuid::new_v4().to_string();
            let sub_token = crate::api::subscription::generate_unique_token(&state.db).await?;
            sqlx::query!(
                r#"INSERT INTO clients (id, inbound_id, email, uuid, auth, flow, enabled,
                                        note, traffic_limit_bytes, disabled_reason, expires_at, sub_token)
                   VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, NULL, ?, ?)"#,
                new_id,
                inbound_id,
                body.email,
                creds.uuid,
                auth,
                body.flow,
                body.note,
                body.traffic_limit_bytes,
                expires_at.clone(),
                sub_token,
            )
            .execute(&mut *tx)
            .await
            .map_err(|e| match e {
                sqlx::Error::Database(d) if d.is_unique_violation() => AppError::Conflict(format!(
                    "client '{}' already exists in inbound {}",
                    body.email, inbound_id
                )),
                e => e.into(),
            })?;
            applied.push((inbound_id.clone(), false));
        }
    }
    for (id, inbound_id) in to_remove {
        sqlx::query!(
            "DELETE FROM clients WHERE id = ? AND inbound_id = ?",
            id,
            inbound_id,
        )
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(applied)
}

/// Post-commit xray `RemoveUser` fanout for the rows whose `inbound_id`
/// fell out of the target set. One batched (tag, enabled) lookup, then
/// per-row gRPC dispatch. Missing inbound = nothing to dispatch (it
/// vanished after the DELETE landed). gRPC failures get collected, not
/// raised — DB is the source of truth.
async fn sync_xray_removed(
    state: &AppState,
    email: &str,
    removed: &[ClientBulkRemoved],
) -> AppResult<Vec<ClientBulkXrayFailure>> {
    let mut failures = Vec::new();
    if removed.is_empty() {
        return Ok(failures);
    }
    let mut qb = sqlx::QueryBuilder::<sqlx::Sqlite>::new(
        "SELECT id, tag, enabled FROM inbounds WHERE id IN (",
    );
    let mut sep = qb.separated(", ");
    for r in removed {
        sep.push_bind(&r.inbound_id);
    }
    qb.push(")");
    let rows = qb
        .build_query_as::<RemovedInboundMetaRow>()
        .fetch_all(&state.db)
        .await?;
    let meta: std::collections::HashMap<String, (String, bool)> = rows
        .into_iter()
        .map(|r| (r.id, (r.tag, r.enabled != 0)))
        .collect();
    for r in removed {
        let Some((tag, true)) = meta.get(&r.inbound_id).cloned() else {
            continue;
        };
        if let Err(e) = state.xray_client.remove_user(&tag, email).await {
            tracing::warn!(
                "bulk-assign: xray RemoveUser({}, {}) failed: {e}",
                tag,
                email
            );
            failures.push(ClientBulkXrayFailure {
                inbound_id: r.inbound_id.clone(),
                inbound_tag: tag,
                message: format!("RemoveUser failed: {e}"),
            });
        }
    }
    Ok(failures)
}

/// Post-commit re-fetch + xray `AddUser` fanout for the just-INSERTed /
/// `UPDATEd` rows. One batched SELECT pulls every touched row, then per
/// row we (for UPDATE) RemoveUser-first to let xray pick up uuid/flow
/// changes, then `AddUser`. gRPC failures get collected. Returns
/// `(created, updated, failures)`.
async fn sync_xray_applied(
    state: &AppState,
    email: &str,
    applied: &[(String, bool)],
    target_inbounds: &std::collections::HashMap<String, crate::models::Inbound>,
) -> AppResult<(Vec<Client>, Vec<Client>, Vec<ClientBulkXrayFailure>)> {
    let mut failures = Vec::new();
    let mut created: Vec<Client> = Vec::new();
    let mut updated: Vec<Client> = Vec::new();
    if applied.is_empty() {
        return Ok((created, updated, failures));
    }
    let mut qb = sqlx::QueryBuilder::<sqlx::Sqlite>::new(
        "SELECT id, inbound_id, email, uuid, auth, flow, enabled, note, \
         traffic_limit_bytes, disabled_reason, expires_at, sub_token, created_at, updated_at \
         FROM clients WHERE email = ",
    );
    qb.push_bind(email);
    qb.push(" AND inbound_id IN (");
    let mut sep = qb.separated(", ");
    for (id, _) in applied {
        sep.push_bind(id);
    }
    qb.push(")");
    let rows = qb.build_query_as::<Row>().fetch_all(&state.db).await?;
    let mut applied_rows: std::collections::HashMap<String, Client> = rows
        .into_iter()
        .map(|r| (r.inbound_id.clone(), row_to_client(r)))
        .collect();
    for (inbound_id, was_update) in applied {
        let Some(client) = applied_rows.remove(inbound_id) else {
            tracing::warn!(
                "bulk-assign: applied row for inbound {} vanished post-commit",
                inbound_id
            );
            continue;
        };
        let inbound = &target_inbounds[inbound_id];
        if inbound.enabled {
            let tag = inbound.tag.clone();
            match inbound.protocol.as_protocol().build_user(&client) {
                Ok(user) => {
                    if *was_update {
                        let _ = state.xray_client.remove_user(&tag, &client.email).await;
                    }
                    if let Err(e) = state.xray_client.add_user(&tag, user).await {
                        tracing::warn!(
                            "bulk-assign: xray AddUser({}, {}) failed: {e}",
                            tag,
                            client.email
                        );
                        failures.push(ClientBulkXrayFailure {
                            inbound_id: inbound_id.clone(),
                            inbound_tag: tag,
                            message: format!("AddUser failed: {e}"),
                        });
                    }
                }
                Err(e) => {
                    tracing::warn!("bulk-assign: build_user for {} failed: {e}", client.email);
                    failures.push(ClientBulkXrayFailure {
                        inbound_id: inbound_id.clone(),
                        inbound_tag: tag,
                        message: format!("build_user failed: {e}"),
                    });
                }
            }
        }
        if *was_update {
            updated.push(client);
        } else {
            created.push(client);
        }
    }
    Ok((created, updated, failures))
}

/// Replace the client's subscription token with a freshly-rolled value
/// and return the updated row. The previous URL stops resolving the
/// moment the UPDATE commits, so this doubles as a revocation primitive
/// when an operator suspects a URL has leaked.
async fn rotate_sub_token(
    _user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> AppResult<Json<Client>> {
    let inbound_id = inbound_id_for_client(&state, &id).await?;
    let token = crate::api::subscription::generate_unique_token(&state.db).await?;
    sqlx::query!(
        "UPDATE clients SET sub_token = ?, updated_at = datetime('now') WHERE id = ?",
        token,
        id,
    )
    .execute(&state.db)
    .await?;
    let row = read_row(&state, &inbound_id, &id).await?;
    Ok(Json(row_to_client(row)))
}

/// Latest per-email traffic + online snapshot from xray's `StatsService`.
/// Polled in the background every 5 s by `traffic::spawn_traffic_poller`,
/// so this handler just reads the warm in-memory map under a short
/// read lock — no gRPC roundtrip in the request path. Frontend polls
/// it at the same cadence (react-query 5 s refetch).
async fn stats_snapshot(
    _user: AuthUser,
    State(state): State<AppState>,
) -> Json<std::collections::HashMap<String, crate::traffic::TrafficSnapshot>> {
    Json(state.traffic.snapshot().await)
}

/// Zero the persisted lifetime totals for one client. Wipes only the
/// `uplink_total / downlink_total / traffic_updated_at` columns; the
/// in-memory `TrafficStore` will catch up on the next 5 s poll
/// (until then the snapshot endpoint may briefly still show the old
/// number, which is fine — no rollback ambiguity).
///
/// xray's own counter for this email is **not** touched. That keeps
/// the rate calculation continuous (no fake spike on the next poll)
/// and matches operator expectation that "Reset" zeros the panel's
/// view, not the proxy's internal session bookkeeping.
async fn reset_traffic(
    _user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> AppResult<StatusCode> {
    // Need the row before the wipe so we know whether to also re-enable
    // (only quota-disabled clients come back on automatically — a manually
    // disabled one stays off).
    let before = sqlx::query!(
        "SELECT inbound_id, disabled_reason FROM clients WHERE id = ?",
        id
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or(AppError::NotFound)?;

    let res = sqlx::query!(
        r#"UPDATE clients
           SET uplink_total = 0,
               downlink_total = 0,
               traffic_updated_at = datetime('now')
           WHERE id = ?"#,
        id,
    )
    .execute(&state.db)
    .await?;
    if res.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }

    // No baseline reset needed: the poller computes deltas against the
    // previous xray-counter value, not the DB total. Right after the wipe
    // the DB sits at 0 and the next tick will still see `delta = 0`
    // (xray's counter hasn't changed), so the cap can't immediately
    // re-trip on stale numbers.

    if before.disabled_reason.as_deref() == Some("quota") {
        sqlx::query!(
            "UPDATE clients SET enabled = 1, disabled_reason = NULL,
                    updated_at = datetime('now') WHERE id = ?",
            id
        )
        .execute(&state.db)
        .await?;

        // Re-attach to xray so traffic actually starts flowing again.
        // Mirrors the create/update paths: fetch the inbound, build a
        // protocol user from the row, push via gRPC. Errors are surfaced
        // because a successful HTTP response would otherwise lie about
        // the gateway state.
        let inbound = super::inbounds::fetch_inbound(&state, &before.inbound_id).await?;
        if inbound.enabled {
            let client = row_to_client(read_row(&state, &before.inbound_id, &id).await?);
            let user = inbound
                .protocol
                .as_protocol()
                .build_user(&client)
                .map_err(AppError::Internal)?;
            if let Err(e) = state.xray_client.add_user(&inbound.tag, user).await {
                tracing::error!(
                    "client {} re-enabled in DB but xray AddUser failed: {e}",
                    client.email
                );
                return Err(AppError::Internal(anyhow::anyhow!(
                    "re-enabled in DB but not applied to xray: {e}"
                )));
            }
        }
    }

    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize, TS)]
#[ts(export, export_to = "../../frontend/src/api/types/client.ts")]
pub struct ShareLinkResponse {
    pub link: String,
    /// Host portion the panel guessed for the share-link. Surfaced so the
    /// frontend can warn the operator when it falls back to a private IP
    /// or a stale value.
    pub host: String,
}

// =============================================================================
// Row mapping
// =============================================================================

/// Tag + enabled flag pulled together for the bulk-assign `removed`
/// loop, where we need to map each torn-down row to its xray handler
/// tag without re-issuing one SELECT per inbound.
#[derive(sqlx::FromRow)]
struct RemovedInboundMetaRow {
    id: String,
    tag: String,
    enabled: i64,
}

#[derive(sqlx::FromRow)]
struct Row {
    id: String,
    inbound_id: String,
    email: String,
    uuid: String,
    auth: Option<String>,
    flow: Option<String>,
    enabled: i64,
    note: Option<String>,
    traffic_limit_bytes: Option<i64>,
    disabled_reason: Option<String>,
    expires_at: Option<String>,
    sub_token: String,
    created_at: String,
    updated_at: String,
}

fn row_to_client(r: Row) -> Client {
    Client {
        id: r.id,
        inbound_id: r.inbound_id,
        email: r.email,
        uuid: r.uuid,
        auth: r.auth,
        flow: r.flow,
        enabled: r.enabled != 0,
        note: r.note,
        traffic_limit_bytes: r.traffic_limit_bytes,
        disabled_reason: r.disabled_reason,
        expires_at: r.expires_at,
        sub_token: r.sub_token,
        created_at: r.created_at,
        updated_at: r.updated_at,
    }
}

/// Normalize a client-supplied ISO-8601 expiry to the DB's UTC
/// `YYYY-MM-DD HH:MM:SS` shape (the `datetime('now')` format the poller
/// compares against). `None` passes through; unparsable input is a 400.
fn normalize_expiry(raw: Option<String>) -> AppResult<Option<String>> {
    match raw {
        None => Ok(None),
        Some(s) => {
            let dt = chrono::DateTime::parse_from_rfc3339(&s)
                .map_err(|e| AppError::BadRequest(format!("invalid expires_at: {e}")))?;
            Ok(Some(
                dt.with_timezone(&chrono::Utc)
                    .format("%Y-%m-%d %H:%M:%S")
                    .to_string(),
            ))
        }
    }
}

/// Look up the inbound's tag + enabled flag, given its id. Returns
/// `AppError::NotFound` if the inbound doesn't exist. Used to gate every
/// client mutation: the URL embeds `inbound_id`, but until we resolve it
/// to a tag we can't make a gRPC call.
///
/// The previous "and flow" sibling was rolled into this — the flow lives
/// on `protocol_config` JSON now and the few callers that wanted it
/// either don't need it any more (delete path) or fetch the full inbound
/// via `super::inbounds::fetch_inbound` to get the typed protocol layer.
async fn inbound_tag_and_enabled(state: &AppState, inbound_id: &str) -> AppResult<(String, bool)> {
    let row = sqlx::query!("SELECT tag, enabled FROM inbounds WHERE id = ?", inbound_id)
        .fetch_optional(&state.db)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok((row.tag, row.enabled != 0))
}

// =============================================================================
// Handlers
// =============================================================================

async fn list(
    _user: AuthUser,
    State(state): State<AppState>,
    Path(inbound_id): Path<String>,
) -> AppResult<Json<Vec<Client>>> {
    // Confirm the inbound exists so a missing parent returns 404, not [].
    inbound_tag_and_enabled(&state, &inbound_id).await?;

    let rows = sqlx::query_as!(
        Row,
        r#"SELECT id, inbound_id, email, uuid, auth, flow, enabled, note,
                  traffic_limit_bytes, disabled_reason, expires_at, sub_token, created_at, updated_at
           FROM clients WHERE inbound_id = ?
           ORDER BY created_at"#,
        inbound_id
    )
    .fetch_all(&state.db)
    .await?;
    Ok(Json(rows.into_iter().map(row_to_client).collect()))
}

async fn get_one(
    _user: AuthUser,
    State(state): State<AppState>,
    Path((inbound_id, id)): Path<(String, String)>,
) -> AppResult<Json<Client>> {
    let row = sqlx::query_as!(
        Row,
        r#"SELECT id, inbound_id, email, uuid, auth, flow, enabled, note,
                  traffic_limit_bytes, disabled_reason, expires_at, sub_token, created_at, updated_at
           FROM clients WHERE id = ? AND inbound_id = ?"#,
        id,
        inbound_id
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or(AppError::NotFound)?;
    Ok(Json(row_to_client(row)))
}

async fn create(
    _user: AuthUser,
    State(state): State<AppState>,
    Path(inbound_id): Path<String>,
    Json(body): Json<ClientCreate>,
) -> AppResult<(StatusCode, Json<Client>)> {
    if body.email.trim().is_empty() {
        return Err(AppError::BadRequest("email is required".to_owned()));
    }

    // Fetch the full inbound row — needed to populate VLESS-encryption
    // settings on the new user proto. `inbound_tag_and_enabled` would be
    // lighter but doesn't carry the protocol layer.
    let inbound = super::inbounds::fetch_inbound(&state, &inbound_id).await?;
    let inbound_tag = inbound.tag.clone();
    let inbound_enabled = inbound.enabled;

    // UUID: caller-supplied or freshly minted. We validate the input by
    // parsing it — xray will reject malformed UUIDs at AlterInbound time
    // anyway, but a 400 here is friendlier than a 500.
    let uuid = match &body.uuid {
        Some(s) if !s.trim().is_empty() => {
            Uuid::parse_str(s.trim())
                .map_err(|e| AppError::BadRequest(format!("invalid uuid: {e}")))?;
            s.trim().to_owned()
        }
        _ => Uuid::new_v4().to_string(),
    };

    // Hysteria-only: auto-generate when omitted so the new client is
    // immediately usable. For VLESS the column stays NULL.
    let trimmed_auth = body
        .auth
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let auth: Option<String> = trimmed_auth.map(str::to_owned).or_else(|| {
        matches!(
            &inbound.protocol,
            crate::protocols::ProtocolConfig::Hysteria2(_)
        )
        .then(|| Uuid::new_v4().to_string())
    });

    let id = Uuid::new_v4().to_string();
    let sub_token = crate::api::subscription::generate_token();
    let expires_at = normalize_expiry(body.expires_at.clone())?;
    sqlx::query!(
        r#"INSERT INTO clients (id, inbound_id, email, uuid, auth, flow, enabled, note,
                                traffic_limit_bytes, disabled_reason, expires_at, sub_token)
           VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, NULL, ?, ?)"#,
        id,
        inbound_id,
        body.email,
        uuid,
        auth,
        body.flow,
        body.note,
        body.traffic_limit_bytes,
        expires_at,
        sub_token,
    )
    .execute(&state.db)
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(d) if d.is_unique_violation() => AppError::Conflict(format!(
            "client with email '{}' already exists in this inbound",
            body.email
        )),
        sqlx::Error::Database(d) if d.is_foreign_key_violation() => AppError::NotFound,
        e => e.into(),
    })?;

    let row = read_row(&state, &inbound_id, &id).await?;
    let client = row_to_client(row);

    // Push to xray only if the parent inbound is enabled (and therefore
    // present as a handler). For a disabled inbound the client is staged
    // and will be picked up on next enable/restart via reconciliation.
    if inbound_enabled {
        let user = inbound
            .protocol
            .as_protocol()
            .build_user(&client)
            .map_err(AppError::Internal)?;
        if let Err(e) = state.xray_client.add_user(&inbound_tag, user).await {
            tracing::error!(
                "DB client {} added to {} but xray AddUser failed: {e}",
                client.email,
                inbound_tag
            );
            return Err(AppError::Internal(anyhow::anyhow!(
                "saved but not applied to xray: {e}"
            )));
        }
    }

    Ok((StatusCode::CREATED, Json(client)))
}

async fn update(
    _user: AuthUser,
    State(state): State<AppState>,
    Path((inbound_id, id)): Path<(String, String)>,
    Json(body): Json<ClientUpdate>,
) -> AppResult<Json<Client>> {
    let inbound = super::inbounds::fetch_inbound(&state, &inbound_id).await?;
    let before = row_to_client(read_row(&state, &inbound_id, &id).await?);

    if let Some(s) = &body.uuid {
        Uuid::parse_str(s.trim())
            .map_err(|e| AppError::BadRequest(format!("invalid uuid: {e}")))?;
    }

    write_client_update_tx(&state, &id, &body).await?;
    let after = refetch_with_quota_recheck(&state, &id, &inbound_id).await?;
    sync_client_update_to_xray(&state, &inbound, &before, &after).await?;
    Ok(Json(after))
}

/// Apply the PATCH body to the DB inside one tx. Email is split out so
/// the unique-violation maps back to a human-readable 409 — the
/// combined UPDATE below would lose that error context. Every other
/// touched column lands in one dynamic UPDATE via `QueryBuilder`,
/// guarded by `has_change` so an empty PATCH stays a no-op.
async fn write_client_update_tx(state: &AppState, id: &str, body: &ClientUpdate) -> AppResult<()> {
    let mut tx = state.db.begin().await?;

    if let Some(email) = &body.email {
        sqlx::query!(
            "UPDATE clients SET email = ?, updated_at = datetime('now') WHERE id = ?",
            email,
            id
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| match e {
            sqlx::Error::Database(d) if d.is_unique_violation() => AppError::Conflict(format!(
                "client with email '{email}' already exists in this inbound"
            )),
            e => e.into(),
        })?;
    }

    // `enabled` carries a paired `disabled_reason` write so the operator's
    // manual toggle never collides with the poller's quota writes: enabling
    // clears the reason, disabling marks it as "manual".
    let mut qb = sqlx::QueryBuilder::new("UPDATE clients SET updated_at = datetime('now')");
    // Accumulator across several independent optional fields — the
    // let-if-seq rewrite only fits a single if/else, not this chain.
    #[allow(clippy::useless_let_if_seq)]
    let mut has_change = false;
    if let Some(uuid) = &body.uuid {
        qb.push(", uuid = ").push_bind(uuid);
        has_change = true;
    }
    if let Some(raw_auth) = &body.auth {
        // Empty string clears the column so the wire-side falls back to uuid.
        let stored: Option<String> = Some(raw_auth.trim())
            .filter(|s| !s.is_empty())
            .map(str::to_owned);
        qb.push(", auth = ").push_bind(stored);
        has_change = true;
    }
    if let Some(flow) = &body.flow {
        qb.push(", flow = ").push_bind(flow);
        has_change = true;
    }
    if let Some(enabled) = body.enabled {
        let reason: Option<&str> = (!enabled).then_some("manual");
        qb.push(", enabled = ").push_bind(i64::from(enabled));
        qb.push(", disabled_reason = ").push_bind(reason);
        has_change = true;
    }
    if let Some(note) = &body.note {
        qb.push(", note = ").push_bind(note);
        has_change = true;
    }
    // PatchField: `Set(n)` → write, `Clear` → NULL, `Unchanged` → no-op.
    if let Some(opt) = body.traffic_limit_bytes.as_change() {
        qb.push(", traffic_limit_bytes = ").push_bind(opt.copied());
        has_change = true;
    }
    if let Some(opt) = body.expires_at.as_change() {
        let normalized = normalize_expiry(opt.cloned())?;
        qb.push(", expires_at = ").push_bind(normalized);
        has_change = true;
    }
    if has_change {
        qb.push(" WHERE id = ").push_bind(id);
        qb.build().execute(&mut *tx).await?;
    }
    tx.commit().await.map_err(AppError::from)
}

/// Post-tx re-fetch + auto-reactivate-on-quota-room. Pulls row +
/// lifetime totals in one SELECT (saves the second round-trip the
/// quota check would otherwise need). If the row was quota-disabled
/// and the operator just raised / cleared the limit so there's room,
/// flip `enabled` back on locally and persist.
async fn refetch_with_quota_recheck(
    state: &AppState,
    id: &str,
    inbound_id: &str,
) -> AppResult<Client> {
    let row = sqlx::query!(
        r#"SELECT id, inbound_id, email, uuid, auth, flow, enabled, note,
                  traffic_limit_bytes, disabled_reason, expires_at, sub_token, created_at, updated_at,
                  (uplink_total + downlink_total) AS "used!: i64"
           FROM clients WHERE id = ? AND inbound_id = ?"#,
        id,
        inbound_id,
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or(AppError::NotFound)?;
    let used = row.used;
    let mut after = row_to_client(Row {
        id: row.id,
        inbound_id: row.inbound_id,
        email: row.email,
        uuid: row.uuid,
        auth: row.auth,
        flow: row.flow,
        enabled: row.enabled,
        note: row.note,
        traffic_limit_bytes: row.traffic_limit_bytes,
        disabled_reason: row.disabled_reason,
        expires_at: row.expires_at,
        sub_token: row.sub_token,
        created_at: row.created_at,
        updated_at: row.updated_at,
    });

    if after.disabled_reason.as_deref() == Some("quota") {
        let has_room = after.traffic_limit_bytes.is_none_or(|cap| used < cap);
        if has_room {
            sqlx::query!(
                "UPDATE clients SET enabled = 1, disabled_reason = NULL,
                        updated_at = datetime('now') WHERE id = ?",
                id
            )
            .execute(&state.db)
            .await?;
            // Mirror the write locally — saves a 3rd SELECT just to
            // learn what we already know. `updated_at` stays sub-second
            // stale; the operator's PATCH-response uses it for ordering
            // at best, not microsecond-precision auditing.
            after.enabled = true;
            after.disabled_reason = None;
        }
    }
    // Sibling of the quota recheck: an expired row whose date was cleared
    // or pushed into the future comes back on. `expires_at` is the stored
    // UTC `YYYY-MM-DD HH:MM:SS`; a string compare against the same-shaped
    // `now` is chronological.
    if after.disabled_reason.as_deref() == Some("expired") {
        let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
        let not_expired = after
            .expires_at
            .as_deref()
            .is_none_or(|exp| exp > now.as_str());
        if not_expired {
            sqlx::query!(
                "UPDATE clients SET enabled = 1, disabled_reason = NULL,
                        updated_at = datetime('now') WHERE id = ?",
                id
            )
            .execute(&state.db)
            .await?;
            after.enabled = true;
            after.disabled_reason = None;
        }
    }
    Ok(after)
}

/// Push the update to xray. Three branches:
///   * identity changes (email/uuid/auth/flow) ⇒ remove old, add new
///   * enabled flip only ⇒ either add or remove
///   * note-only ⇒ no xray call
///
/// Disabled inbound = no-op (xray has no handler to `AlterUser` on; the
/// reconciliation loop picks up the change on the next enable).
async fn sync_client_update_to_xray(
    state: &AppState,
    inbound: &crate::models::Inbound,
    before: &Client,
    after: &Client,
) -> AppResult<()> {
    if !inbound.enabled {
        return Ok(());
    }
    let identity_changed = before.email != after.email
        || before.uuid != after.uuid
        || before.auth != after.auth
        || before.flow != after.flow;
    // Reuse one protocol handle across the identity / enabled branches —
    // `build_user` only needs the protocol layer, never the rest.
    let protocol = inbound.protocol.as_protocol();
    let tag = &inbound.tag;
    if identity_changed {
        if before.enabled {
            let _ = state.xray_client.remove_user(tag, &before.email).await;
        }
        if after.enabled {
            let user = protocol.build_user(after).map_err(AppError::Internal)?;
            if let Err(e) = state.xray_client.add_user(tag, user).await {
                tracing::error!(
                    "client {} updated but xray AddUser failed: {e}",
                    after.email
                );
                return Err(AppError::Internal(anyhow::anyhow!(
                    "saved but not applied to xray: {e}"
                )));
            }
        }
    } else if before.enabled != after.enabled {
        if after.enabled {
            let user = protocol.build_user(after).map_err(AppError::Internal)?;
            if let Err(e) = state.xray_client.add_user(tag, user).await {
                return Err(AppError::Internal(anyhow::anyhow!(
                    "saved but not applied to xray: {e}"
                )));
            }
        } else {
            let _ = state.xray_client.remove_user(tag, &before.email).await;
        }
    }
    Ok(())
}

async fn delete(
    _user: AuthUser,
    State(state): State<AppState>,
    Path((inbound_id, id)): Path<(String, String)>,
) -> AppResult<StatusCode> {
    let (inbound_tag, inbound_enabled) = inbound_tag_and_enabled(&state, &inbound_id).await?;

    let row = sqlx::query!(
        "SELECT email, enabled FROM clients WHERE id = ? AND inbound_id = ?",
        id,
        inbound_id
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or(AppError::NotFound)?;

    if inbound_enabled && row.enabled != 0 {
        let _ = state
            .xray_client
            .remove_user(&inbound_tag, &row.email)
            .await;
    }

    let res = sqlx::query!(
        "DELETE FROM clients WHERE id = ? AND inbound_id = ?",
        id,
        inbound_id
    )
    .execute(&state.db)
    .await?;
    if res.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    Ok(StatusCode::NO_CONTENT)
}

// =============================================================================
// Helpers
// =============================================================================

/// Assemble the vless:// share-link for one client.
///
/// Host source: the system monitor's auto-detected `ipv4` (the outbound
/// address). If neither v4 nor v6 is available the endpoint returns an
/// error — without a host the link can't be useful.
async fn share_link_endpoint(
    _user: AuthUser,
    State(state): State<AppState>,
    Path((inbound_id, id)): Path<(String, String)>,
) -> AppResult<Json<ShareLinkResponse>> {
    let inbound = super::inbounds::fetch_inbound(&state, &inbound_id).await?;
    let client = row_to_client(read_row(&state, &inbound_id, &id).await?);

    let snap = state.host.snapshot().await;
    let host = snap.ipv4.or(snap.ipv6).ok_or_else(|| {
        AppError::Internal(anyhow::anyhow!("no IPv4/IPv6 detected for share-link host"))
    })?;

    let link =
        share_link::build_share_link(&inbound, &client, &host).map_err(AppError::Internal)?;
    Ok(Json(ShareLinkResponse { link, host }))
}

async fn read_row(state: &AppState, inbound_id: &str, id: &str) -> AppResult<Row> {
    sqlx::query_as!(
        Row,
        r#"SELECT id, inbound_id, email, uuid, auth, flow, enabled, note,
                  traffic_limit_bytes, disabled_reason, expires_at, sub_token, created_at, updated_at
           FROM clients WHERE id = ? AND inbound_id = ?"#,
        id,
        inbound_id
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or(AppError::NotFound)
}

/// Look up only the client's `inbound_id` from its global `id`. The global
/// routes use this as the first step before delegating to the nested-style
/// helpers that already know how to operate against `(inbound_id, id)`.
/// Returns `NotFound` if no row matches.
async fn inbound_id_for_client(state: &AppState, id: &str) -> AppResult<String> {
    let row = sqlx::query!("SELECT inbound_id FROM clients WHERE id = ?", id)
        .fetch_optional(&state.db)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(row.inbound_id)
}

// =============================================================================
// Global (top-level) routes
// =============================================================================

/// Query parameters for `GET /api/clients`. All optional — empty filter
/// returns every client across every inbound. Matching is conjunctive:
/// `?inbound_id=X&enabled=true` returns only enabled clients of inbound X.
#[derive(Debug, Deserialize)]
struct ClientListFilters {
    inbound_id: Option<String>,
    /// Case-insensitive substring match on `email`.
    email: Option<String>,
    enabled: Option<bool>,
}

async fn list_global(
    _user: AuthUser,
    State(state): State<AppState>,
    Query(filters): Query<ClientListFilters>,
) -> AppResult<Json<Vec<Client>>> {
    // sqlx::query_as! can't take optional WHERE clauses at compile-time, so
    // we either build a dynamic query (loses compile-time check) or fetch
    // everything and filter in Rust. For the panel's expected scale (≤ a
    // few thousand clients in a maxed-out deployment) the in-memory filter
    // is cheap and lets us keep the compile-time SQL check. If clients ever
    // grow to 100k+, switch to a `QueryBuilder` dynamic SQL build.
    let rows = sqlx::query_as!(
        Row,
        r#"SELECT id, inbound_id, email, uuid, auth, flow, enabled, note,
                  traffic_limit_bytes, disabled_reason, expires_at, sub_token, created_at, updated_at
           FROM clients ORDER BY created_at DESC"#
    )
    .fetch_all(&state.db)
    .await?;

    let email_needle = filters.email.as_deref().map(str::to_lowercase);
    let out: Vec<Client> = rows
        .into_iter()
        .filter(|r| {
            if let Some(inb) = &filters.inbound_id
                && &r.inbound_id != inb
            {
                return false;
            }
            if let Some(en) = filters.enabled
                && (r.enabled != 0) != en
            {
                return false;
            }
            if let Some(needle) = &email_needle
                && !r.email.to_lowercase().contains(needle)
            {
                return false;
            }
            true
        })
        .map(row_to_client)
        .collect();
    Ok(Json(out))
}

async fn get_one_global(
    _user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> AppResult<Json<Client>> {
    let inbound_id = inbound_id_for_client(&state, &id).await?;
    let row = read_row(&state, &inbound_id, &id).await?;
    Ok(Json(row_to_client(row)))
}

async fn create_global(
    user: AuthUser,
    State(state): State<AppState>,
    Json(body): Json<ClientCreateGlobal>,
) -> AppResult<(StatusCode, Json<Client>)> {
    // Re-dispatch to the existing nested handler. Same DB write, same gRPC
    // push, same error semantics — the only difference is where inbound_id
    // came from (URL vs body).
    create(
        user,
        State(state),
        Path(body.inbound_id),
        Json(ClientCreate {
            email: body.email,
            uuid: body.uuid,
            auth: body.auth,
            flow: body.flow,
            note: body.note,
            traffic_limit_bytes: body.traffic_limit_bytes,
            expires_at: body.expires_at,
        }),
    )
    .await
}

async fn update_global(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<ClientUpdate>,
) -> AppResult<Json<Client>> {
    let inbound_id = inbound_id_for_client(&state, &id).await?;
    update(user, State(state), Path((inbound_id, id)), Json(body)).await
}

async fn delete_global(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> AppResult<StatusCode> {
    let inbound_id = inbound_id_for_client(&state, &id).await?;
    delete(user, State(state), Path((inbound_id, id))).await
}

async fn share_link_global(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> AppResult<Json<ShareLinkResponse>> {
    let inbound_id = inbound_id_for_client(&state, &id).await?;
    share_link_endpoint(user, State(state), Path((inbound_id, id))).await
}
