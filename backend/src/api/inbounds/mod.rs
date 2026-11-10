//! Inbounds API: CRUD over the typed layer schema, mirrored into the running
//! xray over gRPC. Every row stores its layers (protocol / transport /
//! security / sniffing / finalmask / sockopt) as JSON blobs.
//!
//! * `store` — row mapping and the SQL, the PATCH write included.
//! * `validate` — the cross-layer gate every create and update passes before
//!   anything is written.
//! * `keys` — server-managed key material: completed on create, carried
//!   forward on update, minted afresh by the Reality rotate endpoint.
//! * `stats` — per-inbound traffic totals.
//!
//! Every write here runs in the same order: validate, build the xray handler
//! config in memory, commit, then push. A config xray would refuse is a 400
//! before any row changes, and a push that fails after the commit is a 500
//! that names it, with the row kept for the next reconcile.

mod keys;
mod stats;
mod store;
mod validate;

pub use store::{fetch_inbound, fetch_inbounds_batch, load_enabled_inbound_rows, row_to_inbound};
pub use validate::validate_finalmask;

use self::{
    keys::{
        complete_server_managed_fields, preserve_reality_keypair, rotate_reality_keypair,
        settle_wireguard_keys,
    },
    stats::stats,
    store::{ensure_port_free, read_row, write_inbound_update_tx},
    validate::{validate_inbound_tag, validate_layers},
};
use crate::{
    AppState,
    auth::AuthUser,
    error::{AppError, AppResult},
    models::{Inbound, InboundCreate, InboundUpdate},
};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
};
use uuid::Uuid;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(list).post(create))
        .route("/stats", get(stats))
        .route("/finalmask-support", get(finalmask_support))
        .route("/{id}", get(get_one).patch(update).delete(delete))
        .route("/{id}/rotate-reality-keypair", post(rotate_reality_keypair))
}

async fn list(_user: AuthUser, State(state): State<AppState>) -> AppResult<Json<Vec<Inbound>>> {
    store::list_inbounds(&state.db).await.map(Json)
}

async fn get_one(
    _user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> AppResult<Json<Inbound>> {
    let row = read_row(&state, &id).await?;
    Ok(Json(row_to_inbound(row)?))
}

async fn create(
    _user: AuthUser,
    State(state): State<AppState>,
    Json(body): Json<InboundCreate>,
) -> AppResult<(StatusCode, Json<Inbound>)> {
    let InboundCreate {
        tag,
        listen,
        port,
        mut protocol,
        transport,
        mut security,
        sniffing,
        finalmask,
        sockopt,
    } = body;

    validate_inbound_tag(&tag)?;

    let mut finalmask = finalmask.unwrap_or_default();
    let sockopt = sockopt.unwrap_or_default();
    validate_layers(&protocol, &transport, &security, &finalmask, true, true)?;
    ensure_port_free(&state.db, port, None).await?;
    complete_server_managed_fields(&state, &mut protocol, &mut security).await?;
    // A derivation failure is the server's problem (missing binary, a core too
    // old to know `xmc`, a wedged `convert pb`), not bad input — and `Internal`
    // renders its whole cause chain, so the operator sees what xray said.
    crate::xray::xmc::complete_finalmask(&state.xray.binary, &mut finalmask)
        .await
        .map_err(AppError::Internal)?;

    let id = Uuid::new_v4().to_string();
    let listen = listen.unwrap_or_else(|| "0.0.0.0".to_owned());
    let sniffing = sniffing.unwrap_or_default();
    // Reject bad sniffing exclusions (e.g. a malformed CIDR) before the
    // INSERT so a conversion failure can't leave a half-created row.
    crate::xray::orchestrator::validate_sniffing(&sniffing)
        .map_err(|e| AppError::BadRequest(e.to_string()))?;

    // Assemble the inbound in memory and build its xray handler config
    // *before* the INSERT. A config that can't be built — e.g. `security=tls`
    // with no certificate — is a permanent bad-config error, so reject it as
    // a 400 here rather than committing a row that xray will never load. That
    // matters because the reconcile loop skips un-buildable rows with only a
    // warn-level log, so a post-commit build failure would leave a phantom
    // enabled inbound in the list. Timestamps are placeholders — the response
    // re-reads the persisted row for the real values.
    let inbound = Inbound {
        id: id.clone(),
        tag,
        enabled: true,
        listen,
        port,
        protocol,
        transport,
        security,
        sniffing,
        finalmask,
        sockopt,
        created_at: String::new(),
        updated_at: String::new(),
    };
    let handler = crate::xray::orchestrator::inbound_to_handler_config(&inbound, &[])
        .map_err(|e| AppError::BadRequest(e.to_string()))?;

    let protocol_json = serde_json::to_string(&inbound.protocol)?;
    let transport_json = serde_json::to_string(&inbound.transport)?;
    let security_json = serde_json::to_string(&inbound.security)?;
    let sniffing_json = serde_json::to_string(&inbound.sniffing)?;
    let finalmask_json = serde_json::to_string(&inbound.finalmask)?;
    let sockopt_json = serde_json::to_string(&inbound.sockopt)?;
    let port_i = i64::from(inbound.port);

    sqlx::query!(
        r#"INSERT INTO inbounds (
            id, tag, enabled, listen, port,
            protocol_config, transport_config, security_config, sniffing_config,
            finalmask_config, sockopt_config
        ) VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?)"#,
        inbound.id,
        inbound.tag,
        inbound.listen,
        port_i,
        protocol_json,
        transport_json,
        security_json,
        sniffing_json,
        finalmask_json,
        sockopt_json,
    )
    .execute(&state.db)
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(d) if d.is_unique_violation() => {
            AppError::Conflict(format!("inbound with tag '{}' already exists", inbound.tag))
        }
        e => e.into(),
    })?;

    // Re-read for the canonical DB timestamps returned to the client.
    let inbound = row_to_inbound(read_row(&state, &id).await?)?;

    // Push the freshly-built handler into xray. The config already built
    // cleanly above, so a failure here is a live-apply problem (gRPC blip /
    // xray down), not bad config: log it and surface a 500, but keep the DB
    // row so the next reconcile or restart applies it.
    if let Err(e) = state.xray_client.add_inbound(handler).await {
        tracing::error!(
            "DB inbound {} created but xray AddInbound failed: {e}",
            inbound.tag
        );
        return Err(AppError::Internal(anyhow::anyhow!(
            "saved but not applied to xray: {e}"
        )));
    }

    Ok((StatusCode::CREATED, Json(inbound)))
}

async fn update(
    _user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(mut body): Json<InboundUpdate>,
) -> AppResult<Json<Inbound>> {
    let before = row_to_inbound(read_row(&state, &id).await?)?;

    // Derive before validating and before writing: the stored blob must carry
    // the keypair for the password it is stored with. The form never sends the
    // keys (they are not in the TS type), so an edit that touches nothing but
    // the hostname would otherwise persist a mask with no key at all.
    if let Some(finalmask) = body.finalmask.as_mut() {
        crate::xray::xmc::complete_finalmask(&state.xray.binary, finalmask)
            .await
            .map_err(AppError::Internal)?;
    }

    // Validate the post-change combination *before* hitting the DB so
    // an illegal swap (Vision×WS, Reality×WS, …) doesn't leave the
    // panel and xray out of sync. Each layer either gets the operator's
    // new value or falls back to the current row.
    // Merged the same way the write path will merge it: a WireGuard PATCH that
    // leaves the device key blank keeps the stored one, so the candidate below
    // is built from the config that will actually be persisted: the stored key
    // carried forward when the body left it blank, the public half re-derived
    // when it didn't.
    let next_protocol = &settle_wireguard_keys(
        body.protocol.as_ref().unwrap_or(&before.protocol),
        &before.protocol,
    )?;
    let next_transport = body.transport.as_ref().unwrap_or(&before.transport);
    let next_security = body.security.as_ref().unwrap_or(&before.security);
    let next_finalmask = body.finalmask.as_ref().unwrap_or(&before.finalmask);
    // The matrix judges the combination whenever the operator submits any part
    // of it — the mask itself, or the transport / security it is keyed on.
    // Moving an inbound to a transport that cannot run its stored mask is a
    // choice being made now, not a legacy row riding along, and leaving it
    // unchecked would strand a mask the create path refuses outright. A PATCH
    // that touches none of the three (the `{enabled: false}` toggle, a rename,
    // a port change) still carries the stored mask through untouched.
    validate_layers(
        next_protocol,
        next_transport,
        next_security,
        next_finalmask,
        body.finalmask.is_some() || body.transport.is_some() || body.security.is_some(),
        body.protocol.is_some(),
    )?;
    let next_sniffing = body.sniffing.as_ref().unwrap_or(&before.sniffing);
    crate::xray::orchestrator::validate_sniffing(next_sniffing)
        .map_err(|e| AppError::BadRequest(e.to_string()))?;

    // If the post-change inbound would be enabled, confirm its config actually
    // builds *before* committing the DB change — same reasoning as `create`.
    // An un-buildable edit (e.g. switching to `security=tls` with no cert) is
    // worse on this path: `sync_inbound_update_to_xray` removes the old working
    // handler *before* failing to add the new one, so the inbound goes offline
    // with the bad config committed and no way back until manual repair. Reject
    // it as a 400 here instead. A disabled result skips this (never pushed), and
    // disabling or deleting a broken inbound stays possible.
    if body.enabled.unwrap_or(before.enabled) {
        let next_sockopt = body.sockopt.as_ref().unwrap_or(&before.sockopt);
        // Build the candidate from the same Reality-keypair-preserved security
        // the write path persists (`preserve_reality_keypair_tx`): a Reality
        // PATCH submits a blank `private_key` (the frontend can't read it) and
        // the stored keypair is carried forward. Validating the raw blank-key
        // body instead would falsely 400 a routine Reality edit with "x25519
        // key must decode to 32 bytes, got 0".
        let candidate_security = preserve_reality_keypair(next_security, &before.security);
        let candidate = Inbound {
            id: before.id.clone(),
            tag: body.tag.clone().unwrap_or_else(|| before.tag.clone()),
            enabled: true,
            listen: body.listen.clone().unwrap_or_else(|| before.listen.clone()),
            port: body.port.unwrap_or(before.port),
            protocol: next_protocol.clone(),
            transport: next_transport.clone(),
            security: candidate_security,
            sniffing: next_sniffing.clone(),
            finalmask: next_finalmask.clone(),
            sockopt: next_sockopt.clone(),
            created_at: before.created_at.clone(),
            updated_at: before.updated_at.clone(),
        };
        // Validate with the SAME enabled clients `sync_inbound_update_to_xray`
        // builds with, not an empty slice — so the pre-commit build is exact
        // parity with the post-commit AddInbound. `build_user` returns `Result`;
        // a future fallible impl must not slip a client-specific failure past
        // this gate into sync's remove-then-fail-to-re-add window.
        let clients = crate::api::clients::load_enabled_clients(&state.db, &id).await?;
        crate::xray::orchestrator::inbound_to_handler_config(&candidate, &clients)
            .map_err(|e| AppError::BadRequest(e.to_string()))?;
    }

    write_inbound_update_tx(&state, &id, &body).await?;
    let after = row_to_inbound(read_row(&state, &id).await?)?;
    sync_inbound_update_to_xray(&state, &id, &before, &after, &body).await?;
    Ok(Json(after))
}

/// Push the inbound update to xray. Tag / port / listen / layer changes
/// all require a remove+add cycle (xray's `AlterInbound` can't mutate
/// them). A pure enable→disable transition removes; disable→enable
/// re-adds with the current client list.
async fn sync_inbound_update_to_xray(
    state: &AppState,
    id: &str,
    before: &Inbound,
    after: &Inbound,
    body: &InboundUpdate,
) -> AppResult<()> {
    let layers_changed = body.protocol.is_some()
        || body.transport.is_some()
        || body.security.is_some()
        || body.sniffing.is_some()
        || body.finalmask.is_some()
        || body.sockopt.is_some();
    let basics_changed = body.tag.is_some() || body.listen.is_some() || body.port.is_some();
    let toggled = before.enabled != after.enabled;

    if before.enabled && (layers_changed || basics_changed || (toggled && !after.enabled)) {
        let _ = state.xray_client.remove_inbound(&before.tag).await;
    }
    if after.enabled && (layers_changed || basics_changed || toggled) {
        let clients = crate::api::clients::load_enabled_clients(&state.db, id).await?;
        let handler = crate::xray::orchestrator::inbound_to_handler_config(after, &clients)
            .map_err(AppError::Internal)?;
        if let Err(e) = state.xray_client.add_inbound(handler).await {
            tracing::error!(
                "inbound {} updated but xray AddInbound failed: {e}",
                after.tag
            );
            return Err(AppError::Internal(anyhow::anyhow!(
                "saved but not applied to xray: {e}"
            )));
        }
    }
    Ok(())
}

async fn delete(
    _user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> AppResult<StatusCode> {
    let row = sqlx::query!("SELECT tag, enabled FROM inbounds WHERE id = ?", id)
        .fetch_optional(&state.db)
        .await?
        .ok_or(AppError::NotFound)?;

    if row.enabled != 0 {
        let _ = state.xray_client.remove_inbound(&row.tag).await;
    }

    let mut tx = state.db.begin().await?;
    let res = sqlx::query!("DELETE FROM inbounds WHERE id = ?", id)
        .execute(&mut *tx)
        .await?;
    if res.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    // Drop the per-inbound traffic total in the same tx, so the tag leaves no
    // orphan row that a later inbound reusing it would inherit.
    sqlx::query!("DELETE FROM inbound_traffic WHERE tag = ?", row.tag)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Re-push an inbound to xray after an in-place key change (a Reality key
/// rotation): drop the old handler and re-add it with the current enabled
/// clients. `what` names the change for the log / error text. Callers
/// invoke this only when the inbound is enabled.
async fn reapply_inbound_to_xray(state: &AppState, after: &Inbound, what: &str) -> AppResult<()> {
    let clients = crate::api::clients::load_enabled_clients(&state.db, &after.id).await?;
    let _ = state.xray_client.remove_inbound(&after.tag).await;
    let handler = crate::xray::orchestrator::inbound_to_handler_config(after, &clients)
        .map_err(AppError::Internal)?;
    if let Err(e) = state.xray_client.add_inbound(handler).await {
        tracing::error!(
            "inbound {} {what} in DB but xray re-add failed: {e}",
            after.tag
        );
        return Err(AppError::Internal(anyhow::anyhow!(
            "{what} in DB but not applied to xray: {e}"
        )));
    }
    Ok(())
}

/// Which `FinalMask` kinds actually run, per transport and security.
///
/// Served rather than duplicated in the frontend on purpose: the rule comes
/// from xray's two mask registries, the API already refuses anything outside
/// it, and a second copy in TypeScript is a copy that will disagree one day.
/// The shape is `{ transport: { security: [kind, …] } }` — small enough to
/// fetch once and keep.
async fn finalmask_support(_user: AuthUser) -> Json<serde_json::Value> {
    use crate::security::SecurityKind;
    use crate::transports::{TransportKind, finalmask::supported_kinds};

    let mut out = serde_json::Map::new();
    for transport in [
        TransportKind::Tcp,
        TransportKind::Ws,
        TransportKind::Xhttp,
        TransportKind::Hysteria,
    ] {
        let mut per_security = serde_json::Map::new();
        for security in [SecurityKind::None, SecurityKind::Tls, SecurityKind::Reality] {
            per_security.insert(
                security.as_db_str().to_owned(),
                serde_json::json!(supported_kinds(transport, security)),
            );
        }
        out.insert(
            transport.as_db_str().to_owned(),
            serde_json::Value::Object(per_security),
        );
    }
    // WireGuard is keyed here as if it were a transport, because to this matrix
    // it is one: it dials UDP itself, its allowed set does not vary with the
    // security layer (there isn't one), and the form already folds a protocol
    // into this vocabulary the same way it folds Hysteria 2.
    let wg = crate::transports::finalmask::wireguard_supported_kinds();
    let mut per_security = serde_json::Map::new();
    for security in [SecurityKind::None, SecurityKind::Tls, SecurityKind::Reality] {
        per_security.insert(security.as_db_str().to_owned(), serde_json::json!(wg));
    }
    out.insert(
        "wireguard".to_owned(),
        serde_json::Value::Object(per_security),
    );
    Json(serde_json::Value::Object(out))
}
