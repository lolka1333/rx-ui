//! Client endpoints.
//!
//! A client row is one user's attachment to one inbound; the user is every row
//! sharing an email. The endpoints that change a user — create on an inbound,
//! the global create, bulk-assign, PATCH, traffic reset — all go through
//! [`user`], which keeps the per-user fields equal on every row and syncs xray
//! for the rows that changed. Per-row operations stay here: deleting one
//! attachment, reissuing a `WireGuard` peer, the share link.
//!
//! Routes are mounted twice: nested under `/api/inbounds/{inbound_id}/clients`
//! and at `/api/clients`, where the inbound is resolved from the client id.
//! The DB write goes through even while the parent inbound is disabled (so the
//! operator can pre-stage clients); the xray side is skipped then, because the
//! inbound has no handler to update.

mod user;

use crate::{
    AppState,
    auth::AuthUser,
    error::{AppError, AppResult},
    models::{
        Client, ClientBulkAssign, ClientBulkAssignResult, ClientCreate, ClientCreateGlobal,
        ClientUpdate,
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

/// Nested router mounted at `/api/inbounds/{inbound_id}/clients`, for callers
/// that already hold the inbound as context — today the reverse-pair wizard's
/// create call. It is also the shared implementation the global `/api/clients`
/// routes delegate into after resolving the inbound from the client id.
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
        .route(
            "/{id}/rotate-wireguard",
            axum::routing::post(rotate_wireguard),
        )
        .route("/bulk-assign", axum::routing::post(bulk_assign))
}

/// Atomic multi-inbound assignment for one user — the write the client form
/// makes.
///
/// The body names the user's whole attachment set: the user ends up on exactly
/// `inbound_ids`, attached where it was missing and detached where it is no
/// longer listed, with the body's flow, reverse tag, note, limit and expiry on
/// every row. Its uuid and Hysteria secret are the caller's when given,
/// otherwise the ones it already has — rotating them on every save would break
/// every installed link — otherwise fresh. Whether it is switched on is not
/// this endpoint's to change; that is the row toggle's.
async fn bulk_assign(
    _user: AuthUser,
    State(state): State<AppState>,
    Json(body): Json<ClientBulkAssign>,
) -> AppResult<Json<ClientBulkAssignResult>> {
    // Trim ONCE, here, and use it for every read and write below. The email is
    // the user's identity key: `WHERE email = ?` lookups match exactly, and xray
    // keys its per-user stats on the same string. Validating the trimmed value
    // but storing the raw one would let `" alice "` become a second user that
    // shares no quota, traffic or credentials with `alice` while looking
    // identical in the UI.
    let email = body.email.trim().to_owned();
    if email.is_empty() {
        return Err(AppError::BadRequest("email is required".to_owned()));
    }
    if body.inbound_ids.is_empty() {
        return Err(AppError::BadRequest(
            "inbound_ids must contain at least one entry; \
             use DELETE /api/clients/{id} to fully remove a user"
                .to_owned(),
        ));
    }
    let mut target = body.inbound_ids.clone();
    target.sort();
    target.dedup();
    let inbounds = super::inbounds::fetch_inbounds_batch(&state, &target).await?;
    if inbounds.len() != target.len() {
        return Err(AppError::NotFound);
    }

    // Validated before anything is written: a malformed uuid would otherwise
    // surface as xray's AddUser failure, after the rows already hold it.
    let caller_uuid = parse_optional_uuid(body.uuid.as_deref())?;
    let stored = user::load_user(&state.db, &email).await?;
    let (enabled, disabled_reason) = stored.as_ref().map_or((true, None), |s| {
        (s.fields.enabled, s.fields.disabled_reason.clone())
    });
    let fields = user::UserFields {
        uuid: caller_uuid
            .map(str::to_owned)
            .or_else(|| stored.as_ref().map(|s| s.fields.uuid.clone()))
            .unwrap_or_else(|| user::UserFields::new_user().uuid),
        auth: user::resolve_auth(
            body.auth.as_deref(),
            stored.as_ref(),
            inbounds.values().any(is_hysteria),
        ),
        flow: body.flow.clone(),
        reverse_tag: normalize_reverse_tag(&state, body.reverse_tag.as_deref()).await?,
        note: body.note.clone(),
        traffic_limit_bytes: body.traffic_limit_bytes,
        expires_at: normalize_expiry(body.expires_at.clone())?,
        enabled,
        disabled_reason,
    };
    let applied = user::apply_user(
        &state,
        &user::UserWrite {
            email,
            rename_from: None,
            fields,
            inbounds,
        },
    )
    .await?;
    Ok(Json(ClientBulkAssignResult {
        created: applied.created,
        updated: applied.updated,
        removed: applied.removed,
        xray_failures: applied.xray_failures,
    }))
}

const fn is_hysteria(inbound: &crate::models::Inbound) -> bool {
    matches!(
        inbound.protocol,
        crate::protocols::ProtocolConfig::Hysteria2(_)
    )
}

/// Validate an optional caller-supplied uuid: trim, treat empty as absent,
/// reject a malformed value with a 400 (friendlier than xray's later
/// `AlterInbound` 500). Borrows through, so the caller keeps ownership.
fn parse_optional_uuid(raw: Option<&str>) -> AppResult<Option<&str>> {
    match raw.map(str::trim).filter(|s| !s.is_empty()) {
        Some(s) => {
            Uuid::parse_str(s).map_err(|e| AppError::BadRequest(format!("invalid uuid: {e}")))?;
            Ok(Some(s))
        }
        None => Ok(None),
    }
}

/// Replace the client's subscription token with a freshly-rolled value
/// and return the updated row. The token belongs to the email, so it is
/// replaced on every attachment at once and the email's retired tokens go
/// with it — the URL that leaked may be any of them. Every previous URL
/// stops resolving the moment the transaction commits, which is what makes
/// this a revocation primitive.
async fn rotate_sub_token(
    _user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> AppResult<Json<Client>> {
    let inbound_id = inbound_id_for_client(&state, &id).await?;
    let mut tx = crate::db::begin_write(&state.db).await?;
    let email: String = sqlx::query_scalar("SELECT email FROM clients WHERE id = ?")
        .bind(&id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(AppError::NotFound)?;
    crate::api::subscription::rotate_token_for_email_on(&mut tx, &email).await?;
    tx.commit().await?;
    let row = read_row(&state, &inbound_id, &id).await?;
    Ok(Json(row_to_client(row)))
}

/// Mint a fresh keypair and pre-shared key for one `WireGuard` peer.
///
/// The tunnel address is deliberately kept: it is the peer's identity at
/// runtime — xray attributes a connection to a user by the source address
/// inside the tunnel — and it is what per-client traffic accounting hangs off,
/// so rotating it would look like a different user to the stats poller.
///
/// The config already in someone's hands stops working the moment this
/// returns; that is the point of the operation, and the UI says so before
/// calling it.
async fn rotate_wireguard(
    _user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> AppResult<Json<Client>> {
    let inbound_id = inbound_id_for_client(&state, &id).await?;
    let inbound = super::inbounds::fetch_inbound(&state, &inbound_id).await?;
    if !matches!(
        inbound.protocol,
        crate::protocols::ProtocolConfig::Wireguard(_)
    ) {
        return Err(AppError::BadRequest(format!(
            "inbound {} is not a WireGuard inbound — this client has no peer keys to rotate",
            inbound.tag
        )));
    }

    let issue_psk = match &inbound.protocol {
        crate::protocols::ProtocolConfig::Wireguard(wg) => wg.issue_preshared_key,
        _ => false,
    };
    let before = row_to_client(read_row(&state, &inbound_id, &id).await?);
    let keys = crate::xray::keygen::generate_wireguard_keypair();
    // A peer that never had an address gets one now. The rows in that state are
    // the ones an inbound inherited when it changed protocol; without this the
    // reissue writes fresh keys and then fails on the missing address, leaving
    // the row half-rotated and the operator with nothing to try next.
    // Reissuing follows the inbound's current policy: an operator who turned
    // pre-shared keys off gets a peer without one, and one who turned them on
    // is how a peer predating the setting finally gets its key.
    let psk = issue_psk.then(crate::xray::keygen::generate_preshared_key);
    let mut tx = crate::db::begin_write(&state.db).await?;
    let address = match before.wg_address.clone().filter(|a| !a.trim().is_empty()) {
        Some(existing) => existing,
        // Allocated in this transaction, like any other peer's — the address is
        // the identity, so it cannot be picked outside one.
        None => wireguard_peer_for(&mut tx, &inbound_id, &inbound.tag, &inbound.protocol)
            .await?
            .address
            .ok_or_else(|| {
                AppError::Internal(anyhow::anyhow!(
                    "inbound {} could not issue a tunnel address",
                    inbound.tag
                ))
            })?,
    };
    sqlx::query!(
        "UPDATE clients SET wg_private_key = ?, wg_public_key = ?, wg_preshared_key = ?,
                            wg_address = ?, updated_at = datetime('now')
         WHERE id = ?",
        keys.private_key,
        keys.public_key,
        psk,
        address,
        id,
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    let after = row_to_client(read_row(&state, &inbound_id, &id).await?);
    // The peer's public key IS its identity to the core, so the running handler
    // has to be told: the old entry is dropped and the new one added.
    user::sync_row(&state, &inbound, Some(&before), Some(&after))
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("saved but not applied to xray: {e}")))?;
    Ok(Json(after))
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

/// Zero a user's traffic, and bring it back on when the quota was what stopped
/// it.
///
/// The counters are the user's — xray counts per email and every row holds the
/// same figure — so all rows are reset together: a row left behind would keep
/// the old total, and the poller reads the largest. The UI still calls this
/// once per row; every call after the first finds nothing left to do.
async fn reset_traffic(
    _user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> AppResult<StatusCode> {
    let email: String = sqlx::query_scalar("SELECT email FROM clients WHERE id = ?")
        .bind(&id)
        .fetch_optional(&state.db)
        .await?
        .ok_or(AppError::NotFound)?;
    sqlx::query(
        "UPDATE clients SET uplink_total = 0, downlink_total = 0, \
         traffic_updated_at = datetime('now') WHERE email = ?",
    )
    .bind(&email)
    .execute(&state.db)
    .await?;
    // No baseline reset needed: the poller computes deltas against the
    // previous xray-counter value, not the DB total, so the cap cannot re-trip
    // on stale numbers right after the wipe.

    // Writing the user back as it is runs the shared recheck, which lifts a
    // quota stop now that the usage is zero and pushes the rows that come back.
    let stored = user::load_user(&state.db, &email)
        .await?
        .ok_or(AppError::NotFound)?;
    let inbounds = super::inbounds::fetch_inbounds_batch(&state, &stored.inbound_ids()).await?;
    let applied = user::apply_user(
        &state,
        &user::UserWrite {
            email,
            rename_from: None,
            fields: stored.fields,
            inbounds,
        },
    )
    .await?;
    if let Some(fail) = applied.xray_failures.first() {
        return Err(AppError::Internal(anyhow::anyhow!(
            "re-enabled in DB but not applied to xray on {}: {}",
            fail.inbound_tag,
            fail.message
        )));
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

#[derive(sqlx::FromRow)]
struct Row {
    id: String,
    inbound_id: String,
    email: String,
    uuid: String,
    auth: Option<String>,
    flow: Option<String>,
    reverse_tag: Option<String>,
    enabled: i64,
    note: Option<String>,
    traffic_limit_bytes: Option<i64>,
    disabled_reason: Option<String>,
    expires_at: Option<String>,
    sub_token: String,
    wg_private_key: Option<String>,
    wg_public_key: Option<String>,
    wg_address: Option<String>,
    wg_preshared_key: Option<String>,
    created_at: String,
    updated_at: String,
}

/// A peer's credentials on a `WireGuard` inbound: a fresh keypair and the
/// lowest free address in the inbound's subnet. All `None` for every other
/// protocol, which is what the columns hold there.
///
/// The address is picked inside the caller's transaction on purpose. It is the
/// peer's identity at runtime — xray attributes a connection by the source
/// address inside the tunnel — so two clients created at the same moment
/// handed the same address would be one user to the core, with their traffic
/// landing on whichever peer it found first.
/// Give every client of a `WireGuard` inbound the peer credentials it is
/// missing, in the caller's transaction.
///
/// The rows that need this are the ones that predate the inbound BEING
/// `WireGuard`: an inbound that changes protocol keeps its clients, and they
/// were inserted when there was no pool to draw an address from. Without a
/// backfill the first of them to be enabled takes the whole inbound down —
/// `build_user` refuses a peer with no key, and one refusal fails the config
/// for every other peer on it.
///
/// Disabled rows are included on purpose: they are exactly the ones the
/// inbound's own build gate cannot see, and re-enabling one later is what
/// would otherwise break the inbound.
pub async fn backfill_wireguard_peers(
    tx: &mut sqlx::SqliteConnection,
    inbound_id: &str,
    tag: &str,
    protocol: &crate::protocols::ProtocolConfig,
) -> AppResult<()> {
    if !matches!(protocol, crate::protocols::ProtocolConfig::Wireguard(_)) {
        return Ok(());
    }
    let pending: Vec<String> = sqlx::query_scalar!(
        r#"SELECT id AS "id!: String" FROM clients
           WHERE inbound_id = ?
             AND (wg_address IS NULL OR wg_address = ''
                  OR wg_public_key IS NULL OR wg_public_key = '')
           ORDER BY created_at, id"#,
        inbound_id
    )
    .fetch_all(&mut *tx)
    .await?;

    for id in pending {
        // One at a time: each row is written before the next address is
        // picked, so the "taken" set the allocator reads is always current.
        let peer = wireguard_peer_for(&mut *tx, inbound_id, tag, protocol).await?;
        sqlx::query!(
            "UPDATE clients SET wg_private_key = ?, wg_public_key = ?, wg_address = ?,
                                wg_preshared_key = ?, updated_at = datetime('now')
             WHERE id = ?",
            peer.private_key,
            peer.public_key,
            peer.address,
            peer.preshared_key,
            id,
        )
        .execute(&mut *tx)
        .await?;
    }
    Ok(())
}

#[derive(Default)]
struct WireguardPeerFields {
    private_key: Option<String>,
    public_key: Option<String>,
    address: Option<String>,
    preshared_key: Option<String>,
}

async fn wireguard_peer_for(
    tx: &mut sqlx::SqliteConnection,
    inbound_id: &str,
    tag: &str,
    protocol: &crate::protocols::ProtocolConfig,
) -> AppResult<WireguardPeerFields> {
    let crate::protocols::ProtocolConfig::Wireguard(wg) = protocol else {
        return Ok(WireguardPeerFields::default());
    };
    let taken: std::collections::HashSet<String> = sqlx::query_scalar!(
        r#"SELECT wg_address AS "wg_address!: String" FROM clients
           WHERE inbound_id = ? AND wg_address IS NOT NULL"#,
        inbound_id
    )
    .fetch_all(&mut *tx)
    .await?
    .into_iter()
    .collect();

    let pool = wg
        .client_addresses()
        .map_err(|e| AppError::BadRequest(format!("inbound {tag}: {e}")))?;
    let address = pool
        .map(|a| a.to_string())
        .find(|a| !taken.contains(a))
        .ok_or_else(|| {
            AppError::BadRequest(format!(
                "inbound {tag}: every address in {} is taken",
                wg.subnet
            ))
        })?;

    let keys = crate::xray::keygen::generate_wireguard_keypair();
    Ok(WireguardPeerFields {
        private_key: Some(keys.private_key),
        public_key: Some(keys.public_key),
        address: Some(address),
        // `WireGuard` treats a pre-shared key as optional, so the inbound says
        // whether its peers get one. On by default; off means the config comes
        // out exactly as a plain `WireGuard` server would write it.
        preshared_key: wg
            .issue_preshared_key
            .then(crate::xray::keygen::generate_preshared_key),
    })
}

fn row_to_client(r: Row) -> Client {
    Client {
        id: r.id,
        inbound_id: r.inbound_id,
        email: r.email,
        uuid: r.uuid,
        auth: r.auth,
        flow: r.flow,
        reverse_tag: r.reverse_tag,
        enabled: r.enabled != 0,
        note: r.note,
        traffic_limit_bytes: r.traffic_limit_bytes,
        disabled_reason: r.disabled_reason,
        expires_at: r.expires_at,
        sub_token: r.sub_token,
        wg_private_key: r.wg_private_key,
        wg_public_key: r.wg_public_key,
        wg_address: r.wg_address,
        wg_preshared_key: r.wg_preshared_key,
        created_at: r.created_at,
        updated_at: r.updated_at,
    }
}

/// Load the enabled clients of an inbound, oldest first — the set xray needs
/// when (re)building that inbound's handler. Takes a bare `&DbPool` (not
/// `&AppState`) so the startup reconciler in `main` can share this single
/// source of truth, and is reused by the inbound CRUD + key-rotation paths in
/// [`super::inbounds`].
pub async fn load_enabled_clients(
    db: &crate::db::DbPool,
    inbound_id: &str,
) -> AppResult<Vec<Client>> {
    let rows = sqlx::query_as!(
        Row,
        r#"SELECT id, inbound_id, email, uuid, auth, flow, reverse_tag, enabled, note,
                  traffic_limit_bytes, disabled_reason, expires_at, sub_token,
                  wg_private_key, wg_public_key, wg_address, wg_preshared_key, created_at, updated_at
           FROM clients
           WHERE inbound_id = ? AND enabled = 1
           ORDER BY created_at ASC"#,
        inbound_id
    )
    .fetch_all(db)
    .await?;
    Ok(rows.into_iter().map(row_to_client).collect())
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
        r#"SELECT id, inbound_id, email, uuid, auth, flow, reverse_tag, enabled, note,
                  traffic_limit_bytes, disabled_reason, expires_at, sub_token,
                  wg_private_key, wg_public_key, wg_address, wg_preshared_key, created_at, updated_at
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
    let row = read_row(&state, &inbound_id, &id).await?;
    Ok(Json(row_to_client(row)))
}

/// Normalise + validate a client's `reverse_tag`. Empty / whitespace → `None`
/// (a normal, non-portal client). A non-empty tag makes the client a reverse
/// PORTAL: xray registers a routable tunnel outbound under it when a bridge
/// dials in, so it must satisfy the SAME rules as a custom outbound tag — not
/// reserved, no whitespace/control chars, and no collision with an existing
/// custom outbound tag (a collision makes every bridge dial-in fail at runtime
/// with `outbound <tag> is not type Reverse`). Shared by every write path so
/// the stored tag is always trimmed-non-empty-and-valid, or NULL.
async fn normalize_reverse_tag(state: &AppState, raw: Option<&str>) -> AppResult<Option<String>> {
    let Some(tag) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    crate::xray::config_gen::validate_routable_tag(tag)
        .map_err(|e| AppError::BadRequest(format!("reverse {e}")))?;
    if crate::api::outbounds::load_custom_outbounds(&state.db)
        .await?
        .iter()
        .any(|o| o.tag == tag)
    {
        return Err(AppError::BadRequest(format!(
            "reverse tag '{tag}' collides with an existing outbound tag"
        )));
    }
    Ok(Some(tag.to_owned()))
}

/// Attach a user to one inbound, creating the user when the email is new.
///
/// The body describes the user, not just this row. For an email that already
/// exists, a field the body leaves out keeps the user's value and one it sets
/// becomes the user's on every attachment, so the new row can never disagree
/// with its siblings. Attaching a user to an inbound it is already on is a 409.
async fn create(
    _user: AuthUser,
    State(state): State<AppState>,
    Path(inbound_id): Path<String>,
    Json(body): Json<ClientCreate>,
) -> AppResult<(StatusCode, Json<Client>)> {
    // Trimmed once and used for every bind below — see `bulk_assign`.
    let email = body.email.trim().to_owned();
    if email.is_empty() {
        return Err(AppError::BadRequest("email is required".to_owned()));
    }
    let inbound = super::inbounds::fetch_inbound(&state, &inbound_id).await?;
    let stored = user::load_user(&state.db, &email).await?;
    if stored.as_ref().is_some_and(|s| s.has_inbound(&inbound_id)) {
        return Err(AppError::Conflict(format!(
            "client with email '{email}' already exists in this inbound"
        )));
    }

    let caller_uuid = parse_optional_uuid(body.uuid.as_deref())?;
    let base = stored
        .as_ref()
        .map_or_else(user::UserFields::new_user, |s| s.fields.clone());
    let reverse_tag = match body.reverse_tag.as_deref() {
        Some(raw) => normalize_reverse_tag(&state, Some(raw)).await?,
        None => base.reverse_tag.clone(),
    };
    let expires_at = match body.expires_at.clone() {
        Some(raw) => normalize_expiry(Some(raw))?,
        None => base.expires_at.clone(),
    };
    let fields = user::UserFields {
        uuid: caller_uuid.map_or_else(|| base.uuid.clone(), str::to_owned),
        auth: user::resolve_auth(body.auth.as_deref(), stored.as_ref(), is_hysteria(&inbound)),
        flow: body.flow.clone().or(base.flow),
        reverse_tag,
        note: body.note.clone().or(base.note),
        traffic_limit_bytes: body.traffic_limit_bytes.or(base.traffic_limit_bytes),
        expires_at,
        enabled: base.enabled,
        disabled_reason: base.disabled_reason,
    };

    let mut ids = stored
        .as_ref()
        .map(user::StoredUser::inbound_ids)
        .unwrap_or_default();
    ids.push(inbound_id.clone());
    let inbounds = super::inbounds::fetch_inbounds_batch(&state, &ids).await?;
    let applied = user::apply_user(
        &state,
        &user::UserWrite {
            email,
            rename_from: None,
            fields,
            inbounds,
        },
    )
    .await?;
    // The row is saved either way. A core that did not take it is reported as
    // an error rather than a 201 the running proxy does not honour.
    if let Some(fail) = applied
        .xray_failures
        .iter()
        .find(|f| f.inbound_id == inbound_id)
    {
        return Err(AppError::Internal(anyhow::anyhow!(
            "saved but not applied to xray: {}",
            fail.message
        )));
    }
    let client = applied
        .created
        .into_iter()
        .find(|c| c.inbound_id == inbound_id)
        .ok_or_else(|| {
            AppError::Internal(anyhow::anyhow!("the new attachment did not come back"))
        })?;
    Ok((StatusCode::CREATED, Json(client)))
}

/// Change a user through one of its rows.
///
/// Every field here belongs to the user, so it lands on every row of the email,
/// not only the one in the URL: a row that disagreed with its siblings is how a
/// user came to connect with one uuid on one inbound and another elsewhere, or
/// to be switched off on some inbounds and not others. Changing `email` renames
/// the user, refused while another user has that email.
async fn update(
    _user: AuthUser,
    State(state): State<AppState>,
    Path((inbound_id, id)): Path<(String, String)>,
    Json(body): Json<ClientUpdate>,
) -> AppResult<Json<Client>> {
    let row = row_to_client(read_row(&state, &inbound_id, &id).await?);
    let stored = user::load_user(&state.db, &row.email)
        .await?
        .ok_or(AppError::NotFound)?;

    let mut f = stored.fields.clone();
    if let Some(raw) = &body.uuid {
        // Trimmed, and the TRIMMED value checked: storing " <uuid> " would pass
        // a check of the trimmed form and then land in the VLESS account, where
        // xray cannot parse it.
        let uuid = raw.trim();
        Uuid::parse_str(uuid).map_err(|e| AppError::BadRequest(format!("invalid uuid: {e}")))?;
        uuid.clone_into(&mut f.uuid);
    }
    if let Some(raw) = &body.auth {
        // Empty clears it: the Hysteria wire falls back to the uuid.
        f.auth = Some(raw.trim())
            .filter(|s| !s.is_empty())
            .map(str::to_owned);
    }
    if let Some(flow) = &body.flow {
        f.flow = Some(flow.clone());
    }
    if let Some(raw) = &body.reverse_tag {
        // Empty clears the tag (back to a normal VLESS user).
        f.reverse_tag = normalize_reverse_tag(&state, Some(raw)).await?;
    }
    if let Some(note) = &body.note {
        f.note = Some(note.clone());
    }
    // PatchField: `Set(n)` → write, `Clear` → NULL, `Unchanged` → leave.
    if let Some(limit) = body.traffic_limit_bytes.as_change() {
        f.traffic_limit_bytes = limit.copied();
    }
    if let Some(expires_at) = body.expires_at.as_change() {
        f.expires_at = normalize_expiry(expires_at.cloned())?;
    }
    if let Some(enabled) = body.enabled {
        // A manual switch says so, which is what keeps the poller's automatic
        // re-enable (quota / expiry) from undoing it.
        f.enabled = enabled;
        f.disabled_reason = (!enabled).then(|| "manual".to_owned());
    }
    let email = match body.email.as_deref().map(str::trim) {
        Some("") => return Err(AppError::BadRequest("email is required".to_owned())),
        Some(new) => new.to_owned(),
        None => row.email.clone(),
    };
    let rename_from = (email != row.email).then(|| row.email.clone());

    let inbounds = super::inbounds::fetch_inbounds_batch(&state, &stored.inbound_ids()).await?;
    let applied = user::apply_user(
        &state,
        &user::UserWrite {
            email,
            rename_from,
            fields: f,
            inbounds,
        },
    )
    .await?;
    if let Some(fail) = applied.xray_failures.first() {
        return Err(AppError::Internal(anyhow::anyhow!(
            "saved but not applied to xray on {}: {}",
            fail.inbound_tag,
            fail.message
        )));
    }
    applied
        .updated
        .into_iter()
        .find(|c| c.id == id)
        .map(Json)
        .ok_or(AppError::NotFound)
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
        r#"SELECT id, inbound_id, email, uuid, auth, flow, reverse_tag, enabled, note,
                  traffic_limit_bytes, disabled_reason, expires_at, sub_token,
                  wg_private_key, wg_public_key, wg_address, wg_preshared_key, created_at, updated_at
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
        r#"SELECT id, inbound_id, email, uuid, auth, flow, reverse_tag, enabled, note,
                  traffic_limit_bytes, disabled_reason, expires_at, sub_token,
                  wg_private_key, wg_public_key, wg_address, wg_preshared_key, created_at, updated_at
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
            // Global create can't produce a portal: a reverse tag is set on the
            // per-inbound create/edit form (and the reverse-pair wizard), where
            // the single-inbound context is what makes the routing rule useful.
            reverse_tag: None,
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
