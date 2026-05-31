//! Inbounds CRUD over the typed layer schema. Every row carries four
//! JSON blobs (protocol / transport / security / sniffing); this module
//! reads them back into the trait-composed `Inbound` struct, runs
//! cross-layer validation, applies create / update / delete mutations,
//! and mirrors the result into the running xray over gRPC.
//!
//! Validation that happens before any DB write:
//!   * `vless_flow=Vision + transport != tcp` — xray rejects it anyway,
//!     but a panel-side 400 keeps the operator out of a half-committed
//!     row situation.
//!   * `security=Reality + transport=ws` — Reality has no WebSocket
//!     support in xray. Same reason as above.
//!   * `security=Reality` requires a non-empty `dest` and a non-empty
//!     `server_names` list.
//!   * `port` must be unique across inbounds.
//!
//! Everything else (tag uniqueness, JSON shape) is enforced by DB
//! constraints + serde at the request boundary.

use crate::{
    AppState,
    auth::AuthUser,
    error::{AppError, AppResult},
    models::{Inbound, InboundCreate, InboundUpdate},
    protocols::{
        ProtocolConfig,
        vless::{VlessEncryptionAuth, VlessEncryptionMode, VlessFlow, VlessXorMode},
    },
    security::SecurityConfig,
    transports::{TransportConfig, finalmask::FinalMask},
    xray::keygen,
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
        .route("/{id}", get(get_one).patch(update).delete(delete))
        .route("/{id}/rotate-reality-keypair", post(rotate_reality_keypair))
        .route(
            "/{id}/regenerate-vless-encryption-keypair",
            post(regenerate_vless_encryption_keypair),
        )
}

// =============================================================================
// Row mapping
// =============================================================================

#[derive(sqlx::FromRow)]
struct Row {
    id: String,
    tag: String,
    enabled: i64,
    listen: String,
    port: i64,
    protocol_config: String,
    transport_config: String,
    security_config: String,
    sniffing_config: String,
    finalmask_config: String,
    sockopt_config: String,
    created_at: String,
    updated_at: String,
}

/// Decode one DB row into the public `Inbound`. Each JSON column maps
/// directly into the corresponding tagged-enum field via `serde_json`.
/// A malformed blob in any layer is surfaced as a 500 — the JSON is
/// always written by this same code, so a parse failure means DB
/// corruption or an aborted backfill, not user error.
fn row_to_inbound(r: Row) -> AppResult<Inbound> {
    let protocol = serde_json::from_str(&r.protocol_config)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("protocol_config JSON: {e}")))?;
    let transport = serde_json::from_str(&r.transport_config)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("transport_config JSON: {e}")))?;
    let security = serde_json::from_str(&r.security_config)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("security_config JSON: {e}")))?;
    let sniffing = serde_json::from_str(&r.sniffing_config)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("sniffing_config JSON: {e}")))?;
    let finalmask = serde_json::from_str(&r.finalmask_config)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("finalmask_config JSON: {e}")))?;
    let sockopt = serde_json::from_str(&r.sockopt_config)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("sockopt_config JSON: {e}")))?;
    Ok(Inbound {
        id: r.id,
        tag: r.tag,
        enabled: r.enabled != 0,
        listen: r.listen,
        #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
        port: r.port as u16,
        protocol,
        transport,
        security,
        sniffing,
        finalmask,
        sockopt,
        created_at: r.created_at,
        updated_at: r.updated_at,
    })
}

// =============================================================================
// Validation
// =============================================================================

/// Cross-layer compatibility checks. xray would reject most of these
/// at `AddInbound` time anyway; doing them up front keeps the panel
/// and xray from drifting if the gRPC call fails between INSERT and
/// `AddInbound`.
fn validate_layers(
    protocol: &ProtocolConfig,
    transport: &TransportConfig,
    security: &SecurityConfig,
    finalmask: &FinalMask,
) -> AppResult<()> {
    // Cross-layer protocol/transport/security compatibility — declared
    // per protocol in `ProtocolConfig::compat`. The validator just
    // checks set membership; rules grow by editing the per-protocol
    // compat block, not by adding branches here.
    let compat = protocol.compat();
    let transport_kind = transport.as_transport().kind();
    let security_kind = security.as_security().kind();
    if !compat.allowed_transports.contains(&transport_kind) {
        return Err(AppError::BadRequest(format!(
            "{} does not support transport '{}'",
            protocol.display_name(),
            transport_kind.as_db_str(),
        )));
    }
    if !compat.allowed_securities.contains(&security_kind) {
        return Err(AppError::BadRequest(format!(
            "{} does not support security '{}'",
            protocol.display_name(),
            security_kind.as_db_str(),
        )));
    }

    // VLESS Vision is TCP-only. Reject any flow=vision combined with
    // non-TCP transports up front. Skipped for non-VLESS protocols.
    if let ProtocolConfig::Vless(vless) = protocol
        && vless.flow == VlessFlow::XtlsRprxVision
        && !matches!(transport, TransportConfig::Tcp(_))
    {
        return Err(AppError::BadRequest(
            "xtls-rprx-vision is only supported on raw TCP, not XHTTP or WebSocket".to_owned(),
        ));
    }

    // Reality + WebSocket is unsupported by xray.
    if matches!(security, SecurityConfig::Reality(_)) && matches!(transport, TransportConfig::Ws(_))
    {
        return Err(AppError::BadRequest(
            "Reality is not supported over WebSocket — use TCP or XHTTP transport \
             (or switch security to TLS for WebSocket)"
                .to_owned(),
        ));
    }

    // Reality wraps the raw TCP socket itself and depends on the
    // underlying conn implementing `CloseWriteConn`. xray-core's Fragment
    // and Sudoku TCP wrappers don't expose that method, so combining
    // either with Reality panics xray on first client handshake. Noise
    // is UDP-only and never touches the TCP socket, so it's still safe.
    if matches!(security, SecurityConfig::Reality(_))
        && matches!(finalmask, FinalMask::Fragment(_) | FinalMask::Sudoku(_))
    {
        return Err(AppError::BadRequest(
            "Reality is incompatible with Fragment / Sudoku FinalMask (xray-core panic). \
             Use Noise (UDP) or switch security to TLS / none."
                .to_owned(),
        ));
    }

    // VLESS fallbacks — xray-core rejects two combos at startup:
    //   * `fallbacks` + `decryption != "none"` (VLESS Encryption) — they
    //     write to the same protocol header bytes and xray bails out at
    //     `infra/conf/vless.go:157` with "fallbacks can not be used
    //     together with decryption".
    //   * `fallbacks` on anything other than TCP — fallbacks fire on the
    //     raw post-TLS stream, which only the TCP transport produces.
    //     WebSocket / XHTTP wrap traffic in their own framing and the
    //     fallback code path never gets called.
    if let ProtocolConfig::Vless(vless) = protocol
        && !vless.fallbacks.is_empty()
    {
        if !matches!(vless.encryption_mode, VlessEncryptionMode::None) {
            return Err(AppError::BadRequest(
                "VLESS fallbacks are incompatible with VLESS Encryption \
                 (xray-core rejects the combo). Disable encryption \
                 or remove the fallbacks."
                    .to_owned(),
            ));
        }
        if !matches!(transport, TransportConfig::Tcp(_)) {
            return Err(AppError::BadRequest(
                "VLESS fallbacks only work on the TCP transport — \
                 WebSocket / XHTTP frame traffic before xray sees it."
                    .to_owned(),
            ));
        }
        for fb in &vless.fallbacks {
            if fb.dest.trim().is_empty() {
                return Err(AppError::BadRequest(
                    "VLESS fallback `dest` is required".to_owned(),
                ));
            }
            if !fb.path.is_empty() && !fb.path.starts_with('/') {
                return Err(AppError::BadRequest(
                    "VLESS fallback `path` must be empty or start with '/'".to_owned(),
                ));
            }
            if fb.xver > 2 {
                return Err(AppError::BadRequest(
                    "VLESS fallback `xver` only accepts 0, 1, or 2".to_owned(),
                ));
            }
        }
    }

    // Reality needs a real dest and at least one serverName.
    if let SecurityConfig::Reality(r) = security {
        if r.dest.trim().is_empty() {
            return Err(AppError::BadRequest("reality dest is required".to_owned()));
        }
        if r.server_names.is_empty() {
            return Err(AppError::BadRequest(
                "reality server_names must have at least one entry".to_owned(),
            ));
        }
        for s in &r.short_ids {
            keygen::decode_short_id(s).map_err(|e| AppError::BadRequest(e.to_string()))?;
        }
    }

    Ok(())
}

/// Port-uniqueness guard. xray's HandlerService.AddInbound does NOT
/// reliably reject duplicate port bindings — on Windows in particular
/// two inbounds can coexist in xray's config while only one actually
/// receives traffic (silent SO_REUSEADDR-style override). A clean 409
/// from the panel is much better than a phantom inbound.
async fn ensure_port_free<'e, E>(conn: E, port: u16, exclude_id: Option<&str>) -> AppResult<()>
where
    E: sqlx::SqliteExecutor<'e>,
{
    let p = i64::from(port);
    let tag: Option<String> = match exclude_id {
        Some(id) => {
            sqlx::query_scalar("SELECT tag FROM inbounds WHERE port = ? AND id != ?")
                .bind(p)
                .bind(id)
                .fetch_optional(conn)
                .await?
        }
        None => {
            sqlx::query_scalar("SELECT tag FROM inbounds WHERE port = ?")
                .bind(p)
                .fetch_optional(conn)
                .await?
        }
    };
    if let Some(tag) = tag {
        return Err(AppError::Conflict(format!(
            "port {port} is already used by inbound '{tag}'"
        )));
    }
    Ok(())
}

/// Server-side completion of operator-supplied layers. Most of the time
/// the operator sends a structurally complete payload, but two fields
/// are always generated by the server (the operator should never see
/// them in the create form):
///   * Reality x25519 keypair — server generates both halves so a
///     misconfigured operator can't paste a public key without its
///     matching private.
///   * VLESS Encryption keypair — calling `xray vlessenc` for the
///     chosen auth (X25519 vs ML-KEM-768). Skipped when mode=None.
///
/// Mutates the typed configs in place so the resulting JSON blobs
/// carry the completed values. Returns Err if the keygen subprocess
/// fails (the operator sees the underlying message).
fn complete_server_managed_fields(
    state: &AppState,
    protocol: &mut ProtocolConfig,
    security: &mut SecurityConfig,
) -> AppResult<()> {
    if let SecurityConfig::Reality(r) = security {
        // Always overwrite — the operator never inputs Reality keys.
        let kp = keygen::generate_reality_keypair();
        r.private_key = kp.private_key;
        r.public_key = kp.public_key;
        if r.short_ids.is_empty() {
            r.short_ids = vec![keygen::generate_short_id()];
        }
        if r.fingerprint.is_empty() {
            "chrome".clone_into(&mut r.fingerprint);
        }
    }

    // VLESS-specific encryption key derivation. Hysteria 2 carries no
    // protocol-level encryption (everything is on the QUIC/TLS layer),
    // so the whole block is skipped for non-VLESS protocols.
    let ProtocolConfig::Vless(v) = protocol else {
        return Ok(());
    };
    if v.encryption_mode == VlessEncryptionMode::Mlkem768x25519Plus {
        let auth = v.encryption_auth.unwrap_or(VlessEncryptionAuth::Mlkem768);
        v.encryption_auth = Some(auth);
        v.encryption_xor_mode
            .get_or_insert_with(VlessXorMode::default);
        v.encryption_seconds_from.get_or_insert(600);
        // Respect frontend-provided keys (pre-generated through
        // `POST /api/keygen/vless-encryption` so the operator can see
        // them in the form before saving). Only fall back to a server-
        // side `xray vlessenc` call when the frontend didn't supply
        // anything — keeps backward compat with API clients that don't
        // know about the standalone keygen endpoint.
        let need_gen = v
            .encryption_server_key
            .as_ref()
            .is_none_or(String::is_empty)
            || v.encryption_client_key
                .as_ref()
                .is_none_or(String::is_empty);
        if need_gen {
            let kp = keygen::generate_vless_encryption_keypair(&state.xray.binary, auth)
                .map_err(AppError::Internal)?;
            v.encryption_server_key = Some(kp.server_key);
            v.encryption_client_key = Some(kp.client_key);
        }
    }

    Ok(())
}

// =============================================================================
// Handlers
// =============================================================================

async fn list(_user: AuthUser, State(state): State<AppState>) -> AppResult<Json<Vec<Inbound>>> {
    let rows = sqlx::query_as!(
        Row,
        r#"SELECT id, tag, enabled, listen, port,
                  protocol_config, transport_config, security_config, sniffing_config,
                  finalmask_config, sockopt_config, created_at, updated_at
           FROM inbounds
           ORDER BY created_at DESC"#
    )
    .fetch_all(&state.db)
    .await?;
    rows.into_iter()
        .map(row_to_inbound)
        .collect::<AppResult<Vec<_>>>()
        .map(Json)
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

    let finalmask = finalmask.unwrap_or_default();
    let sockopt = sockopt.unwrap_or_default();
    validate_layers(&protocol, &transport, &security, &finalmask)?;
    ensure_port_free(&state.db, port, None).await?;
    complete_server_managed_fields(&state, &mut protocol, &mut security)?;

    let id = Uuid::new_v4().to_string();
    let listen = listen.unwrap_or_else(|| "0.0.0.0".to_owned());
    let sniffing = sniffing.unwrap_or_default();

    let protocol_json = serde_json::to_string(&protocol)?;
    let transport_json = serde_json::to_string(&transport)?;
    let security_json = serde_json::to_string(&security)?;
    let sniffing_json = serde_json::to_string(&sniffing)?;
    let finalmask_json = serde_json::to_string(&finalmask)?;
    let sockopt_json = serde_json::to_string(&sockopt)?;
    let port_i = i64::from(port);

    sqlx::query!(
        r#"INSERT INTO inbounds (
            id, tag, enabled, listen, port,
            protocol_config, transport_config, security_config, sniffing_config,
            finalmask_config, sockopt_config
        ) VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?)"#,
        id,
        tag,
        listen,
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
            AppError::Conflict(format!("inbound with tag '{tag}' already exists"))
        }
        e => e.into(),
    })?;

    let inbound = row_to_inbound(read_row(&state, &id).await?)?;

    // Push the new handler into xray. A brand-new inbound has no
    // clients yet (pass empty slice). A gRPC blip here logs loudly and
    // surfaces a 500 — the DB row stays so the next reconcile or
    // restart picks it up.
    let handler = crate::xray::orchestrator::inbound_to_handler_config(&inbound, &[])
        .map_err(AppError::Internal)?;
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
    Json(body): Json<InboundUpdate>,
) -> AppResult<Json<Inbound>> {
    let before = row_to_inbound(read_row(&state, &id).await?)?;

    // Validate the post-change combination *before* hitting the DB so
    // an illegal swap (Vision×WS, Reality×WS, …) doesn't leave the
    // panel and xray out of sync. Each layer either gets the operator's
    // new value or falls back to the current row.
    let next_protocol = body.protocol.as_ref().unwrap_or(&before.protocol);
    let next_transport = body.transport.as_ref().unwrap_or(&before.transport);
    let next_security = body.security.as_ref().unwrap_or(&before.security);
    let next_finalmask = body.finalmask.as_ref().unwrap_or(&before.finalmask);
    validate_layers(next_protocol, next_transport, next_security, next_finalmask)?;

    write_inbound_update_tx(&state, &id, &body).await?;
    let after = row_to_inbound(read_row(&state, &id).await?)?;
    sync_inbound_update_to_xray(&state, &id, &before, &after, &body).await?;
    Ok(Json(after))
}

/// Apply the PATCH body to the DB inside one tx. Each non-`None` field
/// becomes its own sub-UPDATE so the unique-violation on `tag` can be
/// surfaced specifically (a combined dynamic UPDATE would lose that
/// error context). Port writes go through `ensure_port_free` so the
/// same port can't be silently double-bound by two inbounds.
async fn write_inbound_update_tx(
    state: &AppState,
    id: &str,
    body: &InboundUpdate,
) -> AppResult<()> {
    let mut tx = state.db.begin().await?;
    if let Some(tag) = &body.tag {
        sqlx::query!(
            "UPDATE inbounds SET tag = ?, updated_at = datetime('now') WHERE id = ?",
            tag,
            id
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| match e {
            sqlx::Error::Database(d) if d.is_unique_violation() => {
                AppError::Conflict(format!("inbound with tag '{tag}' already exists"))
            }
            e => e.into(),
        })?;
    }
    if let Some(enabled) = body.enabled {
        let v = i64::from(enabled);
        sqlx::query!(
            "UPDATE inbounds SET enabled = ?, updated_at = datetime('now') WHERE id = ?",
            v,
            id
        )
        .execute(&mut *tx)
        .await?;
    }
    if let Some(listen) = &body.listen {
        sqlx::query!(
            "UPDATE inbounds SET listen = ?, updated_at = datetime('now') WHERE id = ?",
            listen,
            id
        )
        .execute(&mut *tx)
        .await?;
    }
    if let Some(port) = body.port {
        let p = i64::from(port);
        ensure_port_free(&mut *tx, port, Some(id)).await?;
        sqlx::query!(
            "UPDATE inbounds SET port = ?, updated_at = datetime('now') WHERE id = ?",
            p,
            id
        )
        .execute(&mut *tx)
        .await?;
    }
    // Layer JSON blobs are persisted in a helper purely to keep this
    // function under the line limit — see `write_inbound_layers_tx`.
    write_inbound_layers_tx(&mut tx, id, body).await?;
    tx.commit().await.map_err(AppError::from)
}

/// Persist the six JSON-blob layer columns of an inbound PATCH (protocol,
/// transport, security, sniffing, finalmask, sockopt). Split out of
/// `write_inbound_update_tx` only to keep it under the line limit — each
/// arm stays explicit because `sqlx::query!` insists on a literal column
/// name, so they can't be collapsed into a loop.
async fn write_inbound_layers_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    id: &str,
    body: &InboundUpdate,
) -> AppResult<()> {
    if let Some(protocol) = &body.protocol {
        let j = serde_json::to_string(protocol)?;
        sqlx::query!(
            "UPDATE inbounds SET protocol_config = ?, updated_at = datetime('now') WHERE id = ?",
            j,
            id
        )
        .execute(&mut **tx)
        .await?;
    }
    if let Some(transport) = &body.transport {
        let j = serde_json::to_string(transport)?;
        sqlx::query!(
            "UPDATE inbounds SET transport_config = ?, updated_at = datetime('now') WHERE id = ?",
            j,
            id
        )
        .execute(&mut **tx)
        .await?;
    }
    if let Some(security) = &body.security {
        let j = serde_json::to_string(security)?;
        sqlx::query!(
            "UPDATE inbounds SET security_config = ?, updated_at = datetime('now') WHERE id = ?",
            j,
            id
        )
        .execute(&mut **tx)
        .await?;
    }
    if let Some(sniffing) = &body.sniffing {
        let j = serde_json::to_string(sniffing)?;
        sqlx::query!(
            "UPDATE inbounds SET sniffing_config = ?, updated_at = datetime('now') WHERE id = ?",
            j,
            id
        )
        .execute(&mut **tx)
        .await?;
    }
    if let Some(finalmask) = &body.finalmask {
        let j = serde_json::to_string(finalmask)?;
        sqlx::query!(
            "UPDATE inbounds SET finalmask_config = ?, updated_at = datetime('now') WHERE id = ?",
            j,
            id
        )
        .execute(&mut **tx)
        .await?;
    }
    if let Some(sockopt) = &body.sockopt {
        let j = serde_json::to_string(sockopt)?;
        sqlx::query!(
            "UPDATE inbounds SET sockopt_config = ?, updated_at = datetime('now') WHERE id = ?",
            j,
            id
        )
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
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
        let clients = load_enabled_clients(&state.db, id).await?;
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

    let res = sqlx::query!("DELETE FROM inbounds WHERE id = ?", id)
        .execute(&state.db)
        .await?;
    if res.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    Ok(StatusCode::NO_CONTENT)
}

/// Generate a fresh Reality x25519 keypair for this inbound. Only legal
/// when the inbound's security layer is Reality; for anything else the
/// call returns 400. After the rotation every previously-issued share
/// link is invalid (the `pbk=` baked into the URL no longer matches the
/// server), so the UI surfaces a confirm dialog.
async fn rotate_reality_keypair(
    _user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> AppResult<Json<Inbound>> {
    let mut inbound = row_to_inbound(read_row(&state, &id).await?)?;
    let SecurityConfig::Reality(ref mut reality) = inbound.security else {
        return Err(AppError::BadRequest(
            "inbound is not configured for Reality — nothing to rotate".to_owned(),
        ));
    };

    let kp = keygen::generate_reality_keypair();
    reality.private_key = kp.private_key;
    reality.public_key = kp.public_key;

    let j = serde_json::to_string(&inbound.security)?;
    sqlx::query!(
        "UPDATE inbounds SET security_config = ?, updated_at = datetime('now') WHERE id = ?",
        j,
        id
    )
    .execute(&state.db)
    .await?;

    let after = row_to_inbound(read_row(&state, &id).await?)?;
    if after.enabled {
        let clients = load_enabled_clients(&state.db, &id).await?;
        let _ = state.xray_client.remove_inbound(&after.tag).await;
        let handler = crate::xray::orchestrator::inbound_to_handler_config(&after, &clients)
            .map_err(AppError::Internal)?;
        if let Err(e) = state.xray_client.add_inbound(handler).await {
            tracing::error!(
                "inbound {} reality key rotated in DB but xray re-add failed: {e}",
                after.tag
            );
            return Err(AppError::Internal(anyhow::anyhow!(
                "rotated in DB but not applied to xray: {e}"
            )));
        }
    }

    Ok(Json(after))
}

/// Generate a fresh VLESS-encryption keypair. Auth defaults to ML-KEM-
/// 768 when the inbound isn't yet configured for PQ; calling this
/// endpoint also flips mode to `mlkem768x25519plus` if it was None
/// (operator's signal that they want it enabled). Same share-link
/// invalidation caveat as `rotate_reality_keypair`.
async fn regenerate_vless_encryption_keypair(
    _user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> AppResult<Json<Inbound>> {
    let mut inbound = row_to_inbound(read_row(&state, &id).await?)?;
    // This endpoint is VLESS-specific (regenerates VLESS-encryption keys).
    // For non-VLESS inbounds reject with a clear 4xx rather than panic.
    let ProtocolConfig::Vless(ref mut vless) = inbound.protocol else {
        return Err(AppError::BadRequest(
            "this endpoint only applies to VLESS inbounds".to_owned(),
        ));
    };

    let auth = vless
        .encryption_auth
        .unwrap_or(VlessEncryptionAuth::Mlkem768);
    let kp = keygen::generate_vless_encryption_keypair(&state.xray.binary, auth)
        .map_err(AppError::Internal)?;

    vless.encryption_mode = VlessEncryptionMode::Mlkem768x25519Plus;
    vless.encryption_auth = Some(auth);
    vless
        .encryption_xor_mode
        .get_or_insert_with(VlessXorMode::default);
    vless.encryption_seconds_from.get_or_insert(600);
    vless.encryption_server_key = Some(kp.server_key);
    vless.encryption_client_key = Some(kp.client_key);

    let j = serde_json::to_string(&inbound.protocol)?;
    sqlx::query!(
        "UPDATE inbounds SET protocol_config = ?, updated_at = datetime('now') WHERE id = ?",
        j,
        id
    )
    .execute(&state.db)
    .await?;

    let after = row_to_inbound(read_row(&state, &id).await?)?;
    if after.enabled {
        let clients = load_enabled_clients(&state.db, &id).await?;
        let _ = state.xray_client.remove_inbound(&after.tag).await;
        let handler = crate::xray::orchestrator::inbound_to_handler_config(&after, &clients)
            .map_err(AppError::Internal)?;
        if let Err(e) = state.xray_client.add_inbound(handler).await {
            tracing::error!(
                "inbound {} vless-encryption regenerated in DB but xray re-add failed: {e}",
                after.tag
            );
            return Err(AppError::Internal(anyhow::anyhow!(
                "regenerated in DB but not applied to xray: {e}"
            )));
        }
    }
    Ok(Json(after))
}

// =============================================================================
// Small helpers
// =============================================================================

async fn read_row(state: &AppState, id: &str) -> AppResult<Row> {
    sqlx::query_as!(
        Row,
        r#"SELECT id, tag, enabled, listen, port,
                  protocol_config, transport_config, security_config, sniffing_config,
                  finalmask_config, sockopt_config, created_at, updated_at
           FROM inbounds WHERE id = ?"#,
        id
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or(AppError::NotFound)
}

/// Public hydration helper for sibling modules (currently `api::clients`,
/// which needs the full `Inbound` view to build share-links and push a
/// rebuilt handler after every client mutation).
pub async fn fetch_inbound(state: &AppState, id: &str) -> AppResult<Inbound> {
    row_to_inbound(read_row(state, id).await?)
}

/// Batched sibling of `fetch_inbound`. Pulls every inbound whose id is in
/// `ids` with a single `WHERE id IN (…)` SELECT and returns them keyed by
/// id. Hot-path callers (subscription bundle, bulk-assign post-commit
/// gRPC sync) used to round-trip per row — this turns `O(N)` SQL calls
/// into one. Rows that fail `row_to_inbound` hydration are silently
/// skipped; the caller's `HashMap::get` returning `None` is treated as
/// "inbound vanished" and handled the same way an explicit 404 would.
pub async fn fetch_inbounds_batch(
    state: &AppState,
    ids: &[String],
) -> AppResult<std::collections::HashMap<String, Inbound>> {
    if ids.is_empty() {
        return Ok(std::collections::HashMap::new());
    }
    let mut qb = sqlx::QueryBuilder::<sqlx::Sqlite>::new(
        "SELECT id, tag, enabled, listen, port, \
         protocol_config, transport_config, security_config, sniffing_config, \
         finalmask_config, sockopt_config, created_at, updated_at FROM inbounds WHERE id IN (",
    );
    let mut sep = qb.separated(", ");
    for id in ids {
        sep.push_bind(id);
    }
    qb.push(")");
    let rows = qb.build_query_as::<Row>().fetch_all(&state.db).await?;
    let mut out = std::collections::HashMap::with_capacity(rows.len());
    for r in rows {
        let id = r.id.clone();
        // Propagate hydration errors — silently dropping corrupt rows
        // would cascade into a misleading 404 at the caller (the
        // caller checks `len() != requested.len()` to detect missing
        // ids, and would conflate "no such inbound" with "DB blob
        // failed to parse"). Better the operator sees the real
        // `AppError::Internal` with the parse error attached.
        out.insert(id, row_to_inbound(r)?);
    }
    Ok(out)
}

/// Load the enabled clients of one inbound, mapped to `models::Client`.
///
/// Takes a bare `&DbPool` (not `&AppState`) so the startup reconciler in
/// `main` can share this single source of truth for the row→`Client`
/// mapping instead of duplicating it.
pub async fn load_enabled_clients(
    db: &crate::db::DbPool,
    inbound_id: &str,
) -> AppResult<Vec<crate::models::Client>> {
    let rows = sqlx::query!(
        r#"SELECT id, inbound_id, email, uuid, auth, flow, enabled, note,
                  traffic_limit_bytes, disabled_reason, sub_token, created_at, updated_at
           FROM clients
           WHERE inbound_id = ? AND enabled = 1
           ORDER BY created_at ASC"#,
        inbound_id
    )
    .fetch_all(db)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| crate::models::Client {
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
            sub_token: r.sub_token,
            created_at: r.created_at,
            updated_at: r.updated_at,
        })
        .collect())
}

#[cfg(test)]
mod validate_layers_tests {
    //! Truth table for `validate_layers`. The function gates create/edit
    //! at the API layer so xray never sees an invalid flow×transport×
    //! security combo.
    use super::*;
    use crate::protocols::vless::{VlessEncryptionMode, VlessFlow, VlessProtocol};
    use crate::security::NoneSecurity;
    use crate::security::reality::RealitySecurity;
    use crate::security::tls::TlsSecurity;
    use crate::transports::finalmask::{FragmentParams, SudokuParams};
    use crate::transports::tcp::TcpTransport;
    use crate::transports::ws::WsTransport;
    use crate::transports::xhttp::XhttpTransport;

    /// Default finalmask for tests that don't care about it. Kept as a
    /// helper so adding a 5th parameter to `validate_layers` is a one-line
    /// edit instead of touching every existing assertion.
    fn vl(p: &ProtocolConfig, t: &TransportConfig, s: &SecurityConfig) -> AppResult<()> {
        validate_layers(p, t, s, &FinalMask::None)
    }

    fn vless(flow: VlessFlow) -> ProtocolConfig {
        ProtocolConfig::Vless(VlessProtocol {
            flow,
            encryption_mode: VlessEncryptionMode::None,
            ..VlessProtocol::default()
        })
    }

    fn reality_ok() -> SecurityConfig {
        SecurityConfig::Reality(RealitySecurity {
            dest: "www.cloudflare.com:443".into(),
            server_names: vec!["www.cloudflare.com".into()],
            short_ids: vec!["aabb1122".into()],
            fingerprint: "chrome".into(),
            ..RealitySecurity::default()
        })
    }

    #[test]
    fn tcp_none_none_ok() {
        vl(
            &vless(VlessFlow::None),
            &TransportConfig::Tcp(TcpTransport {}),
            &SecurityConfig::None(NoneSecurity {}),
        )
        .unwrap();
    }

    #[test]
    fn tcp_vision_reality_ok_canonical_combo() {
        vl(
            &vless(VlessFlow::XtlsRprxVision),
            &TransportConfig::Tcp(TcpTransport {}),
            &reality_ok(),
        )
        .unwrap();
    }

    #[test]
    fn xhttp_vision_err_vision_is_tcp_only() {
        let err = vl(
            &vless(VlessFlow::XtlsRprxVision),
            &TransportConfig::Xhttp(XhttpTransport::default()),
            &SecurityConfig::None(NoneSecurity {}),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("xtls-rprx-vision"), "got: {err}");
        assert!(err.contains("TCP"), "got: {err}");
    }

    #[test]
    fn ws_reality_err_reality_no_ws() {
        let err = vl(
            &vless(VlessFlow::None),
            &TransportConfig::Ws(WsTransport::default()),
            &reality_ok(),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("Reality"), "got: {err}");
        assert!(err.contains("WebSocket"), "got: {err}");
    }

    #[test]
    fn ws_tls_ok_typical_cdn_combo() {
        vl(
            &vless(VlessFlow::None),
            &TransportConfig::Ws(WsTransport::default()),
            &SecurityConfig::Tls(TlsSecurity::default()),
        )
        .unwrap();
    }

    #[test]
    fn reality_empty_dest_err() {
        let mut r = reality_ok();
        if let SecurityConfig::Reality(ref mut inner) = r {
            inner.dest = String::new();
        }
        let err = vl(
            &vless(VlessFlow::None),
            &TransportConfig::Tcp(TcpTransport {}),
            &r,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("dest"), "got: {err}");
    }

    #[test]
    fn reality_empty_server_names_err() {
        let mut r = reality_ok();
        if let SecurityConfig::Reality(ref mut inner) = r {
            inner.server_names.clear();
        }
        let err = vl(
            &vless(VlessFlow::None),
            &TransportConfig::Tcp(TcpTransport {}),
            &r,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("server_names"), "got: {err}");
    }

    /// Regression for the xray-core panic
    /// `*fragment.fragmentConn is not reality.CloseWriteConn` triggered by
    /// running Reality on top of a TCP-side `FinalMask` wrapper. Sudoku has
    /// the same shape and must be rejected too; Noise is UDP-only so it
    /// stays allowed alongside TCP Reality.
    #[test]
    fn reality_with_fragment_err_xray_panic_combo() {
        let err = validate_layers(
            &vless(VlessFlow::None),
            &TransportConfig::Tcp(TcpTransport {}),
            &reality_ok(),
            &FinalMask::Fragment(FragmentParams::default()),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("Reality"), "got: {err}");
        assert!(err.contains("Fragment"), "got: {err}");
    }

    // ---- VLESS fallbacks validation -------------------------------------
    //
    // Mirrors what `infra/conf/vless.go` enforces server-side. We catch
    // these at the panel boundary so the operator sees a clean 400 instead
    // of xray refusing to start with a cryptic Go error on the next reload.

    use crate::protocols::vless::{VlessFallback, VlessFallbackType};

    fn vless_with_fallbacks(fallbacks: Vec<VlessFallback>) -> ProtocolConfig {
        ProtocolConfig::Vless(VlessProtocol {
            flow: VlessFlow::None,
            encryption_mode: VlessEncryptionMode::None,
            fallbacks,
            ..VlessProtocol::default()
        })
    }

    fn fb_minimal() -> VlessFallback {
        VlessFallback {
            dest: "127.0.0.1:8080".into(),
            kind: VlessFallbackType::Tcp,
            ..VlessFallback::default()
        }
    }

    #[test]
    fn fallbacks_with_encryption_err_xray_mutual_exclusion() {
        let mut p = vless_with_fallbacks(vec![fb_minimal()]);
        if let ProtocolConfig::Vless(v) = &mut p {
            v.encryption_mode = VlessEncryptionMode::Mlkem768x25519Plus;
        }
        let err = vl(
            &p,
            &TransportConfig::Tcp(TcpTransport {}),
            &SecurityConfig::None(NoneSecurity {}),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("fallbacks"), "got: {err}");
        assert!(err.contains("Encryption"), "got: {err}");
    }

    #[test]
    fn fallbacks_on_ws_err_tcp_only() {
        let err = vl(
            &vless_with_fallbacks(vec![fb_minimal()]),
            &TransportConfig::Ws(WsTransport::default()),
            &SecurityConfig::Tls(TlsSecurity::default()),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("fallbacks"), "got: {err}");
        assert!(err.contains("TCP"), "got: {err}");
    }

    #[test]
    fn fallbacks_empty_dest_err() {
        let mut fb = fb_minimal();
        fb.dest = "   ".into();
        let err = vl(
            &vless_with_fallbacks(vec![fb]),
            &TransportConfig::Tcp(TcpTransport {}),
            &SecurityConfig::None(NoneSecurity {}),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("dest"), "got: {err}");
    }

    #[test]
    fn fallbacks_path_without_leading_slash_err() {
        let mut fb = fb_minimal();
        fb.path = "fallback".into();
        let err = vl(
            &vless_with_fallbacks(vec![fb]),
            &TransportConfig::Tcp(TcpTransport {}),
            &SecurityConfig::None(NoneSecurity {}),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("path"), "got: {err}");
    }

    #[test]
    fn fallbacks_xver_above_2_err() {
        let mut fb = fb_minimal();
        fb.xver = 3;
        let err = vl(
            &vless_with_fallbacks(vec![fb]),
            &TransportConfig::Tcp(TcpTransport {}),
            &SecurityConfig::None(NoneSecurity {}),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("xver"), "got: {err}");
    }

    #[test]
    fn fallbacks_tcp_no_encryption_ok() {
        let mut fb = fb_minimal();
        fb.path = "/fallback".into();
        fb.xver = 2;
        vl(
            &vless_with_fallbacks(vec![fb]),
            &TransportConfig::Tcp(TcpTransport {}),
            &SecurityConfig::Tls(TlsSecurity::default()),
        )
        .unwrap();
    }

    #[test]
    fn reality_with_sudoku_err_same_root_cause() {
        let err = validate_layers(
            &vless(VlessFlow::None),
            &TransportConfig::Tcp(TcpTransport {}),
            &reality_ok(),
            &FinalMask::Sudoku(SudokuParams::default()),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("Reality"), "got: {err}");
        assert!(err.contains("Sudoku"), "got: {err}");
    }

    #[test]
    fn reality_with_none_finalmask_ok() {
        validate_layers(
            &vless(VlessFlow::None),
            &TransportConfig::Tcp(TcpTransport {}),
            &reality_ok(),
            &FinalMask::None,
        )
        .unwrap();
    }

    // Hysteria 2 cross-layer rules. Force-paired with hysteria transport,
    // TLS-only — every other combo must 4xx at the validator.
    use crate::protocols::hysteria::HysteriaProtocol;
    use crate::transports::hysteria::{HysteriaMasquerade, HysteriaTransport};

    fn hysteria2() -> ProtocolConfig {
        ProtocolConfig::Hysteria2(HysteriaProtocol {})
    }
    fn hysteria_transport() -> TransportConfig {
        TransportConfig::Hysteria(HysteriaTransport {
            auth: None,
            udp_idle_timeout: None,
            masquerade: HysteriaMasquerade::NotFound,
            quic_params: None,
        })
    }

    #[test]
    fn hysteria_with_tls_ok() {
        vl(
            &hysteria2(),
            &hysteria_transport(),
            &SecurityConfig::Tls(TlsSecurity::default()),
        )
        .unwrap();
    }

    #[test]
    fn hysteria_proto_with_tcp_transport_err() {
        let err = vl(
            &hysteria2(),
            &TransportConfig::Tcp(TcpTransport {}),
            &SecurityConfig::Tls(TlsSecurity::default()),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("Hysteria"), "got: {err}");
    }

    #[test]
    fn vless_proto_with_hysteria_transport_err() {
        let err = vl(
            &vless(VlessFlow::None),
            &hysteria_transport(),
            &SecurityConfig::Tls(TlsSecurity::default()),
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("VLESS") && err.contains("hysteria"),
            "got: {err}"
        );
    }

    #[test]
    fn hysteria_with_reality_err() {
        let err = vl(&hysteria2(), &hysteria_transport(), &reality_ok())
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("Hysteria 2") && err.contains("reality"),
            "got: {err}"
        );
    }

    #[test]
    fn hysteria_with_none_security_err() {
        let err = vl(
            &hysteria2(),
            &hysteria_transport(),
            &SecurityConfig::None(NoneSecurity {}),
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("Hysteria 2") && err.contains("none"),
            "got: {err}"
        );
    }
}
