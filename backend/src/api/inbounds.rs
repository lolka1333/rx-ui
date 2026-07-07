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
    transports::{TransportConfig, finalmask::FinalMask, xhttp::XhttpMode},
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
    // Legacy single-item Noise blobs fold into the current `items[]` shape
    // automatically on deserialize (see `NoiseParams` / `NoiseParamsRepr`).
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

/// `FinalMask` cross-checks against the chosen security layer. Split out of
/// `validate_layers` to keep that function readable.
fn validate_finalmask(security: &SecurityConfig, finalmask: &FinalMask) -> AppResult<()> {
    // Reality wraps the raw TCP socket and type-asserts the underlying conn
    // implements `CloseWriteConn`. Sudoku's TCP wrapper doesn't — and, being
    // a symmetric stateful cipher, it MUST run server-side — so Sudoku+Reality
    // panics xray on the first handshake (`is not reality.CloseWriteConn`).
    // Fragment is asymmetric (client-only via `fm=`, never wrapped
    // server-side — see orchestrator), so Fragment+Reality is safe. Noise is
    // UDP-only and never touches the TCP socket.
    if matches!(security, SecurityConfig::Reality(_)) && matches!(finalmask, FinalMask::Sudoku(_)) {
        return Err(AppError::BadRequest(
            "Reality is incompatible with Sudoku FinalMask: Sudoku must run \
             server-side and Reality can't wrap its socket (xray-core panics). \
             Use Fragment (client-side, Reality-safe) or Noise, or switch \
             security to TLS / none."
                .to_owned(),
        ));
    }

    // xray's FragmentMask.Build rejects a final `lengths` entry whose min is
    // 0 ("last lengths entry min can't be 0"). An active Fragment mask whose
    // last length range starts at 0 ships a config the client's xray refuses,
    // so the user simply can't connect — reject it at the panel instead.
    if let FinalMask::Fragment(p) = finalmask
        && finalmask.is_active()
    {
        if p.lengths_min.last().copied().unwrap_or(0) < 1 {
            return Err(AppError::BadRequest(
                "Fragment FinalMask needs a chunk length of at least 1 byte — \
                 xray rejects a zero min on the last length range. Set the last \
                 length min to 1 or more."
                    .to_owned(),
            ));
        }
        // The share-link zips the min/max lists into "min-max" pairs, so lists
        // of different lengths would silently drop ranges; an inverted min > max
        // range is a config error too. The form guarantees neither, but a direct
        // API call could send them — reject both here.
        if p.lengths_min.len() != p.lengths_max.len() || p.delays_min.len() != p.delays_max.len() {
            return Err(AppError::BadRequest(
                "Fragment length/delay ranges are malformed — each range needs \
                 both a min and a max."
                    .to_owned(),
            ));
        }
        if p.lengths_min
            .iter()
            .zip(&p.lengths_max)
            .any(|(mn, mx)| mn > mx)
            || p.delays_min
                .iter()
                .zip(&p.delays_max)
                .any(|(mn, mx)| mn > mx)
        {
            return Err(AppError::BadRequest(
                "Fragment range min must be ≤ max.".to_owned(),
            ));
        }
    }

    // Noise per-item invariants (literal-XOR-rand, decodable literal, bounded
    // rand/delay/reset). Shared with the outbound write path so the same xray
    // process can't be crashed from either — see `FinalMask::validate_noise`.
    finalmask.validate_noise().map_err(AppError::BadRequest)?;

    Ok(())
}

/// Cross-layer compatibility checks. xray would reject most of these
/// at `AddInbound` time anyway; doing them up front keeps the panel
/// and xray from drifting if the gRPC call fails between INSERT and
/// `AddInbound`.
/// Reject the XHTTP uplink knobs xray's JSON conf permits only in packet-up
/// mode (cookie/header uplink-data placement, a GET uplink method). The panel
/// builds the server via proto, which skips that check, so the inbound would
/// "work" while any client — which parses the share link through infra/conf —
/// refuses to start. Reject the invalid combo at the source instead.
fn validate_xhttp_mode(transport: &TransportConfig) -> AppResult<()> {
    let TransportConfig::Xhttp(x) = transport else {
        return Ok(());
    };
    if x.mode == Some(XhttpMode::PacketUp) {
        return Ok(());
    }
    if matches!(
        x.uplink_data_placement.as_deref().map(str::trim),
        Some("cookie" | "header")
    ) {
        return Err(AppError::BadRequest(
            "XHTTP uplink-data placement 'cookie'/'header' requires packet-up mode".to_owned(),
        ));
    }
    if x.uplink_http_method
        .as_deref()
        .is_some_and(|m| m.trim().eq_ignore_ascii_case("GET"))
    {
        return Err(AppError::BadRequest(
            "XHTTP uplinkHTTPMethod 'GET' requires packet-up mode".to_owned(),
        ));
    }
    Ok(())
}

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

    // XHTTP uplink knobs xray's JSON conf accepts only in packet-up mode; the
    // proto build path skips that check, so guard it here (grouped in the
    // helper to keep this function readable).
    validate_xhttp_mode(transport)?;

    // FinalMask compatibility with the security layer (Reality panics on
    // Sudoku; zero-length fragment) — grouped in `validate_finalmask`.
    validate_finalmask(security, finalmask)?;

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
/// the operator sends a structurally complete payload; these key fields are
/// finalised here so the stored material is always self-consistent:
///   * Reality x25519 keypair — the public half is re-derived from the
///     (body-carried) private the frontend sent, or a fresh pair is
///     generated if none was supplied. The public always matches the
///     private, so a hand-crafted request can't paste a mismatched pair.
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
        // Reality x25519 keypair. The frontend pre-generates one (body-carried,
        // like VLESS Encryption) so the operator sees the public key right on
        // the create form; keep that private half but always re-derive the
        // public from it, so a hand-crafted request can't ship a mismatched
        // pair. With no private supplied (older API clients), generate fresh.
        if r.private_key.is_empty() {
            let kp = keygen::generate_reality_keypair();
            r.private_key = kp.private_key;
            r.public_key = kp.public_key;
        } else {
            r.public_key = keygen::derive_reality_public_key(&r.private_key)
                .map_err(|e| AppError::BadRequest(format!("reality private_key: {e}")))?;
        }
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
    // Reject bad sniffing exclusions (e.g. a malformed CIDR) before the
    // INSERT so a conversion failure can't leave a half-created row.
    crate::xray::orchestrator::validate_sniffing(&sniffing)
        .map_err(|e| AppError::BadRequest(e.to_string()))?;

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
    let next_sniffing = body.sniffing.as_ref().unwrap_or(&before.sniffing);
    crate::xray::orchestrator::validate_sniffing(next_sniffing)
        .map_err(|e| AppError::BadRequest(e.to_string()))?;

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
        // Reality's x25519 keypair is server-managed — the frontend never
        // holds the private key, so it submits it blank on every update.
        // Writing that blank straight through wipes the stored keypair and
        // leaves the inbound unbuildable ("x25519 key must decode to 32
        // bytes, got 0"). Carry the existing keypair forward when the
        // incoming private key is empty; an explicit rotate uses its own
        // endpoint and arrives with a real key.
        let security = preserve_reality_keypair_tx(tx, id, security).await?;
        let j = serde_json::to_string(&security)?;
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

/// Preserve the server-managed Reality x25519 keypair across an inbound
/// update. The frontend can't read the private key, so it always submits
/// it (and the derived public key) blank; without this, editing any other
/// field of a Reality inbound overwrites the stored keypair with empty
/// strings and breaks the inbound. Returns the incoming security unchanged
/// for every case except "Reality with a blank private key layered over a
/// stored Reality keypair", where it lifts the existing keypair across.
async fn preserve_reality_keypair_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    id: &str,
    incoming: &crate::security::SecurityConfig,
) -> AppResult<crate::security::SecurityConfig> {
    use crate::security::SecurityConfig;
    let SecurityConfig::Reality(new) = incoming else {
        return Ok(incoming.clone());
    };
    if !new.private_key.is_empty() {
        return Ok(incoming.clone());
    }
    let Some(row) = sqlx::query!("SELECT security_config FROM inbounds WHERE id = ?", id)
        .fetch_optional(&mut **tx)
        .await?
    else {
        return Ok(incoming.clone());
    };
    let Ok(SecurityConfig::Reality(old)) =
        serde_json::from_str::<SecurityConfig>(&row.security_config)
    else {
        return Ok(incoming.clone());
    };
    if old.private_key.is_empty() {
        return Ok(incoming.clone());
    }
    let mut merged = new.clone();
    merged.private_key = old.private_key;
    merged.public_key = old.public_key;
    Ok(SecurityConfig::Reality(merged))
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
        reapply_inbound_to_xray(&state, &after, "reality key rotated").await?;
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
        reapply_inbound_to_xray(&state, &after, "vless-encryption regenerated").await?;
    }
    Ok(Json(after))
}

// =============================================================================
// Small helpers
// =============================================================================

/// Re-push an inbound to xray after an in-place key change (Reality / VLESS-
/// encryption rotation): drop the old handler and re-add it with the current
/// enabled clients. `what` names the change for the log / error text. Callers
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
    use crate::transports::finalmask::{FragmentParams, NoiseItem, NoiseParams, SudokuParams};
    use crate::transports::tcp::TcpTransport;
    use crate::transports::ws::WsTransport;
    use crate::transports::xhttp::{XhttpMode, XhttpTransport};

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

    fn noise(items: Vec<NoiseItem>) -> FinalMask {
        FinalMask::Noise(NoiseParams {
            items,
            ..NoiseParams::default()
        })
    }

    #[test]
    fn noise_negative_rand_rejected() {
        // Reachable only via a direct API body (the UI pins min=0); a negative
        // rand would panic xray at runtime (`make([]byte, RandBetween(neg))`).
        let err = validate_finalmask(
            &SecurityConfig::None(NoneSecurity {}),
            &noise(vec![NoiseItem {
                rand_min: Some(-5),
                rand_max: Some(8),
                ..NoiseItem::default()
            }]),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("random length must be between"), "got: {err}");
    }

    #[test]
    fn noise_oversized_rand_rejected() {
        let err = validate_finalmask(
            &SecurityConfig::None(NoneSecurity {}),
            &noise(vec![NoiseItem {
                rand_max: Some(5_000_000_000),
                ..NoiseItem::default()
            }]),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("random length must be between"), "got: {err}");
    }

    #[test]
    fn noise_literal_plus_rand_accepted_packet_wins() {
        // A literal + a stray rand is NOT rejected — it's the old UI's normal
        // output and the default literal flow. "Packet wins" is applied at
        // build time (rand zeroed), matching the tooltip; a hard 400 here would
        // block editing legacy inbounds and the default literal flow.
        validate_finalmask(
            &SecurityConfig::None(NoneSecurity {}),
            &noise(vec![NoiseItem {
                packet_hex: "dead".into(),
                rand_min: Some(5),
                rand_max: Some(10),
                ..NoiseItem::default()
            }]),
        )
        .unwrap();
    }

    #[test]
    fn noise_undecodable_literal_rejected() {
        // Odd-length / separator-only literals decode to junk or empty — the
        // operator gets an error, not a silent no-op mask.
        for bad in ["abc", "a", ",", "zz"] {
            let err = validate_finalmask(
                &SecurityConfig::None(NoneSecurity {}),
                &noise(vec![NoiseItem {
                    packet_hex: bad.into(),
                    ..NoiseItem::default()
                }]),
            )
            .unwrap_err()
            .to_string();
            assert!(err.contains("literal packet"), "input {bad:?} got: {err}");
        }
    }

    #[test]
    fn noise_in_range_ok() {
        validate_finalmask(
            &SecurityConfig::None(NoneSecurity {}),
            &noise(vec![NoiseItem {
                rand_min: Some(5),
                rand_max: Some(10),
                delay_min: Some(0),
                delay_max: Some(65_535),
                ..NoiseItem::default()
            }]),
        )
        .unwrap();
        // A clean literal with separators is accepted.
        validate_finalmask(
            &SecurityConfig::None(NoneSecurity {}),
            &noise(vec![NoiseItem {
                packet_hex: "de:ad be,ef".into(),
                ..NoiseItem::default()
            }]),
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
    fn xhttp_get_method_outside_packet_up_err() {
        // Case-insensitive: xray uppercases before the check.
        let err = vl(
            &vless(VlessFlow::None),
            &TransportConfig::Xhttp(XhttpTransport {
                uplink_http_method: Some("get".into()),
                ..XhttpTransport::default()
            }),
            &SecurityConfig::None(NoneSecurity {}),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("uplinkHTTPMethod"), "got: {err}");
        assert!(err.contains("packet-up"), "got: {err}");
    }

    #[test]
    fn xhttp_cookie_uplink_outside_packet_up_err() {
        let err = vl(
            &vless(VlessFlow::None),
            &TransportConfig::Xhttp(XhttpTransport {
                uplink_data_placement: Some("cookie".into()),
                ..XhttpTransport::default()
            }),
            &SecurityConfig::None(NoneSecurity {}),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("uplink-data placement"), "got: {err}");
    }

    #[test]
    fn xhttp_packet_up_allows_uplink_knobs() {
        vl(
            &vless(VlessFlow::None),
            &TransportConfig::Xhttp(XhttpTransport {
                mode: Some(XhttpMode::PacketUp),
                uplink_http_method: Some("GET".into()),
                uplink_data_placement: Some("cookie".into()),
                ..XhttpTransport::default()
            }),
            &SecurityConfig::None(NoneSecurity {}),
        )
        .unwrap();
    }

    #[test]
    fn xhttp_post_body_ok_in_any_mode() {
        // POST + body/auto placement carry no mode restriction.
        vl(
            &vless(VlessFlow::None),
            &TransportConfig::Xhttp(XhttpTransport {
                mode: Some(XhttpMode::StreamUp),
                uplink_http_method: Some("POST".into()),
                uplink_data_placement: Some("body".into()),
                ..XhttpTransport::default()
            }),
            &SecurityConfig::None(NoneSecurity {}),
        )
        .unwrap();
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

    /// Sudoku is a symmetric, stateful cipher that must run server-side, and
    /// Reality can't wrap its TCP conn — xray panics
    /// `*sudoku... is not reality.CloseWriteConn`. So Sudoku+Reality stays
    /// rejected.
    #[test]
    fn reality_with_sudoku_err_xray_panic_combo() {
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

    /// Fragment is asymmetric — the panel ships it to the client via `fm=` and
    /// never wraps the server socket with it (orchestrator skips its tcpmask),
    /// so it no longer panics under Reality and must be ACCEPTED. This is the
    /// combo that used to be rejected here.
    #[test]
    fn reality_with_fragment_ok() {
        validate_layers(
            &vless(VlessFlow::None),
            &TransportConfig::Tcp(TcpTransport {}),
            &reality_ok(),
            &FinalMask::Fragment(FragmentParams {
                packets_from: Some(0),
                packets_to: Some(1),
                lengths_min: vec![40],
                lengths_max: vec![80],
                ..FragmentParams::default()
            }),
        )
        .expect("Fragment + Reality must be allowed (Fragment is client-only)");
    }

    /// xray rejects `LengthMin` == 0; the panel must reject an active Fragment
    /// mask with a zero/empty min length before it ships a broken fm=.
    #[test]
    fn fragment_zero_length_rejected() {
        let err = validate_layers(
            &vless(VlessFlow::None),
            &TransportConfig::Tcp(TcpTransport {}),
            &reality_ok(),
            &FinalMask::Fragment(FragmentParams {
                packets_from: Some(0),
                packets_to: Some(1),
                // last length min is 0, max set → the mask is active but
                // ships lengths ["0-80"], which xray would reject.
                lengths_min: vec![0],
                lengths_max: vec![80],
                ..FragmentParams::default()
            }),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("length"), "got: {err}");
    }

    /// A range whose min exceeds its max ("200-100") is a config error; the
    /// panel rejects it instead of shipping an inverted range to xray.
    #[test]
    fn fragment_inverted_range_rejected() {
        let err = validate_layers(
            &vless(VlessFlow::None),
            &TransportConfig::Tcp(TcpTransport {}),
            &reality_ok(),
            &FinalMask::Fragment(FragmentParams {
                packets_from: Some(0),
                packets_to: Some(1),
                lengths_min: vec![200],
                lengths_max: vec![100],
                ..FragmentParams::default()
            }),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("min must be"), "got: {err}");
    }

    /// Mismatched min/max list lengths would silently truncate via the
    /// share-link zip; the panel rejects the malformed config up front.
    #[test]
    fn fragment_mismatched_range_lists_rejected() {
        let err = validate_layers(
            &vless(VlessFlow::None),
            &TransportConfig::Tcp(TcpTransport {}),
            &reality_ok(),
            &FinalMask::Fragment(FragmentParams {
                packets_from: Some(0),
                packets_to: Some(1),
                lengths_min: vec![40, 90],
                lengths_max: vec![80],
                ..FragmentParams::default()
            }),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("malformed"), "got: {err}");
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
