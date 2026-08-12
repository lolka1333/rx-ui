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
//!   * `security=Reality + finalmask=Sudoku` — Sudoku must run server-side
//!     and Reality can't wrap its socket (xray-core panics).
//!   * `FinalMask` invariants: Fragment ranges (`min <= max`) and the Noise
//!     per-item rules, shared with the outbound write path so neither can
//!     crash the same xray process.
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
    transports::{
        TransportConfig,
        finalmask::{FinalMask, FinalMaskScope},
        xhttp::XhttpMode,
    },
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
        .route("/stats", get(stats))
        .route("/finalmask-support", get(finalmask_support))
        .route("/{id}", get(get_one).patch(update).delete(delete))
        .route("/{id}/rotate-reality-keypair", post(rotate_reality_keypair))
        .route(
            "/{id}/regenerate-vless-encryption-keypair",
            post(regenerate_vless_encryption_keypair),
        )
}

/// Per-inbound lifetime traffic (`tag -> {uplink, downlink}`). Cumulative
/// totals persisted by the [`crate::inbound_traffic`] poller — they survive
/// xray restarts, unlike the session-only counters xray exposes directly, and
/// give an accurate per-inbound split even when one client spans several
/// inbounds (xray's per-user counters can't attribute those bytes per-inbound).
#[derive(Debug, Default, serde::Serialize, ts_rs::TS)]
#[ts(export, export_to = "../../frontend/src/api/types/inbound.ts")]
pub struct InboundTraffic {
    #[ts(type = "number")]
    pub uplink: u64,
    #[ts(type = "number")]
    pub downlink: u64,
    /// True when this inbound moved bytes on the last poll tick (~5 s) — drives
    /// the Inbounds page's live-activity glow. Accurate per inbound (computed
    /// from the poller's per-tag deltas), so it follows a client that hops
    /// between inbounds instead of sticking to the first. xray only reports the
    /// rate per email, which is why the front end used to approximate this and
    /// glued the glow to the first inbound a shared email belonged to.
    pub live: bool,
}

async fn stats(
    _user: AuthUser,
    State(state): State<AppState>,
) -> AppResult<Json<std::collections::HashMap<String, InboundTraffic>>> {
    let rows = sqlx::query!(
        r#"SELECT tag            AS "tag!: String",
                  uplink_total   AS "uplink_total!: i64",
                  downlink_total AS "downlink_total!: i64"
           FROM inbound_traffic"#
    )
    .fetch_all(&state.db)
    .await?;
    // Live-activity set for this instant (tags that moved bytes last tick). Read
    // once under a short lock, then looked up per row.
    let live = state.inbound_live.snapshot().await;
    #[allow(clippy::cast_sign_loss)]
    let out = rows
        .into_iter()
        .map(|r| {
            let is_live = live.contains(&r.tag);
            (
                r.tag,
                InboundTraffic {
                    uplink: r.uplink_total.max(0) as u64,
                    downlink: r.downlink_total.max(0) as u64,
                    live: is_live,
                },
            )
        })
        .collect();
    Ok(Json(out))
}

// =============================================================================
// Row mapping
// =============================================================================

/// One `inbounds` row, still JSON-encoded. `row_to_inbound` is the only
/// intended consumer; `tag` is public because the reconciler logs by it.
#[derive(sqlx::FromRow)]
pub struct Row {
    id: String,
    pub tag: String,
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

/// Every enabled inbound, as raw rows. Shared with the boot reconciler so the
/// column list lives in one place.
pub async fn load_enabled_inbound_rows(db: &crate::db::DbPool) -> AppResult<Vec<Row>> {
    // `query_as!`, like `read_row` below: the macro checks the column list and
    // the types against the schema at compile time. The runtime form would
    // turn a renamed column into a 500 at boot instead of a build error.
    Ok(sqlx::query_as!(
        Row,
        r#"SELECT id, tag, enabled, listen, port,
                  protocol_config, transport_config, security_config, sniffing_config,
                  finalmask_config, sockopt_config, created_at, updated_at
           FROM inbounds WHERE enabled = 1"#
    )
    .fetch_all(db)
    .await?)
}

/// Decode one DB row into the public `Inbound`. Each JSON column maps
/// directly into the corresponding tagged-enum field via `serde_json`.
/// A malformed blob in any layer is surfaced as a 500 — the JSON is
/// always written by this same code, so a parse failure means DB
/// corruption or an aborted backfill, not user error.
pub fn row_to_inbound(r: Row) -> AppResult<Inbound> {
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

/// `FinalMask` cross-checks against the transport and the security layer.
/// Split out of `validate_layers` to keep that function readable, and shared
/// with `api::outbounds`: both write paths feed the SAME xray process, so a
/// combination that is inert or fatal on one side is inert or fatal on the
/// other. The caller supplies its own error prefix.
pub fn validate_finalmask(
    transport: &TransportConfig,
    security: &SecurityConfig,
    finalmask: &FinalMask,
    check_matrix: bool,
) -> AppResult<()> {
    // A mask outside the matrix is not an error in xray — it builds, the
    // inbound starts, and the mask never runs, because the transport only ever
    // consults the other registry. Refusing it here is the difference between
    // "obfuscation you don't have" and "obfuscation you think you have".
    //
    // `check_matrix` is off when the caller is carrying a stored mask forward
    // untouched. Rows predating this rule exist (the form used to offer all
    // five masks on every transport), and refusing them unconditionally would
    // mean a PATCH of `{enabled: false}` gets a 400 about a mask the operator
    // can no longer even see in the dropdown — an inbound that is live and
    // unmanageable. A mask that silently does nothing is cosmetic; a mask the
    // operator is actively choosing is not, and that is the case this guards.
    // The gates below are NOT conditional: they cover crashes, not cosmetics.
    //
    // Judged by `is_configured`, not `is_active`: XMC's keys are derived after
    // this runs on the create path, so `is_active` is false there for every
    // freshly submitted XMC mask and the whole check would be dead for it.
    if check_matrix && finalmask.is_configured() {
        let allowed = crate::transports::finalmask::supported_kinds(
            transport.as_transport().kind(),
            security.as_security().kind(),
        );
        if !allowed.contains(&finalmask.kind()) {
            return Err(AppError::BadRequest(format!(
                "FinalMask '{}' does not work with transport '{}' and security \
                 '{}' — xray would build it and never apply it. Supported here: {}.",
                finalmask.kind(),
                transport.as_transport().kind().as_db_str(),
                security.as_security().kind().as_db_str(),
                if allowed.is_empty() {
                    "none".to_owned()
                } else {
                    allowed.join(", ")
                },
            )));
        }
    }

    // Same trap one level down. XHTTP negotiating HTTP/3 is QUIC underneath:
    // the listener gates the wrapper on `!l.isH3` (`splithttp/hub.go:540`) and
    // the dialer goes through `http3.Transport`, which never calls the
    // masking dialer at all. `isH3` is decided by ALPN being exactly `h3` —
    // compared the same way the core compares it, so `["h3","h3"]` (which the
    // core runs over HTTP/2) is not falsely rejected here.
    //
    // Gated by scope rather than by variant: this catches every mask that
    // lives only in the TCP registry — XMC and Fragment today. Sudoku is
    // registered in the UDP one as well and keeps masking over h3. Same
    // severity as the matrix above (silently inert, not fatal), so it carries
    // the same `check_matrix` escape for stored values.
    if check_matrix
        && finalmask.is_configured()
        && matches!(
            finalmask.scope(),
            FinalMaskScope::Tcp | FinalMaskScope::TcpClientOnly
        )
        && matches!(transport, TransportConfig::Xhttp(_))
        && let SecurityConfig::Tls(tls) = security
        && tls.alpn.as_deref().is_some_and(|a| a == ["h3"])
    {
        return Err(AppError::BadRequest(format!(
            "FinalMask '{}' cannot be used with XHTTP over HTTP/3: with ALPN \
             set to h3 only, xray runs the QUIC path and skips TCP masks on \
             both ends. Add h2 / http1.1 to ALPN, or choose another transport.",
            finalmask.kind(),
        )));
    }

    validate_finalmask_security(security, finalmask)
}

fn validate_finalmask_security(security: &SecurityConfig, finalmask: &FinalMask) -> AppResult<()> {
    // Reality wraps the raw TCP socket and type-asserts the underlying conn to
    // `CloseWriteConn` WITHOUT checking (xtls/reality `tls.go:186`), so a
    // server-side mask that lacks `CloseWrite` panics the accept goroutine —
    // which `tcp/hub.go:116` starts with no recover, taking the whole xray
    // process down on the first connection.
    //
    // `xmc.serverConn` has Read/Write/Close/addrs/deadlines and nothing else.
    // Verified rather than reasoned: a vless+reality inbound carrying an XMC
    // mask, one TCP connection, and xray was gone —
    //   panic: interface conversion: *xmc.serverConn is not
    //          reality.CloseWriteConn: missing method CloseWrite
    //
    // Sudoku used to be refused here for the same stated reason. That reason
    // was wrong: `sudoku.wrappedConn` has implemented `CloseWrite` since the
    // commit that introduced it, and the same experiment (reality + sudoku,
    // four connections) left the process running with a clean log. The block
    // denied a working combination, so it is gone.
    //
    // Fragment never runs server-side at all (client-only, via `fm=` — see the
    // orchestrator), and Noise is UDP-only, so neither ever meets Reality.
    if matches!(security, SecurityConfig::Reality(_)) && matches!(finalmask, FinalMask::Xmc(_)) {
        return Err(AppError::BadRequest(
            "Reality is incompatible with XMC FinalMask: XMC must run \
             server-side and Reality can't wrap its socket (xray-core panics). \
             Switch security to TLS / none, or pick another mask."
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

    // XMC profile/password invariants, mirrored from xray's own conf parser so
    // the operator gets a field-level message instead of an inbound that comes
    // up and then drops every connection.
    if let FinalMask::Xmc(p) = finalmask {
        p.validate().map_err(AppError::BadRequest)?;
    }

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

/// `check_matrix` decides whether the transport×mask matrix applies. See
/// `validate_finalmask` — it is off when a stored mask is being carried
/// forward untouched, so a legacy row stays editable.
fn validate_layers(
    protocol: &ProtocolConfig,
    transport: &TransportConfig,
    security: &SecurityConfig,
    finalmask: &FinalMask,
    check_matrix: bool,
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

    // FinalMask compatibility with the transport and the security layer
    // (Reality panics on Sudoku/XMC; XMC needs a TCP path; zero-length
    // fragment) — grouped in `validate_finalmask`.
    validate_finalmask(transport, security, finalmask, check_matrix)?;

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
async fn complete_server_managed_fields(
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
                .await
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
    Json(serde_json::Value::Object(out))
}

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

/// Reject inbound tags that collide with reserved internal tags. The only
/// reserved inbound tag is the gRPC control channel's (`API_TAG`): a user
/// inbound claiming it fails xray's duplicate-tag check and, worse, a later
/// remove/re-add tears down the panel's own control inbound. Mirrors the
/// reserved-tag guard `api::outbounds` runs for outbound tags, and makes the
/// per-inbound traffic poller's `api`-skip invariant actually hold.
fn validate_inbound_tag(tag: &str) -> AppResult<()> {
    if tag == crate::xray::config_gen::API_TAG {
        return Err(AppError::BadRequest(format!(
            "inbound tag '{tag}' is reserved for the internal control channel"
        )));
    }
    Ok(())
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
    validate_layers(&protocol, &transport, &security, &finalmask, true)?;
    ensure_port_free(&state.db, port, None).await?;
    complete_server_managed_fields(&state, &mut protocol, &mut security).await?;
    // A derivation failure is the server's problem (missing binary, a core too
    // old to know `xmc`, a wedged `convert pb`), not bad input — and `Internal`
    // now renders its whole cause chain, so the operator sees what xray said.
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
    let next_protocol = body.protocol.as_ref().unwrap_or(&before.protocol);
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
        validate_inbound_tag(tag)?;
        // Current tag, captured before the rename so the persisted per-inbound
        // traffic total can follow it. `inbound_traffic` is keyed by tag (xray
        // counts per tag), so without the migration below the total would orphan
        // under the old tag and a later inbound reusing it would inherit these
        // bytes — the exact ghost-total misattribution this feature removes.
        let old_tag: Option<String> = sqlx::query_scalar!(
            r#"SELECT tag AS "tag!: String" FROM inbounds WHERE id = ?"#,
            id
        )
        .fetch_optional(&mut *tx)
        .await?;

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

        if let Some(old_tag) = old_tag
            && old_tag != *tag
        {
            // Drop any stale row already under the new tag (left by a previously
            // deleted inbound) before moving the old total onto it, so the
            // UPDATE can't collide with the `inbound_traffic` primary key.
            sqlx::query!("DELETE FROM inbound_traffic WHERE tag = ?", tag)
                .execute(&mut *tx)
                .await?;
            sqlx::query!(
                "UPDATE inbound_traffic SET tag = ? WHERE tag = ?",
                tag,
                old_tag
            )
            .execute(&mut *tx)
            .await?;
        }
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

/// Pure Reality keypair-preserve merge (no DB). Returns `incoming` unchanged
/// unless it is Reality with a blank `private_key` layered over a `stored`
/// Reality keypair, in which case the stored private/public keypair is lifted
/// across. Shared by `preserve_reality_keypair_tx` (write path, reads the
/// stored config inside the tx) and the `update` pre-commit validation (which
/// merges against the already re-read `before.security`) so both build the
/// exact same security.
fn preserve_reality_keypair(
    incoming: &crate::security::SecurityConfig,
    stored: &crate::security::SecurityConfig,
) -> crate::security::SecurityConfig {
    use crate::security::SecurityConfig;
    let (SecurityConfig::Reality(new), SecurityConfig::Reality(old)) = (incoming, stored) else {
        return incoming.clone();
    };
    if !new.private_key.is_empty() || old.private_key.is_empty() {
        return incoming.clone();
    }
    let mut merged = new.clone();
    merged.private_key.clone_from(&old.private_key);
    merged.public_key.clone_from(&old.public_key);
    SecurityConfig::Reality(merged)
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
    // Fast path: only a Reality PATCH with a blank private key needs the DB read.
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
    let Ok(stored) = serde_json::from_str::<SecurityConfig>(&row.security_config) else {
        return Ok(incoming.clone());
    };
    Ok(preserve_reality_keypair(incoming, &stored))
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
        .await
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
    //! Truth table for `validate_layers` (the create/edit gate that keeps xray
    //! from ever seeing an invalid flow×transport×security combo), plus the
    //! `preserve_reality_keypair` merge the update path relies on.
    use super::*;
    use crate::protocols::vless::{VlessEncryptionMode, VlessFlow, VlessProtocol};
    use crate::security::NoneSecurity;
    use crate::security::reality::RealitySecurity;
    use crate::security::tls::TlsSecurity;
    use crate::transports::finalmask::{
        FragmentParams, NoiseItem, NoiseParams, SudokuParams, XmcParams,
    };
    use crate::transports::tcp::TcpTransport;
    use crate::transports::ws::WsTransport;
    use crate::transports::xhttp::{XhttpMode, XhttpTransport};

    /// Default finalmask for tests that don't care about it. Kept as a
    /// helper so adding a 5th parameter to `validate_layers` is a one-line
    /// edit instead of touching every existing assertion.
    fn vl(p: &ProtocolConfig, t: &TransportConfig, s: &SecurityConfig) -> AppResult<()> {
        validate_layers(p, t, s, &FinalMask::None, true)
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
        let err = validate_finalmask_security(
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
        let err = validate_finalmask_security(
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
        validate_finalmask_security(
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
            let err = validate_finalmask_security(
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
        validate_finalmask_security(
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
        validate_finalmask_security(
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

    /// Reality + XMC is the combination that really does kill xray: reality
    /// type-asserts the conn to `CloseWriteConn` unchecked and `xmc.serverConn`
    /// has no `CloseWrite`, so the accept goroutine panics with no recover.
    /// Confirmed by running it — one connection and the process was gone.
    #[test]
    fn reality_with_xmc_err_kills_xray() {
        let err = validate_layers(
            &vless(VlessFlow::None),
            &TransportConfig::Tcp(TcpTransport {}),
            &reality_ok(),
            &FinalMask::Xmc(XmcParams::default()),
            true,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("Reality"), "got: {err}");
        assert!(err.contains("XMC"), "got: {err}");
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
            true,
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
            true,
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
            true,
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
            true,
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
    /// Sudoku under Reality used to be refused on the grounds that it panics
    /// xray. It does not: `sudoku.wrappedConn` implements `CloseWrite`, and a
    /// live reality+sudoku inbound took repeated connections with a clean log.
    /// The combination is allowed, and this test is here so the old rule does
    /// not come back on the strength of the story rather than the measurement.
    fn reality_with_sudoku_ok() {
        validate_layers(
            &vless(VlessFlow::None),
            &TransportConfig::Tcp(TcpTransport {}),
            &reality_ok(),
            &FinalMask::Sudoku(SudokuParams {
                password: "probe".to_owned(),
                ..SudokuParams::default()
            }),
            true,
        )
        .unwrap();
    }

    fn tls_ok() -> SecurityConfig {
        SecurityConfig::Tls(TlsSecurity::default())
    }

    fn tls_alpn(alpn: &[&str]) -> SecurityConfig {
        SecurityConfig::Tls(TlsSecurity {
            alpn: Some(alpn.iter().map(|s| (*s).to_owned()).collect()),
            ..TlsSecurity::default()
        })
    }

    /// A profile the matrix tests can hand around without caring about it.
    fn xmc_profile() -> crate::transports::finalmask::XmcProfile {
        crate::transports::finalmask::XmcProfile {
            username: "Notch".to_owned(),
            uuid: "069a79f4-44e9-4726-a5be-fca90e38aaf5".to_owned(),
            textures_value: "dmFsdWU=".to_owned(),
            textures_signature: "c2ln".to_owned(),
        }
    }

    /// As the form sends it: password and profiles, no derived keys.
    fn xmc_from_form() -> FinalMask {
        FinalMask::Xmc(XmcParams {
            password: "probe".to_owned(),
            profiles: vec![xmc_profile()],
            ..XmcParams::default()
        })
    }

    /// The matrix has to judge a mask the way the form sends it — without the
    /// RSA keys, which are derived after validation on the create path. Gating
    /// on `is_active` instead left this check dead for every new XMC inbound,
    /// so hysteria2 + XMC returned 201 and quietly listened without the mask.
    #[test]
    fn xmc_on_hysteria_rejected_without_derived_keys() {
        let err = validate_layers(
            &hysteria2(),
            &hysteria_transport(),
            &tls_ok(),
            &xmc_from_form(),
            true,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("xmc"), "got: {err}");
    }

    /// The mirror of the case above: on TCP the same mask is in the matrix.
    #[test]
    fn xmc_on_tcp_tls_ok() {
        validate_layers(
            &vless(VlessFlow::None),
            &TransportConfig::Tcp(TcpTransport {}),
            &tls_ok(),
            &xmc_from_form(),
            true,
        )
        .unwrap();
    }

    /// A stored mask carried forward untouched skips the matrix: rows created
    /// before the rule existed must stay editable, or a `{enabled: false}`
    /// PATCH 400s about a mask the dropdown no longer even offers.
    #[test]
    fn legacy_out_of_matrix_mask_survives_an_untouched_update() {
        validate_layers(
            &hysteria2(),
            &hysteria_transport(),
            &tls_ok(),
            &xmc_from_form(),
            false,
        )
        .unwrap();
    }

    /// A blank draft (kind chosen, nothing filled in) is not a mask yet, so
    /// the matrix stays quiet about it — gating on "kind != none" instead
    /// would turn every half-open form section into a 400. Fragment shows this
    /// on its own; a blank XMC draft is stopped one step earlier, by its own
    /// field validation ("XMC needs a password").
    #[test]
    fn empty_fragment_draft_on_hysteria_passes() {
        validate_layers(
            &hysteria2(),
            &hysteria_transport(),
            &tls_ok(),
            &FinalMask::Fragment(FragmentParams::default()),
            true,
        )
        .unwrap();
    }

    /// XHTTP with ALPN exactly `h3` runs the QUIC path, where TCP-registry
    /// masks are never consulted. Fragment lives only in that registry, so it
    /// is refused there just like XMC — the gate is on the scope, not on one
    /// variant.
    #[test]
    fn fragment_on_xhttp_h3_rejected() {
        let err = validate_layers(
            &vless(VlessFlow::None),
            &TransportConfig::Xhttp(XhttpTransport {
                mode: Some(XhttpMode::Auto),
                ..XhttpTransport::default()
            }),
            &tls_alpn(&["h3"]),
            &FinalMask::Fragment(FragmentParams {
                packets_from: Some(0),
                packets_to: Some(1),
                lengths_min: vec![40],
                lengths_max: vec![80],
                ..FragmentParams::default()
            }),
            true,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("HTTP/3"), "got: {err}");
    }

    /// `["h3","h3"]` is not `["h3"]` to the core — it takes the HTTP/2 path,
    /// where the mask does run. Refusing it would be a false negative.
    #[test]
    fn duplicate_h3_alpn_is_not_h3_only() {
        validate_layers(
            &vless(VlessFlow::None),
            &TransportConfig::Xhttp(XhttpTransport {
                mode: Some(XhttpMode::Auto),
                ..XhttpTransport::default()
            }),
            &tls_alpn(&["h3", "h3"]),
            &xmc_from_form(),
            true,
        )
        .unwrap();
    }

    #[test]
    fn reality_with_none_finalmask_ok() {
        validate_layers(
            &vless(VlessFlow::None),
            &TransportConfig::Tcp(TcpTransport {}),
            &reality_ok(),
            &FinalMask::None,
            true,
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

    // === preserve_reality_keypair (update pre-commit build must see the same
    // security the write path persists) ======================================
    #[test]
    fn preserve_reality_keypair_lifts_stored_key_over_blank_patch() {
        // A Reality PATCH submits a blank private_key; the stored keypair must
        // carry forward so the update pre-commit build sees a valid key rather
        // than falsely 400ing with "x25519 key must decode to 32 bytes, got 0".
        let stored = SecurityConfig::Reality(RealitySecurity {
            private_key: "storedPrivateKey".into(),
            public_key: "storedPublicKey".into(),
            dest: "old.example.com:443".into(),
            server_names: vec!["old.example.com".into()],
            ..RealitySecurity::default()
        });
        // Operator edits only `dest`/`server_names`; the frontend blanks the key.
        let incoming = SecurityConfig::Reality(RealitySecurity {
            private_key: String::new(),
            public_key: String::new(),
            dest: "new.example.com:443".into(),
            server_names: vec!["new.example.com".into()],
            ..RealitySecurity::default()
        });
        let SecurityConfig::Reality(merged) = preserve_reality_keypair(&incoming, &stored) else {
            panic!("expected a Reality security");
        };
        assert_eq!(merged.private_key, "storedPrivateKey");
        assert_eq!(merged.public_key, "storedPublicKey");
        assert_eq!(
            merged.dest, "new.example.com:443",
            "the actual edit is kept"
        );
    }

    #[test]
    fn preserve_reality_keypair_passthrough_cases() {
        // Explicit rotate (non-blank incoming key) is left untouched.
        let stored = SecurityConfig::Reality(RealitySecurity {
            private_key: "storedKey".into(),
            ..RealitySecurity::default()
        });
        let rotate = SecurityConfig::Reality(RealitySecurity {
            private_key: "freshKey".into(),
            ..RealitySecurity::default()
        });
        let SecurityConfig::Reality(r) = preserve_reality_keypair(&rotate, &stored) else {
            panic!("expected Reality");
        };
        assert_eq!(r.private_key, "freshKey");

        // Switching TO Reality (blank key) over a non-Reality stored config has
        // no keypair to lift — it stays blank, so the pre-commit build correctly
        // rejects it (this is the fix working, not a regression).
        let stored_none = SecurityConfig::None(NoneSecurity {});
        let blank = SecurityConfig::Reality(RealitySecurity {
            private_key: String::new(),
            ..RealitySecurity::default()
        });
        let SecurityConfig::Reality(r2) = preserve_reality_keypair(&blank, &stored_none) else {
            panic!("expected Reality");
        };
        assert!(r2.private_key.is_empty());
    }
}
