//! Standalone keygen endpoints — generate cryptographic material
//! without binding it to a specific inbound. Used by the frontend
//! create/edit modal to pre-fill the VLESS Encryption keypair the
//! moment the operator picks `mlkem768x25519plus`, instead of
//! waiting for the inbound to be saved first.
//!
//! The persistence path is unchanged: pre-filled keys travel through
//! the normal `POST /api/inbounds` or `PATCH /api/inbounds/{id}` body
//! and `complete_server_managed_fields` keeps any keys the frontend
//! already provided.
//!
//! Reality keys ARE exposed here (body-carried, like VLESS Encryption) so the
//! operator sees the `public_key` the moment they pick Reality, instead of
//! only after the inbound is saved. It stays safe because the endpoint hands
//! back an atomic pair the operator never edits by hand, and
//! `complete_server_managed_fields` re-derives the public from the private on
//! save — a mismatched pair can't take effect. Rotating an existing inbound
//! still goes through its own `/rotate-reality-keypair` handler (which also
//! pushes the new key into the running xray).

use crate::{
    AppState,
    auth::AuthUser,
    error::{AppError, AppResult},
    protocols::vless::VlessEncryptionAuth,
    xray::keygen::{self, EchKeyBundle, RealityKeypair, VlessEncryptionKeypair},
};
use axum::{
    Json, Router,
    extract::{Query, State},
    routing::post,
};
use serde::Deserialize;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/vless-encryption", post(vless_encryption))
        .route("/reality-keypair", post(reality_keypair))
        .route("/ech", post(ech))
}

/// Generate a fresh Reality x25519 keypair. Side-effect-free: nothing is
/// persisted and no xray handler is touched. The frontend shows `public_key`
/// immediately on the create form and sends both halves back with the next
/// `POST /api/inbounds`; `complete_server_managed_fields` re-derives the
/// public from the private so the stored pair is always consistent.
async fn reality_keypair(_user: AuthUser) -> Json<RealityKeypair> {
    Json(keygen::generate_reality_keypair())
}

#[derive(Debug, Deserialize)]
pub struct VlessEncryptionQuery {
    /// Which authentication primitive to generate the keypair for.
    /// Defaults to `mlkem768` when omitted — same default as the
    /// inbound's own regenerate handler.
    #[serde(default)]
    pub auth: Option<String>,
}

/// Generate a fresh VLESS Encryption keypair. Side-effect-free: nothing
/// is written to the DB and no xray handler is touched. The frontend
/// stores the result in form state and sends it back with the next
/// `POST /api/inbounds` (or PATCH).
async fn vless_encryption(
    _user: AuthUser,
    State(state): State<AppState>,
    Query(q): Query<VlessEncryptionQuery>,
) -> AppResult<Json<VlessEncryptionKeypair>> {
    let auth = match q.auth.as_deref() {
        Some("x25519") => VlessEncryptionAuth::X25519,
        // Default + explicit "mlkem768" both pick the post-quantum
        // variant — matches the panel's recommended baseline.
        Some("mlkem768") | None => VlessEncryptionAuth::Mlkem768,
        Some(other) => {
            return Err(AppError::BadRequest(format!(
                "unknown auth `{other}` (expected mlkem768 or x25519)"
            )));
        }
    };
    let kp = keygen::generate_vless_encryption_keypair(&state.xray.binary, auth)
        .map_err(AppError::Internal)?;
    Ok(Json(kp))
}

#[derive(Debug, Deserialize)]
pub struct EchQuery {
    /// `ECHConfig` `public_name` — what clients see when they fall back to
    /// the unencrypted Server Name path. Optional; xray's own default
    /// (`cloudflare-ech.com`) is used when omitted, which is the most
    /// blending-in choice for a fresh operator.
    #[serde(default)]
    pub server_name: Option<String>,
}

/// Generate a fresh ECH key bundle (server keys + matching ECH config list).
/// Side-effect-free: nothing is persisted. The frontend places the
/// `ech_server_keys` string into the inbound's TLS form and sends it back
/// with the next save; `ech_config_list` is surfaced for the operator to
/// distribute to clients (the panel doesn't store it because xray re-derives
/// it from `ech_server_keys` on every boot).
async fn ech(
    _user: AuthUser,
    State(state): State<AppState>,
    Query(q): Query<EchQuery>,
) -> AppResult<Json<EchKeyBundle>> {
    let bundle = keygen::generate_ech_server_keys(&state.xray.binary, q.server_name.as_deref())
        .map_err(AppError::Internal)?;
    Ok(Json(bundle))
}
