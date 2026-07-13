//! Per-inbound VLESS client model. One row = one user of one inbound.
//!
//! The columns are a direct mirror of what xray's
//! `proxy::vless::Account` proto needs: `id` (uuid) and `flow`, plus
//! panel-side metadata (`email` for stats labels, `enabled` for runtime
//! gating, `note` for the operator's eyes).
//!
//! Flow handling: `flow` is `None` (NULL in DB) → "inherit from inbound's
//! `vless_flow`". Explicit `Some("")` is the empty/no-flow override, and
//! `Some("xtls-rprx-vision")` enables Vision for this client only. This
//! mirrors how Account's `flow` field is per-user in the .proto — useful
//! for mixed mobile (no Vision) + desktop (Vision) deployments.

use serde::{Deserialize, Serialize};
use ts_rs::TS;

use super::patch::PatchField;

/// Public view of a client row.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../frontend/src/api/types/client.ts")]
pub struct Client {
    pub id: String,
    pub inbound_id: String,
    pub email: String,
    /// VLESS UUID — the client's secret. Plain text in the API because the
    /// operator needs it to assemble a share-link. Frontend should treat it
    /// like a password (mask by default, eye-toggle to reveal).
    pub uuid: String,
    /// Hysteria 2 auth secret. On a hysteria inbound: the per-user string
    /// the client sends in the HTTP/3 Auth header; `None` falls back to
    /// `uuid` on the wire so pre-hysteria rows keep working without manual
    /// backfill. A VLESS row may still carry the email's shared secret — so
    /// it survives removing the last hysteria attachment — but VLESS ignores
    /// it on the wire.
    pub auth: Option<String>,
    /// `None` → inherit the inbound's `vless_flow`. Explicit `Some` overrides.
    pub flow: Option<String>,
    /// VLESS Reverse Proxy tag (xray 26.7.11+). Non-empty makes this client a
    /// reverse PORTAL endpoint: a connecting bridge registers a tunnel under
    /// this tag, which becomes a routing target. `None` / empty ≡ normal client.
    pub reverse_tag: Option<String>,
    pub enabled: bool,
    pub note: Option<String>,
    /// Hard cap in bytes on the lifetime sum of uplink + downlink. `None` /
    /// `NULL` ≡ no quota. When crossed, the stats poller flips `enabled` off
    /// with `disabled_reason = "quota"` and tells xray to drop the user.
    #[ts(type = "number | null")]
    pub traffic_limit_bytes: Option<i64>,
    /// Why the row is currently `enabled = false`. `None` while enabled (or
    /// for rows that have never been disabled). The operator-visible values:
    ///   * `"manual"` — operator clicked the toggle / saved with off
    ///   * `"quota"` — the poller hit `traffic_limit_bytes`
    ///   * `"expired"` — the poller passed `expires_at`
    ///
    /// The split lets "reset traffic" re-enable a quota client while
    /// leaving manually-disabled ones alone.
    pub disabled_reason: Option<String>,
    /// Absolute expiry instant as a UTC `YYYY-MM-DD HH:MM:SS` string (the
    /// `datetime('now')` shape). `None` / `NULL` ≡ never expires. When it
    /// passes, the stats poller flips `enabled` off with
    /// `disabled_reason = "expired"` and tells xray to drop the user;
    /// clearing or extending it re-enables the row.
    pub expires_at: Option<String>,
    /// Per-row subscription token. The public `GET /sub/{token}` endpoint
    /// resolves it to the client, then aggregates every share-link for
    /// rows with the same `email` across all inbounds — that's how one
    /// URL maps to "all my configs" in v2rayN / Hiddify / sing-box.
    /// 32 lowercase hex chars (16 random bytes). Rotated via
    /// `POST /api/clients/{id}/rotate-sub-token`.
    pub sub_token: String,
    pub created_at: String,
    pub updated_at: String,
}

impl Client {
    /// Wire-level auth secret for Hysteria 2. Explicit `auth` wins; falls
    /// back to `uuid` so a row migrated from a VLESS inbound (and so
    /// never had `auth` set) still authenticates instead of going dark.
    pub fn effective_hysteria_auth(&self) -> &str {
        self.auth
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or(&self.uuid)
    }
}

/// Body for `POST /api/inbounds/{inbound_id}/clients`.
///
/// `uuid` is server-generated when omitted (`Uuid::new_v4()`); the operator
/// can also paste an existing UUID to migrate users from another panel.
#[derive(Debug, Deserialize, TS)]
#[ts(export, export_to = "../../frontend/src/api/types/client.ts")]
pub struct ClientCreate {
    pub email: String,
    pub uuid: Option<String>,
    /// Hysteria 2 per-user auth string. Server-generated if omitted on a
    /// hysteria inbound (random 32-char base64); ignored on a vless inbound.
    pub auth: Option<String>,
    pub flow: Option<String>,
    #[serde(default)]
    pub reverse_tag: Option<String>,
    pub note: Option<String>,
    /// Optional traffic cap in bytes. `None` ≡ no cap; the field can be
    /// added later via PATCH if the operator decides to enforce one.
    #[serde(default)]
    #[ts(type = "number | null")]
    pub traffic_limit_bytes: Option<i64>,
    /// Optional absolute expiry, ISO-8601 from the client; normalized to the
    /// `datetime('now')` shape on write. `None` ≡ never expires.
    #[serde(default)]
    pub expires_at: Option<String>,
}

/// Body for `PATCH /api/inbounds/{inbound_id}/clients/{client_id}`
/// and `PATCH /api/clients/{id}`.
#[derive(Debug, Deserialize, TS)]
#[ts(export, export_to = "../../frontend/src/api/types/client.ts")]
pub struct ClientUpdate {
    pub email: Option<String>,
    pub uuid: Option<String>,
    /// Hysteria 2 auth string. Same meaning as ClientCreate.auth — omit
    /// to leave unchanged; explicit non-empty string replaces it. Setting
    /// to empty string clears it (rare, but the operator may want to
    /// switch a row back to uuid-fallback behaviour).
    pub auth: Option<String>,
    pub flow: Option<String>,
    #[serde(default)]
    pub reverse_tag: Option<String>,
    pub enabled: Option<bool>,
    pub note: Option<String>,
    /// Tri-state PATCH semantics — `Set(n)` writes the cap, `Clear` drops
    /// it back to unlimited, `Unchanged` leaves the column alone.
    /// `#[serde(default)]` is what makes "key absent" deserialize to
    /// `Unchanged`; an explicit `null` from the wire becomes `Clear` via
    /// `PatchField`'s own deserializer.
    #[serde(default)]
    #[ts(type = "number | null | undefined")]
    pub traffic_limit_bytes: PatchField<i64>,
    /// Tri-state PATCH for the expiry instant. Same semantics as
    /// `traffic_limit_bytes`: `Set` writes, `Clear` (explicit null) drops to
    /// never-expires, `Unchanged` leaves it. ISO-8601 in, normalized on write.
    #[serde(default)]
    #[ts(type = "string | null | undefined")]
    pub expires_at: PatchField<String>,
}

/// Body for the top-level `POST /api/clients`.
///
/// Distinct from `ClientCreate` because the nested route picks `inbound_id`
/// up from the URL (`/api/inbounds/{inbound_id}/clients`), whereas the
/// global route needs it explicitly in the body. Field shape is otherwise
/// identical so the frontend can reuse most of its create-form logic.
#[derive(Debug, Deserialize, TS)]
#[ts(export, export_to = "../../frontend/src/api/types/client.ts")]
pub struct ClientCreateGlobal {
    pub inbound_id: String,
    pub email: String,
    pub uuid: Option<String>,
    pub auth: Option<String>,
    pub flow: Option<String>,
    pub note: Option<String>,
    #[serde(default)]
    #[ts(type = "number | null")]
    pub traffic_limit_bytes: Option<i64>,
    #[serde(default)]
    pub expires_at: Option<String>,
}

/// Body for `POST /api/clients/bulk-assign` — the "give this user access
/// to N inbounds in one shot" operation. `inbound_ids` is the desired
/// target set: rows for inbounds present in the set are created (or
/// updated to match the supplied fields), rows for the email's other
/// inbounds are torn down. UUID/auth/flow/note/limit are shared across
/// every produced row so the user has a consistent identity in every
/// client app — and so the same subscription bundle resolves to N
/// distinct share-links instead of N permutations of credentials.
#[derive(Debug, Deserialize, TS)]
#[ts(export, export_to = "../../frontend/src/api/types/client.ts")]
pub struct ClientBulkAssign {
    pub email: String,
    /// Target inbound set. Must contain at least one entry — the bulk
    /// op never deletes the user entirely (use the per-row DELETE for
    /// that, which is more explicit about what's being removed).
    pub inbound_ids: Vec<String>,
    pub uuid: Option<String>,
    pub auth: Option<String>,
    pub flow: Option<String>,
    /// VLESS Reverse Proxy portal tag, shared across every produced row (same
    /// as uuid/flow). `None` / empty ≡ normal client. A bridge dialing in as
    /// this user registers a tunnel outbound under the tag on this server.
    #[serde(default)]
    pub reverse_tag: Option<String>,
    pub note: Option<String>,
    #[serde(default)]
    #[ts(type = "number | null")]
    pub traffic_limit_bytes: Option<i64>,
    #[serde(default)]
    pub expires_at: Option<String>,
}

/// Result of a `POST /api/clients/bulk-assign`. Three sets so the
/// frontend can show "+3 created, 1 updated, 1 removed" without
/// diffing the listing itself, plus a `xray_failures` channel for
/// the post-commit gRPC sync — DB always wins, but the operator
/// needs to know if xray didn't pick up a change so they can hit
/// "Restart xray" before users notice the drift.
#[derive(Debug, Serialize, TS)]
#[ts(export, export_to = "../../frontend/src/api/types/client.ts")]
pub struct ClientBulkAssignResult {
    /// Newly-inserted rows (one per `inbound_id` that didn't already
    /// have an assignment for this email).
    pub created: Vec<Client>,
    /// Existing rows whose fields were rewritten to match the bulk body.
    pub updated: Vec<Client>,
    /// Rows that were dropped because their inbound is no longer in
    /// the target set. Returned as `(client_id, inbound_id)` rather
    /// than the full Client — they don't exist anymore on the server.
    pub removed: Vec<ClientBulkRemoved>,
    /// Per-inbound xray gRPC errors. Empty in the happy path. The DB
    /// is consistent regardless — these are reconciliation hints.
    pub xray_failures: Vec<ClientBulkXrayFailure>,
}

#[derive(Debug, Serialize, TS)]
#[ts(export, export_to = "../../frontend/src/api/types/client.ts")]
pub struct ClientBulkRemoved {
    pub id: String,
    pub inbound_id: String,
}

#[derive(Debug, Serialize, TS)]
#[ts(export, export_to = "../../frontend/src/api/types/client.ts")]
pub struct ClientBulkXrayFailure {
    pub inbound_id: String,
    pub inbound_tag: String,
    /// Operator-readable summary; full details live in backend logs.
    pub message: String,
}
