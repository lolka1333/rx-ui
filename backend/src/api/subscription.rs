//! Public subscription endpoint — `GET /sub/{token}`.
//!
//! Per-client token resolved against the `clients.sub_token` column,
//! then aggregated by `email` so one URL bundles every share-link that
//! shares the client's identity across inbounds. That's how v2rayN /
//! Hiddify / `NekoBox` / sing-box auto-import "all my configs" from one
//! link and auto-refresh when the operator rotates a UUID or adds a
//! new inbound for the same user.
//!
//! Format selector (`?format=…`) covers the three shapes modern client
//! apps accept:
//!   * `base64` (default) — RFC 4648 base64 of `\n`-joined share-links.
//!     Universal: v2rayN-latest, Hiddify, `NekoBox`, sing-box import-from-
//!     URL, Streisand, Clash-bridge converters, Stash, every fork.
//!   * `json` — plain JSON array of share-link strings. v2rayN-latest
//!     and a few newer custom clients prefer it; Content-Type changes
//!     to `application/json` so the parser picks the right path.
//!   * `plain` — raw newline-separated text, no base64. Debug aid for
//!     `curl | nl` and a fallback for older clients that don't decode.
//!
//! Headers follow the subscription-userinfo convention popularised by
//! v2rayN and adopted by every modern client:
//!   * `Subscription-Userinfo: upload=…; download=…; total=…; expire=…`
//!     — the client app surfaces these as a per-profile traffic widget
//!     (used/total bar, remaining-days badge).
//!   * `Profile-Update-Interval: 12` — clients auto-refetch every 12h
//!     so config rotations propagate without operator intervention.
//!   * `Content-Disposition: attachment; filename="<email>"` — gives
//!     the imported profile a sensible default name in the UI.
//!
//! No auth — the URL itself is the credential. Rotation invalidates
//! the old URL atomically (`POST /api/clients/{id}/rotate-sub-token`).

use crate::{
    AppState,
    error::{AppError, AppResult},
    xray::share_link,
};
use axum::{
    Router,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use rand::TryRng;
use serde::Deserialize;
use sqlx::SqlitePool;
use std::fmt::Write as _;

/// Random 32-char lowercase hex token. CSPRNG via OS entropy — these
/// URLs are public-facing, so collision/predictability are both
/// attack surface.
pub fn generate_token() -> String {
    let mut bytes = [0u8; 16];
    rand::rngs::SysRng
        .try_fill_bytes(&mut bytes)
        .expect("OS RNG unavailable");
    let mut out = String::with_capacity(32);
    for b in bytes {
        write!(out, "{b:02x}").expect("write to String never fails");
    }
    out
}

/// Generate a `sub_token` that's verified not to collide with any existing
/// row. 2^128 space makes collisions astronomically unlikely, but the
/// `sub_token` column carries a UNIQUE index — without this pre-check
/// a one-in-a-quintillion collision would bubble as a generic
/// "client already exists" Conflict from the INSERT's unique-violation
/// mapper (which actually catches the `(email, inbound_id)` constraint
/// — wrong message to surface to the operator). Three attempts is
/// vastly more than statistically necessary; if it ever fires, the DB
/// is in trouble and propagating Internal is the right outcome.
pub async fn generate_unique_token(db: &SqlitePool) -> AppResult<String> {
    for _ in 0..3 {
        let candidate = generate_token();
        let exists = sqlx::query_scalar!(
            "SELECT 1 AS \"exists!: i64\" FROM clients WHERE sub_token = ?",
            candidate
        )
        .fetch_optional(db)
        .await?
        .is_some();
        if !exists {
            return Ok(candidate);
        }
    }
    Err(AppError::Internal(anyhow::anyhow!(
        "could not generate a unique sub_token after 3 attempts"
    )))
}

/// Root-level router. Mounted at `/sub` (not `/api/sub`) so subscription
/// clients that don't speak JWT can still pull from a bare URL.
pub fn routes() -> Router<AppState> {
    Router::new().route("/{token}", get(subscription))
}

#[derive(Debug, Default, Deserialize)]
struct SubFormat {
    /// `base64` (default) | `json` | `plain`. `None` ≡ no `?format=`
    /// query at all — distinct from `Some(Base64)` because the absence
    /// is what triggers the HTML-landing fallback for browser visits.
    /// An unrecognised string deserialises to `None` so a typo doesn't
    /// break the client (it still gets the default-base64 path).
    #[serde(default)]
    format: Option<SubFormatKind>,
}

#[derive(Debug, Default, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum SubFormatKind {
    #[default]
    Base64,
    Json,
    Plain,
}

async fn subscription(
    State(state): State<AppState>,
    Path(token): Path<String>,
    Query(fmt): Query<SubFormat>,
    headers_in: HeaderMap,
) -> AppResult<Response> {
    // Operator-configurable subscription knobs (kill-switch, host override,
    // update interval). Single SELECT — these never change per-request.
    let subscription_cfg = load_subscription_cfg(&state.db).await;
    // Kill-switch: returning the same 404 an invalid token would produce
    // keeps the surface indistinguishable from "not configured" — an
    // attacker probing tokens can't tell whether subscriptions are
    // deliberately off or whether they just guessed wrong.
    if !subscription_cfg.enabled {
        return Ok(StatusCode::NOT_FOUND.into_response());
    }

    // Browser-facing visit: if the caller asks for HTML and didn't pin a
    // specific format, hand off to the SPA so the React landing page
    // can render usage instructions, deeplinks, QR, etc. The brand name
    // is substituted directly into `<title>` so the browser tab carries
    // the operator-configured name from the first paint — no
    // "Admin Panel" flash and no `document.title = …` fiddling in
    // React. VPN clients send `Accept: */*` and pass through to the
    // bytes path unchanged.
    if fmt.format.is_none() && wants_html(&headers_in) {
        return Ok(crate::static_assets::serve_index_with_title(
            &subscription_cfg.brand_name,
        ));
    }
    let format = fmt.format.unwrap_or_default();

    // Resolve the token to a client row. 404 is intentional — we want
    // an attacker probing random tokens to see the same "no such URL"
    // response a typo would produce, not a "valid format but not found".
    let owner = sqlx::query!("SELECT email FROM clients WHERE sub_token = ?", token)
        .fetch_optional(&state.db)
        .await?;
    let Some(owner) = owner else {
        return Ok(StatusCode::NOT_FOUND.into_response());
    };

    // Aggregate every enabled client row that shares the email. The
    // ORDER BY pins the bundle order across refreshes so the client
    // app's profile list doesn't reshuffle on every poll.
    let raw_rows = sqlx::query!(
        r#"SELECT id, inbound_id, email, uuid, auth, flow, enabled, note,
                  traffic_limit_bytes, disabled_reason, expires_at, sub_token, created_at, updated_at,
                  uplink_total, downlink_total
           FROM clients
           WHERE email = ?
           ORDER BY inbound_id, created_at"#,
        owner.email,
    )
    .fetch_all(&state.db)
    .await?;
    // Pre-map into a named struct so the helper signatures aren't
    // tied to the anonymous record type that `sqlx::query!` generates.
    let rows: Vec<SubscriptionRow> = raw_rows
        .into_iter()
        .map(|r| SubscriptionRow {
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
            uplink_total: r.uplink_total,
            downlink_total: r.downlink_total,
        })
        .collect();

    // One round-trip for every inbound referenced by the email's rows
    // (deduped — same email rarely lives in 20+ inbounds, but if it
    // does we still want one SELECT, not N).
    let mut inbound_ids: Vec<String> = rows.iter().map(|r| r.inbound_id.clone()).collect();
    inbound_ids.sort();
    inbound_ids.dedup();
    let inbounds = super::inbounds::fetch_inbounds_batch(&state, &inbound_ids).await?;

    let host = if subscription_cfg.host_override.is_empty() {
        best_host(&state).await.unwrap_or_default()
    } else {
        subscription_cfg.host_override
    };
    let bundle = build_bundle(&rows, &inbounds, &host);
    let mut headers = build_response_headers(
        &owner.email,
        &token,
        &bundle,
        subscription_cfg.update_interval,
        &subscription_cfg.brand_name,
        &subscription_cfg.service_url,
    );
    let body = format_body(format, &mut headers, &bundle.links);
    Ok((StatusCode::OK, headers, body).into_response())
}

/// Snapshot of the subscription-relevant fields of `panel_settings`.
/// Defaults applied here so the endpoint stays infallible even if the
/// settings row is missing — a fresh install would 500 otherwise.
struct SubscriptionCfg {
    enabled: bool,
    host_override: String,
    update_interval: u32,
    brand_name: String,
    service_url: String,
}

async fn load_subscription_cfg(db: &SqlitePool) -> SubscriptionCfg {
    let row = sqlx::query!(
        "SELECT sub_enabled, sub_host_override, sub_update_interval_hours,
                sub_brand_name, sub_service_url
            FROM panel_settings WHERE id = 1"
    )
    .fetch_optional(db)
    .await
    .ok()
    .flatten();
    if let Some(r) = row {
        SubscriptionCfg {
            enabled: r.sub_enabled != 0,
            host_override: r.sub_host_override,
            update_interval: u32::try_from(r.sub_update_interval_hours).unwrap_or_else(|_| {
                // Validation gates writes, so a negative/oversized value
                // here means the row was tampered with out-of-band — flag
                // it loudly instead of silently masking the corruption.
                tracing::warn!(
                    "panel_settings.sub_update_interval_hours = {} is out of u32 range — \
                 falling back to 12",
                    r.sub_update_interval_hours
                );
                12
            }),
            brand_name: r.sub_brand_name,
            service_url: r.sub_service_url,
        }
    } else {
        // First-run / corrupted-table fallback. We still serve subscriptions
        // (enabled: true) because that's the historical zero-config
        // behaviour; the operator never had to opt in. But the row should
        // always exist post-migration 0019, so log if it doesn't.
        tracing::error!(
            "panel_settings row missing — serving subscriptions with built-in defaults"
        );
        SubscriptionCfg {
            enabled: true,
            host_override: String::new(),
            update_interval: 12,
            brand_name: String::new(),
            service_url: String::new(),
        }
    }
}

/// One bundle as returned to the client app: links + the aggregated
/// per-direction byte counts that go into the `Subscription-Userinfo`
/// header. Kept on the stack to avoid leaking the row-walk state into
/// the response-building helpers.
struct Bundle {
    links: Vec<String>,
    upload: i64,
    download: i64,
    /// `0` ≡ unlimited (any row had `traffic_limit_bytes = NULL`, or
    /// the email has no rows at all).
    header_total: i64,
    /// Earliest `expires_at` across the bundle as a unix timestamp, or
    /// `0` ≡ no expiry (every row never-expires, or no rows).
    header_expire: i64,
}

/// Walk the email's rows once: derive the per-email byte totals for the
/// userinfo header AND build the share-link bundle, skipping disabled rows.
/// Disabled rows still contribute to used/limit so the operator's "used/limit"
/// widget stays consistent even after a quota flip turns the row off.
///
/// used/limit are the MAX across the email's rows, not the sum: xray counts
/// bytes per email and the poller writes that one per-email total into every
/// (email, inbound) row, so the rows are duplicates. Summing would multiply a
/// multi-inbound user's usage and quota by their inbound count.
fn build_bundle(
    rows: &[SubscriptionRow],
    inbounds: &std::collections::HashMap<String, crate::models::Inbound>,
    host: &str,
) -> Bundle {
    let mut links: Vec<String> = Vec::with_capacity(rows.len());
    let mut upload: i64 = 0;
    let mut download: i64 = 0;
    let mut total: i64 = 0;
    let mut has_unlimited = false;
    let mut earliest_expire: Option<i64> = None;
    for row in rows {
        upload = upload.max(row.uplink_total);
        download = download.max(row.downlink_total);
        match row.traffic_limit_bytes {
            Some(cap) => total = total.max(cap),
            None => has_unlimited = true,
        }
        if let Some(ref exp) = row.expires_at
            && let Ok(dt) = chrono::NaiveDateTime::parse_from_str(exp, "%Y-%m-%d %H:%M:%S")
        {
            let ts = dt.and_utc().timestamp();
            earliest_expire = Some(earliest_expire.map_or(ts, |e| e.min(ts)));
        }
        if !row.enabled {
            continue;
        }
        let Some(inbound) = inbounds.get(&row.inbound_id) else {
            tracing::warn!(
                "subscription: skipping client {} — inbound {} vanished",
                row.id,
                row.inbound_id
            );
            continue;
        };
        let client = row.to_client();
        match share_link::build_share_link(inbound, &client, host) {
            Ok(link) => links.push(link),
            Err(e) => tracing::warn!(
                "subscription: skipping inbound {} — share-link build failed: {e}",
                inbound.tag
            ),
        }
    }
    // `total = 0` is a valid xray-stats value (no upload yet). To mean
    // "unlimited" in the subscription header we set total to 0 only if
    // every row was unlimited (or there were no rows at all).
    let header_total = if has_unlimited { 0 } else { total };
    Bundle {
        links,
        upload,
        download,
        header_total,
        header_expire: earliest_expire.unwrap_or(0),
    }
}

/// Build the subscription response headers. Content-Type is left for
/// `format_body` since it depends on the chosen format.
fn build_response_headers(
    email: &str,
    token: &str,
    bundle: &Bundle,
    update_interval_hours: u32,
    brand_name: &str,
    service_url: &str,
) -> HeaderMap {
    let mut headers = HeaderMap::new();
    // Split upload + download — v2rayN / Hiddify render them as two
    // separate badges. Lumping into one number hid which direction
    // was eating quota; the wire shape `upload=...; download=...` is
    // the convention every client app reads.
    let userinfo = format!(
        "upload={}; download={}; total={}; expire={}",
        bundle.upload, bundle.download, bundle.header_total, bundle.header_expire,
    );
    headers.insert(
        "subscription-userinfo",
        HeaderValue::from_str(&userinfo).unwrap_or(HeaderValue::from_static("")),
    );
    headers.insert(
        "profile-update-interval",
        HeaderValue::from_str(&update_interval_hours.to_string())
            .unwrap_or(HeaderValue::from_static("12")),
    );
    // Brand name → custom header the React landing reads to show the
    // operator-configured service name in the hero. Empty string ≡ no
    // override; the landing falls back to its generic default.
    insert_pct_header(&mut headers, "x-sub-brand", brand_name);
    // Subscriber identity → the React landing displays it under the
    // brand. We don't put this on a known/standard header because
    // `Subscription-Userinfo` already exists and we don't want to risk
    // its parser tripping on a non-numeric value; a custom `x-sub-*`
    // header keeps this orthogonal to the v2rayN-convention bits.
    insert_pct_header(&mut headers, "x-sub-email", email);
    // Operator's main-service URL → "Перейти на сервис" button in the
    // landing header. Empty ≡ button hidden. Already validated as
    // http(s)-only on write, but we still encode here for header
    // safety so the wire shape is consistent across the x-sub-* set.
    insert_pct_header(&mut headers, "x-sub-service", service_url);
    // Sanitise the email for Content-Disposition — filename must avoid
    // CR/LF/quotes/semicolons. Strip the lot; fall back to the token
    // if nothing usable remains (token is always ASCII hex).
    let safe_name: String = email
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(*c, '_' | '-' | '.' | '@'))
        .collect();
    let filename = if safe_name.is_empty() {
        token.to_owned()
    } else {
        safe_name
    };
    let disp = format!("attachment; filename=\"{filename}\"");
    if let Ok(v) = HeaderValue::from_str(&disp) {
        headers.insert(header::CONTENT_DISPOSITION, v);
    }
    headers
}

/// Encode `links` into the requested format AND insert the matching
/// Content-Type header. Default base64 is universal; the JSON / plain
/// branches are escape hatches for newer client apps that prefer them.
fn format_body(fmt: SubFormatKind, headers: &mut HeaderMap, links: &[String]) -> String {
    match fmt {
        SubFormatKind::Json => {
            headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json; charset=utf-8"),
            );
            serde_json::to_string(links).unwrap_or_else(|_| "[]".to_owned())
        }
        SubFormatKind::Plain => {
            headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/plain; charset=utf-8"),
            );
            links.join("\n")
        }
        SubFormatKind::Base64 => {
            headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/plain; charset=utf-8"),
            );
            B64.encode(links.join("\n"))
        }
    }
}

/// Concrete row shape used by `build_bundle`. We pre-map the
/// anonymous `sqlx::query!` records into this struct at fetch time
/// so the helper signature is plain Rust types (no trait, no
/// in-function struct type leakage).
struct SubscriptionRow {
    id: String,
    inbound_id: String,
    email: String,
    uuid: String,
    auth: Option<String>,
    flow: Option<String>,
    enabled: bool,
    note: Option<String>,
    traffic_limit_bytes: Option<i64>,
    disabled_reason: Option<String>,
    expires_at: Option<String>,
    sub_token: String,
    created_at: String,
    updated_at: String,
    uplink_total: i64,
    downlink_total: i64,
}

impl SubscriptionRow {
    /// Build a full `Client` view for the share-link constructor. Used
    /// only inside the per-row branch of `build_bundle`.
    fn to_client(&self) -> crate::models::Client {
        crate::models::Client {
            id: self.id.clone(),
            inbound_id: self.inbound_id.clone(),
            email: self.email.clone(),
            uuid: self.uuid.clone(),
            auth: self.auth.clone(),
            flow: self.flow.clone(),
            reverse_tag: None,
            enabled: self.enabled,
            note: self.note.clone(),
            traffic_limit_bytes: self.traffic_limit_bytes,
            disabled_reason: self.disabled_reason.clone(),
            expires_at: self.expires_at.clone(),
            sub_token: self.sub_token.clone(),
            created_at: self.created_at.clone(),
            updated_at: self.updated_at.clone(),
        }
    }
}

/// Percent-encode `value` so non-ASCII (Cyrillic, etc.) round-trips
/// through `HeaderValue`, then insert under `name`. `HeaderValue`
/// rejects opaque bytes outside `\x20..=\x7e` minus a few control
/// chars, so a raw Russian / Chinese / emoji value would otherwise
/// silently drop. The landing-page side calls `decodeURIComponent` to
/// restore the original. No-op for an empty value.
fn insert_pct_header(headers: &mut HeaderMap, name: &'static str, value: &str) {
    if value.is_empty() {
        return;
    }
    let encoded = urlencoding::encode(value);
    if let Ok(v) = HeaderValue::from_str(&encoded) {
        headers.insert(name, v);
    }
}

/// True iff the caller's `Accept` header prefers HTML. Used to decide
/// whether to fall through to the SPA landing page instead of serving
/// the raw base64 bytes. We're lenient: any explicit `text/html` (with
/// or without a `q=` parameter, anywhere in the list) qualifies. VPN
/// clients send `*/*` or omit the header entirely and pass through to
/// the bytes path.
fn wants_html(headers: &HeaderMap) -> bool {
    headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|a| a.contains("text/html"))
}

/// Pick the best public host for share-links inside the subscription
/// bundle. Order: detected IPv4 → IPv6 → empty. Matches the precedence
/// used by the per-client `/share-link` endpoint so subscription URLs
/// and individual QRs agree on what the user's app will dial.
async fn best_host(state: &AppState) -> Option<String> {
    let snap = state.host.snapshot().await;
    snap.ipv4.or(snap.ipv6)
}
