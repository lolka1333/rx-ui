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
    models::{CustomOutbound, OutboundProtocolConfig},
    security::SecurityConfig,
    transports::TransportConfig,
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
        .route("/warp", axum::routing::post(warp_register))
        .route("/{id}/test", axum::routing::post(test))
        .route("/builtin/{tag}/test", axum::routing::post(test_builtin))
}

/// Optional body of the WARP registration: a WARP+ license key, or nothing at
/// all for a free tunnel.
#[derive(Debug, serde::Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../frontend/src/api/types/outbound.ts")]
pub struct WarpRequest {
    #[serde(default)]
    pub license: String,
}

/// Register a Cloudflare WARP tunnel and return it as a ready outbound —
/// **without storing it**.
///
/// Saving goes through the ordinary whole-list PUT, so a WARP tunnel is
/// validated, applied and reconciled by exactly the same code as an outbound
/// typed by hand; this endpoint only does the part the operator cannot, which
/// is talk to Cloudflare and generate the keys.
async fn warp_register(
    _user: AuthUser,
    State(state): State<AppState>,
    body: Option<Json<WarpRequest>>,
) -> AppResult<Json<CustomOutbound>> {
    let license = body.map(|Json(b)| b.license).unwrap_or_default();
    let keys = crate::xray::keygen::generate_wireguard_keypair();
    let registration = crate::xray::warp::register(keys.private_key, &keys.public_key, &license)
        .await
        .map_err(|e| {
            // A rejected license is the operator's typo and comes back as such,
            // with Cloudflare's own wording. Everything else is the panel's
            // host failing to reach Cloudflare, where the cause chain is what
            // says which step broke.
            match e.downcast::<crate::xray::warp::BadLicense>() {
                Ok(bad) => AppError::BadRequest(bad.0),
                Err(other) => AppError::Internal(other),
            }
        })?;

    let existing = load_custom_outbounds(&state.db).await?;
    let now = chrono::Utc::now().to_rfc3339();
    Ok(Json(CustomOutbound {
        id: uuid::Uuid::new_v4().to_string(),
        tag: free_warp_tag(&existing),
        enabled: true,
        protocol: OutboundProtocolConfig::Wireguard(registration.into_outbound()),
        // A WireGuard outbound dials UDP itself: the stream layer, its security
        // and the masks are not consulted, so they stay at their defaults.
        transport: TransportConfig::Tcp(crate::transports::tcp::TcpTransport {}),
        security: SecurityConfig::None(crate::security::NoneSecurity {}),
        finalmask: crate::transports::finalmask::FinalMask::default(),
        mux: crate::models::OutboundMux::default(),
        send_through: String::new(),
        proxy_tag: String::new(),
        created_at: now.clone(),
        updated_at: now,
    }))
}

/// `warp`, or `warp-2`, `warp-3`… when the plain name is taken. Registering a
/// second tunnel is a normal thing to do — one per exit country, say — and it
/// must not collide with the first.
fn free_warp_tag(existing: &[CustomOutbound]) -> String {
    let taken: std::collections::HashSet<&str> = existing.iter().map(|o| o.tag.as_str()).collect();
    if !taken.contains("warp") {
        return "warp".to_owned();
    }
    // Bounded by the list's own ceiling: with at most `MAX_OUTBOUNDS` tags
    // taken, one of `MAX_OUTBOUNDS + 1` candidates is always free.
    (2..=MAX_OUTBOUNDS + 1)
        .map(|n| format!("warp-{n}"))
        .find(|t| !taken.contains(t.as_str()))
        .unwrap_or_else(|| unreachable!("more candidates than the list can hold"))
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
    // Legacy single-item Noise blobs fold into the current `items[]` shape
    // automatically on deserialize (see `NoiseParams` / `NoiseParamsRepr`), so
    // every read — list, connectivity test, share-link — sees one layout.
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
    // Probe the operator-configured URL (`xray_test_url`), not a hardcoded one,
    // so the exit test reflects the endpoint set in Settings.
    let test_url = crate::api::settings::load_panel_settings(&state.db)
        .await?
        .xray_test_url;
    Ok(Json(
        test_outbound(&state.xray.binary, &ob, &test_url).await,
    ))
}

/// Connectivity test for a built-in outbound. `direct` / `direct-ipv4` make a
/// direct (no-proxy) probe — the server's own egress baseline. `blocked` is a
/// blackhole (drops everything by design) so it isn't testable.
async fn test_builtin(
    _user: AuthUser,
    State(state): State<AppState>,
    Path(tag): Path<String>,
) -> AppResult<Json<OutboundTestResult>> {
    let test_url = crate::api::settings::load_panel_settings(&state.db)
        .await?
        .xray_test_url;
    let result = match tag.as_str() {
        "direct" => test_direct(false, &test_url).await,
        "direct-ipv4" => test_direct(true, &test_url).await,
        other => {
            return Err(AppError::BadRequest(format!("'{other}' is not testable")));
        }
    };
    Ok(Json(result))
}

async fn replace(
    _user: AuthUser,
    State(state): State<AppState>,
    Json(mut body): Json<Vec<CustomOutbound>>,
) -> AppResult<StatusCode> {
    // The stored list is read once: it tells a newly chosen mask from one that
    // is only riding along in the full-array PUT, and its tags are the ones to
    // drop from xray before re-adding.
    let previous = load_custom_outbounds(&state.db).await?;
    validate_outbounds(&body, &previous)?;

    // Derive the server-side half of any mask that has one (today: XMC's RSA
    // keypair) before anything is built or stored. The outbound is a client,
    // and xray's XMC client refuses an empty public key — without this the
    // handler would be built with no mask at all and dial out bare while the
    // form shows one configured.
    for o in &mut body {
        // Server-side failure, not bad input — kept as `Internal` so the whole
        // cause chain reaches the operator (see `error.rs`).
        crate::xray::xmc::complete_finalmask(&state.xray.binary, &mut o.finalmask)
            .await
            .map_err(|e| AppError::Internal(e.context(format!("outbound '{}'", o.tag))))?;
    }

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
    let old_tags: Vec<String> = previous.into_iter().map(|o| o.tag).collect();

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
    // A tag that left the list takes its lifetime total with it. `outbound_traffic`
    // is keyed by tag, so an orphan row would be inherited by the next outbound
    // that happened to reuse the name — the same ghost-total misattribution the
    // inbound path deletes for (`api::inbounds`). Every tag in the submitted
    // list is kept, including a disabled one, because its total is still shown.
    let submitted: std::collections::HashSet<&str> = body.iter().map(|o| o.tag.as_str()).collect();
    for tag in &old_tags {
        if !submitted.contains(tag.as_str())
            && let Err(e) = sqlx::query!("DELETE FROM outbound_traffic WHERE tag = ?", tag)
                .execute(&state.db)
                .await
        {
            tracing::warn!("could not drop the traffic total of removed outbound {tag}: {e}");
        }
    }
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
    // Same guard as the inbound reconcile: no live process means every push
    // burns a 5s dial for nothing, while the caller holds `xray_apply`.
    if !state.xray.status().await.running {
        tracing::info!("xray not running, skipping outbound reconcile until it starts");
        return Ok(());
    }
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
/// Re-prefix a validation error with the outbound it came from. The shared
/// validators speak about "the mask", not about which row carries it, and the
/// whole array is submitted at once.
fn prefix_error(tag: &str, e: AppError) -> AppError {
    match e {
        AppError::BadRequest(m) => AppError::BadRequest(format!("outbound '{tag}': {m}")),
        other => other,
    }
}

/// The mask as the operator sees it: the server-derived key material is
/// stripped, so a mask carried over from the stored list compares equal
/// whether or not the form echoed the keys back.
fn mask_fingerprint(fm: &crate::transports::finalmask::FinalMask) -> String {
    let mut fm = fm.clone();
    if let crate::transports::finalmask::FinalMask::Xmc(p) = &mut fm {
        p.rsa_private_key.clear();
        p.rsa_public_key.clear();
    }
    serde_json::to_string(&fm).unwrap_or_default()
}

/// Is this outbound's mask something the operator is submitting anew, rather
/// than a stored value riding along in the full-array PUT?
fn mask_is_new(o: &CustomOutbound, previous: &[CustomOutbound]) -> bool {
    previous
        .iter()
        .find(|p| p.id == o.id)
        .is_none_or(|p| mask_fingerprint(&p.finalmask) != mask_fingerprint(&o.finalmask))
}

/// `previous` is the stored list, used only to tell a freshly chosen mask from
/// one that was already there — rules added after a row was written must not
/// turn every later save of the whole array into a 400.
fn validate_outbounds(outbounds: &[CustomOutbound], previous: &[CustomOutbound]) -> AppResult<()> {
    if outbounds.len() > MAX_OUTBOUNDS {
        return Err(AppError::BadRequest(format!(
            "too many outbounds (max {MAX_OUTBOUNDS})"
        )));
    }
    let mut seen = std::collections::HashSet::new();
    for o in outbounds {
        let tag = o.tag.trim();
        crate::xray::config_gen::validate_routable_tag(tag)
            .map_err(|e| AppError::BadRequest(format!("outbound {e}")))?;
        if !seen.insert(tag.to_owned()) {
            return Err(AppError::BadRequest(format!(
                "duplicate outbound tag '{tag}'"
            )));
        }
        // The masks ride outbounds too and feed the SAME xray process as the
        // inbounds, so they go through the inbound validator rather than a
        // second copy of it: an out-of-range noise value crash-loops xray, a
        // mask outside the transport's matrix dials out bare while the form
        // shows it configured, and Reality over a mask with no `CloseWrite`
        // panics the process. `check_matrix` is off for a mask carried over
        // from the stored list untouched — the whole outbound array is
        // re-submitted on every save, so judging a pre-existing mask would let
        // one legacy entry block every unrelated outbound write.
        crate::api::inbounds::validate_finalmask(
            &o.transport,
            &o.security,
            &o.finalmask,
            mask_is_new(o, previous),
        )
        .map_err(|e| prefix_error(tag, e))?;
        // Hysteria 2 is a QUIC proxy where the protocol and transport are one
        // and the same, so they must be paired — and the connection needs a
        // password, carried on the transport (where xray's dialer reads it).
        match (&o.protocol, &o.transport) {
            (OutboundProtocolConfig::Hysteria(h), TransportConfig::Hysteria(t)) => {
                if h.address.trim().is_empty() {
                    return Err(AppError::BadRequest(format!(
                        "outbound '{tag}': hysteria2 server address is required"
                    )));
                }
                if t.auth.as_deref().unwrap_or_default().trim().is_empty() {
                    return Err(AppError::BadRequest(format!(
                        "outbound '{tag}': hysteria2 requires a password"
                    )));
                }
                // QUIC is always TLS — xray's hysteria dialer refuses to start
                // with a nil tls config ("tls config is nil").
                if !matches!(o.security, SecurityConfig::Tls(_)) {
                    return Err(AppError::BadRequest(format!(
                        "outbound '{tag}': hysteria2 requires TLS security"
                    )));
                }
            }
            (OutboundProtocolConfig::Hysteria(_), _) => {
                return Err(AppError::BadRequest(format!(
                    "outbound '{tag}': the hysteria2 protocol requires the hysteria transport"
                )));
            }
            (_, TransportConfig::Hysteria(_)) => {
                return Err(AppError::BadRequest(format!(
                    "outbound '{tag}': the hysteria transport requires the hysteria2 protocol"
                )));
            }
            _ => {}
        }
        if let OutboundProtocolConfig::Wireguard(w) = &o.protocol {
            validate_wireguard(w)
                .map_err(|e| AppError::BadRequest(format!("outbound '{tag}': {e}")))?;
        }
    }
    Ok(())
}

/// A hand-written `WireGuard` peer, checked before it reaches the core.
///
/// The keys are checked by the same parser the emitter uses, so a bad one is a
/// 400 rather than a handler that fails to build. The rest is checked here
/// because the core takes those fields as strings and only complains when the
/// tunnel is already being added — which the API reports as "saved but not
/// applied", the least useful moment to learn about a typo.
fn validate_wireguard(w: &crate::models::WireguardOutbound) -> anyhow::Result<()> {
    crate::xray::keygen::parse_wireguard_key(&w.secret_key)
        .map_err(|e| anyhow::anyhow!("private key: {e}"))?;
    crate::xray::keygen::parse_wireguard_key(&w.peer_public_key)
        .map_err(|e| anyhow::anyhow!("peer public key: {e}"))?;
    if !w.pre_shared_key.trim().is_empty() {
        crate::xray::keygen::parse_wireguard_key(&w.pre_shared_key)
            .map_err(|e| anyhow::anyhow!("pre-shared key: {e}"))?;
    }
    // Rejected here rather than at push time: the same strings xray's own JSON
    // config takes, so a bad one is a 400 with the list instead of an outbound
    // that saves and then fails to build.
    anyhow::ensure!(
        matches!(
            w.domain_strategy.trim().to_ascii_lowercase().as_str(),
            "" | "forceip" | "forceipv4" | "forceipv6" | "forceipv4v6" | "forceipv6v4"
        ),
        "unsupported domain strategy: {} (use ForceIP, ForceIPv4, ForceIPv6, \
         ForceIPv4v6 or ForceIPv6v4)",
        w.domain_strategy
    );

    anyhow::ensure!(
        !w.address.is_empty(),
        "the tunnel needs at least one address"
    );
    for addr in &w.address {
        let a = addr.trim();
        // `10.2.0.2/32` or a bare `10.2.0.2` — the core's netstack takes both.
        let ip = a.split_once('/').map_or(a, |(head, _)| head);
        anyhow::ensure!(
            ip.parse::<std::net::IpAddr>().is_ok(),
            "tunnel address is not an IP: {a}"
        );
        if let Some((_, prefix)) = a.split_once('/') {
            let bits: u8 = prefix
                .parse()
                .map_err(|_| anyhow::anyhow!("prefix is not a number: {a}"))?;
            let max = if ip.contains(':') { 128 } else { 32 };
            anyhow::ensure!(bits <= max, "prefix out of range for the family: {a}");
        }
    }

    let endpoint = w.endpoint.trim();
    let (host, port) = endpoint
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("peer endpoint needs a port: {endpoint}"))?;
    anyhow::ensure!(!host.is_empty(), "peer endpoint has no host: {endpoint}");
    let port: u32 = port
        .parse()
        .map_err(|_| anyhow::anyhow!("peer port is not a number: {endpoint}"))?;
    anyhow::ensure!(
        (1..=65535).contains(&port),
        "peer port out of range: {endpoint}"
    );

    // WARP's client id is three bytes; a plain peer has none. Any other length
    // is a value the edge would silently ignore or reject.
    anyhow::ensure!(
        w.reserved.is_empty() || w.reserved.len() == 3,
        "reserved must be empty or exactly three bytes"
    );
    anyhow::ensure!(
        w.mtu == 0 || (576..=1500).contains(&w.mtu),
        "mtu must be 0 (the core's default) or between 576 and 1500"
    );
    anyhow::ensure!(w.keep_alive <= 65535, "keepalive must be at most 65535");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_wireguard;
    use crate::models::WireguardOutbound;

    fn peer() -> WireguardOutbound {
        WireguardOutbound {
            secret_key: "yPz3Yq0mQ5tHhP2xLZ9nR4cVwK7sJd8bFgN6uT1aX0E=".to_owned(),
            address: vec!["10.2.0.2/32".to_owned()],
            peer_public_key: "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=".to_owned(),
            endpoint: "vpn.example.com:51820".to_owned(),
            pre_shared_key: String::new(),
            domain_strategy: String::new(),
            reserved: Vec::new(),
            mtu: 0,
            keep_alive: 25,
            warp: false,
        }
    }

    /// The shapes a peer is normally written in, all of which the core accepts.
    #[test]
    fn a_hand_written_peer_is_accepted() {
        assert!(validate_wireguard(&peer()).is_ok());

        let mut both_families = peer();
        both_families.address = vec![
            "10.2.0.2/32".to_owned(),
            "fd00::2/128".to_owned(),
            // A bare address is legal too — the netstack treats it as a host.
            "10.2.0.3".to_owned(),
        ];
        both_families.mtu = 1280;
        both_families.reserved = vec![1, 2, 3];
        assert!(validate_wireguard(&both_families).is_ok());

        // The keys travel in whichever encoding the far end printed them in.
        let mut hex_key = peer();
        hex_key.secret_key =
            "c8fd3e62ad2643b4787ed8b2d9fa77b8715ec927d6f81f8593b7ad35f5344f41".to_owned();
        assert!(validate_wireguard(&hex_key).is_ok());
    }

    /// Every one of these reaches the core as a string and fails there — while
    /// the tunnel is being added, which the API can only report as "saved but
    /// not applied". They belong in a 400 instead.
    #[test]
    fn a_peer_the_core_would_choke_on_is_refused() {
        /// What one broken peer looks like: a name for the failure and the
        /// edit that produces it.
        type Break = (&'static str, fn(&mut WireguardOutbound));
        let cases: [Break; 7] = [
            ("key that is not a key", |w| {
                w.secret_key = "hunter2".to_owned();
            }),
            ("peer key that is not a key", |w| {
                w.peer_public_key = "not-a-key".to_owned();
            }),
            ("no address at all", |w| w.address.clear()),
            ("address that is not an IP", |w| {
                w.address = vec!["home.example.com/32".to_owned()];
            }),
            ("prefix past the family", |w| {
                w.address = vec!["10.2.0.2/33".to_owned()];
            }),
            ("endpoint without a port", |w| {
                w.endpoint = "vpn.example.com".to_owned();
            }),
            // Two bytes are not WARP's client id and not "no client id" either:
            // the edge answers such a tunnel with silence.
            ("reserved of the wrong length", |w| w.reserved = vec![1, 2]),
        ];
        for (what, break_it) in cases {
            let mut w = peer();
            break_it(&mut w);
            assert!(validate_wireguard(&w).is_err(), "{what} should be refused");
        }
    }
}
