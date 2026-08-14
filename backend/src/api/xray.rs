use crate::{
    AppState,
    auth::AuthUser,
    error::{AppError, AppResult},
    xray::geofiles as geo,
    xray::installer,
};
use axum::{
    Json, Router,
    extract::{Query, State},
    routing::{get, post},
};
use serde::Deserialize;
use std::time::{Duration, Instant};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/releases", get(list_releases))
        .route("/install", post(install))
        .route("/start", post(start))
        .route("/stop", post(stop))
        .route("/restart", post(restart))
        .route("/test-outbound", post(test_outbound))
        .route("/geofiles", get(geofiles).put(save_geofiles))
        .route("/geofiles/update", post(update_geofiles))
}

#[derive(Deserialize)]
struct ReleasesQuery {
    #[serde(default = "default_limit")]
    limit: u32,
    /// Custom source link / `owner/repo` shorthand; empty ≡ default upstream.
    repo: Option<String>,
}
const fn default_limit() -> u32 {
    10
}

/// Resolve the operator-supplied source link to `owner/repo`, falling back to
/// the default upstream repo when none is given. A malformed link is a clean
/// 400, not a request to a bogus GitHub URL.
fn resolve_repo(link: Option<&str>) -> AppResult<String> {
    let Some(l) = link.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(installer::DEFAULT_REPO.to_owned());
    };
    installer::parse_repo(l)
        .ok_or_else(|| AppError::BadRequest(format!("invalid source link: {l}")))
}

async fn list_releases(
    _user: AuthUser,
    Query(q): Query<ReleasesQuery>,
) -> AppResult<Json<Vec<installer::XrayRelease>>> {
    let repo = resolve_repo(q.repo.as_deref())?;
    let releases = installer::fetch_releases(&repo, q.limit.clamp(1, 50))
        .await
        .map_err(AppError::Internal)?;
    Ok(Json(releases))
}

#[derive(Deserialize)]
struct InstallRequest {
    /// Either a tag like "v25.7.26" or the release object the UI got from
    /// `/releases` — we re-fetch by tag to make sure `asset_url` is fresh.
    tag: String,
    /// Source link the tag came from; empty ≡ default upstream repo. Must match
    /// the source the UI listed, or the tag won't be found.
    repo: Option<String>,
}

async fn install(
    _user: AuthUser,
    State(state): State<AppState>,
    Json(req): Json<InstallRequest>,
) -> AppResult<Json<serde_json::Value>> {
    // Refetch the release list so the asset_url is current — the panel can't
    // trust whatever URL the browser sent.
    let repo = resolve_repo(req.repo.as_deref())?;
    let releases = installer::fetch_releases(&repo, 50)
        .await
        .map_err(AppError::Internal)?;
    let release = releases
        .into_iter()
        .find(|r| r.tag == req.tag)
        .ok_or_else(|| AppError::BadRequest(format!("unknown release tag: {}", req.tag)))?;

    let _apply = state.xray_apply.lock().await;
    let install_dir = state
        .xray
        .binary
        .parent()
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("xray binary path has no parent")))?
        .to_path_buf();

    // Stop xray before swapping the binary on Windows (file lock); on Unix it's
    // not strictly required, but keeps behavior consistent. Log the error if
    // stop fails — on Windows the subsequent rename will then fail with a
    // less-helpful "file in use" error, and the stop-failure log is what
    // tells the operator what really went wrong.
    let was_running = state.xray.status().await.running;
    if was_running && let Err(e) = state.xray.stop().await {
        tracing::warn!("xray stop before install failed; proceeding anyway: {e}");
    }

    installer::install_release(&release, &install_dir)
        .await
        .map_err(AppError::Internal)?;

    if was_running {
        // Bring xray back up with the new binary. Regenerate the config first:
        // it carries the routing rules, so starting on a stale file would
        // revert whatever was applied since it was last written. A regen
        // failure must not block the upgrade — start on the last-good config.
        let mut regen_failure = None;
        let has_ipv4 = match crate::xray::reload::write_bootstrap_config(&state).await {
            Ok(v) => Some(v),
            Err(e) => {
                tracing::warn!("config regen before binary restart failed: {e:#}");
                regen_failure = Some(format!("{e:#}"));
                None
            }
        };
        state.xray.start().await.map_err(AppError::Internal)?;
        let live_ipv4 = match has_ipv4 {
            Some(v) => v,
            None => crate::xray::reload::config_on_disk_has_ipv4(&state.xray.config_path).await,
        };
        crate::xray::reload::note_live_ipv4(&state, live_ipv4);
        // Only when the config was actually regenerated: on a regen failure the
        // process came up on the LAST-GOOD file, so the saved rules still aren't
        // live and clearing the markers would hide that.
        if let Some(cause) = regen_failure {
            crate::xray::reload::note_routing_left_behind(&state, &cause).await;
        } else {
            crate::xray::reload::note_routing_in_sync(&state).await;
        }
        // The new process starts with empty in-memory handlers and the
        // cached gRPC channel points at the old one — drop the channel and
        // re-push every enabled inbound so clients keep working without a
        // panel restart (otherwise AddUser later fails "handler not found").
        crate::resync_xray_state(&state).await;
        clear_geo_apply_pending(&state).await;
    }

    Ok(Json(serde_json::json!({
        "installed": release.tag,
        "restarted": was_running,
    })))
}

async fn start(
    _user: AuthUser,
    State(state): State<AppState>,
) -> AppResult<Json<serde_json::Value>> {
    let _apply = state.xray_apply.lock().await;
    // Regenerate the bootstrap config first: routing/Freedom settings saved
    // while xray was stopped only reach the process through this file (the
    // hot-apply path no-ops when it isn't running), so starting without it
    // would come up on a stale config. A regen failure must NOT block the
    // start though — `write_config_validated` leaves the last-good config.json
    // in place, and refusing to start would strand the operator with a stopped
    // xray they can't bring back up.
    let mut regen_failure = None;
    let has_ipv4 = match crate::xray::reload::write_bootstrap_config(&state).await {
        Ok(v) => Some(v),
        Err(e) => {
            tracing::warn!("config regen before start failed; starting on last-good config: {e:#}");
            regen_failure = Some(format!("{e:#}"));
            None
        }
    };
    state.xray.start().await.map_err(AppError::Internal)?;
    // Record what the process actually came up on: the config we just wrote,
    // or — if the regen failed — whatever config.json it loaded instead.
    let live_ipv4 = match has_ipv4 {
        Some(v) => v,
        None => crate::xray::reload::config_on_disk_has_ipv4(&state.xray.config_path).await,
    };
    crate::xray::reload::note_live_ipv4(&state, live_ipv4);
    // The process just loaded the rules from the DB-generated config, so a save
    // made while it was stopped is now live — drop the retry/stale markers. Not
    // when the regen failed, though: then it came up on the last-good config and
    // those rules are still only in the database.
    if let Some(cause) = regen_failure {
        // Skipping the clear isn't enough: if the markers happened to be clear
        // (fresh panel process, or a hot apply that succeeded while config.json
        // stayed behind by design) nothing would ever say the live process is
        // running older rules, and every later save would read as a clean one.
        crate::xray::reload::note_routing_left_behind(&state, &cause).await;
    } else {
        crate::xray::reload::note_routing_in_sync(&state).await;
    }
    crate::resync_xray_state(&state).await;
    clear_geo_apply_pending(&state).await;
    Ok(Json(serde_json::json!({ "started": true })))
}

async fn stop(
    _user: AuthUser,
    State(state): State<AppState>,
) -> AppResult<Json<serde_json::Value>> {
    // Same lock as start/restart/install: the kill runs outside the controller's
    // write lock for up to 3s, and `start` gates only on the already-cleared
    // child/pid — so an apply landing in that window would spawn a second xray
    // on the still-held API port.
    let _apply = state.xray_apply.lock().await;
    state.xray.stop().await.map_err(AppError::Internal)?;
    Ok(Json(serde_json::json!({ "stopped": true })))
}

async fn restart(
    _user: AuthUser,
    State(state): State<AppState>,
) -> AppResult<Json<serde_json::Value>> {
    let _apply = state.xray_apply.lock().await;
    // Regenerate the bootstrap config from current xray settings first, so a
    // Freedom/routing strategy change saved via /api/settings applies on this
    // restart (the live process reloads its config.json on start).
    // A regen failure is almost always the operator's own config — a geosite
    // code with a typo, a rule xray won't build — so it is a 400 with what
    // xray actually said, not a 500.
    let has_ipv4 = crate::xray::reload::write_bootstrap_config(&state)
        .await
        .map_err(|e| AppError::BadRequest(format!("{e:#}")))?;
    state.xray.restart().await.map_err(AppError::Internal)?;
    crate::xray::reload::note_live_ipv4(&state, has_ipv4);
    crate::xray::reload::note_routing_in_sync(&state).await;
    crate::resync_xray_state(&state).await;
    clear_geo_apply_pending(&state).await;
    Ok(Json(serde_json::json!({ "restarted": true })))
}

#[derive(Deserialize)]
struct TestOutboundRequest {
    url: String,
}

/// Fetch the operator-supplied URL from the server a few times to confirm the
/// egress reaches the internet. The backend's own network path is the same one
/// xray's `freedom` outbound uses, so a success here means "the box can get
/// out". Returns the HTTP status + the best (minimum) round-trip latency over
/// the attempts; never errors the request itself (a failed fetch is a normal,
/// reportable result).
async fn test_outbound(
    _user: AuthUser,
    Json(req): Json<TestOutboundRequest>,
) -> AppResult<Json<serde_json::Value>> {
    const ATTEMPTS: usize = 4;
    /// Enough for a Cloudflare trace block; anything longer isn't a probe
    /// endpoint and its body is of no use to us.
    const BODY_KEEP: usize = 512;

    // Same validator the settings field uses, so a URL accepted there is
    // accepted here — a prefix-only check lets `http://a b` through and the
    // failure then reads as "no egress" rather than "bad URL".
    let url = crate::api::settings::validate_optional_http_url(&req.url, "test URL")?;
    // That validator is the "optional field" one — empty is valid there and
    // means "unset". Here there is nothing to probe without a URL.
    if url.is_empty() {
        return Err(AppError::BadRequest("test URL is required".to_owned()));
    }
    let url = url.as_str();
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        // Ignore the machine's HTTP(S)_PROXY env, exactly as the `direct`
        // outbound probe does: this button answers "does the SERVER reach the
        // internet", and a system proxy would answer a different question —
        // and disagree with the Outbounds page about the same server.
        .no_proxy()
        .build()
        .map_err(|e| AppError::Internal(anyhow::anyhow!(e)))?;

    // A single GET measures DNS + TCP + TLS + one round-trip, so its latency is
    // dominated by connection setup and isn't representative. Reuse one client
    // (it pools the connection) across a few requests and report the *minimum*:
    // the warm requests skip the handshake, and the min also drops the occasional
    // first packet that upstream filtering holds up.
    let mut best: Option<(u128, reqwest::StatusCode)> = None;
    // Body of the *best* attempt, so the exit IP reported matches the timing
    // reported. Kept short: the endpoints this field offers answer with a trace
    // block or a bare IP, and an unexpected URL shouldn't park a page in memory.
    let mut best_body = String::new();
    let mut last_error: Option<String> = None;
    for _ in 0..ATTEMPTS {
        let started = Instant::now();
        match client.get(url).send().await {
            Ok(resp) => {
                // `send()` resolves on the response headers, so this is the
                // round-trip time, not the body download.
                let ms = started.elapsed().as_millis();
                let status = resp.status();
                // Draining the body also returns the connection to the pool so
                // the next attempt reuses it instead of doing a fresh handshake.
                let body = resp.text().await.unwrap_or_default();
                if best.is_none_or(|(b, _)| ms < b) {
                    best = Some((ms, status));
                    best_body = body.chars().take(BODY_KEEP).collect();
                }
            }
            Err(e) => last_error = Some(e.to_string()),
        }
    }

    match best {
        Some((ms, status)) => {
            // Same parser the per-outbound test uses, so a Cloudflare trace URL
            // yields IP + country and a bare-IP endpoint yields the IP.
            let (exit_ip, exit_loc) = crate::xray::outbound_test::parse_trace(&best_body);
            Ok(Json(serde_json::json!({
                "ok": status.is_success() || status.is_redirection(),
                "status": status.as_u16(),
                "latency_ms": ms,
                "exit_ip": exit_ip,
                "exit_loc": exit_loc,
            })))
        }
        None => Ok(Json(serde_json::json!({
            "ok": false,
            "status": 0,
            "latency_ms": 0,
            "error": last_error.unwrap_or_else(|| "request failed".to_owned()),
        }))),
    }
}

/// Geofile panel: what is on disk, where it should come from, and whether the
/// panel refreshes it on its own. Deliberately separate from `/settings/panel`
/// — this belongs to the xray-updates surface, and folding it into that big
/// row would make every unrelated settings save carry it.
#[derive(serde::Serialize, ts_rs::TS)]
#[ts(export, export_to = "../../frontend/src/api/types/geofiles.ts")]
pub struct GeoPanel {
    /// A preset id, `custom`, or `xray` for "whatever the release archive
    /// installed".
    pub source: String,
    pub custom_geoip_url: String,
    pub custom_geosite_url: String,
    pub auto_update: bool,
    /// RFC 3339 of the last refresh that WROTE something; empty if never.
    pub updated_at: String,
    /// Preset ids this build knows, so the UI can never offer one the backend
    /// would reject.
    pub sources: Vec<String>,
    /// The files on disk are newer than what the running xray parsed — it needs
    /// a restart before the new lists mean anything.
    pub apply_pending: bool,
    pub files: Vec<geo::GeoFileStatus>,
}

/// The stored geo choice. Its own narrow SELECT rather than a field on
/// `PanelSettings`: that struct is fetched by the whole settings page, and the
/// geofile surface has a different lifetime and a different reader.
struct GeoRow {
    source: String,
    custom_geoip: String,
    custom_geosite: String,
    auto: bool,
    updated_at: String,
    apply_pending: bool,
}

async fn read_geo_row(db: &crate::db::DbPool) -> AppResult<GeoRow> {
    let r = sqlx::query!(
        r#"SELECT geo_source             AS "geo_source!: String",
                  geo_custom_geoip_url   AS "geo_custom_geoip_url!: String",
                  geo_custom_geosite_url AS "geo_custom_geosite_url!: String",
                  geo_auto_update        AS "geo_auto_update!: i64",
                  geo_updated_at         AS "geo_updated_at!: String",
                  geo_apply_pending      AS "geo_apply_pending!: i64"
           FROM panel_settings WHERE id = 1"#
    )
    .fetch_one(db)
    .await?;
    Ok(GeoRow {
        source: r.geo_source,
        custom_geoip: r.geo_custom_geoip_url,
        custom_geosite: r.geo_custom_geosite_url,
        auto: r.geo_auto_update != 0,
        updated_at: r.geo_updated_at,
        apply_pending: r.geo_apply_pending != 0,
    })
}

async fn geofiles(_user: AuthUser, State(state): State<AppState>) -> AppResult<Json<GeoPanel>> {
    let row = read_geo_row(&state.db).await?;
    let dir = geo::dir_for_binary(&state.xray.binary);
    Ok(Json(GeoPanel {
        source: row.source,
        custom_geoip_url: row.custom_geoip,
        custom_geosite_url: row.custom_geosite,
        auto_update: row.auto,
        updated_at: row.updated_at,
        sources: geo::SOURCES.iter().map(|s| s.id.to_owned()).collect(),
        apply_pending: row.apply_pending,
        files: geo::status(&dir).await,
    }))
}

#[derive(Deserialize)]
struct GeoSave {
    source: String,
    #[serde(default)]
    custom_geoip_url: String,
    #[serde(default)]
    custom_geosite_url: String,
    #[serde(default)]
    auto_update: bool,
}

async fn save_geofiles(
    user: AuthUser,
    State(state): State<AppState>,
    Json(body): Json<GeoSave>,
) -> AppResult<Json<GeoPanel>> {
    // Validate before storing. A source the updater cannot resolve would turn
    // every later refresh — including the silent nightly one — into a failure
    // the operator would only ever find in the log.
    if body.source != "xray" {
        geo::urls_for(
            &body.source,
            &body.custom_geoip_url,
            &body.custom_geosite_url,
        )
        .map_err(|e| AppError::BadRequest(format!("{e:#}")))?;
    }
    let auto = i64::from(body.auto_update);
    let geoip = body.custom_geoip_url.trim();
    let geosite = body.custom_geosite_url.trim();
    sqlx::query!(
        "UPDATE panel_settings
            SET geo_source = ?, geo_custom_geoip_url = ?, geo_custom_geosite_url = ?,
                geo_auto_update = ?
          WHERE id = 1",
        body.source,
        geoip,
        geosite,
        auto
    )
    .execute(&state.db)
    .await?;
    geofiles(user, State(state)).await
}

#[derive(serde::Serialize, ts_rs::TS)]
#[ts(export, export_to = "../../frontend/src/api/types/geofiles.ts")]
pub struct GeoUpdateResult {
    pub outcomes: Vec<geo::GeoFileOutcome>,
    /// True when at least one file's bytes differed and it was replaced.
    pub changed: bool,
    /// True when xray was running and got restarted to pick the new files up.
    pub restarted: bool,
}

async fn update_geofiles(
    _user: AuthUser,
    State(state): State<AppState>,
) -> AppResult<Json<GeoUpdateResult>> {
    let row = read_geo_row(&state.db).await?;
    let (source, custom_ip, custom_site) = (row.source, row.custom_geoip, row.custom_geosite);
    if source == "xray" {
        return Err(AppError::BadRequest(
            "geofiles currently come from the xray release archive; pick a source to refresh them independently"
                .to_owned(),
        ));
    }
    let (ip_url, site_url) = geo::urls_for(&source, &custom_ip, &custom_site)
        .map_err(|e| AppError::BadRequest(format!("{e:#}")))?;
    // The operator pressed the button, so applying now is what they asked for.
    Ok(Json(
        run_geo_refresh(&state, &ip_url, &site_url, true).await?,
    ))
}

/// Any path that (re)starts xray has just made it re-read `geoip.dat` /
/// `geosite.dat`, so a restart owed for an earlier geofile download is paid —
/// whoever triggered it. Without this the "restart to apply" banner survived an
/// actual restart and kept asking for one.
async fn clear_geo_apply_pending(state: &AppState) {
    if let Err(e) = sqlx::query!("UPDATE panel_settings SET geo_apply_pending = 0 WHERE id = 1")
        .execute(&state.db)
        .await
    {
        tracing::warn!("could not clear the pending geofile apply: {e}");
    }
}

/// Shared by the button and the nightly task: download, replace what differs,
/// record it, and restart xray only if something actually changed.
async fn run_geo_refresh(
    state: &AppState,
    ip_url: &str,
    site_url: &str,
    apply: bool,
) -> AppResult<GeoUpdateResult> {
    // Download OUTSIDE the lock. Two ~20 MB transfers can take minutes, and the
    // same mutex serialises start/stop/restart/install and the boot reconcile —
    // holding it across the network would freeze the panel's whole xray surface
    // for the duration.
    let fetched = geo::fetch(ip_url, site_url)
        .await
        .map_err(AppError::Internal)?;

    // Everything past here is local and quick, so the lock covers exactly what
    // it must: the file swap and the restart that follows it.
    let _guard = state.xray_apply.lock().await;
    let dir = geo::dir_for_binary(&state.xray.binary);
    let outcomes = geo::apply(&dir, &fetched)
        .await
        .map_err(AppError::Internal)?;
    let changed = outcomes.iter().any(|o| o.changed);
    // A restart is owed either because this run wrote new bytes, or because an
    // earlier one did and nobody has applied it yet. Without the second half
    // the banner's Apply button was unreachable: it re-downloads, finds the
    // files identical, and would take no action at all.
    let was_pending = read_geo_row(&state.db).await?.apply_pending;

    let mut restarted = false;
    if changed || was_pending {
        if changed {
            let sha_of = |n: &str| {
                outcomes
                    .iter()
                    .find(|o| o.name == n)
                    .map_or_else(String::new, |o| o.sha256.clone())
            };
            let ip_sha = sha_of(geo::GEOIP);
            let site_sha = sha_of(geo::GEOSITE);
            let now = chrono::Utc::now().to_rfc3339();
            sqlx::query!(
                "UPDATE panel_settings
                    SET geo_geoip_sha = ?, geo_geosite_sha = ?, geo_updated_at = ?
                  WHERE id = 1",
                ip_sha,
                site_sha,
                now
            )
            .execute(&state.db)
            .await?;
        }

        // New bytes on disk mean nothing to a running xray: it parses these at
        // startup and then caches its geo matchers by FILE NAME (see the core's
        // `common/geodata`), so even re-pushing the routing rules reuses the old
        // in-memory lists. Only a restart applies them — and a restart drops
        // every live connection, which is why the nightly path never takes it.
        let running = state.xray.status().await.running;
        if apply && running {
            match state.xray.restart().await {
                Ok(()) => {
                    restarted = true;
                    // The new process starts with EMPTY in-memory handlers: the
                    // bootstrap config carries only the api inbound, and every
                    // user inbound, client and custom outbound lives in xray's
                    // HandlerService, pushed over gRPC. Skipping this took the
                    // whole VPN down until someone restarted xray again by hand.
                    // Mirrors `/xray/restart`.
                    crate::xray::reload::note_routing_in_sync(state).await;
                    crate::resync_xray_state(state).await;
                }
                Err(e) => tracing::warn!("geofiles updated but xray restart failed: {e:#}"),
            }
        }
        // Owed a restart: the files are ahead of what the live process parsed.
        // Not set when xray is down — the next start reads them anyway.
        let pending = i64::from(!restarted && running);
        sqlx::query!(
            "UPDATE panel_settings SET geo_apply_pending = ? WHERE id = 1",
            pending
        )
        .execute(&state.db)
        .await?;
    }
    Ok(GeoUpdateResult {
        outcomes,
        changed,
        restarted,
    })
}

/// Nightly refresh. Off unless the operator turned it on, and the setting is
/// re-read every tick so flipping the switch takes effect without a restart.
pub fn spawn_geofile_updater(state: AppState) {
    tokio::spawn(async move {
        const PERIOD: Duration = Duration::from_hours(24);
        // Wait before the first check so a panel that is crash-looping can
        // never turn into a download loop against someone else's release page.
        tokio::time::sleep(Duration::from_mins(2)).await;
        let mut tick = tokio::time::interval(PERIOD);
        loop {
            tick.tick().await;
            let Ok(row) = read_geo_row(&state.db).await else {
                continue;
            };
            let source = row.source;
            if !row.auto || source == "xray" {
                continue;
            }
            let Ok((ip_url, site_url)) =
                geo::urls_for(&source, &row.custom_geoip, &row.custom_geosite)
            else {
                tracing::warn!("geofile auto-update skipped: source '{source}' does not resolve");
                continue;
            };
            // apply = false: never restart behind the operator's back. The
            // source publishes daily, so applying here would mean a daily
            // disconnect for every user at whatever hour the panel booted.
            match run_geo_refresh(&state, &ip_url, &site_url, false).await {
                Ok(r) if r.changed => {
                    tracing::info!("geofiles auto-updated from '{source}'; restart xray to apply");
                }
                Ok(_) => tracing::debug!("geofiles already current"),
                Err(e) => tracing::warn!("geofile auto-update failed: {e}"),
            }
        }
    });
}
