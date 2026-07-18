//! Boot-time xray reconciliation.
//!
//! The on-disk config.json is a tiny static bootstrap (see
//! `config_gen::build_bootstrap_config`): just the API dokodemo-door
//! inbound, a freedom outbound, and the routing rule pinning the api
//! inbound to the api outbound. User-facing inbounds are pushed into
//! the running xray dynamically via `HandlerService.AddInbound` (the
//! `xray::grpc` client).
//!
//! This module's job: ensure binary is installed → ensure a valid
//! bootstrap config sits on disk → start (or attach to) the xray
//! process. Runtime CRUD against inbounds happens in `xray::grpc`.

use crate::{
    AppState,
    xray::{config_gen, control::XrayController, installer},
};

/// Boot-time reconciliation: if xray is already running (systemd, a prior
/// panel session, or an externally-managed install) we attach to it.
/// Otherwise we install the binary if missing, lay down the bootstrap config,
/// and start the process.
pub async fn bootstrap(state: &AppState) -> anyhow::Result<()> {
    // Match by absolute path so we never adopt an unrelated xray.exe that
    // happens to live elsewhere on the host (e.g. v2rayN's bundled copy
    // under `Downloads/v2rayN-...`) — taking that over would mean we'd
    // SIGKILL the user's separate VPN client on stop.
    if XrayController::detect_external_pid_for(&state.xray.binary).is_some() {
        state.xray.attach_or_start().await?;
        // We didn't write this process's config, so read what it actually
        // loaded — otherwise the hot routing path would assume no `direct-ipv4`
        // and force a needless restart on the first routing save.
        note_live_ipv4(
            state,
            config_on_disk_has_ipv4(&state.xray.config_path).await,
        );
        // The adopted process started from whatever config.json was on disk,
        // which can predate rules that were applied hot after it was written
        // (panel restart, host reboot under systemd, an operator starting xray
        // by hand). Re-push the current set so the live router matches the DB.
        // Idempotent: a full-replace that re-emits the api pin.
        //
        // Spawned, not awaited: boot must not block on xray. The push waits up
        // to 5s for a channel and can end in a restart, and the panel has to
        // serve /api (login, logs, xray controls) even when xray is unhealthy —
        // bootstrap runs before the listener binds.
        let bg = state.clone();
        tokio::spawn(async move { hot_apply_routing(&bg).await });
        return Ok(());
    }

    // First-run convenience: if xray isn't installed and the user hasn't
    // pointed XRAY_BINARY at a system install, fetch the latest stable
    // release from GitHub. Skipped silently when the env var was set — the
    // user clearly wants to manage xray themselves.
    if !state.xray.binary.exists() {
        if std::env::var_os("XRAY_BINARY").is_some() {
            anyhow::bail!(
                "xray binary not found at {} (set via XRAY_BINARY)",
                state.xray.binary.display()
            );
        }
        if let Some(install_dir) = state.xray.binary.parent() {
            tracing::info!("xray not found, fetching latest stable from github…");
            let release = installer::fetch_latest_stable(installer::DEFAULT_REPO).await?;
            installer::install_release(&release, install_dir).await?;
            tracing::info!(
                "xray {} installed at {}",
                release.tag,
                state.xray.binary.display()
            );
        }
    }

    let has_ipv4 = write_bootstrap_config(state).await?;
    state.xray.start().await?;
    note_live_ipv4(state, has_ipv4);
    Ok(())
}

/// Regenerate the bootstrap config from the operator's current xray
/// settings (Freedom + routing `domainStrategy`) and write it to disk,
/// validated. Called at boot and before every xray restart, so a change
/// to those settings is picked up the next time xray loads its config.
/// Returns whether the config just written declares the `direct-ipv4` outbound.
/// Callers commit that into `live_ipv4_outbound` only AFTER the process actually
/// starts on it — the flag means "the live process has this outbound", and
/// writing a file the process never loads must not change it.
pub async fn write_bootstrap_config(state: &AppState) -> anyhow::Result<bool> {
    let settings = load_bootstrap_settings(state).await?;
    let value = config_gen::build_bootstrap_config(&settings);
    config_gen::write_config_validated(&state.xray.binary, &state.xray.config_path, &value).await?;
    Ok(config_gen::needs_ipv4_outbound(&settings))
}

/// Record that a process which just came up loaded a config with (or without)
/// the `direct-ipv4` outbound.
pub fn note_live_ipv4(state: &AppState, has_ipv4: bool) {
    state
        .live_ipv4_outbound
        .store(has_ipv4, std::sync::atomic::Ordering::Relaxed);
}

/// Whether the config.json currently on disk — the one a running xray loaded —
/// declares the `direct-ipv4` outbound. Used on the attach path, where the panel
/// didn't write the config itself.
pub async fn config_on_disk_has_ipv4(path: &std::path::Path) -> bool {
    let Ok(text) = tokio::fs::read_to_string(path).await else {
        return false;
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
        return false;
    };
    value["outbounds"]
        .as_array()
        .is_some_and(|obs| obs.iter().any(|o| o["tag"] == config_gen::TAG_DIRECT_IPV4))
}

/// Read the operator's current xray-affecting settings from the DB into a
/// `BootstrapSettings`. Shared by the bootstrap writer (restart path) and the
/// live hot-apply path (`RoutingService.AddRule`), so both see the same state.
pub async fn load_bootstrap_settings(
    state: &AppState,
) -> anyhow::Result<config_gen::BootstrapSettings> {
    let row = sqlx::query!(
        "SELECT xray_freedom_strategy, xray_routing_strategy, xray_block_bittorrent,
                xray_blocked_ips, xray_blocked_domains, xray_ipv4_domains,
                xray_custom_rules, xray_rule_order
            FROM panel_settings WHERE id = 1"
    )
    .fetch_one(&state.db)
    .await?;
    // The JSON columns degrade to an empty value on a parse failure (e.g. a
    // hand-edited DB) rather than refusing to boot xray.
    let parse = |s: &str| serde_json::from_str::<Vec<String>>(s).unwrap_or_default();
    let custom_rules: Vec<crate::models::RoutingRule> =
        serde_json::from_str(&row.xray_custom_rules).unwrap_or_default();
    // A reverse bridge makes `direct` need explicit `finalRules` — xray blocks
    // tunnelled traffic by default. Read from the same source the orchestrator
    // pushes from, so the bootstrap matches what actually gets added.
    let has_reverse_bridge = crate::api::outbounds::load_custom_outbounds(&state.db)
        .await
        .unwrap_or_default()
        .iter()
        .any(|ob| {
            ob.enabled
                && matches!(&ob.protocol, crate::models::OutboundProtocolConfig::Vless(v)
                    if !v.reverse_tag.trim().is_empty())
        });
    Ok(config_gen::BootstrapSettings {
        freedom_strategy: row.xray_freedom_strategy,
        routing_strategy: row.xray_routing_strategy,
        block_bittorrent: row.xray_block_bittorrent != 0,
        blocked_ips: parse(&row.xray_blocked_ips),
        blocked_domains: parse(&row.xray_blocked_domains),
        ipv4_domains: parse(&row.xray_ipv4_domains),
        has_reverse_bridge,
        custom_rules,
        rule_order: parse(&row.xray_rule_order),
    })
}

/// What actually happened to the rules the operator just saved. They are
/// persisted either way — this says whether the LIVE router is running them,
/// so the save response can stop claiming success it didn't achieve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoutingApply {
    /// Pushed into the running router. No restart, connections survived.
    Applied,
    /// xray isn't running; the rules load from the config on the next start.
    Deferred,
    /// The push couldn't be used, so xray was restarted onto the new config.
    /// The rules ARE live; the operator's connections dropped to get there.
    Restarted,
    /// The rules are saved but the live router still runs the previous set.
    NotLive {
        /// For the operator, so it must name the actual cause.
        detail: String,
        /// Whether trying the same push again could succeed on its own. A DB
        /// blip or an xray that wasn't listening will clear up; a rule set xray
        /// refuses to build will not, no matter how many times it is pushed.
        /// This is what stops a permanently-bad rule from restarting xray on
        /// every unrelated save the operator makes afterwards.
        retryable: bool,
    },
}

impl RoutingApply {
    /// Why the rules aren't live, for the operator. Every non-live outcome has
    /// one — a bare "not applied" with no reason is the thing this whole path
    /// exists to avoid.
    pub fn detail(&self) -> Option<String> {
        match self {
            Self::Applied | Self::Restarted => None,
            Self::Deferred => Some("xray is not running; the rules load when it starts".into()),
            Self::NotLive { detail, .. } => Some(detail.clone()),
        }
    }

    /// The router is stale for a reason that can clear on its own — the next
    /// push may well succeed without the operator changing anything.
    fn transient(detail: impl Into<String>) -> Self {
        Self::NotLive {
            detail: detail.into(),
            retryable: true,
        }
    }

    /// The router is stale for a reason that will not clear on its own: pushing
    /// the same stored rules again produces the same refusal, and each attempt
    /// costs a recovery restart. Waits for the operator to edit the rules, which
    /// re-opens the normal change-gated path.
    fn permanent(detail: impl Into<String>) -> Self {
        Self::NotLive {
            detail: detail.into(),
            retryable: false,
        }
    }

    /// Whether the panel should push again by itself on the next save, even one
    /// that changes nothing routing-related.
    ///
    /// Only for failures that can resolve without the operator: a stale router
    /// caused by a rule xray refuses is NOT one of them — re-pushing sends the
    /// identical bad set, which xray refuses again, which costs a recovery
    /// restart and drops every connection. That would turn one broken rule into
    /// a restart on every later save. When the operator edits the rules the
    /// normal change-gate fires anyway, so nothing is lost by waiting for them.
    pub const fn worth_retrying(&self) -> bool {
        match self {
            Self::Applied | Self::Restarted => false,
            Self::Deferred => true,
            Self::NotLive { retryable, .. } => *retryable,
        }
    }

    /// Whether getting here cost a restart. `Applied` and `Restarted` are both
    /// "the rules are live", but only one of them dropped every connection to
    /// do it — reporting them identically would let the UI tell an operator no
    /// restart was needed moments after their tunnels went down.
    pub const fn dropped_connections(&self) -> bool {
        matches!(self, Self::Restarted)
    }
}

/// Apply the current routing rules to a LIVE xray via `RoutingService.AddRule`
/// (no restart). No-op when xray isn't running (the next start picks them up
/// from bootstrap).
///
/// CRITICAL failure handling: `AddRule(shouldAppend=false)` is a full-replace,
/// and xray WIPES the entire rule set if any rule in the pushed config fails to
/// build (e.g. a bad geosite code, or geosite.dat missing) — which also drops
/// the api-pin rule and severs the panel↔xray control channel. So if the hot
/// push fails, we don't leave xray half-configured: we restart it, which
/// reloads a validated bootstrap config (or the last-good config.json if the
/// new one fails `xray -test`), restoring the api pin. Rules are already
/// persisted, so nothing is lost.
pub async fn hot_apply_routing(state: &AppState) -> RoutingApply {
    let outcome = apply_routing(state).await;
    // Whether to push again by ourselves on the next save…
    state.routing_out_of_sync.store(
        outcome.worth_retrying(),
        std::sync::atomic::Ordering::Relaxed,
    );
    // …and, separately, whether the router is stale at all. A rule xray refuses
    // is not worth re-pushing (each attempt costs a recovery restart) but IS
    // still stale, and every save until the operator fixes it has to say so
    // rather than report a clean success.
    *state.routing_stale.write().await = outcome.detail();
    outcome
}

/// Record that a (re)start came up on the LAST-GOOD config because the regen
/// failed: the process is healthy, but the rules the operator saved may still
/// be only in the database. Marks stale WITHOUT setting the retry flag — a
/// failed regen is not self-healing, and re-pushing on every later save would
/// buy a recovery restart each time for the same refusal.
///
/// "may": we can't know whether the un-regenerated file already matched the DB
/// (the hot path deliberately never rewrites it, so usually it doesn't). Erring
/// towards warning is the safe direction — the opposite error is the silent
/// success this whole path exists to prevent — and one /xray/restart clears it.
pub async fn note_routing_left_behind(state: &AppState, cause: &str) {
    *state.routing_stale.write().await = Some(format!(
        "xray started on the last-good config; the saved rules may not be live: {cause}"
    ));
}

/// Record that a (re)start loaded the rules straight from the DB-generated
/// config, so the live router is in step again — nothing to retry, nothing to
/// warn about. Without this a save made while xray was stopped would leave both
/// markers set forever, and the next unrelated save would re-push rules that
/// are already live.
pub async fn note_routing_in_sync(state: &AppState) {
    state
        .routing_out_of_sync
        .store(false, std::sync::atomic::Ordering::Relaxed);
    *state.routing_stale.write().await = None;
}

async fn apply_routing(state: &AppState) -> RoutingApply {
    // Serialise against the /xray start|restart|install handlers and any other
    // apply in flight: the recovery path stops and starts the process, and an
    // interleaved start would spawn a second xray on the still-held API port.
    let _apply = state.xray_apply.lock().await;
    if !state.xray.status().await.running {
        tracing::debug!("hot routing: xray not running, rules will apply on next start");
        return RoutingApply::Deferred;
    }
    let settings = match load_bootstrap_settings(state).await {
        Ok(s) => s,
        // Can't read the intended state — leave the live rules as they are
        // rather than push a wrong set or restart on a transient DB error.
        Err(e) => {
            tracing::warn!("hot routing: load settings failed: {e}");
            return RoutingApply::transient(format!("could not read the saved settings: {e}"));
        }
    };
    // `direct-ipv4` is created ONLY by the bootstrap config (at restart) — the
    // hot path never AddOutbounds it. If the rules need it but the running
    // process was started without it, a pushed rule would point at a missing
    // outbound and xray would drop that traffic, so restart to rebuild the
    // outbound set. When the live process already has it (the steady state for
    // an IPv4-force operator), keep applying hot.
    if config_gen::needs_ipv4_outbound(&settings)
        && !state
            .live_ipv4_outbound
            .load(std::sync::atomic::Ordering::Relaxed)
    {
        return rebuild_and_restart(
            state,
            "hot routing: rules need the direct-ipv4 outbound the live process lacks",
            false,
        )
        .await;
    }
    let config = match crate::xray::router_rules::build_router_config(&settings) {
        Ok(c) => c,
        // Nothing was sent, so the live rule set is intact — log and leave it
        // alone rather than restart for no reason.
        Err(e) => {
            tracing::warn!("hot routing: build config failed, live rules left as-is: {e}");
            return RoutingApply::permanent(format!("the rules could not be built: {e}"));
        }
    };
    let Err(err) = state.xray_client.replace_routing_rules(config).await else {
        return RoutingApply::Applied;
    };
    // Decision and explanation come from one match on the error, so neither the
    // recovery nor the wording can drift from what the failure actually means.
    // Unsupported: the live process predates RoutingService (an in-place panel
    // upgrade), so no push will ever land and it has to be restarted onto a
    // regenerated config. Rejected: AddRule(shouldAppend=false) clears the rule
    // set BEFORE building, so the router is now empty, api pin included.
    let Some((rules_wiped, cause)) = err.recovery() else {
        // The request never got out; the live router still has its old (valid)
        // rules, so restarting would be downtime for nothing.
        tracing::warn!("hot routing: xray unreachable, live rules left as-is: {err}");
        return RoutingApply::transient(format!("xray did not answer: {err}"));
    };
    rebuild_and_restart(state, &format!("hot routing: {cause} ({err})"), rules_wiped).await
    // Deliberately NOT rewriting config.json here: it would cost an
    // `xray run -test` subprocess (which loads geosite/geoip) on every save.
    // Every PANEL-mediated start regenerates the config from the DB first
    // (/start, /restart, the binary updater, rebuild_and_restart, boot), so
    // those never load a stale file. A process started outside the panel
    // (systemd, an operator by hand) can, which is why `bootstrap`'s attach
    // branch re-pushes the current rules after adopting one.
}

/// Regenerate the bootstrap config, restart xray, and re-push inbounds/outbounds.
///
/// `reason` is logged so a restart is never unattributable — an operator seeing
/// their tunnels drop has to be able to find out why from the log alone.
///
/// `rules_wiped` decides what to do when the regen itself fails (bad geosite
/// code, `xray -test` rejection, unwritable disk), which leaves the last-good
/// `config.json` on disk. If xray already cleared its rule set we MUST restart
/// anyway — even a stale config restores the api pin, without which the panel
/// loses its control channel. If nothing was wiped, the live rules are still
/// serving traffic and a restart onto a config we couldn't regenerate would be
/// downtime that changes nothing, so we keep the process running instead.
async fn rebuild_and_restart(state: &AppState, reason: &str, rules_wiped: bool) -> RoutingApply {
    let written = write_bootstrap_config(state).await;
    if let Err(e) = &written {
        if !rules_wiped {
            tracing::error!("{reason}: config regen failed, keeping the live process as-is: {e:#}");
            return RoutingApply::permanent(format!("{e:#}"));
        }
        tracing::error!("{reason}: config regen failed, restarting on the last-good config: {e:#}");
    } else {
        tracing::warn!("{reason}: restarting xray on a regenerated config");
    }
    let restarted = state.xray.restart().await;
    // Only claim the new config is live once the process actually came up on
    // it; a failed restart leaves the old one running.
    if let (Ok(has_ipv4), Ok(())) = (&written, &restarted) {
        note_live_ipv4(state, *has_ipv4);
    }
    if let Err(e) = &restarted {
        tracing::error!("recovery restart after hot routing apply failed: {e}");
    }
    crate::resync_xray_state(state).await;
    match (&written, &restarted) {
        (Ok(_), Ok(())) => RoutingApply::Restarted,
        // The process came back, but on the LAST-GOOD config — the rules the
        // operator just saved are stored and not in effect. Saying "restarted"
        // here would be the same lie in a new place.
        (Err(e), Ok(())) => RoutingApply::permanent(format!("{e:#}")),
        (_, Err(e)) => RoutingApply::transient(format!("xray did not come back up: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::RoutingApply;

    /// The flag this drives decides whether an UNRELATED later save re-pushes
    /// the rules. Retrying a set xray refuses is not just useless — the refusal
    /// costs a recovery restart, so it would drop every connection on each save
    /// the operator makes until they fix the rule. Only outcomes that can clear
    /// up on their own are worth retrying.
    #[test]
    fn only_self_healing_failures_are_retried() {
        assert!(!RoutingApply::Applied.worth_retrying());
        assert!(!RoutingApply::Restarted.worth_retrying());
        // xray is down; starting it is exactly what makes this succeed.
        assert!(RoutingApply::Deferred.worth_retrying());
        assert!(RoutingApply::transient("xray did not answer").worth_retrying());
        // A rule set that doesn't build produces the identical failure forever.
        assert!(!RoutingApply::permanent("the rules could not be built").worth_retrying());
        // Either kind still has to explain itself — being un-retryable is not a
        // reason to stop telling the operator the router is behind.
        assert!(RoutingApply::permanent("boom").detail().is_some());
        assert!(RoutingApply::transient("boom").detail().is_some());
    }

    /// Only a restart dropped connections, and the UI wording hangs off this.
    #[test]
    fn only_a_restart_reports_dropped_connections() {
        assert!(RoutingApply::Restarted.dropped_connections());
        assert!(!RoutingApply::Applied.dropped_connections());
        assert!(!RoutingApply::Deferred.dropped_connections());
    }

    /// Every non-live outcome must carry a reason; a bare "not applied" is the
    /// silent failure this whole path exists to prevent.
    #[test]
    fn every_non_live_outcome_explains_itself() {
        assert!(RoutingApply::Applied.detail().is_none());
        assert!(RoutingApply::Restarted.detail().is_none());
        assert!(
            RoutingApply::Deferred
                .detail()
                .is_some_and(|d| !d.is_empty())
        );
        assert!(
            RoutingApply::permanent("boom")
                .detail()
                .is_some_and(|d| d.contains("boom"))
        );
    }
}
