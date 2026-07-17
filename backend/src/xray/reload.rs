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

    write_bootstrap_config(state).await?;
    state.xray.start().await
}

/// Regenerate the bootstrap config from the operator's current xray
/// settings (Freedom + routing `domainStrategy`) and write it to disk,
/// validated. Called at boot and before every xray restart, so a change
/// to those settings is picked up the next time xray loads its config.
pub async fn write_bootstrap_config(state: &AppState) -> anyhow::Result<()> {
    let settings = load_bootstrap_settings(state).await?;
    let value = config_gen::build_bootstrap_config(&settings);
    config_gen::write_config_validated(&state.xray.binary, &state.xray.config_path, &value).await
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
pub async fn hot_apply_routing(state: &AppState) {
    if !state.xray.status().await.running {
        return;
    }
    if push_routing_rules(state).await {
        return; // applied cleanly on the live process — no restart, no drops
    }
    tracing::warn!("hot routing apply failed; restarting xray to restore a consistent rule set");
    let _ = write_bootstrap_config(state).await;
    if let Err(e) = state.xray.restart().await {
        tracing::error!("recovery restart after failed hot routing apply failed: {e}");
    }
    crate::resync_xray_state(state).await;
}

/// Build the full ordered rule set and push it via `AddRule`. Returns whether
/// the live push succeeded; the caller handles recovery on `false`.
async fn push_routing_rules(state: &AppState) -> bool {
    let settings = match load_bootstrap_settings(state).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("hot routing: load settings failed: {e}");
            return false;
        }
    };
    let config = match crate::xray::router_rules::build_router_config(&settings) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("hot routing: build config failed: {e}");
            return false;
        }
    };
    match state.xray_client.replace_routing_rules(config).await {
        Ok(()) => true,
        Err(e) => {
            tracing::warn!("hot routing: AddRule failed: {e}");
            false
        }
    }
}
