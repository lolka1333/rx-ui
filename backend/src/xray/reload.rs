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
            let release = installer::fetch_latest_stable().await?;
            installer::install_release(&release, install_dir).await?;
            tracing::info!(
                "xray {} installed at {}",
                release.tag,
                state.xray.binary.display()
            );
        }
    }

    let value = config_gen::build_bootstrap_config();
    config_gen::write_config_validated(&state.xray.binary, &state.xray.config_path, &value).await?;
    state.xray.start().await
}
