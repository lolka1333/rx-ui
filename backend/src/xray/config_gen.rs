//! Bootstrap xray config.json generator.
//!
//! Produces the *static* config xray needs to come up with a working
//! `HandlerService` API listener. User-facing inbounds are NOT written
//! here — they are pushed into the running xray dynamically via
//! `HandlerService.AddInbound`. This file is therefore deliberately
//! tiny: only what xray refuses to start without.
//!
//! The validate-then-atomic-rename helper (`write_config_validated`)
//! is kept because boot still runs `xray run -test` on the bootstrap
//! config before handing it to the live process.

use serde_json::{Value, json};
use std::path::Path;
use tokio::{fs, io::AsyncWriteExt, process::Command};

/// Build the bootstrap xray config. Minimum needed for a working
/// `HandlerService` + `StatsService` gRPC, plus a default outbound:
///
///   * `log.loglevel=warning`: xray emits HTTP/2 client-side cancels
///     (`stream error: stream ID N; CANCEL`) at INFO, one line per
///     dropped stream — a chatty noise floor that buries any real
///     event. The diagnostics we actually care about (Reality
///     handshake failures, TLS errors, real outbound failures) are
///     all WARN/ERROR, so `warning` keeps the signal and drops the
///     noise. `AddInbound` results are surfaced through the gRPC
///     response, not the log stream, so they're unaffected.
///   * `api` + dokodemo-door inbound on 127.0.0.1:62789: the gRPC entry
///     point. `HandlerService` for runtime inbound/user CRUD,
///     `StatsService` for the per-user traffic + online counters
///     surfaced on the Clients page.
///   * `stats: {}` + `policy.levels.0.statsUser*`: xray collects per-
///     user uplink / downlink / online counters only when the policy
///     opt-in is set. Without these the `StatsService` RPCs return empty.
///   * one `freedom` outbound: every dynamically-added inbound needs
///     somewhere to forward traffic to.
///   * one routing rule pinning the api inbound to the api outbound;
///     without it API calls fall through to `freedom` and bounce.
pub fn build_bootstrap_config() -> Value {
    json!({
        "log": { "loglevel": "warning", "access": "" },
        "api": { "tag": "api", "services": ["HandlerService", "StatsService"] },
        "stats": {},
        "policy": {
            "levels": {
                "0": {
                    "statsUserUplink": true,
                    "statsUserDownlink": true,
                    "statsUserOnline": true
                }
            }
        },
        "inbounds": [{
            "tag": "api",
            "listen": "127.0.0.1",
            "port": 62789,
            "protocol": "dokodemo-door",
            "settings": { "address": "127.0.0.1" }
        }],
        "outbounds": [{ "tag": "direct", "protocol": "freedom" }],
        "routing": {
            "rules": [{ "type": "field", "inboundTag": ["api"], "outboundTag": "api" }]
        }
    })
}

/// Atomically write `value` to `path` after validating it via `xray run -test`.
/// If validation fails the tmp file is removed and the existing `path` is left
/// untouched, so the panel never overwrites a working config with a broken one.
pub async fn write_config_validated(
    binary: &Path,
    path: &Path,
    value: &Value,
) -> anyhow::Result<()> {
    let tmp = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(value)?;
    {
        let mut f = fs::File::create(&tmp).await?;
        f.write_all(&bytes).await?;
        f.sync_all().await?;
    }

    // -format json: xray normally infers from extension (.json/.yaml/.toml)
    // but we hand it a .tmp file, so be explicit.
    let output = Command::new(binary)
        .arg("run")
        .arg("-test")
        .arg("-format")
        .arg("json")
        .arg("-config")
        .arg(&tmp)
        .output()
        .await;

    let output = match output {
        Ok(o) => o,
        Err(e) => {
            let _ = fs::remove_file(&tmp).await;
            anyhow::bail!("failed to invoke xray for config validation: {e}");
        }
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let _ = fs::remove_file(&tmp).await;
        anyhow::bail!(
            "xray rejected config: {}",
            // xray prints the failure to stderr; some builds use stdout.
            if stderr.trim().is_empty() {
                stdout.trim().to_string()
            } else {
                stderr.trim().to_string()
            }
        );
    }

    fs::rename(&tmp, path).await?;
    tracing::info!("xray config validated and written: {}", path.display());
    Ok(())
}
