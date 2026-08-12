//! One way to run the bundled xray CLI.
//!
//! Several things the panel needs are only derivable by the core itself —
//! `vlessenc` keypairs, ECH bundles, the XMC RSA key — and each of them used to
//! carry its own copy of "spawn, check the status, read stdout, guess at what
//! went wrong". They now share this.
//!
//! Two properties matter beyond the deduplication:
//!
//! * These calls run inside axum handlers. `Output::wait` blocks the thread,
//!   and a blocked tokio worker on a single-vCPU VPS is the whole runtime — so
//!   the work goes to `spawn_blocking`.
//! * A child that never exits would hold the request open forever. Every call
//!   gets a deadline; the message says which invocation stalled.

use anyhow::{Context, bail};
use std::ffi::OsStr;
use std::path::Path;
use std::process::Output;
use std::time::Duration;

/// Wall-clock budget for one CLI invocation. These are parse/derive commands
/// measured in the low hundreds of milliseconds, most of it process start —
/// ten seconds means something is wrong, not that we should keep waiting.
pub const CLI_TIMEOUT: Duration = Duration::from_secs(10);

/// Run `xray <args>` off the async runtime and return its stdout.
///
/// Fails with the core's own stderr on a non-zero exit: those messages name
/// the actual problem ("unknown config id: xmc" after a core downgrade), and
/// they are what the operator needs to see instead of a bare 500.
pub async fn run(binary: &Path, args: Vec<String>) -> anyhow::Result<Vec<u8>> {
    let binary = binary.to_path_buf();
    let label = args.join(" ");
    let work = tokio::task::spawn_blocking(move || run_blocking(&binary, &args));
    match tokio::time::timeout(CLI_TIMEOUT, work).await {
        Ok(joined) => joined.context("xray cli task failed")?,
        Err(_) => bail!(
            "`xray {label}` did not finish within {}s",
            CLI_TIMEOUT.as_secs()
        ),
    }
}

/// Blocking half of [`run`], for callers that are already on a blocking thread
/// (and for tests, which have no runtime to hand).
pub fn run_blocking<S: AsRef<OsStr>>(binary: &Path, args: &[S]) -> anyhow::Result<Vec<u8>> {
    let output = invoke(binary, args)?;
    if !output.status.success() {
        bail!(
            "`{} {}` exited with status {}: {}",
            binary.display(),
            args_label(args),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(output.stdout)
}

fn invoke<S: AsRef<OsStr>>(binary: &Path, args: &[S]) -> anyhow::Result<Output> {
    std::process::Command::new(binary)
        .args(args)
        .output()
        .map_err(|e| {
            anyhow::anyhow!(
                "failed to invoke `{} {}`: {e}. Is xray installed at this path?",
                binary.display(),
                args_label(args)
            )
        })
}

fn args_label<S: AsRef<OsStr>>(args: &[S]) -> String {
    args.iter()
        .map(|a| a.as_ref().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}
