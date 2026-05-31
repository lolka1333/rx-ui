use crate::{
    logs::{LogBuffer, LogEntry},
    models::XrayStatus,
};
use chrono::{DateTime, Utc};
use std::{path::PathBuf, process::Stdio, sync::Arc, time::Duration};
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, RefreshKind, System, UpdateKind};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::{Child, ChildStderr, ChildStdout, Command},
    sync::RwLock,
};

#[derive(Clone)]
pub struct XrayController {
    pub binary: PathBuf,
    pub config_path: PathBuf,
    state: Arc<RwLock<XrayState>>,
    /// Where xray's stdout/stderr lines are appended after parsing.
    logs: LogBuffer,
}

#[derive(Default)]
struct XrayState {
    /// Set only when this process spawned xray itself. None when we attached
    /// to an externally-managed PID (systemd, manual launch, prior panel run).
    child: Option<Child>,
    started_at: Option<DateTime<Utc>>,
    pid: Option<u32>,
}

impl XrayController {
    pub fn new(binary: PathBuf, config_path: PathBuf, logs: LogBuffer) -> Self {
        Self {
            binary,
            config_path,
            state: Arc::new(RwLock::new(XrayState::default())),
            logs,
        }
    }

    /// Attach to an already-running xray (matched by absolute binary path)
    /// or spawn one. Called on panel startup so a panel restart doesn't drop
    /// tunnels.
    pub async fn attach_or_start(&self) -> anyhow::Result<()> {
        if let Some(pid) = Self::detect_external_pid_for(&self.binary) {
            let mut state = self.state.write().await;
            state.pid = Some(pid);
            // We don't know the actual launch time of an external process; use
            // attach time as a best-effort hint for the dashboard.
            state.started_at = Some(Utc::now());
            drop(state);
            tracing::info!("attached to existing xray pid {pid}");
            return Ok(());
        }
        self.start().await
    }

    pub async fn start(&self) -> anyhow::Result<()> {
        let mut state = self.state.write().await;
        if state.child.is_some() || state.pid.is_some() {
            anyhow::bail!("xray already running");
        }
        let mut child = Command::new(&self.binary)
            .arg("run")
            .arg("-config")
            .arg(&self.config_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // Intentional: panel restart should NOT kill xray. Drop just detaches.
            .kill_on_drop(false)
            .spawn()?;

        // Drain stdout/stderr line-by-line into the shared log buffer. The
        // tasks finish on their own when the pipes EOF (i.e. xray exits).
        if let Some(stdout) = child.stdout.take() {
            spawn_pipe_reader(stdout, self.logs.clone(), "info");
        }
        if let Some(stderr) = child.stderr.take() {
            // xray writes some non-error output to stderr too; the in-line
            // `[Warning]/[Error]` tag is what actually drives the level.
            spawn_pipe_reader(stderr, self.logs.clone(), "warn");
        }

        state.pid = child.id();
        state.child = Some(child);
        state.started_at = Some(Utc::now());
        // Format Option<u32> rather than substituting 0 for None — pid 0
        // would falsely point at the kernel idle/scheduler process in logs.
        let pid_repr = state.pid.map_or_else(|| "?".to_string(), |p| p.to_string());
        drop(state);

        // xray fails fast on bad config / port-already-in-use (its API
        // dokodemo on 127.0.0.1:62789 collides with any prior orphaned
        // instance that didn't get killed). Without this poll we'd cache a
        // PID that exited 50ms after spawn and the dashboard would lie
        // about xray being up. 800ms is enough to catch the early death
        // without making the happy-path noticeably slower.
        tokio::time::sleep(Duration::from_millis(800)).await;
        let exited_with = {
            let mut state = self.state.write().await;
            let exited = state
                .child
                .as_mut()
                .and_then(|c| c.try_wait().ok().flatten());
            if exited.is_some() {
                // Roll back the lifecycle fields so the next `start()` won't
                // bail with "already running" and so `status()` reports the
                // truth.
                state.child = None;
                state.pid = None;
                state.started_at = None;
            }
            exited
        };
        if let Some(status) = exited_with {
            anyhow::bail!(
                "xray exited immediately ({status}); check `/api/logs` for the xray output (typical cause: API port 62789 already in use by a stale xray instance)"
            );
        }

        tracing::info!(
            "xray started (pid {pid_repr}) with config {}",
            self.config_path.display()
        );
        Ok(())
    }

    pub async fn stop(&self) -> anyhow::Result<()> {
        // Take ALL the lifecycle fields up front, in a single critical
        // section. Earlier versions left `pid`/`started_at` in place during
        // graceful_kill to avoid a 3s "stopped" flicker on the dashboard,
        // but that opened a TOCTOU: a concurrent `start()` could spawn a new
        // process between our drop(state) and the post-kill cleanup, and
        // our cleanup would then overwrite the new pid with None. With a
        // single-admin UI the race is unlikely, but the cost of preventing
        // it (a brief "stopped" flicker while xray is actually shutting
        // down) is much smaller than the cost of a phantom-dead dashboard.
        let (child, pid) = {
            let mut state = self.state.write().await;
            let child = state.child.take();
            let pid = state.pid.take();
            state.started_at = None;
            drop(state);
            (child, pid)
        };

        if let Some(mut child) = child {
            // Owned process: send SIGTERM via sysinfo (so it flushes/closes
            // its sockets), wait for exit, then SIGKILL as a fallback. The
            // .wait() at the end reaps the zombie either way.
            if let Some(child_pid) = child.id() {
                Self::graceful_kill(child_pid).await;
            }
            let _ = child.wait().await;
            tracing::info!("xray stopped (owned child)");
        } else if let Some(pid) = pid {
            Self::kill_external_pid(pid).await?;
            tracing::info!("xray stopped (external pid {pid})");
        }

        Ok(())
    }

    pub async fn restart(&self) -> anyhow::Result<()> {
        // `stop` can fail if xray was already down or the kill timed out;
        // either way we still want to start a fresh process. Log the error
        // instead of swallowing it silently so the operator can correlate
        // a failing restart with the underlying stop problem.
        if let Err(e) = self.stop().await {
            tracing::warn!("xray stop during restart failed; starting anyway: {e}");
        }
        // Give the OS a beat to release the listening sockets.
        tokio::time::sleep(Duration::from_millis(500)).await;
        self.start().await
    }

    pub async fn status(&self) -> XrayStatus {
        let state = self.state.read().await;
        let pid = state.pid;
        let started_at = state.started_at;
        drop(state);

        // For external attachments the Child is None — re-verify the process is
        // alive so the dashboard doesn't lie if xray crashed out from under us.
        let running = pid.is_some_and(Self::pid_alive);

        XrayStatus {
            running,
            pid: if running { pid } else { None },
            version: self.read_version().await.ok(),
            started_at: started_at.map(|d| d.to_rfc3339()),
        }
    }

    pub async fn read_version(&self) -> anyhow::Result<String> {
        let output = Command::new(&self.binary).arg("version").output().await?;
        let text = String::from_utf8_lossy(&output.stdout);
        // First line looks like: "Xray 26.3.27 (Xray, Penetrates Everything.) ..."
        // The dashboard wants a tidy "v26.3.27".
        let first = text.lines().next().unwrap_or("").trim();
        let tag = first.split_whitespace().nth(1).unwrap_or(first);
        Ok(format!("v{tag}"))
    }

    /// Public, name-only entry kept for callers that don't know the full
    /// binary path (e.g. `xray::reload::bootstrap` deciding whether to
    /// attach). Internally we always match by absolute path — see
    /// [`Self::detect_external_pid_for`].
    pub fn detect_external_pid(binary_name: &str) -> Option<u32> {
        // Best-effort wrapper: resolve `binary_name` against CWD-relative
        // `data/xray/<name>` (the panel's default install dir) before
        // falling back to a pure filename comparison. Matches both the
        // self-installed case and a `XRAY_BINARY=/usr/local/bin/xray`
        // override on Linux.
        let candidate = std::path::Path::new("data/xray").join(binary_name);
        if let Some(pid) = Self::detect_external_pid_for(&candidate) {
            return Some(pid);
        }
        Self::detect_external_pid_loose(binary_name)
    }

    /// Strict variant: returns the PID of a running process whose executable
    /// path equals `binary` (after normalisation via `std::path::absolute`).
    /// This is what we want at boot — attaching to *our* xray instance, not
    /// to some unrelated `xray.exe` that lives elsewhere on the host
    /// (e.g. v2rayN's bundled copy under `Downloads/v2rayN-...`).
    pub fn detect_external_pid_for(binary: &std::path::Path) -> Option<u32> {
        let target = std::path::absolute(binary).ok()?;
        let mut sys = System::new_with_specifics(RefreshKind::nothing());
        // BOTH `with_cmd` and `with_exe` need to be enabled — without
        // `with_exe`, sysinfo doesn't query the executable path and
        // `Process::exe()` returns `None` for every process, making the
        // strict match below silently miss our xray every time.
        sys.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::nothing()
                .with_cmd(UpdateKind::Always)
                .with_exe(UpdateKind::Always),
        );
        sys.processes().iter().find_map(|(pid, p)| {
            // Prefer `exe()` (the kernel-reported binary path). If it's
            // None — usually a permissions issue on Windows when a process
            // was started by a different user — fall back to cmd[0],
            // which is the argv[0] the process was launched with.
            let exe_path = p.exe().map(std::path::PathBuf::from).or_else(|| {
                p.cmd()
                    .first()
                    .map(|s| std::path::PathBuf::from(s.to_string_lossy().into_owned()))
            })?;
            let exe_abs = std::path::absolute(&exe_path).ok()?;
            (exe_abs == target).then_some(pid.as_u32())
        })
    }

    /// Loose filename-only match. Used only as a fallback when the strict
    /// path-based check returned None (e.g. binary path canonicalisation
    /// failed). Skips processes whose exe path lives outside our install
    /// directory so we don't accidentally adopt v2rayN's xray and start
    /// `SIGKILLing` it on stop.
    fn detect_external_pid_loose(binary_name: &str) -> Option<u32> {
        let mut sys = System::new_with_specifics(RefreshKind::nothing());
        sys.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::nothing()
                .with_cmd(UpdateKind::Always)
                .with_exe(UpdateKind::Always),
        );
        let cwd = std::env::current_dir().ok()?;
        sys.processes().iter().find_map(|(pid, p)| {
            let exe = p.exe()?;
            let file = exe.file_name()?.to_string_lossy();
            if file != binary_name {
                return None;
            }
            // Only adopt if the process lives under our CWD — avoids
            // hijacking unrelated xray installs on the same host.
            let abs = std::path::absolute(exe).ok()?;
            abs.starts_with(&cwd).then_some(pid.as_u32())
        })
    }

    fn pid_alive(pid: u32) -> bool {
        let mut sys = System::new();
        sys.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[Pid::from_u32(pid)]),
            true,
            ProcessRefreshKind::nothing(),
        );
        sys.process(Pid::from_u32(pid)).is_some()
    }

    async fn kill_external_pid(pid: u32) -> anyhow::Result<()> {
        Self::graceful_kill(pid).await;
        if Self::pid_alive(pid) {
            anyhow::bail!("xray pid {pid} survived SIGTERM + SIGKILL");
        }
        Ok(())
    }

    /// Try to stop a process gracefully (SIGTERM on Unix), polling for exit
    /// up to ~3s, then fall back to SIGKILL. On Windows there's no portable
    /// SIGTERM equivalent — `TerminateProcess` is already roughly SIGKILL —
    /// so this collapses to a single forceful kill on that platform. Always
    /// completes (no error path): the caller verifies with `pid_alive`.
    // `async` is required for the Unix poll loop (tokio::time::sleep). On
    // Windows the `#[cfg(unix)]` block compiles out, leaving zero awaits —
    // clippy then sees an "unused async" we accept on purpose.
    #[allow(clippy::unused_async)]
    async fn graceful_kill(pid: u32) {
        let pid_obj = Pid::from_u32(pid);
        // Single sysinfo::System for the whole operation. The process handle
        // returned by sys.process() borrows from `sys`, so on Unix where we
        // poll between SIGTERM and SIGKILL we have to re-refresh before the
        // fallback — but we don't have to build a new System.
        let mut sys = System::new();
        sys.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[pid_obj]),
            true,
            ProcessRefreshKind::nothing(),
        );

        #[cfg(unix)]
        if let Some(proc) = sys.process(pid_obj)
            && proc.kill_with(sysinfo::Signal::Term) == Some(true)
        {
            // xray on a clean shutdown returns within sub-second; cap
            // the wait at 3s so a hung process doesn't stall stop().
            for _ in 0..30 {
                tokio::time::sleep(Duration::from_millis(100)).await;
                if !Self::pid_alive(pid) {
                    return;
                }
            }
            // SIGTERM didn't take — re-refresh so the SIGKILL fallback below
            // sees the current process state (or `None` if it just exited).
            sys.refresh_processes_specifics(
                ProcessesToUpdate::Some(&[pid_obj]),
                true,
                ProcessRefreshKind::nothing(),
            );
        }

        // SIGKILL fallback (always taken on Windows, taken on Unix only if
        // SIGTERM didn't land or the process refused to exit within the
        // grace window).
        if let Some(proc) = sys.process(pid_obj) {
            proc.kill();
        }
    }
}

/// Trait so `spawn_pipe_reader` can take either stdout or stderr.
trait AsyncReadSend: tokio::io::AsyncRead + Send + Unpin + 'static {}
impl AsyncReadSend for ChildStdout {}
impl AsyncReadSend for ChildStderr {}

/// Drain a process pipe into the panel's log buffer, one entry per line.
/// `fallback_level` is used when xray prints a line without a recognizable
/// `[Info]/[Warning]/[Error]` tag (stdout defaults to info, stderr to warn).
fn spawn_pipe_reader<R: AsyncReadSend>(pipe: R, logs: LogBuffer, fallback_level: &'static str) {
    tokio::spawn(async move {
        let mut lines = BufReader::new(pipe).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            if line.is_empty() {
                continue;
            }
            logs.push(parse_xray_line(&line, fallback_level));
        }
    });
}

/// Convert one xray output line into a `LogEntry`. xray prints lines like:
///   2026/05/15 07:52:55 [Warning] core: Xray 26.4.25 started
/// We strip the timestamp (we use our own UTC ISO one) and pull the level
/// from the `[Tag]` if present.
fn parse_xray_line(line: &str, fallback_level: &str) -> LogEntry {
    let mut level = fallback_level.to_string();
    let mut message = line.to_string();

    // Find `[Level]` anywhere in the line (xray puts it after the timestamp).
    if let Some(start) = line.find('[')
        && let Some(end_rel) = line[start..].find(']')
    {
        let raw = &line[start + 1..start + end_rel];
        let lower = raw.to_ascii_lowercase();
        let normalized = match lower.as_str() {
            "warning" => Some("warn"),
            "info" | "warn" | "error" | "debug" => Some(lower.as_str()),
            _ => None,
        };
        if let Some(lvl) = normalized {
            level = lvl.to_string();
            // Trim "<timestamp> [Level]" prefix from the message; what's left
            // is "core: Xray 26.4.25 started" — already nicely target-prefixed.
            message = line[start + end_rel + 1..].trim().to_string();
        }
    }

    LogEntry {
        timestamp: Utc::now().to_rfc3339(),
        level,
        target: "xray".to_string(),
        message,
    }
}
