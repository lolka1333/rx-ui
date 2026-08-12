//! Short-lived private directories under the system temp dir.
//!
//! Two paths hand a throwaway config to an xray subprocess — the XMC key
//! derivation and the outbound connectivity test — and both want the same
//! three properties: a path no other user can pre-create (a predictable name
//! in a shared temp dir is a symlink-clobber invitation on a multi-user box),
//! 0700 so the contents stay with the panel's own user, and removal on the way
//! out no matter which branch returns.
//!
//! Not worth a `tempfile` dependency: the directory lives for the length of
//! one subprocess and the name is unique per process and instant, so two
//! concurrent callers cannot collide.

use anyhow::Context;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Directories left behind when `Drop` never ran (SIGKILL, OOM, power loss).
/// Swept opportunistically on each create; anything younger than this may
/// belong to a run happening right now, in this process or another instance.
const STALE_AGE: Duration = Duration::from_hours(1);

/// Every directory this module creates starts with it, which is also what the
/// sweeper matches on — so a stray entry is always ours.
const PREFIX: &str = "rx-";

pub struct ScratchDir(PathBuf);

impl ScratchDir {
    /// Create `<temp>/rx-<kind>-<pid>-<nanos>/`, private to this user.
    pub fn new(kind: &str) -> anyhow::Result<Self> {
        let temp = std::env::temp_dir();
        sweep_stale(&temp);
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        let path = temp.join(format!("{PREFIX}{kind}-{}-{stamp}", std::process::id()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&path)
        }
        #[cfg(not(unix))]
        { std::fs::create_dir_all(&path) }
            .with_context(|| format!("create scratch dir for {kind}"))?;
        Ok(Self(path))
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        // Best-effort: a leftover directory in temp is not worth failing an
        // operation that has otherwise succeeded.
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Remove long-abandoned scratch directories. Best-effort throughout: this
/// runs on a request path, and a temp file we cannot delete is not a reason to
/// fail the request.
fn sweep_stale(temp: &Path) {
    let Ok(entries) = std::fs::read_dir(temp) else {
        return;
    };
    for entry in entries.flatten() {
        if !entry.file_name().to_string_lossy().starts_with(PREFIX) {
            continue;
        }
        let old = entry
            .metadata()
            .and_then(|m| m.modified())
            .and_then(|t| {
                t.elapsed()
                    .map_err(|e| std::io::Error::other(e.to_string()))
            })
            .is_ok_and(|age| age > STALE_AGE);
        if old {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
}
