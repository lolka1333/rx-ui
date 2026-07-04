//! Background CPU/memory sampler for the host machine.
//!
//! sysinfo's `cpu_usage()` is a delta between two consecutive `refresh_cpu_usage()`
//! calls. A freshly-built `System` has no prior sample, so the first read always
//! returns 0% or 100% (platform-dependent garbage). The dashboard kept seeing
//! 100% because it built a new `System` per request.
//!
//! We instead keep a single `System` in shared state and refresh it from a
//! tokio task every 2 seconds. Endpoints read the snapshot with no I/O latency.

use crate::models::SystemStats;
use std::{
    net::{IpAddr, UdpSocket},
    sync::Arc,
    time::Duration,
};
use sysinfo::{CpuRefreshKind, Disks, MemoryRefreshKind, RefreshKind, System};
use tokio::sync::RwLock;

const SAMPLE_INTERVAL: Duration = Duration::from_secs(2);

#[derive(Clone)]
pub struct HostMonitor {
    sys: Arc<RwLock<System>>,
    /// Cached at boot — routes don't change often, and probing on every
    /// snapshot would open a UDP socket per dashboard tick.
    ipv4: Option<String>,
    ipv6: Option<String>,
}

impl HostMonitor {
    /// Build the shared sampler and spawn its refresh loop. Call once at boot.
    pub fn spawn() -> Self {
        let kinds = RefreshKind::nothing()
            .with_cpu(CpuRefreshKind::everything())
            .with_memory(MemoryRefreshKind::everything());
        let sys = Arc::new(RwLock::new(System::new_with_specifics(kinds)));

        let bg = sys.clone();
        tokio::spawn(async move {
            // Prime the CPU sampler — sysinfo needs a previous tick to compute
            // the delta. The first post-sleep refresh becomes the first real
            // measurement.
            {
                let mut s = bg.write().await;
                s.refresh_cpu_usage();
                s.refresh_memory();
            }
            loop {
                tokio::time::sleep(SAMPLE_INTERVAL).await;
                let mut s = bg.write().await;
                s.refresh_cpu_usage();
                s.refresh_memory();
            }
        });

        Self {
            sys,
            ipv4: detect_local_ip(false),
            ipv6: detect_local_ip(true),
        }
    }

    /// Read the latest cached snapshot. Disks are queried inline — they don't
    /// need the two-sample dance, and they change rarely enough that polling
    /// them on demand is cheap.
    pub async fn snapshot(&self) -> SystemStats {
        let sys = self.sys.read().await;

        // Report the filesystem the panel actually lives on: the disk whose
        // mount point is the longest prefix of our working directory (where the
        // DB and data dir sit). This beats a hardcoded mount-name allowlist,
        // which both double-counts (e.g. `/` plus `/mnt/...`) and misses
        // non-standard layouts (a data disk on `/data`, Windows `E:`, …).
        // `Path::starts_with` is component-wise, so `/apple` never matches `/app`.
        let disks = Disks::new_with_refreshed_list();
        let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("/"));
        let (disk_total, disk_used) = disks
            .iter()
            .filter(|d| cwd.starts_with(d.mount_point()))
            .max_by_key(|d| d.mount_point().as_os_str().len())
            .map_or((0u64, 0u64), |d| {
                (d.total_space(), d.total_space() - d.available_space())
            });

        SystemStats {
            cpu_percent: sys.global_cpu_usage(),
            cpu_cores: u32::try_from(sys.cpus().len()).unwrap_or(0),
            memory_used_bytes: sys.used_memory(),
            memory_total_bytes: sys.total_memory(),
            disk_used_bytes: disk_used,
            disk_total_bytes: disk_total,
            swap_used_bytes: sys.used_swap(),
            swap_total_bytes: sys.total_swap(),
            uptime_seconds: System::uptime(),
            ipv4: self.ipv4.clone(),
            ipv6: self.ipv6.clone(),
        }
    }
}

/// Find the outbound IP of the host by asking the OS what address it would
/// use to reach a well-known public endpoint. UDP `connect` doesn't send
/// any packets — it only resolves the route — so this is cheap and works
/// offline as long as a default gateway exists.
///
/// `8.8.8.8` (IPv4) and `2001:4860:4860::8888` (IPv6) are Google DNS, picked
/// because they're stable, anycast, and rarely blocked.
fn detect_local_ip(v6: bool) -> Option<String> {
    let (bind, target) = if v6 {
        ("[::]:0", "[2001:4860:4860::8888]:80")
    } else {
        ("0.0.0.0:0", "8.8.8.8:80")
    };
    let socket = UdpSocket::bind(bind).ok()?;
    socket.connect(target).ok()?;
    let ip = socket.local_addr().ok()?.ip();
    // Skip loopback / unspecified — those mean the OS has no route at all.
    match ip {
        IpAddr::V4(v4) if !v4.is_loopback() && !v4.is_unspecified() => Some(v4.to_string()),
        IpAddr::V6(v6) if !v6.is_loopback() && !v6.is_unspecified() => Some(v6.to_string()),
        _ => None,
    }
}
