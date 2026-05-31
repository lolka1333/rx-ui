use serde::{Deserialize, Serialize};
use ts_rs::TS;

#[derive(Debug, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../frontend/src/api/types/stats.ts")]
pub struct SystemStats {
    pub cpu_percent: f32,
    pub cpu_cores: u32,
    // ts-rs maps u64 → bigint by default. Byte counters fit in JS-safe integer
    // range (<2^53 ≈ 9 PB) for any realistic VPS, so emit them as `number` to
    // keep arithmetic in the dashboard simple.
    #[ts(type = "number")]
    pub memory_used_bytes: u64,
    #[ts(type = "number")]
    pub memory_total_bytes: u64,
    #[ts(type = "number")]
    pub disk_used_bytes: u64,
    #[ts(type = "number")]
    pub disk_total_bytes: u64,
    // Swap / page file. On Windows reflects the page file usage, on Linux the
    // swap partition. Replaces load_avg, which was always 0 on Windows.
    #[ts(type = "number")]
    pub swap_used_bytes: u64,
    #[ts(type = "number")]
    pub swap_total_bytes: u64,
    #[ts(type = "number")]
    pub uptime_seconds: u64,
    /// Outbound-facing IPv4 of the host (the address a packet to the public
    /// internet would leave on). `None` if there is no v4 route at all.
    pub ipv4: Option<String>,
    /// Same for IPv6. `None` when the host has no global v6.
    pub ipv6: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../frontend/src/api/types/stats.ts")]
pub struct XrayStatus {
    pub running: bool,
    pub pid: Option<u32>,
    pub version: Option<String>,
    pub started_at: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../frontend/src/api/types/stats.ts")]
pub struct DashboardOverview {
    pub system: SystemStats,
    pub xray: XrayStatus,
    pub inbounds_total: u32,
    pub inbounds_enabled: u32,
}
