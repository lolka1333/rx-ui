//! Per-outbound lifetime traffic, persisted across xray / panel restarts — the
//! outbound sibling of the per-client poller in [`crate::traffic`].
//!
//! xray's `outbound>>>{tag}>>>traffic>>>{uplink|downlink}` counters are
//! session-only: they reset to zero whenever xray restarts. This poller folds
//! the per-tick deltas into the `outbound_traffic` table so the Outbounds page
//! shows a monotonic lifetime total, exactly like `clients.*_total`. No quota /
//! online / drift handling here — outbounds don't have those concerns, so this
//! is a thin accumulate-and-persist loop.

use crate::db::DbPool;
use crate::traffic::fold_stats_to_totals;
use crate::xray::XrayClient;
use std::collections::HashMap;
use std::time::Duration;
use tokio::time::interval;

/// Same cadence as the per-user poller — one `StatsService` roundtrip every 5 s.
const POLL_INTERVAL: Duration = Duration::from_secs(5);

/// Spawn the polling task. Runs for the process lifetime; xray errors are logged
/// at warn level and the loop retries on the next tick.
pub fn spawn_outbound_traffic_poller(client: XrayClient, db: DbPool) {
    tokio::spawn(async move {
        // Per-tag previous-tick session counters, used to compute the delta we
        // persist. Seed the baseline from xray's CURRENT counters before the
        // first tick: on the attach-to-running-xray path those bytes are already
        // in the DB totals, so re-crediting them would double-count. A freshly
        // spawned xray reports ~zero here, so nothing is lost.
        let mut prev: HashMap<String, (u64, u64)> = HashMap::new();
        // Whether the baseline below was actually captured. If all attempts fail
        // it stays false and the first successful poll adopts the baseline
        // instead of crediting the whole session (see `poll_once`).
        let mut seeded = false;
        for attempt in 0..3u8 {
            match client.query_outbound_stats().await {
                Ok(resp) => {
                    prev = fold_stats_to_totals(resp, "outbound>>>");
                    seeded = true;
                    break;
                }
                Err(_) if attempt < 2 => tokio::time::sleep(Duration::from_millis(500)).await,
                Err(e) => {
                    tracing::warn!("outbound traffic baseline seed failed: {e}");
                }
            }
        }

        let mut tick = interval(POLL_INTERVAL);
        // Resume at the normal cadence after a blip instead of firing all the
        // missed ticks back-to-back.
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            poll_once(&client, &db, &mut prev, &mut seeded).await;
        }
    });
}

/// One poll tick: read the current per-outbound counters, compute the delta
/// against the previous tick (treating a counter drop as an xray restart), and
/// fold the deltas into `outbound_traffic`.
async fn poll_once(
    client: &XrayClient,
    db: &DbPool,
    prev: &mut HashMap<String, (u64, u64)>,
    seeded: &mut bool,
) {
    let resp = match client.query_outbound_stats().await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("outbound traffic poll failed: {e}");
            return;
        }
    };
    let current = fold_stats_to_totals(resp, "outbound>>>");
    // If the startup baseline seed failed (xray's gRPC was briefly down at
    // boot), adopt the first good snapshot as the baseline and credit nothing
    // this tick. Otherwise, on the attach-to-running-xray path, the whole
    // session's counters — already folded into the DB by the previous panel
    // process — would be re-added on top, double-counting the lifetime total.
    if !*seeded {
        *prev = current;
        *seeded = true;
        return;
    }
    let pending = crate::traffic::tag_deltas(&current, prev, |_| false);
    *prev = current;
    flush_deltas(db, &pending).await;
}

// Flush all per-tag deltas in one transaction — the shared shape lives in
// `traffic::define_delta_flusher`; only the table differs.
crate::traffic::define_delta_flusher!(
    flush_deltas,
    "outbound",
    r#"INSERT INTO outbound_traffic (tag, uplink_total, downlink_total, updated_at)
       VALUES (?, ?, ?, datetime('now'))
       ON CONFLICT(tag) DO UPDATE SET
           uplink_total   = uplink_total + excluded.uplink_total,
           downlink_total = downlink_total + excluded.downlink_total,
           updated_at     = datetime('now')"#
);
