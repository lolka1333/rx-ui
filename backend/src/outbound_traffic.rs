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
        for attempt in 0..3u8 {
            match client.query_outbound_stats().await {
                Ok(resp) => {
                    prev = fold_stats_to_totals(resp, "outbound>>>");
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
            poll_once(&client, &db, &mut prev).await;
        }
    });
}

/// One poll tick: read the current per-outbound counters, compute the delta
/// against the previous tick (treating a counter drop as an xray restart), and
/// fold the deltas into `outbound_traffic`.
async fn poll_once(client: &XrayClient, db: &DbPool, prev: &mut HashMap<String, (u64, u64)>) {
    let resp = match client.query_outbound_stats().await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("outbound traffic poll failed: {e}");
            return;
        }
    };
    let current = fold_stats_to_totals(resp, "outbound>>>");
    let mut pending: Vec<(String, i64, i64)> = Vec::new();
    for (tag, &(up, down)) in &current {
        let (prev_up, prev_down) = prev.get(tag).copied().unwrap_or((0, 0));
        // xray-restart detection: a counter that dropped below the cached value
        // means xray's counters reset — credit the current value as freshly
        // observed instead of producing a giant wraparound via subtraction.
        let up_delta = if up < prev_up { up } else { up - prev_up };
        let down_delta = if down < prev_down {
            down
        } else {
            down - prev_down
        };
        if up_delta > 0 || down_delta > 0 {
            #[allow(clippy::cast_possible_wrap)]
            pending.push((tag.clone(), up_delta as i64, down_delta as i64));
        }
    }
    *prev = current;
    flush_deltas(db, &pending).await;
}

/// Flush all per-tag deltas in one transaction — one WAL fsync regardless of how
/// many tags changed. Failures are logged, not raised; the next tick retries.
async fn flush_deltas(db: &DbPool, pending: &[(String, i64, i64)]) {
    if pending.is_empty() {
        return;
    }
    let mut tx = match db.begin().await {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!("outbound traffic tx begin failed: {e}");
            return;
        }
    };
    for (tag, up, down) in pending {
        if let Err(e) = sqlx::query!(
            r#"INSERT INTO outbound_traffic (tag, uplink_total, downlink_total, updated_at)
               VALUES (?, ?, ?, datetime('now'))
               ON CONFLICT(tag) DO UPDATE SET
                   uplink_total   = uplink_total + excluded.uplink_total,
                   downlink_total = downlink_total + excluded.downlink_total,
                   updated_at     = datetime('now')"#,
            tag,
            up,
            down,
        )
        .execute(&mut *tx)
        .await
        {
            tracing::warn!("outbound traffic persist failed for {tag}: {e}");
        }
    }
    if let Err(e) = tx.commit().await {
        tracing::warn!("outbound traffic tx commit failed: {e}");
    }
}

#[cfg(test)]
mod tests {
    use crate::traffic::parse_counter;

    #[test]
    fn parses_uplink() {
        assert_eq!(
            parse_counter("outbound>>>my_relay>>>traffic>>>uplink", "outbound>>>"),
            Some(("my_relay", "uplink"))
        );
    }

    #[test]
    fn parses_builtin_downlink() {
        assert_eq!(
            parse_counter("outbound>>>direct>>>traffic>>>downlink", "outbound>>>"),
            Some(("direct", "downlink"))
        );
    }

    #[test]
    fn rejects_user_prefix() {
        assert_eq!(
            parse_counter("user>>>alice@x>>>traffic>>>uplink", "outbound>>>"),
            None
        );
    }
}
