//! Per-client traffic + online-status snapshot, kept warm by a
//! background poll of xray's `StatsService`.
//!
//! xray accumulates per-email counters (`statsUserUplink/Downlink`)
//! and tracks online users via `statsUserOnline`; the policy block in
//! `xray::config_gen` opts in. This module polls once every
//! `POLL_INTERVAL` and exposes the latest snapshot through an
//! `Arc<RwLock<HashMap<email, TrafficSnapshot>>>` that the REST handler
//! reads under a short-lived read lock.
//!
//! Two RPCs per tick:
//!   * `QueryStats(pattern="user>>>")` — every `user>>>{email}>>>
//!     traffic>>>{uplink|downlink}` counter. Persists across socket
//!     close (unlike `GetUsersStats`, which only lists currently-
//!     online users and would drop a client the moment their last
//!     TCP socket closes — even though their cumulative counter is
//!     still meaningful).
//!   * `GetAllOnlineUsers()` — email list of users with an active
//!     TCP right now.
//!
//! Live rate (`uplink_bps` / `downlink_bps`) is computed locally: the
//! poll loop stores the previous tick's cumulative counters and
//! divides `delta_bytes / elapsed_secs`. The first tick after startup
//! emits 0 bps (no previous baseline), which is correct.
//!
//! Persistence across xray / backend restarts: the per-tick delta
//! (`current_xray_total - prev_xray_total`, clamped against counter
//! resets) is written into `clients.uplink_total / downlink_total`
//! every tick. The API serves `db_total + current_xray_session` so
//! the operator sees a monotonic counter that survives restarts.

use crate::db::DbPool;
use crate::xray::XrayClient;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tokio::time::interval;
use ts_rs::TS;

/// How often we hit `GetUsersStats`. 5 s is the same cadence as the
/// dashboard system-stats poll; matches Frontend's react-query default
/// stale window so a single roundtrip drives both panels.
const POLL_INTERVAL: Duration = Duration::from_secs(5);

/// One client's live counters, exposed as-is to the frontend.
#[derive(Debug, Clone, Serialize, TS)]
#[ts(export, export_to = "../../frontend/src/api/types/stats.ts")]
pub struct TrafficSnapshot {
    /// `true` if xray reports at least one active TCP connection OR
    /// the user moved any bytes during the last poll interval. The
    /// `bps > 0` fallback catches short-lived HTTP-style traffic
    /// where every request opens and closes a socket inside one
    /// poll window — `GetAllOnlineUsers` alone never sees those
    /// sockets and would flag the user offline despite obvious
    /// activity.
    pub online: bool,
    /// Lifetime uplink bytes (user→outbound). Includes everything the
    /// panel has ever seen for this email across xray + backend
    /// restarts; backed by the `clients.uplink_total` column.
    #[ts(type = "number")]
    pub uplink_total: u64,
    /// Lifetime downlink bytes (outbound→user). Same persistence
    /// semantics as `uplink_total`.
    #[ts(type = "number")]
    pub downlink_total: u64,
    /// Bytes/sec rate over the last poll interval (uplink). 0 on the
    /// first tick after backend start or after an xray restart.
    #[ts(type = "number")]
    pub uplink_bps: u64,
    /// Bytes/sec rate over the last poll interval (downlink).
    #[ts(type = "number")]
    pub downlink_bps: u64,
}

/// Thread-safe handle to the latest snapshot. Cloning is cheap (Arc).
#[derive(Clone, Default)]
pub struct TrafficStore {
    inner: Arc<RwLock<HashMap<String, TrafficSnapshot>>>,
}

impl TrafficStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot — clones the current map into the caller. Held lock
    /// is read-only and released before the clone is returned.
    pub async fn snapshot(&self) -> HashMap<String, TrafficSnapshot> {
        self.inner.read().await.clone()
    }
}

/// Parse a counter name of shape `user>>>{email}>>>traffic>>>{kind}`
/// into its `(email, kind)` pair. Returns `None` for shapes we don't
/// care about (other prefixes, malformed names).
fn parse_user_counter(name: &str) -> Option<(&str, &str)> {
    let rest = name.strip_prefix("user>>>")?;
    let (email, tail) = rest.split_once(">>>traffic>>>")?;
    Some((email, tail))
}

/// Spawn the polling task. It runs for the lifetime of the panel
/// process; errors from xray (e.g. xray was killed) are logged at
/// warn level and the loop retries on the next tick.
pub fn spawn_traffic_poller(client: XrayClient, store: TrafficStore, db: DbPool) {
    tokio::spawn(async move {
        // Per-email previous-tick state used to compute the delta we
        // persist this tick.
        let mut prev: HashMap<String, PrevTick> = HashMap::new();
        // Seed baselines from xray's CURRENT counters *before* the first
        // tick. This matters for the attach-to-running-xray path: those
        // counters are already reflected in `clients.*_total`, so they
        // must become the baseline rather than being re-credited. A
        // freshly *spawned* xray reports ~zero here, so nothing is lost.
        // Once seeded, an email that appears LATER started from zero this
        // xray session and is credited in full on its first observation
        // (see `compute_delta`) — those are the bytes the old code
        // silently dropped (every client's first poll-window of traffic).
        let mut seeded = false;
        for attempt in 0..3u8 {
            match client.query_user_stats().await {
                Ok(resp) => {
                    let at = Instant::now();
                    for (email, (uplink, downlink)) in fold_stats_to_totals(resp) {
                        prev.insert(
                            email,
                            PrevTick {
                                uplink,
                                downlink,
                                at,
                            },
                        );
                    }
                    seeded = true;
                    break;
                }
                Err(_) if attempt < 2 => tokio::time::sleep(Duration::from_millis(500)).await,
                Err(e) => tracing::warn!(
                    "traffic poller baseline seed failed; first counters credited \
                     conservatively: {e}"
                ),
            }
        }
        let mut tick = interval(POLL_INTERVAL);
        // `Burst` (the default) would fire all missed ticks back-to-
        // back after a long blip; resume at the normal cadence instead.
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tick.tick().await;
            poll_once(&client, &store, &db, &mut prev, &mut seeded).await;
        }
    });
}

/// One tick of the polling loop. Extracted from `spawn_traffic_poller`
/// so the spawn'd future stays thin and `clippy::too_many_lines` doesn't
/// fire on the per-tick logic. Failures inside the tick are logged
/// (not returned) — the loop continues on the next tick, never giving
/// up the polling task.
async fn poll_once(
    client: &XrayClient,
    store: &TrafficStore,
    db: &DbPool,
    prev: &mut HashMap<String, PrevTick>,
    seeded: &mut bool,
) {
    // Two RPCs per tick: traffic counters (resilient to socket close)
    // + a separate online-list (cheap, ground-truth).
    let stats_resp = match client.query_user_stats().await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("traffic poller query_user_stats failed: {e}");
            return;
        }
    };
    let online_resp = match client.get_all_online_users().await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("traffic poller get_all_online_users failed: {e}");
            return;
        }
    };
    let online_set: std::collections::HashSet<String> = online_resp.users.into_iter().collect();
    let xray_totals = fold_stats_to_totals(stats_resp);

    // Read persisted lifetime totals for every email xray currently
    // knows about. One query, joined on email; the missing rows come
    // back as 0 and the rest of the code treats them as transient.
    let db_totals = match load_db_totals(db).await {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!("traffic poller DB read failed: {e}");
            HashMap::new()
        }
    };

    let now = Instant::now();
    // Iterate the UNION of xray's reported emails and the panel's DB
    // rows. Iterating just `xray_totals` (the historical bug) drops
    // every email xray hasn't recorded a counter for yet — fresh after
    // an xray / panel restart that's every email, until the first
    // byte flows. The frontend reads `stats[email]` to render the
    // lifetime total, so missing entries display as "—" instead of
    // the bytes already persisted on disk. Iterating db_totals as
    // well guarantees every DB-known email gets a snapshot, with
    // `xray_total` defaulting to `(0, 0)` until xray catches up.
    let all_emails: std::collections::HashSet<&String> =
        xray_totals.keys().chain(db_totals.keys()).collect();
    let mut next: HashMap<String, TrafficSnapshot> = HashMap::with_capacity(all_emails.len());
    let mut next_prev: HashMap<String, PrevTick> = HashMap::with_capacity(all_emails.len());
    // Accumulator for the per-tick delta UPDATEs, flushed below inside
    // one transaction. Per-statement autocommit would fire one WAL
    // fsync per email — at the 100k-client commercial target that's
    // tens of seconds of disk I/O per tick. One commit keeps it bounded.
    let mut pending_deltas: Vec<(String, i64, i64)> = Vec::new();
    for email in all_emails {
        let (uplink, downlink) = xray_totals.get(email).copied().unwrap_or((0, 0));
        let (up_delta, down_delta, secs) =
            compute_delta(uplink, downlink, prev.get(email), now, *seeded);

        // Queue the delta — flushed in one transaction at the end of
        // the tick. Missing client rows (xray still knows about a
        // deleted email) are ignored downstream: `rows_affected == 0`
        // on the UPDATE is not an error.
        if up_delta > 0 || down_delta > 0 {
            #[allow(clippy::cast_possible_wrap)]
            pending_deltas.push((email.clone(), up_delta as i64, down_delta as i64));
        }

        let meta = db_totals.get(email);
        maybe_drift_correct(client, email, meta, &online_set, up_delta, down_delta).await;
        maybe_enforce_quota(client, db, email, meta, up_delta, down_delta).await;

        // Only track `prev` for emails xray has actually reported. For
        // DB-only emails we'd cache (0, 0) — the moment xray starts
        // reporting them, the FIRST real value would be misread as a
        // huge delta against the synthetic baseline and double-count
        // the lifetime total.
        if xray_totals.contains_key(email) {
            next_prev.insert(
                email.clone(),
                PrevTick {
                    uplink,
                    downlink,
                    at: now,
                },
            );
        }
        next.insert(
            email.clone(),
            build_snapshot(meta, &online_set, email, up_delta, down_delta, secs),
        );
    }
    flush_deltas(db, &pending_deltas).await;
    *prev = next_prev;
    // Baseline is now established: from the next tick on, any never-before-
    // seen email is genuinely new this xray session (its counter starts at
    // zero) and so is credited in full on its first observation.
    *seeded = true;
    *store.inner.write().await = next;
}

/// Roll the `query_user_stats` response into `email -> (uplink, downlink)`.
/// Ignores counters that aren't of the form `user>>>email>>>traffic>>>kind`.
fn fold_stats_to_totals(
    resp: crate::xray::proto::xray::app::stats::command::QueryStatsResponse,
) -> HashMap<String, (u64, u64)> {
    let mut totals: HashMap<String, (u64, u64)> = HashMap::new();
    for s in resp.stat {
        let Some((email, kind)) = parse_user_counter(&s.name) else {
            continue;
        };
        // `stat.value` is `i64` in the proto but xray never sets it
        // negative — `.max(0)` clamps the theoretical-only negative
        // case, then the cast is exact (positive i64 always fits in u64).
        #[allow(clippy::cast_sign_loss)]
        let val = s.value.max(0) as u64;
        let entry = totals.entry(email.to_owned()).or_default();
        match kind {
            "uplink" => entry.0 = val,
            "downlink" => entry.1 = val,
            _ => {} // ignore other counters (e.g. xray-internal ones)
        }
    }
    totals
}

/// Delta vs previous tick. xray-restart detection: if the current total
/// dropped below the cached previous one, xray's counters reset —
/// credit the current value as freshly observed instead of producing a
/// giant wraparound positive via plain subtraction.
///
/// First observation of an email (`prev = None`): when `credit_first` is
/// set the full current value is credited — the email appeared after the
/// startup baseline seed, so it began from zero this xray session (a
/// client created at runtime, or its first traffic since boot). When
/// `credit_first` is false — only on the very first poll, and only if the
/// baseline seed failed — nothing is credited: the conservative choice
/// that can't double-count bytes a prior backend already persisted.
fn compute_delta(
    uplink: u64,
    downlink: u64,
    prev: Option<&PrevTick>,
    now: Instant,
    credit_first: bool,
) -> (u64, u64, f64) {
    let first = if credit_first {
        (uplink, downlink, 0.0_f64)
    } else {
        (0u64, 0u64, 0.0_f64)
    };
    prev.copied().map_or(first, |p| {
        let secs = now.duration_since(p.at).as_secs_f64().max(0.001);
        if uplink < p.uplink || downlink < p.downlink {
            (uplink, downlink, secs)
        } else {
            (uplink - p.uplink, downlink - p.downlink, secs)
        }
    })
}

/// Drift correction: if the DB says this client is disabled but xray
/// still has them in the online set OR moved bytes this tick, the two
/// state machines are out of sync (panel crashed mid-mutation, parallel
/// admin edited the row, SQL-bypass for testing, etc.) — re-issue the
/// gRPC `RemoveUser` so xray catches up. We gate on
/// `online OR delta>0` rather than calling every tick to avoid
/// hammering xray after the first successful removal.
async fn maybe_drift_correct(
    client: &XrayClient,
    email: &str,
    meta: Option<&ClientMeta>,
    online_set: &std::collections::HashSet<String>,
    up_delta: u64,
    down_delta: u64,
) {
    let Some(meta) = meta else { return };
    if meta.enabled {
        return;
    }
    if !(online_set.contains(email) || up_delta > 0 || down_delta > 0) {
        return;
    }
    match client.remove_user(&meta.inbound_tag, email).await {
        Ok(()) => tracing::info!(
            "traffic poller: drift corrected — DB-disabled client {email} was still active in xray, removed"
        ),
        // "User not found" is the expected response on the tick *after*
        // a successful removal: the TCP socket closes, residual byte
        // counters tick once more (so the outer guard is still true),
        // but the user is already gone from xray. Idempotent success,
        // not worth a warning.
        Err(e) if e.to_string().contains("not found") => {}
        Err(e) => {
            tracing::warn!("traffic poller drift-correction RemoveUser failed for {email}: {e}");
        }
    }
}

/// Quota enforcement. Always computes against the freshly-computed
/// lifetime total (`db_total + delta`), even if no delta was persisted
/// this tick — that way a client whose limit was lowered below their
/// existing usage gets cut off on the next poll without needing a new
/// byte to come in. The `enabled` gate stops re-tripping an already-
/// quota'd or manually-off client on every tick.
async fn maybe_enforce_quota(
    client: &XrayClient,
    db: &DbPool,
    email: &str,
    meta: Option<&ClientMeta>,
    up_delta: u64,
    down_delta: u64,
) {
    let Some(meta) = meta else { return };
    if !meta.enabled {
        return;
    }
    let Some(limit) = meta.limit_bytes else {
        return;
    };
    let new_up = meta.uplink_total + up_delta;
    let new_down = meta.downlink_total + down_delta;
    if new_up + new_down < limit {
        return;
    }
    let client_id = meta.id.clone();
    if let Err(e) = sqlx::query!(
        "UPDATE clients SET enabled = 0, disabled_reason = 'quota',
                updated_at = datetime('now') WHERE id = ?",
        client_id,
    )
    .execute(db)
    .await
    {
        tracing::warn!("traffic poller quota flip failed for {email}: {e}");
    } else if let Err(e) = client.remove_user(&meta.inbound_tag, email).await {
        // DB is the source of truth; if the xray call fails the client
        // is still flagged quota-exceeded in the panel UI but bytes
        // keep flowing until xray catches up (typically on the next
        // inbound reload).
        tracing::warn!("traffic poller quota RemoveUser failed for {email}: {e}");
    } else {
        tracing::info!(
            "traffic poller: quota reached for {email} ({} bytes, limit {limit}), removed from xray",
            new_up + new_down
        );
    }
}

/// Compose the per-email `TrafficSnapshot` served to the operator's
/// page. Adds the just-observed delta on top of the DB total so the
/// UI reflects the current tick's bytes without round-tripping back
/// to the DB. `online` is suppressed when the DB says disabled even
/// if xray is still leaking — the drift-correction branch will catch
/// up on the next tick.
fn build_snapshot(
    meta: Option<&ClientMeta>,
    online_set: &std::collections::HashSet<String>,
    email: &str,
    up_delta: u64,
    down_delta: u64,
    secs: f64,
) -> TrafficSnapshot {
    // bps = bytes / seconds. The `u64 → f64` casts lose precision
    // above 2^53 bytes/sec (~9 PB/s), well beyond any realistic link.
    // Same logic for the `f64 → u64` truncation: 5-second deltas at
    // realistic line rates are far below `u64::MAX`.
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    let (uplink_bps, downlink_bps) = if secs > 0.0 {
        (
            (up_delta as f64 / secs) as u64,
            (down_delta as f64 / secs) as u64,
        )
    } else {
        (0, 0)
    };
    let (db_up, db_down) = meta.map_or((0u64, 0u64), |m| (m.uplink_total, m.downlink_total));
    let db_enabled = meta.is_none_or(|m| m.enabled);
    let online = db_enabled && (online_set.contains(email) || uplink_bps > 0 || downlink_bps > 0);
    TrafficSnapshot {
        online,
        uplink_total: db_up + up_delta,
        downlink_total: db_down + down_delta,
        uplink_bps,
        downlink_bps,
    }
}

/// Flush all per-email deltas in one transaction — one WAL fsync
/// regardless of how many rows changed. The email index (migration
/// 0021) keeps each UPDATE at O(log N). Failures are logged, not
/// raised; the next tick will see the same DB state and try again.
async fn flush_deltas(db: &DbPool, pending: &[(String, i64, i64)]) {
    if pending.is_empty() {
        return;
    }
    let mut tx = match db.begin().await {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!("traffic poller tx begin failed: {e}");
            return;
        }
    };
    let mut failed = 0usize;
    for (email, up, down) in pending {
        if let Err(e) = sqlx::query!(
            r#"UPDATE clients
               SET uplink_total = uplink_total + ?,
                   downlink_total = downlink_total + ?,
                   traffic_updated_at = datetime('now')
               WHERE email = ?"#,
            up,
            down,
            email,
        )
        .execute(&mut *tx)
        .await
        {
            failed += 1;
            tracing::warn!("traffic poller persist failed for {email}: {e}");
        }
    }
    if let Err(e) = tx.commit().await {
        tracing::warn!(
            "traffic poller tx commit failed ({} deltas, {failed} stmts errored): {e}",
            pending.len()
        );
    }
}

/// Snapshot of one email's xray-side counters at the previous poll.
#[derive(Debug, Clone, Copy)]
struct PrevTick {
    uplink: u64,
    downlink: u64,
    at: Instant,
}

/// Per-email persisted state needed inside the polling loop, joined
/// with the parent inbound's tag (needed for `remove_user` when a
/// client trips its quota). One query per tick.
#[derive(Debug, Clone)]
struct ClientMeta {
    id: String,
    inbound_tag: String,
    uplink_total: u64,
    downlink_total: u64,
    enabled: bool,
    /// `None` ≡ no quota set.
    limit_bytes: Option<u64>,
}

/// Pull per-client persisted state for every enabled-inbound client. The
/// JOIN drops orphan rows (client whose parent inbound was deleted) so
/// the quota check never tries to act on stale data — those rows still
/// get their counters served via the snapshot, but enforcement skips
/// them.
#[allow(clippy::cast_sign_loss)]
async fn load_db_totals(db: &DbPool) -> sqlx::Result<HashMap<String, ClientMeta>> {
    let rows = sqlx::query!(
        r#"SELECT c.id           AS "id!",
                  c.email        AS "email!",
                  i.tag          AS "inbound_tag!",
                  c.uplink_total AS "uplink_total!",
                  c.downlink_total AS "downlink_total!",
                  c.enabled      AS "enabled!",
                  c.traffic_limit_bytes
           FROM clients c
           JOIN inbounds i ON i.id = c.inbound_id"#
    )
    .fetch_all(db)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| {
            let up = r.uplink_total.max(0) as u64;
            let down = r.downlink_total.max(0) as u64;
            let limit = r
                .traffic_limit_bytes
                .and_then(|v| if v < 0 { None } else { Some(v as u64) });
            (
                r.email,
                ClientMeta {
                    id: r.id,
                    inbound_tag: r.inbound_tag,
                    uplink_total: up,
                    downlink_total: down,
                    enabled: r.enabled != 0,
                    limit_bytes: limit,
                },
            )
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::parse_user_counter;

    #[test]
    fn parses_uplink() {
        assert_eq!(
            parse_user_counter("user>>>alice@x>>>traffic>>>uplink"),
            Some(("alice@x", "uplink"))
        );
    }

    #[test]
    fn parses_downlink_with_at() {
        assert_eq!(
            parse_user_counter("user>>>bob@example.com>>>traffic>>>downlink"),
            Some(("bob@example.com", "downlink"))
        );
    }

    #[test]
    fn rejects_non_user_prefix() {
        assert_eq!(parse_user_counter("inbound>>>tag>>>traffic>>>uplink"), None);
    }

    #[test]
    fn rejects_missing_traffic_segment() {
        assert_eq!(parse_user_counter("user>>>alice@x>>>online"), None);
    }
}
