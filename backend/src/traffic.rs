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
use futures_util::StreamExt;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tokio::time::interval;
use ts_rs::TS;

/// How often we poll `QueryStats` + `GetAllOnlineUsers`. 5 s is the same cadence as the
/// dashboard system-stats poll; matches Frontend's react-query default
/// stale window so a single roundtrip drives both panels.
const POLL_INTERVAL: Duration = Duration::from_secs(5);

/// Max enforcement round-trips (`RemoveUser` + disable) run concurrently per tick.
/// Emails that trip no rule early-return without awaiting, so this only bounds
/// the handful that need action — a mass quota/expiry sweep no longer serializes
/// behind N gRPC + DB round-trips.
const ENFORCE_CONCURRENCY: usize = 16;

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

/// Parse a stats counter name of shape `{prefix}{key}>>>traffic>>>{kind}` into
/// its `(key, kind)` pair. Returns `None` for other prefixes / malformed names.
/// `prefix` is `"user>>>"` (per-client) or `"outbound>>>"` (per-outbound), so
/// both pollers share one parser.
pub fn parse_counter<'a>(name: &'a str, prefix: &str) -> Option<(&'a str, &'a str)> {
    let rest = name.strip_prefix(prefix)?;
    rest.split_once(">>>traffic>>>")
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
                    for (email, (uplink, downlink)) in fold_stats_to_totals(resp, "user>>>") {
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
    let xray_totals = fold_stats_to_totals(stats_resp, "user>>>");

    // Read persisted lifetime totals for every email xray currently
    // knows about. One query, joined on email; the missing rows come
    // back as 0 and the rest of the code treats them as transient.
    let db_totals = match load_db_totals(db).await {
        Ok(m) => m,
        Err(e) => {
            // Skip the tick rather than degrade to an empty map. An empty
            // `db_totals` shrinks the `all_emails` union below to just what
            // xray reported this tick, and the wholesale store overwrite
            // (`*store.inner.write() = next`) would then DROP every
            // DB-known-but-xray-quiet client (idle users, or everyone right
            // after an xray restart) — they'd render "—" until the next tick,
            // i.e. traffic visibly disappears and reappears. A failed read
            // carries no new information, so keeping last tick's snapshot is
            // strictly correct. Same early-return contract as the two gRPC
            // failures above; `flush_deltas` is additive and xray counters use
            // `reset:false`, so the next good tick credits the accumulated
            // bytes with no loss or double-count.
            tracing::warn!("traffic poller DB read failed; keeping last snapshot this tick: {e}");
            return;
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
    // Per-email enforcement (drift/quota/expiry) is deferred out of this loop and
    // run concurrently below, so a tick isn't serialized behind the gRPC + DB
    // round-trips of the emails that trip a rule.
    let mut enforce_batch: Vec<(&String, Option<&ClientMeta>, u64, u64)> = Vec::new();
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
        enforce_batch.push((email, meta, up_delta, down_delta));

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
    // Enforce with bounded concurrency. Within one email the checks stay ordered
    // (drift, then quota, then expiry unless quota already disabled it); across
    // emails they're independent (distinct rows / xray users), so this
    // parallelizes only the round-trips that actually fire.
    // Borrow once as a Copy `&` so each future captures the reference, not the
    // owned set (which an `FnMut` closure can't move out repeatedly).
    let online_set = &online_set;
    futures_util::stream::iter(enforce_batch)
        .for_each_concurrent(
            ENFORCE_CONCURRENCY,
            |(email, meta, up_delta, down_delta)| async move {
                maybe_drift_correct(client, email, meta, online_set, up_delta, down_delta).await;
                // Stop after the first rule that disables the client this tick.
                // `meta.enabled` is read once per tick, so without this the expiry
                // check wouldn't see quota's flip and would redundantly re-UPDATE
                // (and relabel `quota` -> `expired`). Quota is checked first, so a
                // client tripping both is reported as `quota`.
                if !maybe_enforce_quota(client, db, email, meta, up_delta, down_delta).await {
                    maybe_enforce_expiry(client, db, email, meta).await;
                }
            },
        )
        .await;
    flush_deltas(db, &pending_deltas).await;
    *prev = next_prev;
    // Baseline is now established: from the next tick on, any never-before-
    // seen email is genuinely new this xray session (its counter starts at
    // zero) and so is credited in full on its first observation.
    *seeded = true;
    *store.inner.write().await = next;
}

/// Roll a `QueryStats` response into `key -> (uplink, downlink)`, keeping only
/// counters of the form `{prefix}{key}>>>traffic>>>{uplink|downlink}`. Shared by
/// the per-client poller (`"user>>>"`) and the per-outbound poller
/// (`"outbound>>>"`).
pub fn fold_stats_to_totals(
    resp: crate::xray::proto::xray::app::stats::command::QueryStatsResponse,
    prefix: &str,
) -> HashMap<String, (u64, u64)> {
    let mut totals: HashMap<String, (u64, u64)> = HashMap::new();
    for s in resp.stat {
        let Some((key, kind)) = parse_counter(&s.name, prefix) else {
            continue;
        };
        // `stat.value` is `i64` in the proto but xray never sets it negative —
        // `.max(0)` clamps the theoretical-only case, then the cast is exact
        // (positive i64 always fits in u64).
        #[allow(clippy::cast_sign_loss)]
        let val = s.value.max(0) as u64;
        let entry = totals.entry(key.to_owned()).or_default();
        match kind {
            "uplink" => entry.0 = val,
            "downlink" => entry.1 = val,
            _ => {} // ignore other counters (e.g. xray-internal ones)
        }
    }
    totals
}

/// Per-tag byte deltas between two [`fold_stats_to_totals`] snapshots, with the
/// xray-restart detection the tag pollers share: a counter that dropped below
/// its cached previous value means xray reset its session counters, so the
/// current value is credited whole instead of producing a giant wraparound via
/// subtraction. `skip` drops tags before diffing (e.g. the internal `api`
/// inbound). Only tags with a non-zero delta are returned. Extracted so the
/// per-outbound and per-inbound pollers share one tested implementation instead
/// of each carrying its own copy of this subtle reset logic.
pub fn tag_deltas(
    current: &HashMap<String, (u64, u64)>,
    prev: &HashMap<String, (u64, u64)>,
    skip: impl Fn(&str) -> bool,
) -> Vec<(String, i64, i64)> {
    let mut pending = Vec::new();
    for (tag, &(up, down)) in current {
        if skip(tag) {
            continue;
        }
        let (prev_up, prev_down) = prev.get(tag).copied().unwrap_or((0, 0));
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
    pending
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

/// Drop `email` from EVERY inbound the client is attached to. xray keys users
/// per `(inbound, email)`, so a client spanning N inbounds needs N `RemoveUser`
/// calls — otherwise bytes keep flowing through the inbounds we skipped. The
/// "not found" reply is the idempotent no-op (user already gone this tick) and
/// isn't logged.
async fn remove_user_everywhere(client: &XrayClient, tags: &[String], email: &str, context: &str) {
    for tag in tags {
        match client.remove_user(tag, email).await {
            Ok(()) => {}
            Err(e) if e.to_string().contains("not found") => {}
            Err(e) => tracing::warn!(
                "traffic poller {context} RemoveUser failed for {email} in inbound {tag}: {e}"
            ),
        }
    }
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
    tracing::info!(
        "traffic poller: drift corrected — DB-disabled client {email} was still active in xray, removing from {} inbound(s)",
        meta.inbound_tags.len()
    );
    remove_user_everywhere(client, &meta.inbound_tags, email, "drift-correction").await;
}

/// Quota enforcement. Always computes against the freshly-computed
/// lifetime total (`db_total + delta`), even if no delta was persisted
/// this tick — that way a client whose limit was lowered below their
/// existing usage gets cut off on the next poll without needing a new
/// byte to come in. The `enabled` gate stops re-tripping an already-
/// quota'd or manually-off client on every tick.
///
/// Returns `true` when this call disabled the client, so the caller can
/// skip the expiry check: a client that is both over quota and past its
/// expiry should flip once (reason `quota`), not take a redundant second
/// UPDATE + `RemoveUser` that would also clobber the reason to `expired`
/// — `meta.enabled` is read once per tick, so expiry can't see this flip.
///
/// `#[must_use]`: the returned flag *is* the quota→expiry precedence contract;
/// forcing every call site to consume it stops a future edit from silently
/// dropping the guard and reintroducing the redundant double-flip.
#[must_use]
async fn maybe_enforce_quota(
    client: &XrayClient,
    db: &DbPool,
    email: &str,
    meta: Option<&ClientMeta>,
    up_delta: u64,
    down_delta: u64,
) -> bool {
    let Some(meta) = meta else { return false };
    if !meta.enabled {
        return false;
    }
    let Some(limit) = meta.limit_bytes else {
        return false;
    };
    let new_up = meta.uplink_total + up_delta;
    let new_down = meta.downlink_total + down_delta;
    if new_up + new_down < limit {
        return false;
    }
    // Disable EVERY row for this email — the client's on/off state is a
    // property of the identity, not one inbound attachment. The frontend list
    // treats a group as enabled only when all rows are (`rows.every`), so a
    // partial flip would render an inconsistent toggle.
    if let Err(e) = sqlx::query!(
        "UPDATE clients SET enabled = 0, disabled_reason = 'quota',
                updated_at = datetime('now') WHERE email = ?",
        email,
    )
    .execute(db)
    .await
    {
        // DB is the source of truth; if it fails we skip the xray removal too
        // and retry the whole thing next tick. Report "not disabled" so the
        // expiry check still gets a chance to cut the client this same tick.
        tracing::warn!("traffic poller quota flip failed for {email}: {e}");
        return false;
    }
    remove_user_everywhere(client, &meta.inbound_tags, email, "quota").await;
    tracing::info!(
        "traffic poller: quota reached for {email} ({} bytes, limit {limit}), removed from {} inbound(s)",
        new_up + new_down,
        meta.inbound_tags.len()
    );
    true
}

/// Time-driven sibling of `maybe_enforce_quota`: if the client has an
/// `expires_at` in the past, flip it disabled with `disabled_reason =
/// "expired"` and drop the user from xray. The `enabled` gate stops
/// re-tripping an already-off client every tick; clearing or extending
/// the date re-enables it from the API side (see `clients.rs`).
async fn maybe_enforce_expiry(
    client: &XrayClient,
    db: &DbPool,
    email: &str,
    meta: Option<&ClientMeta>,
) {
    let Some(meta) = meta else { return };
    if !meta.enabled {
        return;
    }
    let Some(ref expires_at) = meta.expires_at else {
        return;
    };
    // Stored as fixed-width UTC `YYYY-MM-DD HH:MM:SS`; parse with chrono to
    // compare unambiguously against now.
    let Ok(exp) = chrono::NaiveDateTime::parse_from_str(expires_at, "%Y-%m-%d %H:%M:%S") else {
        tracing::warn!("traffic poller: unparsable expires_at {expires_at:?} for {email}");
        return;
    };
    if exp > chrono::Utc::now().naive_utc() {
        return;
    }
    if let Err(e) = sqlx::query!(
        "UPDATE clients SET enabled = 0, disabled_reason = 'expired',
                updated_at = datetime('now') WHERE email = ?",
        email,
    )
    .execute(db)
    .await
    {
        // DB is source of truth; if it fails we skip xray removal and retry.
        tracing::warn!("traffic poller expiry flip failed for {email}: {e}");
        return;
    }
    remove_user_everywhere(client, &meta.inbound_tags, email, "expiry").await;
    tracing::info!("traffic poller: {email} expired (at {expires_at}), removed from all inbounds");
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
    /// EVERY inbound tag this email is attached to. xray keys users per
    /// `(inbound, email)`, so enforcement (`remove_user`) must fan out to all
    /// of them — dropping the user from a single inbound leaves bytes flowing
    /// through the others.
    inbound_tags: Vec<String>,
    uplink_total: u64,
    downlink_total: u64,
    enabled: bool,
    /// `None` ≡ no quota set.
    limit_bytes: Option<u64>,
    /// UTC `YYYY-MM-DD HH:MM:SS` expiry instant; `None` ≡ never expires.
    expires_at: Option<String>,
}

/// Pull per-client persisted state for every enabled-inbound client. The
/// JOIN drops orphan rows (client whose parent inbound was deleted) so
/// the quota check never tries to act on stale data — those rows still
/// get their counters served via the snapshot, but enforcement skips
/// them.
#[allow(clippy::cast_sign_loss)]
async fn load_db_totals(db: &DbPool) -> sqlx::Result<HashMap<String, ClientMeta>> {
    let rows = sqlx::query!(
        r#"SELECT c.email        AS "email!",
                  i.tag          AS "inbound_tag!",
                  c.uplink_total AS "uplink_total!",
                  c.downlink_total AS "downlink_total!",
                  c.enabled      AS "enabled!",
                  c.traffic_limit_bytes,
                  c.expires_at
           FROM clients c
           JOIN inbounds i ON i.id = c.inbound_id"#
    )
    .fetch_all(db)
    .await?;
    Ok(fold_canonical_metas(rows.into_iter().map(|r| {
        let up = r.uplink_total.max(0) as u64;
        let down = r.downlink_total.max(0) as u64;
        let limit = r
            .traffic_limit_bytes
            .and_then(|v| if v < 0 { None } else { Some(v as u64) });
        (
            r.email,
            ClientMeta {
                inbound_tags: vec![r.inbound_tag],
                uplink_total: up,
                downlink_total: down,
                enabled: r.enabled != 0,
                limit_bytes: limit,
                expires_at: r.expires_at,
            },
        )
    })))
}

/// Collapse the per-`(inbound_id, email)` rows to ONE canonical `ClientMeta`
/// per email, keeping the row with the largest lifetime total.
///
/// xray accounts traffic per email — a single `user>>>{email}>>>traffic`
/// counter regardless of how many inbounds carry that email — so every row
/// sharing an email describes the SAME usage. A plain `HashMap` collect would
/// keep an arbitrary (last-yielded) row; right after a client is attached to a
/// new inbound that row is the freshly-INSERTed one with a 0 total, so the
/// poller would surface ~0 and the client's traffic (and remaining quota
/// headroom) would appear to reset. Picking the max-total row instead matches
/// the subscription builder's max-over-rows and keeps the number stable.
///
/// The canonical meta also carries the UNION of every row's inbound tag so
/// quota/expiry enforcement can drop the user from all of the email's inbounds,
/// not just the one that happened to hold the largest total.
fn fold_canonical_metas(
    pairs: impl Iterator<Item = (String, ClientMeta)>,
) -> HashMap<String, ClientMeta> {
    use std::collections::hash_map::Entry;
    let mut by_email: HashMap<String, ClientMeta> = HashMap::new();
    for (email, mut cand) in pairs {
        match by_email.entry(email) {
            Entry::Vacant(v) => {
                v.insert(cand);
            }
            Entry::Occupied(mut e) => {
                let cur = e.get_mut();
                let higher =
                    cand.uplink_total + cand.downlink_total > cur.uplink_total + cur.downlink_total;
                // Union the inbound tags — enforcement must reach every
                // attachment regardless of which row wins the totals.
                let mut tags = std::mem::take(&mut cur.inbound_tags);
                for tag in std::mem::take(&mut cand.inbound_tags) {
                    if !tags.contains(&tag) {
                        tags.push(tag);
                    }
                }
                if higher {
                    *cur = cand;
                }
                cur.inbound_tags = tags;
            }
        }
    }
    by_email
}

#[cfg(test)]
mod tests {
    use super::{ClientMeta, fold_canonical_metas, parse_counter, tag_deltas};
    use std::collections::HashMap;

    fn meta(tag: &str, up: u64, down: u64) -> ClientMeta {
        ClientMeta {
            inbound_tags: vec![tag.to_owned()],
            uplink_total: up,
            downlink_total: down,
            enabled: true,
            limit_bytes: None,
            expires_at: None,
        }
    }

    #[test]
    fn canonical_meta_keeps_highest_total_not_the_fresh_row() {
        // Same email attached to two inbounds: the original row holds ~7 GB,
        // a freshly attached inbound INSERTs a 0-total row. The 0-row is
        // yielded LAST (mimics the newest-rowid scan the old last-wins
        // collapse surfaced) — the canonical pick must still keep the 7 GB row
        // so the client's traffic and quota headroom don't reset on attach.
        let pairs = vec![
            (
                "bob@x".to_owned(),
                meta("inbA", 5_000_000_000, 2_000_000_000),
            ),
            ("bob@x".to_owned(), meta("inbB", 0, 0)),
        ];
        let out = fold_canonical_metas(pairs.into_iter());
        let m = out.get("bob@x").expect("email present");
        assert_eq!(m.uplink_total, 5_000_000_000, "kept the high-total row");
        assert_eq!(m.downlink_total, 2_000_000_000);
        // The canonical meta carries EVERY inbound the email is attached to, so
        // enforcement can drop the user from all of them — not just inbA.
        assert!(m.inbound_tags.contains(&"inbA".to_owned()));
        assert!(m.inbound_tags.contains(&"inbB".to_owned()));
        assert_eq!(m.inbound_tags.len(), 2);
    }

    #[test]
    fn canonical_meta_order_independent() {
        // Same result regardless of row order (HashMap/rowid scan is unordered).
        let hi = || ("y@z".to_owned(), meta("A", 900, 100));
        let lo = || ("y@z".to_owned(), meta("B", 0, 0));
        assert_eq!(
            fold_canonical_metas(vec![lo(), hi()].into_iter())["y@z"].uplink_total,
            900
        );
        assert_eq!(
            fold_canonical_metas(vec![hi(), lo()].into_iter())["y@z"].uplink_total,
            900
        );
    }

    #[test]
    fn parses_uplink() {
        assert_eq!(
            parse_counter("user>>>alice@x>>>traffic>>>uplink", "user>>>"),
            Some(("alice@x", "uplink"))
        );
    }

    #[test]
    fn parses_downlink_with_at() {
        assert_eq!(
            parse_counter("user>>>bob@example.com>>>traffic>>>downlink", "user>>>"),
            Some(("bob@example.com", "downlink"))
        );
    }

    #[test]
    fn tag_deltas_growth_and_restart() {
        let prev: HashMap<String, (u64, u64)> =
            [("a".to_owned(), (100, 200)), ("b".to_owned(), (50, 50))]
                .into_iter()
                .collect();
        let current: HashMap<String, (u64, u64)> =
            [("a".to_owned(), (170, 200)), ("b".to_owned(), (10, 5))]
                .into_iter()
                .collect();
        let mut out = tag_deltas(&current, &prev, |_| false);
        out.sort();
        // `a` grew by (70, 0); `b` dropped below prev (xray counter reset), so
        // the current value is credited whole rather than a wraparound subtract.
        assert_eq!(out, vec![("a".to_owned(), 70, 0), ("b".to_owned(), 10, 5)]);
    }

    #[test]
    fn tag_deltas_skips_predicate_and_drops_zero() {
        let prev: HashMap<String, (u64, u64)> = HashMap::new();
        let current: HashMap<String, (u64, u64)> = [
            ("api".to_owned(), (999, 999)),
            ("idle".to_owned(), (0, 0)),
            ("live".to_owned(), (5, 0)),
        ]
        .into_iter()
        .collect();
        let out = tag_deltas(&current, &prev, |t| t == "api");
        // `api` filtered by the skip predicate; `idle` has a zero delta and is
        // dropped; only `live` (first observation, credited whole) survives.
        assert_eq!(out, vec![("live".to_owned(), 5, 0)]);
    }

    #[test]
    fn rejects_non_user_prefix() {
        assert_eq!(
            parse_counter("inbound>>>tag>>>traffic>>>uplink", "user>>>"),
            None
        );
    }

    #[test]
    fn rejects_missing_traffic_segment() {
        assert_eq!(parse_counter("user>>>alice@x>>>online", "user>>>"), None);
    }
}
