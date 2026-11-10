//! Per-inbound lifetime traffic, as the `inbound_traffic` poller persists it.

use crate::{AppState, auth::AuthUser, error::AppResult};
use axum::{Json, extract::State};

/// Per-inbound lifetime traffic (`tag -> {uplink, downlink}`). Cumulative
/// totals persisted by the [`crate::inbound_traffic`] poller — they survive
/// xray restarts, unlike the session-only counters xray exposes directly, and
/// give an accurate per-inbound split even when one client spans several
/// inbounds (xray's per-user counters can't attribute those bytes per-inbound).
#[derive(Debug, Default, serde::Serialize, ts_rs::TS)]
#[ts(export, export_to = "../../frontend/src/api/types/inbound.ts")]
pub struct InboundTraffic {
    #[ts(type = "number")]
    pub uplink: u64,
    #[ts(type = "number")]
    pub downlink: u64,
    /// True when this inbound moved bytes on the last poll tick (~5 s) — drives
    /// the Inbounds page's live-activity glow. Accurate per inbound (computed
    /// from the poller's per-tag deltas), so it follows a client that hops
    /// between inbounds instead of sticking to the first. xray only reports the
    /// rate per email, so the front end cannot work this out on its own.
    pub live: bool,
}

pub(super) async fn stats(
    _user: AuthUser,
    State(state): State<AppState>,
) -> AppResult<Json<std::collections::HashMap<String, InboundTraffic>>> {
    let rows = sqlx::query!(
        r#"SELECT tag            AS "tag!: String",
                  uplink_total   AS "uplink_total!: i64",
                  downlink_total AS "downlink_total!: i64"
           FROM inbound_traffic"#
    )
    .fetch_all(&state.db)
    .await?;
    // Live-activity set for this instant (tags that moved bytes last tick). Read
    // once under a short lock, then looked up per row.
    let live = state.inbound_live.snapshot().await;
    #[allow(clippy::cast_sign_loss)]
    let out = rows
        .into_iter()
        .map(|r| {
            let is_live = live.contains(&r.tag);
            (
                r.tag,
                InboundTraffic {
                    uplink: r.uplink_total.max(0) as u64,
                    downlink: r.downlink_total.max(0) as u64,
                    live: is_live,
                },
            )
        })
        .collect();
    Ok(Json(out))
}
