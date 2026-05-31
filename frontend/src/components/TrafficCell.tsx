//! Two-line traffic cell used by the Clients and Inbounds tables.
//! Top line: cumulative ↑/↓ totals as preformatted strings.
//! Bottom line: a thin Antd Progress bar that doubles as a quota gauge
//! when `limit > 0` and as a neutral rhythm-line when unlimited (so
//! quota'd and unlimited rows line up vertically and the eye doesn't
//! have to retrain between them).
//!
//! The `live` flag drives the blue-glow + diagonal-stripe overlay on
//! the bar — `app-traffic-cell-live` / `app-quota-bar-live` are styled
//! in `index.css`. CSS handles the motion so React doesn't re-render
//! at animation frame rate.

import { Progress, Typography } from 'antd';
import { fmtBytes } from '@/lib/format';

const TRAFFIC_LIVE = '#60a5fa';
const TRAFFIC_OVER = '#ef4444';
const TRAFFIC_WARN = '#f59e0b';
const TRAFFIC_OK = '#10b981';

/** Quota usage → bar fill colour. Severity (`>=100`) beats live blue so a
 *  hard-cap alarm isn't masked while bytes are still flowing in the same
 *  tick xray hasn't yet picked up the AlterInbound removal. */
function trafficBarColor(pct: number, hasLimit: boolean, live: boolean): string {
  if (!hasLimit) return TRAFFIC_LIVE;
  if (pct >= 100) return TRAFFIC_OVER;
  if (live) return TRAFFIC_LIVE;
  if (pct >= 80) return TRAFFIC_WARN;
  return TRAFFIC_OK;
}

export function TrafficCell({
  up,
  down,
  live,
  used,
  limit,
}: {
  up: string;
  down: string;
  live: boolean;
  used?: number;
  limit?: number | null;
}) {
  return (
    <div className={live ? 'app-traffic-cell-live' : undefined}>
      <span style={{ fontSize: 12, whiteSpace: 'nowrap' }}>↑ {up}  ↓ {down}</span>
      <TrafficQuotaBar used={used ?? 0} limit={limit ?? null} live={live} />
    </div>
  );
}

/**
 * Thin progress bar under the byte totals. Two modes:
 *  * limited:   `used / limit` text + bar with ramp green → orange →
 *               red as the cap approaches. Live traffic shifts to blue
 *               unless the bar is already red (a hard alarm should not
 *               be coloured over).
 *  * unlimited: no text, just an empty track that brightens to blue
 *               when bytes are moving. Keeps the cell footprint uniform
 *               with quota'd rows so the table grid stays clean.
 */
function TrafficQuotaBar({
  used,
  limit,
  live,
}: {
  used: number;
  limit: number | null;
  live: boolean;
}) {
  const hasLimit = limit != null && limit > 0;
  // Unlimited rows render an empty track (pct=0) so they match the
  // visual weight of a quota'd row at low usage — the diagonal-stripe
  // overlay still rides on top via `app-quota-bar-live` when bytes are
  // moving, which is where the motion cue comes from.
  const pct = hasLimit ? Math.min(100, Math.round((used / limit) * 100)) : 0;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
      {hasLimit && (
        <Typography.Text type="secondary" style={{ fontSize: 11, whiteSpace: 'nowrap' }}>
          {fmtBytes(used)} / {fmtBytes(limit)}
        </Typography.Text>
      )}
      <Progress
        percent={pct}
        showInfo={false}
        size="small"
        strokeColor={trafficBarColor(pct, hasLimit, live)}
        strokeLinecap="butt"
        className={live ? 'app-quota-bar-live' : undefined}
      />
    </div>
  );
}
