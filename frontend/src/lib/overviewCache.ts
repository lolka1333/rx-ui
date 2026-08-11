import type { DashboardOverview } from '@/api/types';

/**
 * Last known `/dashboard/overview` payload, kept for the browser session.
 *
 * Why this exists: the sidebar's Xray plaque and the dashboard both read that
 * endpoint, and a reload used to start with nothing. The plaque painted as an
 * empty slab and then, one round trip later, sprouted a status dot, a label, a
 * version chip and a restart button all at once. The slab's height is fixed
 * (min-height 44px), so nothing moved and layout-shift instrumentation stayed
 * blind to it — but on screen it read as the sidebar flickering on every
 * refresh. Seeding the query from here means a reload paints the settled plaque
 * in its first frame and the fresh response only updates values.
 *
 * `sessionStorage` matches the auth token's lifetime (see stores/auth.ts): a new
 * browser session has no token and lands on the login screen, so a snapshot
 * carried over from a previous session could never be shown anyway.
 */
const KEY = 'app-overview-cache';

export interface CachedOverview {
  /** When the payload was received, for `initialDataUpdatedAt`. */
  at: number;
  data: DashboardOverview;
}

export function readOverviewCache(): CachedOverview | null {
  try {
    const raw = sessionStorage.getItem(KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as Partial<CachedOverview>;
    // Shape-check rather than trust: a half-written or older-format blob would
    // otherwise be handed to the UI as a real payload and crash on access. The
    // check covers exactly what the two consumers dereference without a guard —
    // `xray` for the sidebar plaque, `system` for the dashboard's gauges. A blob
    // carrying one but not the other is from an older build, not a payload.
    if (typeof parsed?.at !== 'number') return null;
    if (!parsed.data?.xray || !parsed.data.system) return null;
    return { at: parsed.at, data: parsed.data };
  } catch {
    return null;
  }
}

export function writeOverviewCache(data: DashboardOverview): void {
  try {
    sessionStorage.setItem(KEY, JSON.stringify({ at: Date.now(), data }));
  } catch {
    // Quota or a locked-down storage policy — the seed is an optimisation,
    // never a requirement, so a failed write is not worth surfacing.
  }
}

export function clearOverviewCache(): void {
  try {
    sessionStorage.removeItem(KEY);
  } catch {
    /* nothing to do — see writeOverviewCache */
  }
}
