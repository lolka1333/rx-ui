/** Client rows grouped by email: the table shows one row per user, and the
 *  per-inbound rows behind it are what every action fans out over. */
import type { Client, TrafficSnapshot } from '@/api/types';

/**
 * Map of `email → live stats`, polled every 5s from
 * `GET /api/clients/stats` (backend keeps a warm in-memory snapshot
 * driven by xray's StatsService). An empty map ≡ "no live data yet"
 * which is normal during the first 5s after backend start.
 */
export type TrafficSnapshotMap = Record<string, TrafficSnapshot>;

/** Per-email aggregate of underlying per-inbound rows. The Clients
 *  table renders one row per group; actions fan out to `rows` so the
 *  operator works on the user identity, not on the per-inbound
 *  fragments xray actually sees. Traffic / online state are already
 *  email-keyed in xray's StatsService, so reading them once per group
 *  (vs once per row) also stops the "same number on 3 rows" illusion. */
export interface ClientGroup {
  /** Email doubles as the React `rowKey` — it's unique within
   *  `clientGroups` by construction (it's literally the group key). */
  email: string;
  rows: Client[];
  /** True iff every row is enabled. The Switch shows checked only when
   *  this holds; partial state renders as off so a single toggle click
   *  flips the whole identity on. */
  allEnabled: boolean;
  anyEnabled: boolean;
  anyDisabledByQuota: boolean;
  anyDisabledByExpiry: boolean;
  /** Earliest non-null expires_at across rows (UTC string), or null if
   *  no row has an expiry. */
  expiresAt: string | null;
  /** Per-email quota = max of the per-row traffic_limit_bytes (they're kept
   *  equal by bulk-assign and enforced per email, not summed), or null if any
   *  row is unlimited (an unlimited quota swallows the others — the user gets
   *  unlimited overall). */
  totalLimit: number | null;
  inboundIds: string[];
  /** First non-empty note across the rows. Bulk-assign keeps them in
   *  sync so this is normally well-defined. */
  note: string | null;
}

/** The status filter above the table. */
export type StatusFilter = 'all' | 'online' | 'enabled' | 'disabled' | 'quota' | 'expired';

/** Email-keyed groups for the table, sorted by email so a refetch does not
 *  reshuffle them.
 *
 *  Rows are filtered first, then grouped: a group with no matching rows
 *  disappears. The status filter judges the GROUP — "enabled" means every row
 *  is enabled, "disabled" means none is. */
export function groupClients(
  clients: Client[],
  emailFilter: string,
  enabledFilter: StatusFilter,
  stats: TrafficSnapshotMap,
): ClientGroup[] {
  const needle = emailFilter.trim().toLowerCase();
  // Step 1 — narrow rows by the per-row filters (inbound, email).
  // `clients` is already server-side narrowed by `inboundIdFilter`,
  // so we don't double-filter here.
  const rowsBeforeStatus = clients.filter((c) => {
    if (needle && !c.email.toLowerCase().includes(needle)) return false;
    return true;
  });
  // Step 2 — group by email.
  const byEmail = new Map<string, Client[]>();
  for (const c of rowsBeforeStatus) {
    const list = byEmail.get(c.email);
    if (list) list.push(c);
    else byEmail.set(c.email, [c]);
  }
  // Step 3 — derive group-level metadata, then apply enabled-filter
  // on the aggregated state.
  const groups: ClientGroup[] = [];
  for (const [email, rows] of byEmail) {
    const allEnabled = rows.every((r) => r.enabled);
    const anyEnabled = rows.some((r) => r.enabled);
    const anyDisabledByQuota = rows.some(
      (r) => !r.enabled && r.disabled_reason === 'quota',
    );
    const anyDisabledByExpiry = rows.some(
      (r) => !r.enabled && r.disabled_reason === 'expired',
    );
    // Earliest expiry across the group; UTC strings sort chronologically.
    const expiresAt =
      rows
        .map((r) => r.expires_at)
        .filter((e): e is string => e != null)
        .sort()[0] ?? null;
    const limits = rows.map((r) => r.traffic_limit_bytes);
    const anyUnlimited = limits.some((l) => l == null);
    // The quota is enforced per email, not per row — bulk-assign keeps the
    // per-inbound limits equal and the backend trips on one row's cap. Take
    // the max (not the sum) so a user in N inbounds shows L, not N*L,
    // matching the subscription userinfo header.
    const totalLimit: number | null = anyUnlimited
      ? null
      : limits.reduce<number>((acc, l) => Math.max(acc, l ?? 0), 0);
    const inboundIds = Array.from(new Set(rows.map((r) => r.inbound_id)));
    if (enabledFilter === 'enabled' && !allEnabled) continue;
    if (enabledFilter === 'disabled' && anyEnabled) continue;
    if (enabledFilter === 'quota' && !anyDisabledByQuota) continue;
    if (enabledFilter === 'expired' && !anyDisabledByExpiry) continue;
    // `stats` is keyed by email; `online` per the TrafficSnapshot doc
    // is true when xray reports any active TCP connection OR any
    // bytes moved during the last poll window. Missing entry (group
    // has zero matching xray data) → counts as offline.
    if (enabledFilter === 'online' && !stats[email]?.online) continue;
    groups.push({
      email,
      rows,
      allEnabled,
      anyEnabled,
      anyDisabledByQuota,
      anyDisabledByExpiry,
      expiresAt,
      totalLimit,
      inboundIds,
      note: rows.find((r) => r.note)?.note ?? null,
    });
  }
  // Stable order — by email so the table doesn't reshuffle on refetch.
  groups.sort((a, b) => a.email.localeCompare(b.email));
  return groups;
}
