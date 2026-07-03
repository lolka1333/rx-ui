/**
 * Top-level Clients page.
 *
 * Lives in the sidebar alongside Inbounds/Dashboard. Shows every client
 * across every inbound, with filters (by inbound, email substring, enabled
 * status) and per-row CRUD. Same DB rows as the nested
 * `/api/inbounds/{id}/clients` endpoint — just queried through the global
 * `/api/clients` route with optional filters.
 *
 * Why top-level (vs nested-only inside Inbounds): under multi-node it's
 * mandatory — bulk operations, cross-inbound search, subscription URLs all
 * need a list of clients that isn't scoped to one inbound. Doing it now
 * (before multi-node) is cheaper than a UX migration later.
 *
 * Inbound assignment is explicit here (Select in the create form) because
 * the page has no implicit inbound context. The form pre-selects the
 * single inbound when only one exists, falls back to a regular Select for
 * 2-5, and shows a searchable Select for 6+.
 */
import {
  Button,
  Form,
  Input,
  InputNumber,
  Modal,
  Popconfirm,
  Popover,
  Select,
  Space,
  Switch,
  Table,
  Tabs,
  Tag,
  Typography,
  App,
  DatePicker,
} from 'antd';
import {
  DeleteOutlined,
  EditOutlined,
  PlusOutlined,
  ReloadOutlined,
  ShareAltOutlined,
  UndoOutlined,
} from '@ant-design/icons';
import {
  keepPreviousData,
  useMutation,
  useQuery,
  useQueryClient,
} from '@tanstack/react-query';
import { useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import dayjs, { type Dayjs } from 'dayjs';
import utc from 'dayjs/plugin/utc';
import { apiClient } from '@/api/client';
import { apiErrorMessage } from '@/api/errors';
import { useNav } from '@/stores/nav';
import { QrCard } from '@/components/QrCard';
import { TrafficCell } from '@/components/TrafficCell';
import { fmtBytes } from '@/lib/format';
import { useClientsFilter } from '@/stores/clientsFilter';
import type {
  Client,
  ClientBulkAssign,
  ClientBulkAssignResult,
  TrafficSnapshot,
  Inbound,
  PanelSettings,
  ShareLinkResponse,
} from '@/api/types';

// Expiry timestamps are stored UTC; parse/format them in UTC and let the
// DatePicker localize for display.
dayjs.extend(utc);

/**
 * Map of `email → live stats`, polled every 5s from
 * `GET /api/clients/stats` (backend keeps a warm in-memory snapshot
 * driven by xray's StatsService). An empty map ≡ "no live data yet"
 * which is normal during the first 5s after backend start.
 */
type TrafficSnapshotMap = Record<string, TrafficSnapshot>;


/** Canonical subscription URL the operator should share with end
 *  users. Prefers panel settings over the admin's current `window.
 *  location`:
 *   * `sub_link_host` (when set) is the host of the /sub/ URL itself —
 *     the panel's public domain, which may differ from both the admin
 *     URL and the server address baked into the configs (`sub_host_
 *     override`). Empty ≡ use the current origin's host.
 *   * `sub_port` (when non-zero) is the public subscription port; the
 *     admin port may be intentionally restricted by firewall.
 *  Falls back to current origin segments when either field is empty,
 *  which works for single-host self-hosted setups. */
function buildSubscriptionUrl(token: string, settings: PanelSettings | undefined): string {
  // Scheme follows the subscription's OWN TLS (sub_tls_mode), not the panel's:
  // 'off' → plain HTTP (a CDN/tunnel terminates TLS upstream), 'custom' → HTTPS
  // with its own cert, 'inherit' → same as the panel, i.e. the admin's current
  // origin scheme. Deriving it from window.location alone would hand out an
  // http link to a TLS listener (or vice-versa) once the two schemes diverge.
  const protocol =
    settings?.sub_tls_mode === 'off'
      ? 'http:'
      : settings?.sub_tls_mode === 'custom'
        ? 'https:'
        : window.location.protocol;
  const host = settings?.sub_link_host?.trim() || window.location.hostname;
  const port = settings && settings.sub_port > 0
    ? String(settings.sub_port)
    : window.location.port;
  // Hide the well-known ports (80/443) from the shown URL regardless of scheme:
  // operators publish the subscription behind a standard-port endpoint (a CDN /
  // tunnel on 443), where the client supplies the port implicitly. A non-standard
  // port is kept so a direct link still resolves.
  const portSuffix = port && port !== '80' && port !== '443' ? `:${port}` : '';
  return `${protocol}//${host}${portSuffix}/sub/${token}`;
}

/** Per-email aggregate of underlying per-inbound rows. The Clients
 *  table renders one row per group; actions fan out to `rows` so the
 *  operator works on the user identity, not on the per-inbound
 *  fragments xray actually sees. Traffic / online state are already
 *  email-keyed in xray's StatsService, so reading them once per group
 *  (vs once per row) also stops the "same number on 3 rows" illusion. */
interface ClientGroup {
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

interface ClientFormValues {
  /** Target inbound set — same user appears in each, sharing uuid/auth/flow.
   *  Empty array is rejected by the form's required-rule (the bulk-assign
   *  backend also rejects it, so this is double-protected). */
  inbound_ids: string[];
  email: string;
  uuid: string;
  /** Hysteria 2 per-user auth secret. Ignored for VLESS inbounds (the
   *  panel still persists whatever the operator typed for forward-compat
   *  if the inbound is later migrated to Hysteria). Empty string for
   *  vless clients in the form. */
  auth: string;
  flow: '' | 'inherit' | 'xtls-rprx-vision';
  note: string;
  /** `null` ≡ no quota. The number is in `traffic_limit_unit` units. */
  traffic_limit_value: number | null;
  traffic_limit_unit: TrafficUnit;
  /** `null` ≡ never expires. Absolute datetime; localized in the picker,
   *  sent to the backend as ISO-8601 (UTC). */
  expires_at: Dayjs | null;
}

type TrafficUnit = 'MB' | 'GB' | 'TB';

const TRAFFIC_UNIT_BYTES: Record<TrafficUnit, number> = {
  MB: 1024 ** 2,
  GB: 1024 ** 3,
  TB: 1024 ** 4,
};

/**
 * Pick the largest unit where the byte count divides cleanly, falling
 * back to MB with a fractional value when nothing fits. `null` / 0
 * ≡ "no quota" and renders as an empty input under the GB default —
 * matches the most common operator default ("set 50 GB").
 */
function bytesToTrafficForm(
  bytes: number | null | undefined,
): { value: number | null; unit: TrafficUnit } {
  if (bytes == null || bytes <= 0) return { value: null, unit: 'GB' };
  for (const unit of ['TB', 'GB', 'MB'] as const) {
    const div = TRAFFIC_UNIT_BYTES[unit];
    if (bytes >= div && bytes % div === 0) {
      return { value: bytes / div, unit };
    }
  }
  return { value: bytes / TRAFFIC_UNIT_BYTES.MB, unit: 'MB' };
}

function trafficFormToBytes(value: number | null, unit: TrafficUnit): number | null {
  if (value == null || value <= 0) return null;
  return Math.round(value * TRAFFIC_UNIT_BYTES[unit]);
}

/**
 * Conditional `auth` field for Hysteria 2 clients. Watches the form's
 * `inbound_ids` set and renders the input when ANY selected inbound's
 * protocol is `hysteria2` — the single auth value is shared across
 * every selected inbound by the bulk-assign endpoint. VLESS-only
 * selections see nothing (the wire uses `uuid` instead).
 *
 * Implemented as its own component (rather than inlined in the form) so
 * the Form.useWatch subscription only re-renders this small subtree,
 * not the whole modal body.
 */
function ClientAuthField({ inboundById }: { inboundById: Map<string, Inbound> }) {
  const { t } = useTranslation();
  const form = Form.useFormInstance();
  const inboundIds = (Form.useWatch<string[] | undefined>('inbound_ids', form)) ?? [];
  const anyHysteria = inboundIds.some(
    (id) => inboundById.get(id)?.protocol.kind === 'hysteria2',
  );
  if (!anyHysteria) return null;
  return (
    <Form.Item
      name="auth"
      label={t('clients.auth')}
      tooltip={t('clients.authTooltip')}
    >
      <Input placeholder={t('clients.authPlaceholder')} allowClear />
    </Form.Item>
  );
}

/**
 * Conditional `flow` field. XTLS Vision is a VLESS-only feature
 * (Hysteria 2 ignores it), so when the target inbound set has zero
 * VLESS rows the picker would be a no-op slot in the form. Hide it
 * instead of greying it out — the operator's eyes don't need to learn
 * "this control means nothing right now."
 */
function ClientFlowField({ inboundById }: { inboundById: Map<string, Inbound> }) {
  const { t } = useTranslation();
  const form = Form.useFormInstance();
  const inboundIds = (Form.useWatch<string[] | undefined>('inbound_ids', form)) ?? [];
  const anyVless = inboundIds.some(
    (id) => inboundById.get(id)?.protocol.kind === 'vless',
  );
  if (!anyVless) return null;
  return (
    <Form.Item name="flow" label={t('clients.flow')}>
      <Select
        options={[
          { value: 'inherit', label: t('clients.flowInherit') },
          { value: '', label: t('clients.flowNone') },
          { value: 'xtls-rprx-vision', label: 'XTLS Vision' },
        ]}
      />
    </Form.Item>
  );
}

export function Clients() {
  const { t } = useTranslation();
  const { message } = App.useApp();
  const qc = useQueryClient();
  // Only the visible tab needs to poll — the page stays mounted (display:none)
  // when you're on another tab, so without this gate its lists keep hitting the
  // API every 5s in the background, draining a phone's battery/radio for data
  // nobody is looking at. The pollers below switch off when this tab isn't
  // current.
  const isActive = useNav((s) => s.current === 'clients');

  // Filter state lives in a module store so the "N клиентов" badge on the
  // Inbounds table can pre-apply the inbound filter when it navigates here.
  const inboundIdFilter = useClientsFilter((s) => s.inboundId);
  const emailFilter = useClientsFilter((s) => s.email);
  const setInboundIdFilter = useClientsFilter((s) => s.setInboundId);
  const setEmailFilter = useClientsFilter((s) => s.setEmail);

  const [enabledFilter, setEnabledFilter] = useState<
    'all' | 'online' | 'enabled' | 'disabled' | 'quota' | 'expired'
  >('all');

  const [modalOpen, setModalOpen] = useState(false);
  const [editing, setEditing] = useState<Client | null>(null);
  // Share modal state. `group` is the whole email-aggregate so the
  // Subscription tab can use any row's sub_token (all resolve to the
  // same bundle), and the Share-link tab can offer a Select to switch
  // between the per-inbound vless:// / hysteria2:// URLs without
  // closing the modal. `currentClientId` tracks which row's share-link
  // is currently rendered — refetching on change.
  const [shareOpen, setShareOpen] = useState<{
    group: ClientGroup;
    currentClientId: string;
    share: ShareLinkResponse;
  } | null>(null);
  const [form] = Form.useForm<ClientFormValues>();

  // Inbounds — need both for the filter dropdown AND for the create-form
  // inbound select. Same query key as the Inbounds page so refetches are
  // shared.
  const { data: inbounds = [], isPending: inboundsPending } = useQuery<Inbound[]>({
    queryKey: ['inbounds'],
    queryFn: async () => (await apiClient.get<Inbound[]>('/inbounds')).data,
  });

  const inboundById = useMemo(() => {
    const m = new Map<string, Inbound>();
    for (const ib of inbounds) m.set(ib.id, ib);
    return m;
  }, [inbounds]);

  // Server-side filter only for inbound_id (it's an indexed FK column);
  // email and enabled get applied here to keep the URL clean and the
  // server-side handler simple. For ≤ a few thousand clients the latency
  // difference is invisible.
  //
  // Two queries: the filtered one drives the visible table; the
  // unfiltered one (shared cache-key with the Inbounds page's client
  // count) feeds the form's "this user already exists in inbounds X, Y"
  // pre-population so the multi-select shows the real assignment set
  // regardless of which inbound filter the page is currently scoped to.
  const { data: clients = [], isPending: clientsPending } = useQuery<Client[]>({
    queryKey: ['clients-global', inboundIdFilter],
    queryFn: async () => {
      const params: Record<string, string> = {};
      if (inboundIdFilter) params.inbound_id = inboundIdFilter;
      return (await apiClient.get<Client[]>('/clients', { params })).data;
    },
    // Keep showing the previous list while a filter change refetches —
    // otherwise switching the inbound filter would blank the table and
    // re-trigger the page-mount reveal animation.
    placeholderData: keepPreviousData,
    // Poll alongside `clients-stats` so server-side row changes the
    // operator didn't trigger themselves (poller flipping `enabled` /
    // `disabled_reason` when a client trips its quota; a limit change
    // from a parallel admin session) propagate without a manual reload.
    // Quota state and limit live on the row, not in the stats snapshot,
    // so without this the progress bar's `% used / limit` would lag
    // until the next mutation invalidated the cache.
    refetchInterval: isActive ? 5_000 : false,
  });

  // Unfiltered global client list — needed by the form's multi-select
  // to show which inbounds the edited email is already assigned to,
  // even when the visible table is filtered down to one inbound.
  // Shares the cache key with the Inbounds page so the request is
  // deduped on tabs where both pages have been visited.
  const { data: allClients = [] } = useQuery<Client[]>({
    queryKey: ['clients-global', null],
    queryFn: async () => (await apiClient.get<Client[]>('/clients')).data,
    refetchInterval: isActive ? 5_000 : false,
  });

  // Live online + traffic snapshot. Backend keeps a 5 s-warm in-memory
  // map populated by xray's StatsService; this query polls at the same
  // cadence so the UI rate matches the underlying delta window.
  // `refetchIntervalInBackground: false` (default) — we don't burn
  // CPU when the tab is hidden.
  const { data: stats = {} } = useQuery<TrafficSnapshotMap>({
    queryKey: ['clients-stats'],
    queryFn: async () => (await apiClient.get<TrafficSnapshotMap>('/clients/stats')).data,
    refetchInterval: isActive ? 5_000 : false,
  });

  // Email-keyed groups for the table. One row per email — the
  // underlying per-inbound rows are accessible via `rows[]` so actions
  // (toggle / reset / delete / share) can fan out across them.
  //
  // Filter logic: we filter rows first, then group. If a group has zero
  // matching rows under the current filter, it disappears entirely. The
  // enabled filter is applied at the GROUP level using
  // `allEnabled` / `anyDisabledByQuota` so a partially-disabled client
  // shows up under both "enabled" (some rows are) and "disabled" (some
  // rows aren't) — wait, that's confusing. Keep it simple: a group
  // counts as enabled iff ALL its rows are enabled.
  const clientGroups = useMemo(() => {
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
  }, [clients, emailFilter, enabledFilter, stats]);

  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ['clients-global'] });
    // The nested-list cache (per-inbound) also goes stale.
    qc.invalidateQueries({ queryKey: ['clients'] });
  };

  // === mutations ==========================================================

  // === group-level fanouts ================================================
  // Each operates on every row in an email-group in parallel — the
  // table renders one row per email but the per-inbound rows still
  // need individual API calls. `Promise.allSettled` so a partial
  // failure surfaces but doesn't strand the others. Caches invalidate
  // once at the end (single refetch, no thrash).

  // Group fanouts. `email` rides along on the variables so the table's
  // per-row spinner can match `mutation.variables?.email === g.email`
  // — using `rows[0].email` would be fragile across refetch reshuffles
  // (the same email's first row id can change). Also: the toggle is
  // optimistic, so `invalidate()` only fires on actual failure —
  // running it unconditionally would lap concurrent toggles and
  // overwrite their optimistic state with a half-applied server
  // snapshot.
  const toggleGroup = useMutation({
    mutationFn: async ({
      rows,
      enabled,
    }: {
      email: string;
      rows: Client[];
      enabled: boolean;
    }) => {
      // Hold the save for at least ~250ms so the switch's loading spinner is
      // actually visible even when the backend answers in a few ms. The flip
      // itself is already instant (optimistic onMutate) — this only keeps the
      // "saving" spinner on screen long enough to read, it doesn't delay the
      // real state change.
      const [results] = await Promise.all([
        Promise.allSettled(
          rows.map((r) => apiClient.patch(`/clients/${r.id}`, { enabled })),
        ),
        new Promise((resolve) => {
          setTimeout(resolve, 250);
        }),
      ]);
      const failed = results.filter((r) => r.status === 'rejected').length;
      return { total: rows.length, failed };
    },
    onMutate: ({ rows, enabled }) => {
      const ids = new Set(rows.map((r) => r.id));
      const snapshots = qc.getQueriesData<Client[]>({ queryKey: ['clients-global'] });
      qc.setQueriesData<Client[]>({ queryKey: ['clients-global'] }, (old) =>
        old?.map((c) => (ids.has(c.id) ? { ...c, enabled } : c)),
      );
      return { snapshots };
    },
    onError: (err: unknown, _vars, ctx) => {
      if (ctx?.snapshots) {
        for (const [key, data] of ctx.snapshots) qc.setQueryData(key, data);
      }
      message.error(apiErrorMessage(err) ?? t('clients.saveError'));
      invalidate();
    },
    onSuccess: (r) => {
      if (r.failed > 0) {
        message.warning(t('clients.partialFailure', { failed: r.failed, total: r.total }));
        invalidate();
      }
      // Happy path: trust the optimistic patch; the 5-second poll will
      // reconcile any drift without thrashing concurrent toggles.
    },
  });

  const resetTrafficGroup = useMutation({
    mutationFn: async ({ rows }: { email: string; rows: Client[] }) => {
      const results = await Promise.allSettled(
        rows.map((r) => apiClient.post(`/clients/${r.id}/reset-traffic`)),
      );
      return {
        total: rows.length,
        failed: results.filter((r) => r.status === 'rejected').length,
      };
    },
    onSuccess: (r) => {
      qc.invalidateQueries({ queryKey: ['clients-stats'] });
      // Always refetch `clients-global`: a successful reset against a
      // quota-disabled client flips `enabled` back on and clears
      // `disabled_reason` server-side. Without this the table row
      // sits in the "Quota exceeded" filter bucket with a stale
      // Switch for up to 5 s until the poller catches up.
      invalidate();
      if (r.failed > 0) {
        message.warning(t('clients.partialFailure', { failed: r.failed, total: r.total }));
      } else {
        message.success(t('clients.trafficReset'));
      }
    },
    onError: (err: unknown) => {
      invalidate();
      message.error(apiErrorMessage(err) ?? t('clients.saveError'));
    },
  });

  const deleteGroup = useMutation({
    mutationFn: async ({ rows }: { email: string; rows: Client[] }) => {
      const results = await Promise.allSettled(
        rows.map((r) => apiClient.delete(`/clients/${r.id}`)),
      );
      return {
        total: rows.length,
        failed: results.filter((r) => r.status === 'rejected').length,
      };
    },
    // Optimistic removal: drop the rows from every `['clients-global', *]`
    // cache key synchronously so the table row disappears in the same
    // React tick. If the request fails (network OR partial-server-side)
    // we restore the snapshot in onError; a 5-s poll would correct it
    // anyway, but this stops the brief "ghost row" flash that the
    // user can spam-click. Matches the `toggleGroup` optimistic pattern.
    onMutate: ({ rows }) => {
      const ids = new Set(rows.map((r) => r.id));
      const snapshots = qc.getQueriesData<Client[]>({ queryKey: ['clients-global'] });
      qc.setQueriesData<Client[]>({ queryKey: ['clients-global'] }, (old) =>
        old?.filter((c) => !ids.has(c.id)),
      );
      return { snapshots };
    },
    onSuccess: (r) => {
      if (r.failed > 0) {
        // Partial failure: some rows are still server-side. Refetch
        // restores them visibly instead of leaving the optimistic
        // delete in place.
        invalidate();
        message.warning(t('clients.partialFailure', { failed: r.failed, total: r.total }));
      } else {
        // Total success — trust the optimistic delete. The 5-s poll
        // will reconcile any drift; no need to thrash the cache.
        message.success(t('clients.deleted'));
      }
    },
    onError: (err: unknown, _vars, ctx) => {
      // Network-level fail. Some deletes may already have committed
      // server-side; restore the snapshot then invalidate so the
      // refetched list matches reality.
      if (ctx?.snapshots) {
        for (const [key, data] of ctx.snapshots) qc.setQueryData(key, data);
      }
      invalidate();
      message.error(apiErrorMessage(err) ?? t('clients.saveError'));
    },
  });

  // Single save path: bulk-assign reconciles the per-inbound rows for
  // this email to the form's `inbound_ids` set. Create flow and edit
  // flow share the same endpoint — the backend's set math handles the
  // "no existing rows for this email" case as N pure INSERTs, and the
  // "edited row removed from an inbound" case as the matching DELETE.
  //
  // What this intentionally drops: changing `enabled` from the modal.
  // It's driven by the inline switch in the row; bundling it here lets
  // a stale form value flip a client that another tab (or the poller's
  // quota re-enable path) just changed.
  const save = useMutation({
    mutationFn: async (values: ClientFormValues) => {
      const flow = values.flow === 'inherit' ? null : values.flow;
      const trafficLimitBytes = trafficFormToBytes(
        values.traffic_limit_value,
        values.traffic_limit_unit,
      );
      const body: ClientBulkAssign = {
        email: values.email.trim(),
        inbound_ids: values.inbound_ids,
        uuid: values.uuid?.trim() ? values.uuid.trim() : null,
        // Empty auth → null. Backend mints one for hysteria inbounds in
        // the target set; vless inbounds ignore the column. `?.` is
        // load-bearing: ClientAuthField renders the `auth` Form.Item only
        // for hysteria targets, so on a VLESS-only selection the field is
        // never registered and `values.auth` is `undefined` — a bare
        // `.trim()` there threw a TypeError *before* the request was sent,
        // which surfaced (misleadingly) as "couldn't connect to backend".
        auth: values.auth?.trim() ? values.auth.trim() : null,
        flow,
        note: values.note || null,
        traffic_limit_bytes: trafficLimitBytes,
        expires_at: values.expires_at ? values.expires_at.toISOString() : null,
      };
      return (await apiClient.post<ClientBulkAssignResult>('/clients/bulk-assign', body))
        .data;
    },
    onSuccess: (result) => {
      invalidate();
      setModalOpen(false);
      setEditing(null);
      const parts: string[] = [];
      if (result.created.length > 0) parts.push(`+${result.created.length}`);
      if (result.updated.length > 0) parts.push(`±${result.updated.length}`);
      if (result.removed.length > 0) parts.push(`−${result.removed.length}`);
      const stats = parts.length > 0 ? ` (${parts.join(' ')})` : '';
      message.success((editing ? t('clients.saved') : t('clients.created')) + stats);
      // DB succeeded, but one or more xray gRPC pushes didn't — the
      // operator needs to know so they can hit "Restart xray" instead
      // of watching the affected users silently fail to connect.
      if (result.xray_failures.length > 0) {
        const tags = result.xray_failures.map((f) => f.inbound_tag).join(', ');
        // 8 s timeout (default is 3 s) — this is an actionable
        // warning ("Restart xray to apply"); the operator stacks
        // success + warning toasts and we don't want the warning to
        // vanish while they're still reading the success line above.
        message.warning(t('clients.xrayDrift', { tags }), 8);
      }
    },
    onError: (err: unknown) =>
      message.error(apiErrorMessage(err) ?? t('clients.saveError')),
  });

  // Two flavors: opening from a fresh table-row click takes a whole
  // group; switching inbounds inside the already-open modal takes just
  // the client. Both fetch the same per-row share-link endpoint, only
  // the state-setter differs.
  const openShare = useMutation({
    mutationFn: async (group: ClientGroup) => {
      const client = group.rows[0];
      const share = (
        await apiClient.get<ShareLinkResponse>(`/clients/${client.id}/share-link`)
      ).data;
      return { group, currentClientId: client.id, share };
    },
    onSuccess: (resp) => setShareOpen(resp),
    onError: (err: unknown) =>
      message.error(apiErrorMessage(err) ?? t('clients.saveError')),
  });
  const switchShareInbound = useMutation({
    mutationFn: async (client: Client) => {
      const share = (
        await apiClient.get<ShareLinkResponse>(`/clients/${client.id}/share-link`)
      ).data;
      return { clientId: client.id, share };
    },
    onSuccess: ({ clientId, share }) => {
      setShareOpen((cur) =>
        cur ? { ...cur, currentClientId: clientId, share } : cur,
      );
    },
    onError: (err: unknown) =>
      message.error(apiErrorMessage(err) ?? t('clients.saveError')),
  });

  // Rotate the per-client subscription token. The previous URL stops
  // resolving the moment the response lands — useful when a URL leaks
  // or the operator just wants a clean break for a paying customer.
  // Refetches the global client list so the new token shows up on
  // every page that shares the cache.
  const rotateSubToken = useMutation({
    mutationFn: async (clientId: string) =>
      (await apiClient.post<Client>(`/clients/${clientId}/rotate-sub-token`)).data,
    onSuccess: (updated) => {
      qc.invalidateQueries({ queryKey: ['clients-global'] });
      // Patch the open group's row in place so the QR re-renders with
      // the new token without waiting for the cache refetch.
      setShareOpen((cur) => {
        if (!cur) return cur;
        const rows = cur.group.rows.map((r) => (r.id === updated.id ? updated : r));
        return { ...cur, group: { ...cur.group, rows } };
      });
      message.success(t('clients.subRotated'));
    },
    onError: (err: unknown) =>
      message.error(apiErrorMessage(err) ?? t('clients.saveError')),
  });

  // === modal controls =====================================================

  const openCreate = () => {
    setEditing(null);
    setModalOpen(true);
  };
  const openEdit = (c: Client) => {
    setEditing(c);
    setModalOpen(true);
  };

  // Sensible default for the create form's inbound multi-select:
  //   * editing existing email → every inbound that email is already in
  //   * create + filter active → pre-select the filtered inbound
  //   * create + single inbound → pre-select it
  //   * otherwise → empty (operator must pick at least one)
  const editingInboundIds = useMemo(() => {
    if (!editing) return null;
    return allClients
      .filter((c) => c.email === editing.email)
      .map((c) => c.inbound_id);
  }, [editing, allClients]);
  const defaultCreateInboundIds: string[] = inboundIdFilter
    ? [inboundIdFilter]
    : inbounds.length === 1
      ? [inbounds[0].id]
      : [];

  // Seed the form when the modal opens — and only then. The modal reuses a
  // single controlled `form` instance whose store outlives each open, and
  // antd merges that lingering store *on top of* `initialValues` — so the
  // prop loses, the fields kept stale data, and after a create the next edit
  // showed a blank form. Writing the values imperatively here sidesteps the
  // merge entirely. editingInboundIds/defaultCreateInboundIds are read fresh
  // at open time but kept out of the deps on purpose: they change on
  // background client-list refetches, and re-seeding mid-edit would clobber
  // whatever the operator is typing.
  useEffect(() => {
    if (!modalOpen) return;
    const tl = bytesToTrafficForm(editing?.traffic_limit_bytes);
    form.setFieldsValue({
      inbound_ids: editingInboundIds ?? defaultCreateInboundIds,
      email: editing?.email ?? '',
      uuid: editing?.uuid ?? '',
      auth: editing?.auth ?? '',
      flow: editing
        ? editing.flow == null
          ? 'inherit'
          : editing.flow === 'xtls-rprx-vision'
            ? 'xtls-rprx-vision'
            : ''
        : 'inherit',
      note: editing?.note ?? '',
      traffic_limit_value: tl.value,
      traffic_limit_unit: tl.unit,
      expires_at: editing?.expires_at ? dayjs.utc(editing.expires_at).local() : null,
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [modalOpen, editing, form]);

  // Auto-clear inbound filter if the selected inbound vanishes (deleted
  // from another tab). Otherwise the badge "filtering by [gone inbound]"
  // sticks indefinitely.
  useEffect(() => {
    if (inboundIdFilter && !inboundById.has(inboundIdFilter)) {
      setInboundIdFilter(null);
    }
  }, [inboundById, inboundIdFilter, setInboundIdFilter]);

  // === render =============================================================

  // Mirror the Inbounds/Dashboard pattern: render nothing until BOTH the
  // inbounds list and clients list have loaded for the first time. Without
  // this gate the table would mount immediately with `[]` defaults, paint
  // the empty state, then snap to the populated rows a moment later —
  // ruining the smooth fade-in. `app-content-reveal` then animates the
  // already-populated content as a single unit.
  if (clientsPending || inboundsPending) {
    return null;
  }

  return (
    <div className="app-content-reveal">
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: 12,
          marginBottom: 16,
        }}
      >
        <Button
          type="primary"
          icon={<PlusOutlined />}
          onClick={openCreate}
          style={{ marginLeft: 'auto' }}
        >
          {t('clients.add')}
        </Button>
      </div>

      {/* Filter bar: inbound, email, enabled. Wraps onto multiple rows on
          narrow viewports — each Select / Input is min-width-bounded but
          flex-grows to fill available space. */}
      <div
        style={{
          display: 'flex',
          flexWrap: 'wrap',
          gap: 8,
          marginBottom: 12,
        }}
      >
        <Select
          allowClear
          showSearch={{ optionFilterProp: 'label' }}
          placeholder={t('clients.filterInbound')}
          value={inboundIdFilter ?? undefined}
          onChange={(v) => setInboundIdFilter(v ?? null)}
          style={{ minWidth: 200, flex: 1 }}
          options={inbounds.map((ib) => ({ value: ib.id, label: ib.tag }))}
        />
        <Input.Search
          allowClear
          name="clients-filter-email"
          placeholder={t('clients.filterEmail')}
          value={emailFilter}
          onChange={(e) => setEmailFilter(e.target.value)}
          style={{ minWidth: 200, flex: 1 }}
        />
        <Select
          value={enabledFilter}
          onChange={setEnabledFilter}
          style={{ minWidth: 140 }}
          options={[
            { value: 'all', label: t('clients.filterStatusAll') },
            { value: 'online', label: t('clients.filterStatusOnline') },
            { value: 'enabled', label: t('clients.filterStatusEnabled') },
            { value: 'disabled', label: t('clients.filterStatusDisabled') },
            { value: 'quota', label: t('clients.filterStatusQuota') },
            { value: 'expired', label: t('clients.filterStatusExpired') },
          ]}
        />
      </div>

      <Table<ClientGroup>
        rowKey="email"
        dataSource={clientGroups}
        pagination={{
          defaultPageSize: 25,
          showSizeChanger: true,
          pageSizeOptions: ['10', '25', '50', '100'],
        }}
        size="small"
        scroll={{ x: 'max-content' }}
        locale={{
          emptyText: (
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              {clients.length === 0
                ? t('clients.empty')
                : t('clients.emptyFiltered')}
            </Typography.Text>
          ),
        }}
        columns={[
          {
            title: '',
            key: 'enabled',
            width: 50,
            // Switch is checked only when ALL rows in the group are
            // enabled — partial state renders as off, so one click
            // flips the whole identity on (no ambiguity about what
            // "checked" means for a mixed group). `loading` while the save
            // is in flight shows a spinner AND blocks re-clicks, so spamming
            // it back-and-forth can't flood the API or thrash the list. antd
            // draws a not-allowed cursor on a loading switch; index.css
            // overrides it to a pointer so it reads as "saving", not "blocked".
            render: (_, g) => (
              <Switch
                size="small"
                checked={g.allEnabled}
                loading={
                  toggleGroup.isPending &&
                  toggleGroup.variables?.email === g.email
                }
                onChange={(v) =>
                  toggleGroup.mutate({ email: g.email, rows: g.rows, enabled: v })
                }
              />
            ),
          },
          {
            // Email + first non-empty note across the group's rows. The
            // note is per-row in the DB but bulk-assign keeps them in
            // sync, so taking the first non-empty is harmless and reads
            // as "the user's note."
            title: t('clients.email'),
            key: 'email',
            render: (_, g) => (
              <div style={{ display: 'flex', flexDirection: 'column', minWidth: 0 }}>
                <Typography.Text strong>{g.email}</Typography.Text>
                {g.note && (
                  <Typography.Text
                    type="secondary"
                    ellipsis={{ tooltip: g.note }}
                    style={{ fontSize: 11, lineHeight: '14px' }}
                  >
                    {g.note}
                  </Typography.Text>
                )}
                {g.expiresAt && (
                  <Typography.Text
                    type={g.anyDisabledByExpiry ? 'danger' : 'secondary'}
                    style={{ fontSize: 11, lineHeight: '14px' }}
                  >
                    {g.anyDisabledByExpiry
                      ? t('clients.expired')
                      : t('clients.expiresOn', {
                          date: dayjs
                            .utc(g.expiresAt)
                            .local()
                            .format('YYYY-MM-DD HH:mm'),
                        })}
                  </Typography.Text>
                )}
              </div>
            ),
          },
          {
            title: t('clients.inbound'),
            key: 'inbound',
            render: (_, g) => (
              <InboundTags
                inboundIds={g.inboundIds}
                inboundById={inboundById}
                onPickFilter={setInboundIdFilter}
              />
            ),
          },
          {
            title: t('clients.online'),
            key: 'online',
            width: 90,
            align: 'center',
            // Online state is per-email in xray's StatsService — all
            // rows of the group share it. Read once.
            render: (_, g) => {
              const online = stats[g.email]?.online ?? false;
              // Real CSS dot — bullet glyphs (●/○) hint at the font's
              // own dot metrics, which on Inter/Segoe UI render
              // stem-heavy and slightly off-baseline. `vertical-align:
              // middle` aligns the dot to the text's lowercase visual
              // centre (not the line-box centre), which for short
              // Cyrillic labels with no descenders is what reads as
              // "centred". The `.live` pulse comes from the same
              // status-dot class as the xray indicator.
              // Hand-styled Tag instead of Antd's `color="green"`
              // preset — the latter resolves to #52c41a (lime-yellow
              // green that reads sickly against the dark surface).
              // Emerald 500 matches the dot colour and the accent
              // palette. `variant="filled"` drops the 1 px outline —
              // on a low-contrast translucent fill the border showed
              // as a pale rim that read as "white stripes" against
              // the dark table row. Fixed `minWidth` keeps online
              // and offline pills the same width so the column
              // doesn't wobble between "в сети" and "не в сети".
              const fg = online ? '#34d399' : '#94a3b8';
              const bg = online ? 'rgba(34, 197, 94, 0.14)' : 'rgba(148, 163, 184, 0.12)';
              return (
                <Tag
                  variant="filled"
                  style={{
                    color: fg,
                    background: bg,
                    minWidth: 78,
                    textAlign: 'center',
                    margin: 0,
                  }}
                >
                  <span
                    className="app-status-dot"
                    style={{
                      color: fg,
                      verticalAlign: 'middle',
                      marginInlineEnd: 6,
                    }}
                  />
                  {online ? t('clients.statusOnline') : t('clients.statusOffline')}
                </Tag>
              );
            },
          },
          {
            title: t('clients.traffic'),
            key: 'traffic',
            width: 200,
            // Traffic and rate are email-keyed in xray's StatsService —
            // read once per group (vs once per row), so the same number
            // doesn't appear on three rows of the same identity. Limit
            // is the aggregate cap across the group's rows; unlimited
            // on ANY row makes the group unlimited.
            render: (_, g) => {
              const s = stats[g.email];
              if (!s) {
                return <Typography.Text type="secondary">—</Typography.Text>;
              }
              const live =
                g.anyEnabled && (s.uplink_bps > 0 || s.downlink_bps > 0);
              return (
                <TrafficCell
                  live={live}
                  up={fmtBytes(s.uplink_total)}
                  down={fmtBytes(s.downlink_total)}
                  used={s.uplink_total + s.downlink_total}
                  limit={g.totalLimit}
                />
              );
            },
          },
          {
            title: t('clients.rate'),
            key: 'rate',
            width: 180,
            align: 'center',
            render: (_, g) => {
              const s = stats[g.email];
              if (!s || (s.uplink_bps === 0 && s.downlink_bps === 0)) {
                return <Typography.Text type="secondary">—</Typography.Text>;
              }
              return (
                <span
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: 12,
                    fontSize: 12,
                    color: '#60a5fa',
                    fontVariantNumeric: 'tabular-nums',
                    whiteSpace: 'nowrap',
                  }}
                >
                  <span>↑ {fmtBytes(s.uplink_bps)}/s</span>
                  <span>↓ {fmtBytes(s.downlink_bps)}/s</span>
                </span>
              );
            },
          },
          {
            title: t('clients.actions'),
            key: 'actions',
            align: 'right',
            width: 180,
            render: (_, g) => (
              <Space>
                <Button
                  type="text"
                  size="small"
                  icon={<ShareAltOutlined />}
                  loading={
                    openShare.isPending && openShare.variables?.email === g.email
                  }
                  onClick={() => openShare.mutate(g)}
                  title={t('clients.shareLink')}
                />
                <Popconfirm
                  title={t('clients.resetTrafficConfirm')}
                  okText={t('common.confirm')}
                  cancelText={t('common.cancel')}
                  onConfirm={() =>
                    resetTrafficGroup.mutate({ email: g.email, rows: g.rows })
                  }
                >
                  <Button
                    type="text"
                    size="small"
                    icon={<UndoOutlined />}
                    loading={
                      resetTrafficGroup.isPending &&
                      resetTrafficGroup.variables?.email === g.email
                    }
                    title={t('clients.resetTraffic')}
                  />
                </Popconfirm>
                <Button
                  type="text"
                  size="small"
                  icon={<EditOutlined />}
                  onClick={() => openEdit(g.rows[0])}
                />
                <Popconfirm
                  title={t('clients.deleteConfirm')}
                  okType="danger"
                  okText={t('common.delete')}
                  cancelText={t('common.cancel')}
                  onConfirm={() =>
                    deleteGroup.mutate({ email: g.email, rows: g.rows })
                  }
                >
                  <Button type="text" danger size="small" icon={<DeleteOutlined />} />
                </Popconfirm>
              </Space>
            ),
          },
        ]}
      />

      {/* Create/Edit modal. The inbound multi-select IS editable in edit
          mode — bulk-assign adds/removes the email's per-inbound rows
          atomically. The email field, by contrast, is locked in edit mode:
          it is the client's identity (bulk-assign keys on it), so changing
          it would spawn a NEW client rather than rename the existing one.
          Delete + recreate to rename. */}
      <Modal
        destroyOnHidden
        open={modalOpen}
        title={
          editing
            ? t('clients.editTitle', { email: editing.email })
            : t('clients.newTitle')
        }
        onCancel={() => {
          setModalOpen(false);
          setEditing(null);
        }}
        onOk={() => form.submit()}
        confirmLoading={save.isPending}
        okText={t('common.save')}
        cancelText={t('common.cancel')}
        okButtonProps={{ disabled: inbounds.length === 0 }}
      >
        {inbounds.length === 0 ? (
          <Typography.Text type="warning">
            {t('clients.noInboundsYet')}
          </Typography.Text>
        ) : (
          // One controlled `form` instance, reused across opens and seeded
          // imperatively by the effect above — see the note there on why an
          // `initialValues` prop alone didn't hold.
          <Form form={form} layout="vertical" onFinish={(v) => save.mutate(v)}>
            {/* Multi-select inbounds — the same user gets created in
                each selected inbound, sharing uuid/auth/flow/limit. On
                edit, this is pre-populated with every inbound the email
                is currently assigned to; toggling adds/removes
                assignments atomically via bulk-assign. */}
            <Form.Item
              name="inbound_ids"
              label={t('clients.inboundMulti')}
              tooltip={t('clients.inboundMultiTooltip')}
              rules={[
                {
                  validator: (_, v) =>
                    Array.isArray(v) && v.length > 0
                      ? Promise.resolve()
                      : Promise.reject(new Error(t('clients.inboundRequired'))),
                },
              ]}
            >
              <Select
                mode="multiple"
                showSearch={{ optionFilterProp: 'label' }}
                placeholder={t('clients.inboundPlaceholder')}
                // `maxTagCount="responsive"` — Antd measures the
                // control width and folds the overflow into a single
                // "+N…" pill with a hover tooltip listing the rest.
                // Stops the modal from stretching when a user picks
                // a lot of inbounds (or just a couple with long tags).
                maxTagCount="responsive"
                options={inbounds.map((ib) => ({ value: ib.id, label: ib.tag }))}
              />
            </Form.Item>
            <Form.Item
              name="email"
              label={t('clients.email')}
              tooltip={editing ? t('clients.emailLockedTooltip') : undefined}
              rules={[{ required: true, message: t('clients.emailRequired') }]}
            >
              {/* Locked in edit mode: bulk-assign keys on email, so changing
                  it would create a new client instead of renaming. */}
              <Input placeholder="user@example.com" disabled={!!editing} />
            </Form.Item>
            <Form.Item
              name="uuid"
              label={t('clients.uuid')}
              tooltip={t('clients.uuidTooltip')}
            >
              <Input placeholder={t('clients.uuidPlaceholder')} />
            </Form.Item>
            {/* Hysteria 2 per-user auth secret. Only mounted when the
                selected parent inbound's protocol is hysteria2 — for
                VLESS the field would be ignored on the wire and just
                confuse the operator. Watches `inbound_id` so the field
                appears immediately when the operator switches the parent
                in the Select above. */}
            <ClientAuthField inboundById={inboundById} />
            <ClientFlowField inboundById={inboundById} />
            {/* Single-line Input, not TextArea: notes for VLESS users are
                typically short labels ("Bob's laptop", "office router") —
                a 2-row TextArea looks empty and visually heavy. If the
                operator ever wants multi-line content there's `\n`-aware
                copy-paste, but the affordance stays compact. */}
            <Form.Item name="note" label={t('clients.note')}>
              <Input placeholder={t('clients.notePlaceholder')} />
            </Form.Item>
            {/* Traffic limit: empty number = unlimited. Two fields paired
                in Space.Compact so they read as one control. Number takes
                the bulk of the width, unit is a fixed-width picker. */}
            {/* The outer Form.Item has a `label` but no `name` (it's a
                composite wrapper for two named children inside the
                Space.Compact). Antd's generated <label> would be orphan
                in that case, so we point `htmlFor` at the first inner
                field so the label-to-control association is valid. */}
            <Form.Item
              label={t('clients.trafficLimit')}
              tooltip={t('clients.trafficLimitTooltip')}
              htmlFor="traffic_limit_value"
            >
              <Space.Compact style={{ width: '100%' }}>
                <Form.Item name="traffic_limit_value" noStyle>
                  <InputNumber
                    min={0}
                    step={1}
                    placeholder={t('clients.limitUnlimited')}
                    style={{ width: '100%' }}
                  />
                </Form.Item>
                <Form.Item name="traffic_limit_unit" noStyle>
                  <Select
                    style={{ width: 96 }}
                    options={[
                      { value: 'MB', label: 'MB' },
                      { value: 'GB', label: 'GB' },
                      { value: 'TB', label: 'TB' },
                    ]}
                  />
                </Form.Item>
              </Space.Compact>
            </Form.Item>
            {/* Expiry: empty = never. showTime because the cutoff is a
                datetime, not a date. Stored UTC, shown in local. */}
            <Form.Item
              name="expires_at"
              label={t('clients.expiry')}
              tooltip={t('clients.expiryTooltip')}
            >
              <DatePicker
                showTime
                format="YYYY-MM-DD HH:mm:ss"
                inputReadOnly
                style={{ width: '100%' }}
                placeholder={t('clients.expiryNever')}
                classNames={{ popup: { root: 'expiry-picker-dropdown' } }}
              />
            </Form.Item>
            {/* Enabled state is operated from the inline switch in the
                table row instead — keeping both controls drifted in
                practice because the modal's form snapshot doesn't follow
                background refetches (poller re-enable after reset, a
                parallel admin tab, etc.). One source of truth → no
                stale toggle, fewer footgun moments. */}
          </Form>
        )}
      </Modal>

      {/* Share modal — two tabs: a single vless:// link (the original
          QR) and a multi-config subscription URL (one URL → every
          share-link for this email, auto-imported by v2rayN / Hiddify /
          sing-box). QRs render as SVG so they stay crisp at any size;
          background stays white regardless of theme — that's a hard
          requirement for reliable scanning by client cameras. */}
      <Modal
        destroyOnHidden
        open={shareOpen != null}
        title={t('clients.shareLinkTitle')}
        onCancel={() => setShareOpen(null)}
        onOk={() => setShareOpen(null)}
        okText={t('common.close')}
        cancelButtonProps={{ style: { display: 'none' } }}
      >
        {shareOpen && (
          <Tabs
            // Subscription tab opens by default for multi-inbound groups
            // — the one URL covers all configs and is the recommended
            // import path. Single-inbound clients see the direct
            // share-link tab first (subscription is overkill for one).
            defaultActiveKey={shareOpen.group.rows.length > 1 ? 'sub' : 'link'}
            items={[
              {
                key: 'link',
                label: t('clients.shareTabLink'),
                children: (
                  <ShareLinkPane
                    group={shareOpen.group}
                    currentClientId={shareOpen.currentClientId}
                    share={shareOpen.share}
                    inboundById={inboundById}
                    onSwitchInbound={(client) => switchShareInbound.mutate(client)}
                    switching={switchShareInbound.isPending}
                  />
                ),
              },
              {
                key: 'sub',
                label: t('clients.shareTabSub'),
                children: (
                  <SubscriptionPane
                    client={shareOpen.group.rows[0]}
                    onRotate={() =>
                      rotateSubToken.mutate(shareOpen.group.rows[0].id)
                    }
                    rotating={rotateSubToken.isPending}
                  />
                ),
              },
            ]}
          />
        )}
      </Modal>
    </div>
  );
}

// =============================================================================
// Share-pane tab bodies
// =============================================================================

/** "Share link" tab — one inbound's vless:// / hysteria2:// URL with
 *  QR + textarea + copy. For multi-inbound groups a Select at the top
 *  switches between rows without closing the modal (each row gets its
 *  own share-link fetched lazily). For single-inbound groups the
 *  Select is hidden — the link IS the only choice. */
function ShareLinkPane({
  group,
  currentClientId,
  share,
  inboundById,
  onSwitchInbound,
  switching,
}: {
  group: ClientGroup;
  currentClientId: string;
  share: ShareLinkResponse;
  inboundById: Map<string, Inbound>;
  onSwitchInbound: (client: Client) => void;
  switching: boolean;
}) {
  const { t } = useTranslation();
  return (
    <Space orientation="vertical" style={{ width: '100%' }} size={16}>
      {group.rows.length > 1 && (
        <Select
          value={currentClientId}
          onChange={(id) => {
            const next = group.rows.find((r) => r.id === id);
            if (next) onSwitchInbound(next);
          }}
          loading={switching}
          style={{ width: '100%' }}
          options={group.rows.map((r) => ({
            value: r.id,
            label: inboundById.get(r.inbound_id)?.tag ?? r.inbound_id.slice(0, 8),
          }))}
        />
      )}
      {/* VLESS-encryption share-links carry a 1579-byte ML-KEM public
          key — total URL ≈ 1800 chars, forcing a high-version QR
          (~v25). `level="L"` drops error correction so the modules
          fit; larger `size` for long links keeps each module
          camera-readable. */}
      <QrCard
        value={share.link}
        size={share.link.length > 800 ? 288 : 224}
        level="L"
      />
      {share.link.length > 800 && (
        <Typography.Text
          type="secondary"
          style={{ fontSize: 11, display: 'block', textAlign: 'center', marginTop: -8 }}
        >
          {t('clients.shareLinkLargeQrHint')}
        </Typography.Text>
      )}
      <Typography.Text type="secondary" style={{ fontSize: 12 }}>
        {t('clients.shareLinkHost')}: <Typography.Text code>{share.host}</Typography.Text>
      </Typography.Text>
      <Input.TextArea
        value={share.link}
        autoSize={{ minRows: 3, maxRows: 6 }}
        readOnly
        style={{
          fontFamily: 'ui-monospace, "JetBrains Mono", Consolas, monospace',
          fontSize: 12,
        }}
      />
      <Typography.Text copyable={{ text: share.link }}>
        {t('clients.copy')}
      </Typography.Text>
    </Space>
  );
}

/** "Subscription" tab — public `/sub/{token}` URL with QR, copy, and a
 *  confirmed rotate action. URL is derived from the current page origin
 *  so the panel doesn't have to know its own external hostname (any
 *  reverse-proxy-fronted host works). The bundle aggregates every
 *  share-link for the client's email, so one URL covers a multi-server
 *  setup; v2rayN-latest / Hiddify / NekoBox / sing-box / Streisand
 *  all accept the default base64 body. */
function SubscriptionPane({
  client,
  onRotate,
  rotating,
}: {
  client: Client;
  onRotate: () => void;
  rotating: boolean;
}) {
  const { t } = useTranslation();
  // Panel settings drive the canonical subscription URL: an operator
  // who set `sub_link_host` wants end-users to fetch the subscription
  // from that hostname (not the admin URL the operator happens to be
  // browsing on); `sub_port` means subscriptions live on a different
  // port than the admin shell. Falls back to `window.location` when
  // either field is empty.
  const settings = useQuery({
    queryKey: ['panel-settings'],
    queryFn: async () => (await apiClient.get<PanelSettings>('/settings/panel')).data,
    staleTime: 30_000,
  }).data;
  const url = buildSubscriptionUrl(client.sub_token, settings);
  return (
    <Space orientation="vertical" style={{ width: '100%' }} size={16}>
      <QrCard value={url} />
      <Typography.Text type="secondary" style={{ fontSize: 12 }}>
        {t('clients.subHint')}
      </Typography.Text>
      <Input.TextArea
        value={url}
        autoSize={{ minRows: 2, maxRows: 4 }}
        readOnly
        style={{
          fontFamily: 'ui-monospace, "JetBrains Mono", Consolas, monospace',
          fontSize: 12,
        }}
      />
      <Space orientation="horizontal" style={{ width: '100%', justifyContent: 'space-between' }}>
        <Typography.Text copyable={{ text: url }}>
          {t('clients.copy')}
        </Typography.Text>
        <Popconfirm
          title={t('clients.subRotateConfirm')}
          okText={t('common.confirm')}
          cancelText={t('common.cancel')}
          okType="danger"
          onConfirm={onRotate}
        >
          <Button
            type="text"
            size="small"
            danger
            icon={<ReloadOutlined />}
            loading={rotating}
          >
            {t('clients.subRotate')}
          </Button>
        </Popconfirm>
      </Space>
    </Space>
  );
}

/** Compact rendering of an email-group's assigned inbounds.
 *
 *  - 1–2 inbounds → all tags inline (no overflow trigger needed)
 *  - 3+ inbounds → first 2 tags inline + a "+N" pill; hovering the
 *    pill opens a Popover with the rest as clickable tags
 *
 *  Stops the column from blowing up on multi-inbound users — a single
 *  email mapped to ten servers takes the same horizontal space as one
 *  mapped to two. Each tag stays click-to-filter so the keyboard-light
 *  operator workflow ("show me everyone on this inbound") still works.
 */
function InboundTags({
  inboundIds,
  inboundById,
  onPickFilter,
}: {
  inboundIds: string[];
  inboundById: Map<string, Inbound>;
  onPickFilter: (id: string) => void;
}) {
  const { t } = useTranslation();
  const VISIBLE = 2;
  const renderTag = (id: string) => {
    const ib = inboundById.get(id);
    return ib ? (
      <Tag
        key={id}
        color="geekblue"
        style={{ cursor: 'pointer', marginInlineEnd: 0 }}
        onClick={() => onPickFilter(id)}
        title={t('clients.filterByThisInbound')}
      >
        {ib.tag}
      </Tag>
    ) : (
      <Typography.Text key={id} type="secondary" style={{ fontSize: 12 }}>
        {id.slice(0, 8)}…
      </Typography.Text>
    );
  };
  const overflow = inboundIds.length - VISIBLE;
  const visibleIds = overflow > 0 ? inboundIds.slice(0, VISIBLE) : inboundIds;
  const hiddenIds = overflow > 0 ? inboundIds.slice(VISIBLE) : [];
  return (
    // 6 px between chips — 4 px read as "almost-touching" when adjacent
    // chips have wider Antd padding (the visual margin between borders
    // shrinks to ~1 px), 8 px feels loose. 6 lands at the eye's notion
    // of "small but clearly separated."
    <Space size={6} wrap>
      {visibleIds.map(renderTag)}
      {overflow > 0 && (
        <Popover
          // Click-only: on touch devices the combined hover-and-click
          // trigger fires twice from one tap, flickering the popover
          // open then immediately closed. Click is unambiguous on both
          // pointer and touch.
          trigger="click"
          content={
            <Space size={6} wrap style={{ maxWidth: 320 }}>
              {hiddenIds.map(renderTag)}
            </Space>
          }
        >
          <Tag style={{ cursor: 'pointer', marginInlineEnd: 0 }}>+{overflow}</Tag>
        </Popover>
      )}
    </Space>
  );
}
