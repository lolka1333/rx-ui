/**
 * Top-level Clients page.
 *
 * Lives in the sidebar alongside Inbounds/Dashboard. Shows every client
 * across every inbound, one row per email, with filters (by inbound, email
 * substring, status) and per-user actions. Inbound assignment is explicit
 * here (a multi-select in the form) because the page has no implicit inbound
 * context.
 *
 * `groups.ts` turns rows into per-email groups, `useClientActions.ts` holds
 * the actions that fan out over a group's rows, and the table, the form and
 * the share modal each have their own file.
 */
import { Button, Input, Select } from 'antd';
import { PlusOutlined } from '@ant-design/icons';
import { keepPreviousData, useQuery } from '@tanstack/react-query';
import { useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { apiClient } from '@/api/client';
import { useLoadState } from '@/api/loadState';
import { LoadError, LoadStale } from '@/components/LoadState';
import { useNav } from '@/stores/nav';
import { useClientsFilter } from '@/stores/clientsFilter';
import type { Client, Inbound } from '@/api/types';
import { type TrafficSnapshotMap, type StatusFilter, groupClients } from './groups';
import { type ShareState, useClientActions } from './useClientActions';
import { ClientsTable } from './ClientsTable';
import { ClientFormModal } from './ClientFormModal';
import { ShareModal } from './ShareModal';

export function Clients() {
  const { t } = useTranslation();
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

  const [enabledFilter, setEnabledFilter] = useState<StatusFilter>('all');

  const [modalOpen, setModalOpen] = useState(false);
  const [editing, setEditing] = useState<Client | null>(null);
  // Share modal state — see `ShareState`.
  const [shareOpen, setShareOpen] = useState<ShareState | null>(null);

  // Inbounds — need both for the filter dropdown AND for the create-form
  // inbound select. Same query key as the Inbounds page so refetches are
  // shared.
  const inboundsQ = useQuery<Inbound[]>({
    queryKey: ['inbounds'],
    queryFn: async () => (await apiClient.get<Inbound[]>('/inbounds')).data,
  });
  const { data: inbounds = [] } = inboundsQ;

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
  const clientsQ = useQuery<Client[]>({
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
  const { data: clients = [] } = clientsQ;

  // Unfiltered global client list — needed by the form's multi-select
  // to show which inbounds the edited email is already assigned to,
  // even when the visible table is filtered down to one inbound.
  // Shares the cache key with the Inbounds page so the request is
  // deduped on tabs where both pages have been visited.
  const allClientsQ = useQuery<Client[]>({
    queryKey: ['clients-global', null],
    queryFn: async () => (await apiClient.get<Client[]>('/clients')).data,
    refetchInterval: isActive ? 5_000 : false,
  });
  const { data: allClients = [] } = allClientsQ;

  // Live online + traffic snapshot. Backend keeps a 5 s-warm in-memory
  // map populated by xray's StatsService; this query polls at the same
  // cadence so the UI rate matches the underlying delta window.
  // `refetchIntervalInBackground: false` (default) — we don't burn
  // CPU when the tab is hidden.
  const statsQ = useQuery<TrafficSnapshotMap>({
    queryKey: ['clients-stats'],
    queryFn: async () => (await apiClient.get<TrafficSnapshotMap>('/clients/stats')).data,
    refetchInterval: isActive ? 5_000 : false,
  });
  const { data: stats = {} } = statsQ;

  // The table needs both the rows and the inbounds they belong to, so both gate
  // the page. The unfiltered list (edit form) and the stats poll only decorate
  // it — and a dead stats poll is the worst thing to hide behind silence, since
  // the Online column then paints every client grey, which reads as an outage
  // that isn't happening.
  const page = useLoadState([clientsQ, inboundsQ], [allClientsQ, statsQ]);

  const clientGroups = useMemo(
    () => groupClients(clients, emailFilter, enabledFilter, stats),
    [clients, emailFilter, enabledFilter, stats],
  );
  const actions = useClientActions(setShareOpen);

  const openCreate = () => {
    setEditing(null);
    setModalOpen(true);
  };
  const openEdit = (c: Client) => {
    setEditing(c);
    setModalOpen(true);
  };

  // Auto-clear inbound filter if the selected inbound vanishes (deleted
  // from another tab). Otherwise the badge "filtering by [gone inbound]"
  // sticks indefinitely.
  useEffect(() => {
    if (inboundIdFilter && !inboundById.has(inboundIdFilter)) {
      setInboundIdFilter(null);
    }
  }, [inboundById, inboundIdFilter, setInboundIdFilter]);

  // Mirror the Inbounds/Dashboard pattern: render nothing until BOTH the
  // inbounds list and clients list have loaded for the first time. Without
  // this gate the table would mount immediately with `[]` defaults, paint
  // the empty state, then snap to the populated rows a moment later —
  // ruining the smooth fade-in. `app-content-reveal` then animates the
  // already-populated content as a single unit.
  if (page.blocked) {
    return null;
  }
  if (page.failed) {
    return <LoadError state={page} />;
  }

  return (
    <div className="app-content-reveal">
      <LoadStale state={page} />
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

      <ClientsTable
        groups={clientGroups}
        clientsCount={clients.length}
        stats={stats}
        inboundById={inboundById}
        onPickInbound={setInboundIdFilter}
        onEdit={openEdit}
        actions={actions}
      />

      <ClientFormModal
        open={modalOpen}
        editing={editing}
        inbounds={inbounds}
        inboundById={inboundById}
        allClients={allClients}
        inboundIdFilter={inboundIdFilter}
        onClose={() => {
          setModalOpen(false);
          setEditing(null);
        }}
      />

      <ShareModal shareOpen={shareOpen} setShareOpen={setShareOpen} inboundById={inboundById} />
    </div>
  );
}
