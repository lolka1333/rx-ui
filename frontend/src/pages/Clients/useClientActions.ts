/**
 * The table's per-user actions. Each fans out over every row of an email
 * group in parallel — the table shows one row per email, but the API still
 * takes one call per inbound row. Caches invalidate once at the end (single
 * refetch, no thrash).
 */
import { App } from 'antd';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import type { Dispatch, SetStateAction } from 'react';
import { useTranslation } from 'react-i18next';
import { apiClient } from '@/api/client';
import { apiErrorMessage } from '@/api/errors';
import type { Client, ShareLinkResponse } from '@/api/types';
import type { ClientGroup } from './groups';

/** What the share modal shows: the whole email group (any row's `sub_token`
 *  serves the Subscription tab — every row of an email carries the same one)
 *  and which row's share link the Link tab currently renders. */
export interface ShareState {
  group: ClientGroup;
  currentClientId: string;
  share: ShareLinkResponse;
}

/** Run `call` for every row at once.
 *
 *  `allSettled` resolves even when every request rejected, so a total failure
 *  would run the SUCCESS path: no rollback of an optimistic update, and a
 *  "done" toast over a backend that did nothing. Re-thrown when nothing got
 *  through, so `onError` reports the real reason; a genuinely mixed result
 *  resolves and keeps the partial-failure toast. */
async function fanOut(rows: Client[], call: (row: Client) => Promise<unknown>) {
  const results = await Promise.allSettled(rows.map(call));
  const failed = results.filter((r) => r.status === 'rejected').length;
  if (failed === rows.length && failed > 0) {
    throw (results[0] as PromiseRejectedResult).reason;
  }
  return { total: rows.length, failed };
}

export function useClientActions(setShareOpen: Dispatch<SetStateAction<ShareState | null>>) {
  const { t } = useTranslation();
  const { message } = App.useApp();
  const qc = useQueryClient();

  const invalidate = () => {
    // Prefix match: this covers every per-inbound list too, since they are
    // all keyed `['clients-global', inboundId]`.
    qc.invalidateQueries({ queryKey: ['clients-global'] });
  };

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
      const [result] = await Promise.all([
        fanOut(rows, (r) => apiClient.patch(`/clients/${r.id}`, { enabled })),
        new Promise((resolve) => {
          setTimeout(resolve, 250);
        }),
      ]);
      return result;
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
    mutationFn: ({ rows }: { email: string; rows: Client[] }) =>
      fanOut(rows, (r) => apiClient.post(`/clients/${r.id}/reset-traffic`)),
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
    mutationFn: ({ rows }: { email: string; rows: Client[] }) =>
      fanOut(rows, (r) => apiClient.delete(`/clients/${r.id}`)),
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

  // Opens the share modal on the group's first row; switching rows inside the
  // modal is the modal's own business.
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

  return { toggleGroup, resetTrafficGroup, deleteGroup, openShare };
}

export type ClientActions = ReturnType<typeof useClientActions>;
