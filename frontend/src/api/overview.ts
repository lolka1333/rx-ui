import { useEffect, useState } from 'react';
import { useQuery, type UseQueryResult } from '@tanstack/react-query';
import { apiClient } from '@/api/client';
import type { DashboardOverview } from '@/api/types';
import { readOverviewCache, writeOverviewCache } from '@/lib/overviewCache';

/**
 * The `/dashboard/overview` poll, shared by the dashboard page and the sidebar's
 * Xray plaque — one query key, one 5s interval, one request.
 *
 * Both call sites go through this hook so the session snapshot in
 * `lib/overviewCache` is seeded and refreshed in exactly one place; whichever
 * component mounts first fills the shared cache entry for the other.
 */
export function useDashboardOverview(): UseQueryResult<DashboardOverview> {
  // Lazy initialiser: read storage once per mount, not on every render.
  const [seed] = useState(readOverviewCache);

  const query = useQuery<DashboardOverview>({
    queryKey: ['dashboard-overview'],
    queryFn: async () => (await apiClient.get<DashboardOverview>('/dashboard/overview')).data,
    refetchInterval: 5_000,
    initialData: seed?.data,
    // Essential companion to `initialData`. Without it the seed would look
    // brand new and the client's default 30s staleTime would suppress the
    // refetch on mount — pinning a stale status on screen for half a minute.
    // With the real timestamp the seed is correctly treated as old and
    // refreshed immediately, so it only ever covers the first frames.
    initialDataUpdatedAt: seed?.at,
  });

  const { data, dataUpdatedAt } = query;
  useEffect(() => {
    // Only persist what the network actually returned. On the mount render
    // `data` is still the seed and `dataUpdatedAt` is the stamp it was read
    // with; writing then would re-date an old snapshot as if it had just
    // arrived. The next reload would take that at face value, and the 30s
    // staleTime this hook is careful to defeat would suppress the refetch after
    // all — pinning a stale status on screen, which is the one thing the
    // timestamp above exists to prevent.
    if (data && dataUpdatedAt !== seed?.at) writeOverviewCache(data);
  }, [data, dataUpdatedAt, seed]);

  return query;
}
