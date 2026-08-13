/** One reading of "did the data actually get here?", shared by every surface.
 *
 *  react-query hands each call site four booleans and leaves the interpretation
 *  to it — which is how `useQuery({...}).data` followed by `if (!data) return
 *  null` became this app's de-facto failure handling: correct-looking, and
 *  completely silent when the backend is down. `data === undefined` means both
 *  "still waiting" and "the request failed", and only the second is worth
 *  telling the operator about.
 *
 *  Three states, not two. The third is the one a `!data` gate cannot see at
 *  all: content IS on screen and the last round trip failed, so what's rendered
 *  is the last known state rather than the current one. Dashboard has always
 *  handled all three by hand; this is that logic with the page-specific parts
 *  taken out.
 */

import type { UseQueryResult } from '@tanstack/react-query';

export interface LoadState {
  /** Nothing arrived and nothing failed — first paint. Callers render `null`:
   *  the house pattern is no skeleton, then `app-content-reveal` fades the
   *  finished content in as one piece. */
  blocked: boolean;
  /** Nothing arrived and a gate query failed — the case the panel had no
   *  answer for. Render `<LoadError>`. */
  failed: boolean;
  /** Renderable, but a listed query is in error: what's on screen is the last
   *  batch that arrived. Render `<LoadStale>` above it. */
  stale: boolean;
  /** First failure found, for `apiErrorMessage()`. */
  error: unknown;
  /** Refetch everything the caller listed, gate and watch alike — a retry that
   *  revived the list but left a dead stats poll behind would only swap one
   *  silent gap for another. */
  retry: () => void;
  /** Any of them in flight, for the retry button's spinner. */
  retrying: boolean;
}

/**
 * @param gate  queries whose payload the surface cannot be drawn without.
 * @param watch queries that only decorate it (pollers, counts, lookups). Their
 *   failures raise the stale banner but must never blank the surface — a dead
 *   stats poll is not a reason to hide the inbound list. That split is the
 *   whole point: before it, any one query's failure took the whole page down.
 *
 * Deliberately not memoised: every field derives from values that change on
 * the render that matters, and `retry`'s only consumer is a Button's onClick,
 * which doesn't care about identity.
 */
export function useLoadState(
  gate: readonly UseQueryResult<unknown>[],
  watch: readonly UseQueryResult<unknown>[] = [],
): LoadState {
  const all = [...gate, ...watch];
  // `data !== undefined` rather than `!isPending`: a query can be pending again
  // after an invalidate while still holding the payload that is on screen.
  // Clients' `placeholderData: keepPreviousData` rests on exactly that
  // distinction, and an `isPending` test there would blank the table on every
  // filter change.
  const ready = gate.every((q) => q.data !== undefined);
  // `isError` alone is not enough: a query with no data flips back to `pending`
  // for the duration of each retry, which would blink the surface back to a
  // blank screen on every attempt and then return the alert. `errorUpdateCount`
  // is the memory of that.
  //
  // The `data === undefined` half is load-bearing in the other direction:
  // `errorUpdateCount` never resets, so without it a single failure anywhere in
  // the session would pin the stale banner on screen for good — including after
  // the backend came back and every query had refreshed.
  const hasFailed = (q: UseQueryResult<unknown>) =>
    q.isError || (q.data === undefined && q.errorUpdateCount > 0);
  const gateFailed = gate.some(hasFailed);
  const firstError = all.find(hasFailed);
  return {
    blocked: !ready && !gateFailed,
    failed: !ready && gateFailed,
    stale: ready && firstError !== undefined,
    // `error` is cleared while a retry is in flight; `failureReason` carries the
    // attempt's own failure, so the alert keeps its text instead of falling back
    // to `String(undefined)` mid-retry.
    error: firstError?.error ?? firstError?.failureReason,
    retry: () => {
      for (const q of all) void q.refetch();
    },
    retrying: all.some((q) => q.isRefetching),
  };
}
