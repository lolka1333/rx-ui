//! Which FinalMask variants a given transport × security actually runs.
//!
//! xray keeps two mask registries and each transport consults exactly one of
//! them, so a mask offered on the wrong side is not an error — it builds, the
//! inbound starts, and nothing ever calls it. The backend refuses those
//! combinations on save; asking it what it allows is how the dropdown and the
//! validator stay one rule instead of two copies that drift.
//!
//! Shared by the inbound and the outbound form. Their protocol vocabularies
//! differ (`hysteria2` vs `hysteria`), so each folds its own fields into
//! [`FinalMaskTransport`] and nothing below this line knows about protocols.
//! WireGuard rides in the same vocabulary: it carries its own UDP socket the
//! way Hysteria does, and its allowed set is narrower than any transport's
//! because the far end is a stock WireGuard client that speaks no mask.

import { useEffect, useMemo, useRef } from 'react';
import { App } from 'antd';
import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { apiClient } from './client';
import type { FinalMask } from './types';

/** Transport in the vocabulary the backend matrix is keyed by. */
export type FinalMaskTransport = 'tcp' | 'ws' | 'xhttp' | 'hysteria' | 'wireguard';

/** `transport -> security -> kinds`, exactly as the endpoint returns it. */
type FinalMaskSupport = Record<string, Record<string, FinalMask['kind'][]>>;

/** Every variant the form can render, mapped to its i18n key — and, because the
 *  record is keyed by the ts-rs union, the one exhaustive list of kinds in the
 *  frontend: adding a variant in Rust breaks the build here until it is handled.
 *  Doubles as the dropdown order and as the fallback while the matrix is in
 *  flight. */
export const FINALMASK_LABEL_KEYS: Record<FinalMask['kind'], string> = {
  none: 'inbounds.finalmaskKindNone',
  sudoku: 'inbounds.finalmaskKindSudoku',
  fragment: 'inbounds.finalmaskKindFragment',
  noise: 'inbounds.finalmaskKindNoise',
  salamander: 'inbounds.finalmaskKindSalamander',
  xmc: 'inbounds.finalmaskKindXmc',
};

function useFinalMaskSupport() {
  return useQuery<FinalMaskSupport>({
    queryKey: ['finalmask-support'],
    queryFn: async () =>
      (await apiClient.get<FinalMaskSupport>('/inbounds/finalmask-support')).data,
    // Derived from the xray build, not from anything the operator can change
    // while the form is open.
    staleTime: Infinity,
  });
}

/** The kinds selectable for this combination. `none` is always in the list —
 *  it is the absence of a mask, not a mask.
 *
 *  While the matrix is loading (or if the request failed — the client does not
 *  retry) every kind is returned rather than an empty list: a dropdown with a
 *  single entry would read as "this transport supports nothing", a worse lie
 *  than briefly showing too much. `pending` is surfaced so the caller can say
 *  so instead of guessing. */
export function useAllowedFinalMasks(transport: string | undefined, security: string | undefined) {
  const { data, isPending } = useFinalMaskSupport();
  const allowed = useMemo<FinalMask['kind'][]>(() => {
    const kinds = transport && security ? data?.[transport]?.[security] : undefined;
    return kinds
      ? ['none', ...kinds]
      : (Object.keys(FINALMASK_LABEL_KEYS) as FinalMask['kind'][]);
  }, [data, transport, security]);
  // `resolved` separates "everything, because we know" from "everything,
  // because we don't know yet" — only the former may drive a reset.
  return {
    allowed,
    isPending,
    resolved: transport !== undefined && security !== undefined
      && data?.[transport]?.[security] !== undefined,
  };
}

/** Snap a mask the current transport cannot run back to `none`, and say so.
 *
 *  Called from the forms' guard code, which stays mounted, rather than from
 *  the FinalMask tab: antd mounts a tab pane on its first visit, so a rule
 *  living in the tab would fire or not depending on which tabs the operator
 *  happened to open.
 *
 *  The mask is read through `getKind`, NOT through `Form.useWatch`, and that is
 *  the whole point: `useWatch` resolves against `getFieldsValue()`, which
 *  clones only REGISTERED fields, so it answers `undefined` for a field whose
 *  tab has never been opened — which is every form on open, i.e. exactly when
 *  this rule has to run. `getFieldValue` reads the store itself and answers for
 *  unmounted fields too. The transport and security arguments come from
 *  always-mounted fields, so they still drive the re-render.
 *
 *  Only acts once the matrix has actually answered: an unreachable panel must
 *  not wipe a mask that is configured and working. */
export function useFinalMaskGuard(
  transport: string | undefined,
  security: string | undefined,
  getKind: () => FinalMask['kind'] | undefined,
  reset: () => void,
) {
  const { t } = useTranslation();
  const { message } = App.useApp();
  const { allowed, resolved } = useAllowedFinalMasks(transport, security);
  // Both callbacks are rebuilt every render at the call sites; parking them in
  // refs keeps this effect keyed on the mask rule alone.
  const getKindRef = useRef(getKind);
  const resetRef = useRef(reset);
  useEffect(() => {
    getKindRef.current = getKind;
    resetRef.current = reset;
  }, [getKind, reset]);

  useEffect(() => {
    // `transport`/`security` are undefined until the form's fields register.
    // Acting on that window is what dropped a valid mask: the call site used to
    // substitute 'tcp'/'none', so a Hysteria 2 inbound was briefly judged
    // against the TCP matrix — which has no salamander — and the mask was reset
    // before `useWatch` caught up. Whether it misfired depended only on whether
    // the support matrix happened to be cached, i.e. on a race.
    if (!transport || !security || !resolved) return;
    const kind = getKindRef.current();
    if (!kind || allowed.includes(kind)) return;
    resetRef.current();
    message.warning(t('inbounds.finalmaskKindDropped', { kind }));
  }, [resolved, allowed, message, t, transport, security]);
}
