/**
 * The cross-section "unsaved changes" wiring: each section publishes a
 * `DirtyHandle` to the page, and the bar at the top saves or discards them all.
 */
import type { FormInstance } from 'antd';
import type { QueryClient } from '@tanstack/react-query';
import { useEffect, useRef } from 'react';

export interface DirtyHandle {
  saving: boolean;
  /** Resolves when the save (and the settings refetch it triggers) is done,
   *  so `saveAll` can sequence sections instead of racing them. */
  onSave: () => Promise<void>;
  onDiscard: () => void;
}

/** Does the live form differ from what's actually saved?
 *
 *  Compared against the saved baseline rather than flagged on any edit, so
 *  typing a value and then putting it back does not leave the "unsaved
 *  changes" bar up with nothing to save.
 *
 *  Nullish and `''` count as the same empty value — an untouched optional input
 *  reports `undefined` where the server sent `''`. Arrays and objects compare
 *  structurally INCLUDING order, because order is itself a setting here (the
 *  routing-rule list). */
export function differsFromSaved(
  current: Record<string, unknown>,
  baseline: Record<string, unknown>,
): boolean {
  const norm = (v: unknown) => (v === undefined || v === null ? '' : v);
  const same = (a: unknown, b: unknown) => {
    const x = norm(a);
    const y = norm(b);
    if (typeof x === 'object' || typeof y === 'object') {
      return JSON.stringify(x) === JSON.stringify(y);
    }
    return x === y;
  };
  // Only the saved settings decide dirtiness. `getFieldsValue(true)` also hands
  // back transient fields the form registered that were never part of the saved
  // row — comparing those would flag the section dirty with nothing to save.
  return Object.keys(baseline).some((k) => !same(current[k], baseline[k]));
}

/** Publish one section's dirty state (and how to save/discard it) to the page.
 *
 *  Extracted because all four sections need byte-identical wiring, and the
 *  wiring has two traps worth stating once instead of four times:
 *
 *  - `mutation` is a fresh object every render, so it CANNOT be an effect dep —
 *    it would republish the handle on every render, which feeds back through
 *    `onDirtyChange` into another render. The save goes through a ref that a
 *    deps-less effect keeps current; only `mutation.isPending` is a dep.
 *  - `onSave` is awaitable so `saveAll` can run sections one at a time. It takes
 *    the same path `onFinish` does (validate, then the section's own mutation)
 *    and awaits the query invalidation too, so the next section's payload merges
 *    post-save data. Errors are already surfaced by field validation and the
 *    mutation's own onError, hence the bare `.catch`.
 */
export function useSectionDirtyPublish<V>({
  dirty,
  setDirty,
  form,
  mutation,
  onDirtyChange,
  qc,
}: {
  dirty: boolean;
  setDirty: (v: boolean) => void;
  form: FormInstance<V>;
  mutation: { mutateAsync: (v: V) => Promise<unknown>; isPending: boolean };
  onDirtyChange: (h: DirtyHandle | null) => void;
  qc: QueryClient;
}) {
  const saveRef = useRef(mutation.mutateAsync);
  useEffect(() => {
    saveRef.current = mutation.mutateAsync;
  });

  useEffect(() => {
    onDirtyChange(
      dirty
        ? {
            saving: mutation.isPending,
            onSave: () =>
              form
                .validateFields()
                .then((v) => saveRef.current(v))
                .then(() => qc.invalidateQueries({ queryKey: ['panel-settings'] }))
                .then(() => undefined)
                .catch(() => undefined),
            onDiscard: () => {
              form.resetFields();
              setDirty(false);
            },
          }
        : null,
    );
  }, [dirty, mutation.isPending, form, onDirtyChange, qc, setDirty]);
}
