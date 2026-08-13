/** The two failure surfaces, lifted out of Dashboard — until now the only page
 *  in the panel that had any.
 *
 *  Both self-gate on the state they're handed, so a call site drops them in
 *  unconditionally and never repeats the condition. That is what lets a page's
 *  early return, a settings section and a modal body all use the same two
 *  components without each inventing its own wording for "the backend is down".
 *
 *  Separate file from `api/loadState.ts` on purpose: `react-refresh/only-export
 *  -components` (eslint.config.js) rejects a module that exports both a hook
 *  and components.
 */

import { Alert, Button } from 'antd';
import { useTranslation } from 'react-i18next';
import { apiErrorMessage } from '@/api/errors';
import type { LoadState } from '@/api/loadState';

/**
 * Stands in for content that could not be loaded at all. Full width wherever it
 * lands: a page returns it early in place of its table, a settings section or a
 * modal renders it where the form would have been.
 */
export function LoadError({
  state,
  fallback,
}: {
  state: LoadState;
  /** Copy for the failures `apiErrorMessage` can't name — a 400 from a bad
   *  custom release link reads better as "check the link" than as "Error".
   *  Falls through to the raw error so nothing is ever swallowed. */
  fallback?: string;
}) {
  const { t } = useTranslation();
  if (!state.failed) return null;
  return (
    <Alert
      type="error"
      showIcon
      title={t('common.error')}
      description={apiErrorMessage(state.error) ?? fallback ?? String(state.error)}
      action={
        <Button size="small" onClick={state.retry} loading={state.retrying}>
          {t('common.retry')}
        </Button>
      }
    />
  );
}

/**
 * Sits above content that is still on screen but no longer current. A `banner`
 * (square, full-bleed) on purpose, so it reads as a strip over the page rather
 * than another card competing with the content it annotates.
 */
export function LoadStale({ state }: { state: LoadState }) {
  const { t } = useTranslation();
  if (!state.stale) return null;
  return (
    <Alert
      type="warning"
      showIcon
      banner
      title={t('common.stale')}
      action={
        <Button size="small" onClick={state.retry} loading={state.retrying}>
          {t('common.retry')}
        </Button>
      }
      style={{ marginBottom: 16 }}
    />
  );
}
