import i18n from '@/i18n';

/**
 * Surface a human-readable string from an axios failure.
 *
 * Three tiers, in priority order:
 *   1. Backend's own `{ "error": "..." }` body (the most useful — the
 *      backend's `AppError::IntoResponse` always serializes this shape).
 *   2. HTTP status with a friendly explanation for the most common
 *      proxy / transport classes (502 / 503 / 504 / network-down).
 *      Reaches an operator who's looking at a Vite dev proxy that
 *      can't talk to the backend before they go grep the logs.
 *   3. Plain `null` so the caller can fall through to its own
 *      generic copy (`t('common.error')` etc.) instead of leaking
 *      the raw "AxiosError: Request failed with status code 502"
 *      message into the UI.
 *
 * Usage:
 *   } catch (err: unknown) {
 *     message.error(apiErrorMessage(err) ?? t('common.error'));
 *   }
 */
export interface ApiError {
  code?: string;
  message?: string;
  response?: {
    status?: number;
    data?: {
      error?: string;
    };
  };
}

export function apiErrorMessage(err: unknown): string | null {
  const e = err as ApiError | undefined;
  // Backend-supplied error wins.
  const backendMessage = e?.response?.data?.error;
  if (backendMessage) return backendMessage;

  // No response at all → connection didn't reach the backend.
  // axios sets `code: 'ERR_NETWORK'` for plain socket failures and
  // `'ECONNABORTED'` for timeouts; either way we don't have a status.
  if (!e?.response) {
    return e?.code === 'ECONNABORTED'
      ? i18n.t('common.errorTimeout')
      : i18n.t('common.errorNoConnection');
  }

  // Have a status — these three are the only ones the operator
  // typically can't act on through normal validation messaging.
  const status = e.response.status;
  if (status === 502 || status === 503 || status === 504) {
    return i18n.t('common.errorBackendDown', { status });
  }

  return null;
}
