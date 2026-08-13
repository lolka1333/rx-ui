import { App, Tooltip } from 'antd';
import { ReloadOutlined } from '@ant-design/icons';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { apiClient } from '@/api/client';
import { apiErrorMessage } from '@/api/errors';
import { useDashboardOverview } from '@/api/overview';

/**
 * Sidebar status block — Xray run state + version + restart, pinned above the
 * account card. Reads from the same `dashboard-overview` query as the dashboard,
 * so it shares one cache and one 5s poll (no extra request). Collapses to a
 * single status dot when the rail is narrow.
 */
export function SidebarStatus({
  collapsed = false,
  mobile = false,
}: {
  collapsed?: boolean;
  mobile?: boolean;
}) {
  const { t } = useTranslation();
  const { message } = App.useApp();
  const qc = useQueryClient();

  // Seeded from the session snapshot, so a reload paints the filled plaque in
  // its first frame instead of an empty slab that fills in a round trip later.
  const { data, isError, error } = useDashboardOverview();

  const restart = useMutation({
    mutationFn: async () => apiClient.post('/xray/restart'),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['dashboard-overview'] });
      message.success(t('dashboard.xrayRestartedToast'));
    },
    onError: (err: unknown) => {
      message.error(apiErrorMessage(err) ?? t('common.error'));
    },
  });

  const running = data?.xray.running ?? false;

  // The 5s overview poll doubles as this plaque's heartbeat, so its failure
  // is the one outage signal visible from every page — which is what lets the
  // surfaces we deliberately leave silent elsewhere stay silent. Neither green
  // nor red here: the last colour we saw would be asserting a state we can no
  // longer observe. No retry button either — the next poll IS the retry.
  const unreachable = isError;

  // "Запущен" / "Остановлен" → "Xray запущен" / "Xray остановлен" without a new
  // i18n key: lower-case the reused dashboard string and prefix the engine name.
  const stateLabel = unreachable
    ? t('common.unreachable')
    : `Xray ${(running
        ? t('dashboard.xrayRunning')
        : t('dashboard.xrayStopped')
      ).toLowerCase()}`;

  // One DOM structure for every state — the collapsed rail just hides the label,
  // version and restart via CSS (no React swap), so the plaque's width can
  // animate smoothly on collapse instead of jumping. The tooltip is only armed
  // (title set) while collapsed, where the dot is all that's visible.
  const narrow = collapsed && !mobile;

  // The no-data case keeps the same element at the same slot rather than
  // returning a bare <div>: swapping the element TYPE made React unmount and
  // remount the node when the payload landed, which also dragged antd's Tooltip
  // styles into the middle of the boot. This only happens on the first load of
  // a session now — a reload is seeded (see useDashboardOverview) — but a
  // structural swap mid-boot is worth not having at all.
  return (
    <Tooltip
      title={
        narrow && data
          ? unreachable
            ? (apiErrorMessage(error) ?? t('common.unreachable'))
            : `${stateLabel}${data.xray.version ? ` · ${data.xray.version}` : ''}`
          : ''
      }
      placement="right"
      arrow={false}
    >
      <div
        className={`sidebar-status${narrow ? ' sidebar-status--collapsed' : ''}`}
        aria-hidden={data ? undefined : true}
      >
        {data && (
          <div className="sidebar-status-head">
            <span
              className={`sidebar-status-dot${
                unreachable ? ' is-stale' : running ? ' is-up' : ' is-down'
              }`}
            />
            <span className="sidebar-status-label">{stateLabel}</span>
            {data.xray.version && <span className="sidebar-status-ver">{data.xray.version}</span>}
            <button
              type="button"
              className="sidebar-status-restart"
              onClick={() => restart.mutate()}
              disabled={!running || unreachable || restart.isPending}
              aria-label={t('dashboard.xrayRestart')}
            >
              <ReloadOutlined spin={restart.isPending} />
            </button>
          </div>
        )}
      </div>
    </Tooltip>
  );
}
