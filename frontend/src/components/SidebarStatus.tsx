import { App, Tooltip } from 'antd';
import { ReloadOutlined } from '@ant-design/icons';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { apiClient } from '@/api/client';
import { apiErrorMessage } from '@/api/errors';
import type { DashboardOverview } from '@/api/types';

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

  const { data } = useQuery<DashboardOverview>({
    queryKey: ['dashboard-overview'],
    queryFn: async () => (await apiClient.get<DashboardOverview>('/dashboard/overview')).data,
    refetchInterval: 5_000,
  });

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

  if (!data) return null;

  const running = data.xray.running;

  // "Запущен" / "Остановлен" → "Xray запущен" / "Xray остановлен" without a new
  // i18n key: lower-case the reused dashboard string and prefix the engine name.
  const stateLabel = `Xray ${(running
    ? t('dashboard.xrayRunning')
    : t('dashboard.xrayStopped')
  ).toLowerCase()}`;

  // One DOM structure for both states — the collapsed rail just hides the label,
  // version and restart via CSS (no React swap), so the plaque's width can
  // animate smoothly on collapse instead of jumping. The tooltip is only armed
  // (title set) while collapsed, where the dot is all that's visible.
  const narrow = collapsed && !mobile;

  return (
    <Tooltip
      title={narrow ? `${stateLabel}${data.xray.version ? ` · ${data.xray.version}` : ''}` : ''}
      placement="right"
      arrow={false}
    >
      <div className={`sidebar-status${narrow ? ' sidebar-status--collapsed' : ''}`}>
        <div className="sidebar-status-head">
          <span className={`sidebar-status-dot${running ? ' is-up' : ' is-down'}`} />
          <span className="sidebar-status-label">{stateLabel}</span>
          {data.xray.version && <span className="sidebar-status-ver">{data.xray.version}</span>}
          <button
            type="button"
            className="sidebar-status-restart"
            onClick={() => restart.mutate()}
            disabled={!running || restart.isPending}
            aria-label={t('dashboard.xrayRestart')}
          >
            <ReloadOutlined spin={restart.isPending} />
          </button>
        </div>
      </div>
    </Tooltip>
  );
}
