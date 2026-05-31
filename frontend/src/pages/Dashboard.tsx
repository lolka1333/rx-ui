import { Alert, App, Card, Col, Row, Progress, Tag, Grid, Button, theme } from 'antd';
import {
  PoweroffOutlined,
  ReloadOutlined,
  ToolOutlined,
  PlayCircleOutlined,
  UnorderedListOutlined,
  ControlOutlined,
  DatabaseOutlined,
} from '@ant-design/icons';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { apiClient } from '@/api/client';
import { apiErrorMessage } from '@/api/errors';
import { XrayUpdatesModal } from '@/components/XrayUpdatesModal';
import { LogsModal } from '@/components/LogsModal';
import { ServerInfoCard } from '@/components/ServerInfoCard';
import type { DashboardOverview } from '@/api/types';

function fmtBytes(n: number): string {
  if (n === 0) return '0';
  const units = ['Б', 'КБ', 'МБ', 'ГБ', 'ТБ'];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v >= 10 ? 0 : 1)} ${units[i]}`;
}

interface GaugeProps {
  label: string;
  percent: number;
  detail?: string;
  color: string;
}

function Gauge({ label, percent, detail, color }: GaugeProps) {
  const { token } = theme.useToken();
  const screens = Grid.useBreakpoint();
  const safe = Math.min(100, Math.max(0, Math.round(percent)));
  const gaugeSize = screens.sm ? 130 : 110;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 8 }}>
      <Progress
        type="dashboard"
        percent={safe}
        size={gaugeSize}
        gapDegree={90}
        strokeWidth={4}
        strokeColor={color}
        railColor={token.colorBorderSecondary}
        strokeLinecap="round"
        format={(p) => (
          <span
            style={{
              fontSize: screens.sm ? 22 : 18,
              fontWeight: 600,
              color: token.colorText,
              fontVariantNumeric: 'tabular-nums',
            }}
          >
            {p}%
          </span>
        )}
      />
      <div className="app-gauge-meta" style={{ marginTop: -4 }}>
        <span
          className="app-gauge-label"
          style={{ fontSize: 15, color: token.colorTextSecondary, fontWeight: 500 }}
        >
          {label}
        </span>
        {detail && (
          <span
            className="app-gauge-detail"
            style={{
              fontSize: 13,
              color: token.colorTextTertiary,
              fontVariantNumeric: 'tabular-nums',
              whiteSpace: 'nowrap',
            }}
          >
            {detail}
          </span>
        )}
      </div>
    </div>
  );
}

export function Dashboard() {
  const { t } = useTranslation();
  const { token } = theme.useToken();
  const { message } = App.useApp();
  const screens = Grid.useBreakpoint();
  const isMobile = !screens.md;
  const isMobileSm = !screens.sm;
  const qc = useQueryClient();
  const [updatesOpen, setUpdatesOpen] = useState(false);
  const [logsOpen, setLogsOpen] = useState(false);
  const {
    data,
    isLoading,
    isError,
    error,
    refetch,
    isRefetching,
  } = useQuery<DashboardOverview>({
    queryKey: ['dashboard-overview'],
    queryFn: async () => (await apiClient.get<DashboardOverview>('/dashboard/overview')).data,
    refetchInterval: 5_000,
  });

  const xrayAction = useMutation({
    mutationFn: async (action: 'start' | 'stop' | 'restart') =>
      apiClient.post(`/xray/${action}`),
    onSuccess: (_d, action) => {
      qc.invalidateQueries({ queryKey: ['dashboard-overview'] });
      message.success(
        {
          start: t('dashboard.xrayStartedToast'),
          stop: t('dashboard.xrayStoppedToast'),
          restart: t('dashboard.xrayRestartedToast'),
        }[action],
      );
    },
    onError: (err: unknown) => {
      message.error(apiErrorMessage(err) ?? t('common.error'));
    },
  });

  // All hooks called above this point so the order is stable across renders.
  // Distinguish "still waiting on the first response" from "had data, refetch
  // failed". First load returns `null` so nothing flashes — when data arrives
  // the content mounts fresh and `.app-content-reveal` fades it in. The second
  // case keeps the stale data on screen with a small "stale" banner.
  if (isLoading && !data) {
    return null;
  }
  if (isError && !data) {
    return (
      <Alert
        type="error"
        showIcon
        title={t('common.error')}
        description={apiErrorMessage(error) ?? String(error)}
        action={
          <Button size="small" onClick={() => refetch()} loading={isRefetching}>
            {t('common.retry')}
          </Button>
        }
      />
    );
  }

  const cpu = Math.round(data?.system.cpu_percent ?? 0);
  const memPct = data?.system.memory_total_bytes
    ? Math.round((data.system.memory_used_bytes / data.system.memory_total_bytes) * 100)
    : 0;
  const diskPct = data?.system.disk_total_bytes
    ? Math.round((data.system.disk_used_bytes / data.system.disk_total_bytes) * 100)
    : 0;
  const swapPct = data?.system.swap_total_bytes
    ? Math.round((data.system.swap_used_bytes / data.system.swap_total_bytes) * 100)
    : 0;

  const swapColor =
    swapPct > 80 ? token.colorError : swapPct > 50 ? token.colorWarning : token.colorSuccess;

  return (
    <div className="app-content-reveal">
      <ServerInfoCard
        ipv4={data?.system.ipv4 ?? null}
        ipv6={data?.system.ipv6 ?? null}
      />
      <Card
        variant="borderless"
        styles={{ body: { padding: isMobile ? 16 : 24 } }}
      >
        <Row gutter={[16, 16]} justify="space-around">
          <Col xs={12} lg={6}>
            <Gauge
              label={t('dashboard.cpu')}
              percent={cpu}
              detail={t('dashboard.cpuCores', { count: data?.system.cpu_cores ?? 0 })}
              color={token.colorPrimary}
            />
          </Col>
          <Col xs={12} lg={6}>
            <Gauge
              label={t('dashboard.memory')}
              percent={memPct}
              detail={`${fmtBytes(data?.system.memory_used_bytes ?? 0)} / ${fmtBytes(data?.system.memory_total_bytes ?? 0)}`}
              color="#06b6d4"
            />
          </Col>
          <Col xs={12} lg={6}>
            <Gauge
              label={t('dashboard.disk')}
              percent={diskPct}
              detail={`${fmtBytes(data?.system.disk_used_bytes ?? 0)} / ${fmtBytes(data?.system.disk_total_bytes ?? 0)}`}
              color="#22d3ee"
            />
          </Col>
          <Col xs={12} lg={6}>
            <Gauge
              label={t('dashboard.swap')}
              percent={swapPct}
              detail={`${fmtBytes(data?.system.swap_used_bytes ?? 0)} / ${fmtBytes(data?.system.swap_total_bytes ?? 0)}`}
              color={swapColor}
            />
          </Col>
        </Row>
      </Card>

      <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
        <Col xs={24} lg={12}>
      <Card
        title={
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 10 }}>
            <span>Xray</span>
            {isMobileSm && data?.xray.version && (
              <Tag
                color="success"
                variant="outlined"
                style={{ margin: 0, fontWeight: 500, fontSize: 11 }}
              >
                {data.xray.version}
              </Tag>
            )}
          </span>
        }
        variant="borderless"
        extra={
          <Tag
            color={data?.xray.running ? 'success' : 'error'}
            variant="filled"
            style={{
              margin: 0,
              fontWeight: 500,
              // Override fill + border so the chip reads as text-only on the
              // card header; antd v6 dropped the `bordered` shorthand, so we
              // have to clear them inline.
              background: 'transparent',
              borderColor: 'transparent',
              display: 'inline-flex',
              alignItems: 'center',
              gap: 6,
            }}
          >
            <span className={`app-status-dot${data?.xray.running ? ' live' : ''}`} />
            {data?.xray.running ? t('dashboard.xrayRunning') : t('dashboard.xrayStopped')}
          </Tag>
        }
        styles={{ body: { padding: 0 } }}
      >
        <Row
          style={{
            borderTop: `1px solid ${token.colorBorderSecondary}`,
          }}
        >
          {data?.xray.running ? (
            <ActionCell
              icon={<PoweroffOutlined />}
              label={t('dashboard.xrayStop')}
              iconOnly={isMobileSm}
              loading={xrayAction.isPending && xrayAction.variables === 'stop'}
              onClick={() => xrayAction.mutate('stop')}
              divider
            />
          ) : (
            <ActionCell
              icon={<PlayCircleOutlined />}
              label={t('dashboard.xrayStart')}
              iconOnly={isMobileSm}
              loading={xrayAction.isPending && xrayAction.variables === 'start'}
              onClick={() => xrayAction.mutate('start')}
              divider
            />
          )}
          <ActionCell
            icon={<ReloadOutlined />}
            label={t('dashboard.xrayRestart')}
            iconOnly={isMobileSm}
            loading={xrayAction.isPending && xrayAction.variables === 'restart'}
            onClick={() => xrayAction.mutate('restart')}
            disabled={!data?.xray.running}
            divider
          />
          <ActionCell
            icon={<ToolOutlined />}
            label={data?.xray.version ?? t('dashboard.xrayNotInstalled')}
            iconOnly={isMobileSm}
            onClick={() => setUpdatesOpen(true)}
          />
        </Row>
      </Card>
        </Col>
        <Col xs={24} lg={12}>
      <Card
        title={t('management.title')}
        variant="borderless"
        styles={{ body: { padding: 0 } }}
      >
        <Row
          style={{
            borderTop: `1px solid ${token.colorBorderSecondary}`,
          }}
        >
          <ActionCell
            icon={<UnorderedListOutlined />}
            label={t('management.logs')}
            iconOnly={isMobileSm}
            onClick={() => setLogsOpen(true)}
            divider
          />
          <ActionCell
            icon={<ControlOutlined />}
            label={t('management.config')}
            iconOnly={isMobileSm}
            onClick={() => message.info(t('management.comingSoon'))}
            divider
          />
          <ActionCell
            icon={<DatabaseOutlined />}
            label={t('management.backup')}
            iconOnly={isMobileSm}
            onClick={() => message.info(t('management.comingSoon'))}
          />
        </Row>
      </Card>
        </Col>
      </Row>

      <XrayUpdatesModal
        open={updatesOpen}
        onClose={() => setUpdatesOpen(false)}
        currentVersion={data?.xray.version ?? null}
      />
      <LogsModal open={logsOpen} onClose={() => setLogsOpen(false)} />
    </div>
  );
}

interface ActionCellProps {
  icon: React.ReactNode;
  label: string;
  onClick: () => void;
  loading?: boolean;
  disabled?: boolean;
  /** Render a vertical divider on the trailing edge of this cell. */
  divider?: boolean;
  /** Hide the label and rely on the icon alone — used on phones to keep
      three actions on a single row without text crowding. */
  iconOnly?: boolean;
}

function ActionCell({
  icon,
  label,
  onClick,
  loading,
  disabled,
  divider,
  iconOnly,
}: ActionCellProps) {
  const { token } = theme.useToken();
  const screens = Grid.useBreakpoint();
  const isMobile = !screens.sm;
  return (
    <Col
      xs={8}
      sm={8}
      style={{
        borderRight: divider ? `1px solid ${token.colorBorderSecondary}` : undefined,
      }}
    >
      <Button
        type="text"
        block
        icon={icon}
        loading={loading}
        disabled={disabled}
        onClick={onClick}
        // Native tooltip so a long-press on iOS / hover on desktop still
        // surfaces the action name when only the icon is visible.
        title={iconOnly ? label : undefined}
        aria-label={iconOnly ? label : undefined}
        style={{
          height: isMobile ? 48 : 56,
          borderRadius: 0,
          color: disabled ? token.colorTextDisabled : token.colorTextSecondary,
          fontSize: 14,
        }}
      >
        {iconOnly ? null : label}
      </Button>
    </Col>
  );
}
