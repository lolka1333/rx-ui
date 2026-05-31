import { Modal, Select, Button, Grid, Switch, Typography, theme } from 'antd';
import { ReloadOutlined, DownloadOutlined } from '@ant-design/icons';
import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { useMemo } from 'react';
import { apiClient } from '@/api/client';
import { useLogsPrefs } from '@/stores/logsPrefs';
import type { LogEntry } from '@/api/types';

interface Props {
  open: boolean;
  onClose: () => void;
}

const LIMIT_OPTIONS = [20, 50, 100, 200, 500];

export function LogsModal({ open, onClose }: Props) {
  const { t } = useTranslation();
  const { token } = theme.useToken();
  const screens = Grid.useBreakpoint();
  const isMobile = !screens.sm;

  const limit = useLogsPrefs((s) => s.limit);
  const level = useLogsPrefs((s) => s.level);
  const autoRefresh = useLogsPrefs((s) => s.autoRefresh);
  const setLimit = useLogsPrefs((s) => s.setLimit);
  const setLevel = useLogsPrefs((s) => s.setLevel);
  const setAutoRefresh = useLogsPrefs((s) => s.setAutoRefresh);

  const { data: entries = [], isFetching, refetch } = useQuery<LogEntry[]>({
    queryKey: ['logs', limit, level],
    queryFn: async () => {
      const params: Record<string, unknown> = { limit };
      if (level !== 'all') params.level = level;
      return (await apiClient.get<LogEntry[]>('/logs', { params })).data;
    },
    enabled: open,
    refetchInterval: open && autoRefresh ? 3000 : false,
    staleTime: 1000,
  });

  // Stable React keys built from content + a within-batch counter for the
  // rare case of identical (timestamp, level, target, message) tuples. Memoised
  // so the Map and the string concatenations only run when `entries` actually
  // changes — without memo this allocated up to ~500 strings on every render.
  const keyedEntries = useMemo(() => {
    const seen = new Map<string, number>();
    return entries.map((e) => {
      const base = `${e.timestamp}|${e.level}|${e.target}|${e.message}`;
      const n = seen.get(base) ?? 0;
      seen.set(base, n + 1);
      return { entry: e, key: n === 0 ? base : `${base}#${n}` };
    });
  }, [entries]);

  const downloadPlain = () => {
    const text = entries
      .slice()
      .reverse() // oldest-first in the export
      .map(
        (e) =>
          `${e.timestamp} ${e.level.toUpperCase().padEnd(5)} ${e.target} - ${e.message}`,
      )
      .join('\n');
    const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    // Local time, not UTC — the operator usually compares the downloaded
    // file with what's on screen, and the on-screen timestamps (formatTs
    // below) use the browser's local timezone. UTC in the filename would
    // be off by N hours and easy to misread.
    const d = new Date();
    const pad = (n: number) => String(n).padStart(2, '0');
    const ts =
      `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}-` +
      `${pad(d.getHours())}-${pad(d.getMinutes())}-${pad(d.getSeconds())}`;
    a.download = `panel-${ts}.log`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  return (
    <Modal
      open={open}
      onCancel={onClose}
      width={isMobile ? '100%' : 920}
      centered={!isMobile}
      destroyOnHidden
      style={isMobile ? { top: 0, maxWidth: '100vw', margin: 0, paddingBottom: 0 } : undefined}
      styles={{
        body: {
          // Body holds toolbar + entries; only the entries list scrolls so
          // the filter row stays visible while the user reads logs.
          display: 'flex',
          flexDirection: 'column',
          maxHeight: isMobile ? 'calc(100dvh - 160px)' : 'calc(100vh - 160px)',
          paddingTop: 8,
          overflow: 'hidden',
        },
      }}
      title={
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 12 }}>
          {t('logs.title')}
          <Button
            type="text"
            size="small"
            icon={<ReloadOutlined spin={isFetching} />}
            onClick={() => refetch()}
            aria-label={t('logs.refresh')}
          />
        </span>
      }
      footer={null}
    >
      {/* Toolbar */}
      <div
        style={{
          display: 'flex',
          flexWrap: 'wrap',
          alignItems: 'center',
          gap: 12,
          marginBottom: 12,
        }}
      >
        <Select
          size="small"
          value={limit}
          onChange={setLimit}
          style={{ width: 80 }}
          options={LIMIT_OPTIONS.map((v) => ({ value: v, label: String(v) }))}
        />
        <Select
          size="small"
          value={level}
          onChange={setLevel}
          style={{ width: 120 }}
          options={[
            { value: 'all', label: t('logs.levelAll') },
            { value: 'info', label: t('logs.levelInfo') },
            { value: 'warn', label: t('logs.levelWarn') },
            { value: 'error', label: t('logs.levelError') },
          ]}
        />
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
          <Switch size="small" checked={autoRefresh} onChange={setAutoRefresh} />
          <Typography.Text type="secondary" style={{ fontSize: 13 }}>
            {t('logs.autoRefresh')}
          </Typography.Text>
        </span>
        <Button
          type="primary"
          shape="circle"
          icon={<DownloadOutlined />}
          onClick={downloadPlain}
          disabled={entries.length === 0}
          style={{ marginLeft: 'auto' }}
          aria-label={t('logs.download')}
        />
      </div>

      {/* Scrollable entries list — toolbar above stays fixed. Class lives
          in index.css so the dedicated terminal-style background and
          scrollbar are scoped here (no leak to other modals). */}
      <div
        className="app-logs-surface"
        style={{
          flex: 1,
          minHeight: 0,
          overflowY: 'auto',
          // Intentionally no `scrollbar-gutter` — it reserves space sized
          // for the native bar (~12px), which made our 6px custom thumb
          // look like it floated in a wide channel. Now the thumb sits
          // flush against the right edge.
          padding: '12px 12px 12px 14px',
          borderRadius: 8,
        }}
      >
      {entries.length === 0 && (
        <Typography.Text type="secondary">{t('logs.empty')}</Typography.Text>
      )}
      <div
        style={{
          display: 'flex',
          flexDirection: 'column',
          gap: 4,
          fontFamily: 'ui-monospace, "JetBrains Mono", Consolas, monospace',
          fontSize: 12.5,
          lineHeight: 1.65,
        }}
      >
        {keyedEntries.map(({ entry: e, key }) => (
          <div
            key={key}
            style={{
              wordBreak: 'break-word',
              color: token.colorTextSecondary,
            }}
          >
            <span style={{ color: token.colorTextTertiary }}>{formatTs(e.timestamp)}</span>{' '}
            <span style={{ color: levelColor(e.level), fontWeight: 500 }}>
              {e.level.toUpperCase()}
            </span>{' '}
            <span style={{ color: token.colorTextTertiary }}>{shortTarget(e.target)}:</span>{' '}
            {e.message}
          </div>
        ))}
      </div>
      </div>
    </Modal>
  );
}

function formatTs(iso: string): string {
  // Show as YYYY/MM/DD HH:MM:SS to match the reference screenshot.
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const pad = (n: number) => String(n).padStart(2, '0');
  return (
    `${d.getFullYear()}/${pad(d.getMonth() + 1)}/${pad(d.getDate())} ` +
    `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
  );
}

/**
 * Desaturated, pastel-leaning palette — the saturated `colorSuccess` /
 * `colorWarning` from the antd tokens read as "alarm" colors against a
 * dark surface, which is fatiguing when scanning many lines. These are
 * closer to what VS Code / iTerm use for syntax accents.
 */
function levelColor(level: string): string {
  switch (level.toLowerCase()) {
    case 'error':
      return '#fca5a5';
    case 'warn':
      return '#fbbf24';
    case 'info':
      return '#86efac';
    case 'debug':
      return '#a5b4fc';
    default:
      return '#cbd5e1';
  }
}

function shortTarget(target: string): string {
  // `<crate>::xray::reload` → `XRAY` style; pick the second segment
  // if it exists, uppercase it.
  const parts = target.split('::');
  if (parts.length >= 2) return parts[1].toUpperCase();
  return target.toUpperCase();
}
