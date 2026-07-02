import {
  App,
  Modal,
  Collapse,
  Alert,
  Typography,
  Button,
  Grid,
  theme,
} from 'antd';
import { ToolOutlined, GlobalOutlined, CheckOutlined } from '@ant-design/icons';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { apiClient } from '@/api/client';
import { apiErrorMessage } from '@/api/errors';
import type { XrayRelease } from '@/api/types';

interface Props {
  open: boolean;
  onClose: () => void;
  currentVersion: string | null;
}

function fmtSize(bytes: number | null | undefined): string {
  if (!bytes) return '';
  const mb = bytes / (1024 * 1024);
  return `${mb.toFixed(1)} MB`;
}

// Relative "published" time (e.g. "3 days ago" / "3 дня назад") via the
// built-in Intl API — no dayjs plugin needed, and it localizes off the active
// i18n language. Picks the largest sensible unit down to minutes.
function fmtAgo(iso: string | null | undefined, locale: string): string {
  if (!iso) return '';
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return '';
  const diffSec = Math.round((then - Date.now()) / 1000);
  const abs = Math.abs(diffSec);
  const rtf = new Intl.RelativeTimeFormat(locale, { numeric: 'auto' });
  const units: [Intl.RelativeTimeFormatUnit, number][] = [
    ['year', 31_536_000],
    ['month', 2_592_000],
    ['week', 604_800],
    ['day', 86_400],
    ['hour', 3_600],
    ['minute', 60],
  ];
  for (const [unit, secs] of units) {
    if (abs >= secs) return rtf.format(Math.round(diffSec / secs), unit);
  }
  return rtf.format(diffSec, 'second');
}

export function XrayUpdatesModal({ open, onClose, currentVersion }: Props) {
  const { t, i18n } = useTranslation();
  const { message } = App.useApp();
  const qc = useQueryClient();
  const screens = Grid.useBreakpoint();
  const isMobile = !screens.sm;
  const [selected, setSelected] = useState<string | null>(null);

  const { data: releases, isLoading } = useQuery<XrayRelease[]>({
    queryKey: ['xray-releases'],
    // Limit to the 6 most recent releases — older versions are rarely the
    // pick, and a shorter list keeps the mobile modal from looking like
    // a wall of releases.
    queryFn: async () =>
      (await apiClient.get<XrayRelease[]>('/xray/releases', { params: { limit: 6 } })).data,
    enabled: open,
    staleTime: 5 * 60_000,
  });

  useEffect(() => {
    // Deliberate open-triggered seeding of the version picker, not a render
    // cascade — runs once per open while nothing is selected.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    if (open && currentVersion && !selected) setSelected(currentVersion);
  }, [open, currentVersion, selected]);

  const install = useMutation({
    // Install downloads a ~30 MB archive from GitHub, unpacks it, and may
    // restart xray — easily 30-60s on a slow link. Override the 15s global
    // axios timeout for this single call so the request doesn't abort
    // mid-download while the backend keeps working.
    mutationFn: async (tag: string) =>
      apiClient.post('/xray/install', { tag }, { timeout: 5 * 60_000 }),
    onSuccess: (_d, tag) => {
      qc.invalidateQueries({ queryKey: ['dashboard-overview'] });
      message.success(t('xrayUpdates.installed', { tag }));
      onClose();
    },
    onError: (err: unknown) => {
      message.error(apiErrorMessage(err) ?? t('xrayUpdates.installError'));
    },
  });

  const installable =
    selected !== null &&
    selected !== currentVersion &&
    releases?.some((r) => r.tag === selected && r.asset_url);

  const onInstall = () => {
    if (selected) install.mutate(selected);
  };

  // Custom footer so we can stack buttons full-width on phones (taller, easier
  // to tap; the default antd footer right-aligns small buttons).
  const footer = isMobile ? (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
      <Button
        type="primary"
        block
        size="large"
        loading={install.isPending}
        disabled={!installable}
        onClick={onInstall}
      >
        {t('common.install')}
      </Button>
      <Button block size="large" onClick={onClose}>
        {t('common.close')}
      </Button>
    </div>
  ) : undefined;

  const rowLabels = {
    preRelease: t('xrayUpdates.preRelease'),
    stable: t('xrayUpdates.stableLabel'),
    noBuild: t('xrayUpdates.noBuild'),
  };

  // Roving tabindex for the release radiogroup: exactly one row is a Tab
  // stop — the selected one, or the first installable one before anything
  // is selected. Arrow keys (handler on the group below) move within.
  const tabStopTag = releases?.some((r) => r.tag === selected && r.asset_url)
    ? selected
    : (releases?.find((r) => r.asset_url)?.tag ?? null);

  return (
    <Modal
      open={open}
      title={t('xrayUpdates.title')}
      onCancel={onClose}
      onOk={onInstall}
      okText={t('common.install')}
      okButtonProps={{ disabled: !installable, loading: install.isPending }}
      cancelText={t('common.close')}
      width={isMobile ? '100%' : 560}
      centered={!isMobile}
      // Phone layout: snap to top edge, fill width, square corners — feels
      // like a native bottom-sheet rather than a desktop dialog floating in
      // the middle of a tall viewport.
      style={
        isMobile
          ? { top: 0, maxWidth: '100vw', margin: 0, paddingBottom: 0 }
          : undefined
      }
      styles={{
        body: {
          // On phones leave room for header (56) + footer with stacked
          // buttons (~140) + safe-area. On desktop the footer is shorter and
          // the title is centered higher, ~180px is enough breathing room.
          maxHeight: isMobile ? 'calc(100dvh - 220px)' : 'calc(100vh - 180px)',
          overflowY: 'auto',
          // Reserve space for the scrollbar so it doesn't overlay the right
          // edge of release rows. `paddingRight` keeps the Alert and rows
          // from butting up against the scrollbar gutter.
          scrollbarGutter: 'stable',
          paddingTop: 8,
          paddingRight: 8,
        },
      }}
      wrapClassName={isMobile ? 'app-modal-fullscreen' : undefined}
      footer={footer}
    >
      {/* Xray + Geofiles are both collapsible; Xray is open by default. */}
      <Collapse
        defaultActiveKey={['xray']}
        ghost
        className="app-updates-collapse"
        items={[
          {
            key: 'xray',
            label: (
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: 10, fontWeight: 500 }}>
                <ToolOutlined />
                Xray
              </span>
            ),
            children: (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                <Alert type="warning" showIcon title={t('xrayUpdates.warning')} />
                {isLoading && <ReleaseSkeletonList />}
                {!isLoading && releases && (
                  <div
                    role="radiogroup"
                    aria-label={t('xrayUpdates.title')}
                    // The rows are hand-rolled radios, so the group supplies
                    // the ARIA keyboard contract itself: arrows move between
                    // installable rows and select follows focus.
                    onKeyDown={(e) => {
                      const dir =
                        e.key === 'ArrowDown' || e.key === 'ArrowRight'
                          ? 1
                          : e.key === 'ArrowUp' || e.key === 'ArrowLeft'
                            ? -1
                            : 0;
                      if (!dir) return;
                      e.preventDefault();
                      const radios = [
                        ...e.currentTarget.querySelectorAll<HTMLElement>(
                          '[role="radio"]:not([aria-disabled="true"])',
                        ),
                      ];
                      if (!radios.length) return;
                      const at = radios.indexOf(e.target as HTMLElement);
                      const next =
                        at === -1
                          ? radios[dir > 0 ? 0 : radios.length - 1]
                          : radios[(at + dir + radios.length) % radios.length];
                      next.focus();
                      next.click();
                    }}
                    style={{ display: 'flex', flexDirection: 'column', gap: 8, width: '100%' }}
                  >
                    {releases.map((r, idx) => (
                      <ReleaseRow
                        key={r.tag}
                        release={r}
                        isCurrent={r.tag === currentVersion}
                        isLatest={idx === 0 && r.tag !== currentVersion}
                        isSelected={r.tag === selected}
                        isTabStop={r.tag === tabStopTag}
                        onSelect={() => r.asset_url && setSelected(r.tag)}
                        published={fmtAgo(r.published_at, i18n.language)}
                        labels={rowLabels}
                      />
                    ))}
                  </div>
                )}
              </div>
            ),
          },
          {
            key: 'geofiles',
            label: (
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: 10, fontWeight: 500 }}>
                <GlobalOutlined />
                Geofiles
              </span>
            ),
            children: (
              <Typography.Text type="secondary" style={{ fontSize: 13 }}>
                {t('xrayUpdates.geofilesNote')}
              </Typography.Text>
            ),
          },
        ]}
      />
      <style>{`
        /* Subtle "section" feel for the collapse panels — ghost mode by itself
           looked like floating plain text. Round the row, give it a background
           tint, and let hover bump the tint slightly so it reads as
           interactive. A gap between panels keeps them from touching. */
        .app-updates-collapse .ant-collapse-item {
          margin-bottom: 10px;
        }
        .app-updates-collapse .ant-collapse-item:last-child {
          margin-bottom: 0;
        }
        .app-updates-collapse .ant-collapse-header {
          border-radius: 10px !important;
          padding: 10px 14px !important;
          background-color: rgba(255, 255, 255, 0.025);
          transition: background-color 0.15s ease;
        }
        .app-updates-collapse .ant-collapse-header:hover {
          background-color: rgba(255, 255, 255, 0.05);
        }
        [data-theme="light"] .app-updates-collapse .ant-collapse-header {
          background-color: rgba(0, 0, 0, 0.025);
        }
        [data-theme="light"] .app-updates-collapse .ant-collapse-header:hover {
          background-color: rgba(0, 0, 0, 0.05);
        }
        .app-updates-collapse .ant-collapse-content-box {
          padding: 12px 4px 8px !important;
        }

        @media (max-width: 575px) {
          /* Snap-to-edge feel for the modal on phones (antd v6 doesn't expose
             a styles.content slot, so we override by wrapper class). */
          .app-modal-fullscreen .ant-modal-content {
            border-radius: 0 !important;
            min-height: 100dvh;
          }
        }
      `}</style>
    </Modal>
  );
}

interface ReleaseRowProps {
  release: XrayRelease;
  isCurrent: boolean;
  isLatest: boolean;
  isSelected: boolean;
  /** The group's single Tab stop (roving tabindex) — see the radiogroup. */
  isTabStop: boolean;
  onSelect: () => void;
  published: string;
  labels: {
    preRelease: string;
    stable: string;
    noBuild: string;
  };
}

function ReleaseRow({
  release,
  isCurrent,
  isLatest,
  isSelected,
  isTabStop,
  onSelect,
  published,
  labels,
}: ReleaseRowProps) {
  const { token } = theme.useToken();
  const noAsset = !release.asset_url;
  // Per-row meta = channel + size (or "no build") + when it was published.
  const channel = release.prerelease ? labels.preRelease : labels.stable;
  const size = noAsset ? labels.noBuild : fmtSize(release.asset_size);
  const meta = [channel, size, published].filter(Boolean).join(' · ');
  const selected = isSelected && !noAsset;
  // Status shows as the colour of the version pill itself: green = installed,
  // accent = latest, warm amber for the rest (the pre-release channel's hue).
  // installed/latest still stand out, so it's not the old "wall of orange".
  const pillFg = isCurrent
    ? token.colorSuccess
    : isLatest
      ? token.colorPrimary
      : token.colorWarningText;
  const pillBg = isCurrent
    ? `${token.colorSuccess}30`
    : isLatest
      ? `${token.colorPrimary}30`
      : token.colorWarningBg;

  return (
    <div
      className="app-release-row"
      onClick={noAsset ? undefined : onSelect}
      role="radio"
      aria-checked={selected}
      aria-disabled={noAsset}
      tabIndex={noAsset ? -1 : isTabStop ? 0 : -1}
      onKeyDown={(e) => {
        if (!noAsset && (e.key === 'Enter' || e.key === ' ')) {
          e.preventDefault();
          onSelect();
        }
      }}
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: 12,
        padding: '12px 15px',
        minHeight: 52,
        borderRadius: 10,
        // Each release is its own raised card. Status lives in the coloured
        // version pill (below). A faint glassy top-highlight lifts every card;
        // the selected one is marked by an accent wash + a thin 1px accent
        // border — no outer halo, which read as too heavy.
        background: selected ? `${token.colorPrimary}14` : token.colorFillQuaternary,
        border: `1px solid ${selected ? token.colorPrimaryBorder : token.colorBorderSecondary}`,
        boxShadow: 'inset 0 1px 0 rgba(255, 255, 255, 0.05)',
        cursor: noAsset ? 'not-allowed' : 'pointer',
        opacity: noAsset ? 0.45 : 1,
        transition: 'border-color 0.15s, background-color 0.15s',
        WebkitTapHighlightColor: 'transparent',
        userSelect: 'none',
      }}
    >
      <span
        style={{
          fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace',
          fontSize: 14,
          fontWeight: 500,
          color: pillFg,
          background: pillBg,
          borderRadius: 8,
          padding: '3px 10px',
          // Uniform width so the version pills form a tidy column even though
          // the tags differ in length (v26.6.27 vs v26.6.1). Sized to fit a
          // 9-char tag (v26.10.15 — two-digit month + day) with slack.
          minWidth: 96,
          textAlign: 'center',
          whiteSpace: 'nowrap',
          flex: '0 0 auto',
        }}
      >
        {release.tag}
      </span>
      {meta && (
        <Typography.Text
          type="secondary"
          style={{
            flex: 1,
            minWidth: 0,
            fontSize: 12,
            whiteSpace: 'nowrap',
            overflow: 'hidden',
            textOverflow: 'ellipsis',
          }}
        >
          {meta}
        </Typography.Text>
      )}
      {selected ? (
        <CheckOutlined style={{ fontSize: 16, color: token.colorPrimary, flex: '0 0 auto' }} />
      ) : (
        <span style={{ width: 16, flex: '0 0 auto' }} aria-hidden="true" />
      )}
    </div>
  );
}

/**
 * 6 placeholder rows shaped like real release rows, inside the same bordered
 * container — keeps the modal's vertical rhythm steady while GitHub responds,
 * instead of dropping a lonely spinner in the middle.
 */
function ReleaseSkeletonList() {
  const { token } = theme.useToken();
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
      {Array.from({ length: 6 }).map((_, i) => (
        <div
          key={i}
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: 12,
            padding: '12px 15px',
            minHeight: 52,
            borderRadius: 10,
            border: `1px solid ${token.colorBorderSecondary}`,
            background: token.colorFillQuaternary,
          }}
        >
          <SkeletonBlock width={80} height={15} radius={4} delay={i * 0.06} />
          <SkeletonBlock width={120} height={10} radius={4} delay={i * 0.06 + 0.05} />
        </div>
      ))}
    </div>
  );
}

function SkeletonBlock({
  width,
  height,
  radius,
  delay,
}: {
  width: number;
  height: number;
  radius: number | string;
  delay: number;
}) {
  return (
    <span
      className="app-skeleton-block"
      style={{
        display: 'inline-block',
        width,
        height,
        borderRadius: radius,
        animationDelay: `${delay}s`,
      }}
    />
  );
}
