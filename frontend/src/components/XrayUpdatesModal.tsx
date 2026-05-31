import {
  App,
  Modal,
  Collapse,
  Alert,
  Radio,
  Tag,
  Typography,
  Button,
  Grid,
  theme,
} from 'antd';
import { ToolOutlined, GlobalOutlined } from '@ant-design/icons';
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

export function XrayUpdatesModal({ open, onClose, currentVersion }: Props) {
  const { t } = useTranslation();
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
                <Alert
                  type="warning"
                  showIcon
                  title={t('xrayUpdates.warning')}
                />
                {isLoading && <ReleaseSkeletonList />}
                {!isLoading && releases && (
                  <Radio.Group
                    value={selected}
                    onChange={(e) => setSelected(e.target.value as string)}
                    style={{ display: 'flex', flexDirection: 'column', gap: 8, width: '100%' }}
                  >
                    {releases.map((r) => (
                      <ReleaseRow
                        key={r.tag}
                        release={r}
                        isCurrent={r.tag === currentVersion}
                        isSelected={r.tag === selected}
                        onSelect={() => r.asset_url && setSelected(r.tag)}
                        labels={{
                          preRelease: t('xrayUpdates.preRelease'),
                          noBuild: t('xrayUpdates.noBuild'),
                        }}
                      />
                    ))}
                  </Radio.Group>
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
        /* Subtle "section" feel for the two collapse panels — ghost mode by
           itself looked like floating plain text. Round the row, give it a
           background tint, and let hover bump the tint slightly so they read
           as interactive. Body padding trimmed since the icon already adds
           breathing room on the left. */
        .app-updates-collapse .ant-collapse-item {
          margin-bottom: 6px;
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

        /* Make the radio circle big enough to tap on phones. Antd's default
           is 16px which is below the 44px touch-target guideline. */
        @media (max-width: 575px) {
          .app-release-row .ant-radio-inner {
            width: 22px;
            height: 22px;
          }
          .app-release-row .ant-radio-inner::after {
            width: 22px;
            height: 22px;
            margin-block-start: -11px;
            margin-inline-start: -11px;
          }
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
  isSelected: boolean;
  onSelect: () => void;
  labels: { preRelease: string; noBuild: string };
}

function ReleaseRow({ release, isCurrent, isSelected, onSelect, labels }: ReleaseRowProps) {
  const { token } = theme.useToken();
  const noAsset = !release.asset_url;

  // Collapse all secondary info into one nowrap text line so a tag like
  // "v26.4.25" never wraps below "pre-release" on a 320px-wide phone.
  const meta = [
    release.prerelease ? labels.preRelease : null,
    noAsset ? labels.noBuild : null,
    fmtSize(release.asset_size),
  ]
    .filter(Boolean)
    .join(' · ');

  return (
    <div
      className="app-release-row"
      onClick={noAsset ? undefined : onSelect}
      role="button"
      tabIndex={noAsset ? -1 : 0}
      onKeyDown={(e) => {
        if (!noAsset && (e.key === 'Enter' || e.key === ' ')) {
          e.preventDefault();
          onSelect();
        }
      }}
      style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        gap: 12,
        padding: '12px 14px',
        borderRadius: 10,
        border: `1px solid ${
          isSelected && !noAsset ? token.colorPrimary : token.colorBorderSecondary
        }`,
        background: isSelected && !noAsset ? `${token.colorPrimary}14` : 'transparent',
        cursor: noAsset ? 'not-allowed' : 'pointer',
        opacity: noAsset ? 0.45 : 1,
        transition: 'border-color 0.15s, background-color 0.15s',
        minHeight: 52,
        WebkitTapHighlightColor: 'transparent',
        userSelect: 'none',
      }}
    >
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 8,
          minWidth: 0,
          flex: 1,
          flexWrap: 'wrap',
        }}
      >
        <Tag
          color={isCurrent ? 'success' : release.prerelease ? 'orange' : 'purple'}
          style={{ margin: 0, fontWeight: 500 }}
        >
          {release.tag}
        </Tag>
        {meta && (
          <Typography.Text
            type="secondary"
            style={{ fontSize: 11, whiteSpace: 'nowrap' }}
          >
            {meta}
          </Typography.Text>
        )}
      </div>
      <Radio value={release.tag} disabled={noAsset} />
    </div>
  );
}

/**
 * 6 placeholder rows shaped like real release rows — keeps the modal's
 * vertical rhythm steady while GitHub responds, instead of dropping a
 * lonely spinner in the middle.
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
            padding: '12px 14px',
            borderRadius: 10,
            border: `1px solid ${token.colorBorderSecondary}`,
            minHeight: 52,
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, flex: 1 }}>
            <SkeletonBlock width={60} height={20} radius={6} delay={i * 0.06} />
            <SkeletonBlock width={110} height={10} radius={4} delay={i * 0.06 + 0.05} />
          </div>
          <SkeletonBlock width={16} height={16} radius="50%" delay={i * 0.06 + 0.1} />
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
