/** The two tabs of the share modal: one inbound's link, and the user's
 *  subscription URL. */
import { Alert, Button, Input, Popconfirm, Select, Space, Typography } from 'antd';
import { ReloadOutlined } from '@ant-design/icons';
import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { apiClient } from '@/api/client';
import { useLoadState } from '@/api/loadState';
import { LoadError } from '@/components/LoadState';
import { QrCard } from '@/components/QrCard';
import type { Client, Inbound, PanelSettings, ShareLinkResponse } from '@/api/types';
import type { ClientGroup } from './groups';

/** Canonical subscription URL the operator should share with end
 *  users. Prefers panel settings over the admin's current `window.
 *  location`:
 *   * `sub_link_host` (when set) is the host of the /sub/ URL itself —
 *     the panel's public domain, which may differ from both the admin
 *     URL and the server address baked into the configs (`sub_host_
 *     override`). Empty ≡ use the current origin's host.
 *   * `sub_port` (when non-zero) is the public subscription port; the
 *     admin port may be intentionally restricted by firewall.
 *  Falls back to current origin segments when either field is empty,
 *  which works for single-host self-hosted setups. */
function buildSubscriptionUrl(token: string, settings: PanelSettings | undefined): string {
  // Scheme follows the subscription's OWN TLS (sub_tls_mode), not the panel's:
  // 'off' → plain HTTP (a CDN/tunnel terminates TLS upstream), 'custom' → HTTPS
  // with its own cert, 'inherit' → same as the panel, i.e. the admin's current
  // origin scheme. Deriving it from window.location alone would hand out an
  // http link to a TLS listener (or vice-versa) once the two schemes diverge.
  //
  // sub_tls_mode belongs to the dedicated listener, which only exists at a
  // non-zero sub_port. At port 0 the panel serves /sub/ itself, so its scheme —
  // the current origin's — is the only true one, whatever mode is stored.
  const ownListener = (settings?.sub_port ?? 0) > 0;
  const protocol =
    ownListener && settings?.sub_tls_mode === 'off'
      ? 'http:'
      : ownListener && settings?.sub_tls_mode === 'custom'
        ? 'https:'
        : window.location.protocol;
  const host = settings?.sub_link_host?.trim() || window.location.hostname;
  const port = settings && settings.sub_port > 0
    ? String(settings.sub_port)
    : window.location.port;
  // Hide the well-known ports (80/443) from the shown URL regardless of scheme:
  // operators publish the subscription behind a standard-port endpoint (a CDN /
  // tunnel on 443), where the client supplies the port implicitly. A non-standard
  // port is kept so a direct link still resolves.
  const portSuffix = port && port !== '80' && port !== '443' ? `:${port}` : '';
  return `${protocol}//${host}${portSuffix}/sub/${token}`;
}

/** Byte-mode capacity of the largest QR (version 40) at error-correction
 *  level L is 2953 bytes. Kept a little under it: the encoder throws on
 *  overflow, and it throws from render. */
const QR_MAX_BYTES = 2900;

/** QR byte-mode counts bytes, not code points — links carry percent-encoded
 *  UTF-8 and a `#name` fragment that need not be ASCII. */
function qrBytes(link: string): number {
  return new TextEncoder().encode(link).length;
}

/** "Share link" tab — one inbound's vless:// / hysteria2:// URL with
 *  QR + textarea + copy. For multi-inbound groups a Select at the top
 *  switches between rows without closing the modal (each row gets its
 *  own share-link fetched lazily). For single-inbound groups the
 *  Select is hidden — the link IS the only choice. */
export function ShareLinkPane({
  group,
  currentClientId,
  share,
  inboundById,
  onSwitchInbound,
  switching,
}: {
  group: ClientGroup;
  currentClientId: string;
  share: ShareLinkResponse;
  inboundById: Map<string, Inbound>;
  onSwitchInbound: (client: Client) => void;
  switching: boolean;
}) {
  const { t } = useTranslation();
  return (
    <Space orientation="vertical" style={{ width: '100%' }} size={16}>
      {group.rows.length > 1 && (
        <Select
          value={currentClientId}
          onChange={(id) => {
            const next = group.rows.find((r) => r.id === id);
            if (next) onSwitchInbound(next);
          }}
          loading={switching}
          style={{ width: '100%' }}
          options={group.rows.map((r) => ({
            value: r.id,
            label: inboundById.get(r.inbound_id)?.tag ?? r.inbound_id.slice(0, 8),
          }))}
        />
      )}
      {/* VLESS-encryption share-links carry a 1579-byte ML-KEM public
          key — total URL ≈ 1800 chars, forcing a high-version QR
          (~v25). `level="L"` drops error correction so the modules
          fit; larger `size` for long links keeps each module
          camera-readable.

          Past the byte-mode ceiling the encoder throws — from render, where
          React 19 unmounts the whole root and the panel goes white. An XMC
          mask with two profiles is already over it (each profile carries a
          684-char RSA signature), and the form invites adding more, so the
          link is measured before it is handed over. The text and the copy
          button below stay: only the QR has a size limit. */}
      {qrBytes(share.link) <= QR_MAX_BYTES ? (
        <QrCard
          value={share.link}
          // 354 = 2 px per module on a version-40 code (177 modules), the
          // densest a share-link can be. Below that the card would snap
          // down to one pixel per module.
          size={share.link.length > 800 ? 354 : 224}
          level="L"
        />
      ) : (
        <Alert type="info" showIcon title={t('clients.shareLinkTooLongForQr')} />
      )}
      {share.link.length > 800 && qrBytes(share.link) <= QR_MAX_BYTES && (
        <Typography.Text
          type="secondary"
          style={{ fontSize: 11, display: 'block', textAlign: 'center', marginTop: -8 }}
        >
          {t('clients.shareLinkLargeQrHint')}
        </Typography.Text>
      )}
      <Typography.Text type="secondary" style={{ fontSize: 12 }}>
        {t('clients.shareLinkHost')}: <Typography.Text code>{share.host}</Typography.Text>
      </Typography.Text>
      <Input.TextArea
        value={share.link}
        // A URI fits in a few wrapped rows; a WireGuard config is a dozen
        // short lines, and cutting it at six turns the [Peer] section into
        // something the operator has to scroll for.
        autoSize={{ minRows: 3, maxRows: share.link.includes('\n') ? 14 : 6 }}
        readOnly
        style={{
          fontFamily: 'var(--font-mono)',
          fontSize: 12,
        }}
      />
      <Typography.Text copyable={{ text: share.link }}>
        {t('clients.copy')}
      </Typography.Text>
    </Space>
  );
}

/** "Subscription" tab — public `/sub/{token}` URL with QR, copy, and a
 *  confirmed rotate action. The URL comes from `buildSubscriptionUrl`: the
 *  subscription host and port from the panel settings, the current page's
 *  origin for whatever they leave empty. The bundle aggregates every
 *  share-link for the client's email, so one URL covers a multi-server
 *  setup; v2rayN-latest / Hiddify / NekoBox / sing-box / Streisand
 *  all accept the default base64 body. */
export function SubscriptionPane({
  client,
  onRotate,
  rotating,
}: {
  client: Client;
  onRotate: () => void;
  rotating: boolean;
}) {
  const { t } = useTranslation();
  // Panel settings drive the canonical subscription URL: an operator
  // who set `sub_link_host` wants end-users to fetch the subscription
  // from that hostname (not the admin URL the operator happens to be
  // browsing on); `sub_port` means subscriptions live on a different
  // port than the admin shell. Falls back to `window.location` when
  // either field is empty.
  const settingsQ = useQuery({
    queryKey: ['panel-settings'],
    queryFn: async () => (await apiClient.get<PanelSettings>('/settings/panel')).data,
    staleTime: 30_000,
  });
  const settings = settingsQ.data;
  const state = useLoadState([settingsQ]);
  const url = buildSubscriptionUrl(client.sub_token, settings);
  return (
    <Space orientation="vertical" style={{ width: '100%' }} size={16}>
      {/* The QR stays: falling back to the current origin is right for the
          common single-host setup. But when the settings fetch failed we cannot
          know whether this operator overrode the host or port, and the link
          still looks authoritative — so say the settings could not be read
          rather than let a wrong URL be copied out to a user. */}
      <LoadError state={state} />
      <QrCard value={url} />
      <Typography.Text type="secondary" style={{ fontSize: 12 }}>
        {t('clients.subHint')}
      </Typography.Text>
      <Input.TextArea
        value={url}
        autoSize={{ minRows: 2, maxRows: 4 }}
        readOnly
        style={{
          fontFamily: 'var(--font-mono)',
          fontSize: 12,
        }}
      />
      <Space orientation="horizontal" style={{ width: '100%', justifyContent: 'space-between' }}>
        <Typography.Text copyable={{ text: url }}>
          {t('clients.copy')}
        </Typography.Text>
        <Popconfirm
          title={t('clients.subRotateConfirm')}
          okText={t('common.confirm')}
          cancelText={t('common.cancel')}
          okType="danger"
          onConfirm={onRotate}
        >
          <Button
            type="text"
            size="small"
            danger
            icon={<ReloadOutlined />}
            loading={rotating}
          >
            {t('clients.subRotate')}
          </Button>
        </Popconfirm>
      </Space>
    </Space>
  );
}
