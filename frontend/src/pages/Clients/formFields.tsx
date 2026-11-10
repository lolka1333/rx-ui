/**
 * The protocol-dependent fields of the client form. Each watches the form's
 * `inbound_ids` and shows itself only when the selected inbounds give it a
 * meaning, so the Form.useWatch subscription re-renders just that field.
 */
import { Button, Form, Input, Popconfirm, Select } from 'antd';
import { ReloadOutlined } from '@ant-design/icons';
import { useTranslation } from 'react-i18next';
import type { Client, Inbound } from '@/api/types';

/**
 * Conditional `auth` field for Hysteria 2 clients. Watches the form's
 * `inbound_ids` set and renders the input when ANY selected inbound's
 * protocol is `hysteria2` — the single auth value is shared across
 * every selected inbound by the bulk-assign endpoint. VLESS-only
 * selections see nothing (the wire uses `uuid` instead).
 *
 * Implemented as its own component (rather than inlined in the form) so
 * the Form.useWatch subscription only re-renders this small subtree,
 * not the whole modal body.
 */
export function ClientAuthField({ inboundById }: { inboundById: Map<string, Inbound> }) {
  const { t } = useTranslation();
  const form = Form.useFormInstance();
  const inboundIds = (Form.useWatch<string[] | undefined>('inbound_ids', form)) ?? [];
  const anyHysteria = inboundIds.some(
    (id) => inboundById.get(id)?.protocol.kind === 'hysteria2',
  );
  if (!anyHysteria) return null;
  return (
    <Form.Item
      name="auth"
      label={t('clients.auth')}
      tooltip={t('clients.authTooltip')}
    >
      <Input placeholder={t('clients.authPlaceholder')} allowClear />
    </Form.Item>
  );
}

/**
 * One WireGuard peer's credentials, read-only, with a rotate action.
 *
 * The panel owns both halves of a peer's keypair (that is what lets it hand
 * out a ready config), so there is nothing here for the operator to type — but
 * plenty to look at: which address inside the tunnel this peer holds, the key
 * the server knows it by, and the pre-shared key that has to match on both
 * sides. Rotating mints new secrets and keeps the address, because the address
 * is the peer's identity at runtime and what its traffic is counted against.
 */
export function ClientWireguardBlock({
  row,
  inboundTag,
  showTag,
  onRotate,
  rotating,
}: {
  row: Client;
  inboundTag: string;
  showTag: boolean;
  onRotate: () => void;
  rotating: boolean;
}) {
  const { t } = useTranslation();
  // Ordinary fields in the form's own flow: same label-above-control shape,
  // same spacing, same control as everything around them. The only difference
  // is that the operator cannot type in them.
  //
  // The inbound's tag rides in the labels instead of a heading, and only when
  // it has to — one email can sit on two WireGuard inbounds, and then there
  // are two addresses on screen with nothing to tell them apart.
  const label = (key: string) => (showTag ? `${t(key)} · ${inboundTag}` : t(key));
  return (
    <>
      <Form.Item label={label('clients.wgAddress')} tooltip={t('clients.wgAddressHint')}>
        <Input readOnly value={row.wg_address ?? ''} />
      </Form.Item>
      <Form.Item label={label('clients.wgPublicKey')} tooltip={t('clients.wgPublicKeyHint')}>
        <Input readOnly value={row.wg_public_key ?? ''} />
      </Form.Item>
      {/* Empty when the inbound issues no pre-shared key, or for a peer that
          predates them: the config then carries no PresharedKey line, and
          reissuing is how such a peer gets one. */}
      <Form.Item label={label('clients.wgPsk')} tooltip={t('clients.wgPskHint')}>
        <Input
          readOnly
          value={row.wg_preshared_key ?? ''}
          placeholder={t('clients.wgNoPsk')}
        />
      </Form.Item>
      <Form.Item>
        <Popconfirm
          title={t('clients.wgRotateConfirm')}
          description={<div style={{ maxWidth: 360 }}>{t('clients.wgRotateWarning')}</div>}
          okText={t('clients.wgRotateOk')}
          okType="danger"
          cancelText={t('common.cancel')}
          onConfirm={onRotate}
        >
          <Button size="small" icon={<ReloadOutlined />} loading={rotating}>
            {t('clients.wgRotate')}
          </Button>
        </Popconfirm>
      </Form.Item>
    </>
  );
}

/**
 * The same section on the create form, before the peer exists.
 *
 * Shown rather than omitted on purpose: leaving it out made the credentials
 * look optional — something the operator had failed to fill in — when in fact
 * every peer gets all three, and the panel is the one that issues them. The
 * address decides what the rest is worth: it is drawn from the inbound's pool
 * inside the transaction that creates the row, so there is nothing honest to
 * show here until that happens.
 */
export function ClientWireguardPending({ inboundById }: { inboundById: Map<string, Inbound> }) {
  const { t } = useTranslation();
  const form = Form.useFormInstance();
  const inboundIds = (Form.useWatch<string[] | undefined>('inbound_ids', form)) ?? [];
  const anyWireguard = inboundIds.some(
    (id) => inboundById.get(id)?.protocol.kind === 'wireguard',
  );
  if (!anyWireguard) return null;
  // Plain fields in the form's own flow — no heading, no rule. What they are
  // is already said by the labels, and a section header here would be the only
  // one in the modal.
  return (
    <>
      {(['wgAddress', 'wgPublicKey', 'wgPsk'] as const).map((key) => (
        <Form.Item key={key} label={t(`clients.${key}`)} tooltip={t(`clients.${key}Hint`)}>
          <Input disabled placeholder={t('clients.wgIssuedOnSave')} />
        </Form.Item>
      ))}
    </>
  );
}

/**
 * The UUID field, hidden when every selected inbound is WireGuard. A peer is
 * identified by its key and its address inside the tunnel — both generated by
 * the panel — so a UUID typed here would go nowhere. Still shown as soon as
 * one VLESS or Hysteria inbound is in the set: there the same value is the
 * client's identity (and Hysteria's auth fallback).
 */
export function ClientUuidField({ inboundById }: { inboundById: Map<string, Inbound> }) {
  const { t } = useTranslation();
  const form = Form.useFormInstance();
  const inboundIds = (Form.useWatch<string[] | undefined>('inbound_ids', form)) ?? [];
  const allWireguard =
    inboundIds.length > 0 &&
    inboundIds.every((id) => inboundById.get(id)?.protocol.kind === 'wireguard');
  if (allWireguard) return null;
  return (
    <Form.Item name="uuid" label={t('clients.uuid')} tooltip={t('clients.uuidTooltip')}>
      <Input placeholder={t('clients.uuidPlaceholder')} />
    </Form.Item>
  );
}

/**
 * Conditional `flow` field. XTLS Vision is a VLESS-only feature
 * (Hysteria 2 ignores it), so when the target inbound set has zero
 * VLESS rows the picker would be a no-op slot in the form. Hide it
 * instead of greying it out — the operator's eyes don't need to learn
 * "this control means nothing right now."
 */
export function ClientFlowField({ inboundById }: { inboundById: Map<string, Inbound> }) {
  const { t } = useTranslation();
  const form = Form.useFormInstance();
  const inboundIds = (Form.useWatch<string[] | undefined>('inbound_ids', form)) ?? [];
  const anyVless = inboundIds.some(
    (id) => inboundById.get(id)?.protocol.kind === 'vless',
  );
  if (!anyVless) return null;
  return (
    <Form.Item name="flow" label={t('clients.flow')}>
      <Select
        options={[
          { value: 'inherit', label: t('clients.flowInherit') },
          { value: '', label: t('clients.flowNone') },
          { value: 'xtls-rprx-vision', label: 'XTLS Vision' },
        ]}
      />
    </Form.Item>
  );
}

/**
 * Conditional VLESS Reverse Proxy portal field. Same VLESS-only visibility
 * rule as the flow picker (Hysteria has no reverse mode). A non-empty tag
 * turns this user into a reverse portal: a bridge — a VLESS outbound elsewhere
 * carrying the same tag — dials in as this user and registers a tunnel outbound
 * under the tag on this server, which routing rules can then target.
 */
export function ClientReverseField({ inboundById }: { inboundById: Map<string, Inbound> }) {
  const { t } = useTranslation();
  const form = Form.useFormInstance();
  const inboundIds = (Form.useWatch<string[] | undefined>('inbound_ids', form)) ?? [];
  const anyVless = inboundIds.some((id) => inboundById.get(id)?.protocol.kind === 'vless');
  if (!anyVless) return null;
  return (
    <Form.Item
      name="reverse_tag"
      label={t('clients.reverseTag')}
      tooltip={t('clients.reverseTagHint')}
    >
      <Input placeholder={t('clients.reverseTagPlaceholder')} allowClear />
    </Form.Item>
  );
}
