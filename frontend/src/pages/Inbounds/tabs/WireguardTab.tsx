//! WireGuard inbound panel — the node as a WireGuard server device.
//!
//! The operator owns the tunnel subnet, the MTU and the resolver handed to
//! clients; the device keypair follows Reality's contract exactly. A fresh pair
//! is fetched from `POST /api/keygen/wireguard-keypair` the moment the tab
//! opens on a new inbound, so the public key clients will carry is on screen
//! before anything is saved, and both halves round-trip in the form.
//!
//! The private key is shown and editable on purpose. Unlike Reality's — which
//! the panel never hands out — this one IS the server's identity in every
//! config already in a user's hands: an operator rebuilding a node, or moving
//! an existing WireGuard server into the panel, needs to paste the key they
//! already have instead of invalidating every client. The backend re-derives
//! the public half from whatever private half arrives, so a mismatched pair
//! cannot be stored.

import { App, Button, Form, Input, InputNumber, Switch, Tooltip, Typography } from 'antd';
import { ReloadOutlined } from '@ant-design/icons';
import { useCallback, useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { apiClient } from '@/api/client';
import { apiErrorMessage } from '@/api/errors';
import type { WireguardKeypair } from '@/api/types';
import { Section } from '../widgets';
import type { FormValues } from '../form/types';

/** `10.66.66.0/24` — a v4 network plus a prefix the backend will accept.
 *  The real check is server-side (it also rejects host addresses and
 *  prefixes that leave no room); this one exists so a typo doesn't cost
 *  a round-trip. */
const SUBNET_RE = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;

export function WireguardTab() {
  const { t } = useTranslation();
  const { message } = App.useApp();
  const form = Form.useFormInstance<FormValues>();
  const [generating, setGenerating] = useState(false);
  // Whether the private key was edited by hand since the shown pair was made.
  // The public field can then say it is about to be recomputed rather than
  // displaying a key that no longer belongs to the private one. Driven by the
  // input's own onChange — rc-field-form keeps a child's handler and calls it
  // alongside its own, so this composes with the Form.Item binding.
  const [handEdited, setHandEdited] = useState(false);

  const fetchKeypair = useCallback(async () => {
    const { data } = await apiClient.post<WireguardKeypair>('/keygen/wireguard-keypair');
    form.setFieldsValue({
      wg_secret_key: data.private_key,
      wg_public_key: data.public_key,
    });
  }, [form]);

  const regenerate = useCallback(() => {
    setGenerating(true);
    fetchKeypair()
      .then(() => setHandEdited(false))
      .catch((err: unknown) => message.error(apiErrorMessage(err) ?? t('inbounds.wgKeygenError')))
      .finally(() => setGenerating(false));
  }, [fetchKeypair, message, t]);

  // A new inbound arrives with both halves empty — fill them so the operator
  // sees the pair up front. Editing reuses the stored one. The ref stops
  // StrictMode's double-invoked mount effect from burning a second keygen.
  const didInit = useRef(false);
  useEffect(() => {
    if (didInit.current) return;
    if (!form.getFieldValue('wg_public_key')) {
      didInit.current = true;
      fetchKeypair().catch((err: unknown) =>
        message.error(apiErrorMessage(err) ?? t('inbounds.wgKeygenError')),
      );
    }
  }, [form, fetchKeypair, message, t]);

  return (
    <>
      <Form.Item
        name="wg_subnet"
        label={t('inbounds.wgSubnet')}
        tooltip={t('inbounds.wgSubnetHint')}
        rules={[
          { required: true, message: t('inbounds.wgSubnetRequired') },
          { pattern: SUBNET_RE, message: t('inbounds.wgSubnetInvalid') },
        ]}
      >
        <Input placeholder="10.66.66.0/24" style={{ fontFamily: 'var(--font-mono)' }} />
      </Form.Item>

      <Form.Item name="wg_mtu" label={t('inbounds.wgMtu')} tooltip={t('inbounds.wgMtuHint')}>
        <InputNumber min={576} max={1500} placeholder="1420" />
      </Form.Item>

      <Form.Item name="wg_dns" label={t('inbounds.wgDns')} tooltip={t('inbounds.wgDnsHint')}>
        <Input placeholder="1.1.1.1" allowClear />
      </Form.Item>

      <Form.Item
        name="wg_client_allowed_ips"
        label={t('inbounds.wgAllowedIps')}
        tooltip={t('inbounds.wgAllowedIpsHint')}
      >
        <Input placeholder="0.0.0.0/0" style={{ fontFamily: 'var(--font-mono)' }} allowClear />
      </Form.Item>

      <Form.Item
        name="wg_client_keepalive"
        label={t('inbounds.wgKeepalive')}
        tooltip={t('inbounds.wgKeepaliveHint')}
      >
        <InputNumber min={0} max={65535} placeholder="25" />
      </Form.Item>

      {/* Optional in WireGuard itself, so it stays the operator's call. Off
          means a peer is issued exactly what a plain WireGuard server would
          hand out; flipping it changes nothing for peers that already exist. */}
      <Form.Item
        name="wg_issue_preshared_key"
        label={t('inbounds.wgIssuePsk')}
        tooltip={t('inbounds.wgIssuePskHint')}
        valuePropName="checked"
      >
        <Switch />
      </Form.Item>

      {/* Collapsed by default, like every other block of knobs in this form:
          the pair is generated and re-derived for the operator, so it is here
          to be copied or replaced, not filled in. */}
      <Section itemKey="wireguardKeys" labelKey="inbounds.wgKeysSection">
        <Form.Item
          name="wg_secret_key"
          label={t('inbounds.wgPrivateKey')}
          tooltip={t('inbounds.wgPrivateKeyHint')}
        >
          {/* Plain text, not `Input.Password`: a masked field makes Chrome read
              the tab as a login form and pop "save password?" over it — and the
              panel shows every other key (the outbound's own WireGuard private
              key, VLESS encryption keys) in the clear anyway. */}
          <Input
            style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}
            placeholder={generating ? t('inbounds.wgKeygenRunning') : undefined}
            autoComplete="off"
            spellCheck={false}
            onChange={() => setHandEdited(true)}
            addonAfter={
              <Tooltip title={t('inbounds.wgRegenerate')}>
                <Button
                  size="small"
                  type="text"
                  icon={<ReloadOutlined />}
                  loading={generating}
                  onClick={regenerate}
                />
              </Tooltip>
            }
          />
        </Form.Item>
        <Typography.Text type="secondary" style={{ fontSize: 11, display: 'block', marginTop: -8 }}>
          {t('inbounds.wgPrivateKeyWarning')}
        </Typography.Text>

        <Form.Item
          name="wg_public_key"
          label={t('inbounds.wgPublicKey')}
          tooltip={t('inbounds.wgPublicKeyHint')}
          style={{ marginTop: 12 }}
        >
          <Input readOnly style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }} />
        </Form.Item>
        {handEdited && (
          <Typography.Text type="warning" style={{ fontSize: 11, display: 'block', marginTop: -8 }}>
            {t('inbounds.wgPublicKeyStale')}
          </Typography.Text>
        )}
      </Section>
    </>
  );
}
