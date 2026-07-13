//! Create/edit form for a custom outbound. Single vertical form (no tabs —
//! the shape is small): a VLESS or Hysteria 2 endpoint + transport + client-side
//! security, with Mux and Advanced (sendThrough / chaining) tucked into
//! collapsible sections. The protocol picker swaps the protocol-specific block
//! (VLESS UUID/flow/encryption vs. the Hysteria 2 password); transport/security
//! sub-fields appear inline the moment their kind is picked, since several carry
//! required values (Reality publicKey…).

import { App, Button, Form, Input, InputNumber, Select, Space, Typography } from 'antd';
import { memo, useCallback, useLayoutEffect, useMemo, useState, type ReactNode } from 'react';
import { ImportOutlined } from '@ant-design/icons';
import { useTranslation } from 'react-i18next';
import type { CustomOutbound, VlessEncryptionMode } from '@/api/types';
import { FinalMaskTab } from '@/pages/Inbounds/tabs/FinalMaskTab';
import { LinkParseError, parseOutboundLink } from './parseLink';
// Single source of truth for uTLS fingerprints — same list the inbound
// Reality/TLS tabs use (chrome … 360/qq … hello*_NNN version-pinned).
import { FINGERPRINT_OPTIONS } from '@/pages/Inbounds/helpers';
import {
  AddonLabel,
  HeaderListField,
  InputField,
  Section,
  SelectField,
  SwitchField,
} from '@/pages/Inbounds/widgets';
import {
  OUTBOUND_DEFAULTS,
  outboundToForm,
  type OutboundFormValues,
  type OutboundNetwork,
  type OutboundProtocol,
  type OutboundSecurity,
} from './form';

interface OutboundFormProps {
  formKey: number;
  form: ReturnType<typeof Form.useForm<OutboundFormValues>>[0];
  editing: CustomOutbound | null;
  onFinish: (values: OutboundFormValues) => void;
}

const PROTOCOL_OPTIONS = [
  { value: 'vless', label: 'VLESS' },
  { value: 'hysteria', label: 'Hysteria2' },
];

const NETWORK_OPTIONS = [
  { value: 'tcp', label: 'TCP' },
  { value: 'ws', label: 'WebSocket' },
  { value: 'xhttp', label: 'XHTTP' },
];

const SECURITY_OPTIONS = [
  { value: 'none', label: 'None' },
  { value: 'tls', label: 'TLS' },
  { value: 'reality', label: 'Reality' },
];

// Hysteria 2 rides on QUIC, which is always TLS — the only valid security.
const HYSTERIA_SECURITY_OPTIONS = [{ value: 'tls', label: 'TLS' }];

const XHTTP_MODE_OPTIONS = [
  { value: 'auto', label: 'auto' },
  { value: 'packet-up', label: 'packet-up' },
  { value: 'stream-up', label: 'stream-up' },
  { value: 'stream-one', label: 'stream-one' },
];

const ALPN_OPTIONS = [
  { value: 'h2', label: 'h2' },
  { value: 'http/1.1', label: 'http/1.1' },
  { value: 'h3', label: 'h3' },
];

// Small inline heading for a conditional block, with a hairline divider above
// so transport / security groups read as distinct without nesting a Collapse.
function SubHeader({ children }: { children: ReactNode }) {
  return (
    <div
      style={{
        marginTop: 8,
        marginBottom: 12,
        paddingTop: 10,
        borderTop: '1px solid var(--border)',
      }}
    >
      <Typography.Text strong style={{ fontSize: 14 }}>
        {children}
      </Typography.Text>
    </div>
  );
}

export const OutboundForm = memo(function OutboundForm({
  formKey,
  form,
  editing,
  onFinish,
}: OutboundFormProps) {
  const { t } = useTranslation();
  const protocol = Form.useWatch('protocol_kind', form) as OutboundProtocol | undefined;
  const isHysteria = protocol === 'hysteria';
  const network = Form.useWatch('network', form) as OutboundNetwork | undefined;
  const security = Form.useWatch('security', form) as OutboundSecurity | undefined;
  const encryptionMode = Form.useWatch('encryption_mode', form) as
    | VlessEncryptionMode
    | undefined;
  const xhttpObfs = Form.useWatch('xhttp_x_padding_obfs_mode', form) as boolean | undefined;
  const { message } = App.useApp();
  const [linkText, setLinkText] = useState('');

  // Paste a vless:// or hysteria2:// share-link → overlay its fields on a clean
  // default base. Keep the operator's tag (use the link's #name only when the
  // tag is empty) and the enabled flag.
  const applyLink = useCallback(() => {
    const text = linkText.trim();
    if (!text) return;
    try {
      const parsed = parseOutboundLink(text);
      const cur = form.getFieldsValue(true) as OutboundFormValues;
      form.setFieldsValue({
        ...OUTBOUND_DEFAULTS,
        ...parsed,
        tag: cur.tag?.trim() ? cur.tag : (parsed.tag ?? ''),
        enabled: cur.enabled ?? true,
      });
      setLinkText('');
      message.success(t('outbounds.linkParsed'));
    } catch (e) {
      message.error(
        e instanceof LinkParseError ? t(e.i18nKey, e.params) : t('outbounds.linkError'),
      );
    }
  }, [linkText, form, message, t]);

  useLayoutEffect(() => {
    form.resetFields();
  }, [formKey, form]);

  const initialValues = useMemo(
    () => (editing != null ? outboundToForm(editing) : OUTBOUND_DEFAULTS),
    [editing],
  );

  return (
    <Form
      key={formKey}
      form={form}
      layout="vertical"
      initialValues={initialValues}
      onFinish={onFinish}
      style={{ marginTop: 8 }}
    >
      {/* Paste a vless:// or hysteria2:// link to auto-fill the whole form. */}
      <Space.Compact style={{ display: 'flex', marginBottom: 16 }}>
        <AddonLabel side="before">{t('outbounds.link')}</AddonLabel>
        <Input
          value={linkText}
          onChange={(e) => setLinkText(e.target.value)}
          onPressEnter={applyLink}
          placeholder={t('outbounds.linkPlaceholder')}
          allowClear
          style={{ flex: 1, minWidth: 0 }}
        />
        <Button type="primary" ghost icon={<ImportOutlined />} onClick={applyLink}>
          {t('outbounds.linkParse')}
        </Button>
      </Space.Compact>

      <InputField
        name="tag"
        labelKey="outbounds.tag"
        tooltipKey="outbounds.tagHint"
        rules={[{ required: true, message: t('outbounds.tagRequired') }]}
      />

      <Form.Item name="protocol_kind" label={t('outbounds.protocol')} style={{ marginBottom: 12 }}>
        <Select
          options={PROTOCOL_OPTIONS}
          onChange={(val) => {
            // QUIC mandates TLS — snap security to it the moment hysteria is picked.
            if (val === 'hysteria') form.setFieldsValue({ security: 'tls' });
          }}
        />
      </Form.Item>

      {/* Endpoint — remote server address/port (shared by both protocols) */}
      <div style={{ display: 'flex', gap: 12 }}>
        <Form.Item
          name="address"
          label={t('outbounds.address')}
          rules={[{ required: true, message: t('outbounds.addressRequired') }]}
          style={{ flex: 2, marginBottom: 12 }}
        >
          <Input placeholder="example.com" />
        </Form.Item>
        <Form.Item
          name="port"
          label={t('outbounds.port')}
          rules={[{ required: true, message: t('outbounds.portRequired') }]}
          style={{ flex: 1, marginBottom: 12 }}
        >
          <InputNumber min={1} max={65535} style={{ width: '100%' }} />
        </Form.Item>
      </div>

      {!isHysteria && (
        <>
          <InputField
            name="uuid"
            labelKey="outbounds.uuid"
            rules={[{ required: true, message: t('outbounds.uuidRequired') }]}
          />

          <div style={{ display: 'flex', gap: 12 }}>
            <Form.Item name="flow" label={t('outbounds.flow')} style={{ flex: 1, marginBottom: 12 }}>
              <Select
                options={[
                  { value: '', label: t('outbounds.flowNone') },
                  { value: 'xtls-rprx-vision', label: 'xtls-rprx-vision' },
                ]}
              />
            </Form.Item>
            <Form.Item
              name="encryption_mode"
              label={t('outbounds.encryption')}
              tooltip={t('outbounds.encryptionHint')}
              style={{ flex: 1, marginBottom: 12 }}
            >
              <Select
                options={[
                  { value: 'none', label: 'none' },
                  { value: 'mlkem768x25519plus', label: 'mlkem768x25519plus' },
                ]}
              />
            </Form.Item>
          </div>

          <Form.Item
            name="reverse_tag"
            label={t('outbounds.reverseTag')}
            tooltip={t('outbounds.reverseTagHint')}
            style={{ marginBottom: 12 }}
          >
            <Input placeholder={t('outbounds.reverseTagPlaceholder')} allowClear />
          </Form.Item>

          {encryptionMode === 'mlkem768x25519plus' && (
            <>
              <SubHeader>{t('outbounds.encSection')}</SubHeader>
              <InputField
                name="encryption_client_key"
                labelKey="outbounds.encClientKey"
                tooltipKey="outbounds.encClientKeyHint"
                rules={[{ required: true, message: t('outbounds.encClientKeyRequired') }]}
              />
              <div style={{ display: 'flex', gap: 12 }}>
                <Form.Item
                  name="encryption_xor_mode"
                  label={t('outbounds.encXorMode')}
                  style={{ flex: 1, marginBottom: 0 }}
                >
                  <Select
                    options={[
                      { value: 'native', label: 'native' },
                      { value: 'xorpub', label: 'xorpub' },
                      { value: 'random', label: 'random' },
                    ]}
                  />
                </Form.Item>
                <Form.Item
                  name="encryption_padding"
                  label={t('outbounds.encPadding')}
                  tooltip={t('outbounds.encPaddingHint')}
                  style={{ flex: 1, marginBottom: 0 }}
                >
                  <Input placeholder="100-111-1111.75-0-111" />
                </Form.Item>
              </div>
            </>
          )}
        </>
      )}

      {isHysteria && (
        <InputField
          name="hysteria_auth"
          labelKey="outbounds.hysteriaAuth"
          tooltipKey="outbounds.hysteriaAuthHint"
          rules={[{ required: true, message: t('outbounds.hysteriaAuthRequired') }]}
        />
      )}

      <div style={{ display: 'flex', gap: 12 }}>
        {!isHysteria && (
          <Form.Item
            name="network"
            label={t('outbounds.network')}
            style={{ flex: 1, marginBottom: 12 }}
          >
            <Select options={NETWORK_OPTIONS} />
          </Form.Item>
        )}
        <Form.Item name="security" label={t('outbounds.security')} style={{ flex: 1, marginBottom: 12 }}>
          <Select options={isHysteria ? HYSTERIA_SECURITY_OPTIONS : SECURITY_OPTIONS} />
        </Form.Item>
      </div>

      {/* Transport sub-fields (VLESS only — hysteria IS its own transport) */}
      {!isHysteria && network === 'ws' && (
        <>
          <SubHeader>{t('outbounds.transportWs')}</SubHeader>
          <InputField name="ws_path" labelKey="outbounds.wsPath" />
          <InputField name="ws_host" labelKey="outbounds.wsHost" last />
          <Section itemKey="ws-adv" labelKey="outbounds.advanced">
            <Form.Item
              label={t('outbounds.wsHeaders')}
              tooltip={t('outbounds.wsHeadersHint')}
              style={{ marginBottom: 12 }}
            >
              <HeaderListField name="ws_headers" />
            </Form.Item>
            <Form.Item
              name="ws_heartbeat_period"
              label={t('outbounds.wsHeartbeat')}
              tooltip={t('outbounds.wsHeartbeatHint')}
              style={{ marginBottom: 0 }}
            >
              <InputNumber min={0} max={3600} style={{ width: '100%' }} />
            </Form.Item>
          </Section>
        </>
      )}
      {!isHysteria && network === 'xhttp' && (
        <>
          <SubHeader>{t('outbounds.transportXhttp')}</SubHeader>
          <InputField name="xhttp_path" labelKey="outbounds.xhttpPath" />
          <InputField name="xhttp_host" labelKey="outbounds.xhttpHost" />
          <SelectField name="xhttp_mode" labelKey="outbounds.xhttpMode" options={XHTTP_MODE_OPTIONS} />
          <Section itemKey="xhttp-adv" labelKey="outbounds.xhttpAdv">
            <Form.Item
              label={t('outbounds.xhttpHeaders')}
              tooltip={t('outbounds.xhttpHeadersHint')}
              style={{ marginBottom: 12 }}
            >
              <HeaderListField name="xhttp_headers" />
            </Form.Item>
            <InputField
              name="xhttp_x_padding_bytes"
              labelKey="outbounds.xhttpPaddingBytes"
              tooltipKey="outbounds.xhttpPaddingBytesHint"
            />
            <SwitchField
              name="xhttp_x_padding_obfs_mode"
              labelKey="outbounds.xhttpObfs"
              tooltipKey="outbounds.xhttpObfsHint"
            />
            {xhttpObfs && (
              <>
                <div style={{ display: 'flex', gap: 12 }}>
                  <Form.Item
                    name="xhttp_x_padding_placement"
                    label={t('outbounds.xhttpPadPlacement')}
                    style={{ flex: 1, marginBottom: 12 }}
                  >
                    <Input placeholder="header" />
                  </Form.Item>
                  <Form.Item
                    name="xhttp_x_padding_key"
                    label={t('outbounds.xhttpPadKey')}
                    style={{ flex: 1, marginBottom: 12 }}
                  >
                    <Input />
                  </Form.Item>
                </div>
                <div style={{ display: 'flex', gap: 12 }}>
                  <Form.Item
                    name="xhttp_x_padding_header"
                    label={t('outbounds.xhttpPadHeader')}
                    style={{ flex: 1, marginBottom: 12 }}
                  >
                    <Input />
                  </Form.Item>
                  <Form.Item
                    name="xhttp_x_padding_method"
                    label={t('outbounds.xhttpPadMethod')}
                    style={{ flex: 1, marginBottom: 12 }}
                  >
                    <Input placeholder="GET" />
                  </Form.Item>
                </div>
              </>
            )}
            <div style={{ display: 'flex', gap: 12 }}>
              <Form.Item
                name="xhttp_session_placement"
                label={t('outbounds.xhttpSessionPlacement')}
                style={{ flex: 1, marginBottom: 12 }}
              >
                <Input placeholder="path" />
              </Form.Item>
              <Form.Item
                name="xhttp_session_key"
                label={t('outbounds.xhttpSessionKey')}
                style={{ flex: 1, marginBottom: 12 }}
              >
                <Input />
              </Form.Item>
            </div>
            <div style={{ display: 'flex', gap: 12 }}>
              <Form.Item
                name="xhttp_session_id_table"
                label={t('outbounds.xhttpSessionTable')}
                tooltip={t('outbounds.xhttpSessionTableHint')}
                style={{ flex: 1, marginBottom: 12 }}
              >
                <Input placeholder="Base62" />
              </Form.Item>
              <Form.Item
                name="xhttp_session_id_length"
                label={t('outbounds.xhttpSessionLength')}
                style={{ flex: 1, marginBottom: 12 }}
              >
                <Input placeholder="16-32" />
              </Form.Item>
            </div>
            <div style={{ display: 'flex', gap: 12 }}>
              <Form.Item
                name="xhttp_seq_placement"
                label={t('outbounds.xhttpSeqPlacement')}
                style={{ flex: 1, marginBottom: 12 }}
              >
                <Input placeholder="query" />
              </Form.Item>
              <Form.Item
                name="xhttp_seq_key"
                label={t('outbounds.xhttpSeqKey')}
                style={{ flex: 1, marginBottom: 12 }}
              >
                <Input />
              </Form.Item>
            </div>
            <div style={{ display: 'flex', gap: 12 }}>
              <Form.Item
                name="xhttp_uplink_data_placement"
                label={t('outbounds.xhttpUplinkPlacement')}
                style={{ flex: 1, marginBottom: 0 }}
              >
                <Input placeholder="body" />
              </Form.Item>
              <Form.Item
                name="xhttp_uplink_data_key"
                label={t('outbounds.xhttpUplinkKey')}
                style={{ flex: 1, marginBottom: 0 }}
              >
                <Input />
              </Form.Item>
            </div>
          </Section>
        </>
      )}

      {/* Security sub-fields (client side) */}
      {security === 'tls' && (
        <>
          <SubHeader>{t('outbounds.securityTls')}</SubHeader>
          <InputField
            name="tls_server_name"
            labelKey="outbounds.tlsServerName"
            tooltipKey="outbounds.tlsServerNameHint"
          />
          <Form.Item name="tls_alpn" label={t('outbounds.tlsAlpn')} style={{ marginBottom: 12 }}>
            <Select mode="multiple" allowClear options={ALPN_OPTIONS} placeholder="http/1.1" />
          </Form.Item>
          <SelectField
            name="tls_fingerprint"
            labelKey="outbounds.fingerprint"
            options={FINGERPRINT_OPTIONS}
          />
          <Form.Item
            name="tls_verify_peer_cert_by_name"
            label={t('outbounds.tlsVcn')}
            tooltip={t('outbounds.tlsVcnHint')}
            style={{ marginBottom: 12 }}
          >
            <Select mode="tags" allowClear placeholder="example.com" />
          </Form.Item>
          <Form.Item
            name="tls_pinned_peer_cert_sha256"
            label={t('outbounds.tlsPcs')}
            tooltip={t('outbounds.tlsPcsHint')}
            style={{ marginBottom: 0 }}
          >
            <Select mode="tags" allowClear placeholder="SHA-256 (hex / base64)" />
          </Form.Item>
        </>
      )}
      {security === 'reality' && (
        <>
          <SubHeader>{t('outbounds.securityReality')}</SubHeader>
          <InputField
            name="reality_server_name"
            labelKey="outbounds.realityServerName"
            tooltipKey="outbounds.realityServerNameHint"
            rules={[{ required: true, message: t('outbounds.realityServerNameRequired') }]}
          />
          <InputField
            name="reality_public_key"
            labelKey="outbounds.realityPublicKey"
            tooltipKey="outbounds.realityPublicKeyHint"
            rules={[{ required: true, message: t('outbounds.realityPublicKeyRequired') }]}
          />
          <InputField
            name="reality_short_id"
            labelKey="outbounds.realityShortId"
            tooltipKey="outbounds.realityShortIdHint"
          />
          <div style={{ display: 'flex', gap: 12 }}>
            <Form.Item
              name="reality_fingerprint"
              label={t('outbounds.fingerprint')}
              style={{ flex: 1, marginBottom: 0 }}
            >
              <Select options={FINGERPRINT_OPTIONS} />
            </Form.Item>
            <Form.Item
              name="reality_spider_x"
              label={t('outbounds.realitySpiderX')}
              style={{ flex: 1, marginBottom: 0 }}
            >
              <Input placeholder="/" />
            </Form.Item>
          </div>
        </>
      )}

      {/* Mux */}
      <Section itemKey="mux" labelKey="outbounds.muxSection">
        <SwitchField name="mux_enabled" labelKey="outbounds.muxEnabled" />
        <Form.Item
          name="mux_concurrency"
          label={t('outbounds.muxConcurrency')}
          tooltip={t('outbounds.muxConcurrencyHint')}
          style={{ marginBottom: 0 }}
        >
          <InputNumber style={{ width: '100%' }} />
        </Form.Item>
      </Section>

      {/* FinalMask — mirror the upstream's socket obfuscation (reuses the
          inbound tab; Sudoku/Noise must match the server or it drops). */}
      <Section itemKey="finalmask" labelKey="outbounds.finalmaskSection">
        <FinalMaskTab />
      </Section>

      {/* Advanced */}
      <Section itemKey="advanced" labelKey="outbounds.advancedSection">
        <InputField
          name="send_through"
          labelKey="outbounds.sendThrough"
          tooltipKey="outbounds.sendThroughHint"
        />
        <InputField
          name="proxy_tag"
          labelKey="outbounds.proxyTag"
          tooltipKey="outbounds.proxyTagHint"
          last
        />
      </Section>
    </Form>
  );
});
