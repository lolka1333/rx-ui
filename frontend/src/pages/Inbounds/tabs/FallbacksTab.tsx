//! VLESS-fallback editor. xray-core uses fallbacks as a post-decryption
//! routing matrix: traffic that survives TLS/Reality but fails to decode
//! as VLESS gets forwarded to the matched `(SNI, ALPN, path)` entry. The
//! UI is gated three ways:
//!   * `protocol_kind === 'vless'` — only protocol that ships fallbacks
//!   * `network === 'tcp'` — fallbacks fire on raw post-TLS bytes; WS /
//!     XHTTP frame traffic before xray's fallback hook runs
//!   * `vless_encryption_mode === 'none'` — xray rejects the combo at
//!     startup with "fallbacks can not be used together with decryption"
//! When any precondition fails we still mount the tab (so the operator
//! sees that the feature exists) but render an Alert explaining what to
//! change.

import { Alert, Button, Flex, Form, Input, InputNumber, Select, Typography } from 'antd';
import { DeleteOutlined, PlusOutlined } from '@ant-design/icons';
import { useTranslation } from 'react-i18next';
import type { VlessFallback, VlessFallbackType } from '@/api/types';
import { Section } from '../widgets';
import { DEFAULTS } from '../form/defaults';
import type { FormValues } from '../form/types';

/** Default values written when the operator clicks "Add fallback".
 *  `kind: 'tcp'` covers the common nginx-on-localhost scenario; the
 *  operator overrides via the inline select. */
const NEW_FALLBACK: VlessFallback = {
  name: '',
  alpn: '',
  path: '',
  type: 'tcp' satisfies VlessFallbackType,
  dest: '',
  xver: 0,
};

const ALPN_OPTIONS = [
  { value: '', label: 'any' },
  { value: 'h2', label: 'h2' },
  { value: 'http/1.1', label: 'http/1.1' },
];

const TYPE_OPTIONS: { value: VlessFallbackType; label: string }[] = [
  { value: 'tcp', label: 'tcp' },
  { value: 'unix', label: 'unix' },
  { value: 'serve', label: 'serve' },
];

export function FallbacksTab() {
  const { t } = useTranslation();
  const form = Form.useFormInstance<FormValues>();
  // `Form.useWatch` returns `undefined` on first render before the form's
  // initialValues are committed to the store. Without the fallback the
  // tab flashes its "incompatible" alert on every modal-open even though
  // the defaults are fully compatible.
  const protoKind = Form.useWatch('protocol_kind', form) ?? DEFAULTS.protocol_kind;
  const network = Form.useWatch('network', form) ?? DEFAULTS.network;
  const encMode =
    Form.useWatch('vless_encryption_mode', form) ?? DEFAULTS.vless_encryption_mode;

  // Surface the exact reason the feature is unavailable instead of an
  // abstract "not supported" — the operator can fix one knob and come
  // back, no panel docs lookup needed.
  if (protoKind !== 'vless') {
    return (
      <Alert
        type="info"
        showIcon
        title={t('inbounds.fallbacksOnlyVless')}
      />
    );
  }
  if (network !== 'tcp') {
    return (
      <Alert
        type="warning"
        showIcon
        title={t('inbounds.fallbacksOnlyTcp')}
      />
    );
  }
  if (encMode !== 'none') {
    return (
      <Alert
        type="warning"
        showIcon
        title={t('inbounds.fallbacksNoEncryption')}
      />
    );
  }

  return (
    <Section itemKey="fallbacks" labelKey="inbounds.fallbacksSection">
      <Alert
        type="info"
        showIcon
        title={t('inbounds.fallbacksHint')}
        style={{ marginBottom: 16 }}
      />
      <Form.List name="vless_fallbacks">
        {(fields, { add, remove }) => (
          <>
            {fields.map((field) => (
              <div
                key={field.key}
                style={{
                  border: '1px solid var(--border)',
                  borderRadius: 8,
                  padding: 12,
                  marginBottom: 12,
                }}
              >
                <Flex justify="space-between" align="center" style={{ marginBottom: 8 }}>
                  <Typography.Text
                    type="secondary"
                    style={{ fontSize: 12, fontWeight: 500 }}
                  >
                    {t('inbounds.fallbacksItemTitle', { n: field.name + 1 })}
                  </Typography.Text>
                  <Button
                    type="text"
                    danger
                    size="small"
                    icon={<DeleteOutlined />}
                    onClick={() => remove(field.name)}
                    aria-label={t('inbounds.fallbacksRemove')}
                  />
                </Flex>
                {/* One grid for all 6 fields keeps left/right edges aligned
                    row-to-row. 2fr/1fr matches the natural "long value /
                    short value" split (dest URL ↔ type select, SNI host ↔
                    ALPN dropdown, path ↔ proxy-proto number). */}
                <div
                  style={{
                    display: 'grid',
                    gridTemplateColumns: '2fr 1fr',
                    columnGap: 12,
                  }}
                >
                  <Form.Item
                    name={[field.name, 'dest']}
                    label={t('inbounds.fallbacksDest')}
                    tooltip={t('inbounds.fallbacksDestHint')}
                    rules={[{ required: true, message: t('inbounds.fallbacksDestRequired') }]}
                    style={{ marginBottom: 12 }}
                  >
                    <Input placeholder="127.0.0.1:8080" />
                  </Form.Item>
                  <Form.Item
                    name={[field.name, 'type']}
                    label={t('inbounds.fallbacksType')}
                    tooltip={t('inbounds.fallbacksTypeHint')}
                    style={{ marginBottom: 12 }}
                  >
                    <Select options={TYPE_OPTIONS} />
                  </Form.Item>
                  <Form.Item
                    name={[field.name, 'name']}
                    label={t('inbounds.fallbacksName')}
                    tooltip={t('inbounds.fallbacksNameHint')}
                    style={{ marginBottom: 12 }}
                  >
                    <Input placeholder="(any SNI)" />
                  </Form.Item>
                  <Form.Item
                    name={[field.name, 'alpn']}
                    label={t('inbounds.fallbacksAlpn')}
                    tooltip={t('inbounds.fallbacksAlpnHint')}
                    style={{ marginBottom: 12 }}
                  >
                    <Select options={ALPN_OPTIONS} />
                  </Form.Item>
                  <Form.Item
                    name={[field.name, 'path']}
                    label={t('inbounds.fallbacksPath')}
                    tooltip={t('inbounds.fallbacksPathHint')}
                    rules={[
                      {
                        validator: (_, value: string) => {
                          if (!value || value.startsWith('/')) return Promise.resolve();
                          return Promise.reject(
                            new Error(t('inbounds.fallbacksPathInvalid')),
                          );
                        },
                      },
                    ]}
                    style={{ marginBottom: 0 }}
                  >
                    <Input placeholder="/grpc" />
                  </Form.Item>
                  <Form.Item
                    name={[field.name, 'xver']}
                    label={t('inbounds.fallbacksXver')}
                    tooltip={t('inbounds.fallbacksXverHint')}
                    style={{ marginBottom: 0 }}
                  >
                    <InputNumber min={0} max={2} style={{ width: '100%' }} />
                  </Form.Item>
                </div>
              </div>
            ))}
            <Button
              type="dashed"
              icon={<PlusOutlined />}
              onClick={() => add(NEW_FALLBACK)}
              style={{ width: '100%' }}
            >
              {t('inbounds.fallbacksAdd')}
            </Button>
          </>
        )}
      </Form.List>
    </Section>
  );
}
