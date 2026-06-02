//! VLESS post-quantum encryption section. Rendered inside `GeneralTab`
//! (registered via PROTOCOL_REGISTRY.vless.MainTabExtras) since it's
//! VLESS-specific. Owns its own keypair-generation mutation + the
//! auto-(re)generate effect that keeps the keys in sync with the
//! selected `auth` primitive.

import { Button, Form, Input, InputNumber, Select, Typography, App } from 'antd';
import { ReloadOutlined } from '@ant-design/icons';
import { useEffect, useRef, useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { apiClient } from '@/api/client';
import { apiErrorMessage } from '@/api/errors';
import type { VlessEncryptionAuth, VlessEncryptionMode } from '@/api/types';
import { Section } from '../widgets';
import type { FormValues } from '../form/types';

export function VlessEncryption() {
  const { t } = useTranslation();
  const { message } = App.useApp();
  const form = Form.useFormInstance<FormValues>();
  const mode = Form.useWatch('vless_encryption_mode', form) as
    | VlessEncryptionMode
    | undefined;
  const auth = Form.useWatch('vless_encryption_auth', form) as
    | VlessEncryptionAuth
    | undefined;
  // Watch the keys through the form so a fresh keygen + setFieldsValue
  // re-renders the card without us having to thread state through
  // props — the form instance IS the single source of truth here.
  const serverKey = (Form.useWatch('vless_encryption_server_key', form) ?? '') as string;
  const clientKey = (Form.useWatch('vless_encryption_client_key', form) ?? '') as string;
  const enabled = mode === 'mlkem768x25519plus';
  const hasKeys = serverKey.length > 0 && clientKey.length > 0;
  const [serverKeyShown, setServerKeyShown] = useState(false);

  const keygen = useMutation({
    mutationFn: async (a: VlessEncryptionAuth) =>
      (
        await apiClient.post<{ server_key: string; client_key: string }>(
          '/keygen/vless-encryption',
          undefined,
          { params: { auth: a } },
        )
      ).data,
    onSuccess: (kp) => {
      form.setFieldsValue({
        vless_encryption_server_key: kp.server_key,
        vless_encryption_client_key: kp.client_key,
      });
    },
    onError: (err: unknown) =>
      message.error(apiErrorMessage(err) ?? t('inbounds.vlessEncRegenerateError')),
  });

  // Auto-(re)generate keys in two distinct cases:
  //   1. Operator just flipped the mode to PQ and the form has no keys
  //      yet (fresh-create flow).
  //   2. Operator changed the `auth` primitive (X25519 ↔ ML-KEM-768) —
  //      the existing keys belong to the wrong primitive now, so they
  //      have to be regenerated to match the new selection.
  // We track the auth value the current keys were generated for in a
  // ref; mismatch with the form value means a regeneration is due.
  // For an inbound being edited, the ref initialises to the auth read
  // from `inboundToForm`, so the effect stays inert until the operator
  // actually changes the dropdown.
  const prevAuthRef = useRef<VlessEncryptionAuth | undefined>(auth);
  useEffect(() => {
    if (!enabled || !auth || keygen.isPending) return;
    const noKeys = !hasKeys;
    const authChanged = prevAuthRef.current !== auth;
    if (noKeys || authChanged) {
      keygen.mutate(auth);
      prevAuthRef.current = auth;
    }
    // `keygen` is stable; intentionally NOT in deps to avoid re-firing
    // on its own onSuccess. `keygen.isPending` IS in deps so that an
    // auth change made while a previous keygen is in flight gets picked
    // up the moment the in-flight mutation settles.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enabled, hasKeys, auth, keygen.isPending]);

  return (
    <Section itemKey="vlessEncryption" labelKey="inbounds.vlessEncSection">
      {/* Both Mode and Auth use Select (not Radio.Group) for the same
          reason Transport does: the labels are too long to fit on a
          mobile-width viewport when laid out as horizontal radio
          buttons, and we want a stable, single-row footprint. */}
      <Form.Item
        name="vless_encryption_mode"
        label={t('inbounds.vlessEncMode')}
        tooltip={t('inbounds.vlessEncModeTooltip')}
        style={{ marginBottom: enabled ? 12 : 0 }}
      >
        <Select
          options={[
            { value: 'none', label: t('inbounds.vlessEncModeNone') },
            { value: 'mlkem768x25519plus', label: 'mlkem768x25519plus' },
          ]}
        />
      </Form.Item>

      {enabled && (
        <>
          {/* Register the keypair fields so `Form.useWatch` above can
              subscribe and so `form.getFieldsValue(true)` on submit
              picks them up. Hidden = no UI render; the actual keypair
              display lives in the styled card below. */}
          <Form.Item name="vless_encryption_server_key" noStyle hidden>
            <Input />
          </Form.Item>
          <Form.Item name="vless_encryption_client_key" noStyle hidden>
            <Input />
          </Form.Item>

          <Form.Item
            name="vless_encryption_auth"
            label={t('inbounds.vlessEncAuth')}
            tooltip={t('inbounds.vlessEncAuthTooltip')}
            style={{ marginBottom: 12 }}
          >
            <Select
              options={[
                {
                  value: 'mlkem768',
                  label: (
                    <span>
                      ML-KEM-768
                      <span style={{ opacity: 0.6, fontSize: 11, marginLeft: 6 }}>
                        (post-quantum)
                      </span>
                    </span>
                  ),
                },
                { value: 'x25519', label: 'X25519' },
              ]}
            />
          </Form.Item>

          {/* Keypair card — visually distinct from the form to underline
              "this is generated material, not something you type". Server
              key uses Antd's Input.Password for the eye-toggle (with
              built-in mask), client key is read-only Input with the
              standard copyable suffix. Labels sit above the inputs at a
              consistent width; the regenerate action lives in a fixed
              footer row regardless of whether keys exist. */}
          <Form.Item style={{ marginBottom: 12 }}>
            <div
              style={{
                border: '1px solid var(--ant-color-border-secondary, rgba(0,0,0,0.08))',
                borderRadius: 8,
                padding: 14,
                background: 'var(--ant-color-fill-quaternary, rgba(0,0,0,0.02))',
              }}
            >
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  marginBottom: 10,
                }}
              >
                <Typography.Text strong style={{ fontSize: 13 }}>
                  {t('inbounds.vlessEncKeys')}
                </Typography.Text>
                <Button
                  size="small"
                  type="text"
                  icon={<ReloadOutlined />}
                  loading={keygen.isPending}
                  onClick={() => auth && keygen.mutate(auth)}
                  title={
                    hasKeys
                      ? t('inbounds.vlessEncRegenerate')
                      : t('inbounds.vlessEncGenerate')
                  }
                />
              </div>

              {hasKeys ? (
                <>
                  <label
                    htmlFor="vless-enc-server-key"
                    className="ant-typography ant-typography-secondary"
                    style={{ fontSize: 11, display: 'block', marginBottom: 2 }}
                  >
                    {t('inbounds.vlessEncServerKey')}
                  </label>
                  <Input.Password
                    id="vless-enc-server-key"
                    size="small"
                    readOnly
                    value={serverKey}
                    visibilityToggle={{
                      visible: serverKeyShown,
                      onVisibleChange: setServerKeyShown,
                    }}
                    style={{
                      fontFamily: 'ui-monospace, "JetBrains Mono", Consolas, monospace',
                      fontSize: 11,
                      marginBottom: 10,
                    }}
                  />

                  <label
                    htmlFor="vless-enc-client-key"
                    className="ant-typography ant-typography-secondary"
                    style={{ fontSize: 11, display: 'block', marginBottom: 2 }}
                  >
                    {t('inbounds.vlessEncClientKey')}
                  </label>
                  <Input
                    id="vless-enc-client-key"
                    size="small"
                    readOnly
                    value={clientKey}
                    suffix={
                      <Typography.Text
                        copyable={{ text: clientKey, tooltips: false }}
                        style={{ marginLeft: 4 }}
                      />
                    }
                    style={{
                      fontFamily: 'ui-monospace, "JetBrains Mono", Consolas, monospace',
                      fontSize: 11,
                    }}
                  />
                </>
              ) : (
                <Typography.Text type="secondary" style={{ fontSize: 12, display: 'block' }}>
                  {keygen.isPending
                    ? t('inbounds.vlessEncKeysGenerating')
                    : t('inbounds.vlessEncKeysIdle')}
                </Typography.Text>
              )}
            </div>
          </Form.Item>

          <Section itemKey="vlessEncAdvanced" labelKey="inbounds.vlessEncAdvancedSection">
            <Form.Item
              name="vless_encryption_xor_mode"
              label={t('inbounds.vlessEncXorMode')}
              tooltip={t('inbounds.vlessEncXorModeTooltip')}
              style={{ marginBottom: 12 }}
            >
              <Select
                options={[
                  { value: 'native', label: t('inbounds.vlessEncXorNative') },
                  { value: 'xorpub', label: t('inbounds.vlessEncXorXorpub') },
                  { value: 'random', label: t('inbounds.vlessEncXorRandom') },
                ]}
              />
            </Form.Item>
            {/* align-items:flex-end keeps both inputs on one line even when a
                label wraps to two rows on a narrow (mobile) viewport. */}
            <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', alignItems: 'flex-end' }}>
              <Form.Item
                name="vless_encryption_seconds_from"
                label={t('inbounds.vlessEncSecondsFrom')}
                tooltip={t('inbounds.vlessEncSecondsTooltip')}
                style={{ marginBottom: 12, flex: 1, minWidth: 120 }}
              >
                <InputNumber min={1} style={{ width: '100%' }} />
              </Form.Item>
              <Form.Item
                name="vless_encryption_seconds_to"
                label={t('inbounds.vlessEncSecondsTo')}
                style={{ marginBottom: 12, flex: 1, minWidth: 120 }}
              >
                <InputNumber
                  min={0}
                  placeholder={t('inbounds.vlessEncSecondsToPlaceholder')}
                  style={{ width: '100%' }}
                />
              </Form.Item>
            </div>
            <Form.Item
              name="vless_encryption_padding"
              label={t('inbounds.vlessEncPadding')}
              tooltip={t('inbounds.vlessEncPaddingTooltip')}
              style={{ marginBottom: 0 }}
            >
              <Input placeholder={t('inbounds.vlessEncPaddingPlaceholder')} />
            </Form.Item>
          </Section>
        </>
      )}
    </Section>
  );
}
