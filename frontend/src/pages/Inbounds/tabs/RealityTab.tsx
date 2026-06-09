//! Reality security tab. Destination + serverNames + shortIds + uTLS
//! fingerprint + xver, plus the x25519 public key.
//!
//! The keypair is body-carried: on a NEW inbound it's generated up front via
//! `POST /api/keygen/reality-keypair` and held in the form, so the operator
//! sees the public key immediately (the backend re-derives the public from the
//! private on save, so the pair can't drift). When editing, the stored key is
//! shown with a server-side "rotate" action instead (which also pushes the new
//! key into the running xray).

import {
  App,
  Button,
  Form,
  Input,
  InputNumber,
  Popconfirm,
  Select,
  Tooltip,
  Typography,
} from 'antd';
import { QuestionCircleOutlined, ReloadOutlined } from '@ant-design/icons';
import { useCallback, useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { apiClient } from '@/api/client';
import { apiErrorMessage } from '@/api/errors';
import type { Inbound } from '@/api/types';
import { FINGERPRINT_OPTIONS } from '../helpers';
import { SideBySide } from '../widgets';
import type { FormValues } from '../form/types';

interface RealityTabProps {
  editing: Inbound | null;
  onRotate: () => void;
  rotating: boolean;
}

export function RealityTab({ editing, onRotate, rotating }: RealityTabProps) {
  const { t } = useTranslation();
  const { message } = App.useApp();
  const form = Form.useFormInstance<FormValues>();
  // The public key lives in the form (single source of truth) so a fresh
  // keygen + setFieldsValue re-renders this display.
  const publicKey = (Form.useWatch('reality_public_key', form) ?? '') as string;
  const [generating, setGenerating] = useState(false);

  // Side-effect-free server keygen; the atomic private+public pair is held in
  // the form and round-trips on save (the backend re-derives the public from
  // the private so the stored pair can't drift). Writes land in antd's form
  // store rather than React state, so calling this from the mount effect below
  // doesn't trip react-hooks/set-state-in-effect.
  const fetchKeypair = useCallback(async () => {
    const { data } = await apiClient.post<{ private_key: string; public_key: string }>(
      '/keygen/reality-keypair',
    );
    form.setFieldsValue({
      reality_private_key: data.private_key,
      reality_public_key: data.public_key,
    });
  }, [form]);

  // Manual "regenerate" button. The spinner state is React state, but it's set
  // from a click handler (allowed) — not from an effect.
  const regenerate = useCallback(() => {
    setGenerating(true);
    fetchKeypair()
      .catch((err: unknown) =>
        message.error(apiErrorMessage(err) ?? t('inbounds.realityKeygenError')),
      )
      .finally(() => setGenerating(false));
  }, [fetchKeypair, message, t]);

  // Auto-generate on a fresh inbound so the public key shows straight away;
  // editing reuses the inbound's stored key. The ref keeps StrictMode's
  // double-invoked mount effect (dev) from firing a second keygen.
  const didInit = useRef(false);
  useEffect(() => {
    if (editing || didInit.current) return;
    if (!form.getFieldValue('reality_public_key')) {
      didInit.current = true;
      fetchKeypair().catch((err: unknown) =>
        message.error(apiErrorMessage(err) ?? t('inbounds.realityKeygenError')),
      );
    }
  }, [editing, form, fetchKeypair, message, t]);

  return (
    <>
      <Form.Item
        name="reality_dest"
        label={t('inbounds.realityDest')}
        tooltip={t('inbounds.realityDestTooltip')}
        rules={[{ required: true, message: t('inbounds.realityDestRequired') }]}
        style={{ marginBottom: 12 }}
      >
        <Input placeholder={t('inbounds.realityDestPlaceholder')} />
      </Form.Item>

      <Form.Item
        name="reality_server_names"
        label={t('inbounds.serverNames')}
        tooltip={t('inbounds.serverNamesTooltip')}
        rules={[
          {
            validator: (_, v) =>
              Array.isArray(v) && v.length > 0
                ? Promise.resolve()
                : Promise.reject(new Error(t('inbounds.serverNamesRequired'))),
          },
        ]}
        style={{ marginBottom: 12 }}
      >
        <Select
          mode="tags"
          tokenSeparators={[',', ' ']}
          placeholder={t('inbounds.serverNamesPlaceholder')}
        />
      </Form.Item>

      <Form.Item
        name="reality_short_ids"
        label={t('inbounds.shortIds')}
        tooltip={t('inbounds.shortIdsTooltip')}
        style={{ marginBottom: 12 }}
      >
        <Select
          mode="tags"
          tokenSeparators={[',', ' ']}
          placeholder={t('inbounds.shortIdsPlaceholder')}
        />
      </Form.Item>

      <SideBySide>
        <Form.Item
          name="reality_fingerprint"
          label={t('inbounds.fingerprint')}
          style={{ flex: 1, marginBottom: 12 }}
        >
          <Select options={FINGERPRINT_OPTIONS} />
        </Form.Item>
        <Form.Item
          name="reality_xver"
          label={<span style={{ whiteSpace: 'nowrap' }}>{t('inbounds.xver')}</span>}
          tooltip={t('inbounds.xverTooltip')}
          style={{ width: 130, marginBottom: 12 }}
        >
          <InputNumber min={0} max={2} style={{ width: '100%' }} />
        </Form.Item>
      </SideBySide>

      <Form.Item
        name="reality_spider_x"
        label={t('inbounds.realitySpiderX')}
        tooltip={t('inbounds.realitySpiderXTooltip')}
        style={{ marginBottom: 12 }}
      >
        <Input placeholder="/" />
      </Form.Item>

      {/* Hidden round-trip fields: the keypair travels in the form so a
          create carries it to the server (which re-derives the public). */}
      <Form.Item name="reality_private_key" noStyle hidden>
        <Input />
      </Form.Item>
      <Form.Item name="reality_public_key" noStyle hidden>
        <Input />
      </Form.Item>

      {/* Label row holds just the title + help; the (re)generate action lives
          inside the field as a suffix. */}
      <Form.Item style={{ marginBottom: 0 }}>
        <div
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: 6,
            marginBottom: 6,
            minHeight: 24,
          }}
        >
          <span style={{ fontWeight: 400 }}>{t('inbounds.publicKey')}</span>
          <Tooltip title={t('inbounds.publicKeyTooltip')}>
            <QuestionCircleOutlined style={{ opacity: 0.45, fontSize: 13, cursor: 'help' }} />
          </Tooltip>
        </div>
        {/* New inbound: generate a fresh local pair. Editing: rotate the stored
            key server-side (guarded by a confirm). */}
        <Input
          readOnly
          value={publicKey}
          placeholder={generating ? t('inbounds.realityGenerating') : undefined}
          style={{
            fontFamily: 'ui-monospace, "JetBrains Mono", Consolas, monospace',
            fontSize: 12,
          }}
          suffix={
            editing ? (
              <Popconfirm
                title={t('inbounds.rotateKeypairConfirm')}
                description={
                  <div style={{ maxWidth: 360 }}>{t('inbounds.rotateKeypairWarning')}</div>
                }
                okText={t('inbounds.rotateKeypairConfirmOk')}
                okType="danger"
                cancelText={t('common.cancel')}
                onConfirm={onRotate}
              >
                <Tooltip title={t('inbounds.rotateKeypair')}>
                  <Button
                    size="small"
                    type="text"
                    icon={<ReloadOutlined />}
                    loading={rotating}
                    style={{ marginInlineEnd: -4 }}
                  />
                </Tooltip>
              </Popconfirm>
            ) : (
              <Tooltip title={t('inbounds.realityRegenerate')}>
                <Button
                  size="small"
                  type="text"
                  icon={<ReloadOutlined />}
                  loading={generating}
                  onClick={regenerate}
                  style={{ marginInlineEnd: -4 }}
                />
              </Tooltip>
            )
          }
        />
        <Typography.Text type="secondary" style={{ fontSize: 11 }}>
          {t('inbounds.privateKeyHidden')}
        </Typography.Text>
      </Form.Item>
    </>
  );
}
