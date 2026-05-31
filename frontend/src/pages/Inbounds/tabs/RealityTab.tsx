//! Reality security tab. Destination + serverNames + shortIds + uTLS
//! fingerprint + xver, plus a public-key display with a "rotate" action
//! when editing (server-side regenerates the x25519 keypair).

import { Button, Form, Input, InputNumber, Popconfirm, Select, Tooltip, Typography } from 'antd';
import { QuestionCircleOutlined, ReloadOutlined } from '@ant-design/icons';
import { useTranslation } from 'react-i18next';
import type { Inbound } from '@/api/types';
import { realityPublicKey, FINGERPRINT_OPTIONS } from '../helpers';
import { SideBySide } from '../widgets';

interface RealityTabProps {
  editing: Inbound | null;
  onRotate: () => void;
  rotating: boolean;
}

export function RealityTab({ editing, onRotate, rotating }: RealityTabProps) {
  const { t } = useTranslation();
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

      {editing && (
        // Skip Antd's label prop entirely — the parent `<label>` element
        // it renders is inline-width and won't stretch our flex-spacer.
        // Render the label row ourselves as a normal block-level flex
        // so `justify-content: space-between` actually pushes the
        // rotate button to the right edge.
        <Form.Item style={{ marginBottom: 0 }}>
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              marginBottom: 6,
              minHeight: 24,
            }}
          >
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
              <span style={{ fontWeight: 400 }}>{t('inbounds.publicKey')}</span>
              <Tooltip title={t('inbounds.publicKeyTooltip')}>
                <QuestionCircleOutlined
                  style={{ opacity: 0.45, fontSize: 13, cursor: 'help' }}
                />
              </Tooltip>
            </span>
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
                />
              </Tooltip>
            </Popconfirm>
          </div>
          <Input.TextArea
            readOnly
            value={realityPublicKey(editing)}
            autoSize
            style={{
              fontFamily: 'ui-monospace, "JetBrains Mono", Consolas, monospace',
              fontSize: 12,
            }}
          />
          <Typography.Text type="secondary" style={{ fontSize: 11 }}>
            {t('inbounds.privateKeyHidden')}
          </Typography.Text>
        </Form.Item>
      )}
    </>
  );
}
