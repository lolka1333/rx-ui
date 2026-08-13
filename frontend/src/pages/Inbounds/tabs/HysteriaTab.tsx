//! Hysteria 2 transport panel. Auth + UDP idle + masquerade selector
//! with per-kind sub-fields. The shared `QuicTuning` block lives at the
//! end (Hysteria's transport always uses QUIC, so it makes sense in
//! the same tab as the rest of Hysteria's knobs).

import { Form, Input, InputNumber, Select, Switch } from 'antd';
import { useTranslation } from 'react-i18next';
import { QuicTuning } from './QuicTuning';
import { SideBySide } from '../widgets';
import type { FormMasqueradeKind, FormValues } from '../form/types';

export function HysteriaTab() {
  const { t } = useTranslation();
  const form = Form.useFormInstance<FormValues>();
  const masqKind = Form.useWatch('hysteria_masq_kind', form) as FormMasqueradeKind | undefined;
  return (
    <>
      <Form.Item
        name="hysteria_auth"
        label={t('inbounds.hysteriaAuth')}
        tooltip={t('inbounds.hysteriaAuthHint')}
      >
        <Input placeholder={t('inbounds.hysteriaAuthPlaceholder')} allowClear />
      </Form.Item>

      <Form.Item
        name="hysteria_udp_idle_timeout"
        label={t('inbounds.hysteriaUdpIdle')}
        tooltip={t('inbounds.hysteriaUdpIdleHint')}
      >
        <InputNumber min={0} placeholder="60" />
      </Form.Item>

      <Form.Item
        name="hysteria_masq_kind"
        label={t('inbounds.hysteriaMasq')}
        tooltip={t('inbounds.hysteriaMasqHint')}
      >
        <Select
          options={[
            { value: 'notfound', label: t('inbounds.hysteriaMasqNotFound') },
            { value: 'file', label: t('inbounds.hysteriaMasqFile') },
            { value: 'proxy', label: t('inbounds.hysteriaMasqProxy') },
            { value: 'string', label: t('inbounds.hysteriaMasqString') },
          ]}
        />
      </Form.Item>

      {masqKind === 'file' && (
        <Form.Item
          name="hysteria_masq_file_root"
          label={t('inbounds.hysteriaMasqFileRoot')}
          tooltip={t('inbounds.hysteriaMasqFileRootHint')}
          rules={[{ required: true, message: t('inbounds.hysteriaMasqFileRootRequired') }]}
        >
          <Input placeholder="/var/www/decoy" />
        </Form.Item>
      )}

      {masqKind === 'proxy' && (
        <>
          <Form.Item
            name="hysteria_masq_proxy_url"
            label={t('inbounds.hysteriaMasqProxyUrl')}
            tooltip={t('inbounds.hysteriaMasqProxyUrlHint')}
            rules={[{ required: true, message: t('inbounds.hysteriaMasqProxyUrlRequired') }]}
          >
            <Input placeholder="https://example.com" />
          </Form.Item>
          <SideBySide>
            <Form.Item
              name="hysteria_masq_proxy_rewrite_host"
              label={t('inbounds.hysteriaMasqProxyRewriteHost')}
              valuePropName="checked"
              style={{ flex: 1 }}
            >
              <Switch />
            </Form.Item>
            <Form.Item
              name="hysteria_masq_proxy_insecure"
              label={t('inbounds.hysteriaMasqProxyInsecure')}
              valuePropName="checked"
              style={{ flex: 1 }}
            >
              <Switch />
            </Form.Item>
          </SideBySide>
        </>
      )}

      {masqKind === 'string' && (
        <>
          <Form.Item
            name="hysteria_masq_string_content"
            label={t('inbounds.hysteriaMasqStringContent')}
          >
            <Input.TextArea rows={4} placeholder="<html>...</html>" />
          </Form.Item>
          <Form.Item
            name="hysteria_masq_string_status_code"
            label={t('inbounds.hysteriaMasqStringStatus')}
            style={{ marginBottom: 12, maxWidth: 200 }}
          >
            <InputNumber min={100} max={599} />
          </Form.Item>
        </>
      )}

      <QuicTuning />
    </>
  );
}
