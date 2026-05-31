//! WebSocket transport tab. Path + Host on top, advanced block (custom
//! headers, PROXY-protocol acceptance, heartbeat) tucked under a
//! `Section` so the simple case stays one short scroll.

import { Form, Input, InputNumber } from 'antd';
import { useTranslation } from 'react-i18next';
import { HeaderListField, Section, SwitchField } from '../widgets';

export function WebSocketTab() {
  const { t } = useTranslation();
  return (
    <>
      <Form.Item
        name="ws_path"
        label={t('inbounds.wsPath')}
        tooltip={t('inbounds.wsPathTooltip')}
        style={{ marginBottom: 12 }}
      >
        <Input placeholder={t('inbounds.wsPathPlaceholder')} />
      </Form.Item>
      <Form.Item
        name="ws_host"
        label={t('inbounds.wsHost')}
        tooltip={t('inbounds.wsHostTooltip')}
        style={{ marginBottom: 12 }}
      >
        <Input placeholder={t('inbounds.wsHostPlaceholder')} />
      </Form.Item>
      <Section itemKey="ws-advanced" labelKey="inbounds.wsAdvanced">
        <Form.Item
          label={t('inbounds.wsHeaders')}
          tooltip={t('inbounds.wsHeadersHint')}
          style={{ marginBottom: 12 }}
        >
          <HeaderListField name="ws_headers" />
        </Form.Item>
        <SwitchField name="ws_accept_proxy_protocol" labelKey="inbounds.wsAcceptProxyProtocol" />
        <Form.Item
          name="ws_heartbeat_period"
          label={t('inbounds.wsHeartbeatPeriod')}
          tooltip={t('inbounds.wsHeartbeatPeriodTooltip')}
          style={{ marginBottom: 0 }}
        >
          <InputNumber min={0} max={3600} style={{ width: '100%' }} />
        </Form.Item>
      </Section>
    </>
  );
}
