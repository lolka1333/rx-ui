//! Sockopt tab — socket-level options (streamSettings.sockopt).
//! Inbound-level (applies regardless of protocol/transport). The
//! headline field is trustedXForwardedFor: xray-core #6159 warns when
//! it's unset on XHTTP/WS/HttpUpgrade inbounds (X-Forwarded-For is
//! otherwise trusted implicitly and spoofable). acceptProxyProtocol is
//! the other real-client-IP knob (PROXY-protocol header from a trusted
//! upstream LB). Keepalive, TFO, MPTCP and v6only are optional tuning.
//! All-empty here ⇒ backend emits no sockopt block.

import { Form, Select, InputNumber, Switch } from 'antd';
import { useTranslation } from 'react-i18next';

export function SockoptTab() {
  const { t } = useTranslation();
  return (
    <>
      <Form.Item
        name="sockopt_trusted_x_forwarded_for"
        label={t('inbounds.sockoptTrustedXff')}
        tooltip={t('inbounds.sockoptTrustedXffTooltip')}
        style={{ marginBottom: 12 }}
      >
        <Select
          mode="tags"
          tokenSeparators={[',', ' ']}
          placeholder={t('inbounds.sockoptTrustedXffPlaceholder')}
        />
      </Form.Item>
      <Form.Item
        name="sockopt_accept_proxy_protocol"
        label={t('inbounds.sockoptAcceptProxyProtocol')}
        tooltip={t('inbounds.sockoptAcceptProxyProtocolTooltip')}
        valuePropName="checked"
        style={{ marginBottom: 12 }}
      >
        <Switch />
      </Form.Item>
      <Form.Item
        name="sockopt_tcp_keep_alive_interval"
        label={t('inbounds.sockoptKeepAliveInterval')}
        tooltip={t('inbounds.sockoptKeepAliveIntervalTooltip')}
        style={{ marginBottom: 12 }}
      >
        <InputNumber min={0} style={{ width: '100%' }} placeholder="0" />
      </Form.Item>
      <Form.Item
        name="sockopt_tcp_keep_alive_idle"
        label={t('inbounds.sockoptKeepAliveIdle')}
        tooltip={t('inbounds.sockoptKeepAliveIdleTooltip')}
        style={{ marginBottom: 12 }}
      >
        <InputNumber min={0} style={{ width: '100%' }} placeholder="0" />
      </Form.Item>
      <Form.Item
        name="sockopt_tcp_fast_open"
        label={t('inbounds.sockoptTfo')}
        tooltip={t('inbounds.sockoptTfoTooltip')}
        style={{ marginBottom: 12 }}
      >
        <Select
          allowClear
          placeholder={t('inbounds.sockoptTfoDefault')}
          options={[
            { value: 256, label: t('inbounds.sockoptTfoEnabled') },
            { value: -1, label: t('inbounds.sockoptTfoDisabled') },
          ]}
        />
      </Form.Item>
      <Form.Item
        name="sockopt_tcp_mptcp"
        label={t('inbounds.sockoptMptcp')}
        tooltip={t('inbounds.sockoptMptcpTooltip')}
        valuePropName="checked"
        style={{ marginBottom: 12 }}
      >
        <Switch />
      </Form.Item>
      <Form.Item
        name="sockopt_v6only"
        label={t('inbounds.sockoptV6only')}
        tooltip={t('inbounds.sockoptV6onlyTooltip')}
        valuePropName="checked"
        style={{ marginBottom: 0 }}
      >
        <Switch />
      </Form.Item>
    </>
  );
}
