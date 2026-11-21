//! Port hopping fields (`hy_hop_*`), rendered inside the Hysteria inbound tab
//! and the Hysteria outbound form. The caller supplies the heading.
//!
//! `side="server"`: an inbound. Hopping never runs there — the core's server
//! refuses `udphop` — it reaches clients through the share link, and server
//! port hopping needs the host to redirect the range to the inbound's port,
//! so the redirect commands are shown ready to copy.

import { Alert, Form, Input, InputNumber, Select, Switch, Typography } from 'antd';
import { useTranslation } from 'react-i18next';
import { hopBlockedByMask, hopRedirectCommands, type HopFormFields } from '@/lib/udpHop';
import { SideBySide } from '@/pages/Inbounds/widgets';

export function PortHoppingFields({ side }: { side: 'server' | 'client' }) {
  const { t } = useTranslation();
  const form = Form.useFormInstance<
    HopFormFields & { port?: number | null; finalmask_kind?: string }
  >();
  // Under XICMP hopping cannot run (both own the socket): like the Fallbacks
  // tab on a non-TCP transport, only a warning is shown, and the save leaves
  // hopping out (`formToHop`). The values stay in the form store, so picking
  // another mask brings them back.
  const blocked = hopBlockedByMask(Form.useWatch('finalmask_kind', form) as string | undefined);
  const local = Form.useWatch('hy_hop_local', form) as boolean | undefined;
  const remote = Form.useWatch('hy_hop_remote', form) as HopFormFields['hy_hop_remote'] | undefined;
  const ports = (Form.useWatch('hy_hop_ports', form) as string | undefined) ?? '';
  const listenPort = Form.useWatch('port', form) as number | null | undefined;
  const remoteOn = remote !== undefined && remote !== 'off';
  const timed = Boolean(local) || remote === 'interval';
  const commands =
    side === 'server' && remoteOn ? hopRedirectCommands(ports, listenPort) : [];

  if (blocked) {
    return <Alert type="warning" showIcon title={t('hop.blockedByXicmp')} />;
  }

  return (
    <>
      {side === 'server' && (
        <Typography.Paragraph type="secondary" style={{ fontSize: 12, marginBottom: 12 }}>
          {t('hop.serverNote')}
        </Typography.Paragraph>
      )}
      <Form.Item
        name="hy_hop_local"
        label={t('hop.local')}
        tooltip={t('hop.localHint')}
        valuePropName="checked"
      >
        <Switch />
      </Form.Item>
      <Form.Item name="hy_hop_remote" label={t('hop.remote')} tooltip={t('hop.remoteHint')}>
        <Select
          options={[
            { value: 'off', label: t('hop.remoteOff') },
            { value: 'per_connection', label: t('hop.remotePerConnection') },
            { value: 'interval', label: t('hop.remoteInterval') },
          ]}
        />
      </Form.Item>
      {remoteOn && (
        <Form.Item
          name="hy_hop_ports"
          label={t('hop.ports')}
          tooltip={t(side === 'server' ? 'hop.portsHintServer' : 'hop.portsHintClient')}
          rules={[{ required: true, whitespace: true, message: t('hop.portsRequired') }]}
        >
          <Input placeholder="20000-30000" allowClear />
        </Form.Item>
      )}
      {commands.length > 0 && (
        <div style={{ marginTop: -8, marginBottom: 16 }}>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            {t('hop.redirectNote')}
          </Typography.Text>
          {commands.map((c) => (
            <Typography.Paragraph
              key={c}
              copyable
              code
              style={{ fontSize: 12, marginBottom: 4, marginTop: 4, wordBreak: 'break-all' }}
            >
              {c}
            </Typography.Paragraph>
          ))}
        </div>
      )}
      {timed && (
        <SideBySide>
          <Form.Item
            name="hy_hop_interval_min"
            label={t('hop.intervalMin')}
            tooltip={t('hop.intervalHint')}
            style={{ flex: 1 }}
          >
            <InputNumber min={5} placeholder="30" style={{ width: '100%' }} />
          </Form.Item>
          <Form.Item name="hy_hop_interval_max" label={t('hop.intervalMax')} style={{ flex: 1 }}>
            <InputNumber min={5} placeholder="30" style={{ width: '100%' }} />
          </Form.Item>
        </SideBySide>
      )}
    </>
  );
}
