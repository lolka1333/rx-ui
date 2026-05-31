//! Shared QUIC-tuning panel. Used by both Hysteria 2 and XHTTP+H3 —
//! the form fields (`quic_*`) live at the top level of FormValues, so
//! the same widget renders in either parent. `buildQuicParams` collects
//! them on submit and the right transport variant gets the proto.

import { useMemo } from 'react';
import { Form, Input, InputNumber, Select, Switch } from 'antd';
import { useTranslation } from 'react-i18next';
import { NumberUnitField, Section, SideBySide } from '../widgets';
import type { FormCongestion, FormValues } from '../form/types';

/** Congestion modes paired with their display label. `default` resolves
 *  through i18n; the rest are protocol-canonical strings. */
const CONGESTION_MODES: { value: FormCongestion; label: string | null }[] = [
  { value: 'default', label: null },
  { value: 'bbr', label: 'BBR' },
  { value: 'brutal', label: 'Brutal' },
  { value: 'force-brutal', label: 'Force Brutal' },
  { value: 'reno', label: 'Reno' },
];

export function QuicTuning() {
  const { t } = useTranslation();
  const form = Form.useFormInstance<FormValues>();
  const congestion = Form.useWatch('quic_congestion', form) as FormCongestion | undefined;
  const brutalActive = congestion === 'brutal' || congestion === 'force-brutal';
  const congestionOptions = useMemo(
    () =>
      CONGESTION_MODES.map(({ value, label }) => ({
        value,
        label: label ?? t('inbounds.quicCongestionDefault'),
      })),
    [t],
  );
  return (
    <Section itemKey="quic" labelKey="inbounds.quicSection">
      <Form.Item
        name="quic_congestion"
        label={t('inbounds.quicCongestion')}
        tooltip={t('inbounds.quicCongestionHint')}
        style={{ marginBottom: 12 }}
      >
        <Select options={congestionOptions} />
      </Form.Item>

      {brutalActive && (
        <SideBySide>
          <NumberUnitField
            name="quic_brutal_up_mbps"
            labelKey="inbounds.quicBrutalUp"
            tooltipKey="inbounds.quicBrutalHint"
            placeholder="100"
            min={1}
            unit={t('inbounds.unitMbps')}
          />
          <NumberUnitField
            name="quic_brutal_down_mbps"
            labelKey="inbounds.quicBrutalDown"
            placeholder="100"
            min={1}
            unit={t('inbounds.unitMbps')}
          />
        </SideBySide>
      )}

      {congestion === 'bbr' && (
        <Form.Item
          name="quic_bbr_profile"
          label={t('inbounds.quicBbrProfile')}
          tooltip={t('inbounds.quicBbrProfileHint')}
          style={{ marginBottom: 12 }}
        >
          <Input placeholder="standard" allowClear />
        </Form.Item>
      )}

      <SideBySide>
        <NumberUnitField
          name="quic_max_idle_timeout_secs"
          labelKey="inbounds.quicMaxIdle"
          tooltipKey="inbounds.quicMaxIdleHint"
          placeholder="30"
          unit={t('inbounds.unitSec')}
        />
        <NumberUnitField
          name="quic_keep_alive_period_secs"
          labelKey="inbounds.quicKeepAlive"
          tooltipKey="inbounds.quicKeepAliveHint"
          placeholder="10"
          unit={t('inbounds.unitSec')}
        />
      </SideBySide>

      <Form.Item
        name="quic_udp_hop_ports"
        label={t('inbounds.quicUdpHopPorts')}
        tooltip={t('inbounds.quicUdpHopPortsHint')}
        style={{ marginBottom: 12 }}
      >
        <Select mode="tags" tokenSeparators={[',', ' ']} placeholder="20000, 20001, 20002" />
      </Form.Item>
      <SideBySide>
        <NumberUnitField
          name="quic_udp_hop_interval_min"
          labelKey="inbounds.quicUdpHopIntervalMin"
          placeholder="30"
          unit={t('inbounds.unitSec')}
        />
        <NumberUnitField
          name="quic_udp_hop_interval_max"
          labelKey="inbounds.quicUdpHopIntervalMax"
          placeholder="60"
          unit={t('inbounds.unitSec')}
        />
      </SideBySide>

      <SideBySide>
        <NumberUnitField
          name="quic_init_stream_receive_window"
          labelKey="inbounds.quicInitStreamWindow"
          tooltipKey="inbounds.quicWindowHint"
          unit={t('inbounds.unitBytes')}
        />
        <NumberUnitField
          name="quic_max_stream_receive_window"
          labelKey="inbounds.quicMaxStreamWindow"
          unit={t('inbounds.unitBytes')}
        />
      </SideBySide>
      <SideBySide>
        <NumberUnitField
          name="quic_init_conn_receive_window"
          labelKey="inbounds.quicInitConnWindow"
          unit={t('inbounds.unitBytes')}
        />
        <NumberUnitField
          name="quic_max_conn_receive_window"
          labelKey="inbounds.quicMaxConnWindow"
          unit={t('inbounds.unitBytes')}
        />
      </SideBySide>

      <Form.Item
        name="quic_max_incoming_streams"
        label={t('inbounds.quicMaxIncomingStreams')}
        tooltip={t('inbounds.quicMaxIncomingStreamsHint')}
        style={{ marginBottom: 12 }}
      >
        <InputNumber min={0} style={{ width: '100%' }} />
      </Form.Item>

      <Form.Item
        name="quic_disable_path_mtu_discovery"
        label={t('inbounds.quicDisablePathMtu')}
        tooltip={t('inbounds.quicDisablePathMtuHint')}
        valuePropName="checked"
        style={{ marginBottom: 0 }}
      >
        <Switch />
      </Form.Item>
    </Section>
  );
}
