//! Shared QUIC-tuning panel. Used by both Hysteria 2 and XHTTP+H3 —
//! the form fields (`quic_*`) live at the top level of FormValues, so
//! the same widget renders in either parent. `buildQuicParams` collects
//! them on submit and the right transport variant gets the proto.

import { useMemo } from 'react';
import { Form, InputNumber, Select, Switch } from 'antd';
import { useTranslation } from 'react-i18next';
import { bbrProfileSelectOptions, MIN_RECEIVE_WINDOW, receiveWindowRule } from '@/lib/quic';
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

/** `hysteria`: the inbound's share link carries the client half of this
 *  tuning (keepalive, windows, the Chrome switch) in `fm.quicParams`, so the
 *  hints say so and the client-only switch is shown. XHTTP links carry none. */
export function QuicTuning({ hysteria = false }: { hysteria?: boolean }) {
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
  const bbrProfileOptions = useMemo(() => bbrProfileSelectOptions(t), [t]);
  // The four windows share the floor: shown in the empty field, and flagged
  // under it while a smaller value is typed.
  const windowField = useMemo(
    () => ({
      unit: t('inbounds.unitBytes'),
      placeholder: t('inbounds.quicWindowPlaceholder', { min: MIN_RECEIVE_WINDOW }),
      rules: [receiveWindowRule(t('inbounds.quicWindowMin', { min: MIN_RECEIVE_WINDOW }))],
    }),
    [t],
  );
  return (
    <Section itemKey="quic" labelKey="inbounds.quicSection">
      <Form.Item
        name="quic_congestion"
        label={t('inbounds.quicCongestion')}
        tooltip={t('inbounds.quicCongestionHint')}
      >
        <Select options={congestionOptions} />
      </Form.Item>

      {brutalActive && (
        <>
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
          <Form.Item
            name="quic_brutal_disable_loss_compensation"
            label={t('inbounds.quicBrutalNoLossComp')}
            tooltip={t('inbounds.quicBrutalNoLossCompHint')}
            valuePropName="checked"
          >
            <Switch />
          </Form.Item>
        </>
      )}

      {congestion === 'bbr' && (
        <Form.Item
          name="quic_bbr_profile"
          label={t('inbounds.quicBbrProfile')}
          tooltip={t('inbounds.quicBbrProfileHint')}
        >
          <Select options={bbrProfileOptions} />
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
          tooltipKey={hysteria ? 'inbounds.quicKeepAliveHintHy' : 'inbounds.quicKeepAliveHint'}
          placeholder="10"
          unit={t('inbounds.unitSec')}
        />
      </SideBySide>

      <SideBySide>
        <NumberUnitField
          name="quic_init_stream_receive_window"
          labelKey="inbounds.quicInitStreamWindow"
          tooltipKey={hysteria ? 'inbounds.quicWindowHintHy' : 'inbounds.quicWindowHint'}
          {...windowField}
        />
        <NumberUnitField
          name="quic_max_stream_receive_window"
          labelKey="inbounds.quicMaxStreamWindow"
          {...windowField}
        />
      </SideBySide>
      <SideBySide>
        <NumberUnitField
          name="quic_init_conn_receive_window"
          labelKey="inbounds.quicInitConnWindow"
          {...windowField}
        />
        <NumberUnitField
          name="quic_max_conn_receive_window"
          labelKey="inbounds.quicMaxConnWindow"
          {...windowField}
        />
      </SideBySide>

      <Form.Item
        name="quic_max_incoming_streams"
        label={t('inbounds.quicMaxIncomingStreams')}
        tooltip={t('inbounds.quicMaxIncomingStreamsHint')}
      >
        <InputNumber min={0} />
      </Form.Item>

      <Form.Item
        name="quic_disable_path_mtu_discovery"
        label={t('inbounds.quicDisablePathMtu')}
        tooltip={t('inbounds.quicDisablePathMtuHint')}
        valuePropName="checked"
      >
        <Switch />
      </Form.Item>

      <Form.Item
        name="quic_disable_gso"
        label={t('inbounds.quicDisableGso')}
        tooltip={t('inbounds.quicDisableGsoHint')}
        valuePropName="checked"
      >
        <Switch />
      </Form.Item>

      <Form.Item
        name="quic_disable_stateless_reset"
        label={t('inbounds.quicDisableStatelessReset')}
        tooltip={t('inbounds.quicDisableStatelessResetHint')}
        valuePropName="checked"
        style={hysteria ? undefined : { marginBottom: 0 }}
      >
        <Switch />
      </Form.Item>

      {hysteria && (
        <Form.Item
          name="quic_disable_chrome_parrot"
          label={t('inbounds.quicDisableChromeParrot')}
          tooltip={t('inbounds.quicDisableChromeParrotHint')}
          valuePropName="checked"
          style={{ marginBottom: 0 }}
        >
          <Switch />
        </Form.Item>
      )}
    </Section>
  );
}
