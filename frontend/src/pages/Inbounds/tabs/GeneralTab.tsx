//! "Основное" tab — top-level inbound knobs: tag, port, listen address,
//! protocol family, transport, security, optional flow. The set of
//! valid (transport, security, flow) combos is driven entirely by the
//! protocol registry — there is no `if (protocol === 'hysteria')`
//! branching in here. Per-protocol UI (e.g. VLESS encryption block)
//! slots in via `def.MainTabExtras`.

import { Form, Input, InputNumber, Radio, Select, Switch } from 'antd';
import { useTranslation } from 'react-i18next';
import type { TransportConfig } from '@/api/types';
import { PROTOCOL_REGISTRY } from '../form/registry';
import type { FormNetwork, FormProtocol, FormSecurity, FormValues, ProtocolDef } from '../form/types';
import { ChipGroup, Section, SideBySide } from '../widgets';

export function GeneralTab() {
  const { t } = useTranslation();
  const form = Form.useFormInstance<FormValues>();
  const watchedProtocol = Form.useWatch('protocol_kind', form) as FormProtocol | undefined;
  const watchedNetwork = Form.useWatch('network', form) as FormNetwork | undefined;
  const watchedSecurity = Form.useWatch('security', form) as FormSecurity | undefined;
  const def = PROTOCOL_REGISTRY[watchedProtocol ?? 'vless'];
  const networkSelectable = def.allowedTransports.length > 1;
  const ProtocolMainExtras = def.MainTabExtras;
  // Transport-selector option set. The list is intentionally local so
  // each label can reach i18n; the registry filters by `value`.
  const networkOptions = [
    { value: 'tcp', label: t('inbounds.networkTcp') },
    {
      value: 'ws',
      label: (
        <span>
          {t('inbounds.networkWs')}
          <span style={{ opacity: 0.55, fontSize: 11, marginLeft: 6 }}>
            ({t('inbounds.networkWsLegacyBadge')})
          </span>
        </span>
      ),
    },
    { value: 'xhttp', label: t('inbounds.networkXhttp') },
  ];
  return (
    <>
      <SideBySide>
        <Form.Item
          name="tag"
          label={t('inbounds.tag')}
          style={{ flex: 1, marginBottom: 12 }}
          rules={[{ required: true, message: t('inbounds.tagRequired') }]}
        >
          <Input placeholder={t('inbounds.tagPlaceholder')} />
        </Form.Item>
        <Form.Item
          name="port"
          label={t('inbounds.portLabel')}
          style={{ width: 110, marginBottom: 12 }}
          rules={[{ required: true }]}
        >
          <InputNumber min={1} max={65535} style={{ width: '100%' }} />
        </Form.Item>
      </SideBySide>

      <Form.Item
        name="listen"
        label={t('inbounds.listenAddress')}
        style={{ marginBottom: 12 }}
      >
        <Input placeholder={t('inbounds.listenPlaceholder')} />
      </Form.Item>

      <Form.Item
        name="protocol_kind"
        label={t('inbounds.protocol')}
        style={{ marginBottom: 12 }}
        tooltip={!networkSelectable ? t('inbounds.protocolHysteriaHint') : undefined}
      >
        <Select
          options={(Object.entries(PROTOCOL_REGISTRY) as Array<[FormProtocol, ProtocolDef]>)
            .map(([value, d]) => ({ value, label: d.label }))}
        />
      </Form.Item>

      {/* columnGap-only flex: keep horizontal spacing for desktop where
          all three fit on one row, but rowGap=0 so when they wrap on a
          narrow viewport the only vertical spacing is each Form.Item's
          own marginBottom (12px) — matching all other Form.Items above
          and avoiding the doubled gap from flex row-gap stacking on
          marginBottom. */}
      <div style={{ display: 'flex', columnGap: 12, rowGap: 0, flexWrap: 'wrap' }}>
        {networkSelectable && (
          <Form.Item
            name="network"
            label={t('inbounds.network')}
            rules={[{ required: true }]}
            tooltip={
              watchedNetwork === 'ws'
                ? t('inbounds.networkWsDeprecatedTooltip')
                : undefined
            }
            style={{ marginBottom: 12, minWidth: 180 }}
          >
            <Select
              options={networkOptions.filter((o) =>
                def.allowedTransports.includes(o.value as TransportConfig['kind']),
              )}
            />
          </Form.Item>
        )}
        {/* Security selector — options disabled per registry. The parent's
            auto-reset snaps `security` to the protocol's default when the
            current value falls outside the allow-list; the disabled state
            here just stops the operator from re-introducing one. */}
        <Form.Item
          name="security"
          label={t('inbounds.security')}
          htmlFor="security-radio-first"
          tooltip={
            !def.allowedSecurities.includes('reality') && def.allowedSecurities.length === 1
              ? t('inbounds.securityTlsRequiredHysteriaHint')
              : watchedNetwork === 'ws'
                ? t('inbounds.securityNoRealityOnWs')
                : watchedSecurity === 'none'
                  ? t('inbounds.securityNoneHint')
                  : undefined
          }
          style={{ marginBottom: 12 }}
        >
          <Radio.Group optionType="button">
            <Radio.Button
              id="security-radio-first"
              value="none"
              disabled={!def.allowedSecurities.includes('none')}
            >
              {t('inbounds.securityNone')}
            </Radio.Button>
            <Radio.Button
              value="tls"
              disabled={!def.allowedSecurities.includes('tls')}
            >
              {t('inbounds.securityTls')}
            </Radio.Button>
            {/* Reality also requires RAW/XHTTP/gRPC (no WebSocket) per
                xray's `transport_internet.go:1989`. */}
            <Radio.Button
              value="reality"
              disabled={!def.allowedSecurities.includes('reality') || watchedNetwork === 'ws'}
            >
              {t('inbounds.securityReality')}
            </Radio.Button>
          </Radio.Group>
        </Form.Item>
        {def.hasFlow && (
          <Form.Item
            name="vless_flow"
            label={t('inbounds.flow')}
            htmlFor="vless-flow-radio-first"
            tooltip={
              watchedNetwork !== undefined && watchedNetwork !== 'tcp'
                ? t('inbounds.visionTcpOnly')
                : undefined
            }
            style={{ marginBottom: 12 }}
          >
            <Radio.Group optionType="button">
              <Radio.Button id="vless-flow-radio-first" value="none">
                {t('inbounds.flowNone')}
              </Radio.Button>
              <Radio.Button
                value="xtls-rprx-vision"
                disabled={watchedNetwork !== undefined && watchedNetwork !== 'tcp'}
              >
                {t('inbounds.flowVision')}
              </Radio.Button>
            </Radio.Group>
          </Form.Item>
        )}
      </div>

      {ProtocolMainExtras && <ProtocolMainExtras />}

      {/* Sniffing collapsed by default: enabled+protocols are usually set
          once at creation (the defaults http/tls/fakedns cover the vast
          majority of use cases), so hiding them behind one click keeps the
          main tab short. */}
      <Section itemKey="sniffing" labelKey="inbounds.sniffingSection">
        <Form.Item
          name="sniffing_enabled"
          label={t('inbounds.sniffingEnabled')}
          tooltip={t('inbounds.sniffingEnabledHint')}
          valuePropName="checked"
          style={{ marginBottom: 12 }}
        >
          <Switch />
        </Form.Item>
        <Form.Item
          name="sniffing_dest_override"
          label={t('inbounds.sniffingDestOverride')}
          style={{ marginBottom: 0 }}
        >
          <ChipGroup
            options={[
              { value: 'http', label: t('inbounds.sniffingDestHttp') },
              { value: 'tls', label: t('inbounds.sniffingDestTls') },
              { value: 'fakedns', label: t('inbounds.sniffingDestFakedns') },
              { value: 'quic', label: t('inbounds.sniffingDestQuic') },
            ]}
          />
        </Form.Item>
      </Section>
    </>
  );
}
