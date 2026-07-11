//! XHTTP transport tab — three operator-essential knobs (path / host /
//! mode) on top, the ~28 advanced splithttp.Config fields tucked into a
//! collapsed `Section` so they don't bury the basics. XHTTP+H3 also
//! renders the shared `QuicTuning` panel since both use
//! `StreamConfig.quic_params` under the hood.

import { Collapse, Form, Input, InputNumber, Select, Typography } from 'antd';
import { useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import {
  AutoCompleteField,
  HeaderListField,
  InputField,
  NumberField,
  RangeField,
  Section,
  SelectField,
  SwitchField,
} from '../widgets';
import { QuicTuning } from './QuicTuning';

const XHTTP_MODE_OPTIONS = [
  { value: 'auto', labelKey: 'inbounds.xhttpModeAuto' },
  { value: 'packet-up', labelKey: 'inbounds.xhttpModePacketUp' },
  { value: 'stream-up', labelKey: 'inbounds.xhttpModeStreamUp' },
  { value: 'stream-one', labelKey: 'inbounds.xhttpModeStreamOne' },
] as const;

// Predefined session-ID alphabets xray ships (infra/conf splithttp). The
// operator can also type a custom ASCII set, so this drives an AutoComplete
// (preset suggestions + free input), not a plain Select.
const SESSION_ID_TABLE_OPTIONS = [
  'ALPHABET',
  'Alphabet',
  'BASE36',
  'Base62',
  'HEX',
  'alphabet',
  'base36',
  'hex',
  'number',
].map((value) => ({ value }));

// The four placement sets are NOT interchangeable — they're separate by
// design in xray-core. Source of truth:
// https://github.com/XTLS/Xray-core/blob/main/infra/conf/transport_internet.go
//
//   x_padding_placement     → cookie | header | query | queryInHeader
//   session_placement       → path | cookie | header | query
//   seq_placement           → path | cookie | header | query
//   uplink_data_placement   → auto | body | cookie | header
//                             (cookie / header valid in packet-up only)
//   uplink_http_method      → POST | GET (GET valid in packet-up only)
const PADDING_PLACEMENT_VALUES = ['cookie', 'header', 'query', 'queryInHeader'];
// xray-core's x-padding obfs method whitelist — see
// transport/internet/splithttp/xpadding.go (GeneratePadding switch).
const PADDING_METHOD_VALUES = ['repeat-x', 'tokenish'];
const SESSION_PLACEMENT_VALUES = ['path', 'cookie', 'header', 'query'];
const UPLINK_DATA_PLACEMENT_VALUES = ['auto', 'body', 'cookie', 'header'];
const HTTP_METHOD_VALUES = ['POST', 'GET'];

export function XhttpTab() {
  const { t } = useTranslation();
  return (
    <>
      <Form.Item
        name="xhttp_path"
        label={t('inbounds.xhttpPath')}
        tooltip={t('inbounds.xhttpPathTip')}
        style={{ marginBottom: 12 }}
      >
        <Input placeholder={t('inbounds.xhttpPathPlaceholder')} />
      </Form.Item>
      <Form.Item
        name="xhttp_host"
        label={t('inbounds.xhttpHost')}
        tooltip={t('inbounds.xhttpHostTip')}
        style={{ marginBottom: 12 }}
      >
        <Input placeholder={t('inbounds.xhttpHostPlaceholder')} />
      </Form.Item>
      <Form.Item
        name="xhttp_mode"
        label={t('inbounds.xhttpMode')}
        tooltip={t('inbounds.xhttpModeTip')}
        style={{ marginBottom: 12 }}
      >
        <Select
          options={XHTTP_MODE_OPTIONS.map((o) => ({ value: o.value, label: t(o.labelKey) }))}
        />
      </Form.Item>

      {/* Advanced XHTTP — collapsed by default; without this the 28 fields
          would dominate the panel and bury the three knobs (path/host/mode)
          the operator actually opens this tab for. */}
      <Section itemKey="xhttp-advanced" labelKey="inbounds.xhttpAdvanced">
        <XhttpAdvanced />
      </Section>
      {/* XHTTP+H3 reads the same StreamConfig.quic_params slot as
          Hysteria. Render the shared panel so operators can tune QUIC
          when ALPN=["h3"] is in play (xray ignores it for TCP/H2 mode). */}
      <QuicTuning />
    </>
  );
}

// =============================================================================
// XHTTP advanced fields — wrapped into 7 nested accordion panels, all
// collapsed by default. Without this nesting the parent Advanced collapse
// would dump ~28 form rows on the page at once and bury the basic
// path/host/mode knobs above. Each subsection groups a related slice of
// splithttp.Config and can be expanded independently; React Query / Form
// preserve values across collapse toggles, so opening one panel doesn't
// reset siblings or lose unsaved input. All fields are optional from
// xray's perspective — empty/null means "use xray default."
// =============================================================================

function XhttpAdvanced() {
  const { t } = useTranslation();
  // uplinkHTTPMethod=GET and cookie/header uplink-data placement are packet-up
  // only (xray rejects them in any other mode — see infra/conf splithttp). Grey
  // those knobs out unless the mode is packet-up so the operator can't build an
  // invalid combo, and the adapter drops them from the payload for good measure.
  const form = Form.useFormInstance();
  const uplinkPacketUpOnly = Form.useWatch('xhttp_mode', form) !== 'packet-up';
  // The "По умолчанию" entry uses value="" so the backend sees null
  // (orNull strips empties before sending) and xray falls back to its
  // own default for that field. Translated label is the only dynamic
  // bit, so we build the option arrays via useMemo on `t`.
  const opts = useMemo(() => {
    const def = { value: '', label: t('inbounds.xhttpPlacementDefault') };
    const wrap = (values: readonly string[]) => [
      def,
      ...values.map((v) => ({ value: v, label: v })),
    ];
    return {
      paddingPlacement: wrap(PADDING_PLACEMENT_VALUES),
      paddingMethod: wrap(PADDING_METHOD_VALUES),
      sessionPlacement: wrap(SESSION_PLACEMENT_VALUES),
      uplinkDataPlacement: wrap(UPLINK_DATA_PLACEMENT_VALUES),
      httpMethod: wrap(HTTP_METHOD_VALUES),
    };
  }, [t]);
  return (
    <Collapse
      ghost
      size="small"
      items={[
        {
          key: 'headers',
          label: t('inbounds.xhttpHeaders'),
          children: (
            <>
              <Typography.Paragraph
                type="secondary"
                style={{ marginTop: 0, marginBottom: 8, fontSize: 12 }}
              >
                {t('inbounds.xhttpHeadersHint')}
              </Typography.Paragraph>
              <HeaderListField name="xhttp_headers" />
            </>
          ),
        },
        {
          key: 'wire',
          label: t('inbounds.xhttpWireSection'),
          children: (
            <>
              <RangeField
                name="xhttp_x_padding_bytes"
                labelKey="inbounds.xhttpXPaddingBytes"
                tooltipKey="inbounds.xhttpXPaddingBytesHint"
              />
              {/* columnGap-only flex: on desktop both switches sit on one
                  row with 24px between them; on mobile they wrap and the
                  first switch's own marginBottom (12px via no-last)
                  provides the vertical gap — flex rowGap stays 0 so the
                  spacing doesn't double-stack. */}
              <div style={{ display: 'flex', columnGap: 24, rowGap: 0, flexWrap: 'wrap' }}>
                <SwitchField
                  name="xhttp_no_grpc_header"
                  labelKey="inbounds.xhttpNoGrpcHeader"
                  tooltipKey="inbounds.xhttpNoGrpcHeaderTip"
                />
                <SwitchField
                  name="xhttp_no_sse_header"
                  labelKey="inbounds.xhttpNoSseHeader"
                  tooltipKey="inbounds.xhttpNoSseHeaderTip"
                  last
                />
              </div>
            </>
          ),
        },
        {
          key: 'sc',
          label: t('inbounds.xhttpScSection'),
          children: (
            <>
              <RangeField
                name="xhttp_sc_max_each_post_bytes"
                labelKey="inbounds.xhttpScMaxEachPostBytes"
                tooltipKey="inbounds.xhttpScMaxEachPostBytesHint"
              />
              <RangeField
                name="xhttp_sc_min_posts_interval_ms"
                labelKey="inbounds.xhttpScMinPostsIntervalMs"
                tooltipKey="inbounds.xhttpScMinPostsIntervalMsHint"
              />
              <Form.Item
                name="xhttp_sc_max_buffered_posts"
                label={t('inbounds.xhttpScMaxBufferedPosts')}
                tooltip={t('inbounds.xhttpScMaxBufferedPostsHint')}
                style={{ marginBottom: 12 }}
              >
                <InputNumber min={0} style={{ width: '100%' }} />
              </Form.Item>
              <RangeField
                name="xhttp_sc_stream_up_server_secs"
                labelKey="inbounds.xhttpScStreamUpServerSecs"
                tooltipKey="inbounds.xhttpScStreamUpServerSecsHint"
                last
              />
            </>
          ),
        },
        {
          key: 'xmux',
          label: t('inbounds.xhttpXmuxSection'),
          children: (
            <>
              <RangeField
                name="xhttp_xmux_max_concurrency"
                labelKey="inbounds.xhttpXmuxMaxConcurrency"
                tooltipKey="inbounds.xhttpXmuxMaxConcurrencyTip"
              />
              <RangeField
                name="xhttp_xmux_max_connections"
                labelKey="inbounds.xhttpXmuxMaxConnections"
                tooltipKey="inbounds.xhttpXmuxMaxConnectionsTip"
              />
              <RangeField
                name="xhttp_xmux_c_max_reuse_times"
                labelKey="inbounds.xhttpXmuxCMaxReuseTimes"
                tooltipKey="inbounds.xhttpXmuxCMaxReuseTimesTip"
              />
              <RangeField
                name="xhttp_xmux_h_max_request_times"
                labelKey="inbounds.xhttpXmuxHMaxRequestTimes"
                tooltipKey="inbounds.xhttpXmuxHMaxRequestTimesTip"
              />
              <RangeField
                name="xhttp_xmux_h_max_reusable_secs"
                labelKey="inbounds.xhttpXmuxHMaxReusableSecs"
                tooltipKey="inbounds.xhttpXmuxHMaxReusableSecsTip"
              />
              <NumberField
                name="xhttp_xmux_h_keep_alive_period"
                labelKey="inbounds.xhttpXmuxHKeepAlivePeriod"
                tooltipKey="inbounds.xhttpXmuxHKeepAlivePeriodTip"
                last
              />
            </>
          ),
        },
        {
          key: 'padding-obfs',
          label: t('inbounds.xhttpPaddingObfsSection'),
          children: (
            <>
              <SwitchField
                name="xhttp_x_padding_obfs_mode"
                labelKey="inbounds.xhttpXPaddingObfsMode"
                tooltipKey="inbounds.xhttpXPaddingObfsModeTip"
              />
              <InputField
                name="xhttp_x_padding_key"
                labelKey="inbounds.xhttpXPaddingKey"
                tooltipKey="inbounds.xhttpXPaddingKeyTip"
              />
              <InputField
                name="xhttp_x_padding_header"
                labelKey="inbounds.xhttpXPaddingHeader"
                tooltipKey="inbounds.xhttpXPaddingHeaderTip"
              />
              <SelectField
                name="xhttp_x_padding_placement"
                labelKey="inbounds.xhttpXPaddingPlacement"
                tooltipKey="inbounds.xhttpXPaddingPlacementTip"
                options={opts.paddingPlacement}
              />
              <SelectField
                name="xhttp_x_padding_method"
                labelKey="inbounds.xhttpXPaddingMethod"
                tooltipKey="inbounds.xhttpXPaddingMethodTip"
                options={opts.paddingMethod}
                last
              />
            </>
          ),
        },
        {
          key: 'session',
          label: t('inbounds.xhttpSessionSection'),
          children: (
            <>
              <SelectField
                name="xhttp_uplink_http_method"
                labelKey="inbounds.xhttpUplinkHttpMethod"
                tooltipKey="inbounds.xhttpUplinkHttpMethodTip"
                options={opts.httpMethod}
                disabled={uplinkPacketUpOnly}
              />
              <SelectField
                name="xhttp_session_placement"
                labelKey="inbounds.xhttpSessionPlacement"
                tooltipKey="inbounds.xhttpSessionPlacementTip"
                options={opts.sessionPlacement}
              />
              <InputField
                name="xhttp_session_key"
                labelKey="inbounds.xhttpSessionKey"
                tooltipKey="inbounds.xhttpSessionKeyTip"
              />
              <SelectField
                name="xhttp_seq_placement"
                labelKey="inbounds.xhttpSeqPlacement"
                tooltipKey="inbounds.xhttpSeqPlacementTip"
                options={opts.sessionPlacement}
              />
              <InputField
                name="xhttp_seq_key"
                labelKey="inbounds.xhttpSeqKey"
                tooltipKey="inbounds.xhttpSeqKeyTip"
              />
              <AutoCompleteField
                name="xhttp_session_id_table"
                labelKey="inbounds.xhttpSessionIdTable"
                tooltipKey="inbounds.xhttpSessionIdTableTip"
                options={SESSION_ID_TABLE_OPTIONS}
              />
              <InputField
                name="xhttp_session_id_length"
                labelKey="inbounds.xhttpSessionIdLength"
                tooltipKey="inbounds.xhttpSessionIdLengthTip"
                last
              />
            </>
          ),
        },
        {
          key: 'uplink',
          label: t('inbounds.xhttpUplinkSection'),
          children: (
            <>
              <SelectField
                name="xhttp_uplink_data_placement"
                labelKey="inbounds.xhttpUplinkDataPlacement"
                tooltipKey="inbounds.xhttpUplinkDataPlacementTip"
                options={opts.uplinkDataPlacement}
                disabled={uplinkPacketUpOnly}
              />
              <InputField
                name="xhttp_uplink_data_key"
                labelKey="inbounds.xhttpUplinkDataKey"
                tooltipKey="inbounds.xhttpUplinkDataKeyTip"
                disabled={uplinkPacketUpOnly}
              />
              <RangeField
                name="xhttp_uplink_chunk_size"
                labelKey="inbounds.xhttpUplinkChunkSize"
                tooltipKey="inbounds.xhttpUplinkChunkSizeTip"
              />
              <NumberField
                name="xhttp_server_max_header_bytes"
                labelKey="inbounds.xhttpServerMaxHeaderBytes"
                tooltipKey="inbounds.xhttpServerMaxHeaderBytesTip"
                last
              />
            </>
          ),
        },
      ]}
    />
  );
}
