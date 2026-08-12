//! FinalMask tab — wire-level last-stage obfuscation that wraps socket
//! bytes after TLS / Reality completes. v2 covers three variants:
//!   * `sudoku`   — TCP + UDP, password-protected lookup + ASCII
//!                  entropy + variable padding
//!   * `fragment` — TCP-only, random-sized chunks with delays
//!   * `noise`    — UDP-only, prepended random bytes per datagram
//!
//! **Symmetric configuration is mandatory.** The variants do a stateful
//! handshake — mismatch → the connection is dropped server-side. The
//! share-link's `fm=` parameter (added in xray-core v26.3.27) ships
//! the same settings to v2rayN / Hiddify / sing-box so subscriptions
//! bootstrap clients automatically; old client builds that don't
//! understand `fm=` will fail to connect — that's intentional.

import { useEffect, useMemo, useState } from 'react';
import { App, Alert, Button, Form, Input, InputNumber, Select, Typography } from 'antd';
import type { FormListFieldData } from 'antd';
import { DeleteOutlined, PlusOutlined } from '@ant-design/icons';
import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { apiClient } from '@/api/client';
import { apiErrorMessage } from '@/api/errors';
import type { FinalMask, XmcProfile } from '@/api/types';
import { InputField, RangePair, Section, SelectField, SideBySide } from '../widgets';
import type { FormValues, SudokuAscii } from '../form/types';

/** Sudoku padding is `uint32` on the proto but xray rejects values above
 *  255 — same range the upstream docs document. */
const SUDOKU_PADDING_MAX = 255;

/** xray encrypts `verifyToken + password` under a 1024-bit RSA key with
 *  PKCS#1 v1.5 padding: 128 bytes of block, 11 of padding, 4 of token. */
const XMC_PASSWORD_MAX_BYTES = 113;

/** Variant catalogue rendered into the kind-selector. Each maps to a
 *  translated label so the dropdown stays localised; the transport-scope
 *  hint (TCP / UDP) is part of the label so the operator picks the right
 *  variant for their inbound at a glance. */
const VARIANT_LABEL_KEYS: Record<FinalMask['kind'], string> = {
  none: 'inbounds.finalmaskKindNone',
  sudoku: 'inbounds.finalmaskKindSudoku',
  fragment: 'inbounds.finalmaskKindFragment',
  noise: 'inbounds.finalmaskKindNoise',
  salamander: 'inbounds.finalmaskKindSalamander',
  xmc: 'inbounds.finalmaskKindXmc',
};

/** Which masks xray will actually run, keyed transport → security → kinds.
 *
 *  Fetched rather than hardcoded. xray keeps two mask registries and each
 *  transport consults exactly one of them, so a mask offered on the wrong side
 *  is not an error — it builds, the inbound starts, and nothing ever calls it.
 *  The backend already refuses those combinations; asking it what it allows is
 *  how the dropdown and the validator stay the same rule instead of two copies
 *  that drift. */
type SupportMatrix = Record<string, Record<string, FinalMask['kind'][]>>;

function useFinalMaskSupport() {
  return useQuery<SupportMatrix>({
    queryKey: ['finalmask-support'],
    queryFn: async () =>
      (await apiClient.get<SupportMatrix>('/inbounds/finalmask-support')).data,
    // Derived from the xray build, not from anything the operator can change
    // while the form is open.
    staleTime: Infinity,
  });
}

/** Operator-selectable ASCII modes for Sudoku. `''` (empty) means
 *  "use xray's default" and is the form's resting state. */
const ASCII_MODES: Exclude<SudokuAscii, ''>[] = ['prefer_entropy', 'prefer_ascii'];

const ASCII_OPTIONS = ASCII_MODES.map((value) => ({ value, label: value }));

export function FinalMaskTab() {
  const { t } = useTranslation();
  const form = Form.useFormInstance<FormValues>();
  const kind = Form.useWatch('finalmask_kind', form);
  // The form has no single "transport" field: `network` covers the TCP family
  // and Hysteria arrives as a protocol, taking its QUIC transport with it.
  // The backend matrix is keyed by the transport, so fold them here.
  const protocolKind = Form.useWatch('protocol_kind', form);
  const network = Form.useWatch('network', form);
  const security = Form.useWatch('security', form);
  const transport = protocolKind === 'hysteria2' ? 'hysteria' : network;
  const { data: support } = useFinalMaskSupport();

  // `none` is always offered — it is the absence of a mask, not a mask.
  const allowed = useMemo<FinalMask['kind'][]>(() => {
    const kinds = support?.[transport]?.[security];
    // Until the matrix arrives, show everything rather than an empty list:
    // a dropdown with one entry would read as "this transport supports
    // nothing", which is a worse lie than showing too much for a moment.
    return kinds ? ['none', ...kinds] : (Object.keys(VARIANT_LABEL_KEYS) as FinalMask['kind'][]);
  }, [support, transport, security]);

  const variantOptions = useMemo(
    () => allowed.map((value) => ({ value, label: t(VARIANT_LABEL_KEYS[value]) })),
    [allowed, t],
  );

  // Changing transport or security can strip the mask that was selected —
  // switching a TCP inbound to Hysteria takes XMC away with it. Leaving the
  // old value selected would show an empty tab and then fail on save with a
  // message about a combination the operator can no longer see.
  useEffect(() => {
    if (kind && !allowed.includes(kind)) {
      form.setFieldValue('finalmask_kind', 'none');
    }
  }, [allowed, kind, form]);

  return (
    <>
      <Alert
        type="info"
        showIcon
        title={t('inbounds.finalmaskNotice')}
        style={{ marginBottom: 16 }}
      />
      <Form.Item
        name="finalmask_kind"
        label={t('inbounds.finalmaskKind')}
        tooltip={t('inbounds.finalmaskKindTooltip')}
        extra={t('inbounds.finalmaskKindScopeHint')}
        style={{ marginBottom: 16 }}
      >
        <Select options={variantOptions} />
      </Form.Item>

      {kind === 'sudoku' && <SudokuFields />}
      {kind === 'fragment' && <FragmentFields />}
      {kind === 'noise' && <NoiseFields />}
      {kind === 'salamander' && <SalamanderFields />}
      {kind === 'xmc' && <XmcFields />}
    </>
  );
}

/** XMC — the inbound pretends to be a vanilla Minecraft server: a real login
 *  in the clear, then AES-CFB8, then the tunnel sliced into `xmc:data`
 *  custom-payload packets. Probing the port answers like a genuine server.
 *
 *  The profiles are real Mojang session data. Nothing in the protocol checks
 *  them — but nothing stops an observer from checking either, and an invented
 *  profile is the anomaly the mask exists to avoid. So the form resolves them
 *  by nickname through the panel rather than asking anyone to paste a signed
 *  textures blob by hand. */
function XmcFields() {
  const { t } = useTranslation();
  const { message } = App.useApp();
  const form = Form.useFormInstance<FormValues>();
  const [resolving, setResolving] = useState<number | null>(null);

  const resolve = async (index: number) => {
    const profiles = form.getFieldValue('finalmask_xmc_profiles') as XmcProfile[];
    const username = (profiles[index]?.username ?? '').trim();
    if (!username) {
      message.warning(t('inbounds.finalmaskXmcResolveNeedsName'));
      return;
    }
    setResolving(index);
    try {
      const { data } = await apiClient.get<XmcProfile>('/mojang/profile', {
        params: { username },
      });
      const next = [...profiles];
      // Mojang's spelling wins — it may differ in case from what was typed,
      // and the profile has to match the account exactly.
      next[index] = { ...data };
      form.setFieldValue('finalmask_xmc_profiles', next);
      message.success(t('inbounds.finalmaskXmcResolved', { name: data.username }));
    } catch (e) {
      message.error(apiErrorMessage(e) ?? t('inbounds.finalmaskXmcResolveFailed'));
    } finally {
      setResolving(null);
    }
  };

  return (
    <Section itemKey="finalmask-xmc" labelKey="inbounds.finalmaskXmcSection">
      <Alert
        type="warning"
        showIcon
        title={t('inbounds.finalmaskXmcPrivacyNotice')}
        style={{ marginBottom: 16 }}
      />
      <SideBySide>
        <Form.Item
          name="finalmask_xmc_hostname"
          label={t('inbounds.finalmaskXmcHostname')}
          tooltip={t('inbounds.finalmaskXmcHostnameTooltip')}
        >
          <Input
            placeholder={t('inbounds.finalmaskXmcHostnamePlaceholder')}
            allowClear
          />
        </Form.Item>
        <Form.Item
          name="finalmask_xmc_password"
          label={t('inbounds.finalmaskXmcPassword')}
          tooltip={t('inbounds.finalmaskXmcPasswordTooltip')}
          rules={[
            {
              validator: (_, v: string) => {
                if (!v || !v.trim()) {
                  return Promise.reject(new Error(t('inbounds.finalmaskXmcPasswordRequired')));
                }
                // The handshake encrypts `verifyToken + password` under a
                // 1024-bit RSA key with PKCS#1 v1.5 padding, which leaves 113
                // bytes. Longer fails at connect time, not at save time, so
                // catch it here where it can still be explained.
                const bytes = new TextEncoder().encode(v).length;
                return bytes > XMC_PASSWORD_MAX_BYTES
                  ? Promise.reject(
                      new Error(
                        t('inbounds.finalmaskXmcPasswordTooLong', {
                          bytes,
                          max: XMC_PASSWORD_MAX_BYTES,
                        }),
                      ),
                    )
                  : Promise.resolve();
              },
            },
          ]}
        >
          <Input.Password
            placeholder={t('inbounds.finalmaskXmcPasswordPlaceholder')}
            allowClear
          />
        </Form.Item>
      </SideBySide>

      <Typography.Paragraph type="secondary" style={{ fontSize: 12, marginBottom: 8 }}>
        {t('inbounds.finalmaskXmcProfilesHint')}
      </Typography.Paragraph>

      <Form.List name="finalmask_xmc_profiles">
        {(fields, { add, remove }) => (
          <>
            {fields.map((field: FormListFieldData) => (
              <div
                key={field.key}
                style={{
                  display: 'flex',
                  gap: 8,
                  alignItems: 'flex-start',
                  marginBottom: 8,
                }}
              >
                <Form.Item
                  name={[field.name, 'username']}
                  style={{ marginBottom: 0, flex: '0 0 200px' }}
                >
                  <Input
                    placeholder={t('inbounds.finalmaskXmcUsernamePlaceholder')}
                    onPressEnter={(e) => {
                      e.preventDefault();
                      void resolve(field.name);
                    }}
                  />
                </Form.Item>
                <Button
                  onClick={() => void resolve(field.name)}
                  loading={resolving === field.name}
                >
                  {t('inbounds.finalmaskXmcResolve')}
                </Button>
                {/* Resolved, not typed: shown so it is obvious the row is
                    filled and which account it points at, but read-only —
                    hand-editing a UUID or a signature only breaks the
                    signature's agreement with the name. */}
                <Form.Item name={[field.name, 'uuid']} style={{ marginBottom: 0, flex: 1 }}>
                  <Input readOnly placeholder={t('inbounds.finalmaskXmcUuidPlaceholder')} />
                </Form.Item>
                <Form.Item name={[field.name, 'textures_value']} hidden>
                  <Input />
                </Form.Item>
                <Form.Item name={[field.name, 'textures_signature']} hidden>
                  <Input />
                </Form.Item>
                <Button
                  type="text"
                  danger
                  icon={<DeleteOutlined />}
                  disabled={fields.length === 1}
                  onClick={() => remove(field.name)}
                />
              </div>
            ))}
            <Button
              type="dashed"
              icon={<PlusOutlined />}
              onClick={() =>
                add({ username: '', uuid: '', textures_value: '', textures_signature: '' })
              }
              block
            >
              {t('inbounds.finalmaskXmcAddProfile')}
            </Button>
          </>
        )}
      </Form.List>
    </Section>
  );
}

/** Salamander — Hysteria 2's native obfs. Just a shared password; the
 *  hysteria2 share-link emits it as the standard `obfs=salamander&
 *  obfs-password=…` so any hysteria2 client (not only xray) picks it up. */
function SalamanderFields() {
  const { t } = useTranslation();
  return (
    <Section itemKey="finalmask-salamander" labelKey="inbounds.finalmaskSalamanderSection">
      <Form.Item
        name="finalmask_salamander_password"
        label={t('inbounds.finalmaskSalamanderPassword')}
        tooltip={t('inbounds.finalmaskSalamanderPasswordTooltip')}
        rules={[
          {
            validator: (_, v: string) =>
              v && v.trim()
                ? Promise.resolve()
                : Promise.reject(new Error(t('inbounds.finalmaskSalamanderPasswordRequired'))),
          },
        ]}
        style={{ marginBottom: 0 }}
      >
        <Input.Password
          placeholder={t('inbounds.finalmaskSalamanderPasswordPlaceholder')}
          allowClear
        />
      </Form.Item>
    </Section>
  );
}

function SudokuFields() {
  const { t } = useTranslation();
  return (
    <Section itemKey="finalmask-sudoku" labelKey="inbounds.finalmaskSudokuSection">
      <Form.Item
        name="finalmask_sudoku_password"
        label={t('inbounds.finalmaskSudokuPassword')}
        tooltip={t('inbounds.finalmaskSudokuPasswordTooltip')}
        rules={[
          {
            validator: (_, v: string) =>
              v && v.trim()
                ? Promise.resolve()
                : Promise.reject(new Error(t('inbounds.finalmaskSudokuPasswordRequired'))),
          },
        ]}
        style={{ marginBottom: 12 }}
      >
        <Input.Password
          placeholder={t('inbounds.finalmaskSudokuPasswordPlaceholder')}
          allowClear
        />
      </Form.Item>
      <Form.Item
        name="finalmask_sudoku_ascii"
        label={t('inbounds.finalmaskSudokuAscii')}
        tooltip={t('inbounds.finalmaskSudokuAsciiTooltip')}
        style={{ marginBottom: 12 }}
      >
        <Select options={ASCII_OPTIONS} />
      </Form.Item>
      <SideBySide>
        <Form.Item
          name="finalmask_sudoku_padding_min"
          label={t('inbounds.finalmaskSudokuPaddingMin')}
          tooltip={t('inbounds.finalmaskSudokuPaddingTooltip')}
          style={{ flex: 1, marginBottom: 0 }}
        >
          <InputNumber min={0} max={SUDOKU_PADDING_MAX} style={{ width: '100%' }} />
        </Form.Item>
        <Form.Item
          name="finalmask_sudoku_padding_max"
          label={t('inbounds.finalmaskSudokuPaddingMax')}
          style={{ flex: 1, marginBottom: 0 }}
        >
          <InputNumber min={0} max={SUDOKU_PADDING_MAX} style={{ width: '100%' }} />
        </Form.Item>
      </SideBySide>
    </Section>
  );
}

function FragmentFields() {
  const { t } = useTranslation();
  const form = Form.useFormInstance<FormValues>();
  // The explicit "from..to" segment inputs only matter for the `range` mode;
  // tlshello / all encode their packets pair internally (0,1 / 0,0), so we
  // hide the raw inputs to keep the operator out of the magic-numbers trap.
  const packetsMode = Form.useWatch('finalmask_fragment_packets_mode', form);
  // Reject malformed range-list input ("3-5-7", "40-", "200-100") so a typo
  // surfaces inline instead of silently truncating or sending an inverted range.
  const rangeListRule = {
    validator(_rule: unknown, value: unknown) {
      const text = typeof value === 'string' ? value.trim() : '';
      if (!text) return Promise.resolve();
      for (const raw of text.split(',')) {
        const part = raw.trim();
        if (!part) continue;
        const seg = part.split('-').map((s) => s.trim());
        if (seg.length > 2 || seg.some((s) => !/^\d+$/.test(s))) {
          return Promise.reject(new Error(t('inbounds.finalmaskFragmentRangeInvalid')));
        }
        if (seg.length === 2 && Number(seg[0]) > Number(seg[1])) {
          return Promise.reject(new Error(t('inbounds.finalmaskFragmentRangeOrder')));
        }
      }
      return Promise.resolve();
    },
  };
  return (
    <Section itemKey="finalmask-fragment" labelKey="inbounds.finalmaskFragmentSection">
      <Typography.Paragraph
        type="secondary"
        style={{ fontSize: 12, marginBottom: 12 }}
      >
        {t('inbounds.finalmaskFragmentHint')}
      </Typography.Paragraph>
      <SelectField
        name="finalmask_fragment_packets_mode"
        labelKey="inbounds.finalmaskFragmentPacketsMode"
        tooltipKey="inbounds.finalmaskFragmentPacketsModeTooltip"
        options={[
          { value: 'tlshello', label: t('inbounds.finalmaskFragmentModeTlshello') },
          { value: 'all', label: t('inbounds.finalmaskFragmentModeAll') },
          { value: 'range', label: t('inbounds.finalmaskFragmentModeRange') },
        ]}
      />
      {packetsMode === 'range' && (
        <RangePair
          labelKey="inbounds.finalmaskFragmentPackets"
          tooltipKey="inbounds.finalmaskFragmentPacketsTooltip"
          minName="finalmask_fragment_packets_from"
          maxName="finalmask_fragment_packets_to"
        />
      )}
      <InputField
        name="finalmask_fragment_lengths"
        labelKey="inbounds.finalmaskFragmentLengths"
        tooltipKey="inbounds.finalmaskFragmentLengthsTooltip"
        rules={[rangeListRule]}
      />
      <InputField
        name="finalmask_fragment_delays"
        labelKey="inbounds.finalmaskFragmentDelays"
        tooltipKey="inbounds.finalmaskFragmentDelaysTooltip"
        rules={[rangeListRule]}
        last
      />
    </Section>
  );
}

/** One noise item. Extracted into its own component so it can `useWatch` its
 *  own `packet_hex`: per xray a noise item is EITHER a literal hex prefix OR a
 *  random-length range, never both. When a literal is set the range is dropped
 *  on save ("packet wins"), so we disable the random inputs — otherwise the
 *  operator fills both and the random bytes vanish silently. */
function NoiseItemRow({
  field,
  idx,
  disableRemove,
  onRemove,
  hexRule,
}: {
  field: FormListFieldData;
  idx: number;
  disableRemove: boolean;
  onRemove: () => void;
  hexRule: object;
}) {
  const { t } = useTranslation();
  const form = Form.useFormInstance<FormValues>();
  const packetHex = Form.useWatch(
    ['finalmask_noise_items', field.name, 'packet_hex'],
    form,
  );
  const hasLiteral = (packetHex ?? '').trim() !== '';
  return (
    <div
      style={{
        border: '1px solid var(--border)',
        borderRadius: 8,
        padding: 12,
        marginBottom: 8,
      }}
    >
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          marginBottom: 8,
        }}
      >
        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
          {t('inbounds.finalmaskNoiseItem', { n: idx + 1 })}
        </Typography.Text>
        <Button
          type="text"
          danger
          size="small"
          icon={<DeleteOutlined />}
          // Keep at least one row so the list never renders empty;
          // a single blank item is treated as "no noise" server-side.
          disabled={disableRemove}
          aria-label={t('inbounds.finalmaskNoiseRemoveItem')}
          onClick={onRemove}
        />
      </div>
      <Form.Item
        name={[field.name, 'packet_hex']}
        label={t('inbounds.finalmaskNoisePacketHex')}
        tooltip={t('inbounds.finalmaskNoisePacketHexTooltip')}
        rules={[hexRule]}
        style={{ marginBottom: 12 }}
      >
        <Input placeholder="e.g. deadbeef or empty" allowClear />
      </Form.Item>
      <Form.Item
        label={t('inbounds.finalmaskNoiseRand')}
        tooltip={t('inbounds.finalmaskNoiseRandTooltip')}
        style={{ marginBottom: 12 }}
      >
        <SideBySide>
          <Form.Item name={[field.name, 'rand_min']} noStyle>
            <InputNumber
              min={0}
              disabled={hasLiteral}
              placeholder="min"
              style={{ width: '100%' }}
            />
          </Form.Item>
          <Form.Item name={[field.name, 'rand_max']} noStyle>
            <InputNumber
              min={0}
              disabled={hasLiteral}
              placeholder="max"
              style={{ width: '100%' }}
            />
          </Form.Item>
        </SideBySide>
      </Form.Item>
      <Form.Item
        label={t('inbounds.finalmaskNoiseDelay')}
        tooltip={t('inbounds.finalmaskNoiseDelayTooltip')}
        style={{ marginBottom: 0 }}
      >
        <SideBySide>
          <Form.Item name={[field.name, 'delay_min']} noStyle>
            <InputNumber min={0} placeholder="min" style={{ width: '100%' }} />
          </Form.Item>
          <Form.Item name={[field.name, 'delay_max']} noStyle>
            <InputNumber min={0} placeholder="max" style={{ width: '100%' }} />
          </Form.Item>
        </SideBySide>
      </Form.Item>
    </div>
  );
}

function NoiseFields() {
  const { t } = useTranslation();
  // Backend's `decode_hex_relaxed` returns an empty Vec on the first non-hex
  // character, silently disabling that item. Catch typos at submit time so the
  // operator sees an error instead of a mysteriously broken inbound.
  const hexRule = {
    pattern: /^(?:0[xX])?[0-9a-fA-F\s:,]*$/,
    message: t('inbounds.finalmaskNoisePacketHexInvalid'),
  };
  return (
    <Section itemKey="finalmask-noise" labelKey="inbounds.finalmaskNoiseSection">
      <Typography.Paragraph
        type="secondary"
        style={{ fontSize: 12, marginBottom: 12 }}
      >
        {t('inbounds.finalmaskNoiseHint')}
      </Typography.Paragraph>
      <Form.List name="finalmask_noise_items">
        {(fields, { add, remove }) => (
          <>
            {fields.map((field, idx) => (
              <NoiseItemRow
                key={field.key}
                field={field}
                idx={idx}
                disableRemove={fields.length <= 1}
                onRemove={() => remove(field.name)}
                hexRule={hexRule}
              />
            ))}
            <Button
              type="dashed"
              size="small"
              icon={<PlusOutlined />}
              block
              onClick={() =>
                add({
                  packet_hex: '',
                  rand_min: null,
                  rand_max: null,
                  delay_min: null,
                  delay_max: null,
                })
              }
            >
              {t('inbounds.finalmaskNoiseAddItem')}
            </Button>
          </>
        )}
      </Form.List>
    </Section>
  );
}

