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

import { useMemo } from 'react';
import { Alert, Form, Input, InputNumber, Select, Typography } from 'antd';
import { useTranslation } from 'react-i18next';
import type { FinalMask } from '@/api/types';
import { RangePair, Section, SideBySide } from '../widgets';
import type { FormValues, SudokuAscii } from '../form/types';

/** Sudoku padding is `uint32` on the proto but xray rejects values above
 *  255 — same range the upstream docs document. */
const SUDOKU_PADDING_MAX = 255;

/** Variant catalogue rendered into the kind-selector. Each maps to a
 *  translated label so the dropdown stays localised; the transport-scope
 *  hint (TCP / UDP) is part of the label so the operator picks the right
 *  variant for their inbound at a glance. */
const VARIANT_LABEL_KEYS: Record<FinalMask['kind'], string> = {
  none: 'inbounds.finalmaskKindNone',
  sudoku: 'inbounds.finalmaskKindSudoku',
  fragment: 'inbounds.finalmaskKindFragment',
  noise: 'inbounds.finalmaskKindNoise',
};

/** Operator-selectable ASCII modes for Sudoku. `''` (empty) means
 *  "use xray's default" and is the form's resting state. */
const ASCII_MODES: Exclude<SudokuAscii, ''>[] = ['prefer_entropy', 'prefer_ascii'];

const ASCII_OPTIONS = ASCII_MODES.map((value) => ({ value, label: value }));

export function FinalMaskTab() {
  const { t } = useTranslation();
  const form = Form.useFormInstance<FormValues>();
  const kind = Form.useWatch('finalmask_kind', form);
  const variantOptions = useMemo(
    () =>
      (Object.entries(VARIANT_LABEL_KEYS) as [FinalMask['kind'], string][]).map(
        ([value, labelKey]) => ({ value, label: t(labelKey) }),
      ),
    [t],
  );
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
        style={{ marginBottom: 16 }}
      >
        <Select options={variantOptions} />
      </Form.Item>

      {kind === 'sudoku' && <SudokuFields />}
      {kind === 'fragment' && <FragmentFields />}
      {kind === 'noise' && <NoiseFields />}
    </>
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
  return (
    <Section itemKey="finalmask-fragment" labelKey="inbounds.finalmaskFragmentSection">
      <Typography.Paragraph
        type="secondary"
        style={{ fontSize: 12, marginBottom: 12 }}
      >
        {t('inbounds.finalmaskFragmentHint')}
      </Typography.Paragraph>
      <RangePair
        labelKey="inbounds.finalmaskFragmentLength"
        tooltipKey="inbounds.finalmaskFragmentLengthTooltip"
        minName="finalmask_fragment_length_min"
        maxName="finalmask_fragment_length_max"
      />
      <RangePair
        labelKey="inbounds.finalmaskFragmentPackets"
        tooltipKey="inbounds.finalmaskFragmentPacketsTooltip"
        minName="finalmask_fragment_packets_from"
        maxName="finalmask_fragment_packets_to"
      />
      <RangePair
        labelKey="inbounds.finalmaskFragmentDelay"
        tooltipKey="inbounds.finalmaskFragmentDelayTooltip"
        minName="finalmask_fragment_delay_min"
        maxName="finalmask_fragment_delay_max"
        last
      />
    </Section>
  );
}

function NoiseFields() {
  const { t } = useTranslation();
  return (
    <Section itemKey="finalmask-noise" labelKey="inbounds.finalmaskNoiseSection">
      <Typography.Paragraph
        type="secondary"
        style={{ fontSize: 12, marginBottom: 12 }}
      >
        {t('inbounds.finalmaskNoiseHint')}
      </Typography.Paragraph>
      <Form.Item
        name="finalmask_noise_packet_hex"
        label={t('inbounds.finalmaskNoisePacketHex')}
        tooltip={t('inbounds.finalmaskNoisePacketHexTooltip')}
        rules={[
          {
            // Backend's `decode_hex_relaxed` returns an empty Vec on the
            // first non-hex character, silently disabling the noise mask.
            // Catch typos at form-submit time so the operator sees an
            // error instead of a mysteriously broken inbound.
            pattern: /^(?:0[xX])?[0-9a-fA-F\s:,]*$/,
            message: t('inbounds.finalmaskNoisePacketHexInvalid'),
          },
        ]}
        style={{ marginBottom: 12 }}
      >
        <Input placeholder="e.g. deadbeef or empty" allowClear />
      </Form.Item>
      <RangePair
        labelKey="inbounds.finalmaskNoiseRand"
        tooltipKey="inbounds.finalmaskNoiseRandTooltip"
        minName="finalmask_noise_rand_min"
        maxName="finalmask_noise_rand_max"
        last
      />
    </Section>
  );
}

