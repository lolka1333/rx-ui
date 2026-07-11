//! Shared form widgets for the inbound editor — Section header,
//! ChipGroup multi-select, HTTP-header list editor, and the
//! `Form.Item` helpers (Input / Number / Select / Switch / range pair
//! with unit-suffix variants). Previously split across four files in
//! `ui/`; consolidated here because every consumer pulled from at
//! least two of them and the per-widget files had more comment
//! header than implementation.

import { useMemo, type CSSProperties, type ReactNode } from 'react';
import type { FormItemProps } from 'antd';
import {
  AutoComplete,
  Button,
  Collapse,
  Form,
  Input,
  InputNumber,
  Select,
  Space,
  Switch,
  Typography,
  theme,
} from 'antd';
import { DeleteOutlined, PlusOutlined } from '@ant-design/icons';
import { useTranslation } from 'react-i18next';

// =============================================================================
// Section — collapsible block with the consistent panel-header treatment
// used across the form (Sniffing, XHTTP Advanced, QUIC tuning, Encryption).
// =============================================================================

interface SectionProps {
  itemKey: string;
  labelKey: string;
  children: ReactNode;
}

export function Section({ itemKey, labelKey, children }: SectionProps) {
  const { t } = useTranslation();
  return (
    <Collapse
      ghost
      style={{
        marginTop: 12,
        marginBottom: 0,
        paddingTop: 4,
        borderTop: '1px solid var(--border)',
      }}
      items={[
        {
          key: itemKey,
          label: (
            <Typography.Text strong style={{ fontSize: 15 }}>
              {t(labelKey)}
            </Typography.Text>
          ),
          children,
        },
      ]}
    />
  );
}

// =============================================================================
// ChipGroup — multi-select chip strip. Controlled (`value` / `onChange`) so a
// `Form.Item` wires it like a Checkbox.Group; visually a row of accent-coloured
// pills matching the segmented Encryption / Flow buttons.
// =============================================================================

interface ChipGroupProps {
  /** Injected by the enclosing `Form.Item` so its `<label for=>` resolves
   *  to a real labelable element. We hang it on the first `<button>` —
   *  a `<div>` would trip Chrome's a11y audit. */
  id?: string;
  value?: string[];
  onChange?: (next: string[]) => void;
  options: { value: string; label: string }[];
}

export function ChipGroup({ id, value, onChange, options }: ChipGroupProps) {
  const { token } = theme.useToken();
  const selected = value ?? [];
  const toggle = (val: string) => {
    const next = selected.includes(val)
      ? selected.filter((v) => v !== val)
      : [...selected, val];
    onChange?.(next);
  };
  return (
    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
      {options.map((opt, idx) => {
        const active = selected.includes(opt.value);
        return (
          <button
            key={opt.value}
            id={idx === 0 ? id : undefined}
            type="button"
            onClick={() => toggle(opt.value)}
            style={{
              padding: '4px 14px',
              borderRadius: 999,
              fontSize: 13,
              lineHeight: '20px',
              fontWeight: active ? 600 : 500,
              cursor: 'pointer',
              border: `1px solid ${active ? token.colorPrimary : token.colorBorder}`,
              background: active ? token.colorPrimary : 'transparent',
              color: active ? token.colorTextLightSolid : token.colorTextSecondary,
              transition:
                'background 0.18s ease, color 0.18s ease, border-color 0.18s ease',
            }}
            onMouseEnter={(e) => {
              if (!active) {
                e.currentTarget.style.borderColor = token.colorPrimaryBorderHover;
                e.currentTarget.style.color = token.colorText;
              }
            }}
            onMouseLeave={(e) => {
              if (!active) {
                e.currentTarget.style.borderColor = token.colorBorder;
                e.currentTarget.style.color = token.colorTextSecondary;
              }
            }}
          >
            {opt.label}
          </button>
        );
      })}
    </div>
  );
}

// =============================================================================
// HeaderListField — HTTP-header key/value editor used by the WS/XHTTP tabs.
// =============================================================================

interface HeaderListFieldProps {
  /** Form field name (e.g. `ws_headers`, `xhttp_headers`). */
  name: string;
}

export function HeaderListField({ name }: HeaderListFieldProps) {
  const { t } = useTranslation();
  return (
    <Form.List name={name}>
      {(fields, { add, remove }) => (
        <>
          {fields.map((field) => (
            <div
              key={field.key}
              style={{ display: 'flex', gap: 8, marginBottom: 8 }}
            >
              <Form.Item
                name={[field.name, 'name']}
                style={{ flex: 1, marginBottom: 0 }}
              >
                <Input placeholder={t('inbounds.xhttpHeaderName')} />
              </Form.Item>
              <Form.Item
                name={[field.name, 'value']}
                style={{ flex: 2, marginBottom: 0 }}
              >
                <Input placeholder={t('inbounds.xhttpHeaderValue')} />
              </Form.Item>
              <Button
                type="text"
                danger
                size="small"
                icon={<DeleteOutlined />}
                onClick={() => remove(field.name)}
              />
            </div>
          ))}
          <Button
            type="dashed"
            size="small"
            icon={<PlusOutlined />}
            onClick={() => add({ name: '', value: '' })}
            block
          >
            {t('inbounds.xhttpHeaderAdd')}
          </Button>
        </>
      )}
    </Form.List>
  );
}

// =============================================================================
// Form.Item wrappers — `labelKey`/`tooltipKey` take i18n keys (not translated
// strings) so each helper owns its own `useTranslation`. `last` flag flips
// the bottom margin to 0 for the final row in a section.
// =============================================================================

interface FieldProps {
  name: string;
  labelKey: string;
  tooltipKey?: string;
  last?: boolean;
  rules?: FormItemProps['rules'];
  /** Grey out the input when the setting doesn't apply in the current mode. */
  disabled?: boolean;
}

export function RangeField({ name, labelKey, tooltipKey, last }: FieldProps) {
  const { t } = useTranslation();
  return (
    <Form.Item
      name={name}
      label={t(labelKey)}
      tooltip={tooltipKey ? t(tooltipKey) : undefined}
      style={{ marginBottom: last ? 0 : 12 }}
    >
      <Input placeholder={t('inbounds.xhttpRangeHint')} />
    </Form.Item>
  );
}

interface SelectFieldProps extends FieldProps {
  options: { value: string; label: string }[];
}

export function SelectField({
  name,
  labelKey,
  tooltipKey,
  options,
  last,
  disabled,
}: SelectFieldProps) {
  const { t } = useTranslation();
  return (
    <Form.Item
      name={name}
      label={t(labelKey)}
      tooltip={tooltipKey ? t(tooltipKey) : undefined}
      style={{ marginBottom: last ? 0 : 12 }}
    >
      <Select options={options} disabled={disabled} />
    </Form.Item>
  );
}

export function NumberField({ name, labelKey, tooltipKey, last }: FieldProps) {
  const { t } = useTranslation();
  return (
    <Form.Item
      name={name}
      label={t(labelKey)}
      tooltip={tooltipKey ? t(tooltipKey) : undefined}
      style={{ marginBottom: last ? 0 : 12 }}
    >
      <InputNumber min={0} style={{ width: '100%' }} />
    </Form.Item>
  );
}

export function InputField({ name, labelKey, tooltipKey, last, rules, disabled }: FieldProps) {
  const { t } = useTranslation();
  return (
    <Form.Item
      name={name}
      label={t(labelKey)}
      tooltip={tooltipKey ? t(tooltipKey) : undefined}
      rules={rules}
      style={{ marginBottom: last ? 0 : 12 }}
    >
      <Input disabled={disabled} />
    </Form.Item>
  );
}

// Free-text input with a dropdown of preset suggestions. Unlike `SelectField`
// the operator can ALSO type a value that isn't in the list — for fields that
// take a known preset OR a custom string (e.g. XHTTP `sessionIDTable`: a
// predefined alphabet name or a custom ASCII set). Typing filters the presets
// by case-insensitive substring; whatever is typed is kept as the value.
interface AutoCompleteFieldProps extends FieldProps {
  options: { value: string; label?: string }[];
  placeholderKey?: string;
}

export function AutoCompleteField({
  name,
  labelKey,
  tooltipKey,
  options,
  placeholderKey,
  last,
}: AutoCompleteFieldProps) {
  const { t } = useTranslation();
  return (
    <Form.Item
      name={name}
      label={t(labelKey)}
      tooltip={tooltipKey ? t(tooltipKey) : undefined}
      style={{ marginBottom: last ? 0 : 12 }}
    >
      <AutoComplete
        options={options}
        allowClear
        style={{ width: '100%' }}
        placeholder={placeholderKey ? t(placeholderKey) : undefined}
        showSearch={{
          filterOption: (input, option) =>
            String(option?.value ?? '')
              .toLowerCase()
              .includes(input.toLowerCase()),
        }}
      />
    </Form.Item>
  );
}

export function SwitchField({ name, labelKey, tooltipKey, last }: FieldProps) {
  const { t } = useTranslation();
  return (
    <Form.Item
      name={name}
      label={t(labelKey)}
      tooltip={tooltipKey ? t(tooltipKey) : undefined}
      valuePropName="checked"
      style={{ marginBottom: last ? 0 : 12 }}
    >
      <Switch size="small" />
    </Form.Item>
  );
}

// =============================================================================
// AddonLabel — non-interactive label that looks like antd's deprecated
// Input/InputNumber `addonBefore`/`addonAfter`. antd v6 deprecated those props
// in favour of composing inside `Space.Compact`; this IS that composed piece.
// `side` picks which edge merges (borderless, square corners) with the
// neighbouring control so the pair reads as one rounded control.
// =============================================================================

export function AddonLabel({
  side,
  children,
}: {
  side: 'before' | 'after';
  children: ReactNode;
}) {
  const { token } = theme.useToken();
  // Memoize on primitive token fields rather than the `token` object — antd's
  // `useToken` returns a fresh object every render, so `[token]` would
  // invalidate immediately and the memo would do nothing.
  const style = useMemo<CSSProperties>(() => {
    const base: CSSProperties = {
      flex: '0 0 auto',
      display: 'inline-flex',
      alignItems: 'center',
      justifyContent: 'center',
      height: token.controlHeight,
      paddingInline: 10,
      border: `${token.lineWidth}px solid ${token.colorBorder}`,
      background: token.colorFillTertiary,
      color: token.colorTextSecondary,
      fontSize: token.fontSize,
      lineHeight: 1,
      whiteSpace: 'nowrap',
      userSelect: 'none',
    };
    if (side === 'after') {
      // Drop the left border + left rounding so it merges with the control
      // on its left.
      base.borderInlineStart = 0;
      base.borderStartEndRadius = token.borderRadius;
      base.borderEndEndRadius = token.borderRadius;
    } else {
      // Mirror image — merge with the control on its right.
      base.borderInlineEnd = 0;
      base.borderStartStartRadius = token.borderRadius;
      base.borderEndStartRadius = token.borderRadius;
    }
    return base;
  }, [
    side,
    token.controlHeight,
    token.lineWidth,
    token.colorBorder,
    token.borderRadius,
    token.colorFillTertiary,
    token.colorTextSecondary,
    token.fontSize,
  ]);
  return <span style={style}>{children}</span>;
}

// =============================================================================
// NumberWithUnit — InputNumber + a unit suffix (via AddonLabel), styled to look
// like one control (a plain <Input> suffix ignores width:auto and grabs ~180px).
// =============================================================================

interface NumberWithUnitProps {
  value?: number | null;
  onChange?: (v: number | null) => void;
  unit: string;
  min?: number;
  placeholder?: string;
}

// Hoisted so the InputNumber's style identity is stable across renders —
// antd diffs by reference, and a new object every render forces extra work
// even though the values are unchanged.
const NUMBER_FLEX_STYLE = { flex: 1, minWidth: 0 } as const;

export function NumberWithUnit({ value, onChange, unit, min, placeholder }: NumberWithUnitProps) {
  return (
    <Space.Compact block>
      <InputNumber
        value={value}
        onChange={onChange}
        min={min}
        placeholder={placeholder}
        // `flex: 1` + `minWidth: 0` lets the number input claim all the
        // space the unit-suffix doesn't take. Plain `width: 100%` collapses
        // here because InputNumber's wrapper has `flex: 0 1 auto` by
        // default inside `Space.Compact`.
        style={NUMBER_FLEX_STYLE}
      />
      <AddonLabel side="after">{unit}</AddonLabel>
    </Space.Compact>
  );
}

// =============================================================================
// Layout helpers — paired side-by-side rows and range (min/max) pair.
// =============================================================================

/** Two children side-by-side with shared gap. Use for paired Form.Items where
 *  each carries its own label. */
export function SideBySide({ children }: { children: ReactNode }) {
  return <div style={{ display: 'flex', gap: 12 }}>{children}</div>;
}

interface RangePairProps {
  labelKey: string;
  tooltipKey?: string;
  minName: string;
  maxName: string;
  last?: boolean;
}

/** Two `InputNumber`s side-by-side under one shared label. Convention for
 *  any `[min, max]` knob set as a single range. */
export function RangePair({ labelKey, tooltipKey, minName, maxName, last }: RangePairProps) {
  const { t } = useTranslation();
  return (
    <Form.Item
      label={t(labelKey)}
      tooltip={tooltipKey ? t(tooltipKey) : undefined}
      style={{ marginBottom: last ? 0 : 12 }}
    >
      <SideBySide>
        <Form.Item name={minName} noStyle>
          <InputNumber min={0} placeholder="min" style={{ width: '100%' }} />
        </Form.Item>
        <Form.Item name={maxName} noStyle>
          <InputNumber min={0} placeholder="max" style={{ width: '100%' }} />
        </Form.Item>
      </SideBySide>
    </Form.Item>
  );
}

interface NumberWithUnitFieldProps {
  name: string;
  labelKey: string;
  tooltipKey?: string;
  unit: string;
  placeholder?: string;
  min?: number;
}

/** Half-row `Form.Item` carrying a `NumberWithUnit`. Pair two of them inside
 *  a `SideBySide` to lay out QUIC-style "left value / right value" rows
 *  where each side has its own label, tooltip, and placeholder. */
export function NumberUnitField({
  name,
  labelKey,
  tooltipKey,
  unit,
  placeholder,
  min = 0,
}: NumberWithUnitFieldProps) {
  const { t } = useTranslation();
  return (
    <Form.Item
      name={name}
      label={t(labelKey)}
      tooltip={tooltipKey ? t(tooltipKey) : undefined}
      style={{ flex: 1, marginBottom: 12 }}
    >
      <NumberWithUnit min={min} placeholder={placeholder} unit={unit} />
    </Form.Item>
  );
}
