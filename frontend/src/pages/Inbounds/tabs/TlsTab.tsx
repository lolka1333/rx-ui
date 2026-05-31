//! TLS security tab — multi-cert array editor + transport-level knobs.
//!
//! Each cert entry is either an inline PEM blob (stored verbatim in the
//! panel DB, so backups are self-contained) or a filesystem path that
//! xray re-reads at handshake time (the path mode hand-offs cert
//! rotation to an external tool — certbot, vault-agent, etc.). Per-cert
//! we surface `usage` / OCSP stapling / chain-build / one-time-loading
//! knobs which mirror xray's `Certificate` proto.
//!
//! Top-level knobs cover the full operator-relevant surface of xray's
//! `tls::Config`: server-name override, ALPN, min/max version, cipher
//! suites (TLS 1.2), session-resumption, reject-unknown-SNI, ECH server
//! keys, master-key-log.

import {
  App,
  Button,
  Form,
  Input,
  InputNumber,
  Radio,
  Select,
  Switch,
  Tooltip,
  Typography,
} from 'antd';
import { DeleteOutlined, PlusOutlined, QuestionCircleOutlined } from '@ant-design/icons';
import { useMutation } from '@tanstack/react-query';
import { useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { apiClient } from '@/api/client';
import { apiErrorMessage } from '@/api/errors';
import type { EchKeyBundle, TlsCertSource, TlsCertUsage } from '@/api/types';
import { ChipGroup, Section } from '../widgets';
import type { FormValues } from '../form/types';

// h3 is exclusive: xray's splithttp hub only spins up a QUIC listener
// when ALPN is exactly ["h3"] — `len == 1 && [0] == "h3"` in
// `splithttp.Hub.Start`. Combining h3 with h2 or http/1.1 falls back to
// TCP/H2, so we surface h3 alongside the others and let the operator
// pick one mode.
const ALPN_OPTIONS = [
  { value: 'h3', label: 'h3 (HTTP/3 — QUIC)' },
  { value: 'h2', label: 'h2 (HTTP/2)' },
  { value: 'http/1.1', label: 'http/1.1' },
];

// Cipher-suite whitelist xray accepts. xray resolves names through Go's
// `tls.CipherSuites()` (crypto/tls returns all non-insecure suites —
// both TLS 1.2 AEADs/CBC and the three fixed TLS 1.3 suites). Order in
// this dropdown is xray's own preference order copied from Go's
// `cipherSuitesPreferenceOrder` so the most sensible defaults sort to
// the top. TLS 1.3 suites are listed in a separate group — see
// `tlsCipherSuites13GroupLabel` i18n key — because Go's stdlib ignores
// CipherSuites for TLS 1.3; xray accepts them but they won't take effect.
const CIPHER_SUITE_GROUPS = [
  {
    label: 'TLS 1.2 — ECDHE AEAD',
    values: [
      'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
      'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
      'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
      'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
      'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
      'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
    ],
  },
  {
    label: 'TLS 1.2 — ECDHE CBC',
    values: [
      'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA',
      'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
      'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA',
      'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
    ],
  },
  {
    label: 'TLS 1.2 — RSA-only (no PFS)',
    values: [
      'TLS_RSA_WITH_AES_128_GCM_SHA256',
      'TLS_RSA_WITH_AES_256_GCM_SHA384',
      'TLS_RSA_WITH_AES_128_CBC_SHA',
      'TLS_RSA_WITH_AES_256_CBC_SHA',
    ],
  },
] as const;

const TLS13_SUITES = [
  'TLS_AES_128_GCM_SHA256',
  'TLS_AES_256_GCM_SHA384',
  'TLS_CHACHA20_POLY1305_SHA256',
] as const;

const CURVE_OPTIONS = [
  { value: 'X25519', label: 'X25519' },
  { value: 'X25519MLKEM768', label: 'X25519MLKEM768 (post-quantum)' },
  { value: 'P-256', label: 'P-256 (secp256r1)' },
  { value: 'P-384', label: 'P-384' },
  { value: 'P-521', label: 'P-521' },
];

const PEM_HEADER_RE = /-----BEGIN [A-Z ]+-----/;

/** Validator: accept empty (handled by `required` on the parent) or any
 *  PEM-shaped blob. Strict enough to catch "I pasted my SSH key" but
 *  loose on header word (`PRIVATE KEY`, `ENCRYPTED PRIVATE KEY`, etc). */
function pemRule(message: string) {
  return {
    validator: (_: unknown, v: string) =>
      !v || PEM_HEADER_RE.test(v) ? Promise.resolve() : Promise.reject(new Error(message)),
  };
}

export function TlsTab() {
  const { t } = useTranslation();
  const { message } = App.useApp();
  const form = Form.useFormInstance<FormValues>();
  // Read the current TLS `server_name` so the ECH keygen's `public_name`
  // matches whatever the operator is exposing. Falls back to xray's own
  // default (`cloudflare-ech.com`) on the backend when empty.
  const tlsServerName = (Form.useWatch('tls_server_name', form) ?? '') as string;
  // Both halves of the keypair go straight into form values — the
  // private `ech_server_keys` is what xray reads, the public
  // `ech_config_list` rides along in the share-link's `ech=` param so
  // operators don't have to ship it out of band.
  const echKeygen = useMutation({
    mutationFn: async (sn: string) =>
      (
        await apiClient.post<EchKeyBundle>('/keygen/ech', undefined, {
          params: sn ? { server_name: sn } : {},
        })
      ).data,
    onSuccess: (bundle) => {
      form.setFieldValue('tls_ech_server_keys', bundle.ech_server_keys);
      form.setFieldValue('tls_ech_config_list', bundle.ech_config_list);
      message.success(t('inbounds.tlsEchGenerated'));
    },
    onError: (err: unknown) =>
      message.error(apiErrorMessage(err) ?? t('inbounds.tlsEchGenerateError')),
  });

  const tlsVerOpts = useMemo(
    () => [
      { value: '', label: t('inbounds.tlsVersionDefault') },
      { value: '1.2', label: 'TLS 1.2' },
      { value: '1.3', label: 'TLS 1.3' },
    ],
    [t],
  );
  const cipherSuiteOpts = useMemo(
    () => [
      ...CIPHER_SUITE_GROUPS.map((g) => ({
        label: g.label,
        options: g.values.map((v) => ({ value: v, label: v })),
      })),
      {
        label: t('inbounds.tlsCipherSuites13GroupLabel'),
        options: TLS13_SUITES.map((v) => ({ value: v, label: v })),
      },
    ],
    [t],
  );
  const usageOpts = useMemo(
    () => [
      { value: 'encipherment', label: t('inbounds.tlsCertUsageEncipherment') },
      { value: 'verify', label: t('inbounds.tlsCertUsageVerify') },
      { value: 'issue', label: t('inbounds.tlsCertUsageIssue') },
    ],
    [t],
  );
  return (
    <>
      <Form.List name="tls_certificates">
        {(fields, { add, remove }) => (
          <>
            {fields.length === 0 && (
              <Typography.Text type="secondary" style={{ fontSize: 12, display: 'block', marginBottom: 8 }}>
                {t('inbounds.tlsCertificatesEmpty')}
              </Typography.Text>
            )}
            {fields.map((field) => (
              <CertificateRow
                key={field.key}
                name={field.name}
                onRemove={() => remove(field.name)}
                usageOpts={usageOpts}
              />
            ))}
            <Form.Item style={{ marginBottom: 12 }}>
              <Button
                type="dashed"
                onClick={() =>
                  add({
                    source: 'inline' as TlsCertSource,
                    cert: '',
                    key: '',
                    usage: 'encipherment' as TlsCertUsage,
                    ocsp_stapling: 0,
                    build_chain: false,
                    one_time_loading: true,
                  })
                }
                icon={<PlusOutlined />}
                block
              >
                {t('inbounds.tlsAddCertificate')}
              </Button>
            </Form.Item>
          </>
        )}
      </Form.List>

      <Form.Item
        name="tls_server_name"
        label={t('inbounds.tlsServerName')}
        tooltip={t('inbounds.tlsServerNameTooltip')}
        style={{ marginBottom: 12 }}
      >
        <Input placeholder="vless.example.com" />
      </Form.Item>
      <Form.Item
        name="tls_alpn"
        label={t('inbounds.tlsAlpn')}
        tooltip={t('inbounds.tlsAlpnTooltip')}
        style={{ marginBottom: 12 }}
      >
        <ChipGroup options={ALPN_OPTIONS} />
      </Form.Item>
      <div style={{ display: 'flex', columnGap: 12, rowGap: 0, flexWrap: 'wrap' }}>
        <Form.Item
          name="tls_min_version"
          label={t('inbounds.tlsMinVersion')}
          style={{ marginBottom: 12, minWidth: 180 }}
        >
          <Select options={tlsVerOpts} />
        </Form.Item>
        <Form.Item
          name="tls_max_version"
          label={t('inbounds.tlsMaxVersion')}
          tooltip={t('inbounds.tlsMaxVersionTooltip')}
          style={{ marginBottom: 12, minWidth: 180 }}
        >
          <Select options={tlsVerOpts} />
        </Form.Item>
      </div>
      <Form.Item
        name="tls_reject_unknown_sni"
        label={t('inbounds.tlsRejectUnknownSni')}
        tooltip={t('inbounds.tlsRejectUnknownSniTooltip')}
        valuePropName="checked"
        style={{ marginBottom: 12 }}
      >
        <Switch size="small" />
      </Form.Item>

      {/* Advanced TLS — cipher suites, session resumption, ECH, key-log.
          Tucked behind a collapse because the defaults are sane for the
          vast majority of operators and the form's main panel should
          stay short. */}
      <Section itemKey="tlsAdvanced" labelKey="inbounds.tlsAdvancedSection">
        <Form.Item
          name="tls_enable_session_resumption"
          label={t('inbounds.tlsEnableSessionResumption')}
          tooltip={t('inbounds.tlsEnableSessionResumptionTooltip')}
          valuePropName="checked"
          style={{ marginBottom: 12 }}
        >
          <Switch size="small" />
        </Form.Item>
        <Form.Item
          name="tls_cipher_suites"
          label={t('inbounds.tlsCipherSuites')}
          tooltip={t('inbounds.tlsCipherSuitesTooltip')}
          style={{ marginBottom: 12 }}
        >
          <Select
            mode="multiple"
            allowClear
            placeholder={t('inbounds.tlsCipherSuitesPlaceholder')}
            options={cipherSuiteOpts}
            optionFilterProp="label"
            style={{ width: '100%' }}
          />
        </Form.Item>
        {/* ECH server keys + on-demand generator. The "Generate" button
            calls `POST /api/keygen/ech` which shells out to
            `xray tls ech --serverName <tls_server_name>` — same binary
            xray will use at handshake time, so we get bit-for-bit
            compatibility instead of replicating the ECHConfig wire
            format in Rust. On success we drop the base64 server-keys
            into the textarea; the matching public `ech_config_list`
            is registered hidden so it rides through to save. */}
        <Form.Item
          name="tls_ech_server_keys"
          label={
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
              {t('inbounds.tlsEchServerKeys')}
              <Button
                size="small"
                type="link"
                loading={echKeygen.isPending}
                onClick={() => echKeygen.mutate(tlsServerName)}
                style={{ padding: 0, height: 'auto', fontSize: 12 }}
              >
                {t('inbounds.tlsEchGenerate')}
              </Button>
            </span>
          }
          tooltip={t('inbounds.tlsEchServerKeysTooltip')}
          style={{ marginBottom: 12 }}
        >
          <Input.TextArea
            rows={3}
            placeholder={t('inbounds.tlsEchServerKeysPlaceholder')}
            style={{ fontFamily: 'ui-monospace, "JetBrains Mono", Consolas, monospace', fontSize: 12 }}
          />
        </Form.Item>
        {/* `ech_config_list` is registered as a hidden Form.Item so the
            value the Generate button populated survives form re-mounts
            and rides through to save. The visible copy-block is gone:
            the public ECH bytes now travel inside the share-link's
            `ech=` param — no manual distribution step. */}
        <Form.Item name="tls_ech_config_list" hidden noStyle>
          <Input type="hidden" />
        </Form.Item>
        <Form.Item
          name="tls_master_key_log"
          label={t('inbounds.tlsMasterKeyLog')}
          tooltip={t('inbounds.tlsMasterKeyLogTooltip')}
          style={{ marginBottom: 12 }}
        >
          <Input placeholder="/var/log/xray/sslkey.log" />
        </Form.Item>
        {/* TLS 1.3 curve preferences — ordered list (first match wins).
            Select mode="multiple" preserves selection order in the returned
            value, which is exactly what xray wants. */}
        <Form.Item
          name="tls_curve_preferences"
          label={t('inbounds.tlsCurvePreferences')}
          tooltip={t('inbounds.tlsCurvePreferencesTooltip')}
          style={{ marginBottom: 0 }}
        >
          <Select
            mode="tags"
            placeholder={t('inbounds.tlsCurvePreferencesPlaceholder')}
            options={CURVE_OPTIONS}
            tokenSeparators={[',']}
          />
        </Form.Item>
      </Section>
    </>
  );
}

interface CertificateRowProps {
  name: number;
  onRemove: () => void;
  usageOpts: Array<{ value: string; label: string }>;
}

/**
 * One row of the TLS certificate array. Lives in its own component so
 * `Form.useWatch` on the entry-local `source` field re-renders just this
 * row (not the whole TlsTab) when the operator toggles inline ↔ path.
 *
 * The source toggle drives the cert/key input shape:
 *   * `inline` — multi-line `Input.TextArea` with a PEM-shape regex
 *                validator (catches "I pasted my SSH key by mistake"
 *                — without being strict enough to reject odd headers
 *                like `BEGIN ENCRYPTED PRIVATE KEY`).
 *   * `path`   — single-line `Input` with a hint about chmod + the
 *                fact that xray needs read access at the configured
 *                user, not the panel's user.
 */
function CertificateRow({ name, onRemove, usageOpts }: CertificateRowProps) {
  const { t } = useTranslation();
  const form = Form.useFormInstance();
  const source =
    (Form.useWatch(['tls_certificates', name, 'source'], form) as TlsCertSource | undefined) ??
    'inline';
  const isInline = source === 'inline';
  return (
    <div
      style={{
        border: '1px solid var(--ant-color-border-secondary, rgba(0,0,0,0.08))',
        borderRadius: 8,
        padding: 14,
        marginBottom: 12,
        background: 'var(--ant-color-fill-quaternary, rgba(0,0,0,0.02))',
      }}
    >
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 8,
          marginBottom: 14,
        }}
      >
        <Typography.Text type="secondary" style={{ fontSize: 12, minWidth: 22 }}>
          #{name + 1}
        </Typography.Text>
        <Form.Item name={[name, 'source']} noStyle>
          <Radio.Group
            options={[
              { value: 'inline', label: t('inbounds.tlsCertSourceInline') },
              { value: 'path', label: t('inbounds.tlsCertSourcePath') },
            ]}
            optionType="button"
            size="small"
          />
        </Form.Item>
        <Tooltip title={t('inbounds.tlsCertSourceTooltip')}>
          <QuestionCircleOutlined style={{ opacity: 0.45, fontSize: 13, cursor: 'help' }} />
        </Tooltip>
        <div style={{ flex: 1 }} />
        <Button
          type="text"
          danger
          size="small"
          icon={<DeleteOutlined />}
          onClick={onRemove}
          aria-label={t('inbounds.tlsRemoveCertificate')}
        />
      </div>
      <PemField
        name={[name, 'cert']}
        label={isInline ? t('inbounds.tlsCertPem') : t('inbounds.tlsCertPath')}
        tooltip={isInline ? t('inbounds.tlsCertPemTooltip') : t('inbounds.tlsCertPathTooltip')}
        invalidMessage={t('inbounds.tlsCertPemInvalid')}
        inlinePlaceholder={'-----BEGIN CERTIFICATE-----\nMIIDxz...\n-----END CERTIFICATE-----'}
        pathPlaceholder="/etc/letsencrypt/live/example.com/fullchain.pem"
        isInline={isInline}
      />
      <PemField
        name={[name, 'key']}
        label={isInline ? t('inbounds.tlsKeyPem') : t('inbounds.tlsKeyPath')}
        tooltip={isInline ? t('inbounds.tlsKeyPemTooltip') : t('inbounds.tlsKeyPathTooltip')}
        invalidMessage={t('inbounds.tlsKeyPemInvalid')}
        inlinePlaceholder={'-----BEGIN PRIVATE KEY-----\nMIIEvQ...\n-----END PRIVATE KEY-----'}
        pathPlaceholder="/etc/letsencrypt/live/example.com/privkey.pem"
        isInline={isInline}
      />
      <div style={{ display: 'flex', columnGap: 12, rowGap: 0, flexWrap: 'wrap' }}>
        <Form.Item
          name={[name, 'usage']}
          label={t('inbounds.tlsCertUsage')}
          tooltip={t('inbounds.tlsCertUsageTooltip')}
          style={{ marginBottom: 12, minWidth: 180 }}
        >
          <Select options={usageOpts} size="small" />
        </Form.Item>
        <Form.Item
          name={[name, 'ocsp_stapling']}
          label={t('inbounds.tlsOcspStapling')}
          tooltip={t('inbounds.tlsOcspStaplingTooltip')}
          style={{ marginBottom: 12, minWidth: 160 }}
        >
          <InputNumber min={0} placeholder="0" style={{ width: '100%' }} size="small" />
        </Form.Item>
        <Form.Item
          name={[name, 'build_chain']}
          label={t('inbounds.tlsBuildChain')}
          tooltip={t('inbounds.tlsBuildChainTooltip')}
          valuePropName="checked"
          style={{ marginBottom: 12 }}
        >
          <Switch size="small" />
        </Form.Item>
        {/* one_time_loading hidden when source=inline (it's forced true
            by the backend — no file to watch). Surface only for path. */}
        {!isInline && (
          <Form.Item
            name={[name, 'one_time_loading']}
            label={t('inbounds.tlsOneTimeLoading')}
            tooltip={t('inbounds.tlsOneTimeLoadingTooltip')}
            valuePropName="checked"
            style={{ marginBottom: 12 }}
          >
            <Switch size="small" />
          </Form.Item>
        )}
      </div>
    </div>
  );
}

interface PemFieldProps {
  name: (string | number)[];
  label: string;
  tooltip: string;
  invalidMessage: string;
  inlinePlaceholder: string;
  pathPlaceholder: string;
  isInline: boolean;
}

/** Shared cert/key field — same shape twice in `CertificateRow` and the
 *  inline-vs-path branching is identical for both. */
function PemField({
  name,
  label,
  tooltip,
  invalidMessage,
  inlinePlaceholder,
  pathPlaceholder,
  isInline,
}: PemFieldProps) {
  return (
    <Form.Item
      name={name}
      label={label}
      tooltip={tooltip}
      rules={isInline ? [pemRule(invalidMessage)] : []}
      style={{ marginBottom: 12 }}
    >
      {isInline ? (
        <Input.TextArea
          rows={5}
          placeholder={inlinePlaceholder}
          style={{ fontFamily: 'ui-monospace, "JetBrains Mono", Consolas, monospace', fontSize: 12 }}
        />
      ) : (
        <Input placeholder={pathPlaceholder} />
      )}
    </Form.Item>
  );
}
