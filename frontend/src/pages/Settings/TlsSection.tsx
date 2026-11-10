/**
 * HTTPS — the operator's certificate and key for the panel's own listener.
 * TLS binds at process start, so a change is applied by a restart.
 */
import { App, Form } from 'antd';
import { KeyOutlined, SafetyCertificateOutlined } from '@ant-design/icons';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { apiClient } from '@/api/client';
import { apiErrorMessage } from '@/api/errors';
import { useLoadState } from '@/api/loadState';
import { LoadError, LoadStale } from '@/components/LoadState';
import type { PanelSettings } from '@/api/types';
import { mergePanelSettings } from '@/lib/panelSettings';
import { pemRule } from '@/lib/pem';
import { reportRouting } from '@/lib/routingReport';
import type { RoutingApplyResult } from '@/lib/routingReport';
import { PemDropField } from './PemDropField';
import { type DirtyHandle, differsFromSaved, useSectionDirtyPublish } from './dirty';
import { SectionFrame, FieldLabel, FieldGroup, RowSwitch } from './fields';
import { normaliseClientPrefix } from './prefix';

interface TlsFormValues {
  panel_tls_enabled: boolean;
  panel_tls_cert: string;
  panel_tls_key: string;
}

export function TlsSection({
  onDirtyChange,
}: {
  onDirtyChange: (h: DirtyHandle | null) => void;
}) {
  const { t } = useTranslation();
  const { message, modal } = App.useApp();
  const qc = useQueryClient();
  const [form] = Form.useForm<TlsFormValues>();
  const [dirty, setDirty] = useState(false);

  const settingsQuery = useQuery<PanelSettings>({
    queryKey: ['panel-settings'],
    queryFn: async () => (await apiClient.get<PanelSettings>('/settings/panel')).data,
  });

  const mutation = useMutation({
    mutationFn: async (values: TlsFormValues) => {
      // PUT replaces the whole row; mergePanelSettings forwards every field this
      // section doesn't own. The key is sent only when the operator pasted one
      // (empty ≡ the backend keeps the stored key).
      // Read the cache at SEND time, not from the render closure: with two
      // sections dirty, the second save would otherwise merge a snapshot
      // taken before the first one landed and revert its fields.
      const current =
        qc.getQueryData<PanelSettings>(['panel-settings']) ?? settingsQuery.data;
      const res = await apiClient.put<RoutingApplyResult>(
        '/settings/panel',
        mergePanelSettings(current, {
          panel_tls_enabled: values.panel_tls_enabled,
          panel_tls_cert: values.panel_tls_cert,
          panel_tls_key: values.panel_tls_key?.trim() ?? '',
        }),
      );
      return { values, routing: res.data ?? {} };
    },
    onSuccess: ({ values, routing }) => {
      const report = reportRouting(routing, message, t);
      // Only offer the restart when something TLS-relevant actually moved —
      // toggling HTTPS, swapping the cert, or pasting a new key.
      const old = settingsQuery.data;
      const tlsChanged =
        old != null &&
        (values.panel_tls_enabled !== old.panel_tls_enabled ||
          values.panel_tls_cert !== old.panel_tls_cert ||
          !!values.panel_tls_key.trim());
      qc.invalidateQueries({ queryKey: ['panel-settings'] });
      setDirty(false);
      // The key is stored now and never re-fetched — drop it from the form so
      // it isn't re-sent or left on screen.
      form.setFieldValue('panel_tls_key', '');
      if (!tlsChanged || old == null) {
        if (report === 'clean') message.success(t('settings.panelSaved'));
        return;
      }
      // TLS binds at process start, so the change lands only after a restart.
      const scheme = values.panel_tls_enabled ? 'https' : 'http';
      const path = normaliseClientPrefix(old.panel_base_path);
      const url = `${scheme}://${window.location.hostname}:${old.panel_port}${path || '/'}`;
      modal.confirm({
        title: t('settings.tlsRestartTitle'),
        content: t('settings.tlsRestartBody'),
        okText: t('settings.tlsRestartConfirm'),
        cancelText: t('settings.xrayRestartLater'),
        okButtonProps: { danger: true },
        onOk: async () => {
          try {
            await apiClient.post('/settings/panel/restart');
          } catch {
            // The process exits mid-response, so a transport error is expected.
          }
          message.success({ content: t('settings.tlsRestarting', { url }), duration: 10 });
          window.setTimeout(() => {
            window.location.href = url;
          }, 4000);
        },
      });
    },
    onError: (err: unknown) =>
      message.error(apiErrorMessage(err) ?? t('settings.panelSaveError')),
  });

  // Publishes this section's dirty state to the page-level bar.
  useSectionDirtyPublish({ dirty, setDirty, form, mutation, onDirtyChange, qc });

  const data = settingsQuery.data;
  const state = useLoadState([settingsQuery]);
  const tlsBaseline = useMemo(
    () => (data ? {
            panel_tls_enabled: data.panel_tls_enabled,
            panel_tls_cert: data.panel_tls_cert,
            panel_tls_key: '',
          } : {}),
    [data],
  );
  const certPresent = !!data?.panel_tls_cert?.trim();
  const keyPresent = !!data?.panel_tls_key_set;
  const httpsOn = !!data?.panel_tls_enabled;
  return (
    <SectionFrame title={t('settings.tlsSection')}>
      <LoadError state={state} />
      <LoadStale state={state} />
      {data && (
        <Form<TlsFormValues>
          form={form}
          layout="vertical"
          autoComplete="off"
          key={`tls-${data.panel_tls_enabled}-${data.panel_tls_key_set}`}
          initialValues={tlsBaseline}
          disabled={mutation.isPending}
          onValuesChange={() =>
            setDirty(differsFromSaved(form.getFieldsValue(true), tlsBaseline))
          }
          onFinish={(v) => mutation.mutate(v)}
        >
          <FieldGroup>
            <Form.Item
              name="panel_tls_enabled"
              className="app-field-switch"
              label={
                <FieldLabel
                  title={t('settings.tlsEnabled')}
                  desc={t('settings.tlsEnabledHint')}
                />
              }
              valuePropName="checked"
            >
              <RowSwitch />
            </Form.Item>
          </FieldGroup>

          {/* Status ribbon — reflects only what the panel actually knows: is a
              cert stored, is a key stored, is HTTPS active. Domain / issuer /
              expiry / fingerprint would need the backend to parse the stored
              cert, so they're intentionally absent rather than faked. */}
          <div className="app-tls-ribbon" data-active={httpsOn && certPresent}>
            <span className="app-tls-live" data-on={httpsOn} aria-hidden="true" />
            <span className="app-tls-rb-main">
              {certPresent ? t('settings.tlsStatusCertLoaded') : t('settings.tlsStatusCertNone')}
            </span>
            <span className="app-tls-sep" aria-hidden="true">
              ·
            </span>
            <span>{keyPresent ? t('settings.tlsStatusKeySaved') : t('settings.tlsStatusKeyNone')}</span>
            <span className="app-tls-sep" aria-hidden="true">
              ·
            </span>
            <span>{httpsOn ? t('settings.tlsStatusHttpsOn') : t('settings.tlsStatusHttpsOff')}</span>
            {httpsOn && certPresent ? (
              <span className="app-tls-rb-badge">{t('settings.tlsStatusActive')}</span>
            ) : null}
          </div>

          <div className="app-tls-sec">
            <span className="app-tls-sec-title">{t('settings.tlsReplaceTitle')}</span>
            <span className="app-tls-sec-sub">
              {certPresent ? t('settings.tlsReplaceSubHas') : t('settings.tlsReplaceSubNone')}
            </span>
            <span className="app-tls-sec-line" />
          </div>

          <div className="app-tls-pair">
            <Form.Item
              name="panel_tls_cert"
              className="app-tls-fitem"
              extra={t('settings.tlsCertHint')}
              rules={[
                pemRule(t('settings.tlsCertInvalid')),
                ({ getFieldValue }) => ({
                  validator: (_: unknown, v: string) =>
                    getFieldValue('panel_tls_enabled') && !v?.trim()
                      ? Promise.reject(new Error(t('settings.tlsCertRequired')))
                      : Promise.resolve(),
                }),
              ]}
            >
              <PemDropField
                fieldName={t('settings.tlsCert')}
                hintSub={t('settings.tlsDropHint')}
                placeholder={
                  certPresent
                    ? t('settings.tlsCertStoredPlaceholder')
                    : '-----BEGIN CERTIFICATE-----'
                }
                chipText={t('settings.tlsChipReplace')}
                icon={<SafetyCertificateOutlined />}
                disabled={mutation.isPending}
              />
            </Form.Item>
            <Form.Item
              name="panel_tls_key"
              className="app-tls-fitem"
              extra={t('settings.tlsKeyHint')}
              rules={[
                pemRule(t('settings.tlsKeyInvalid')),
                ({ getFieldValue }) => ({
                  validator: (_: unknown, v: string) =>
                    getFieldValue('panel_tls_enabled') && !data.panel_tls_key_set && !v?.trim()
                      ? Promise.reject(new Error(t('settings.tlsKeyRequired')))
                      : Promise.resolve(),
                }),
              ]}
            >
              <PemDropField
                fieldName={t('settings.tlsKey')}
                hintSub={t('settings.tlsDropHint')}
                placeholder={
                  data.panel_tls_key_set
                    ? t('settings.tlsKeyStoredPlaceholder')
                    : '-----BEGIN PRIVATE KEY-----'
                }
                chipText={
                  data.panel_tls_key_set
                    ? t('settings.tlsChipKeySet')
                    : t('settings.tlsChipKeyUnset')
                }
                chipDot={data.panel_tls_key_set}
                icon={<KeyOutlined />}
                disabled={mutation.isPending}
              />
            </Form.Item>
          </div>
        </Form>
      )}
    </SectionFrame>
  );
}
