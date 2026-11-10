/**
 * Subscription — how users get their subscription URL: the switch, the hosts
 * that go into links, the update interval, the name and link client apps show,
 * and the subscription's own port and TLS.
 */
import { App, Form, Input, InputNumber, Select } from 'antd';
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

interface SubscriptionFormValues {
  sub_enabled: boolean;
  sub_host_override: string;
  sub_link_host: string;
  sub_update_interval_hours: number;
  sub_brand_name: string;
  sub_service_url: string;
  sub_port: number;
  sub_tls_mode: string;
  sub_cert_pem: string;
  sub_key_pem: string;
}

export function SubscriptionSection({
  onDirtyChange,
}: {
  onDirtyChange: (h: DirtyHandle | null) => void;
}) {
  const { t } = useTranslation();
  const { message } = App.useApp();
  const qc = useQueryClient();
  const [form] = Form.useForm<SubscriptionFormValues>();
  const [dirty, setDirty] = useState(false);

  // Reuse the `panel-settings` query — `AccessSection` already populates
  // it on first paint, so we get a free cache hit. Keeps the two
  // sections in sync if either one writes (both invalidate the same
  // key on save).
  const settingsQuery = useQuery<PanelSettings>({
    queryKey: ['panel-settings'],
    queryFn: async () => (await apiClient.get<PanelSettings>('/settings/panel')).data,
  });

  const mutation = useMutation({
    mutationFn: async (values: SubscriptionFormValues) => {
      // PUT replaces the whole row; mergePanelSettings forwards the panel /
      // xray fields from the cache so a subscription save doesn't clobber them.
      // Read the cache at SEND time, not from the render closure: with two
      // sections dirty, the second save would otherwise merge a snapshot
      // taken before the first one landed and revert its fields.
      const current =
        qc.getQueryData<PanelSettings>(['panel-settings']) ?? settingsQuery.data;
      const res = await apiClient.put<RoutingApplyResult>(
        '/settings/panel',
        mergePanelSettings(current, {
          sub_enabled: values.sub_enabled,
          sub_host_override: values.sub_host_override.trim(),
          sub_link_host: values.sub_link_host.trim(),
          sub_update_interval_hours: values.sub_update_interval_hours,
          sub_brand_name: values.sub_brand_name.trim(),
          sub_service_url: values.sub_service_url.trim(),
          sub_port: values.sub_port,
          sub_tls_mode: values.sub_tls_mode,
          // The cert/key Form.Items are only mounted in 'custom' mode, so antd
          // omits them from `values` (undefined) in inherit/off — optional-chain
          // to avoid a crash, and empty ≡ keep the stored pair (backend
          // keep-stored) so a non-custom save can't wipe a stored cert/key.
          sub_cert_pem: values.sub_cert_pem?.trim() ?? '',
          sub_key_pem: values.sub_key_pem?.trim() ?? '',
        }),
      );
      return res.data ?? {};
    },
    onSuccess: (routing) => {
      const report = reportRouting(routing, message, t);
      // Clear the key input after save (like TlsSection): the key is now stored,
      // and the form only re-inits when sub_key_set flips — replacing an
      // already-stored key wouldn't otherwise reset the textarea, leaving the
      // pasted key visible and re-sent on the next save.
      form.setFieldValue('sub_key_pem', '');
      qc.invalidateQueries({ queryKey: ['panel-settings'] });
      setDirty(false);
      if (report === 'clean') message.success(t('settings.subscriptionSaved'));
    },
    onError: (err: unknown) =>
      message.error(apiErrorMessage(err) ?? t('settings.subscriptionSaveError')),
  });

  // Publishes this section's dirty state to the page-level bar.
  useSectionDirtyPublish({ dirty, setDirty, form, mutation, onDirtyChange, qc });

  const data = settingsQuery.data;
  const state = useLoadState([settingsQuery]);
  const subBaseline = useMemo(
    () => (data ? {
            sub_enabled: data.sub_enabled,
            sub_host_override: data.sub_host_override,
            sub_link_host: data.sub_link_host,
            sub_update_interval_hours: data.sub_update_interval_hours,
            sub_brand_name: data.sub_brand_name,
            sub_service_url: data.sub_service_url,
            sub_port: data.sub_port,
            sub_tls_mode: data.sub_tls_mode,
            sub_cert_pem: data.sub_cert_pem,
            sub_key_pem: '',
          } : {}),
    [data],
  );
  return (
    <SectionFrame title={t('settings.sectionSubscription')}>
      <LoadError state={state} />
      <LoadStale state={state} />
      {data && (
        <Form<SubscriptionFormValues>
          form={form}
          layout="vertical"
          autoComplete="off"
          key={`${data.sub_enabled}-${data.sub_host_override}-${data.sub_link_host}-${data.sub_update_interval_hours}-${data.sub_brand_name}-${data.sub_service_url}-${data.sub_port}-${data.sub_tls_mode}-${data.sub_key_set}`}
          initialValues={subBaseline}
          disabled={mutation.isPending}
          onValuesChange={() =>
            setDirty(differsFromSaved(form.getFieldsValue(true), subBaseline))
          }
          onFinish={(v) => mutation.mutate(v)}
        >
          <FieldGroup>
            <Form.Item
              name="sub_enabled"
              className="app-field-switch"
              label={
                <FieldLabel
                  title={t('settings.subEnabled')}
                  desc={t('settings.subEnabledHint')}
                />
              }
              valuePropName="checked"
            >
              <RowSwitch />
            </Form.Item>
          </FieldGroup>

          {/* Watch the toggle so the dependent fields grey out when
              subscriptions are off — they keep their stored value
              (so flipping the switch back on restores the config),
              just become read-only while disabled. One watcher wraps both
              groups since every dependent field shares the same gate. */}
          <Form.Item
            shouldUpdate={(p, n) =>
              p.sub_enabled !== n.sub_enabled || p.sub_port !== n.sub_port
            }
            noStyle
          >
            {({ getFieldValue }) => {
              const enabled = getFieldValue('sub_enabled') as boolean;
              // TLS below configures the DEDICATED subscription listener, and
              // that listener only exists at a non-zero port. At port 0 the
              // /sub/ routes are served by the panel's own listener on the
              // panel's own TLS, so a mode picked here would govern nothing
              // while the share link kept promising its scheme.
              const ownListener = enabled && (getFieldValue('sub_port') as number) > 0;
              return (
                <>
                  <FieldGroup title={t('settings.subGroupConnection')}>
                    <Form.Item
                      name="sub_host_override"
                      label={
                        <FieldLabel
                          title={t('settings.subHostOverride')}
                          desc={t('settings.subHostOverrideHint')}
                        />
                      }
                      rules={[
                        {
                          // Bare hostname / IPv4 / bracketed-IPv6 only — no
                          // scheme, path, or whitespace. Same constraint the
                          // backend enforces server-side; surfacing it as a
                          // form rule shows the error inline before submit.
                          pattern: /^(?:[A-Za-z0-9.\-:[\]]+)?$/,
                          message: t('settings.subHostOverrideInvalid'),
                        },
                      ]}
                    >
                      <Input
                        placeholder={t('settings.subHostOverridePlaceholder')}
                        disabled={!enabled}
                      />
                    </Form.Item>
                    <Form.Item
                      name="sub_link_host"
                      label={
                        <FieldLabel
                          title={t('settings.subLinkHost')}
                          desc={t('settings.subLinkHostHint')}
                        />
                      }
                      rules={[
                        {
                          // Same bare-host constraint as the connection address
                          // above; this one is the host of the /sub/ URL itself.
                          pattern: /^(?:[A-Za-z0-9.\-:[\]]+)?$/,
                          message: t('settings.subHostOverrideInvalid'),
                        },
                      ]}
                    >
                      <Input
                        placeholder={t('settings.subLinkHostPlaceholder')}
                        disabled={!enabled}
                      />
                    </Form.Item>
                    <Form.Item
                      name="sub_port"
                      label={
                        <FieldLabel
                          title={t('settings.subPort')}
                          desc={t('settings.subPortHint')}
                        />
                      }
                      // 0 is how the API spells "no dedicated port". On screen
                      // that is an empty field rather than a lone 0, and
                      // clearing the field stores 0 again — so the saved value,
                      // the dirty check and the TLS gate below all still see 0.
                      getValueProps={(v: number | null) => ({ value: v === 0 ? null : v })}
                      normalize={(v: number | null) => v ?? 0}
                      rules={[
                        {
                          validator: (_, v: number) => {
                            if (v === 0) return Promise.resolve();
                            if (!Number.isInteger(v) || v < 1 || v > 65535) {
                              return Promise.reject(new Error(t('settings.subPortRange')));
                            }
                            return Promise.resolve();
                          },
                        },
                      ]}
                    >
                      <InputNumber
                        min={0}
                        max={65535}
                        disabled={!enabled}
                        placeholder={t('settings.subPortPlaceholder')}
                      />
                    </Form.Item>
                    <Form.Item
                      name="sub_tls_mode"
                      label={
                        <FieldLabel
                          title={t('settings.subTlsMode')}
                          // Locked is the common case (the port defaults to 0),
                          // so the row says why instead of leaving the operator
                          // to guess what greyed it out.
                          desc={
                            ownListener
                              ? t('settings.subTlsModeHint')
                              : t('settings.subTlsModeLocked')
                          }
                        />
                      }
                    >
                      <Select
                        disabled={!ownListener}
                        options={[
                          { value: 'inherit', label: t('settings.subTlsInherit') },
                          { value: 'off', label: t('settings.subTlsOff') },
                          { value: 'custom', label: t('settings.subTlsCustom') },
                        ]}
                      />
                    </Form.Item>
                    <Form.Item
                      noStyle
                      shouldUpdate={(p, n) => p.sub_tls_mode !== n.sub_tls_mode}
                    >
                      {({ getFieldValue }) => (
                        // Same pair of drop targets as the Security tab, and
                        // revealed rather than snapped in — in BOTH directions.
                        // The block stays mounted and is collapsed by CSS
                        // instead of being conditionally rendered: `{cond &&
                        // <Block/>}` tears the node out the instant cond turns
                        // false, leaving nothing to animate on the way out.
                        // antd preserves field values across this either way,
                        // and both validators are already gated on the mode, so
                        // a collapsed pair stays quiet.
                        //
                        // `inert` is what makes "collapsed" mean collapsed for
                        // the keyboard too: the CSS collapse (0fr + opacity +
                        // overflow) hides the block but leaves its two
                        // textareas focusable, so tabbing through the tab put
                        // the caret in an invisible field.
                        <div
                          className={`app-reveal${
                            getFieldValue('sub_tls_mode') === 'custom' ? ' is-in' : ''
                          }`}
                          inert={getFieldValue('sub_tls_mode') !== 'custom'}
                        >
                          <div className="app-tls-pair">
                            <Form.Item
                              name="sub_cert_pem"
                              className="app-tls-fitem"
                              extra={t('settings.tlsCertHint')}
                              rules={[
                                pemRule(t('settings.tlsCertInvalid')),
                                ({ getFieldValue: g }) => ({
                                  validator: (_: unknown, v: string) =>
                                    g('sub_tls_mode') === 'custom' && !v?.trim()
                                      ? Promise.reject(
                                          new Error(t('settings.subTlsCertRequired')),
                                        )
                                      : Promise.resolve(),
                                }),
                              ]}
                            >
                              <PemDropField
                                fieldName={t('settings.subTlsCert')}
                                hintSub={t('settings.tlsDropHint')}
                                placeholder={
                                  data.sub_cert_pem.trim()
                                    ? t('settings.tlsCertStoredPlaceholder')
                                    : '-----BEGIN CERTIFICATE-----'
                                }
                                chipText={t('settings.tlsChipReplace')}
                                icon={<SafetyCertificateOutlined />}
                                disabled={!enabled}
                              />
                            </Form.Item>
                            <Form.Item
                              name="sub_key_pem"
                              className="app-tls-fitem"
                              extra={t('settings.tlsKeyHint')}
                              rules={[
                                pemRule(t('settings.tlsKeyInvalid')),
                                ({ getFieldValue: g }) => ({
                                  validator: (_: unknown, v: string) =>
                                    g('sub_tls_mode') === 'custom' &&
                                    !data.sub_key_set &&
                                    !v?.trim()
                                      ? Promise.reject(
                                          new Error(t('settings.subTlsKeyRequired')),
                                        )
                                      : Promise.resolve(),
                                }),
                              ]}
                            >
                              <PemDropField
                                fieldName={t('settings.subTlsKey')}
                                hintSub={t('settings.tlsDropHint')}
                                placeholder={
                                  data.sub_key_set
                                    ? t('settings.tlsKeyStoredPlaceholder')
                                    : '-----BEGIN PRIVATE KEY-----'
                                }
                                chipText={
                                  data.sub_key_set
                                    ? t('settings.tlsChipKeySet')
                                    : t('settings.tlsChipKeyUnset')
                                }
                                chipDot={data.sub_key_set}
                                icon={<KeyOutlined />}
                                disabled={!enabled}
                              />
                            </Form.Item>
                          </div>
                        </div>
                      )}
                    </Form.Item>
                    <Form.Item
                      name="sub_update_interval_hours"
                      label={
                        <FieldLabel
                          title={t('settings.subUpdateInterval')}
                          desc={t('settings.subUpdateIntervalHint')}
                        />
                      }
                      rules={[
                        {
                          required: true,
                          message: t('settings.subUpdateIntervalRequired'),
                        },
                        {
                          type: 'number',
                          min: 1,
                          max: 168,
                          message: t('settings.subUpdateIntervalRange'),
                        },
                      ]}
                    >
                      <InputNumber min={1} max={168} disabled={!enabled} />
                    </Form.Item>
                  </FieldGroup>
                  <FieldGroup title={t('settings.subGroupBranding')}>
                    <Form.Item
                      name="sub_brand_name"
                      label={
                        <FieldLabel
                          title={t('settings.subBrandName')}
                          desc={t('settings.subBrandNameHint')}
                        />
                      }
                      rules={[
                        {
                          max: 60,
                          message: t('settings.subBrandNameTooLong'),
                        },
                      ]}
                    >
                      <Input
                        placeholder={t('settings.subBrandNamePlaceholder')}
                        disabled={!enabled}
                        maxLength={60}
                      />
                    </Form.Item>
                    <Form.Item
                      name="sub_service_url"
                      label={
                        <FieldLabel
                          title={t('settings.subServiceUrl')}
                          desc={t('settings.subServiceUrlHint')}
                        />
                      }
                      rules={[
                        {
                          validator: (_, v: string) => {
                            if (!v) return Promise.resolve();
                            if (!/^https?:\/\//.test(v)) {
                              return Promise.reject(new Error(t('settings.subServiceUrlInvalid')));
                            }
                            if (v.length > 2048) {
                              return Promise.reject(new Error(t('settings.subServiceUrlTooLong')));
                            }
                            return Promise.resolve();
                          },
                        },
                      ]}
                    >
                      <Input
                        placeholder={t('settings.subServiceUrlPlaceholder')}
                        disabled={!enabled}
                      />
                    </Form.Item>
                  </FieldGroup>
                </>
              );
            }}
          </Form.Item>
        </Form>
      )}
    </SectionFrame>
  );
}
