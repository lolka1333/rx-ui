/**
 * Access — the panel's port and URL prefix, plus this browser's interface
 * preferences (language, page width), which apply at once and are not saved
 * with the panel's settings.
 */
import { App, Form, Input, InputNumber, Select } from 'antd';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useCallback, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { apiClient } from '@/api/client';
import { apiErrorMessage } from '@/api/errors';
import { useLoadState } from '@/api/loadState';
import { LoadError, LoadStale } from '@/components/LoadState';
import { setLocaleAndReload, useLocale } from '@/stores/locale';
import { useLayoutWidth } from '@/stores/layoutWidth';
import { LOCALES } from '@/i18n';
import type { PanelSettings } from '@/api/types';
import { mergePanelSettings } from '@/lib/panelSettings';
import { reportRouting } from '@/lib/routingReport';
import type { RoutingApplyResult } from '@/lib/routingReport';
import { type DirtyHandle, differsFromSaved, useSectionDirtyPublish } from './dirty';
import { SectionFrame, FieldLabel, FieldGroup } from './fields';
import { normaliseClientPrefix } from './prefix';

interface PanelAccessFormValues {
  panel_port: number;
  panel_base_path: string;
}

export function AccessSection({
  onDirtyChange,
}: {
  onDirtyChange: (h: DirtyHandle | null) => void;
}) {
  const { t } = useTranslation();
  const { message } = App.useApp();
  const qc = useQueryClient();
  const [form] = Form.useForm<PanelAccessFormValues>();
  const [dirty, setDirty] = useState(false);

  // Always read the panel's real port/prefix from the backend. We used to
  // seed `initialData` from `window.location` for a synchronous first paint,
  // but the URL lies whenever the panel is reached through a reverse proxy or
  // an SSH tunnel — the browser's port is the tunnel's, not the panel's — so
  // the form showed e.g. the SSH-forwarded port instead of the configured
  // one. The form just waits the ~50ms for the real response instead.
  const settingsQuery = useQuery<PanelSettings>({
    queryKey: ['panel-settings'],
    queryFn: async () => (await apiClient.get<PanelSettings>('/settings/panel')).data,
  });

  const mutation = useMutation({
    mutationFn: async (values: PanelAccessFormValues) => {
      // PUT replaces the whole row; mergePanelSettings forwards every field
      // this section doesn't own (sub_* / xray_*) from the cache so saving the
      // port doesn't reset them.
      // Read the cache at SEND time, not from the render closure: with two
      // sections dirty, the second save would otherwise merge a snapshot
      // taken before the first one landed and revert its fields.
      const current =
        qc.getQueryData<PanelSettings>(['panel-settings']) ?? settingsQuery.data;
      const res = await apiClient.put<RoutingApplyResult>(
        '/settings/panel',
        mergePanelSettings(current, {
          panel_port: values.panel_port,
          panel_base_path: values.panel_base_path,
        }),
      );
      return { values, routing: res.data ?? {} };
    },
    onSuccess: ({ values, routing }) => {
      const report = reportRouting(routing, message, t);
      // Compare against the panel's real old port (from the backend), not the
      // browser's — under a proxy/tunnel they differ, and using the browser
      // port made an unchanged save look like a port change.
      const oldPort = settingsQuery.data?.panel_port;
      const oldPath = settingsQuery.data?.panel_base_path ?? '';
      qc.invalidateQueries({ queryKey: ['panel-settings'] });
      setDirty(false);
      const normalisedPath = normaliseClientPrefix(values.panel_base_path);
      const portChanged = oldPort != null && values.panel_port !== oldPort;
      const pathChanged = normalisedPath !== oldPath;
      if (portChanged || pathChanged) {
        // No trailing slash on a prefix (`/secret`, not `/secret/`) — the SPA
        // is served at the no-slash form and the injected <base href> handles
        // relative resolution. Root collapses to `/`.
        const newUrl = `${window.location.protocol}//${window.location.hostname}:${values.panel_port}${normalisedPath || '/'}`;
        // Don't auto-navigate on top of a routing warning: the reload takes it
        // off screen after 2.5s and the operator never learns their rules aren't
        // live. But then the copy has to change too — the listener has ALREADY
        // moved, so promising a redirect that isn't coming would leave them
        // waiting on a page whose address no longer serves the panel.
        message.success({
          // antd message notices have no close affordance of their own, so the
          // never-expiring variant gets a click handler — otherwise it sits over
          // the page until a reload.
          key: 'panel-moved',
          onClick: () => message.destroy('panel-moved'),
          content:
            report === 'clean'
              ? t('settings.panelSavedHotRedirect', { url: newUrl })
              : t('settings.panelSavedMoved', { url: newUrl }),
          duration: report === 'clean' ? 6 : 0,
        });
        if (report === 'clean') {
          window.setTimeout(() => {
            window.location.href = newUrl;
          }, 2500);
        }
      } else if (report === 'clean') {
        message.success(t('settings.panelSaved'));
      }
    },
    onError: (err: unknown) =>
      message.error(apiErrorMessage(err) ?? t('settings.panelSaveError')),
  });

  // Publishes this section's dirty state to the page-level bar.
  useSectionDirtyPublish({ dirty, setDirty, form, mutation, onDirtyChange, qc });

  // `settingsQuery.data` lands a moment after the /api/settings/panel
  // response. Skip the form entirely until then — no skeleton, no
  // placeholder, just empty space for ~50ms (and never a wrong port).
  const data = settingsQuery.data;
  const state = useLoadState([settingsQuery]);
  const accessBaseline = useMemo(
    () => (data ? {
            panel_port: data.panel_port,
            panel_base_path: data.panel_base_path,
          } : {}),
    [data],
  );
  return (
    <SectionFrame title={t('settings.panelSection')}>
      <LoadError state={state} />
      <LoadStale state={state} />
      {data && (
        <Form<PanelAccessFormValues>
          form={form}
          layout="vertical"
          autoComplete="off"
          key={`${data.panel_port}-${data.panel_base_path}`}
          initialValues={accessBaseline}
          disabled={mutation.isPending}
          onValuesChange={() =>
            setDirty(differsFromSaved(form.getFieldsValue(true), accessBaseline))
          }
          onFinish={(v) => mutation.mutate(v)}
        >
          <FieldGroup title={t('settings.accessGroupPanel')}>
            <Form.Item
              name="panel_port"
              label={
                <FieldLabel
                  title={t('settings.panelPort')}
                  desc={t('settings.panelPortHint')}
                />
              }
              rules={[
                { required: true, message: t('settings.panelPortRequired') },
                {
                  type: 'number',
                  min: 1,
                  max: 65535,
                  message: t('settings.panelPortRange'),
                },
              ]}
            >
              <InputNumber min={1} max={65535} />
            </Form.Item>
            <Form.Item
              name="panel_base_path"
              label={
                <FieldLabel
                  title={t('settings.panelBasePath')}
                  desc={t('settings.panelBasePathHint')}
                />
              }
            >
              <Input placeholder={t('settings.panelBasePathPlaceholder')} />
            </Form.Item>
          </FieldGroup>
        </Form>
      )}
      {/* Language picker lives in the same section but OUTSIDE the form:
          locale is a per-browser preference persisted in localStorage by
          `useLocale`, not a server-side panel setting, so it skips the
          dirty-bar / Save flow and applies immediately on change. */}
      {data && <InterfacePrefs />}
    </SectionFrame>
  );
}

/**
 * Standalone interface preferences at the bottom of the Access section:
 * language (via `setLocaleAndReload`, which owns the write-storage-then-reload
 * rationale) and how wide the page may run. Both live OUTSIDE the access form
 * so the dirty bar doesn't touch them — they apply the moment they change and
 * belong to this browser, not to the panel's stored settings.
 */
function InterfacePrefs() {
  const { t } = useTranslation();
  const locale = useLocale((s) => s.locale);
  const width = useLayoutWidth((s) => s.width);
  const setWidth = useLayoutWidth((s) => s.set);
  const onChange = useCallback(
    (next: typeof locale) => {
      if (next !== locale) setLocaleAndReload(next);
    },
    [locale],
  );
  return (
    <FieldGroup title={t('settings.interfaceGroup')}>
      <div className="app-settings-plaque">
        <FieldLabel title={t('settings.language')} desc={t('settings.languageHint')} />
        <div className="app-settings-plaque-control">
          <Select
            value={locale}
            onChange={onChange}
            options={LOCALES.map((l) => ({ value: l.value, label: l.label }))}
          />
        </div>
      </div>
      <div className="app-settings-plaque">
        <FieldLabel title={t('settings.pageWidth')} desc={t('settings.pageWidthHint')} />
        <div className="app-settings-plaque-control">
          <Select
            value={width}
            onChange={setWidth}
            options={[
              { value: 'normal', label: t('settings.pageWidthNormal') },
              { value: 'wide', label: t('settings.pageWidthWide') },
              { value: 'full', label: t('settings.pageWidthFull') },
            ]}
          />
        </div>
      </div>
    </FieldGroup>
  );
}
