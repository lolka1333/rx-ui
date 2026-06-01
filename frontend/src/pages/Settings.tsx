/**
 * Settings page — single long scroll, GitHub-style.
 *
 * Every section lives on the page at the same time, stacked
 * vertically with hairline dividers between them. There is no
 * navigation: the operator reads top-to-bottom (or jumps with the
 * browser scrollbar) and edits in place. The page-level DirtyBar
 * floats at the top while any section has unsaved changes, so the
 * operator can scroll, edit several sections, then save them all
 * in one click.
 */
import {
  App,
  Button,
  Col,
  Form,
  Input,
  InputNumber,
  Row,
  Select,
  Switch,
  Typography,
} from 'antd';
import { LogoutOutlined } from '@ant-design/icons';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import type { ReactNode } from 'react';
import { useCallback, useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { apiClient } from '@/api/client';
import { apiErrorMessage } from '@/api/errors';
import { useAuth } from '@/stores/auth';
import { useLocale } from '@/stores/locale';
import { LOCALES } from '@/i18n';
import type { PanelSettings } from '@/api/types';

type SectionKey = 'account' | 'access' | 'subscription';

/** Fallback values for the subscription side of `PanelSettings`, used by:
 *   1) the AccessSection mutation when it can't read the current
 *      subscription-side values from the cache (e.g. initial-render
 *      race) but still has to PUT them as part of the whole-row replace,
 *   2) the SubscriptionSection mutation for the same reason, in reverse,
 *   3) `deriveSettingsFromUrl` for the not-yet-loaded-from-backend state.
 *  Keep these in sync with the backend defaults in
 *  `backend/migrations/0024_subscription_settings.sql` +
 *  `0025_subscription_enabled.sql`. */
const SUBSCRIPTION_DEFAULTS = {
  sub_enabled: true,
  sub_host_override: '',
  sub_update_interval_hours: 12,
  sub_brand_name: '',
  sub_service_url: '',
  sub_port: 0,
} as const;

interface CredentialsFormValues {
  current_password: string;
  new_username: string;
  new_password: string;
  new_password_confirm: string;
}

interface PanelAccessFormValues {
  panel_port: number;
  panel_base_path: string;
}

interface SubscriptionFormValues {
  sub_enabled: boolean;
  sub_host_override: string;
  sub_update_interval_hours: number;
  sub_brand_name: string;
  sub_service_url: string;
  sub_port: number;
}

interface DirtyHandle {
  saving: boolean;
  onSave: () => void;
  onDiscard: () => void;
}

export function Settings() {
  // Page-level dirty registry. Sections publish handles by key so
  // the bar can save / discard everything at once with a single
  // click, no matter how many sections the operator has touched.
  const [dirtyHandles, setDirtyHandles] = useState<
    Partial<Record<SectionKey, DirtyHandle>>
  >({});
  const setDirty = useCallback(
    (key: SectionKey, handle: DirtyHandle | null) => {
      setDirtyHandles((prev) => {
        if (handle === null) {
          if (!prev[key]) return prev;
          const next = { ...prev };
          delete next[key];
          return next;
        }
        return { ...prev, [key]: handle };
      });
    },
    [],
  );
  const dirtyCount = Object.keys(dirtyHandles).length;
  const anySaving = Object.values(dirtyHandles).some((h) => h?.saving);
  const saveAll = useCallback(() => {
    for (const h of Object.values(dirtyHandles)) h?.onSave();
  }, [dirtyHandles]);
  const discardAll = useCallback(() => {
    for (const h of Object.values(dirtyHandles)) h?.onDiscard();
  }, [dirtyHandles]);

  // Stable per-section callbacks. Inline arrows in JSX would create
  // a new function reference on every render, which propagates as
  // a changed `onDirtyChange` prop to each section and re-fires
  // their useEffect → republishes the handle → infinite loop.
  // useCallback locks the reference until `setDirty` itself changes
  // (which it doesn't — it's already useCallback'd above with [] deps).
  const onAccountDirty = useCallback(
    (h: DirtyHandle | null) => setDirty('account', h),
    [setDirty],
  );
  const onAccessDirty = useCallback(
    (h: DirtyHandle | null) => setDirty('access', h),
    [setDirty],
  );
  const onSubscriptionDirty = useCallback(
    (h: DirtyHandle | null) => setDirty('subscription', h),
    [setDirty],
  );

  return (
    <div className="app-content-reveal app-settings-page">
      <DirtyBar
        visible={dirtyCount > 0}
        saving={anySaving}
        count={dirtyCount}
        onSave={saveAll}
        onDiscard={discardAll}
      />

      <AccountSection onDirtyChange={onAccountDirty} />
      <hr className="app-settings-divider" />
      <AccessSection onDirtyChange={onAccessDirty} />
      <hr className="app-settings-divider" />
      <SubscriptionSection onDirtyChange={onSubscriptionDirty} />
      <hr className="app-settings-divider" />
      <SessionSection />
    </div>
  );
}

/**
 * Vertical-flow section header + body wrapper. Title sits at H3,
 * description below in muted secondary text, then the body (form,
 * info block, etc.) underneath. Max-width on the form column so
 * inputs don't stretch into "punch-card" territory on wide displays.
 */
function SectionFrame({
  title,
  description,
  children,
}: {
  title: string;
  description?: string;
  children: React.ReactNode;
}) {
  return (
    <section className="app-settings-section">
      <Typography.Title level={3} style={{ marginTop: 0, marginBottom: 4 }}>
        {title}
      </Typography.Title>
      {description && (
        <Typography.Paragraph type="secondary" style={{ marginBottom: 20 }}>
          {description}
        </Typography.Paragraph>
      )}
      <div style={{ maxWidth: 760 }}>{children}</div>
    </section>
  );
}

// =============================================================================
// Account — change username / password
// =============================================================================

function AccountSection({
  onDirtyChange,
}: {
  onDirtyChange: (h: DirtyHandle | null) => void;
}) {
  const { t } = useTranslation();
  const { message } = App.useApp();
  const logout = useAuth((s) => s.logout);
  const currentUsername = useAuth((s) => s.user?.username ?? '');
  const [form] = Form.useForm<CredentialsFormValues>();
  const [dirty, setDirty] = useState(false);

  const mutation = useMutation({
    mutationFn: async (values: CredentialsFormValues) => {
      const newUsername = values.new_username.trim();
      const newPassword = values.new_password;
      await apiClient.post('/auth/credentials', {
        current_password: values.current_password,
        new_username: newUsername || null,
        new_password: newPassword || null,
      });
    },
    onSuccess: () => {
      message.success(t('settings.credentialsUpdated'));
      logout();
    },
    onError: (err: unknown) =>
      message.error(apiErrorMessage(err) ?? t('settings.credentialsError')),
  });

  useEffect(() => {
    onDirtyChange(
      dirty
        ? {
            saving: mutation.isPending,
            onSave: () => form.submit(),
            onDiscard: () => {
              form.resetFields();
              setDirty(false);
            },
          }
        : null,
    );
  }, [dirty, mutation.isPending, form, onDirtyChange]);

  return (
    <SectionFrame
      title={t('settings.accountSection')}
      description={t('settings.accountHint')}
    >
      <Form<CredentialsFormValues>
        form={form}
        layout="vertical"
        autoComplete="off"
        onFinish={(v) => mutation.mutate(v)}
        onValuesChange={() => setDirty(true)}
        initialValues={{
          current_password: '',
          new_username: '',
          new_password: '',
          new_password_confirm: '',
        }}
        disabled={mutation.isPending}
      >
        <Row gutter={24}>
          <Col xs={24} sm={12}>
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              {t('settings.colCurrent')}
            </Typography.Text>
            <div style={{ height: 8 }} />
            {/* Read-only "current username" line. Not wrapped in Form.Item
                because the field isn't registered with the form (no `name=`):
                antd's generated <label> ends up orphan and the disabled
                <Input> ends up id-less, both of which Chrome's accessibility
                audit flags. Plain <label htmlFor> + a regular <Input id>
                gives the same visual and a valid label-to-control link. */}
            <div style={{ marginBottom: 24 }}>
              <label
                htmlFor="settings-current-username"
                style={{ display: 'block', marginBottom: 8 }}
              >
                {t('settings.currentUsername')}
              </label>
              <Input
                id="settings-current-username"
                value={currentUsername}
                disabled
              />
            </div>
            <Form.Item
              name="current_password"
              label={t('settings.currentPassword')}
              rules={[
                { required: true, message: t('settings.currentPasswordRequired') },
              ]}
              style={{ marginBottom: 0 }}
            >
              <Input.Password autoComplete="current-password" />
            </Form.Item>
          </Col>
          <Col xs={24} sm={12}>
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              {t('settings.colNew')}
            </Typography.Text>
            <div style={{ height: 8 }} />
            <Form.Item
              name="new_username"
              label={t('settings.newUsername')}
              tooltip={t('settings.newUsernameHint')}
            >
              <Input autoComplete="off" placeholder={currentUsername} />
            </Form.Item>
            <Form.Item
              name="new_password"
              label={t('settings.newPassword')}
              tooltip={t('settings.newPasswordHint')}
              rules={[{ min: 4, message: t('settings.newPasswordTooShort') }]}
            >
              <Input.Password autoComplete="new-password" />
            </Form.Item>
            <Form.Item
              name="new_password_confirm"
              label={t('settings.newPasswordConfirm')}
              dependencies={['new_password']}
              rules={[
                ({ getFieldValue }) => ({
                  validator(_, value) {
                    const pw = getFieldValue('new_password') as string;
                    if (!pw && !value) return Promise.resolve();
                    if (pw === value) return Promise.resolve();
                    return Promise.reject(
                      new Error(t('settings.newPasswordMismatch')),
                    );
                  },
                }),
              ]}
              style={{ marginBottom: 0 }}
            >
              <Input.Password autoComplete="new-password" />
            </Form.Item>
          </Col>
        </Row>
      </Form>
    </SectionFrame>
  );
}

// =============================================================================
// Access — change panel port + URL prefix
// =============================================================================

function AccessSection({
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
      // PUT replaces the whole panel_settings row, so we forward the
      // current subscription-side values verbatim. Without this the
      // operator changing the panel port would silently reset the
      // subscription host override.
      const current = settingsQuery.data;
      await apiClient.put('/settings/panel', {
        panel_port: values.panel_port,
        panel_base_path: values.panel_base_path,
        sub_enabled: current?.sub_enabled ?? SUBSCRIPTION_DEFAULTS.sub_enabled,
        sub_host_override:
          current?.sub_host_override ?? SUBSCRIPTION_DEFAULTS.sub_host_override,
        sub_update_interval_hours:
          current?.sub_update_interval_hours ??
          SUBSCRIPTION_DEFAULTS.sub_update_interval_hours,
        sub_brand_name:
          current?.sub_brand_name ?? SUBSCRIPTION_DEFAULTS.sub_brand_name,
        sub_service_url:
          current?.sub_service_url ?? SUBSCRIPTION_DEFAULTS.sub_service_url,
        sub_port: current?.sub_port ?? SUBSCRIPTION_DEFAULTS.sub_port,
      });
      return values;
    },
    onSuccess: (values) => {
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
      // The browser's port differs from the panel's when we're reached via a
      // reverse proxy or SSH tunnel. A `localhost:<new-port>` redirect would
      // then point at an address the browser can't reach, so only auto-redirect
      // on direct access; behind a proxy just tell the operator where it moved.
      const browserPort = window.location.port
        ? Number(window.location.port)
        : window.location.protocol === 'https:'
          ? 443
          : 80;
      const behindProxy = oldPort != null && browserPort !== oldPort;
      if (portChanged || pathChanged) {
        if (behindProxy) {
          message.success({
            content: t('settings.panelSavedProxyNote', {
              port: values.panel_port,
              path: normalisedPath || '/',
            }),
            duration: 8,
          });
        } else {
          const newUrl = `${window.location.protocol}//${window.location.hostname}:${values.panel_port}${normalisedPath}/`;
          message.success({
            content: t('settings.panelSavedHotRedirect', { url: newUrl }),
            duration: 6,
          });
          window.setTimeout(() => {
            window.location.href = newUrl;
          }, 2500);
        }
      } else {
        message.success(t('settings.panelSaved'));
      }
    },
    onError: (err: unknown) =>
      message.error(apiErrorMessage(err) ?? t('settings.panelSaveError')),
  });

  useEffect(() => {
    onDirtyChange(
      dirty
        ? {
            saving: mutation.isPending,
            onSave: () => form.submit(),
            onDiscard: () => {
              form.resetFields();
              setDirty(false);
            },
          }
        : null,
    );
  }, [dirty, mutation.isPending, form, onDirtyChange]);

  // `settingsQuery.data` lands a moment after the /api/settings/panel
  // response. Skip the form entirely until then — no skeleton, no
  // placeholder, just empty space for ~50ms (and never a wrong port).
  const data = settingsQuery.data;
  return (
    <SectionFrame
      title={t('settings.panelSection')}
      description={t('settings.panelSettingsHotHint')}
    >
      {data && (
        <Form<PanelAccessFormValues>
          form={form}
          layout="vertical"
          autoComplete="off"
          className="app-settings-fade-in"
          key={`${data.panel_port}-${data.panel_base_path}`}
          initialValues={{
            panel_port: data.panel_port,
            panel_base_path: data.panel_base_path,
          }}
          disabled={mutation.isPending}
          onValuesChange={() => setDirty(true)}
          onFinish={(v) => mutation.mutate(v)}
        >
          <Row gutter={24}>
            <Col xs={24} sm={12}>
              <Form.Item
                name="panel_port"
                label={t('settings.panelPort')}
                tooltip={t('settings.panelPortHint')}
                rules={[
                  { required: true, message: t('settings.panelPortRequired') },
                  {
                    type: 'number',
                    min: 1,
                    max: 65535,
                    message: t('settings.panelPortRange'),
                  },
                ]}
                style={{ marginBottom: 0 }}
              >
                <InputNumber min={1} max={65535} style={{ width: '100%' }} />
              </Form.Item>
            </Col>
            <Col xs={24} sm={12}>
              <Form.Item
                name="panel_base_path"
                label={t('settings.panelBasePath')}
                tooltip={t('settings.panelBasePathHint')}
                style={{ marginBottom: 0 }}
              >
                <Input placeholder={t('settings.panelBasePathPlaceholder')} />
              </Form.Item>
            </Col>
          </Row>
        </Form>
      )}
      {/* Language picker lives in the same section but OUTSIDE the form:
          locale is a per-browser preference persisted in localStorage by
          `useLocale`, not a server-side panel setting, so it skips the
          dirty-bar / Save flow and applies immediately on change. */}
      {data && <LanguagePicker />}
    </SectionFrame>
  );
}

/**
 * Standalone language picker rendered at the bottom of the Access section.
 * Writes the chosen locale straight to the localStorage key `useLocale`
 * reads from, then triggers a full page reload so the entire panel
 * re-boots in the new language. Bypasses the zustand setter on purpose:
 * calling it would notify subscribers and cause React to repaint the
 * tree with the new translations BEFORE the reload, which looked like a
 * jarring "snap then reload" two-stage transition. Writing storage
 * directly + reloading gives the operator a single clean transition —
 * click, browser reload spinner, fresh page on the new language.
 * Sits OUTSIDE the access form so the dirty-bar doesn't touch it.
 */
function LanguagePicker() {
  const { t } = useTranslation();
  const locale = useLocale((s) => s.locale);
  const setLocale = useLocale((s) => s.set);
  const onChange = useCallback(
    (next: typeof locale) => {
      if (next === locale) return;
      // Zustand/persist storage shape is `{state:{...}, version:0}`.
      // Merge into existing state so we don't clobber any future fields.
      try {
        const raw = localStorage.getItem('app-locale');
        const parsed = raw ? (JSON.parse(raw) as { state?: unknown; version?: number }) : {};
        const state = (parsed.state as Record<string, unknown> | undefined) ?? {};
        localStorage.setItem(
          'app-locale',
          JSON.stringify({
            state: { ...state, locale: next },
            version: parsed.version ?? 0,
          }),
        );
      } catch {
        // localStorage unavailable (private mode / quota) — fall back to
        // the zustand path. The reload still fires below so the operator
        // gets the new language one way or another.
        setLocale(next);
      }
      window.location.reload();
    },
    [locale, setLocale],
  );
  return (
    <div style={{ marginTop: 28, maxWidth: 320 }}>
      <Typography.Text style={{ display: 'block', marginBottom: 8 }}>
        {t('settings.language')}
      </Typography.Text>
      <Select
        value={locale}
        onChange={onChange}
        options={LOCALES.map((l) => ({ value: l.value, label: l.label }))}
        style={{ width: '100%' }}
      />
    </div>
  );
}

// =============================================================================
// Session — show JWT expiry, sign-out button
// =============================================================================

function SessionSection() {
  const { t } = useTranslation();
  const logout = useAuth((s) => s.logout);
  const authToken = useAuth((s) => s.token);
  const qc = useQueryClient();
  const sessionInfo = useMemo(() => decodeSessionInfo(authToken), [authToken]);

  // Re-render once a minute so the "valid for ~Nh" copy stays fresh
  // without us having to subscribe to a global ticker for what is
  // effectively a static-ish display.
  const [, setTick] = useState(0);
  useEffect(() => {
    const id = window.setInterval(() => setTick((n) => n + 1), 60_000);
    return () => window.clearInterval(id);
  }, []);

  return (
    <SectionFrame
      title={t('settings.sectionSession')}
      description={t('settings.sessionHint')}
    >
      <Row gutter={[24, 12]} style={{ marginBottom: 20 }}>
        <Col xs={12} sm={6}>
          <SessionField
            label={t('settings.sessionStatusLabel')}
            value={
              sessionInfo
                ? t('settings.sessionStatusActive')
                : t('settings.sessionStatusInactive')
            }
            valueStrong
          />
        </Col>
        <Col xs={12} sm={6}>
          <SessionField
            label={t('settings.sessionExpiryLabel')}
            value={
              sessionInfo
                ? t('settings.sessionExpiryDescription', {
                    hours: sessionInfo.hoursLeft,
                  })
                : t('settings.sessionExpiryDescriptionInactive')
            }
          />
        </Col>
      </Row>
      <Button
        icon={<LogoutOutlined />}
        danger
        onClick={() => {
          logout();
          qc.clear();
        }}
      >
        {t('settings.sessionSignOut')}
      </Button>
    </SectionFrame>
  );
}

/** Compact "small caps label / large value" pair used inside the
 *  session section. Kept as a tiny named component so the parent's
 *  JSX reads as a list of fields instead of a soup of nested
 *  Typography elements with identical styling props. */
function SessionField({
  label,
  value,
  valueStrong,
}: {
  label: string;
  value: ReactNode;
  valueStrong?: boolean;
}) {
  return (
    <>
      <Typography.Text type="secondary" style={{ fontSize: 12 }}>
        {label}
      </Typography.Text>
      <div>
        <Typography.Text strong={valueStrong} style={{ fontSize: 16 }}>
          {value}
        </Typography.Text>
      </div>
    </>
  );
}

// =============================================================================
// Subscription — host override + Profile-Update-Interval
// =============================================================================

function SubscriptionSection({
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
      // Subscription fields go through the same PUT endpoint as the panel
      // port / base-path fields. We send the latest panel-side values
      // verbatim so a save here doesn't clobber edits an operator made
      // in the Access section (the PUT replaces the whole row).
      const current = settingsQuery.data;
      if (!current) {
        throw new Error('panel settings not loaded');
      }
      await apiClient.put('/settings/panel', {
        panel_port: current.panel_port,
        panel_base_path: current.panel_base_path,
        sub_enabled: values.sub_enabled,
        sub_host_override: values.sub_host_override.trim(),
        sub_update_interval_hours: values.sub_update_interval_hours,
        sub_brand_name: values.sub_brand_name.trim(),
        sub_service_url: values.sub_service_url.trim(),
        sub_port: values.sub_port,
      });
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['panel-settings'] });
      setDirty(false);
      message.success(t('settings.subscriptionSaved'));
    },
    onError: (err: unknown) =>
      message.error(apiErrorMessage(err) ?? t('settings.subscriptionSaveError')),
  });

  useEffect(() => {
    onDirtyChange(
      dirty
        ? {
            saving: mutation.isPending,
            onSave: () => form.submit(),
            onDiscard: () => {
              form.resetFields();
              setDirty(false);
            },
          }
        : null,
    );
  }, [dirty, mutation.isPending, form, onDirtyChange]);

  const data = settingsQuery.data;
  return (
    <SectionFrame
      title={t('settings.sectionSubscription')}
      description={t('settings.subscriptionHint')}
    >
      {data && (
        <Form<SubscriptionFormValues>
          form={form}
          layout="vertical"
          autoComplete="off"
          className="app-settings-fade-in"
          key={`${data.sub_enabled}-${data.sub_host_override}-${data.sub_update_interval_hours}-${data.sub_brand_name}-${data.sub_service_url}-${data.sub_port}`}
          initialValues={{
            sub_enabled: data.sub_enabled,
            sub_host_override: data.sub_host_override,
            sub_update_interval_hours: data.sub_update_interval_hours,
            sub_brand_name: data.sub_brand_name,
            sub_service_url: data.sub_service_url,
            sub_port: data.sub_port,
          }}
          disabled={mutation.isPending}
          onValuesChange={() => setDirty(true)}
          onFinish={(v) => mutation.mutate(v)}
        >
          <Form.Item
            name="sub_enabled"
            label={t('settings.subEnabled')}
            tooltip={t('settings.subEnabledHint')}
            valuePropName="checked"
            style={{ marginBottom: 20 }}
          >
            <Switch />
          </Form.Item>

          {/* Watch the toggle so the dependent fields grey out when
              subscriptions are off — they keep their stored value
              (so flipping the switch back on restores the config),
              just become read-only while disabled. */}
          <Form.Item shouldUpdate={(p, n) => p.sub_enabled !== n.sub_enabled} noStyle>
            {({ getFieldValue }) => {
              const enabled = getFieldValue('sub_enabled') as boolean;
              return (
                <Row gutter={24}>
                  <Col xs={24} sm={14}>
                    <Form.Item
                      name="sub_host_override"
                      label={t('settings.subHostOverride')}
                      tooltip={t('settings.subHostOverrideHint')}
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
                      style={{ marginBottom: 0 }}
                    >
                      <Input
                        placeholder={t('settings.subHostOverridePlaceholder')}
                        disabled={!enabled}
                      />
                    </Form.Item>
                  </Col>
                  <Col xs={24} sm={10}>
                    <Form.Item
                      name="sub_update_interval_hours"
                      label={t('settings.subUpdateInterval')}
                      tooltip={t('settings.subUpdateIntervalHint')}
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
                      style={{ marginBottom: 0 }}
                    >
                      <InputNumber
                        min={1}
                        max={168}
                        disabled={!enabled}
                        style={{ width: '100%' }}
                      />
                    </Form.Item>
                  </Col>
                </Row>
              );
            }}
          </Form.Item>
          <Form.Item shouldUpdate={(p, n) => p.sub_enabled !== n.sub_enabled} noStyle>
            {({ getFieldValue }) => {
              const enabled = getFieldValue('sub_enabled') as boolean;
              return (
                <>
                  <Form.Item
                    name="sub_brand_name"
                    label={t('settings.subBrandName')}
                    tooltip={t('settings.subBrandNameHint')}
                    rules={[
                      {
                        max: 60,
                        message: t('settings.subBrandNameTooLong'),
                      },
                    ]}
                    style={{ marginBottom: 20, marginTop: 20 }}
                  >
                    <Input
                      placeholder={t('settings.subBrandNamePlaceholder')}
                      disabled={!enabled}
                      maxLength={60}
                    />
                  </Form.Item>
                  <Form.Item
                    name="sub_service_url"
                    label={t('settings.subServiceUrl')}
                    tooltip={t('settings.subServiceUrlHint')}
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
                    style={{ marginBottom: 20 }}
                  >
                    <Input
                      placeholder={t('settings.subServiceUrlPlaceholder')}
                      disabled={!enabled}
                    />
                  </Form.Item>
                  <Form.Item
                    name="sub_port"
                    label={t('settings.subPort')}
                    tooltip={t('settings.subPortHint')}
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
                    style={{ marginBottom: 0 }}
                  >
                    <InputNumber
                      min={0}
                      max={65535}
                      disabled={!enabled}
                      style={{ width: '100%' }}
                      placeholder={t('settings.subPortPlaceholder')}
                    />
                  </Form.Item>
                </>
              );
            }}
          </Form.Item>
        </Form>
      )}
    </SectionFrame>
  );
}

// =============================================================================
// Page-level DirtyBar
// =============================================================================

function DirtyBar({
  visible,
  saving,
  count,
  onSave,
  onDiscard,
}: {
  visible: boolean;
  saving: boolean;
  count: number;
  onSave: () => void;
  onDiscard: () => void;
}) {
  const { t } = useTranslation();
  const [mounted, setMounted] = useState(visible);
  useEffect(() => {
    if (visible) {
      // Mount immediately on show; the delayed unmount below keeps the node
      // alive for the 220ms exit transition.
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setMounted(true);
      return undefined;
    }
    const id = window.setTimeout(() => setMounted(false), 220);
    return () => window.clearTimeout(id);
  }, [visible]);
  if (!mounted) return null;
  return (
    <div
      className={`app-settings-dirtybar${visible ? ' is-visible' : ''}`}
      role="region"
      aria-live="polite"
    >
      <div className="app-settings-dirtybar-inner">
        <span className="app-settings-dirtybar-dot" aria-hidden="true" />
        <Typography.Text style={{ flex: '1 1 auto', minWidth: 0 }}>
          {count > 1
            ? t('settings.dirtyHintMany', { count })
            : t('settings.dirtyHint')}
        </Typography.Text>
        <Button onClick={onDiscard} disabled={saving}>
          {t('settings.discard')}
        </Button>
        <Button type="primary" onClick={onSave} loading={saving}>
          {t('settings.save')}
        </Button>
      </div>
    </div>
  );
}

// =============================================================================
// Helpers
// =============================================================================

function decodeSessionInfo(token: string | null): { hoursLeft: number } | null {
  if (!token) return null;
  try {
    const payload = JSON.parse(atob(token.split('.')[1])) as { exp?: unknown };
    if (typeof payload.exp !== 'number') return null;
    const secondsLeft = payload.exp - Math.floor(Date.now() / 1000);
    if (secondsLeft <= 0) return null;
    return { hoursLeft: Math.max(1, Math.round(secondsLeft / 3600)) };
  } catch {
    return null;
  }
}

function normaliseClientPrefix(raw: string): string {
  const trimmed = raw.trim();
  if (!trimmed || trimmed === '/') return '';
  const inner = trimmed.replace(/^\/+|\/+$/g, '');
  return inner ? `/${inner}` : '';
}
