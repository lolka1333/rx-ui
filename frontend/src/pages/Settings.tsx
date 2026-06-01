/**
 * Settings — a full-window modal.
 *
 * A left rail lists the categories (Account, Session, Access,
 * Subscription); the selected one renders in the content pane on the
 * right. All sections stay mounted and are toggled with `display` so
 * unsaved edits survive switching between them. A DirtyBar pinned to
 * the modal footer appears while any section has pending changes, so
 * the operator can edit across categories and save in one click.
 */
import {
  App,
  Button,
  Form,
  Input,
  InputNumber,
  Modal,
  Select,
  Switch,
  Typography,
} from 'antd';
import {
  CloseOutlined,
  ControlOutlined,
  LinkOutlined,
  LogoutOutlined,
  UserOutlined,
} from '@ant-design/icons';
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

type CategoryKey = 'account' | 'access' | 'subscription';

/** Left-nav structure for the settings modal. Short labels here; the
 *  per-section headings live inside each section. The account page bundles
 *  profile info + password + the active session under one entry, so there's a single item in the
 *  first group. */
const SETTINGS_GROUPS: {
  titleKey: string;
  items: { key: CategoryKey; labelKey: string; icon: ReactNode }[];
}[] = [
  {
    titleKey: 'settings.groupAccount',
    items: [
      { key: 'account', labelKey: 'settings.navAccount', icon: <UserOutlined /> },
    ],
  },
  {
    titleKey: 'settings.groupPanel',
    items: [
      { key: 'access', labelKey: 'settings.navAccess', icon: <ControlOutlined /> },
      { key: 'subscription', labelKey: 'settings.navSubscription', icon: <LinkOutlined /> },
    ],
  },
];

/**
 * Settings — a full-window modal. A categorized left nav
 * switches the visible section; every section stays mounted, so the
 * form state and the cross-section "save all" dirty registry survive
 * category switches (and closing/reopening the modal). Rendered
 * always-mounted by AdminApp and revealed via `open`.
 */
export function Settings({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { t } = useTranslation();
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
  const onAccessDirty = useCallback(
    (h: DirtyHandle | null) => setDirty('access', h),
    [setDirty],
  );
  const onSubscriptionDirty = useCallback(
    (h: DirtyHandle | null) => setDirty('subscription', h),
    [setDirty],
  );

  const [active, setActive] = useState<CategoryKey>('account');

  // Esc closes the modal — only wired while it's open.
  useEffect(() => {
    if (!open) return undefined;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  // Keep the overlay displayed through its close animation: `open` drives the
  // visible state, `rendered` stays true for the exit zoom-out, then flips
  // false so the base `display:none` hides it. (Same delayed-unmount trick as
  // the DirtyBar.) The 160ms timeout sits just past the 140ms out-animation.
  const [rendered, setRendered] = useState(open);
  useEffect(() => {
    if (open) {
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setRendered(true);
      return undefined;
    }
    const id = window.setTimeout(() => setRendered(false), 160);
    return () => window.clearTimeout(id);
  }, [open]);

  return (
    <div
      className={`app-settings-overlay${open ? ' is-open' : rendered ? ' is-closing' : ''}`}
      aria-hidden={!open}
    >
      <div className="app-settings-backdrop" onClick={onClose} />
      <div
        className="app-settings-modal"
        role="dialog"
        aria-modal="true"
        aria-label={t('settings.title')}
      >
        <nav className="app-settings-nav">
          <div className="app-settings-nav-title">{t('settings.title')}</div>
          {SETTINGS_GROUPS.map((group) => (
            <div key={group.titleKey} className="app-settings-nav-group">
              <div className="app-settings-nav-grouptitle">{t(group.titleKey)}</div>
              {group.items.map((item) => (
                <button
                  key={item.key}
                  type="button"
                  className={`app-settings-nav-item${active === item.key ? ' is-active' : ''}`}
                  onClick={() => setActive(item.key)}
                >
                  <span className="app-settings-nav-icon">{item.icon}</span>
                  {t(item.labelKey)}
                </button>
              ))}
            </div>
          ))}
        </nav>

        <div className="app-settings-content-wrap">
          <button
            type="button"
            className="app-settings-close"
            onClick={onClose}
            aria-label={t('common.close')}
          >
            <CloseOutlined />
          </button>
          <div className="app-settings-content-scroll">
            <div style={{ display: active === 'account' ? 'block' : 'none' }}>
              <AccountSection />
            </div>
            <div style={{ display: active === 'access' ? 'block' : 'none' }}>
              <AccessSection onDirtyChange={onAccessDirty} />
            </div>
            <div style={{ display: active === 'subscription' ? 'block' : 'none' }}>
              <SubscriptionSection onDirtyChange={onSubscriptionDirty} />
            </div>
          </div>
          <DirtyBar
            visible={dirtyCount > 0}
            saving={anySaving}
            count={dirtyCount}
            onSave={saveAll}
            onDiscard={discardAll}
          />
        </div>
      </div>
    </div>
  );
}

/**
 * Section wrapper: a big heading, an optional one-paragraph subtitle in
 * muted text, then the body (form, field groups). The column width is
 * capped in CSS (`.app-settings-section`) so it fills the content pane on
 * wide displays without leaving a dead gap on the right — values and
 * controls align to the column edge.
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
      <h1 className="app-settings-section-title">{title}</h1>
      {description && <p className="app-settings-section-sub">{description}</p>}
      <div>{children}</div>
    </section>
  );
}

/** A titled block of rows within a section — the "Account information" /
 *  "Password & security" headings grouping related rows. Consecutive
 *  groups get a hairline divider above them (see CSS). */
function FieldGroup({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="app-settings-fieldgroup">
      <h2 className="app-settings-fieldgroup-title">{title}</h2>
      <div>{children}</div>
    </div>
  );
}

// =============================================================================
// Account — change username / password
// =============================================================================

function AccountSection() {
  const { t } = useTranslation();
  const { message } = App.useApp();
  const logout = useAuth((s) => s.logout);
  const currentUsername = useAuth((s) => s.user?.username ?? '');
  const authToken = useAuth((s) => s.token);
  const qc = useQueryClient();
  const [form] = Form.useForm<CredentialsFormValues>();
  // Each field is a compact read-only row with an "Edit"
  // button; clicking it opens a focused modal dialog for just that field.
  const [editing, setEditing] = useState<'login' | 'password' | null>(null);

  // Active-session info (JWT expiry) lives on this same page under the
  // "Password & security" group — sessions sit alongside the password
  // controls, so we merged the old standalone Session section in.
  const sessionInfo = useMemo(() => decodeSessionInfo(authToken), [authToken]);
  // Re-render once a minute so the "valid for ~Nh" copy stays fresh.
  const [, setTick] = useState(0);
  useEffect(() => {
    const id = window.setInterval(() => setTick((n) => n + 1), 60_000);
    return () => window.clearInterval(id);
  }, []);

  const mutation = useMutation({
    mutationFn: async (values: CredentialsFormValues) => {
      // The backend changes username + password through one endpoint
      // (either may be null). `editing` decides which one this submit
      // touches; the other is left untouched.
      await apiClient.post('/auth/credentials', {
        current_password: values.current_password,
        new_username: editing === 'login' ? values.new_username?.trim() || null : null,
        new_password: editing === 'password' ? values.new_password || null : null,
      });
    },
    onSuccess: () => {
      message.success(t('settings.credentialsUpdated'));
      logout();
    },
    onError: (err: unknown) =>
      message.error(apiErrorMessage(err) ?? t('settings.credentialsError')),
  });

  const close = () => {
    if (!mutation.isPending) setEditing(null);
  };

  return (
    <section className="app-settings-section">
      <FieldGroup title={t('settings.groupInfo')}>
        <InfoRow
          label={t('settings.currentUsername')}
          value={currentUsername}
          action={
            <Button
              variant="filled"
              color="default"
              className="app-settings-editbtn"
              onClick={() => setEditing('login')}
            >
              {t('common.edit')}
            </Button>
          }
        />
      </FieldGroup>

      <FieldGroup title={t('settings.groupSecurity')}>
        <InfoRow
          label={t('settings.passwordLabel')}
          value="••••••••••"
          action={
            <Button
              variant="filled"
              color="default"
              className="app-settings-editbtn"
              onClick={() => setEditing('password')}
            >
              {t('common.edit')}
            </Button>
          }
        />
        <InfoRow
          label={t('settings.sectionSession')}
          value={
            sessionInfo
              ? t('settings.sessionExpiryDescription', { hours: sessionInfo.hoursLeft })
              : t('settings.sessionExpiryDescriptionInactive')
          }
          action={
            <Button
              danger
              icon={<LogoutOutlined />}
              onClick={() => {
                logout();
                qc.clear();
              }}
            >
              {t('settings.sessionSignOut')}
            </Button>
          }
        />
      </FieldGroup>

      {/* Edit dialog — opens over the settings modal (antd popups sit above
          the overlay thanks to the raised zIndexPopupBase). New value first,
          current password to confirm. */}
      <Modal
        open={editing !== null}
        title={
          editing === 'password'
            ? t('settings.editPasswordTitle')
            : t('settings.editLoginTitle')
        }
        width={440}
        okText={t('common.done')}
        cancelText={t('common.cancel')}
        confirmLoading={mutation.isPending}
        maskClosable={!mutation.isPending}
        keyboard={!mutation.isPending}
        onCancel={close}
        onOk={() => form.submit()}
        afterOpenChange={(o) => {
          if (o) form.resetFields();
        }}
        destroyOnHidden
      >
        <Form
          form={form}
          layout="vertical"
          autoComplete="off"
          disabled={mutation.isPending}
          onFinish={(v) => mutation.mutate(v)}
        >
          {editing === 'password' ? (
            <>
              <Form.Item
                name="new_password"
                label={t('settings.newPassword')}
                rules={[
                  { required: true, message: t('settings.newPasswordRequired') },
                  { min: 4, message: t('settings.newPasswordTooShort') },
                ]}
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
                      if (getFieldValue('new_password') === value) return Promise.resolve();
                      return Promise.reject(new Error(t('settings.newPasswordMismatch')));
                    },
                  }),
                ]}
              >
                <Input.Password autoComplete="new-password" />
              </Form.Item>
            </>
          ) : (
            <Form.Item
              name="new_username"
              label={t('settings.newUsername')}
              rules={[{ required: true, message: t('settings.newUsernameRequired') }]}
            >
              <Input autoComplete="off" placeholder={currentUsername} />
            </Form.Item>
          )}
          <Form.Item
            name="current_password"
            label={t('settings.currentPassword')}
            rules={[{ required: true, message: t('settings.currentPasswordRequired') }]}
            style={{ marginBottom: 0 }}
          >
            <Input.Password autoComplete="current-password" />
          </Form.Item>
        </Form>
      </Modal>
    </section>
  );
}

/** One account row: label on the left, value pushed to the
 *  right, and an action control (Edit / Sign-out) at the far edge. The big
 *  gap between label and value is the "spacious" look — it's intentional,
 *  not empty space. */
function InfoRow({
  label,
  value,
  action,
}: {
  label: string;
  value: ReactNode;
  action: ReactNode;
}) {
  return (
    <div className="app-settings-inforow">
      <div className="app-settings-inforow-label">{label}</div>
      <div className="app-settings-inforow-value">{value}</div>
      {action}
    </div>
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
      if (portChanged || pathChanged) {
        const newUrl = `${window.location.protocol}//${window.location.hostname}:${values.panel_port}${normalisedPath}/`;
        message.success({
          content: t('settings.panelSavedHotRedirect', { url: newUrl }),
          duration: 6,
        });
        window.setTimeout(() => {
          window.location.href = newUrl;
        }, 2500);
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
          key={`${data.panel_port}-${data.panel_base_path}`}
          initialValues={{
            panel_port: data.panel_port,
            panel_base_path: data.panel_base_path,
          }}
          disabled={mutation.isPending}
          onValuesChange={() => setDirty(true)}
          onFinish={(v) => mutation.mutate(v)}
        >
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
          >
            <InputNumber min={1} max={65535} style={{ width: 200 }} />
          </Form.Item>
          <Form.Item
            name="panel_base_path"
            label={t('settings.panelBasePath')}
            tooltip={t('settings.panelBasePathHint')}
            style={{ marginBottom: 0 }}
          >
            <Input placeholder={t('settings.panelBasePathPlaceholder')} />
          </Form.Item>
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
                <>
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
                    style={{ marginBottom: 20 }}
                  >
                    <Input
                      placeholder={t('settings.subHostOverridePlaceholder')}
                      disabled={!enabled}
                    />
                  </Form.Item>
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
                    <InputNumber min={1} max={168} disabled={!enabled} style={{ width: 200 }} />
                  </Form.Item>
                </>
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
