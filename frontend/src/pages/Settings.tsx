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
  Tabs,
  Tag,
  Tooltip,
  Typography,
} from 'antd';
import type { SelectProps } from 'antd';
import {
  BranchesOutlined,
  CheckOutlined,
  CloseOutlined,
  ControlOutlined,
  DatabaseOutlined,
  LeftOutlined,
  LinkOutlined,
  LoadingOutlined,
  LogoutOutlined,
  RightOutlined,
  SafetyCertificateOutlined,
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
import type { PanelSettings, PanelSettingsUpdate, RoutingRule } from '@/api/types';
import { RoutingRulesField } from '@/components/RoutingRulesField';

type SectionKey = 'account' | 'access' | 'subscription' | 'xray' | 'tls';

/** Fallback values for the subscription side of `PanelSettings`, consumed by
 *  `mergePanelSettings` (the whole-row PUT merge, when the cache isn't
 *  populated yet) and by `deriveSettingsFromUrl` (not-yet-loaded state).
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

/** Fallback values for the xray side of `PanelSettings`, mirroring the backend
 *  column defaults in `backend/migrations/0031_xray_settings.sql` +
 *  `0032_xray_routing.sql`. Consumed by `mergePanelSettings` for the
 *  not-yet-loaded case. */
const XRAY_DEFAULTS = {
  xray_freedom_strategy: 'AsIs',
  xray_routing_strategy: 'AsIs',
  xray_test_url: '',
  xray_block_bittorrent: false,
  xray_blocked_ips: [] as string[],
  xray_blocked_domains: [] as string[],
  xray_ipv4_domains: [] as string[],
  xray_custom_rules: [] as RoutingRule[],
  xray_rule_order: [] as string[],
} as const;

/** Fallback values for the panel-HTTPS side of `PanelSettings`, mirroring the
 *  backend column defaults in `backend/migrations/0036_panel_tls.sql`. The
 *  private key is never read back from the server (only `panel_tls_key_set`),
 *  so the merge always sends `panel_tls_key: ''` — the backend reads empty as
 *  "keep the stored key", and the TLS section overrides it only when the
 *  operator pastes a replacement. */
const TLS_DEFAULTS = {
  panel_tls_enabled: false,
  panel_tls_cert: '',
} as const;

/** `PUT /settings/panel` replaces the whole row, so every save must send all
 *  fields. Each settings section owns only a slice; this builds the full body
 *  from the cached settings (or the *_DEFAULTS, pre-load) and applies the
 *  caller's overrides — keeping the forward-everything-else logic in one place
 *  so a newly added field can't silently drop from two of the three saves. */
function mergePanelSettings(
  current: PanelSettings | undefined,
  overrides: Partial<PanelSettingsUpdate>,
): PanelSettingsUpdate {
  return {
    panel_port: current?.panel_port ?? 8080,
    panel_base_path: current?.panel_base_path ?? '',
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
    xray_freedom_strategy:
      current?.xray_freedom_strategy ?? XRAY_DEFAULTS.xray_freedom_strategy,
    xray_routing_strategy:
      current?.xray_routing_strategy ?? XRAY_DEFAULTS.xray_routing_strategy,
    xray_test_url: current?.xray_test_url ?? XRAY_DEFAULTS.xray_test_url,
    xray_block_bittorrent:
      current?.xray_block_bittorrent ?? XRAY_DEFAULTS.xray_block_bittorrent,
    xray_blocked_ips: current?.xray_blocked_ips ?? XRAY_DEFAULTS.xray_blocked_ips,
    xray_blocked_domains:
      current?.xray_blocked_domains ?? XRAY_DEFAULTS.xray_blocked_domains,
    xray_ipv4_domains:
      current?.xray_ipv4_domains ?? XRAY_DEFAULTS.xray_ipv4_domains,
    xray_custom_rules:
      current?.xray_custom_rules ?? XRAY_DEFAULTS.xray_custom_rules,
    xray_rule_order:
      current?.xray_rule_order ?? XRAY_DEFAULTS.xray_rule_order,
    panel_tls_enabled:
      current?.panel_tls_enabled ?? TLS_DEFAULTS.panel_tls_enabled,
    panel_tls_cert: current?.panel_tls_cert ?? TLS_DEFAULTS.panel_tls_cert,
    // Empty ≡ keep the stored key; the TLS section overrides this with the
    // pasted PEM when (and only when) the operator supplies a new key.
    panel_tls_key: '',
    ...overrides,
  };
}

/** No-op control that only registers the `xray_rule_order` array field on the
 *  form, so it's reactive via `Form.useWatch` and writable via `setFieldsValue`
 *  — the value is rendered/edited by RoutingRulesField, not here. Antd injects
 *  value/onChange at runtime; this control intentionally ignores them. */
const HiddenField = () => null;

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

type CategoryKey = SectionKey;

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
      { key: 'tls', labelKey: 'settings.navTls', icon: <SafetyCertificateOutlined /> },
      { key: 'subscription', labelKey: 'settings.navSubscription', icon: <LinkOutlined /> },
    ],
  },
  {
    titleKey: 'settings.groupEngine',
    items: [
      { key: 'xray', labelKey: 'settings.navXray', icon: <DatabaseOutlined /> },
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
  const onXrayDirty = useCallback(
    (h: DirtyHandle | null) => setDirty('xray', h),
    [setDirty],
  );
  const onTlsDirty = useCallback(
    (h: DirtyHandle | null) => setDirty('tls', h),
    [setDirty],
  );

  // `null` = the section list (drill-in root); a key = that section's detail
  // screen. Opening always starts at the list (reset on close, below).
  const [active, setActive] = useState<CategoryKey | null>(null);
  // Which section the detail panel renders. Tracked separately from `active`
  // so the panel keeps showing its section through the slide-OUT (when
  // `active` is already null on the way back) instead of blanking mid-glide.
  const [lastDetail, setLastDetail] = useState<CategoryKey | null>(null);

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
    const id = window.setTimeout(() => {
      setRendered(false);
      // Back to the section list so the next open starts at the root,
      // matching the push-navigation model.
      setActive(null);
      setLastDetail(null);
    }, 220);
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
        data-view={active === null ? 'list' : 'detail'}
      >
        {/* Fixed header — it never slides, so the close button (and the
            title / back control) sit ABOVE the push animation instead of
            having the panels travel under them. Morphs title ⇄ back by view. */}
        <div className="app-settings-header">
          {active === null ? (
            <span className="app-settings-header-title">{t('settings.title')}</span>
          ) : (
            <button
              type="button"
              className="app-settings-header-back"
              onClick={() => setActive(null)}
            >
              <LeftOutlined />
              <span>{t('settings.title')}</span>
            </button>
          )}
          <button
            type="button"
            className="app-settings-close"
            onClick={onClose}
            aria-label={t('common.close')}
          >
            <CloseOutlined />
          </button>
        </div>

        {/* Drill-in: the root list and the detail screen are both mounted,
            stacked, and slide horizontally (push navigation) below the fixed
            header, driven by the modal's `data-view`. */}
        <div className="app-settings-drill">
          {/* Root — sections as drill-in rows. */}
          <div className="app-settings-drill-list">
            {SETTINGS_GROUPS.map((group) => (
              <div key={group.titleKey} className="app-settings-drill-group">
                <div className="app-settings-drill-grouptitle">{t(group.titleKey)}</div>
                {group.items.map((item) => (
                  <button
                    key={item.key}
                    type="button"
                    className="app-settings-drill-row"
                    onClick={() => {
                      setLastDetail(item.key);
                      setActive(item.key);
                    }}
                  >
                    <span className="app-settings-drill-row-icon">{item.icon}</span>
                    <span className="app-settings-drill-row-label">{t(item.labelKey)}</span>
                    <RightOutlined className="app-settings-drill-row-go" />
                  </button>
                ))}
              </div>
            ))}
          </div>

          {/* Detail — just the active section; the back control lives in the
              fixed header above. Sections stay mounted (toggled by `lastDetail`,
              which lingers through the slide-out so the panel doesn't blank
              mid-animation). */}
          <div className="app-settings-drill-detail">
            <div className="app-settings-drill-body">
              <div style={{ display: lastDetail === 'account' ? 'block' : 'none' }}>
                <AccountSection />
              </div>
              <div style={{ display: lastDetail === 'access' ? 'block' : 'none' }}>
                <AccessSection onDirtyChange={onAccessDirty} />
              </div>
              <div style={{ display: lastDetail === 'tls' ? 'block' : 'none' }}>
                <TlsSection onDirtyChange={onTlsDirty} />
              </div>
              <div style={{ display: lastDetail === 'subscription' ? 'block' : 'none' }}>
                <SubscriptionSection onDirtyChange={onSubscriptionDirty} />
              </div>
              <div style={{ display: lastDetail === 'xray' ? 'block' : 'none' }}>
                <XraySection onDirtyChange={onXrayDirty} />
              </div>
            </div>
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
      <div className="app-settings-fields">{children}</div>
    </section>
  );
}

/** A titled block of rows within a section — the "Account information" /
 *  "Password & security" headings grouping related rows. Consecutive
 *  groups get a hairline divider above them (see CSS). */
function FieldGroup({ title, children }: { title?: string; children: ReactNode }) {
  return (
    <div className="app-settings-fieldgroup">
      {title && <h2 className="app-settings-fieldgroup-title">{title}</h2>}
      <div className="app-settings-group">{children}</div>
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
              variant="filled"
              color="default"
              className="app-settings-logout"
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
        mask={{ closable: !mutation.isPending }}
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
      <div className="app-settings-inforow-main">
        <div className="app-settings-inforow-label">{label}</div>
        <div className="app-settings-inforow-value">{value}</div>
      </div>
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
      // PUT replaces the whole row; mergePanelSettings forwards every field
      // this section doesn't own (sub_* / xray_*) from the cache so saving the
      // port doesn't reset them.
      const current = settingsQuery.data;
      await apiClient.put(
        '/settings/panel',
        mergePanelSettings(current, {
          panel_port: values.panel_port,
          panel_base_path: values.panel_base_path,
        }),
      );
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
          <FieldGroup title={t('settings.accessGroupPanel')}>
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
              <InputNumber min={1} max={65535} />
            </Form.Item>
            <Form.Item
              name="panel_base_path"
              label={t('settings.panelBasePath')}
              tooltip={t('settings.panelBasePathHint')}
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
      {data && <LanguagePicker />}
    </SectionFrame>
  );
}

// =============================================================================
// HTTPS / TLS — serve the panel over HTTPS with an operator-provided cert+key
// =============================================================================

interface TlsFormValues {
  panel_tls_enabled: boolean;
  panel_tls_cert: string;
  panel_tls_key: string;
}

const PEM_HEADER_RE = /-----BEGIN [A-Z0-9 ]+-----/;

/** Validator: accept empty (the required check is separate) or any PEM-shaped
 *  blob — strict enough to catch a wrong paste, loose on the header word. */
function pemRule(msg: string) {
  return {
    validator: (_: unknown, v: string) =>
      !v || PEM_HEADER_RE.test(v) ? Promise.resolve() : Promise.reject(new Error(msg)),
  };
}

function TlsSection({
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
      const current = settingsQuery.data;
      await apiClient.put(
        '/settings/panel',
        mergePanelSettings(current, {
          panel_tls_enabled: values.panel_tls_enabled,
          panel_tls_cert: values.panel_tls_cert,
          panel_tls_key: values.panel_tls_key?.trim() ?? '',
        }),
      );
      return values;
    },
    onSuccess: (values) => {
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
        message.success(t('settings.panelSaved'));
        return;
      }
      // TLS binds at process start, so the change lands only after a restart.
      const scheme = values.panel_tls_enabled ? 'https' : 'http';
      const path = normaliseClientPrefix(old.panel_base_path);
      const url = `${scheme}://${window.location.hostname}:${old.panel_port}${path}/`;
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
    <SectionFrame title={t('settings.tlsSection')} description={t('settings.tlsSectionHint')}>
      {data && (
        <Form<TlsFormValues>
          form={form}
          layout="vertical"
          autoComplete="off"
          key={`tls-${data.panel_tls_enabled}-${data.panel_tls_key_set}`}
          initialValues={{
            panel_tls_enabled: data.panel_tls_enabled,
            panel_tls_cert: data.panel_tls_cert,
            panel_tls_key: '',
          }}
          disabled={mutation.isPending}
          onValuesChange={() => setDirty(true)}
          onFinish={(v) => mutation.mutate(v)}
        >
          <FieldGroup>
            <Form.Item
              name="panel_tls_enabled"
              label={t('settings.tlsEnabled')}
              tooltip={t('settings.tlsEnabledHint')}
              valuePropName="checked"
            >
              <Switch />
            </Form.Item>
            <Form.Item
              name="panel_tls_cert"
              label={t('settings.tlsCert')}
              tooltip={t('settings.tlsCertHint')}
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
              <Input.TextArea
                rows={5}
                spellCheck={false}
                placeholder="-----BEGIN CERTIFICATE-----"
                style={{
                  fontFamily: 'ui-monospace, "JetBrains Mono", Consolas, monospace',
                  fontSize: 12,
                }}
              />
            </Form.Item>
            <Form.Item
              name="panel_tls_key"
              label={t('settings.tlsKey')}
              tooltip={t('settings.tlsKeyHint')}
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
              <Input.TextArea
                rows={5}
                spellCheck={false}
                placeholder={
                  data.panel_tls_key_set
                    ? t('settings.tlsKeyStoredPlaceholder')
                    : '-----BEGIN PRIVATE KEY-----'
                }
                style={{
                  fontFamily: 'ui-monospace, "JetBrains Mono", Consolas, monospace',
                  fontSize: 12,
                }}
              />
            </Form.Item>
          </FieldGroup>
        </Form>
      )}
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
    <FieldGroup title={t('settings.interfaceGroup')}>
      <div className="app-settings-plaque">
        <span className="app-settings-plaque-label">{t('settings.language')}</span>
        <div className="app-settings-plaque-control">
          <Select
            value={locale}
            onChange={onChange}
            options={LOCALES.map((l) => ({ value: l.value, label: l.label }))}
          />
        </div>
      </div>
    </FieldGroup>
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
      // PUT replaces the whole row; mergePanelSettings forwards the panel /
      // xray fields from the cache so a subscription save doesn't clobber them.
      const current = settingsQuery.data;
      await apiClient.put(
        '/settings/panel',
        mergePanelSettings(current, {
          sub_enabled: values.sub_enabled,
          sub_host_override: values.sub_host_override.trim(),
          sub_update_interval_hours: values.sub_update_interval_hours,
          sub_brand_name: values.sub_brand_name.trim(),
          sub_service_url: values.sub_service_url.trim(),
          sub_port: values.sub_port,
        }),
      );
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
          <FieldGroup>
            <Form.Item
              name="sub_enabled"
              label={t('settings.subEnabled')}
              tooltip={t('settings.subEnabledHint')}
              valuePropName="checked"
            >
              <Switch />
            </Form.Item>
          </FieldGroup>

          {/* Watch the toggle so the dependent fields grey out when
              subscriptions are off — they keep their stored value
              (so flipping the switch back on restores the config),
              just become read-only while disabled. One watcher wraps both
              groups since every dependent field shares the same gate. */}
          <Form.Item shouldUpdate={(p, n) => p.sub_enabled !== n.sub_enabled} noStyle>
            {({ getFieldValue }) => {
              const enabled = getFieldValue('sub_enabled') as boolean;
              return (
                <>
                  <FieldGroup title={t('settings.subGroupConnection')}>
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
                    >
                      <Input
                        placeholder={t('settings.subHostOverridePlaceholder')}
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
                    >
                      <InputNumber
                        min={0}
                        max={65535}
                        disabled={!enabled}
                        placeholder={t('settings.subPortPlaceholder')}
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
                    >
                      <InputNumber min={1} max={168} disabled={!enabled} />
                    </Form.Item>
                  </FieldGroup>
                  <FieldGroup title={t('settings.subGroupBranding')}>
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

// =============================================================================
// Xray — engine settings (outbound/routing). These live in xray's bootstrap
// config, so a Freedom/routing strategy change only applies on an xray
// restart — the section saves to the DB, then offers to restart (which
// regenerates the bootstrap and bounces the process).
// =============================================================================

interface XrayFormValues {
  xray_freedom_strategy: string;
  xray_routing_strategy: string;
  xray_test_url: string;
  xray_block_bittorrent: boolean;
  xray_blocked_ips: string[];
  xray_blocked_domains: string[];
  xray_ipv4_domains: string[];
  xray_custom_rules: RoutingRule[];
  xray_rule_order: string[];
}

/** Freedom-outbound `domainStrategy` values; mirrors the backend allowlist
 *  in `api/settings.rs`. AsIs = no DNS forcing; the UseIP / ForceIP families
 *  pick the egress address family. */
const FREEDOM_STRATEGY_OPTIONS = [
  'AsIs',
  'UseIP',
  'UseIPv4',
  'UseIPv6',
  'UseIPv4v6',
  'UseIPv6v4',
  'ForceIP',
  'ForceIPv4',
  'ForceIPv6',
  'ForceIPv4v6',
  'ForceIPv6v4',
].map((value) => ({ value, label: value }));

/** Routing-block `domainStrategy` values. */
const ROUTING_STRATEGY_OPTIONS = ['AsIs', 'IPIfNonMatch', 'IPOnDemand'].map(
  (value) => ({ value, label: value }),
);

type GeoOption = { value: string; code: string; label: string };

/** Quick-pick presets for the blocked-IP field: country names + a 2-letter
 *  code badge, each mapping to an xray `geoip:` matcher. The field stays
 *  free-text (mode="tags"), so custom IPs / CIDRs / geoip codes still work. */
const GEOIP_OPTIONS: GeoOption[] = [
  { value: 'geoip:private', code: 'IP', label: 'Private IPs' },
  { value: 'geoip:ru', code: 'RU', label: 'Russia' },
  { value: 'geoip:ua', code: 'UA', label: 'Ukraine' },
  { value: 'geoip:by', code: 'BY', label: 'Belarus' },
  { value: 'geoip:kz', code: 'KZ', label: 'Kazakhstan' },
  { value: 'geoip:cn', code: 'CN', label: 'China' },
  { value: 'geoip:ir', code: 'IR', label: 'Iran' },
  { value: 'geoip:us', code: 'US', label: 'USA' },
  { value: 'geoip:de', code: 'DE', label: 'Germany' },
  { value: 'geoip:nl', code: 'NL', label: 'Netherlands' },
  { value: 'geoip:gb', code: 'GB', label: 'United Kingdom' },
  { value: 'geoip:tr', code: 'TR', label: 'Turkey' },
  { value: 'geoip:br', code: 'BR', label: 'Brazil' },
  { value: 'geoip:vn', code: 'VN', label: 'Vietnam' },
  { value: 'geoip:es', code: 'ES', label: 'Spain' },
  { value: 'geoip:id', code: 'ID', label: 'Indonesia' },
];

/** Quick-pick presets for the blocked-domain field: `geosite:` categories +
 *  common TLD matchers (regexp). Custom domains / geosite codes still work. */
const GEOSITE_OPTIONS: GeoOption[] = [
  { value: 'geosite:category-ads-all', code: 'AD', label: 'Ads' },
  { value: 'geosite:category-porn', code: '18', label: 'Porn (18+)' },
  { value: 'geosite:cn', code: 'CN', label: 'China sites' },
  { value: 'geosite:google', code: 'G', label: 'Google' },
  { value: 'geosite:telegram', code: 'TG', label: 'Telegram' },
  { value: 'regexp:\\.ru$', code: 'RU', label: '.ru' },
  { value: 'regexp:\\.su$', code: 'RU', label: '.su' },
  { value: 'regexp:\\.xn--p1ai$', code: 'RU', label: '.рф' },
  { value: 'regexp:\\.ua$', code: 'UA', label: '.ua' },
  { value: 'regexp:\\.cn$', code: 'CN', label: '.cn' },
  { value: 'regexp:\\.vn$', code: 'VN', label: '.vn' },
];

/** value -> preset, so a selected chip can show the same code badge. */
const GEO_BY_VALUE = new Map<string, GeoOption>(
  [...GEOIP_OPTIONS, ...GEOSITE_OPTIONS].map((o) => [o.value, o]),
);

/** Dropdown row: "<code> <name>". A custom (typed) option has no code. */
const renderGeoOption: NonNullable<SelectProps['optionRender']> = (option) => {
  const o = option.data as GeoOption;
  return (
    <span>
      {o.code ? <span className="geo-code">{o.code}</span> : null}
      {o.label}
    </span>
  );
};

/** Selected chip: a preset shows "<code> <name>", a custom value shows raw. */
const renderGeoTag: NonNullable<SelectProps['tagRender']> = (props) => {
  const o = GEO_BY_VALUE.get(String(props.value));
  return (
    <Tag closable={props.closable} onClose={props.onClose}>
      {o ? (
        <>
          <span className="geo-code">{o.code}</span>
          {o.label}
        </>
      ) : (
        String(props.value)
      )}
    </Tag>
  );
};

interface OutboundTestResult {
  ok: boolean;
  status: number;
  latency_ms: number;
  error?: string;
}

function XraySection({
  onDirtyChange,
}: {
  onDirtyChange: (h: DirtyHandle | null) => void;
}) {
  const { t } = useTranslation();
  const { message, modal } = App.useApp();
  const qc = useQueryClient();
  const [form] = Form.useForm<XrayFormValues>();
  const [dirty, setDirty] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<OutboundTestResult | null>(null);

  const settingsQuery = useQuery<PanelSettings>({
    queryKey: ['panel-settings'],
    queryFn: async () => (await apiClient.get<PanelSettings>('/settings/panel')).data,
  });

  const mutation = useMutation({
    mutationFn: async (values: XrayFormValues) => {
      // PUT replaces the whole row; mergePanelSettings forwards the panel /
      // subscription fields from the cache so saving xray doesn't reset them.
      const current = settingsQuery.data;
      await apiClient.put(
        '/settings/panel',
        mergePanelSettings(current, {
          xray_freedom_strategy: values.xray_freedom_strategy,
          xray_routing_strategy: values.xray_routing_strategy,
          xray_test_url: values.xray_test_url,
          xray_block_bittorrent: values.xray_block_bittorrent,
          xray_blocked_ips: values.xray_blocked_ips,
          xray_blocked_domains: values.xray_blocked_domains,
          xray_ipv4_domains: values.xray_ipv4_domains,
          xray_custom_rules: values.xray_custom_rules,
          xray_rule_order: values.xray_rule_order,
        }),
      );
      return values;
    },
    onSuccess: (values) => {
      // Strategies + routing rules live in the xray config and need a restart
      // to apply; the test URL is store-only. Offer the restart only when a
      // config-affecting field actually moved.
      const old = settingsQuery.data;
      const sameList = (a: string[], b: string[] | undefined) =>
        JSON.stringify(a) === JSON.stringify(b ?? []);
      const xrayConfigChanged =
        old != null &&
        (values.xray_freedom_strategy !== old.xray_freedom_strategy ||
          values.xray_routing_strategy !== old.xray_routing_strategy ||
          values.xray_block_bittorrent !== old.xray_block_bittorrent ||
          !sameList(values.xray_blocked_ips, old.xray_blocked_ips) ||
          !sameList(values.xray_blocked_domains, old.xray_blocked_domains) ||
          !sameList(values.xray_ipv4_domains, old.xray_ipv4_domains) ||
          JSON.stringify(values.xray_custom_rules) !==
            JSON.stringify(old.xray_custom_rules ?? []) ||
          JSON.stringify(values.xray_rule_order) !==
            JSON.stringify(old.xray_rule_order ?? []));
      qc.invalidateQueries({ queryKey: ['panel-settings'] });
      setDirty(false);
      if (xrayConfigChanged) {
        modal.confirm({
          title: t('settings.xrayRestartTitle'),
          content: t('settings.xrayRestartBody'),
          okText: t('settings.xrayRestartConfirm'),
          cancelText: t('settings.xrayRestartLater'),
          okButtonProps: { danger: true },
          onOk: async () => {
            try {
              await apiClient.post('/xray/restart');
              message.success(t('settings.xrayRestarted'));
            } catch (err: unknown) {
              message.error(apiErrorMessage(err) ?? t('settings.xrayRestartError'));
            }
          },
        });
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

  // "Test outbound": the server fetches the current URL field value through
  // its own egress (the same path xray's freedom outbound uses) and reports
  // the HTTP status + latency. Reads the live form value so it works before
  // the operator saves.
  const runTest = useCallback(async () => {
    const url = String(form.getFieldValue('xray_test_url') ?? '').trim();
    if (!url) {
      message.warning(t('settings.xrayTestEmpty'));
      return;
    }
    setTesting(true);
    setTestResult(null);
    try {
      const { data } = await apiClient.post<OutboundTestResult>(
        '/xray/test-outbound',
        { url },
      );
      setTestResult(data);
      if (data.ok) {
        message.success(
          t('settings.xrayTestOk', { status: data.status, ms: data.latency_ms }),
        );
      } else {
        message.error(
          t('settings.xrayTestFail', {
            status: data.status,
            error: data.error ?? '',
          }),
        );
      }
    } catch (err: unknown) {
      const error = apiErrorMessage(err) ?? t('settings.xrayTestError');
      setTestResult({ ok: false, status: 0, latency_ms: 0, error });
      message.error(error);
    } finally {
      setTesting(false);
    }
  }, [form, message, t]);

  const data = settingsQuery.data;
  return (
    <SectionFrame
      title={t('settings.xraySection')}
      description={t('settings.xraySectionHint')}
    >
      {data && (
        <Form<XrayFormValues>
          form={form}
          layout="vertical"
          autoComplete="off"
          key={JSON.stringify([
            data.xray_freedom_strategy,
            data.xray_routing_strategy,
            data.xray_test_url,
            data.xray_block_bittorrent,
            data.xray_blocked_ips,
            data.xray_blocked_domains,
            data.xray_ipv4_domains,
            data.xray_custom_rules ?? [],
            data.xray_rule_order ?? [],
          ])}
          initialValues={{
            xray_freedom_strategy: data.xray_freedom_strategy,
            xray_routing_strategy: data.xray_routing_strategy,
            xray_test_url: data.xray_test_url,
            xray_block_bittorrent: data.xray_block_bittorrent,
            xray_blocked_ips: data.xray_blocked_ips,
            xray_blocked_domains: data.xray_blocked_domains,
            xray_ipv4_domains: data.xray_ipv4_domains,
            xray_custom_rules: data.xray_custom_rules ?? [],
            xray_rule_order: data.xray_rule_order ?? [],
          }}
          disabled={mutation.isPending}
          onValuesChange={() => setDirty(true)}
          onFinish={(v) => mutation.mutate(v)}
        >
          <Tabs
            className="xray-tabs"
            defaultActiveKey="basic"
            items={[
              {
                key: 'basic',
                // forceRender keeps every tab's fields mounted in the form even
                // while another tab is shown — otherwise antd lazy-mounts panes
                // and an unvisited tab's fields drop out of the submit payload.
                forceRender: true,
                label: t('settings.xrayTabBasic'),
                icon: <ControlOutlined />,
                children: (
                  <FieldGroup title={t('settings.xrayGroupBasic')}>
                    <Form.Item
                      name="xray_freedom_strategy"
                      label={t('settings.xrayFreedomStrategy')}
                      tooltip={t('settings.xrayFreedomStrategyHint')}
                    >
                      <Select options={FREEDOM_STRATEGY_OPTIONS} />
                    </Form.Item>
                    <Form.Item
                      name="xray_routing_strategy"
                      label={t('settings.xrayRoutingStrategy')}
                      tooltip={t('settings.xrayRoutingStrategyHint')}
                    >
                      <Select options={ROUTING_STRATEGY_OPTIONS} />
                    </Form.Item>
                    {/* Test action is the icon inside the field: click to run,
                        then it recolours by result — green check on success, red
                        cross on failure — with the HTTP status / latency in its
                        tooltip. The detailed toast still fires on click. */}
                    <Form.Item
                      name="xray_test_url"
                      label={t('settings.xrayTestUrl')}
                      tooltip={t('settings.xrayTestUrlHint')}
                    >
                      <Input
                        placeholder="https://www.google.com/gen_204"
                        suffix={
                          <Tooltip
                            // Force the tooltip shut while a test runs. Clicking
                            // the icon with the result tooltip open would swap its
                            // text and reposition the *open* popup, briefly
                            // overflowing for one frame (a scrollbar flash / jerk).
                            // Hiding it during the test skips that reposition; a
                            // fresh show afterwards positions cleanly on its own.
                            open={testing ? false : undefined}
                            title={
                              testResult
                                ? testResult.ok
                                  ? `${testResult.status} · ${testResult.latency_ms} ms`
                                  : testResult.status
                                    ? `HTTP ${testResult.status}`
                                    : (testResult.error ??
                                      t('settings.xrayTestError'))
                                : t('settings.xrayTestRun')
                            }
                          >
                            <span
                              role="button"
                              aria-label={t('settings.xrayTestRun')}
                              // Don't let the icon steal focus into the URL input
                              // on click — focusing a partly-scrolled field makes
                              // the browser scroll it into view, jerking the modal.
                              onMouseDown={(e) => e.preventDefault()}
                              onClick={(e) => {
                                e.stopPropagation();
                                if (!testing) runTest();
                              }}
                              style={{
                                cursor: testing ? 'default' : 'pointer',
                                display: 'inline-flex',
                                fontSize: 16,
                              }}
                            >
                              {testing ? (
                                <LoadingOutlined />
                              ) : testResult ? (
                                testResult.ok ? (
                                  <CheckOutlined style={{ color: '#52c41a' }} />
                                ) : (
                                  <CloseOutlined style={{ color: '#ff4d4f' }} />
                                )
                              ) : (
                                <CheckOutlined style={{ opacity: 0.45 }} />
                              )}
                            </span>
                          </Tooltip>
                        }
                      />
                    </Form.Item>
                  </FieldGroup>
                ),
              },
              {
                key: 'routing',
                forceRender: true,
                label: t('settings.xrayTabRouting'),
                icon: <BranchesOutlined />,
                children: (
                  <>
                  <FieldGroup title={t('settings.xrayGroupRouting')}>
                    <Form.Item
                      name="xray_block_bittorrent"
                      label={t('settings.xrayBlockBittorrent')}
                      tooltip={t('settings.xrayBlockBittorrentHint')}
                      valuePropName="checked"
                    >
                      <Switch />
                    </Form.Item>
                    <Form.Item
                      name="xray_blocked_ips"
                      label={t('settings.xrayBlockedIps')}
                      tooltip={t('settings.xrayBlockedIpsHint')}
                    >
                      <Select
                        mode="tags"
                        options={GEOIP_OPTIONS}
                        showSearch={{ optionFilterProp: 'label' }}
                        optionRender={renderGeoOption}
                        tagRender={renderGeoTag}
                        tokenSeparators={[',', ' ']}
                        placeholder={t('settings.xrayGeoPlaceholder')}
                      />
                    </Form.Item>
                    <Form.Item
                      name="xray_blocked_domains"
                      label={t('settings.xrayBlockedDomains')}
                      tooltip={t('settings.xrayBlockedDomainsHint')}
                    >
                      <Select
                        mode="tags"
                        options={GEOSITE_OPTIONS}
                        showSearch={{ optionFilterProp: 'label' }}
                        optionRender={renderGeoOption}
                        tagRender={renderGeoTag}
                        tokenSeparators={[',', ' ']}
                        placeholder={t('settings.xrayGeoPlaceholder')}
                      />
                    </Form.Item>
                    <Form.Item
                      name="xray_ipv4_domains"
                      label={t('settings.xrayIpv4Domains')}
                      tooltip={t('settings.xrayIpv4DomainsHint')}
                    >
                      <Select
                        mode="tags"
                        open={false}
                        tokenSeparators={[',', ' ']}
                        placeholder={t('settings.xrayListPlaceholder')}
                      />
                    </Form.Item>
                  </FieldGroup>
                  <Form.Item name="xray_custom_rules" noStyle>
                    <RoutingRulesField />
                  </Form.Item>
                  <Form.Item name="xray_rule_order" hidden>
                    <HiddenField />
                  </Form.Item>
                  </>
                ),
              },
            ]}
          />
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
        <Typography.Text
          className="app-settings-dirtybar-text"
          style={{ flex: '1 1 auto', minWidth: 0 }}
        >
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
