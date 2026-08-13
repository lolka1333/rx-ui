/**
 * Settings — a full-window modal.
 *
 * A left rail lists the categories (Account, Access, HTTPS,
 * Subscription, Xray); the selected one renders in the content pane on the
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
import type { FormInstance, SelectProps, SwitchProps } from 'antd';
import {
  BranchesOutlined,
  CheckOutlined,
  ClockCircleOutlined,
  CloseOutlined,
  CloudUploadOutlined,
  ControlOutlined,
  DownOutlined,
  KeyOutlined,
  LinkOutlined,
  LoadingOutlined,
  LockOutlined,
  LogoutOutlined,
  SafetyCertificateOutlined,
  UserOutlined,
} from '@ant-design/icons';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import type { QueryClient } from '@tanstack/react-query';
import type { DragEvent, FocusEventHandler, PointerEvent, ReactNode } from 'react';
import { forwardRef, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { apiClient } from '@/api/client';
import { apiErrorMessage } from '@/api/errors';
import { useLoadState } from '@/api/loadState';
import { LoadError, LoadStale } from '@/components/LoadState';
import { useAuth } from '@/stores/auth';
import { useNav, type SettingsSection } from '@/stores/nav';
import { setLocaleAndReload, useLocale } from '@/stores/locale';
import { LOCALES } from '@/i18n';
import type { PanelSettings, RoutingRule } from '@/api/types';
import {
  GEOIP_PRESETS,
  GEOSITE_PRESETS,
  GEO_PRESET_BY_VALUE,
  type GeoPreset,
} from '@/lib/geoPresets';
import { mergePanelSettings } from '@/lib/panelSettings';
import { pemRule } from '@/lib/pem';
import { reportRouting } from '@/lib/routingReport';
import type { RoutingApplyResult } from '@/lib/routingReport';
import { RoutingRulesField } from '@/components/RoutingRulesField';

type SectionKey = 'account' | 'access' | 'subscription' | 'xray' | 'tls';

// PanelSettings *_DEFAULTS and the whole-row PUT merge (`mergePanelSettings`)
// live in `@/lib/panelSettings` — shared with the reverse-pair wizard, which
// can't import from this component module (react-refresh only-export-components).

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
  sub_link_host: string;
  sub_update_interval_hours: number;
  sub_brand_name: string;
  sub_service_url: string;
  sub_port: number;
  sub_tls_mode: string;
  sub_cert_pem: string;
  sub_key_pem: string;
}

interface DirtyHandle {
  saving: boolean;
  /** Resolves when the save (and the settings refetch it triggers) is done,
   *  so `saveAll` can sequence sections instead of racing them. */
  onSave: () => Promise<void>;
  onDiscard: () => void;
}

/** Publish one section's dirty state (and how to save/discard it) to the page.
 *
 *  Extracted because all four sections need byte-identical wiring, and the
 *  wiring has two traps worth stating once instead of four times:
 *
 *  - `mutation` is a fresh object every render, so it CANNOT be an effect dep —
 *    it would republish the handle on every render, which feeds back through
 *    `onDirtyChange` into another render. The save goes through a ref that a
 *    deps-less effect keeps current; only `mutation.isPending` is a dep.
 *  - `onSave` is awaitable so `saveAll` can run sections one at a time. It takes
 *    the same path `onFinish` does (validate, then the section's own mutation)
 *    and awaits the query invalidation too, so the next section's payload merges
 *    post-save data. Errors are already surfaced by field validation and the
 *    mutation's own onError, hence the bare `.catch`.
 */
/** Does the live form differ from what's actually saved?
 *
 *  The sections used to flag themselves dirty on ANY edit, so typing a value
 *  and then putting it back left the "unsaved changes" bar stuck on screen with
 *  nothing to save. Compare against the saved baseline instead.
 *
 *  Nullish and `''` count as the same empty value — an untouched optional input
 *  reports `undefined` where the server sent `''`. Arrays and objects compare
 *  structurally INCLUDING order, because order is itself a setting here (the
 *  routing-rule list). */
function differsFromSaved(
  current: Record<string, unknown>,
  baseline: Record<string, unknown>,
): boolean {
  const norm = (v: unknown) => (v === undefined || v === null ? '' : v);
  const same = (a: unknown, b: unknown) => {
    const x = norm(a);
    const y = norm(b);
    if (typeof x === 'object' || typeof y === 'object') {
      return JSON.stringify(x) === JSON.stringify(y);
    }
    return x === y;
  };
  // Only the saved settings decide dirtiness. `getFieldsValue(true)` also hands
  // back transient fields the form registered that were never part of the saved
  // row — comparing those would flag the section dirty with nothing to save.
  return Object.keys(baseline).some((k) => !same(current[k], baseline[k]));
}

function useSectionDirtyPublish<V>({
  dirty,
  setDirty,
  form,
  mutation,
  onDirtyChange,
  qc,
}: {
  dirty: boolean;
  setDirty: (v: boolean) => void;
  form: FormInstance<V>;
  mutation: { mutateAsync: (v: V) => Promise<unknown>; isPending: boolean };
  onDirtyChange: (h: DirtyHandle | null) => void;
  qc: QueryClient;
}) {
  const saveRef = useRef(mutation.mutateAsync);
  useEffect(() => {
    saveRef.current = mutation.mutateAsync;
  });

  useEffect(() => {
    onDirtyChange(
      dirty
        ? {
            saving: mutation.isPending,
            onSave: () =>
              form
                .validateFields()
                .then((v) => saveRef.current(v))
                .then(() => qc.invalidateQueries({ queryKey: ['panel-settings'] }))
                .then(() => undefined)
                .catch(() => undefined),
            onDiscard: () => {
              form.resetFields();
              setDirty(false);
            },
          }
        : null,
    );
  }, [dirty, mutation.isPending, form, onDirtyChange, qc, setDirty]);
}

/**
 * Settings — a full-width page. The sidebar's "Settings" accordion selects
 * the visible category via the `section` prop; every section stays mounted,
 * so the form state and the cross-section "save all" dirty registry survive
 * switching categories (and navigating away and back). Rendered
 * always-mounted by AdminApp, revealed when `current` is a `settings-*` page.
 */
/** The two panes of the Xray settings page. */
type XrayTab = 'basic' | 'routing';

export function Settings({ section }: { section: SectionKey }) {
  const { t } = useTranslation();
  const setCurrent = useNav((s) => s.setCurrent);
  // Every section runs this same query, so subscribing here is free (react-query
  // dedupes by key) and it gives the PAGE something to gate on. Without it the
  // tabs, the group plaques and the section chrome all painted immediately on a
  // reload while every field inside was still empty — an empty shell hanging on
  // screen — and the fields then popped in with no motion, because the page
  // wrapper had already played its entrance over that empty frame. The other
  // four pages already do exactly this.
  const pageQuery = useQuery<PanelSettings>({
    queryKey: ['panel-settings'],
    queryFn: async () => (await apiClient.get<PanelSettings>('/settings/panel')).data,
  });
  const pageState = useLoadState([pageQuery]);
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
  const [savingAll, setSavingAll] = useState(false);
  // Ref as well as state: two clicks in the same tick would both read the
  // pre-render `savingAll === false`.
  const savingAllRef = useRef(false);
  // The per-section flag drops between sections (each clears its own dirty
  // state as its request resolves), so on its own it would let a second click
  // land mid-sequence and start a concurrent pass — the exact interleaving the
  // sequential loop exists to prevent. `savingAll` spans the whole run.
  const anySaving = savingAll || Object.values(dirtyHandles).some((h) => h?.saving);
  const saveAll = useCallback(async () => {
    if (savingAllRef.current) return;
    savingAllRef.current = true;
    setSavingAll(true);
    try {
      // Sequential, not concurrent: every section PUTs the WHOLE settings row,
      // merging the fields it doesn't own from the cached copy. Fired together,
      // the second save would build its payload from a pre-first-save snapshot
      // and silently revert the first section's changes — including routing
      // rules, which would then be pushed to the live router.
      for (const h of Object.values(dirtyHandles)) await h?.onSave();
    } finally {
      savingAllRef.current = false;
      setSavingAll(false);
    }
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

  // Two settings groups, each its own sidebar entry: the PANEL container (a
  // tabbed card over account / access / TLS / subscription) and the standalone
  // XRAY page. Both stay mounted (display-toggled) so the "save all" dirty
  // registry and unsaved edits survive switching between them. `section` (from
  // the sidebar) is 'xray' for the Xray page and a panel key otherwise.
  const tabLabel = (icon: ReactNode, label: string) => (
    <span className="app-settings-tab">
      {icon}
      {label}
    </span>
  );
  const isXray = section === 'xray';
  const panelTab: SettingsSection = isXray ? 'account' : section;

  // Nothing until the first payload lands — same contract as the other pages:
  // no skeleton flash, and `app-content-reveal` fades the real content in once
  // there is something to show. A refetch keeps the current content on screen.
  //
  // A `blocked` gate only — deliberately no `failed` branch here. An early
  // return would take the whole page off screen, and Account is the one settings
  // surface that keeps working with the backend down (it reads the auth store,
  // not the network). Each section owns its own failure surface instead.
  if (pageState.blocked) return null;

  return (
    <div className="app-settings-page app-content-reveal">
      <DirtyBar
        visible={dirtyCount > 0}
        saving={anySaving}
        count={dirtyCount}
        onSave={saveAll}
        onDiscard={discardAll}
      />
      {/* The entry animation lives on these two blocks, not on the page wrapper
          in App.tsx. Both settings pages share one wrapper (so the cross-section
          dirty registry survives switching), and that wrapper stays displayed
          when the sidebar moves between them — a CSS animation only replays
          when an element comes back from `display: none`, so the switch had no
          animation at all while every other tab did. Sitting on the blocks that
          actually toggle, it replays for a section switch AND for arriving from
          another page (the wrapper's display flip restarts descendants too). */}
      <div className="app-page-fade" style={{ display: isXray ? 'none' : 'block' }}>
        <Tabs
          className="app-settings-tabs"
          activeKey={panelTab}
          onChange={(k) => setCurrent(`settings-${k as SettingsSection}`)}
          items={[
            {
              key: 'account',
              forceRender: true,
              label: tabLabel(<UserOutlined />, t('settings.navAccount')),
              children: <AccountSection />,
            },
            {
              key: 'access',
              forceRender: true,
              label: tabLabel(<ControlOutlined />, t('settings.navAccess')),
              children: <AccessSection onDirtyChange={onAccessDirty} />,
            },
            {
              key: 'tls',
              forceRender: true,
              label: tabLabel(<SafetyCertificateOutlined />, t('settings.navTls')),
              children: <TlsSection onDirtyChange={onTlsDirty} />,
            },
            {
              key: 'subscription',
              forceRender: true,
              label: tabLabel(<LinkOutlined />, t('settings.navSubscription')),
              children: <SubscriptionSection onDirtyChange={onSubscriptionDirty} />,
            },
          ]}
        />
      </div>
      <div className="app-page-fade" style={{ display: isXray ? 'block' : 'none' }}>
        <XraySection onDirtyChange={onXrayDirty} />
      </div>
    </div>
  );
}

/**
 * Section wrapper: the section's heading, then the body (form, field groups).
 * The column width is capped in CSS (`.app-settings-section`) so it fills the
 * content pane on wide displays without leaving a dead gap on the right —
 * values and controls align to the column edge.
 *
 * The heading is for the document outline and screen readers only. On screen
 * the tab strip (or the sidebar, for the Xray page) already names the category,
 * so printing it again inside the panel was repetition — as was the paragraph
 * of blurb that used to sit under it, which restated the tab name and the
 * per-field hints. Both were hidden in CSS for a while; the blurb is gone now,
 * and the heading is taken off the screen without being taken out of the
 * document (see `.app-settings-page .app-settings-section-title`).
 */
function SectionFrame({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="app-settings-section">
      <h1 className="app-settings-section-title">{title}</h1>
      <div>{children}</div>
    </section>
  );
}

/** A titled block of rows within a section — the "Account information" /
 *  "Password & security" headings grouping related rows. Consecutive
 *  groups get a hairline divider above them (see CSS). */
/** Field label in the 3x-ui idiom: the setting's name with its explanation
 *  directly beneath it in muted text, instead of hidden behind a `?` tooltip.
 *  The pair fills the row's left column; the control sits in the right one —
 *  that's what gives a settings row its weight. */
function FieldLabel({ title, desc }: { title: string; desc?: string }) {
  return (
    <span className="app-field-label">
      <span className="app-field-title">{title}</span>
      {desc ? <span className="app-field-desc">{desc}</span> : null}
    </span>
  );
}

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
    <SectionFrame title={t('settings.accountSection')}>
      <FieldGroup title={t('settings.groupInfo')}>
        <InfoRow
          icon={<UserOutlined />}
          label={t('settings.currentUsername')}
          desc={t('settings.currentUsernameHint')}
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
          icon={<LockOutlined />}
          label={t('settings.passwordLabel')}
          desc={t('settings.passwordRowHint')}
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
          icon={<ClockCircleOutlined />}
          label={t('settings.sectionSession')}
          desc={t('settings.sessionRowHint')}
          value={
            sessionInfo ? (
              <>
                {/* Live dot: the session is the one row on this tab whose value
                    is a STATE rather than a stored setting, so it carries a
                    status marker the others don't need. */}
                <span className="app-settings-inforow-dot" aria-hidden="true" />
                {t('settings.sessionExpiryDescription', { hours: sessionInfo.hoursLeft })}
              </>
            ) : (
              t('settings.sessionExpiryDescriptionInactive')
            )
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

      {/* Edit dialog for changing the login or password. New value first,
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
    </SectionFrame>
  );
}

/** One account row, on the SAME two-column grid as the form rows on the other
 *  tabs: the left column names the setting, the right column carries its
 *  current value together with the action that changes it (Edit / Sign-out).
 *
 *  Value and action belong side by side. The earlier layout kept the value on
 *  the left and pinned the action to the row's far edge, which stranded the
 *  button ~700px from the value it acts on and left the row looking unfinished
 *  no matter how it was styled. */
function InfoRow({
  icon,
  label,
  desc,
  value,
  action,
}: {
  icon: ReactNode;
  label: string;
  desc?: string;
  value: ReactNode;
  action: ReactNode;
}) {
  return (
    <div className="app-settings-inforow">
      <span className="app-settings-inforow-id">
        <span className="app-settings-inforow-icon" aria-hidden="true">
          {icon}
        </span>
        <span className="app-field-label">
          <span className="app-field-title">{label}</span>
          {desc ? <span className="app-field-desc">{desc}</span> : null}
        </span>
      </span>
      <div className="app-settings-inforow-control">
        <span className="app-settings-inforow-value">{value}</span>
        {action}
      </div>
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

/**
 * A PEM field styled as a compact dashed drop target: a name row always on top,
 * then a short mono textarea that grows on focus/content, with an upload
 * invitation that fades once the field is focused or filled. Dropping a .pem
 * file reads it straight into the field.
 *
 * Controlled the antd way — `value`/`onChange` come from the wrapping
 * `Form.Item`, so validation and dirty-tracking work unchanged. `forwardRef`
 * lets antd scroll-to-error focus the textarea.
 */
/**
 * A Switch whose whole settings row is the hit target: clicking anywhere in
 * the row toggles it, and the row washes on hover to advertise that. A 44px
 * pill at the far end of a 1000px row is a small thing to aim at, and the rest
 * of the row was doing nothing.
 *
 * The row click is REPLAYED as a real click on the switch button rather than
 * writing the field directly: `form.setFieldValue` does not fire
 * `onValuesChange`, so a direct write would flip the control while leaving the
 * page's unsaved-changes tracking blind to it. Going through the button keeps
 * one code path — validation, dirty tracking and the disabled state all behave
 * exactly as they do for a click on the switch itself.
 *
 * Mouse affordance only: the switch stays the keyboard target, so no second
 * tab stop is introduced for the row.
 */
function RowSwitch(props: SwitchProps) {
  const btn = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    const row = btn.current?.closest('.app-field-switch');
    if (!row) return undefined;
    const onRowClick = (e: Event) => {
      const target = e.target as HTMLElement | null;
      // The switch handles clicks on itself; replaying one would undo it.
      if (target?.closest('.ant-switch')) return;
      btn.current?.click();
    };
    row.addEventListener('click', onRowClick);
    return () => row.removeEventListener('click', onRowClick);
  }, []);
  return <Switch {...props} ref={btn} />;
}

interface PemDropFieldProps {
  value?: string;
  onChange?: (e: { target: { value: string } }) => void;
  onBlur?: FocusEventHandler<HTMLTextAreaElement>;
  id?: string;
  placeholder?: string;
  fieldName: string;
  hintSub: string;
  chipText: string;
  chipDot?: boolean;
  icon: ReactNode;
  disabled?: boolean;
}

/** At most one PEM field may have a caret on the way to it. Shared across the
 *  instances on purpose: clicking the second field while the first one's caret
 *  was still pending let that timer fire mid-growth and focus the OTHER field,
 *  which is exactly what kills a height animation. Whoever is opening now owns
 *  the caret, and cancels whatever was queued before it. */
let pendingCaret: number | null = null;
let pendingCaretCleanup: (() => void) | null = null;
function cancelPendingCaret() {
  if (pendingCaret !== null) {
    window.clearTimeout(pendingCaret);
    pendingCaret = null;
  }
  if (pendingCaretCleanup) {
    pendingCaretCleanup();
    pendingCaretCleanup = null;
  }
}

/** Every mounted PEM field's "close yourself" handle. A field normally closes on
 *  blur, but one that was opened and then abandoned before its caret arrived
 *  never gets a blur to close on — click one field, click the next, and the
 *  first would sit open for good. Handing over closes them all; the one taking
 *  over reopens itself in the same render. A field holding a certificate stays
 *  tall regardless: that comes from `:not(:placeholder-shown)`, not from here. */
const pemClosers = new Set<() => void>();

const PemDropField = forwardRef<HTMLTextAreaElement, PemDropFieldProps>(function PemDropField(
  { value, onChange, onBlur, id, placeholder, fieldName, hintSub, chipText, chipDot, icon, disabled },
  ref,
) {
  const { t } = useTranslation();
  const { message } = App.useApp();
  const [dragOver, setDragOver] = useState(false);
  // Open/closed is tracked here rather than left to `:focus` in CSS, and the
  // click opens the box BEFORE the caret lands in it.
  //
  // Chrome will not animate the height of a focused textarea. Measured on this
  // very field: the same 44→128 transition runs frame by frame while the field
  // is unfocused (45.3 → 54.2 → 69.6 → 85.7 …) and collapses to the final value
  // the instant focus arrives — mid-flight, even. It is not the trigger and not
  // the element: animating an ancestor while the textarea inside holds focus
  // snaps just the same. So the growth has to finish before the field is
  // focused, which is what the pointer handler below does.
  const [open, setOpen] = useState(false);
  /** Matches the box's transition in the stylesheet, plus a frame of slack. */
  const OPEN_MS = 180;
  /** Corner square the browser draws the resize grip in. */
  const GRIP = 20;
  /** The resting strip, and a ceiling for a dragged-open box. Both mirror the
   *  stylesheet's `.app-tls-ta` height and its `--open-h` fallback. */
  const CLOSED_H = 44;
  const MAX_OPEN = 800;

  /** Releases an in-flight resize drag; set while the grip is held. */
  const releaseGrip = useRef<(() => void) | null>(null);

  useEffect(() => {
    const close = () => setOpen(false);
    pemClosers.add(close);
    return () => {
      pemClosers.delete(close);
      // A drag or a queued caret can still be in flight when this field goes
      // away — switching settings tabs unmounts it. Both hang listeners on
      // `document`, and one of them holds a timer that would focus a detached
      // node; nothing else would ever reach them again.
      releaseGrip.current?.();
      cancelPendingCaret();
    };
  }, []);

  /** Click on a closed field: grow it first, put the caret in afterwards. The
   *  default action is what focuses a textarea, so suppressing it is what buys
   *  the animation its 180ms. Only for the closed, empty state — a field that
   *  is already open behaves like an ordinary textarea, caret placement and
   *  all. Reduced-motion users get the caret immediately; there is no animation
   *  for them to wait on. */
  const onPointerDown = (e: PointerEvent<HTMLTextAreaElement>) => {
    const el = e.currentTarget;

    // The resize grip lives in the bottom-right corner and is dragged with the
    // same pointerdown this handler intercepts. Suppressing the default action
    // — which is what buys the open animation its 180ms — also cancels the
    // browser's resize drag, so the grip stopped working entirely. Leave the
    // corner alone, and switch the height transition off for the duration of
    // the drag: with it on, the box eased toward the pointer 160ms behind and
    // the whole thing felt like it was sagging.
    const box = el.getBoundingClientRect();
    if (e.clientX > box.right - GRIP && e.clientY > box.bottom - GRIP) {
      const drop = el.closest('.app-tls-drop');
      drop?.classList.add('is-resizing');
      const done = () => {
        releaseGrip.current = null;
        drop?.classList.remove('is-resizing');
        document.removeEventListener('pointerup', done);
        document.removeEventListener('pointercancel', done);
        // A drag leaves the height written onto the element itself, which
        // outranks every rule in the stylesheet — the box could no longer
        // collapse. Keep the size as this field's OPEN height instead and give
        // the stylesheet back control: the box still closes to the strip, and
        // reopens at the size the operator chose. Clearing the inline height
        // and focusing happen in the same task, so nothing is painted in
        // between and there is no flash.
        const dragged = Math.round(el.getBoundingClientRect().height);
        el.style.height = '';
        if (drop instanceof HTMLElement && dragged > CLOSED_H + 4) {
          drop.style.setProperty('--open-h', `${Math.min(dragged, MAX_OPEN)}px`);
        }
        el.focus();
      };
      releaseGrip.current = done;
      document.addEventListener('pointerup', done);
      document.addEventListener('pointercancel', done);
      return;
    }

    if (open || (value ?? '').length > 0) return;
    // A focused textarea suppresses height animations for the whole document,
    // not just for itself — so opening the second field while the first still
    // held the caret made the second one snap. Suppressing the default action
    // (below) is what keeps the old field focused, so the blur has to be
    // explicit. It also gives the other field its own closing animation, and
    // fires the form's blur handler exactly as clicking away normally would.
    // Order matters: cancel first, then blur (the old field's blur handler
    // cancels too, and must not be able to kill the caret queued below).
    cancelPendingCaret();
    const active = document.activeElement;
    if (active instanceof HTMLElement && active !== el) active.blur();
    pemClosers.forEach((close) => close());
    // Two cases skip the deferral and let the browser focus normally, with
    // `:focus` holding the box open: reduced motion, where there is no
    // animation to wait for; and touch or pen, where the software keyboard only
    // comes up if focus lands in the same task as the tap — from a timer it
    // stays down. A finger also pans: suppressing the default here would arm a
    // caret that fires 180ms into a scroll and drags the page back.
    if (
      e.pointerType !== 'mouse' ||
      window.matchMedia('(prefers-reduced-motion: reduce)').matches
    ) {
      return;
    }
    setOpen(true);
    e.preventDefault();

    // Give the caret up if the operator's next action lands anywhere else
    // before it is due. Without this, clicking the field and then quickly
    // clicking something else — a toggle, another tab — pulled focus back into
    // the field 180ms later, over whatever they had just clicked, and left the
    // box open with no blur coming to close it.
    // `pointercancel` targets this very field — it fires when the browser takes
    // the gesture over — so it cannot be filtered by target like the other two.
    const abort = (ev: Event) => {
      if (ev.type === 'pointercancel' || ev.target !== el) {
        cancelPendingCaret();
        setOpen(false);
      }
    };
    pendingCaretCleanup = () => {
      document.removeEventListener('pointerdown', abort, true);
      document.removeEventListener('pointercancel', abort, true);
      document.removeEventListener('focusin', abort, true);
    };
    document.addEventListener('pointerdown', abort, true);
    document.addEventListener('pointercancel', abort, true);
    document.addEventListener('focusin', abort, true);

    pendingCaret = window.setTimeout(() => {
      pendingCaret = null;
      pendingCaretCleanup?.();
      pendingCaretCleanup = null;
      // The field was just clicked, so it is already in view; scrolling to it
      // could only move the page out from under the operator.
      el.focus({ preventScroll: true });
      // Hand the open state over to `:focus` and drop the flag. The flag exists
      // only to cover the window before the caret arrives, so it can never be
      // left set on a field nobody is in.
      setOpen(false);
    }, OPEN_MS);
  };

  const onDrop = (e: DragEvent<HTMLTextAreaElement>) => {
    e.preventDefault();
    setDragOver(false);
    const file = e.dataTransfer.files?.[0];
    if (file) {
      // A dropped folder also arrives as a File, and reading it rejects. Say so
      // rather than leaving the drop to fail silently on an unhandled rejection.
      void file
        .text()
        .then((txt) => onChange?.({ target: { value: txt.trim() } }))
        .catch(() => message.error(t('settings.tlsDropUnreadable')));
      return;
    }
    // Text dragged from an editor or another field carries no File at all. It
    // is a PEM just the same, and the hint invites pasting one.
    const text = e.dataTransfer.getData('text/plain').trim();
    if (text) onChange?.({ target: { value: text } });
  };
  return (
    <div className="app-tls-field-inner">
      <div className="app-tls-flabel">
        <span className="app-tls-tile-sm" aria-hidden="true">
          {icon}
        </span>
        <span className="app-tls-fname">{fieldName}</span>
        <span className={`app-tls-chip${chipDot ? ' is-set' : ''}`}>
          {chipDot ? <span className="app-tls-chip-dot" aria-hidden="true" /> : null}
          {chipText}
        </span>
      </div>
      <div className={`app-tls-drop${dragOver ? ' is-drag' : ''}${open ? ' is-open' : ''}`}>
        <textarea
          ref={ref}
          id={id}
          className="app-tls-ta"
          spellCheck={false}
          value={value ?? ''}
          placeholder={placeholder}
          disabled={disabled}
          onChange={(e) => onChange?.(e)}
          onPointerDown={onPointerDown}
          onBlur={(e) => {
            // Clicking away before the caret arrived: drop it, or it would pull
            // focus back into a field the operator has already left.
            cancelPendingCaret();
            setOpen(false);
            onBlur?.(e);
          }}
          onDragOver={(e) => {
            e.preventDefault();
            setDragOver(true);
          }}
          onDragLeave={() => setDragOver(false)}
          onDrop={onDrop}
        />
        {/* The resting field is one strip, so it carries both halves of what an
            operator needs: the PEM header says WHAT belongs here — and differs
            between the two fields, which is what tells them apart at a glance —
            while the sub says HOW to get it in. The header is the textarea's own
            placeholder, reused rather than duplicated, so the two can't drift. */}
        <div className="app-tls-hint" aria-hidden="true">
          <span className="app-tls-hint-ic">
            <CloudUploadOutlined />
          </span>
          <span className="app-tls-hint-ghost">{placeholder}</span>
          <span className="app-tls-hint-sub">{hintSub}</span>
        </div>
      </div>
    </div>
  );
});

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

/**
 * Standalone language picker at the bottom of the Access section; switches
 * the UI language via `setLocaleAndReload` (which owns the write-storage-then-
 * reload rationale). Sits OUTSIDE the access form so the dirty-bar doesn't
 * touch it.
 */
function LanguagePicker() {
  const { t } = useTranslation();
  const locale = useLocale((s) => s.locale);
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
                          desc={t('settings.subTlsModeHint')}
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

/**
 * Endpoints offered for the egress test. The list is deliberately closed: the
 * result is only useful when the backend can read the exit IP out of the reply,
 * and it understands exactly two shapes (see `outbound_test::parse_trace`) —
 * a Cloudflare `cdn-cgi/trace` block, which also carries the country, and a
 * bare single-line IP. A URL like `generate_204` answers with an empty body, so
 * the exit IP on this page and on Outbounds stays blank — which is what this
 * list exists to prevent.
 */
const TEST_URL_TRACE = [
  'https://www.cloudflare.com/cdn-cgi/trace',
  'https://speed.cloudflare.com/cdn-cgi/trace',
  'https://1.1.1.1/cdn-cgi/trace',
];
const TEST_URL_PLAIN = [
  'https://api.ipify.org',
  'https://api64.ipify.org',
  'https://ifconfig.me/ip',
  'https://icanhazip.com',
  'https://ipinfo.io/ip',
  'https://checkip.amazonaws.com',
];
const hostOf = (u: string) => {
  try {
    return new URL(u).host;
  } catch {
    return u;
  }
};

/** Dropdown row: "<code> <name>". A custom (typed) option has no code. */
const renderGeoOption: NonNullable<SelectProps['optionRender']> = (option) => {
  const o = option.data as GeoPreset;
  return (
    <span>
      {o.code ? <span className="geo-code">{o.code}</span> : null}
      {o.label}
    </span>
  );
};

/** Selected chip: a preset shows "<code> <name>", a custom value shows raw. */
const renderGeoTag: NonNullable<SelectProps['tagRender']> = (props) => {
  const o = GEO_PRESET_BY_VALUE.get(String(props.value));
  return (
    <Tag closable={props.closable} onClose={props.onClose}>
      {o ? (
        <>
          {o.code ? <span className="geo-code">{o.code}</span> : null}
          {o.label}
        </>
      ) : (
        String(props.value)
      )}
    </Tag>
  );
};

/** Shape of `POST /api/xray/test-outbound` — the panel's own egress probe.
 *  Distinct from the generated `OutboundTestResult` in `@/api/types`, which
 *  belongs to `/outbounds/{id}/test`; the two endpoints answer different
 *  questions and the names must not be confusable. */
interface XrayEgressTestResult {
  ok: boolean;
  status: number;
  latency_ms: number;
  /** Exit IP the probe endpoint saw — null when its reply carried no IP. */
  exit_ip?: string | null;
  /** Country code, only Cloudflare's trace block reports one. */
  exit_loc?: string | null;
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
  const [testResult, setTestResult] = useState<XrayEgressTestResult | null>(null);
  const [xrayTab, setXrayTab] = useState<XrayTab>('basic');

  const settingsQuery = useQuery<PanelSettings>({
    queryKey: ['panel-settings'],
    queryFn: async () => (await apiClient.get<PanelSettings>('/settings/panel')).data,
  });

  const mutation = useMutation({
    mutationFn: async (values: XrayFormValues) => {
      // PUT replaces the whole row; mergePanelSettings forwards the panel /
      // subscription fields from the cache so saving xray doesn't reset them.
      // Read the cache at SEND time, not from the render closure: with two
      // sections dirty, the second save would otherwise merge a snapshot
      // taken before the first one landed and revert its fields.
      const current =
        qc.getQueryData<PanelSettings>(['panel-settings']) ?? settingsQuery.data;
      // The response says whether the LIVE router actually took the rules —
      // the row is saved either way, so a save that didn't reach xray still
      // succeeds at the HTTP level and would otherwise look like it worked.
      const res = await apiClient.put<RoutingApplyResult>(
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
      return { values, routing: res.data ?? {} };
    },
    onSuccess: ({ values, routing }) => {
      // Two different kinds of xray-affecting field, and they must not share a
      // prompt. The rule fields are pushed into the LIVE router by the save
      // itself (the backend's `routing_fields_changed` gate covers exactly the
      // six below), so asking for a restart there would drop every connection
      // to apply what is already applied. The strategies live in the config
      // file and genuinely only take effect on the next load.
      const old = settingsQuery.data;
      const sameList = (a: string[], b: string[] | undefined) =>
        JSON.stringify(a) === JSON.stringify(b ?? []);
      const restartNeeded =
        old != null &&
        (values.xray_freedom_strategy !== old.xray_freedom_strategy ||
          values.xray_routing_strategy !== old.xray_routing_strategy);
      const appliedLive =
        old != null &&
        (values.xray_block_bittorrent !== old.xray_block_bittorrent ||
          !sameList(values.xray_blocked_ips, old.xray_blocked_ips) ||
          !sameList(values.xray_blocked_domains, old.xray_blocked_domains) ||
          !sameList(values.xray_ipv4_domains, old.xray_ipv4_domains) ||
          JSON.stringify(values.xray_custom_rules) !==
            JSON.stringify(old.xray_custom_rules ?? []) ||
          JSON.stringify(values.xray_rule_order) !==
            JSON.stringify(old.xray_rule_order ?? []));
      qc.invalidateQueries({ queryKey: ['panel-settings'] });
      setDirty(false);
      // First and unconditionally: strategy fields and rule fields share this
      // form and this button, so a save can both need a restart and have failed
      // to reach the live router. Reporting only one would drop the message the
      // operator can actually act on.
      const report = reportRouting(routing, message, t);
      // Don't prompt when the backend already bounced xray: it regenerated the
      // config from the DB, so the strategy change came up with it and a second
      // outage would buy nothing.
      if (restartNeeded && !routing.routing_restarted) {
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
      } else if (report === 'clean') {
        // Only claim success when the reporter didn't already say otherwise —
        // it owns both the not-live warning and the restart notice.
        message.success(
          appliedLive ? t('settings.xrayRoutingApplied') : t('settings.panelSaved'),
        );
      }
    },
    onError: (err: unknown) =>
      message.error(apiErrorMessage(err) ?? t('settings.panelSaveError')),
  });

  // Publishes this section's dirty state to the page-level bar.
  useSectionDirtyPublish({ dirty, setDirty, form, mutation, onDirtyChange, qc });

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
      const { data } = await apiClient.post<XrayEgressTestResult>(
        '/xray/test-outbound',
        { url },
      );
      setTestResult(data);
      if (data.ok) {
        // The exit IP is the point of the probe, so lead the toast with it when
        // the endpoint returned one; a URL whose reply carries no IP still gets
        // the plain status/latency line.
        const exit = [data.exit_ip, data.exit_loc].filter(Boolean).join(' · ');
        message.success(
          exit
            ? t('settings.xrayTestOkIp', {
                exit,
                status: data.status,
                ms: data.latency_ms,
              })
            : t('settings.xrayTestOk', {
                status: data.status,
                ms: data.latency_ms,
              }),
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
  const state = useLoadState([settingsQuery]);
  const xrayBaseline = useMemo(
    () => (data ? {
            xray_freedom_strategy: data.xray_freedom_strategy,
            xray_routing_strategy: data.xray_routing_strategy,
            xray_test_url: data.xray_test_url,
            xray_block_bittorrent: data.xray_block_bittorrent,
            xray_blocked_ips: data.xray_blocked_ips,
            xray_blocked_domains: data.xray_blocked_domains,
            xray_ipv4_domains: data.xray_ipv4_domains,
            xray_custom_rules: data.xray_custom_rules ?? [],
            xray_rule_order: data.xray_rule_order ?? [],
          } : {}),
    [data],
  );
  return (
    <SectionFrame title={t('settings.xraySection')}>
      <LoadError state={state} />
      <LoadStale state={state} />
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
          initialValues={xrayBaseline}
          disabled={mutation.isPending}
          onValuesChange={() =>
            setDirty(differsFromSaved(form.getFieldsValue(true), xrayBaseline))
          }
          onFinish={(v) => mutation.mutate(v)}
        >
          <Tabs
            className="xray-tabs app-settings-tabs"
            activeKey={xrayTab}
            onChange={(k) => setXrayTab(k as XrayTab)}
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
                      label={
                        <FieldLabel
                          title={t('settings.xrayFreedomStrategy')}
                          desc={t('settings.xrayFreedomStrategyHint')}
                        />
                      }
                    >
                      <Select options={FREEDOM_STRATEGY_OPTIONS} />
                    </Form.Item>
                    <Form.Item
                      name="xray_routing_strategy"
                      label={
                        <FieldLabel
                          title={t('settings.xrayRoutingStrategy')}
                          desc={t('settings.xrayRoutingStrategyHint')}
                        />
                      }
                    >
                      <Select options={ROUTING_STRATEGY_OPTIONS} />
                    </Form.Item>
                    {/* A closed list, not free text: the exit IP only shows up
                        when the reply is one the backend can read (see
                        TEST_URL_TRACE / TEST_URL_PLAIN). The test action is the
                        icon beside the field — click to run, then it recolours
                        by result, with status / latency / exit IP in its
                        tooltip. The detailed toast still fires on click. */}
                    <Form.Item
                      name="xray_test_url"
                      className="app-field-testurl"
                      label={
                        <FieldLabel
                          title={t('settings.xrayTestUrl')}
                          desc={t('settings.xrayTestUrlHint')}
                        />
                      }
                    >
                      <Select
                        popupMatchSelectWidth={false}
                        options={[
                          {
                            label: t('settings.xrayTestGroupTrace'),
                            options: TEST_URL_TRACE.map((value) => ({
                              value,
                              label: hostOf(value),
                            })),
                          },
                          {
                            label: t('settings.xrayTestGroupPlain'),
                            options: TEST_URL_PLAIN.map((value) => ({
                              value,
                              label: hostOf(value),
                            })),
                          },
                        ]}
                        suffixIcon={
                          <span className="app-testurl-suffix">
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
                                  ? [
                                      `${testResult.status} · ${testResult.latency_ms} ms`,
                                      testResult.exit_ip,
                                      testResult.exit_loc,
                                    ]
                                      .filter(Boolean)
                                      .join(' · ')
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
                          {/* Keep a chevron so the field still reads as a list.
                              It is inert (see CSS): the click falls through to
                              the selector, which opens the dropdown. */}
                          <DownOutlined className="app-testurl-chevron" />
                          </span>
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
                      className="app-field-switch"
                      label={
                        <FieldLabel
                          title={t('settings.xrayBlockBittorrent')}
                          desc={t('settings.xrayBlockBittorrentHint')}
                        />
                      }
                      valuePropName="checked"
                    >
                      <RowSwitch />
                    </Form.Item>
                    <Form.Item
                      name="xray_blocked_ips"
                      label={
                        <FieldLabel
                          title={t('settings.xrayBlockedIps')}
                          desc={t('settings.xrayBlockedIpsHint')}
                        />
                      }
                    >
                      <Select
                        mode="tags"
                        options={GEOIP_PRESETS}
                        showSearch={{ optionFilterProp: 'label' }}
                        optionRender={renderGeoOption}
                        tagRender={renderGeoTag}
                        tokenSeparators={[',', ' ']}
                        placeholder={t('settings.xrayGeoPlaceholder')}
                      />
                    </Form.Item>
                    <Form.Item
                      name="xray_blocked_domains"
                      label={
                        <FieldLabel
                          title={t('settings.xrayBlockedDomains')}
                          desc={t('settings.xrayBlockedDomainsHint')}
                        />
                      }
                    >
                      <Select
                        mode="tags"
                        options={GEOSITE_PRESETS}
                        showSearch={{ optionFilterProp: 'label' }}
                        optionRender={renderGeoOption}
                        tagRender={renderGeoTag}
                        tokenSeparators={[',', ' ']}
                        placeholder={t('settings.xrayGeoPlaceholder')}
                      />
                    </Form.Item>
                    <Form.Item
                      name="xray_ipv4_domains"
                      label={
                        <FieldLabel
                          title={t('settings.xrayIpv4Domains')}
                          desc={t('settings.xrayIpv4DomainsHint')}
                        />
                      }
                    >
                      <Select
                        mode="tags"
                        open={false}
                        tokenSeparators={[',', ' ']}
                        placeholder={t('settings.xrayListPlaceholder')}
                        // Same chip renderer as the two lists above it. Without
                        // it antd draws its own chip, 27.6px against their 21px,
                        // so one field in the group wrapped on a different pitch
                        // and clipped its last row against the shared height cap.
                        tagRender={renderGeoTag}
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
  // `shown` drives the `is-visible` class. It stays false for the first painted
  // frame after mount, then flips true on a later frame so the CSS enter
  // transition (height 0→auto, inner fade+slide) actually runs. Without this the
  // node mounts already at full height and snaps in — jerking the whole page.
  const [shown, setShown] = useState(false);
  // Only true once the bar has actually been open, so the collapsed first frame
  // of a fresh mount is not mistaken for a dismissal.
  const [leaving, setLeaving] = useState(false);
  useEffect(() => {
    if (visible) {
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setMounted(true);
      setLeaving(false);
      // Two frames: the first lets the browser paint the collapsed state, the
      // second commits the open state so the transition has a from-value.
      let raf2 = 0;
      const raf1 = requestAnimationFrame(() => {
        raf2 = requestAnimationFrame(() => setShown(true));
      });
      return () => {
        cancelAnimationFrame(raf1);
        cancelAnimationFrame(raf2);
      };
    }
    setShown(false);
    setLeaving(true);
    // Keep the node alive through the exit animation (see the 0.32–0.34s CSS).
    const id = window.setTimeout(() => setMounted(false), 380);
    return () => window.clearTimeout(id);
  }, [visible]);
  if (!mounted) return null;
  return (
    <div
      // Three states, not two. The entrance is an animation (it has to replay
      // when the page un-hides with the bar already open), so the exit is an
      // animation too rather than a transition: a transition would start from
      // whatever the entrance animation happened to be showing, which collapses
      // the bar instantly if it is discarded while that entrance is still in
      // flight. `is-out` only appears after the bar has been open, so a freshly
      // mounted collapsed bar does not play the exit.
      className={`app-settings-dirtybar${
        shown ? ' is-visible' : leaving ? ' is-out' : ''
      }`}
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
