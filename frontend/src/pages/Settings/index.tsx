/**
 * Settings — a full-width page. The sidebar's "Settings" accordion selects
 * the visible category via the `section` prop; every section stays mounted,
 * so the form state and the cross-section "save all" dirty registry survive
 * switching categories (and navigating away and back). Rendered
 * always-mounted by AdminApp, revealed when `current` is a `settings-*` page.
 *
 * One file per section. `fields.tsx` holds the row primitives they share and
 * `dirty.ts` the unsaved-changes wiring the bar at the top of the page saves
 * through.
 */
import { Button, Tabs, Typography } from 'antd';
import { ControlOutlined, LinkOutlined, SafetyCertificateOutlined, UserOutlined } from '@ant-design/icons';
import { useQuery } from '@tanstack/react-query';
import { useCallback, useEffect, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { apiClient } from '@/api/client';
import { useLoadState } from '@/api/loadState';
import { useNav } from '@/stores/nav';
import type { SettingsSection } from '@/stores/nav';
import type { PanelSettings } from '@/api/types';
import { AccessSection } from './AccessSection';
import { AccountSection } from './AccountSection';
import { SubscriptionSection } from './SubscriptionSection';
import { TlsSection } from './TlsSection';
import { XraySection } from './XraySection';
import type { DirtyHandle } from './dirty';

type SectionKey = 'account' | 'access' | 'subscription' | 'xray' | 'tls';

// PanelSettings *_DEFAULTS and the whole-row PUT merge (`mergePanelSettings`)
// live in `@/lib/panelSettings` — shared with the reverse-pair wizard, which
// can't import from this component module (react-refresh only-export-components).

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
