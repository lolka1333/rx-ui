import { create } from 'zustand';
import { persist } from 'zustand/middleware';

/**
 * Active top-level page. Persisted to localStorage so a page reload keeps
 * the operator on the same tab — without persistence, every F5 dropped
 * back to Dashboard regardless of what the user was actually doing.
 *
 * We deliberately do NOT use React Router for this. The panel is single-
 * admin, single-host, 2-3 top-level pages — full router infra (route
 * tree, links, back/forward semantics) is heavier than the problem
 * warrants. Bookmarking individual pages also isn't a real use case here.
 *
 * If/when the page count grows past ~5, or deep-link URLs become useful
 * (e.g. `/inbounds/:id`), this should be replaced by a router. For now,
 * localStorage + a tiny enum string is the right shape.
 */
/** Settings categories, surfaced as sub-items under the sidebar's "Settings"
 *  group. Each is a first-class page (rendered full-width in the content area),
 *  keyed `settings-<section>` so it slots into the same `current` nav model as
 *  the top-level pages — no separate modal state. */
export const SETTINGS_SECTIONS = [
  'account',
  'access',
  'tls',
  'subscription',
  'xray',
] as const;
export type SettingsSection = (typeof SETTINGS_SECTIONS)[number];
export type SettingsPage = `settings-${SettingsSection}`;

export type NavPage = 'dashboard' | 'inbounds' | 'outbounds' | 'clients' | SettingsPage;

const VALID_PAGES: ReadonlySet<NavPage> = new Set<NavPage>([
  'dashboard',
  'inbounds',
  'outbounds',
  'clients',
  ...SETTINGS_SECTIONS.map((s): SettingsPage => `settings-${s}`),
]);

export function isNavPage(value: unknown): value is NavPage {
  return typeof value === 'string' && VALID_PAGES.has(value as NavPage);
}

/** True for any `settings-*` page. */
export function isSettingsPage(value: NavPage): value is SettingsPage {
  return value.startsWith('settings-');
}

/** The section a `settings-*` page targets, or null for a top-level page. */
export function settingsSectionOf(value: NavPage): SettingsSection | null {
  return isSettingsPage(value) ? (value.slice('settings-'.length) as SettingsSection) : null;
}

/** The two settings destinations under the sidebar's "Settings" accordion:
 *  "panel" (account / access / TLS / subscription, in a tabbed container) and
 *  the standalone Xray page. True for the former. */
export function isPanelSettingsPage(value: NavPage): boolean {
  return isSettingsPage(value) && value !== 'settings-xray';
}

interface NavState {
  current: NavPage;
  setCurrent: (page: NavPage) => void;
}

export const useNav = create<NavState>()(
  persist(
    (set) => ({
      current: 'dashboard',
      setCurrent: (page) => set({ current: page }),
    }),
    {
      name: 'app-nav',
      // Defensive merge: if someone hand-edits localStorage or we ship a
      // version that removes a page, fall back to the in-code default
      // rather than rendering a broken (empty) page.
      merge: (persisted, current) => {
        const p = persisted as { current?: unknown } | undefined;
        return {
          ...current,
          current: isNavPage(p?.current) ? p.current : current.current,
        };
      },
    },
  ),
);
