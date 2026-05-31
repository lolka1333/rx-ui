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
export type NavPage = 'dashboard' | 'inbounds' | 'clients' | 'settings';

const VALID_PAGES: ReadonlySet<NavPage> = new Set([
  'dashboard',
  'inbounds',
  'clients',
  'settings',
]);

function isNavPage(value: unknown): value is NavPage {
  return typeof value === 'string' && VALID_PAGES.has(value as NavPage);
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
