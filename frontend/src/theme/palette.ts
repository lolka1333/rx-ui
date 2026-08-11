/**
 * The three palettes, and the layout constants the pre-paint shell shares with
 * the app.
 *
 * This module exists apart from `tokens.ts` because two very different things
 * need to read it. `tokens.ts` turns it into an Antd theme, and `vite.config.ts`
 * stamps a couple of these values straight into `index.html` — the inline
 * script that paints the page's background and the sidebar column before the
 * bundle has even parsed. That script cannot import anything, so the values
 * used to be typed out a second time in the HTML with a "keep them in sync"
 * comment standing guard. They drifted anyway: the mobile drawer sat on
 * `#0c0d10` for a whole palette revision after the real colour became
 * `#0d0d0d`. Hence: one definition, injected at build time.
 *
 * Keep this file free of imports. Anything it pulls in, the Vite config pulls
 * in too, and the config runs in Node before any of the app's dependencies are
 * available.
 */

export type ThemeMode = 'light' | 'dark' | 'darker';

export interface Palette {
  bg: string;
  bgLayout: string;
  sidebar: string;
  surface: string;
  surfaceElev: string;
  border: string;
  borderStrong: string;
  text: string;
  textSecondary: string;
  textTertiary: string;
}

export const PALETTES: Record<ThemeMode, Palette> = {
  light: {
    bg: '#f8fafc',
    bgLayout: '#f1f5f9',
    sidebar: '#ffffff',
    surface: '#ffffff',
    surfaceElev: '#ffffff',
    border: '#e2e8f0',
    borderStrong: '#cbd5e1',
    text: '#0f172a',
    textSecondary: '#475569',
    textTertiary: '#64748b',
  },
  dark: {
    bg: '#0b1220',
    bgLayout: '#0b1220',
    sidebar: '#131c2e',
    surface: '#131c2e',
    surfaceElev: '#1a2438',
    border: '#1e2a44',
    borderStrong: '#2a3a5c',
    text: '#f1f5f9',
    textSecondary: '#94a3b8',
    textTertiary: '#64748b',
  },
  darker: {
    // Pure grayscale at every level — earlier values (#0c0d10, #1b1d22, …)
    // had a 5-7-unit blue lean per channel that the eye reads as bluish-
    // violet against the near-black bg, especially on input borders. The
    // operator wants "очень тёмная" to actually feel neutral-dark, not
    // tinted, so every R/G/B trio is now equal.
    bg: '#050505',
    bgLayout: '#050505',
    sidebar: '#0d0d0d',
    surface: '#0d0d0d',
    surfaceElev: '#141414',
    border: '#1f1f1f',
    borderStrong: '#2d2d2d',
    // Soft off-white, NOT pure white. Near-white (#fafafa) on the near-black
    // bg is ~18:1 contrast — technically great, but it glares and tires the
    // eye on this very-dark palette. ~#d4 keeps it crisply readable (~12:1)
    // while taking the harsh edge off all primary text app-wide.
    text: '#d4d4d4',
    textSecondary: '#a1a1a1',
    textTertiary: '#717171',
  },
};

/** Expanded rail width. Also the width of the pre-paint placeholder column. */
export const SIDEBAR_WIDTH = 208;
/** Collapsed rail: icons only. Not persisted, so the shell never draws it. */
export const SIDEBAR_COLLAPSED = 64;
