import type { ThemeConfig } from 'antd';
import { theme as antdTheme } from 'antd';
import type { ThemeMode } from '@/stores/theme';

interface Palette {
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

const PALETTES: Record<ThemeMode, Palette> = {
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
    text: '#fafafa',
    textSecondary: '#a1a1a1',
    textTertiary: '#717171',
  },
};

function build(mode: ThemeMode): ThemeConfig {
  const isLight = mode === 'light';
  const p = PALETTES[mode];

  const menuDark = {
    darkItemBg: 'transparent',
    darkSubMenuItemBg: 'transparent',
    // The vivid solid accent reads fine on the bluish "тёмная" bg, but on the
    // near-black "очень тёмная" bg (#050505) it glares. There the selected
    // item gets a muted, translucent indigo fill instead of the full-bright
    // solid, so it still reads as "selected" without burning.
    darkItemSelectedBg: mode === 'darker' ? 'rgba(99, 102, 241, 0.55)' : '#6366f1',
    darkItemSelectedColor: '#ffffff',
    darkItemHoverBg: 'rgba(255, 255, 255, 0.06)',
    darkItemActiveBg: 'rgba(255, 255, 255, 0.06)',
    darkItemColor: '#cbd5e1',
  };
  const menuLight = {
    itemBg: 'transparent',
    subMenuItemBg: 'transparent',
    itemSelectedBg: '#6366f1',
    itemSelectedColor: '#ffffff',
    itemHoverBg: 'rgba(0, 0, 0, 0.04)',
    itemActiveBg: 'rgba(0, 0, 0, 0.04)',
    itemColor: '#334155',
  };

  return {
    // cssVar emits Antd's design tokens as `--ant-*` CSS variables instead of
    // baking literal values into class rules. Theme switching becomes a single
    // variable swap — no CSS-in-JS regen, no <style> tag rewrite, no layout
    // thrash. `hashed: false` keeps Antd's class names stable across renders.
    cssVar: { key: 'xp' },
    hashed: false,
    algorithm: isLight ? antdTheme.defaultAlgorithm : antdTheme.darkAlgorithm,
    token: {
      colorPrimary: '#6366f1',
      colorBgBase: p.bg,
      colorBgContainer: p.surface,
      colorBgElevated: p.surfaceElev,
      colorBgLayout: p.bgLayout,
      colorBorder: p.border,
      colorBorderSecondary: p.border,
      colorText: p.text,
      colorTextSecondary: p.textSecondary,
      colorTextTertiary: p.textTertiary,
      colorSuccess: '#22c55e',
      colorError: '#ef4444',
      colorWarning: '#f59e0b',
      controlItemBgActive: isLight ? 'rgba(99, 102, 241, 0.08)' : 'rgba(99, 102, 241, 0.16)',
      controlItemBgActiveHover: isLight ? 'rgba(99, 102, 241, 0.12)' : 'rgba(99, 102, 241, 0.22)',
      borderRadius: 10,
      borderRadiusLG: 14,
      fontFamily: '"Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
      fontSize: 14,
      fontSizeHeading2: 26,
      fontSizeHeading3: 20,
      fontWeightStrong: 600,
      controlHeight: 36,
      controlHeightLG: 42,
      wireframe: false,
      motionDurationSlow: '0.18s',
      motionDurationMid: '0.14s',
      motionDurationFast: '0.08s',
      // Antd's dark algorithm replaces the default drop-shadows with a
      // multi-stop white glow (`rgba(255,255,255,0.01)` etc). On high-DPI
      // displays with non-integer scaling the wide low-alpha stops quantize
      // into visible pixel bands around popups (Select dropdown, message
      // toast, Modal). Single-stop black shadows render cleanly on both
      // palettes — light surfaces still cast a soft dark shadow, dark
      // surfaces sink into the bg without the banded glow.
      boxShadow:
        '0 2px 6px rgba(0, 0, 0, 0.18), 0 4px 12px rgba(0, 0, 0, 0.22)',
      boxShadowSecondary:
        '0 6px 16px rgba(0, 0, 0, 0.28), 0 3px 6px rgba(0, 0, 0, 0.18)',
      boxShadowTertiary: '0 2px 6px rgba(0, 0, 0, 0.2)',
    },
    components: {
      Layout: {
        siderBg: p.sidebar,
        headerBg: p.sidebar,
        bodyBg: 'transparent',
      },
      Menu: {
        ...(isLight ? menuLight : menuDark),
        itemBorderRadius: 10,
        itemMarginInline: 12,
        itemMarginBlock: 3,
        itemHeight: 40,
        fontSize: 13,
        iconSize: 16,
        collapsedIconSize: 18,
      },
      Card: {
        colorBgContainer: p.surface,
        paddingLG: 20,
      },
      Button: {
        primaryShadow: 'none',
        defaultShadow: 'none',
      },
      Table: {
        headerBg: 'transparent',
        headerColor: p.textTertiary,
        headerSplitColor: 'transparent',
        rowHoverBg: isLight ? 'rgba(0,0,0,0.02)' : 'rgba(255,255,255,0.02)',
        borderColor: p.border,
      },
      Progress: {
        circleTextColor: p.text,
      },
      Switch: {
        colorPrimary: '#6366f1',
        colorPrimaryHover: '#4f46e5',
      },
      Tooltip: {
        colorBgSpotlight: isLight ? 'rgba(15, 23, 42, 0.96)' : 'rgba(15, 23, 42, 0.98)',
        colorTextLightSolid: '#f1f5f9',
        borderRadiusOuter: 6,
        boxShadowSecondary: '0 4px 12px rgba(0,0,0,0.25)',
        fontSize: 12,
        controlHeight: 24,
        sizePopupArrow: 0,
      },
      Drawer: {
        colorBgElevated: p.sidebar,
      },
    },
  };
}

// Pre-built once at module load — buildThemeConfig won't run on every mode change.
export const THEMES: Record<ThemeMode, ThemeConfig> = {
  light: build('light'),
  dark: build('dark'),
  darker: build('darker'),
};

export function applyCssVariables(mode: ThemeMode): void {
  const p = PALETTES[mode];
  const r = document.documentElement.style;
  r.setProperty('--bg', p.bg);
  r.setProperty('--sidebar', p.sidebar);
  r.setProperty('--surface', p.surface);
  r.setProperty('--surface-2', p.surfaceElev);
  r.setProperty('--border', p.border);
  r.setProperty('--border-strong', p.borderStrong);
  r.setProperty('--text', p.text);
  r.setProperty('--text-2', p.textSecondary);
  r.setProperty('--text-3', p.textTertiary);
  r.setProperty('--accent', '#6366f1');
  // Keep <html>'s inline backgroundColor in sync — the pre-paint script
  // in index.html sets it on initial load to avoid a flash-of-white, but
  // it only runs once. Without this line, switching theme mid-session
  // updates every CSS variable AND every Antd component, but the html
  // element keeps showing the stale colour from page load, which leaks
  // through any time the layout doesn't fully cover the viewport (and
  // shows through Antd's transparent body bg). Setting it here makes
  // theme switches feel atomic.
  r.backgroundColor = p.bg;
  document.documentElement.dataset.theme = mode;
}
