import type { ThemeConfig } from 'antd';
import { theme as antdTheme } from 'antd';
import { PALETTES } from '@/theme/palette';
import type { ThemeMode } from '@/theme/palette';

// The "you are here" wash behind the active navigation row. Deliberately
// translucent: it tints the rail instead of covering it, so the row reads as
// part of the sidebar rather than a plate dropped on top of it — and the
// accent stays on the glyph, where it says "this page", instead of flooding a
// whole block. One function feeds both the Antd Menu tokens and the
// `--nav-active` variable, so the few CSS rules that must paint this state on
// elements Antd doesn't tokenise (a shut submenu title) can't drift out of
// step with the menu itself.
function navActive(mode: ThemeMode): string {
  // Lighter on white — the same alpha that reads as a gentle tint on a dark
  // rail turns into a solid lilac band on a light one.
  return mode === 'light' ? 'rgba(99, 102, 241, 0.14)' : 'rgba(99, 102, 241, 0.18)';
}

function build(mode: ThemeMode): ThemeConfig {
  const isLight = mode === 'light';
  const p = PALETTES[mode];
  const active = navActive(mode);

  const menuDark = {
    darkItemBg: 'transparent',
    darkSubMenuItemBg: 'transparent',
    // Hover flyouts off the collapsed rail are portalled to <body>, so they
    // escape both the sider's own background and any `.ant-layout-sider`
    // rule. Antd's dark algorithm then falls back to its stock navy
    // (#001529), which ignores our palette entirely — on "очень тёмная" the
    // popup stayed blue while everything around it went neutral near-black.
    // The elevated surface is the right fill: it's what every other portalled
    // panel (dropdown, popover, modal) already uses via `colorBgElevated`.
    darkPopupBg: p.surfaceElev,
    darkItemSelectedBg: active,
    darkItemSelectedColor: p.text,
    // Kept in step with the hover rule in index.css, which is what actually
    // paints (it carries `!important`; this token does not).
    darkItemHoverBg: 'rgba(255, 255, 255, 0.04)',
    // Antd's default here is pure white, which left a row you were merely
    // pointing at brighter than the row you were actually on. Hover now lands
    // on the same text colour as the active row; what separates them is the
    // wash, the weight and the accent glyph, not who is whiter.
    darkItemHoverColor: p.text,
    // Resting labels sit a step below the active row's ink — that step is what
    // makes "selected" legible once the fill stopped being a solid block. On
    // "тёмная" the step is a cool slate. On "очень тёмная" it takes the
    // palette's own secondary ink instead: that palette is deliberately
    // neutral, and #cbd5e1 was both the one blue-leaning grey left in it and,
    // at 1.00:1 against #d4d4d4, no step at all.
    darkItemColor: mode === 'darker' ? p.textSecondary : '#cbd5e1',
  };
  const menuLight = {
    itemBg: 'transparent',
    subMenuItemBg: 'transparent',
    itemSelectedBg: active,
    itemSelectedColor: p.text,
    // An open group whose child is active: antd tints the parent title with
    // `colorPrimary` unless told otherwise, so on the light palette "Настройки"
    // alone turned indigo while every other row kept its normal ink. The dark
    // algorithm derives this from `darkItemSelectedColor` and needs no twin.
    subMenuItemSelectedColor: p.text,
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
        // Deep slate on the light and "тёмная" palettes; neutral near-black on
        // "очень тёмная", where a slate fill is the one blue patch left on an
        // otherwise grayscale screen.
        colorBgSpotlight: mode === 'darker' ? 'rgba(20, 20, 20, 0.98)' : 'rgba(15, 23, 42, 0.97)',
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
  r.setProperty('--nav-active', navActive(mode));
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
