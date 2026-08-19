import { useEffect, useMemo } from 'react';
import { App as AntdApp, ConfigProvider } from 'antd';
import ruRU from 'antd/locale/ru_RU';
import enUS from 'antd/locale/en_US';
import { QueryClientProvider } from '@tanstack/react-query';
import App from './App';
import { useTheme } from '@/stores/theme';
import { useLocale } from '@/stores/locale';
import { THEMES, applyCssVariables } from '@/theme/tokens';
import { ErrorBoundary } from '@/components/ErrorBoundary';
import { queryClient } from '@/api/client';
import i18n from '@/i18n';

// Antd's built-in locale bundles for ru/en — passed to ConfigProvider so
// internal components (DatePicker, Pagination, Empty) speak the same
// language as our i18n strings.
const ANTD_LOCALES = { ru: ruRU, en: enUS } as const;

export function Root() {
  const mode = useTheme((s) => s.mode);
  const locale = useLocale((s) => s.locale);

  useEffect(() => {
    applyCssVariables(mode);
  }, [mode]);

  // Push the locale into i18next and antd in lockstep so a single store
  // controls both the app text and antd's built-in strings (datepicker,
  // empty-state, etc).
  useEffect(() => {
    if (i18n.language !== locale) {
      // changeLanguage returns a Promise that resolves once the new
      // translations are loaded. Our bundles are static, so we don't
      // need to block the render on it — the next render after state
      // change picks up the new strings. `.catch` keeps a hypothetical
      // failure (loader override, future async-load) from surfacing as
      // an unhandled-rejection devtools warning.
      i18n.changeLanguage(locale).catch((e: unknown) => {
        console.warn('i18n.changeLanguage failed', e);
      });
    }
    document.documentElement.lang = locale;
  }, [locale]);

  // Memoised: a fresh theme object on every render makes antd recompute its
  // token cache and re-render every styled component under it.
  const antdTheme = useMemo(
    () => ({
      ...THEMES[mode],
      // Lift antd popups (Select dropdowns, tooltips, toasts) above the
      // settings modal overlay (z-index 1100) — otherwise they open behind
      // it and look broken (the language dropdown wouldn't show).
      token: { ...THEMES[mode].token, zIndexPopupBase: 1200 },
    }),
    [mode],
  );

  return (
    // `input.autoComplete` is set once here rather than field by field: this
    // is an operator console, and every text field in it — a server address, a
    // tag, a path — is a value the browser has no business remembering or
    // offering back. The two password fields ask for their own semantics at
    // their call sites, which overrides this.
    <ConfigProvider
      locale={ANTD_LOCALES[locale]}
      theme={antdTheme}
      input={{ autoComplete: 'off' }}
    >
      {/* <AntdApp> provides a context-aware message/notification/modal so
          static `message.success(...)` calls pick up the current theme and
          locale instead of antd's global fallback. Components should switch
          to `App.useApp().message` over time. */}
      <AntdApp>
        <QueryClientProvider client={queryClient}>
          <ErrorBoundary>
            <App />
          </ErrorBoundary>
        </QueryClientProvider>
      </AntdApp>
    </ConfigProvider>
  );
}
