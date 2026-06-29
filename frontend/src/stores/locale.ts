import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import { isLocale, type Locale } from '@/i18n';

interface LocaleState {
  locale: Locale;
  set: (locale: Locale) => void;
}

export const useLocale = create<LocaleState>()(
  persist(
    (set) => ({
      locale: 'ru',
      set: (locale) => set({ locale }),
    }),
    {
      name: 'app-locale',
      // Guard against hand-edited / corrupted localStorage. Without this an
      // arbitrary string would flow into i18next.changeLanguage and into
      // antd's ConfigProvider via ANTD_LOCALES[locale], where it would
      // resolve to `undefined` and break the date picker / empty-state
      // strings until the user reset the storage by hand.
      merge: (persisted, current) => {
        const p = persisted as { locale?: unknown } | undefined;
        return {
          ...current,
          locale: isLocale(p?.locale) ? p.locale : current.locale,
        };
      },
    },
  ),
);

/**
 * Switch the UI language and hard-reload the page. Writes the chosen locale
 * straight into the persisted `app-locale` key (merging into the zustand-persist
 * shape `{ state: { ... }, version }`), then reloads.
 *
 * It deliberately BYPASSES the zustand setter (`useLocale.set`): calling it
 * would notify subscribers and repaint the React tree on the new language a
 * frame before the reload, which looked like a jarring "snap, then reload".
 * Writing storage + reloading gives one clean transition — click, reload
 * spinner, fresh page. The `getState().set` in the catch is only the fallback
 * for when localStorage is unavailable (private mode / quota); the reload still
 * fires so the language takes effect either way.
 *
 * Shared by the admin LanguagePicker and the subscription-page footer picker.
 */
export function setLocaleAndReload(next: Locale): void {
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
    useLocale.getState().set(next);
  }
  window.location.reload();
}
