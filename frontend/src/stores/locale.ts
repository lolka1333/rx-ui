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
