import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';
import { ru } from './ru';
import { en } from './en';

export type Locale = 'ru' | 'en';

export const LOCALES: { value: Locale; label: string; short: string }[] = [
  { value: 'ru', label: 'Русский', short: 'RU' },
  { value: 'en', label: 'English', short: 'EN' },
];

export function isLocale(v: unknown): v is Locale {
  return v === 'ru' || v === 'en';
}

/**
 * Read the persisted locale directly from storage at module-load time so
 * `init({ lng })` matches what `useLocale` will hydrate to — otherwise the
 * first paint renders in `ru` and immediately re-renders in `en` once the
 * store hydrates, producing a visible language flash for English users.
 *
 * We can't import `useLocale` here because `stores/locale.ts` imports the
 * `Locale` type from this file — adding the reverse import would create a
 * cycle. Reading the raw storage entry is self-contained and matches the
 * key/shape that `zustand/persist` writes ({ state: { locale, ... } }).
 */
function initialLocale(): Locale {
  if (typeof window === 'undefined') return 'ru';
  try {
    const raw = window.localStorage.getItem('app-locale');
    if (!raw) return 'ru';
    const parsed = JSON.parse(raw) as { state?: { locale?: unknown } };
    const value = parsed?.state?.locale;
    return isLocale(value) ? value : 'ru';
  } catch {
    return 'ru';
  }
}

// Fire-and-forget init at module load. `init` returns a Promise, but our
// resources are bundled (no network fetch), so it resolves synchronously
// in practice and there's nothing useful to await before the React tree
// renders. `void` flags the dropped promise to the type checker.
void i18n
  .use(initReactI18next)
  .init({
    lng: initialLocale(),
    fallbackLng: 'ru',
    resources: {
      ru: { translation: ru },
      en: { translation: en },
    },
    interpolation: {
      escapeValue: false, // React already escapes
    },
    returnNull: false,
  });

export default i18n;
