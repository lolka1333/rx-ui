import { create } from 'zustand';
import { persist } from 'zustand/middleware';

export type ThemeMode = 'light' | 'dark' | 'darker';

interface ThemeState {
  mode: ThemeMode;
  set: (mode: ThemeMode) => void;
}

export const useTheme = create<ThemeState>()(
  persist(
    (set) => ({
      mode: 'dark',
      set: (mode) => set({ mode }),
    }),
    { name: 'app-theme' },
  ),
);

if (import.meta.env.DEV) {
  window.__theme = useTheme;
}
