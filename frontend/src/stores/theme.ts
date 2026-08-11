import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import type { ThemeMode } from '@/theme/palette';

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
