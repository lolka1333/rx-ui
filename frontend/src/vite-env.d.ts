/// <reference types="vite/client" />

declare module '*.css';

// Dev-only zustand store handles exposed on `window` for poking state from
// the browser console. Guarded by `import.meta.env.DEV` so the assignment
// (and the type widening) only exists in development.
declare global {
  interface Window {
    __auth?: typeof import('@/stores/auth').useAuth;
    __theme?: typeof import('@/stores/theme').useTheme;
  }
}

export {};
