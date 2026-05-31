import { create } from 'zustand';
import { persist, createJSONStorage } from 'zustand/middleware';
import type { UserView } from '@/api/types';

export type { UserView };

interface AuthState {
  token: string | null;
  user: UserView | null;
  login: (token: string, user: UserView) => void;
  logout: () => void;
}

// `sessionStorage` instead of the default `localStorage`: the bearer token
// is then scoped to a single browser session. Closing the tab/window drops
// the credential — an XSS that exfiltrates `sessionStorage` only gets the
// current session, and the token cannot be read from another tab of the
// same origin. A proper httpOnly cookie + CSRF would be stricter, but for
// a single-admin self-hosted panel this is a meaningful XSS-blast-radius
// reduction at zero UX cost.
export const useAuth = create<AuthState>()(
  persist(
    (set) => ({
      token: null,
      user: null,
      login: (token, user) => set({ token, user }),
      logout: () => set({ token: null, user: null }),
    }),
    {
      name: 'app-auth',
      storage: createJSONStorage(() => sessionStorage),
    },
  ),
);

if (import.meta.env.DEV) {
  window.__auth = useAuth;
}
