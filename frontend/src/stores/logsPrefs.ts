import { create } from 'zustand';
import { persist } from 'zustand/middleware';

export type LogLevel = 'all' | 'info' | 'warn' | 'error';

interface LogsPrefsState {
  limit: number;
  level: LogLevel;
  autoRefresh: boolean;
  setLimit: (limit: number) => void;
  setLevel: (level: LogLevel) => void;
  setAutoRefresh: (v: boolean) => void;
}

/**
 * Persisted UI prefs for the Logs modal — limit/level/auto-refresh stick
 * across reopens and page reloads via localStorage.
 */
export const useLogsPrefs = create<LogsPrefsState>()(
  persist(
    (set) => ({
      limit: 20,
      level: 'info',
      autoRefresh: false,
      setLimit: (limit) => set({ limit }),
      setLevel: (level) => set({ level }),
      setAutoRefresh: (autoRefresh) => set({ autoRefresh }),
    }),
    { name: 'app-logs-prefs' },
  ),
);
