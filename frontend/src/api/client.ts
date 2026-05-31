import axios from 'axios';
import { QueryClient } from '@tanstack/react-query';
import { useAuth } from '@/stores/auth';

// Single QueryClient instance shared between the React provider tree and
// the 401 interceptor below — the latter needs to cancel every in-flight
// query after the auth store is cleared, otherwise the dashboard/logs
// pollers keep hitting /api with a stale Authorization header and the
// server logs fill with 401s.
//
// `retry: 0`: the dashboard and logs views run on `refetchInterval`
// (5s / 3s). A built-in retry would double the request rate against a
// flapping backend for no extra coverage — the next polling tick is the
// natural retry. One-off queries that genuinely need a retry can opt in
// per-query.
export const queryClient = new QueryClient({
  defaultOptions: {
    queries: { retry: 0, staleTime: 30_000 },
  },
});

export const apiClient = axios.create({
  baseURL: '/api',
  timeout: 15_000,
});

apiClient.interceptors.request.use((config) => {
  // Defensive: if sessionStorage is corrupted or the zustand store throws
  // during getState (e.g. malformed persisted blob), the unhandled error
  // would break *every* outgoing request. Fall back to no Authorization
  // header — the backend will return 401, the response interceptor below
  // will then run logout()/clear() and put the user back at the login screen
  // where the broken storage gets overwritten on the next successful login.
  let token: string | null = null;
  try {
    token = useAuth.getState().token;
  } catch (e) {
    console.warn('auth store read failed in request interceptor', e);
  }
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

apiClient.interceptors.response.use(
  (resp) => resp,
  (err) => {
    if (err.response?.status === 401) {
      // Drop auth first so any query restarted by clear() reads a null
      // token and is short-circuited at the request interceptor.
      useAuth.getState().logout();
      // Cancel every in-flight poll (dashboard 5s, logs 3s) and clear the
      // cache so the next login starts clean. Without this the pollers
      // keep firing without an Authorization header → cascading 401s.
      queryClient.cancelQueries();
      queryClient.clear();
    }
    return Promise.reject(err);
  },
);
