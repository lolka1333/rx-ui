import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'node:path';

export default defineConfig(({ command }) => ({
  // Relative asset base for the production build so the SPA works both at the
  // root AND under a secret URL prefix: index.html emits `./assets/...` and
  // chunks load via `import.meta.url`, all resolved against the `<base href>`
  // the backend stamps in. Dev stays at '/' so Vite's HMR + module URLs are
  // clean (the dev server serves at the root and proxies /api).
  base: command === 'build' ? './' : '/',
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  build: {
    // antd v6 is a single ~1.23 MB module (its rc-* primitives are inlined, so
    // it can't be split along package boundaries); icons are peeled into their
    // own chunk below. The remaining antd-vendor is irreducible and already
    // cached on its own, so lift the threshold just above it instead of chasing
    // a meaningless split.
    chunkSizeWarningLimit: 1300,
    rolldownOptions: {
      output: {
        // Split heavy dependencies into separate chunks so they can be cached
        // and don't block the initial Login render
        manualChunks(id: string) {
          if (!id.includes('node_modules')) return undefined;
          const norm = id.replace(/\\/g, '/');
          if (/\/(react|react-dom|scheduler)\//.test(norm)) {
            return 'react-vendor';
          }
          // Icons are a self-contained set (tree-shaken to what we use) — their
          // own chunk caches independently of the antd core.
          if (/\/@ant-design\/icons/.test(norm)) {
            return 'icons-vendor';
          }
          if (
            /\/(antd|@ant-design|@rc-component)\//.test(norm) ||
            /\/rc-[\w-]+\//.test(norm)
          ) {
            return 'antd-vendor';
          }
          if (/\/(@tanstack|axios|zustand)\//.test(norm)) {
            return 'data-vendor';
          }
          return undefined;
        },
      },
    },
  },
  server: {
    host: '0.0.0.0',
    port: 5173,
    strictPort: true,
    // `/api` — the JSON API. `/sub` — the public subscription endpoint.
    // Both forward to the backend; in production the backend itself
    // serves every path so this proxy is dev-only. The `/sub` bypass
    // splits the route by Accept header: a browser visit (text/html)
    // lands on Vite's own dev index.html so the React landing page
    // renders with HMR preamble + module URLs that match the dev
    // server; a VPN client (Accept: */*) still proxies through to the
    // backend so import-from-URL keeps returning base64.
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8080',
        changeOrigin: true,
      },
      '/sub': {
        target: 'http://127.0.0.1:8080',
        changeOrigin: true,
        bypass(req) {
          const accept = req.headers.accept ?? '';
          if (accept.includes('text/html')) return '/index.html';
          return null;
        },
      },
    },
  },
  preview: {
    host: '0.0.0.0',
    port: 5173,
    strictPort: true,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8080',
        changeOrigin: true,
      },
      '/sub': {
        target: 'http://127.0.0.1:8080',
        changeOrigin: true,
        bypass(req) {
          const accept = req.headers.accept ?? '';
          if (accept.includes('text/html')) return '/index.html';
          return null;
        },
      },
    },
  },
}));
