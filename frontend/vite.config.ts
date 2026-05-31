import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'node:path';

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  build: {
    // Antd alone is ~1MB. We've already split vendors; the warning is informational.
    chunkSizeWarningLimit: 1200,
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
});
