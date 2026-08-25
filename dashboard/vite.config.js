import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// The dashboard talks to the backend over same-origin /api and /ws.
// In dev and preview, Vite proxies both to the local backend (port
// 4000 by default). In production, nginx (deployment/nginx.conf) does
// the same job, so the browser code never hardcodes a backend origin.
const backend = process.env.SENTINELX_BACKEND || 'http://127.0.0.1:4000';

const proxy = {
  '/api': { target: backend, changeOrigin: true },
  '/ws': { target: backend.replace(/^http/, 'ws'), ws: true, changeOrigin: true },
};

// allowedHosts: the dashboard may be viewed through a tunnel/preview
// proxy (e.g. GitHub Codespaces, CI web previews) whose Host header is
// not localhost — allow any host so those keep working.
export default defineConfig({
  plugins: [react()],
  server: { host: true, port: 5173, proxy, allowedHosts: true },
  preview: { host: true, port: 4173, proxy, allowedHosts: true },
  build: { outDir: 'dist', sourcemap: false },
});
