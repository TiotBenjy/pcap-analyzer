/// <reference types="vitest/config" />
import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import { availableParallelism } from 'node:os';
import { defineConfig } from 'vite';
import { frozenPrototype } from './vite-plugins/frozenPrototype';

// Dev mode (./x.sh dev): the browser talks to Vite only; Vite proxies /api to the Rust backend
// and injects the bearer token, so the token never reaches the page.
const apiUrl = process.env.NETSIFT_API_URL ?? 'http://127.0.0.1:7878';
const apiToken = process.env.NETSIFT_API_TOKEN ?? '';

export default defineConfig({
  plugins: [frozenPrototype(), react(), tailwindcss()],
  // Relative asset paths: required by the Tauri custom protocol.
  base: './',
  server: {
    proxy: {
      '/api': {
        target: apiUrl,
        changeOrigin: true,
        headers: apiToken ? { Authorization: `Bearer ${apiToken}` } : {},
      },
    },
  },
  build: {
    target: 'es2022',
    // No data: URIs for fonts/assets: the desktop CSP only allows data: for images.
    assetsInlineLimit: 0,
    sourcemap: false,
    rollupOptions: {
      output: {
        // Heavy libraries get their own chunks; they are only reached through dynamic imports.
        manualChunks(id) {
          if (id.includes('node_modules/echarts') || id.includes('node_modules/zrender')) return 'echarts';
          if (id.includes('node_modules/sigma') || id.includes('node_modules/graphology')) return 'graph';
          return undefined;
        },
      },
    },
  },
  test: {
    environment: 'jsdom',
    globals: false,
    setupFiles: ['./src/test/setup.ts'],
    include: ['src/**/*.test.{ts,tsx}'],
    css: false,
    // Hang detector, not a speed limit: above Testing Library's asyncUtilTimeout (5 s,
    // src/test/setup.ts) so that a missing element reports its query. The slowest test takes
    // about 2 s on an idle machine and up to 4x that with the load average at 100 on 22 cores.
    testTimeout: 20_000,
    // Several gates (worktrees, release) often run at once on one machine. Measured on 22 cores,
    // idle: 4 workers run the suite in about 10 s against 7.5 s with one fork per file (14), and
    // every extra jsdom fork takes CPU from the other gates.
    maxWorkers: Math.min(4, Math.max(1, availableParallelism() - 1)),
  },
});
