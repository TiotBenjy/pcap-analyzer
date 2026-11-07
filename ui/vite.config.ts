/// <reference types="vitest/config" />
import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

// Dev mode (./x.sh dev): the browser talks to Vite only; Vite proxies /api to the Rust backend
// and injects the bearer token, so the token never reaches the page.
const apiUrl = process.env.NETSIFT_API_URL ?? 'http://127.0.0.1:7878';
const apiToken = process.env.NETSIFT_API_TOKEN ?? '';

export default defineConfig({
  plugins: [react(), tailwindcss()],
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
  },
});
