import { defineConfig, devices } from '@playwright/test';

// Visual checks (`./x.sh shots`): the production build is served by `vite preview`, whose proxy
// forwards /api to the backend started by scripts/ct/shots.sh (NETSIFT_API_URL/NETSIFT_API_TOKEN).
const PORT = Number(process.env.NETSIFT_PREVIEW_PORT ?? 4173);

export default defineConfig({
  testDir: 'tests/visual',
  outputDir: 'test-results',
  fullyParallel: true,
  forbidOnly: process.env.CI !== undefined && process.env.CI !== '',
  retries: 0,
  reporter: [['list']],
  use: {
    baseURL: `http://127.0.0.1:${PORT}`,
    ...devices['Desktop Chrome'],
    deviceScaleFactor: 1,
    locale: 'en-US',
    timezoneId: 'UTC',
  },
  projects: [{ name: 'chromium' }],
  webServer: {
    command: `npm run preview -- --host 127.0.0.1 --port ${PORT} --strictPort`,
    url: `http://127.0.0.1:${PORT}`,
    reuseExistingServer: false,
    timeout: 60_000,
    stdout: 'ignore',
    stderr: 'pipe',
  },
});
