import { defineConfig, devices } from '@playwright/test';

// Visual checks (`./x.sh shots`): the production build is served by `vite preview`, whose proxy
// forwards /api to the backend started by scripts/ct/shots.sh (NETSIFT_API_URL/NETSIFT_API_TOKEN).
const PORT = Number(process.env.NETSIFT_PREVIEW_PORT ?? 4173);

// Desktop smoke test (tests/desktop) in WebKit, the engine of the Linux webview (WebKitGTK).
// The image only ships Chromium: scripts/ct/webkit.sh installs Playwright's WebKit and its few
// missing system libraries in the cache volume, then exports its launcher path. In CI, WebKit is
// installed at the default location by `playwright install --with-deps webkit`.
const WEBKIT_EXECUTABLE = process.env.NETSIFT_WEBKIT_EXECUTABLE;

export default defineConfig({
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
  projects: [
    { name: 'chromium', testDir: 'tests/visual' },
    { name: 'desktop-chromium', testDir: 'tests/desktop' },
    {
      name: 'desktop-webkit',
      testDir: 'tests/desktop',
      use: {
        ...devices['Desktop Safari'],
        deviceScaleFactor: 1,
        launchOptions: WEBKIT_EXECUTABLE === undefined ? {} : { executablePath: WEBKIT_EXECUTABLE },
      },
    },
  ],
  webServer: {
    command: `npm run preview -- --host 127.0.0.1 --port ${PORT} --strictPort`,
    url: `http://127.0.0.1:${PORT}`,
    reuseExistingServer: false,
    timeout: 60_000,
    stdout: 'ignore',
    stderr: 'pipe',
  },
});
