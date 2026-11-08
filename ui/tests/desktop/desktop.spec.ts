import { expect, type Locator, type Page, test } from '@playwright/test';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { ScanResponse } from '../../src/api/types/ScanResponse';

// Desktop smoke test (`./x.sh shots` or `./x.sh shots desktop`): the production build with what
// Tauri injects before any page script of the desktop webview:
//   - `Object.freeze(Object.prototype)`: `freezePrototype: true` in tauri.conf.json; tauri 2 runs
//     its scripts/freeze_prototype.js first in the init script, and freezes nothing else;
//   - `window.__TAURI_INTERNALS__`, whose `invoke` answers the commands the UI uses
//     (`get_api_endpoint`, `set_ui_language`, `plugin:dialog|open`).
// So the desktop-only code paths (Tauri bridge, native picker) and the lazily loaded chart chunk
// run under the constraints of the AppImage. Projects: `desktop-webkit` (WebKit, the engine of
// WebKitGTK and of the macOS webview) and `desktop-chromium` (close to WebView2 on Windows; its
// messages name the property, e.g. "Cannot assign to read only property 'constructor'").
// The test fails on any uncaught page error, console error, and on any route error screen.

interface DemoSession {
  id: string;
  name: string;
  state: string;
  anomaly_count: number;
  chunk_count: number;
}

const PICKED_FILE = '/captures/desktop-smoke.pcapng';
/** Same folder as the view captures of tests/visual. */
const OUT_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '../../../.artifacts/screens');

async function demoSession(page: Page): Promise<DemoSession> {
  const res = await page.request.get('/api/v1/sessions?limit=1000');
  expect(res.ok(), 'demo API reachable through the preview proxy').toBe(true);
  const body = (await res.json()) as { items?: DemoSession[] };
  const ready = (body.items ?? [])
    .filter((s) => s.state === 'ready')
    .sort((a, b) => b.anomaly_count - a.anomaly_count || b.chunk_count - a.chunk_count);
  const first = ready[0];
  if (first === undefined) throw new Error('no ready demo session (netsift demo-session)');
  return first;
}

/** Installs the Tauri globals before any page script, freeze first as Tauri does. */
async function emulateTauri(page: Page): Promise<void> {
  await page.addInitScript((picked: string) => {
    Object.freeze(Object.prototype);

    try {
      localStorage.setItem('netsift.lang', 'en');
    } catch {
      /* ignore */
    }
    const calls: string[] = [];
    let nextCallback = 1;
    const internals = {
      calls,
      transformCallback: () => nextCallback++,
      unregisterCallback: () => undefined,
      invoke(cmd: string): Promise<unknown> {
        calls.push(cmd);
        switch (cmd) {
          case 'get_api_endpoint':
            // The preview proxy adds the real token; this one only exercises the header.
            return Promise.resolve({ base_url: `${location.origin}/api/v1`, token: 'desktop-smoke' });
          case 'set_ui_language':
            return Promise.resolve(null);
          case 'plugin:dialog|open':
            return Promise.resolve(picked);
          default:
            return Promise.reject(new Error(`unexpected Tauri command ${cmd}`));
        }
      },
    };
    Object.defineProperty(window, '__TAURI_INTERNALS__', { value: internals });
  }, PICKED_FILE);
}

/** Collects uncaught errors and console errors, with the stack when the argument is an Error. */
function watchErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(`pageerror ${e.stack ?? e.message}`));
  page.on('console', (m) => {
    if (m.type() !== 'error') return;
    const text = `console.error ${m.text()}`;
    const index = errors.push(text) - 1;
    const first = m.args()[0];
    if (first === undefined) return;
    void first
      .evaluate((e: unknown) => (e instanceof Error ? (e.stack ?? '') : ''))
      .then((stack) => {
        if (stack !== '') errors[index] = `${text}\n${stack}`;
      })
      .catch(() => undefined);
  });
  return errors;
}

/**
 * Waits for `ready` or an error screen, whichever comes first, then requires a healthy page.
 * (A failing lazy chunk shows the error screen only after its module is evaluated.)
 */
async function expectHealthy(page: Page, errors: string[], when: string, ready: Locator): Promise<void> {
  await expect(ready.or(page.getByTestId('route-error')).or(page.getByText('Something went wrong!')).first()).toBeVisible();
  await page.waitForLoadState('networkidle');
  const detail = () => errors.join('\n\n');
  await expect(page.getByText('Something went wrong!'), `TanStack default error screen (${when})\n${detail()}`).toHaveCount(0);
  await expect(page.getByTestId('route-error'), `route error screen (${when})\n${detail()}`).toHaveCount(0);
  expect(errors, `errors in the page (${when})`).toEqual([]);
}

test('desktop smoke: native import dialog, session overview and sources', async ({ page }) => {
  const errors = watchErrors(page);
  const session = await demoSession(page);
  await emulateTauri(page);
  // The demo API is read-only: report a writable server so the import buttons are enabled (the
  // wizard stops before starting the import).
  await page.route('**/api/v1/server-info', async (route) => {
    const res = await route.fetch();
    const info = (await res.json()) as Record<string, unknown>;
    await route.fulfill({ response: res, json: { ...info, read_only: false } });
  });
  // The picked path does not exist on the demo server (and its roots refuse it): canned scan.
  const scan: ScanResponse = {
    path: PICKED_FILE,
    groups: [
      {
        id: 0,
        pattern: 'single_file',
        prefix: 'desktop-smoke',
        file_count: 1,
        total_bytes: 4096,
        first_ts_us: 1_700_000_000_000_000,
        last_ts_us: 1_700_000_060_000_000,
        anomalies: [],
      },
    ],
    skipped: [],
    truncated: false,
  };
  await page.route('**/api/v1/sessions/import/scan', (route) => route.fulfill({ json: scan }));
  await page.setViewportSize({ width: 1440, height: 900 });

  await page.goto('/#/captures');
  await expectHealthy(page, errors, 'captures', page.getByRole('table', { name: 'Sessions' }));

  // Import file: system dialog (plugin:dialog|open), then the review step.
  await page.getByRole('button', { name: 'Import file' }).first().click();
  await page.getByRole('dialog').getByRole('button', { name: 'Choose a file' }).click();
  await expectHealthy(page, errors, 'import review', page.getByRole('dialog').getByRole('button', { name: 'Start import' }));
  await page.keyboard.press('Escape');
  await expect(page.getByRole('dialog')).toHaveCount(0);

  // Opening a session from the list: the step that failed in the desktop app.
  await page.getByRole('button', { name: `Open ${session.name}` }).first().click();
  await page.waitForURL(new RegExp(`/sessions/${session.id}/overview$`));
  // The traffic chart is drawn: the ECharts chunk loaded and ran under the frozen prototype.
  const chart = page.getByRole('img', { name: /^Traffic by protocol/ }).locator('svg').first();
  await expectHealthy(page, errors, 'overview', chart);
  await expect(page.getByTestId('overview-summary')).toBeVisible();

  await page.getByRole('link', { name: 'Sources' }).first().click();
  await expectHealthy(page, errors, 'sources', page.getByRole('table', { name: 'Chunks of the session' }));
  await expect(page.getByRole('img', { name: /^Coverage timeline/ })).toBeVisible();

  // The desktop bridge was used, not the web fallback.
  const commands = await page.evaluate(
    () => (window as unknown as { __TAURI_INTERNALS__: { calls: string[] } }).__TAURI_INTERNALS__.calls,
  );
  expect(commands).toEqual(expect.arrayContaining(['get_api_endpoint', 'set_ui_language', 'plugin:dialog|open']));
});

test('desktop smoke: a failing view shows the NetSift error screen', async ({ page }, testInfo) => {
  await emulateTauri(page);
  // The chart chunk fails to load: the route must render RouteError, not the TanStack default.
  await page.route(/\/assets\/EChartsRenderer-[^/]+\.js$/, (route) => route.abort());
  const session = await demoSession(page);
  await page.goto(`/#/sessions/${session.id}/overview`);
  const screen = page.getByTestId('route-error');
  await expect(screen).toBeVisible();
  await expect(screen.getByRole('heading', { name: 'This view could not be displayed' })).toBeVisible();
  await expect(screen.getByRole('button', { name: 'Reload' })).toBeVisible();
  await expect(screen.getByRole('button', { name: 'Copy details' })).toBeVisible();
  await expect(page.getByText('Something went wrong!')).toHaveCount(0);
  // The shell stays usable around the error.
  await expect(page.getByRole('navigation').first()).toBeVisible();
  await page.screenshot({ path: `${OUT_DIR}/route-error-${testInfo.project.name}.png` });
});
