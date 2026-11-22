import { expect, type Page, test } from '@playwright/test';
import { mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { en } from '../../src/i18n/en';
import { fr } from '../../src/i18n/fr';
import { mockBackwardAnomalies, mockImportProgress } from './anomalyMocks';
import { mockUpdate } from './updateMocks';

// Screenshots + automated layout assertions from docs/UI_GUIDELINES.md ("Tests visuels"):
//   1. PNG per view, width and theme in .artifacts/screens/<view>-<width>-<theme>.png
//   2. no horizontal overflow (page or main column); the document never scrolls (only #main does),
//      even with #main scrolled to the bottom, and no absolutely positioned box escapes its scroll
//      container (an `sr-only` label without a positioned ancestor makes the whole page scroll)
//   3. no overlapping text/tspan boxes inside one SVG chart, no label outside its SVG
//   4. every [data-testid="truncatable"] element has a title
// Select views with SHOT_VIEW=<name>|all and languages with SHOT_LANG=en|fr|all.
//
// French runs (`fr/` subfolder, light theme: text length does not depend on the theme) open the
// view in English, switch the language in Settings without reloading, come back through the
// history and only then check and capture the view: they prove the language switch reaches
// mounted views and cached queries, and that the longer French labels fit.

/**
 * Views covered by the visual tests. Add a line when a view is implemented. Session views resolve
 * their path at run time, on the demo session created by `netsift demo-session`.
 */
const VIEWS: Record<string, string | ((page: Page) => Promise<string>)> = {
  captures: '/captures',
  'captures-geoip-missing': '/captures',
  connections: async (page) => `/sessions/${await demoSessionId(page)}/connections`,
  'connections-flows': async (page) => `/sessions/${await demoSessionId(page)}/connections`,
  credentials: async (page) => `/sessions/${await demoSessionId(page)}/credentials`,
  'credentials-range': async (page) => rangedPath(page, 'credentials'),
  'credentials-export': async (page) => `/sessions/${await demoSessionId(page)}/credentials`,
  'credentials-open': async (page) => `/sessions/${await demoSessionId(page)}/credentials`,
  dns: async (page) => `/sessions/${await demoSessionId(page)}/dns`,
  'dns-range': async (page) => rangedPath(page, 'dns'),
  http: async (page) => `/sessions/${await demoSessionId(page)}/http`,
  'http-range': async (page) => rangedPath(page, 'http'),
  'http-headers': async (page) => `/sessions/${await demoSessionId(page)}/http-headers`,
  'import-progress': '/captures',
  network: async (page) => `/sessions/${await demoSessionId(page)}/network`,
  'network-detail': async (page) => `/sessions/${await demoSessionId(page)}/network`,
  'open-ports': async (page) => `/sessions/${await demoSessionId(page)}/open-ports`,
  overview: async (page) => `/sessions/${await demoSessionId(page)}/overview`,
  'overview-export': async (page) => `/sessions/${await demoSessionId(page)}/overview`,
  'overview-range': async (page) => rangedPath(page, 'overview'),
  'overview-range-dialog': async (page) => rangedPath(page, 'overview'),
  pictures: async (page) => `/sessions/${await demoSessionId(page)}/pictures`,
  servers: async (page) => `/sessions/${await demoSessionId(page)}/servers`,
  'servers-empty': async (page) => `/sessions/${await demoSessionId(page)}/servers`,
  'servers-filter': async (page) => `/sessions/${await demoSessionId(page)}/servers`,
  settings: '/settings',
  'settings-geoip-outdated': '/settings',
  'settings-licenses': '/settings',
  'settings-licenses-initial': '/settings',
  'settings-notices-both': '/settings',
  'settings-update': '/settings',
  'settings-update-notes': '/settings',
  smb: async (page) => `/sessions/${await demoSessionId(page)}/smb`,
  'smb-auth': async (page) => `/sessions/${await demoSessionId(page)}/smb?tab=auth`,
  'smb-auth-range': async (page) => rangedPath(page, 'smb', 'tab=auth'),
  'smb-range': async (page) => rangedPath(page, 'smb'),
  sources: async (page) => `/sessions/${await demoSessionId(page)}/sources`,
  'sources-backwards': async (page) => `/sessions/${await demoSessionId(page)}/sources`,
  ssdp: async (page) => `/sessions/${await demoSessionId(page)}/ssdp`,
  'ssdp-filter': async (page) => `/sessions/${await demoSessionId(page)}/ssdp`,
  'ssdp-range': async (page) => rangedPath(page, 'ssdp'),
  'ssdp-raw': async (page) => `/sessions/${await demoSessionId(page)}/ssdp`,
  tls: async (page) => `/sessions/${await demoSessionId(page)}/tls`,
  'tls-range': async (page) => rangedPath(page, 'tls'),
  'connections-range': async (page) => rangedPath(page, 'connections'),
};

/** Secrets of the demo session (fake fixture values), which the Credentials captures must never show. */
const DEMO_SECRETS = [
  's3cret-fixture',
  'demo-only',
  'basic-fixture',
  'proxy-fixture',
  'smtp-fixture',
  'login-fixture',
  'pop-fixture',
  'imap-fixture',
  'ldap-fixture',
  '::CONTOSO:',
];

/** Placeholder id when no session exists: the session views then render their error or not-found state. */
const NO_SESSION = '00000000000000000000000000';

/**
 * Demo session used by the session views: the ready session with the most anomalies, then the
 * most chunks (best coverage timeline). Read through the `vite preview` proxy, which adds the token.
 */
async function demoSessionId(page: Page): Promise<string> {
  const res = await page.request.get('/api/v1/sessions?limit=1000');
  if (!res.ok()) return NO_SESSION;
  const body = (await res.json()) as { items?: { id: string; state: string; anomaly_count: number; chunk_count: number }[] };
  const ranked = [...(body.items ?? [])].sort(
    (a, b) =>
      Number(b.state === 'ready') - Number(a.state === 'ready') ||
      b.anomaly_count - a.anomaly_count ||
      b.chunk_count - a.chunk_count,
  );
  return ranked[0]?.id ?? NO_SESSION;
}

/**
 * `view` of the demo session under a time range (P5.2): the second quarter of its captured period,
 * so that the header shows the range chip and the view the figures of the range.
 */
async function rangedPath(page: Page, view: string, extra = ''): Promise<string> {
  const id = await demoSessionId(page);
  const res = await page.request.get(`/api/v1/sessions/${id}/summary`);
  if (!res.ok()) return `/sessions/${id}/${view}`;
  const s = (await res.json()) as { first_ts_us: number | null; last_ts_us: number | null };
  if (s.first_ts_us === null || s.last_ts_us === null) return `/sessions/${id}/${view}`;
  // The busiest fifth of the period (by bytes, over 20 buckets), so that the views have rows.
  const series = await page.request.get(`/api/v1/sessions/${id}/timeseries?points=20&metric=bytes`);
  const t = (await series.json()) as { start_us: number; step_us: number; points: number; series: { bytes: number[] | null }[] };
  const totals = Array.from({ length: t.points }, (_, i) => t.series.reduce((sum, p) => sum + (p.bytes?.[i] ?? 0), 0));
  const width = Math.max(1, Math.floor(t.points / 5));
  let best = 0;
  let bestSum = -1;
  for (let i = 0; i + width <= t.points; i++) {
    const sum = totals.slice(i, i + width).reduce((a, b) => a + b, 0);
    if (sum > bestSum) {
      best = i;
      bestSum = sum;
    }
  }
  const from = t.start_us + best * t.step_us;
  const more = extra === '' ? '' : `&${extra}`;
  return `/sessions/${id}/${view}?from_us=${from}&to_us=${from + width * t.step_us - 1}${more}`;
}

/**
 * Views captured with the GeoIP notice (P4.9). The shots server is read-only, so it never offers
 * the database: `GET /geoip/status` is mocked, and `server-info` / `settings` are patched (writable
 * server, startup check on) so that the banner and Settings > Online render as a user sees them.
 */
const GEOIP_NOTICE: Record<string, 'missing' | 'outdated'> = {
  'captures-geoip-missing': 'missing',
  'settings-geoip-outdated': 'outdated',
  'settings-notices-both': 'outdated',
};

/** `YYYY-MM` of the month `back` months before the current one (UTC). */
function monthKey(back = 0): string {
  const now = new Date();
  const d = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - back, 1));
  return `${String(d.getUTCFullYear())}-${String(d.getUTCMonth() + 1).padStart(2, '0')}`;
}

async function mockGeoipNotice(page: Page, kind: 'missing' | 'outdated'): Promise<void> {
  const status =
    kind === 'missing'
      ? { state: 'missing', built_month: null, online: 'off', published_month: null, offer: 'download' }
      : { state: 'outdated', built_month: monthKey(2), online: 'published', published_month: monthKey(), offer: 'update' };
  await page.route('**/api/v1/geoip/status', (route) =>
    route.fulfill({ json: { current_month: monthKey(), ...status } }),
  );
  // Settings > About shows the same database as the banner.
  const built = new Date(`${monthKey(2)}-01T00:00:00Z`).getTime() * 1000;
  const geoip =
    kind === 'outdated'
      ? { status: 'available', source: 'bundled', built_at_us: built, size_bytes: 8 << 20, installed_at_us: null }
      : { status: 'missing', source: null, built_at_us: null, size_bytes: null, installed_at_us: null };
  await page.route('**/api/v1/server-info', async (route) => {
    const res = await route.fetch();
    return route.fulfill({ response: res, json: { ...((await res.json()) as object), read_only: false, geoip } });
  });
  await page.route('**/api/v1/settings', async (route) => {
    if (route.request().method() !== 'GET') return route.continue();
    const res = await route.fetch();
    const body = (await res.json()) as { online: object };
    return route.fulfill({ response: res, json: { ...body, online: { ...body.online, geoip_check: kind === 'outdated' } } });
  });
}

type Lang = 'en' | 'fr';
const DICTIONARIES = { en, fr } as const;

const selectedLang = process.env.SHOT_LANG ?? 'all';
if (!['en', 'fr', 'all'].includes(selectedLang)) throw new Error(`unknown language "${selectedLang}"; known: en, fr, all`);
const LANGS: readonly Lang[] = selectedLang === 'all' ? ['en', 'fr'] : [selectedLang as Lang];

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * Accessible name or text pattern of a dictionary template: placeholders match anything, any
 * whitespace (French no-break spaces included) matches any whitespace. Anchored at the start
 * unless `anywhere`; whole value when `exact`.
 */
function pattern(template: string, { exact = false, anywhere = false } = {}): RegExp {
  const body = template
    .split(/\{\{[^}]+\}\}/)
    .map((part) => escapeRe(part).replace(/\s+/g, '\\s+'))
    .join('.+?');
  return new RegExp(`${anywhere ? '' : '^'}${body}${exact ? '$' : ''}`);
}

/** Exact name of a dictionary value with its placeholders filled. */
function filled(template: string, values: Record<string, string> = {}): RegExp {
  return pattern(template.replace(/\{\{(\w+)\}\}/g, (_m, k: string) => values[k] ?? `{{${k}}}`), { exact: true });
}

/**
 * Upper bound for a view to finish loading. Only this wait is long: the first chart of a view
 * needs the lazy ECharts chunk and its query, which can take several seconds when other gates
 * share the machine.
 */
const LOAD_TIMEOUT = 20_000;

/** Waits until no loading placeholder is left and every chart has drawn its SVG. */
async function settled(page: Page): Promise<void> {
  await expect(page.locator('#main [data-skeleton]')).toHaveCount(0, { timeout: LOAD_TIMEOUT });
  await page.waitForFunction(
    () =>
      [...document.querySelectorAll('#main [data-chart]')].every(
        (chart) => (chart.querySelector('svg')?.childElementCount ?? 0) > 0,
      ),
    undefined,
    { timeout: LOAD_TIMEOUT },
  );
}

const WIDTHS = [375, 768, 1280, 1920] as const;
const THEMES = ['light', 'dark'] as const;
const HEIGHT = 900;
/** Upper bound of a capture height (very long views are cut there). */
const MAX_SHOT_HEIGHT = 6000;

const here = dirname(fileURLToPath(import.meta.url));
const OUT_DIR = resolve(here, '../../../.artifacts/screens');

const selected = process.env.SHOT_VIEW ?? 'all';
const views = Object.entries(VIEWS).filter(([name]) => selected === 'all' || selected === name);
if (views.length === 0) throw new Error(`unknown view "${selected}"; known: ${Object.keys(VIEWS).join(', ')}`);

interface LayoutReport {
  pageOverflow: { scrollWidth: number; innerWidth: number } | null;
  documentScroll: { scrollWidth: number; scrollHeight: number; innerWidth: number; innerHeight: number } | null;
  bodyScroll: { scrollWidth: number; scrollHeight: number; clientWidth: number; clientHeight: number } | null;
  escaping: string[];
  mainOverflow: { scrollWidth: number; clientWidth: number } | null;
  overlaps: string[];
  outside: string[];
  untitled: string[];
}

async function inspectLayout(page: Page): Promise<LayoutReport> {
  return page.evaluate(() => {
    const TOL = 1;
    const doc = document.documentElement;
    const main = document.getElementById('main');
    // Measured even though html/body hide their overflow (index.css): that guard only stops the
    // user from scrolling, the overflow itself is the bug.
    const scroller = document.scrollingElement ?? doc;
    const report: LayoutReport = {
      pageOverflow: doc.scrollWidth > window.innerWidth ? { scrollWidth: doc.scrollWidth, innerWidth: window.innerWidth } : null,
      documentScroll:
        scroller.scrollHeight > window.innerHeight + TOL || scroller.scrollWidth > window.innerWidth + TOL
          ? {
              scrollWidth: scroller.scrollWidth,
              scrollHeight: scroller.scrollHeight,
              innerWidth: window.innerWidth,
              innerHeight: window.innerHeight,
            }
          : null,
      // With overflow hidden on html, body is a scroll container of its own: an in-flow overflow
      // is clipped there (not counted above) but focus can still scroll it.
      bodyScroll:
        document.body.scrollHeight > document.body.clientHeight + TOL || document.body.scrollWidth > document.body.clientWidth + TOL
          ? {
              scrollWidth: document.body.scrollWidth,
              scrollHeight: document.body.scrollHeight,
              clientWidth: document.body.clientWidth,
              clientHeight: document.body.clientHeight,
            }
          : null,
      escaping: [],
      mainOverflow:
        main !== null && main.scrollWidth > main.clientWidth + TOL
          ? { scrollWidth: main.scrollWidth, clientWidth: main.clientWidth }
          : null,
      overlaps: [],
      outside: [],
      untitled: [],
    };

    const label = (el: Element) => (el.textContent ?? '').trim().slice(0, 40);

    // An absolutely positioned box takes its nearest positioned ancestor as containing block. When
    // that ancestor lies outside the nearest scroll container (or there is none: the viewport), the
    // box is neither clipped nor scrolled by the container and extends the page at its static position.
    const scrolls = (el: Element) => {
      const cs = getComputedStyle(el);
      return /auto|scroll/.test(`${cs.overflowX} ${cs.overflowY}`);
    };
    for (const el of document.body.querySelectorAll('*')) {
      if (!(el instanceof HTMLElement) || getComputedStyle(el).position !== 'absolute') continue;
      let container = el.parentElement;
      while (container !== null && container !== document.body && !scrolls(container)) container = container.parentElement;
      if (container === null || container === document.body) continue;
      const block = el.offsetParent;
      // offsetParent is null for a box that is not rendered (display: none in an ancestor).
      if (block === null && el.getClientRects().length === 0) continue;
      if (block === null || !container.contains(block)) {
        const where = container.id === '' ? container.tagName.toLowerCase() : `#${container.id}`;
        report.escaping.push(`${el.tagName.toLowerCase()}.${el.className} "${label(el)}" out of ${where}`);
      }
    }
    for (const svg of document.querySelectorAll('svg')) {
      // Icons (lucide) have no text; only charts are checked.
      const texts = [...svg.querySelectorAll('text, tspan')].filter((t) => {
        // A <text> whose content is entirely in <tspan> children is checked through them.
        if (t.tagName === 'text' && t.querySelector('tspan') !== null) return false;
        const r = t.getBoundingClientRect();
        return (t.textContent ?? '').trim() !== '' && r.width > 0 && r.height > 0;
      });
      if (texts.length === 0) continue;
      const box = svg.getBoundingClientRect();
      const rects = texts.map((t) => ({ el: t, r: t.getBoundingClientRect() }));
      for (const { el, r } of rects) {
        if (r.left < box.left - TOL || r.right > box.right + TOL || r.top < box.top - TOL || r.bottom > box.bottom + TOL) {
          report.outside.push(label(el));
        }
      }
      rects.forEach((a, i) => {
        for (const b of rects.slice(i + 1)) {
          const w = Math.min(a.r.right, b.r.right) - Math.max(a.r.left, b.r.left);
          const h = Math.min(a.r.bottom, b.r.bottom) - Math.max(a.r.top, b.r.top);
          if (w > TOL && h > TOL) report.overlaps.push(`"${label(a.el)}" / "${label(b.el)}"`);
        }
      });
    }

    for (const el of document.querySelectorAll('[data-testid="truncatable"]')) {
      if (!el.hasAttribute('title')) report.untitled.push(label(el));
    }
    return report;
  });
}

test.beforeAll(() => {
  mkdirSync(OUT_DIR, { recursive: true });
  mkdirSync(`${OUT_DIR}/fr`, { recursive: true });
});

for (const lang of LANGS) {
  for (const [view, target] of views) {
    for (const theme of lang === 'en' ? THEMES : (['light'] as const)) {
      for (const width of WIDTHS) {
        test(`${view} ${width}px ${theme}${lang === 'en' ? '' : ` ${lang}`}`, async ({ page }) => {
          const D = DICTIONARIES[lang];
          const shotDir = lang === 'en' ? OUT_DIR : `${OUT_DIR}/${lang}`;
          // Deterministic environment: English UI, theme from the emulated system preference.
          await page.addInitScript(() => {
            try {
              localStorage.setItem('netsift.lang', 'en');
              localStorage.removeItem('netsift.theme');
            } catch {
              /* ignore */
            }
            // Same as the desktop webview (`freezePrototype` in tauri.conf.json).
            Object.freeze(Object.prototype);
          });
          const pageErrors: string[] = [];
          page.on('pageerror', (e) => pageErrors.push(e.message));
          await page.emulateMedia({ colorScheme: theme, reducedMotion: 'reduce' });
          await page.setViewportSize({ width, height: HEIGHT });

          const path = typeof target === 'string' ? target : await target(page);
          const geoipNotice = GEOIP_NOTICE[view];
          if (geoipNotice !== undefined) await mockGeoipNotice(page, geoipNotice);
          // Mocked server answers of some views (online checks: no network in screenshots).
          if (view.startsWith('settings-update') || view === 'settings-notices-both') await mockUpdate(page);
          if (view === 'import-progress') await mockImportProgress(page);
          if (view === 'sources-backwards') await mockBackwardAnomalies(page);
          await page.goto(`/#${path}`);
          await page.locator('#main h1').first().waitFor();
          await page.waitForLoadState('networkidle');
          await page.evaluate(() => document.fonts.ready);
          await settled(page);

          await expect(page.locator('html')).toHaveClass(theme === 'dark' ? /\bdark\b/ : /^(?!.*\bdark\b)/);

          if (lang !== 'en') {
            // Language switch without reload: Settings (in-app navigation), then back to the view,
            // whose queries are already cached.
            const away = path !== '/settings';
            if (away) {
              await page.evaluate(() => {
                window.location.hash = '#/settings';
              });
            }
            // The radio is visually hidden behind its label (segmented control): click the label.
            const choice = page.getByRole('radio', { name: D.language[lang] });
            await page.locator('label').filter({ has: choice }).click();
            await expect(choice).toBeChecked();
            await expect(page.locator('html')).toHaveAttribute('lang', lang);
            if (away) {
              await page.goBack();
              await expect(page).toHaveURL(new RegExp(`#${escapeRe(path)}$`));
            }
            await page.locator('#main h1').first().waitFor();
            await page.waitForLoadState('networkidle');
            await settled(page);
          }

          // With the demo sessions, the data views must show data, not an empty or error state.
          if (view === 'captures' && (await demoSessionId(page)) !== NO_SESSION) {
            await expect(
              page.getByRole('table', { name: D.views.captures.tableLabel }).or(page.getByRole('list', { name: D.views.captures.tableLabel })),
            ).toBeVisible();
          }
          if (view === 'sources' && !path.includes(NO_SESSION)) {
            await expect(page.getByRole('img', { name: pattern(D.views.sources.coverageLabel_other) })).toBeVisible();
            await expect(page.getByRole('table', { name: D.views.sources.chunksLabel }).or(page.getByRole('list', { name: D.views.sources.chunksLabel }))).toBeVisible();
          }

          if (view === 'import-progress') {
            // Grouped warnings of a finished import, reopened from the importing row (mocked stream).
            await page.getByRole('button', { name: filled(D.views.captures.progress, { name: 'office-ring-buffer' }) }).click();
            const dialog = page.getByRole('dialog', { name: D.views.import.titleProgress });
            await expect(dialog.getByText(D.views.import.done, { exact: true })).toBeVisible();
            await expect(dialog.getByRole('region', { name: D.views.import.warnings }).getByRole('listitem')).toHaveCount(6);
          }
          if (view === 'sources-backwards' && !path.includes(NO_SESSION)) {
            await expect(page.getByTestId('anomaly-summary')).toContainText(pattern(D.views.sources.summaryBackwards_other, { anywhere: true }));
          }

          if (view === 'overview' && !path.includes(NO_SESSION)) {
            await expect(page.getByTestId('overview-summary')).toBeVisible();
            await expect(page.getByRole('img', { name: pattern(D.views.overview.traffic.chartLabel) })).toBeVisible();
            // The demo session must show at least DNS, HTTP and TLS in the series.
            const id = path.split('/')[2] ?? NO_SESSION;
            const res = await page.request.get(`/api/v1/sessions/${id}/timeseries?points=200`);
            expect(res.ok()).toBe(true);
            const body = (await res.json()) as { series: { protocol: string }[] };
            const protocols = body.series.map((s) => s.protocol);
            for (const p of ['dns', 'http', 'tls']) expect(protocols).toContain(p);
          }

          if (view === 'connections' && !path.includes(NO_SESSION)) {
            await expect(page.getByRole('table', { name: D.views.connections.table.label }).or(page.getByRole('list', { name: D.views.connections.table.label }))).toBeVisible();
            await expect(page
                .getByRole('list', { name: filled(D.views.connections.countries.listLabel, { title: D.views.connections.countries.sources }) })
                .or(page.getByText(D.views.connections.countries.noCountry).first())).toBeVisible();
            // Chord diagram from 768 px, ranked pairs below.
            await expect(
              width >= 768
                ? page.getByRole('img', { name: pattern(D.views.connections.chord.chartLabel) })
                : page.getByRole('list', { name: D.views.connections.chord.listLabel }),
            ).toBeVisible();
          }
          if (view === 'overview-export' && !path.includes(NO_SESSION)) {
            // Save PCAP dialog with the time range: left open for the capture (read-only server:
            // the Save button stays disabled, nothing is written).
            await page.getByRole('button', { name: D.views.exportPcap.action, exact: true }).click();
            const dialog = page.getByRole('dialog', { name: D.views.exportPcap.dialog.title });
            await expect(dialog).toBeVisible();
            // The radio is visually hidden behind its label (segmented control): click the label.
            await dialog.getByText(D.views.exportPcap.dialog.range, { exact: true }).click();
            await expect(dialog.getByRole('radio', { name: D.views.exportPcap.dialog.range })).toBeChecked();
            await expect(dialog.getByRole('textbox', { name: D.views.exportPcap.dialog.from })).toBeVisible();
            await expect(dialog.getByRole('button', { name: D.views.exportPcap.dialog.start, exact: true })).toBeDisabled();
          }
          if (view.endsWith('-range') && !path.includes(NO_SESSION)) {
            // The header chip shows the active range (dimmed on a view that does not apply it).
            await expect(page.getByTestId('time-range-chip')).toBeVisible();
            await page.waitForLoadState('networkidle');
          }
          if (view === 'smb-auth-range' && !path.includes(NO_SESSION)) {
            // No NTLM session in the busiest fifth of the demo: the empty state of a range.
            await expect(page.getByText(D.timeRange.emptyText).first()).toBeVisible();
            await expect(page.getByRole('button', { name: D.timeRange.clear }).last()).toBeVisible();
          }
          if (view === 'overview-range-dialog' && !path.includes(NO_SESSION)) {
            await page.getByRole('button', { name: D.timeRange.controls.edit, exact: true }).click();
            await expect(page.getByRole('dialog', { name: D.timeRange.dialog.title })).toBeVisible();
          }
          if (view === 'connections-flows' && !path.includes(NO_SESSION)) {
            // Flows of the largest conversation, each with its Save PCAP action.
            await page.getByRole('button', { name: pattern(D.views.exportPcap.flows.actionLabel) }).first().click();
            const dialog = page.getByRole('dialog', { name: D.views.exportPcap.flows.title });
            await expect(dialog.getByRole('list', { name: D.views.exportPcap.flows.listLabel })).toBeVisible();
            await page.waitForLoadState('networkidle');
          }
          if ((view === 'network' || view === 'network-detail') && !path.includes(NO_SESSION)) {
            await expect(page.getByTestId('network-summary')).toBeVisible();
            if (width >= 768) {
              // sigma (WebGL) draws the graph once the layout worker answered; without WebGL the
              // links are listed, which the capture must make obvious.
              const canvas = page.getByTestId('network-canvas');
              await expect(canvas.or(page.getByText(pattern(D.views.network.graph.noWebgl.split(/\s*:/)[0] ?? '')))).toBeVisible();
              if ((await canvas.count()) > 0) await expect(canvas).toHaveAttribute('data-ready', 'true');
            } else {
              await expect(page.getByRole('list', { name: D.views.network.graph.listLabel })).toBeVisible();
            }
          }
          if (view === 'network-detail' && !path.includes(NO_SESSION)) {
            // The file server found by the search: its detail panel and server role badges.
            await page.getByRole('searchbox').fill('FILESRV01');
            const panel = page.getByRole('complementary', { name: D.views.network.panel.title });
            await expect(panel.getByText(filled(D.views.network.panel.role, { role: 'SMB' }))).toBeVisible();
            await expect(panel.getByRole('list', { name: D.views.network.panel.neighbors })).toBeVisible();
            await page.waitForLoadState('networkidle');
            await page.evaluate(() => document.getElementById('main')?.scrollTo(0, 0));
          }
          if (view.startsWith('credentials') && !path.includes(NO_SESSION)) {
            const list = page.getByRole('list', { name: D.views.credentials.list.label, exact: true });
            await expect(list).toBeVisible();
            await expect(
              page
                .getByRole('table', { name: D.views.credentials.paths.label })
                .or(page.getByRole('list', { name: D.views.credentials.paths.label })),
            ).toBeVisible();
            if (view === 'credentials-open') {
              // The first card expanded: its secret is fetched but stays masked in the capture.
              await list.getByRole('button', { expanded: false }).first().click();
              await expect(page.getByText(pattern(D.secret.hidden_other.split('(')[0] ?? '')).first()).toBeVisible();
              await page.waitForLoadState('networkidle');
              await page.evaluate(() => document.getElementById('main')?.scrollTo(0, 0));
            }
            if (view === 'credentials-export') {
              // Confirmation dialog: checked and captured on its own, then the export runs and the
              // sensitive-data banner is part of the main capture.
              await page.getByRole('button', { name: D.views.credentials.export.csv, exact: true }).first().click();
              const dialog = page.getByRole('dialog', { name: D.views.credentials.export.title });
              await expect(dialog).toBeVisible();
              const r = await inspectLayout(page);
              expect(r.pageOverflow, 'horizontal page overflow (export dialog)').toBeNull();
              expect(r.documentScroll, 'the document scrolls (export dialog)').toBeNull();
              expect(r.bodyScroll, 'the body scrolls (export dialog)').toBeNull();
              expect(r.escaping, 'absolutely positioned boxes outside their scroll container (export dialog)').toEqual([]);
              expect(r.untitled, 'truncatable elements without title (export dialog)').toEqual([]);
              await page.screenshot({ path: `${shotDir}/credentials-export-dialog-${width}-${theme}.png` });
              const download = page.waitForEvent('download');
              await dialog.getByRole('button', { name: D.views.credentials.export.confirm, exact: true }).click();
              const file = await download;
              expect(file.suggestedFilename()).toMatch(/^credentials-.*\.csv$/);
              await expect(page.getByText(pattern(D.views.credentials.export.banner, { anywhere: true }))).toBeVisible();
              await expect(dialog).toBeHidden();
            }
            // Fixture secrets of the demo session never appear in clear text.
            const text = await page.evaluate(() => document.body.innerText);
            for (const secret of DEMO_SECRETS) expect(text.includes(secret), `secret visible: ${secret.length} chars`).toBe(false);
          }
          if (view === 'open-ports' && !path.includes(NO_SESSION)) {
            await expect(page.getByRole('list', { name: D.views.openPorts.chart.label })).toBeVisible();
            await expect(
              page
                .getByRole('table', { name: D.views.openPorts.table.label })
                .or(page.getByRole('list', { name: D.views.openPorts.table.label })),
            ).toBeVisible();
          }
          if (view === 'pictures' && !path.includes(NO_SESSION)) {
            await expect(page.getByTestId('pictures-summary')).toBeVisible();
            const grid = page.getByRole('list', { name: D.views.pictures.gridLabel });
            await expect(grid).toBeVisible();
            // Thumbnails are PNG generated by the backend, inlined as data: URLs (no other source).
            await expect(grid.locator('img').first()).toBeVisible();
            const sources = await grid.locator('img').evaluateAll((imgs) => imgs.map((i) => i.getAttribute('src') ?? ''));
            for (const src of sources) expect(src.startsWith('data:image/png;base64,')).toBe(true);
          }
          if (view === 'tls' && !path.includes(NO_SESSION)) {
            await expect(page.getByTestId('tls-summary')).toBeVisible();
            await expect(page.getByRole('img', { name: pattern(D.views.tls.charts.versionsLabel) })).toBeVisible();
            await expect(page.getByRole('table', { name: D.views.tls.table.label }).or(page.getByRole('list', { name: D.views.tls.table.label }))).toBeVisible();
            await expect(page.getByRole('list', { name: D.views.tls.charts.suitesLabel })).toBeVisible();
          }
          if ((view === 'http' || view === 'http-headers') && !path.includes(NO_SESSION)) {
            const list = filled(view === 'http' ? D.views.http.listLabel : D.views.httpHeaders.listLabel);
            // Methods: a donut up to five groups, bars beyond.
            await expect(
              page.getByRole('img', { name: pattern(D.views.http.methodsLabel) }).or(page.getByRole('list', { name: D.views.http.methodsLabel })),
            ).toBeVisible();
            await expect(page.getByRole('list', { name: list })).toBeVisible();
            if (view === 'http-headers') {
              // Search a session cookie: the expanded row then shows masked values and highlights.
              const before = (await page.getByTestId('http-row-count').textContent()) ?? '';
              await page.getByRole('searchbox').fill('session');
              await expect(page.getByTestId('http-row-count')).not.toHaveText(before);
              await page.waitForLoadState('networkidle');
            }
            // The first row expanded: details (and masked header values) are part of the review.
            await page.getByRole('list', { name: list }).getByRole('button', { expanded: false }).first().click();
            await expect(page.getByRole('table', { name: D.views.http.detail.requestHeaders }).first()).toBeVisible();
            await page.waitForLoadState('networkidle');
          }
          if (view === 'dns' && !path.includes(NO_SESSION)) {
            await expect(page.getByRole('list', { name: D.views.dns.charts.resultsLabel })).toBeVisible();
            const pairs = page.getByRole('table', { name: D.views.dns.table.label });
            await expect(pairs.or(page.getByRole('list', { name: D.views.dns.table.label }))).toBeVisible();
            // The first pair expanded: its queries are laid out and checked too.
            await page.getByRole('button', { name: pattern(D.views.dns.table.expand) }).first().click();
            await expect(
              page
                .getByRole('table', { name: pattern(D.views.dns.messages.label) })
                .or(page.getByRole('list', { name: pattern(D.views.dns.messages.label) })),
            ).toBeVisible();
            await page.waitForLoadState('networkidle');
            // Clicking scrolled the main column: back to the top for the capture.
            await page.evaluate(() => document.getElementById('main')?.scrollTo(0, 0));
          }

          if (view.startsWith('ssdp') && !path.includes(NO_SESSION)) {
            await expect(page.getByTestId('ssdp-summary')).toBeVisible();
            await expect(page.getByRole('list', { name: D.views.ssdp.devices.label })).toBeVisible();
            const messages = page.getByRole('list', { name: D.views.ssdp.messages.label });
            await expect(messages).toBeVisible();
            if (view === 'ssdp-range') {
              // Folded device counters: "whole session" under the column title, or in each card below md.
              const whole = page.getByText(new RegExp(escapeRe(D.timeRange.wholeSession), 'i')).locator('visible=true');
              await expect(whole.first()).toBeVisible();
            }
            if (view === 'ssdp-filter') {
              // The printer as sender: its filter chip, then NOTIFY alive / byebye and response badges.
              await page.getByRole('button', { name: filled(D.views.ssdp.rank.filterSender, { address: '192.168.1.50' }) }).click();
              await expect(page.getByText(filled(D.views.ssdp.messages.senderChip, { address: '192.168.1.50' }))).toBeVisible();
              await expect(messages.getByText(`${D.views.ssdp.messages.badge.notify} byebye`).first()).toBeVisible();
              await expect(messages.getByText(filled(D.views.ssdp.messages.badge.response, { status: '200' })).first()).toBeVisible();
              await page.waitForLoadState('networkidle');
              await page.evaluate(() => document.getElementById('main')?.scrollTo(0, 0));
            }
            if (view === 'ssdp-raw') {
              // The first device and the first message expanded: raw text in a mono block, copy actions.
              await page.getByRole('list', { name: D.views.ssdp.devices.label }).getByRole('button', { expanded: false }).first().click();
              await messages.getByRole('button', { expanded: false }).first().click();
              await expect(page.getByTestId('ssdp-raw')).toBeVisible();
              await page.waitForLoadState('networkidle');
              await page.evaluate(() => document.getElementById('main')?.scrollTo(0, 0));
            }
          }

          if (view === 'servers' && !path.includes(NO_SESSION)) {
            await expect(page.getByRole('list', { name: D.views.servers.rolesLabel })).toBeVisible();
            const dnsServers = filled(D.views.servers.listLabel, { role: 'DNS' });
            const dns = page.getByRole('table', { name: dnsServers }).or(page.getByRole('list', { name: dnsServers }));
            await expect(dns).toBeVisible();
            // The first DNS server expanded: its evidence is laid out and checked too.
            await page.getByRole('button', { name: pattern(D.views.servers.showEvidence) }).first().click();
            await expect(
              page
                .getByRole('table', { name: pattern(D.views.servers.evidenceLabel) })
                .or(page.getByRole('list', { name: pattern(D.views.servers.evidenceLabel) })),
            ).toBeVisible();
            await page.evaluate(() => document.getElementById('main')?.scrollTo(0, 0));
          }

          if ((view === 'servers-empty' || view === 'servers-filter') && !path.includes(NO_SESSION)) {
            const dnsServers = filled(D.views.servers.listLabel, { role: 'DNS' });
            await expect(page.getByRole('table', { name: dnsServers }).or(page.getByRole('list', { name: dnsServers }))).toBeVisible();
            await page.getByRole('button', { name: pattern(D.views.servers.categories) }).click();
            await expect(page.getByRole('group', { name: D.views.servers.categories })).toBeVisible();
            if (view === 'servers-empty') {
              // LAN servers off: the roles served only on the LAN show their empty state.
              await page.getByRole('checkbox', { name: D.addressCategories.private }).uncheck();
              await expect(page.getByText(filled(D.views.servers.empty, { role: 'LDAP' }))).toBeVisible();
              await page.keyboard.press('Escape');
              await expect(page.getByRole('group', { name: D.views.servers.categories })).toBeHidden();
            }
            await page.waitForLoadState('networkidle');
          }

          if (geoipNotice !== undefined) {
            const banner = page.getByTestId('notice-geoip');
            await expect(banner).toBeVisible();
            const action = geoipNotice === 'missing' ? D.views.geoipPrompt.download : D.views.geoipPrompt.update;
            await expect(banner.getByRole('button', { name: action, exact: true })).toBeEnabled();
            await expect(banner.getByRole('button', { name: D.notices.dismiss })).toBeVisible();
            if (geoipNotice === 'outdated') {
              await expect(page.getByTestId('geoip-check-status')).toContainText(pattern(D.views.geoipPrompt.checkPublished, { anywhere: true }));
            }
          }
          if (view === 'settings') {
            // /server-info is authenticated: "Read-only" proves the proxy injects a valid token.
            await expect(page.getByTestId('backend-status')).toContainText(D.views.settings.backendOk.split(',')[0] ?? '');
            await expect(page.getByTestId('server-mode')).toHaveText(D.views.settings.readOnly);
            // Online checks read from the server settings: off by default, locked when read-only.
            const online = page.getByTestId('online-settings');
            for (const name of [D.views.online.geoipCheck, D.views.online.updateCheck]) {
              const toggle = online.getByRole('switch', { name });
              await expect(toggle).toHaveAttribute('aria-checked', 'false');
              await expect(toggle).toBeDisabled();
            }
          }
          if (view === 'settings-update' || view === 'settings-update-notes') {
            // Newer release (mocked): banner with the notes as text, result in About, release page
            // link in web mode (no download from the screenshot server).
            const banner = page.getByTestId('notice-update');
            await expect(banner).toContainText(pattern(D.views.updates.available.replace('{{version}}', '0.2.0'), { anywhere: true }));
            await expect(banner.getByTestId('update-release-page')).toBeVisible();
            await expect(page.getByTestId('update-status')).toHaveAttribute('data-status', 'available');
            await expect(page.getByTestId('update-section').getByTestId('update-release-page')).toBeVisible();
          }
          if (view === 'settings-notices-both') {
            // MAX_NOTICES = 2: the GeoIP and update banners stack under the header, in registry order.
            const area = page.getByTestId('notice-area');
            await expect(area.getByTestId('notice-geoip')).toBeVisible();
            await expect(area.getByTestId('notice-update')).toBeVisible();
            await expect(area.locator('[data-testid^="notice-"]')).toHaveCount(2);
          }
          if (view === 'settings-update-notes') {
            await page.getByTestId('update-section').getByRole('button', { name: D.views.updates.notes }).click();
            const dialog = page.getByRole('dialog', { name: filled(D.views.updates.notesTitle, { version: '0.2.0' }) });
            await expect(dialog.locator('pre')).toContainText('<b>Markup stays text</b>');
          }
          if (view === 'settings-licenses' || view === 'settings-licenses-initial') {
            // Third-party licenses: the dialog as it opens (groups closed), then, for
            // settings-licenses, a search, one package and its license text shown.
            await page.getByRole('button', { name: D.views.settings.thirdParty.open }).click();
            const dialog = page.getByRole('dialog', { name: D.views.settings.thirdParty.title });
            await expect(dialog.getByTestId('licenses-count')).toBeVisible();
            await expect(dialog.getByTestId('license-package')).toHaveCount(0);
          }
          if (view === 'settings-licenses') {
            const dialog = page.getByRole('dialog', { name: D.views.settings.thirdParty.title });
            await dialog.getByRole('searchbox').fill('tauri');
            await dialog.getByRole('button', { name: D.views.settings.thirdParty.showText }).first().click();
            await expect(dialog.locator('pre').first()).toBeVisible();
            await settled(page);
          }

          const check = async (when: string) => {
            const r = await inspectLayout(page);
            expect(r.pageOverflow, `horizontal page overflow (${when})`).toBeNull();
            expect(r.documentScroll, `the document scrolls, not only #main (${when})`).toBeNull();
            expect(r.bodyScroll, `the body scrolls, not only #main (${when})`).toBeNull();
            expect(r.escaping, `absolutely positioned boxes outside their scroll container (${when})`).toEqual([]);
            expect(r.mainOverflow, `horizontal overflow in the main column (${when})`).toBeNull();
            expect(r.overlaps, `overlapping chart labels (${when})`).toEqual([]);
            expect(r.outside, `chart labels outside their SVG (${when})`).toEqual([]);
            expect(r.untitled, `truncatable elements without title (${when})`).toEqual([]);
          };
          await settled(page);
          await check(`${HEIGHT}px high`);
          expect(pageErrors, 'uncaught errors in the page (frozen Object.prototype)').toEqual([]);

          // Bottom of a long view: boxes laid out far down #main must not extend the document.
          const scrollTop = await page.evaluate(() => {
            const main = document.getElementById('main');
            const top = main?.scrollTop ?? 0;
            main?.scrollTo(0, main.scrollHeight);
            return top;
          });
          await check('#main scrolled to the bottom');
          await page.evaluate((top) => document.getElementById('main')?.scrollTo(0, top), scrollTop);

          // `#main` scrolls, not the page, so `fullPage` alone would only capture the first screen:
          // grow the viewport to the content height (same width, same layout) before the capture.
          const contentHeight = await page.evaluate(() => {
            const main = document.getElementById('main');
            return main === null ? 0 : Math.ceil(main.getBoundingClientRect().top + main.scrollHeight);
          });
          if (contentHeight > HEIGHT) {
            await page.setViewportSize({ width, height: Math.min(contentHeight, MAX_SHOT_HEIGHT) });
            await page.waitForTimeout(100); // ResizeObserver-driven layouts (timeline) settle
          }

          // Key data must be visible in the capture, not clipped by an internal scroll.
          const hidden = await page.evaluate(() =>
            [...document.querySelectorAll('[data-shot-visible]')]
              .filter((el) => {
                // Behind an open modal dialog (import progress), the page is covered on purpose.
                const modal = document.querySelector('[aria-modal="true"]');
                if (modal !== null && !modal.contains(el)) return false;
                const r = el.getBoundingClientRect();
                if (r.width === 0 || r.right > window.innerWidth || r.bottom > window.innerHeight) return true;
                const hit = document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2);
                return hit === null || !el.contains(hit);
              })
              .map((el) => el.getAttribute('data-shot-visible')),
          );
          expect(hidden, 'key elements hidden or clipped in the capture').toEqual([]);
          if (view === 'sources' && !path.includes(NO_SESSION)) {
            await expect(page.getByRole('heading', { name: D.views.sources.anomalies })).toBeInViewport();
            // From 1280 px, every chunk column fits: no hidden internal horizontal scroll.
            if (width >= 1280) {
              await expect(page.getByRole('columnheader', { name: D.views.sources.col.format })).toBeInViewport({ ratio: 1 });
            }
          }
          if (view === 'captures' && width >= 1280 && (await demoSessionId(page)) !== NO_SESSION) {
            await expect(page.getByRole('columnheader', { name: D.views.captures.col.actions })).toBeInViewport({ ratio: 1 });
          }

          await page.screenshot({ path: `${shotDir}/${view}-${width}-${theme}.png`, fullPage: true });
          await check('full height');
        });
      }
    }
  }
}
