import { expect, type Page, test } from '@playwright/test';
import { mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

// Screenshots + automated layout assertions from docs/UI_GUIDELINES.md ("Tests visuels"):
//   1. PNG per view, width and theme in .artifacts/screens/<view>-<width>-<theme>.png
//   2. no horizontal overflow (page or main column)
//   3. no overlapping text/tspan boxes inside one SVG chart, no label outside its SVG
//   4. every [data-testid="truncatable"] element has a title
// Select views with SHOT_VIEW=<name>|all.

/**
 * Views covered by the visual tests. Add a line when a view is implemented. Session views resolve
 * their path at run time, on the demo session created by `netsift demo-session`.
 */
const VIEWS: Record<string, string | ((page: Page) => Promise<string>)> = {
  captures: '/captures',
  connections: async (page) => `/sessions/${await demoSessionId(page)}/connections`,
  http: async (page) => `/sessions/${await demoSessionId(page)}/http`,
  'http-headers': async (page) => `/sessions/${await demoSessionId(page)}/http-headers`,
  'open-ports': async (page) => `/sessions/${await demoSessionId(page)}/open-ports`,
  overview: async (page) => `/sessions/${await demoSessionId(page)}/overview`,
  settings: '/settings',
  sources: async (page) => `/sessions/${await demoSessionId(page)}/sources`,
  tls: async (page) => `/sessions/${await demoSessionId(page)}/tls`,
};

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
    const report: LayoutReport = {
      pageOverflow: doc.scrollWidth > window.innerWidth ? { scrollWidth: doc.scrollWidth, innerWidth: window.innerWidth } : null,
      mainOverflow:
        main !== null && main.scrollWidth > main.clientWidth + TOL
          ? { scrollWidth: main.scrollWidth, clientWidth: main.clientWidth }
          : null,
      overlaps: [],
      outside: [],
      untitled: [],
    };

    const label = (el: Element) => (el.textContent ?? '').trim().slice(0, 40);
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
});

for (const [view, target] of views) {
  for (const theme of THEMES) {
    for (const width of WIDTHS) {
      test(`${view} ${width}px ${theme}`, async ({ page }) => {
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
        await page.goto(`/#${path}`);
        await page.locator('#main h1').first().waitFor();
        await page.waitForLoadState('networkidle');
        await page.evaluate(() => document.fonts.ready);

        await expect(page.locator('html')).toHaveClass(theme === 'dark' ? /\bdark\b/ : /^(?!.*\bdark\b)/);

        // With the demo sessions, the data views must show data, not an empty or error state.
        if (view === 'captures' && (await demoSessionId(page)) !== NO_SESSION) {
          await expect(
            page.getByRole('table', { name: 'Sessions' }).or(page.getByRole('list', { name: 'Sessions' })),
          ).toBeVisible();
        }
        if (view === 'sources' && !path.includes(NO_SESSION)) {
          await expect(page.getByRole('img', { name: /^Coverage timeline/ })).toBeVisible();
          await expect(page.getByRole('table', { name: 'Chunks of the session' })).toBeVisible();
        }

        if (view === 'overview' && !path.includes(NO_SESSION)) {
          await expect(page.getByTestId('overview-summary')).toBeVisible();
          await expect(page.getByRole('img', { name: /^Traffic by protocol/ })).toBeVisible();
          // The demo session must show at least DNS, HTTP and TLS in the series.
          const id = path.split('/')[2] ?? NO_SESSION;
          const res = await page.request.get(`/api/v1/sessions/${id}/timeseries?points=200`);
          expect(res.ok()).toBe(true);
          const body = (await res.json()) as { series: { protocol: string }[] };
          const protocols = body.series.map((s) => s.protocol);
          for (const p of ['dns', 'http', 'tls']) expect(protocols).toContain(p);
        }

        if (view === 'connections' && !path.includes(NO_SESSION)) {
          await expect(page.getByRole('table', { name: 'Conversations between hosts' })).toBeVisible();
          await expect(page.getByRole('list', { name: 'Countries of Download sources' }).or(page.getByText('No geolocated host').first())).toBeVisible();
          // Chord diagram from 768 px, ranked pairs below.
          await expect(
            width >= 768
              ? page.getByRole('img', { name: /^Traffic between the \d+ main endpoints/ })
              : page.getByRole('list', { name: 'Pairs of endpoints ranked by bytes' }),
          ).toBeVisible();
        }
        if (view === 'open-ports' && !path.includes(NO_SESSION)) {
          await expect(page.getByRole('img', { name: /^Ports open on the most hosts/ })).toBeVisible();
          await expect(
            page.getByRole('table', { name: 'Hosts with open ports' }).or(page.getByRole('list', { name: 'Hosts with open ports' })),
          ).toBeVisible();
        }
        if (view === 'tls' && !path.includes(NO_SESSION)) {
          await expect(page.getByTestId('tls-summary')).toBeVisible();
          await expect(page.getByRole('img', { name: /^Negotiated TLS versions/ })).toBeVisible();
          await expect(page.getByRole('table', { name: 'TLS sessions' })).toBeVisible();
        }
        if ((view === 'http' || view === 'http-headers') && !path.includes(NO_SESSION)) {
          const list = view === 'http' ? 'HTTP transactions' : 'HTTP transactions and their headers';
          await expect(page.getByRole('img', { name: /^Transactions by request method/ })).toBeVisible();
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
          await expect(page.getByRole('table', { name: 'Request headers' }).first()).toBeVisible();
          await page.waitForLoadState('networkidle');
        }

        if (view === 'settings') {
          // /server-info is authenticated: "Read-only" proves the proxy injects a valid token.
          await expect(page.getByTestId('backend-status')).toContainText('Connected');
          await expect(page.getByTestId('server-mode')).toHaveText('Read-only');
        }

        const check = async (when: string) => {
          const r = await inspectLayout(page);
          expect(r.pageOverflow, `horizontal page overflow (${when})`).toBeNull();
          expect(r.mainOverflow, `horizontal overflow in the main column (${when})`).toBeNull();
          expect(r.overlaps, `overlapping chart labels (${when})`).toEqual([]);
          expect(r.outside, `chart labels outside their SVG (${when})`).toEqual([]);
          expect(r.untitled, `truncatable elements without title (${when})`).toEqual([]);
        };
        await check(`${HEIGHT}px high`);
        expect(pageErrors, 'uncaught errors in the page (frozen Object.prototype)').toEqual([]);

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
              const r = el.getBoundingClientRect();
              if (r.width === 0 || r.right > window.innerWidth || r.bottom > window.innerHeight) return true;
              const hit = document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2);
              return hit === null || !el.contains(hit);
            })
            .map((el) => el.getAttribute('data-shot-visible')),
        );
        expect(hidden, 'key elements hidden or clipped in the capture').toEqual([]);
        if (view === 'sources' && !path.includes(NO_SESSION)) {
          await expect(page.getByRole('heading', { name: 'Anomalies' })).toBeInViewport();
          // From 1280 px, every chunk column fits: no hidden internal horizontal scroll.
          if (width >= 1280) {
            await expect(page.getByRole('columnheader', { name: 'Format' })).toBeInViewport({ ratio: 1 });
          }
        }
        if (view === 'captures' && width >= 1280 && (await demoSessionId(page)) !== NO_SESSION) {
          await expect(page.getByRole('columnheader', { name: 'Actions' })).toBeInViewport({ ratio: 1 });
        }

        await page.screenshot({ path: `${OUT_DIR}/${view}-${width}-${theme}.png`, fullPage: true });
        await check('full height');
      });
    }
  }
}
