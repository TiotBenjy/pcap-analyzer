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

/** Views covered by the visual tests. Add a line when a view is implemented. */
const VIEWS: Record<string, string> = {
  captures: '/captures',
  overview: '/overview',
  settings: '/settings',
};

const WIDTHS = [375, 768, 1280, 1920] as const;
const THEMES = ['light', 'dark'] as const;
const HEIGHT = 900;

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

for (const [view, path] of views) {
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
        });
        await page.emulateMedia({ colorScheme: theme, reducedMotion: 'reduce' });
        await page.setViewportSize({ width, height: HEIGHT });

        await page.goto(`/#${path}`);
        await page.locator('#main h1').first().waitFor();
        await page.waitForLoadState('networkidle');
        await page.evaluate(() => document.fonts.ready);

        await expect(page.locator('html')).toHaveClass(theme === 'dark' ? /\bdark\b/ : /^(?!.*\bdark\b)/);

        if (view === 'settings') {
          // /server-info is authenticated: "Read-only" proves the proxy injects a valid token.
          await expect(page.getByTestId('backend-status')).toContainText('Connected');
          await expect(page.getByTestId('server-mode')).toHaveText('Read-only');
        }

        await page.screenshot({ path: `${OUT_DIR}/${view}-${width}-${theme}.png`, fullPage: true });

        const r = await inspectLayout(page);
        expect(r.pageOverflow, 'horizontal page overflow').toBeNull();
        expect(r.mainOverflow, 'horizontal overflow in the main column').toBeNull();
        expect(r.overlaps, 'overlapping chart labels').toEqual([]);
        expect(r.outside, 'chart labels outside their SVG').toEqual([]);
        expect(r.untitled, 'truncatable elements without title').toEqual([]);
      });
    }
  }
}
