import { expect, test, type Browser, type TestInfo } from '@playwright/test';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { en } from '../../src/i18n/en';

// Display time of the Overview on the benchmark session (`./x.sh bench ui`, docs/PERFORMANCE.md):
// from the click on "Overview" in the sidebar (the application is already loaded, on the Sources
// view of the session) to the traffic chart drawn and the summary shown. Each run uses a new
// browser context, so that no query nor script is cached. Two cases: a click one second after the
// Sources view settled, and a click as soon as the sidebar is shown. Not part of the gate: run by
// scripts/ct/bench.sh only.

const RUNS = Number(process.env.PERF_RUNS ?? 7);
const OUT = resolve(dirname(fileURLToPath(import.meta.url)), '../../../.artifacts/bench/ui-overview.md');
const CHART = en.views.overview.traffic.chartLabel;

interface Timing {
  fetched: number;
  drawn: number;
}

async function measure(browser: Browser, testInfo: TestInfo, id: string, waitMs: number): Promise<Timing> {
  const baseURL = testInfo.project.use.baseURL;
  const context = await browser.newContext({
    ...(baseURL === undefined ? {} : { baseURL }),
    viewport: { width: 1280, height: 800 },
  });
  const page = await context.newPage();
  // Hash routing, as in the visual tests.
  await page.goto(`/#/sessions/${id}/sources`);
  await page.locator('#main h1').first().waitFor();
  const link = page.getByRole('link', { name: en.nav.items.overview }).first();
  await expect(link).toBeVisible();
  if (waitMs > 0) {
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(waitMs);
  }
  const summary = page.waitForResponse((r) => r.url().includes(`/sessions/${id}/summary`) && r.ok());
  const series = page.waitForResponse((r) => r.url().includes(`/sessions/${id}/timeseries`) && r.ok());
  const start = Date.now();
  await link.click();
  await Promise.all([summary, series]);
  const fetched = Date.now() - start;
  await expect(page.getByRole('img', { name: CHART })).toBeVisible();
  // Series drawn (ECharts SVG renderer) and summary shown. A series area of the benchmark session
  // is a path of hundreds of points: axes and grid lines alone (an empty chart) do not count.
  await page.waitForFunction(
    (label) =>
      [...(document.querySelector(`[aria-label="${label}"]`)?.querySelectorAll('path') ?? [])].some(
        (p) => (p.getAttribute('d')?.length ?? 0) > 2000,
      ),
    CHART,
  );
  await expect(page.getByTestId('overview-summary')).toBeVisible();
  const drawn = Date.now() - start;
  await context.close();
  return { fetched, drawn };
}

test('overview display time', async ({ browser }, testInfo) => {
  test.setTimeout(RUNS * 2 * 60_000);
  const baseURL = testInfo.project.use.baseURL;
  const probe = await browser.newContext(baseURL === undefined ? {} : { baseURL });
  const res = await probe.request.get('/api/v1/sessions?limit=1');
  expect(res.ok()).toBe(true);
  const id = ((await res.json()) as { items: { id: string }[] }).items[0]?.id ?? '';
  expect(id).not.toBe('');
  await probe.close();

  const after: Timing[] = [];
  const immediate: Timing[] = [];
  for (let run = 0; run < RUNS; run++) {
    after.push(await measure(browser, testInfo, id, 1000));
    immediate.push(await measure(browser, testInfo, id, 0));
  }
  const row = (label: string, values: number[]) => {
    const sorted = [...values].sort((a, b) => a - b);
    const at = (p: number) => sorted[Math.round((sorted.length - 1) * p)] ?? 0;
    return `| ${label} | ${String(at(0.5))} | ${String(at(0.95))} | ${String(sorted.at(-1) ?? 0)} | ${String(RUNS)} |`;
  };
  const lines = [
    row('clic 1 s après l’ouverture : réponses de `summary` et `timeseries`', after.map((t) => t.fetched)),
    row('clic 1 s après l’ouverture : graphique dessiné, résumé affiché', after.map((t) => t.drawn)),
    row('clic immédiat : réponses', immediate.map((t) => t.fetched)),
    row('clic immédiat : graphique dessiné, résumé affiché', immediate.map((t) => t.drawn)),
  ];
  mkdirSync(dirname(OUT), { recursive: true });
  writeFileSync(OUT, `| Affichage de l'Overview | Médiane (ms) | p95 (ms) | Max (ms) | Essais |\n|---|---|---|---|---|\n${lines.join('\n')}\n`);
  process.stdout.write(`${lines.join('\n')}\n`);
});
