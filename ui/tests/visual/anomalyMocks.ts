import type { Page } from '@playwright/test';
import type { AnomalyInfo } from '../../src/api/types/AnomalyInfo';
import type { ImportEvent } from '../../src/api/types/ImportEvent';
import type { SessionSummary } from '../../src/api/types/SessionSummary';

// Timestamps going backwards, as a real multi-day import reports them: the demo sessions have none.
//  - `import-progress`: an importing session in the Captures list whose event stream sends a burst
//    of identical warnings (grouped on one line each) and the end of the import;
//  - `sources-backwards`: the demo session's anomalies plus backward steps of every magnitude.

const IMPORT_ID = '01JZZZZZZZZZZZZZZZZZZZZZZZ';
const T0 = Date.UTC(2026, 10, 8, 12) * 1000;

/** `timestamp_backwards` as the API sends it (`*_ns` detail keys converted to `*_us`). */
function backwards(chunk: number, stepUs: number, i: number): AnomalyInfo {
  const ts = T0 + chunk * 60_000_000 + i * 1_000;
  return {
    id: null,
    code: 'timestamp_backwards',
    chunk,
    ts_us: ts,
    detail: { offset: 4096 + i * 128, previous_us: ts + stepUs, ts_us: ts },
  };
}

const WARNINGS: AnomalyInfo[] = [
  { id: null, code: 'missing_sequence', chunk: 12, ts_us: null, detail: { first: 13, last: 13 } },
  ...Array.from({ length: 10 }, (_, i) => backwards(6, [180, 1_234, 950, 2_400][i % 4] ?? 1, i)),
  { id: null, code: 'time_gap', chunk: 29, ts_us: T0, detail: { previous: 28, gap_us: 44_000_000, threshold_us: 5_000_000 } },
  ...Array.from({ length: 10 }, (_, i) => backwards(31, 3_000_000 + i * 250_000, i)),
  backwards(40, 42, 0),
  { id: null, code: 'truncated_tail', chunk: 44, ts_us: null, detail: { offset: 104_857_590 } },
];

function sse(events: ImportEvent[]): string {
  return events.map((e) => `event: ${e.type}\ndata: ${JSON.stringify(e)}\n\n`).join('');
}

export async function mockImportProgress(page: Page): Promise<void> {
  await page.route(
    (url) => url.pathname === '/api/v1/sessions',
    async (route) => {
      if (route.request().method() !== 'GET') return route.continue();
      const res = await route.fetch();
      const body = (await res.json()) as { items: SessionSummary[] };
      const importing: SessionSummary = {
        id: IMPORT_ID,
        name: 'office-ring-buffer',
        sources: ['/captures/office'],
        created_us: T0,
        state: 'importing',
        state_detail: null,
        first_ts_us: T0,
        last_ts_us: T0 + 2 * 86_400_000_000,
        source_bytes: 45 * 512 * 1024 * 1024,
        packets: 23_600_000,
        chunk_count: 45,
        anomaly_count: 0,
      };
      return route.fulfill({ response: res, json: { ...body, items: [importing, ...body.items] } });
    },
  );
  const progress: ImportEvent = {
    type: 'progress',
    bytes_done: 45 * 512 * 1024 * 1024,
    bytes_total: 45 * 512 * 1024 * 1024,
    chunk_index: 44,
    chunk_count: 45,
    chunk_name: 'ring_00045_20261110120000.pcapng',
    packets: 23_600_000,
    rate_bps: 95 * 1024 * 1024,
    eta_s: 0,
    phase: 'finishing',
    step: null,
    steps_done: 0,
    steps_total: 0,
    warnings_found: 582,
  };
  const events: ImportEvent[] = [
    progress,
    ...WARNINGS.map((w): ImportEvent => ({ type: 'warning', ...w })),
    { type: 'done', state: 'ready', packets: 23_600_000, flows: 1_250_000, anomalies: 582, duration_s: 251 },
  ];
  await page.route(`**/api/v1/sessions/${IMPORT_ID}/events`, (route) =>
    route.fulfill({ status: 200, headers: { 'content-type': 'text/event-stream' }, body: sse(events) }),
  );
}

/** Backward steps of every magnitude (µs to minutes) appended to the demo session's anomalies. */
export async function mockBackwardAnomalies(page: Page): Promise<void> {
  const extra = [42, 1_234, 45_000, 3_200_000, 754_000_000].map((step, i) => ({
    ...backwards(i + 2, step, i),
    id: `backwards-${String(i)}`,
  }));
  await page.route(
    (url) => /^\/api\/v1\/sessions\/[^/]+\/anomalies$/.test(url.pathname),
    async (route) => {
      const res = await route.fetch();
      const body = (await res.json()) as { items: AnomalyInfo[]; next_cursor: string | null };
      // First page only: the extra rows are not repeated on the following ones.
      const first = !new URL(route.request().url()).searchParams.has('cursor');
      return route.fulfill({ response: res, json: { ...body, items: first ? [...body.items, ...extra] : body.items } });
    },
  );
}
