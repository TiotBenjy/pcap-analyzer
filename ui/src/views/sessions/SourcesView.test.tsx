import { screen, within } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import * as client from '../../api/client';
import * as api from '../../api/sessions';
import i18n from '../../i18n';
import { renderApp } from '../../test/renderApp';
import { anomaly, chunks, page, session } from '../../test/sessionFixtures';
import { anomalyDetail, anomalyLabel, anomalySummary } from './anomalies';
import { buildCoverage, MAX_LANES, ticks } from './coverage';

vi.mock('../../api/sessions');
vi.mock('../../api/client', async (importOriginal) => ({
  ...(await importOriginal<typeof client>()),
  apiGet: vi.fn(),
}));

const m = vi.mocked(api);
const t = i18n.t.bind(i18n);

// 50 one-minute dumpcap chunks: number 13 missing (ring buffer), a 43 s gap after number 30.
const CHUNKS = chunks(50, [13], 30);
const ANOMALIES = [
  anomaly('missing_sequence', 12, { first: 13, last: 13 }),
  anomaly('time_gap', 29, { previous: 28, gap_us: 44_000_000, threshold_us: 5_000_000 }),
];

describe('buildCoverage', () => {
  it('places one segment per chunk, the gap and the missing number', () => {
    const c = buildCoverage(CHUNKS, ANOMALIES);
    expect(c).not.toBeNull();
    if (c === null) return;
    expect(c.segments).toHaveLength(49);
    expect(c.lanes).toBe(1);
    expect(c.overlaps).toEqual([]);
    expect(c.gaps).toHaveLength(1);
    expect(c.gaps[0]?.seconds).toBeCloseTo(44, 0);
    expect(c.missing).toHaveLength(1);
    // The missing file marker sits in the hole between chunk 11 (seq 12) and chunk 12 (seq 14).
    const before = CHUNKS[11]?.last_ts_us ?? 0;
    const after = CHUNKS[12]?.first_ts_us ?? 0;
    expect(c.missing[0]?.at).toBeGreaterThan(before);
    expect(c.missing[0]?.at).toBeLessThan(after);
  });

  it('stacks overlapping chunks on a second lane and highlights the overlap', () => {
    const [a, b] = chunks(2);
    if (a === undefined || b === undefined) throw new Error('fixture');
    const overlapping = { ...b, first_ts_us: (a.last_ts_us ?? 0) - 10_000_000 };
    const c = buildCoverage([a, overlapping], []);
    expect(c?.lanes).toBe(2);
    expect(c?.overlaps).toEqual([{ start: overlapping.first_ts_us, end: a.last_ts_us }]);
  });

  it('caps the lanes: further overlapping chunks share the last one', () => {
    const base = chunks(1)[0];
    if (base === undefined) throw new Error('fixture');
    const stacked = Array.from({ length: 12 }, (_, i) => ({ ...base, id: i }));
    const c = buildCoverage(stacked, []);
    expect(c?.lanes).toBe(MAX_LANES);
    expect(c?.crowded).toBe(true);
    expect(c?.segments.filter((s) => s.lane === MAX_LANES - 1)).toHaveLength(12 - MAX_LANES + 1);
  });

  it('keeps an aberrant timestamp from squashing the timeline', () => {
    const regular = chunks(20);
    const last = regular[19];
    if (last === undefined) throw new Error('fixture');
    const aberrant = { ...last, id: 99, first_ts_us: 0, last_ts_us: 1_000_000 }; // 1970
    const c = buildCoverage([...regular, aberrant], []);
    expect(c?.outliers).toBe(1);
    expect(c?.start).toBe(regular[0]?.first_ts_us);
    expect(c?.end).toBe(last.last_ts_us);
    expect(buildCoverage(regular, [])?.outliers).toBe(0);
  });

  it('returns null without timestamps and spaces ticks evenly', () => {
    expect(buildCoverage([{ ...(CHUNKS[0] as (typeof CHUNKS)[number]), first_ts_us: null }], [])).toBeNull();
    expect(ticks(0, 100, 3)).toEqual([0, 50, 100]);
  });
});

describe('anomaly texts', () => {
  it('translates known codes and falls back for unknown ones', () => {
    for (const code of [
      'missing_sequence',
      'time_gap',
      'overlap',
      'duplicate',
      'truncated_tail',
      'timestamp_backwards',
      'linktype_change',
      'out_of_order',
      'analyzer_panicked',
    ]) {
      expect(anomalyLabel(t, code)).not.toContain(code);
    }
    expect(anomalyLabel(t, 'brand_new_code')).toBe('Other anomaly (brand_new_code)');
  });

  it('describes details and summarizes', () => {
    expect(anomalyDetail(t, anomaly('missing_sequence', 3, { first: 4, last: 6 }))).toBe('Numbers 4 to 6');
    expect(anomalyDetail(t, anomaly('time_gap', 3, { gap_us: 43e6 }))).toBe('43 s without packets');
    expect(anomalyDetail(t, anomaly('overlap', 3, { previous: 2, overlap_us: 2.5e6 }))).toBe(
      '2.5 s overlap with chunk 2',
    );
    expect(anomalyDetail(t, anomaly('analyzer_panicked', 3, { analyzer: 'dns', message: 'secret' }))).toBe(
      'Analyzer dns',
    );
    expect(anomalySummary(t, ANOMALIES)).toEqual(['1 missing file in the sequence', '1 time gap of 44 s']);
  });
});

describe('Sources view', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    vi.mocked(client.apiGet).mockResolvedValue({ version: 'test', read_only: true, can_browse: false, status: 'ok' });
    m.getSession.mockResolvedValue(session());
    m.listChunks.mockResolvedValue(page(CHUNKS));
    m.listAnomalies.mockResolvedValue(page(ANOMALIES));
  });

  it('shows the timeline with the gap and the missing file, the chunks and the anomalies', async () => {
    renderApp('/sessions/01JC0FFEE0000000000000000A/sources');
    expect(await screen.findByRole('heading', { level: 1, name: 'Sources' })).toBeInTheDocument();
    expect(await screen.findByText('office-uplink')).toBeInTheDocument();

    const timeline = await screen.findByRole('img', { name: 'Coverage timeline of 49 chunks' });
    expect(timeline).toHaveAccessibleDescription(/49 chunks from .* Time gaps: 1\. Overlaps: 0\. Missing files: 1\./);
    expect(within(timeline as unknown as HTMLElement).getAllByTestId('coverage-segment')).toHaveLength(49);
    const gap = within(timeline as unknown as HTMLElement).getByTestId('coverage-gap');
    expect(gap.querySelector('title')).toHaveTextContent('Time gap of 44 s');
    const missing = within(timeline as unknown as HTMLElement).getByTestId('coverage-missing');
    expect(missing.querySelector('title')).toHaveTextContent('Missing file: #13');

    expect(screen.getByTestId('anomaly-summary')).toHaveTextContent(
      '1 missing file in the sequence, 1 time gap of 44 s',
    );

    const chunkTable = screen.getByRole('table', { name: 'Chunks of the session' });
    expect(timeline).toHaveAttribute('aria-details', chunkTable.parentElement?.parentElement?.id ?? 'missing');
    expect(within(chunkTable).getAllByRole('row')).toHaveLength(50);
    const name = within(chunkTable).getByText('ring_00001_20261108.pcapng');
    expect(name).toHaveAttribute('title', '/captures/office/ring_00001_20261108.pcapng');

    const anomalyTable = screen.getByRole('table', { name: 'Anomalies' });
    expect(within(anomalyTable).getByText('Missing files in the sequence')).toBeInTheDocument();
    expect(within(anomalyTable).getByText('Number 13')).toBeInTheDocument();
    expect(within(anomalyTable).getByText('Time gap')).toBeInTheDocument();
  });

  it('shows the empty states of a session without chunks', async () => {
    m.listChunks.mockResolvedValue(page([]));
    m.listAnomalies.mockResolvedValue(page([]));
    renderApp('/sessions/01JC0FFEE0000000000000000A/sources');
    expect(await screen.findAllByText('No chunk recorded')).toHaveLength(2);
    expect(screen.getByText('No anomaly: the chunks are continuous')).toBeInTheDocument();
  });

  it('shows error states with retry', async () => {
    m.listChunks.mockRejectedValue(new Error('boom'));
    renderApp('/sessions/01JC0FFEE0000000000000000A/sources');
    expect(await screen.findAllByText('Data could not be loaded')).toHaveLength(2);
  });
});
