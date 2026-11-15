import { afterEach, describe, expect, it } from 'vitest';
import i18n from '../../i18n';
import { anomaly } from '../../test/sessionFixtures';
import {
  anomalyDetail,
  anomalySummary,
  backwardStepUs,
  groupAnomalies,
  REPEAT_LIMIT,
  WARNINGS_PER_KIND,
} from './anomalies';

const t = i18n.t.bind(i18n);
const NBSP = ' ';

/** `timestamp_backwards` as the API sends it: `*_ns` detail keys converted to `*_us`. */
const backwards = (chunk: number, stepUs: number, offset = 0) =>
  anomaly('timestamp_backwards', chunk, {
    offset,
    previous_us: 1_700_000_000_000_000 + stepUs,
    ts_us: 1_700_000_000_000_000,
  });

afterEach(async () => {
  await i18n.changeLanguage('en');
});

describe('backward steps', () => {
  it('reads the step of timestamps going backwards and of the merge', () => {
    expect(backwardStepUs(backwards(6, 1_200))).toBe(1_200);
    // Legacy `*_ns` keys.
    expect(
      backwardStepUs(anomaly('timestamp_backwards', 6, { previous_ns: 5_000_000_000, ts_ns: 2_000_000_000 })),
    ).toBe(3_000_000);
    expect(backwardStepUs(anomaly('out_of_order', null, { packets: 4, max_backstep_us: 250 }))).toBe(250);
    expect(backwardStepUs(anomaly('timestamp_backwards', 6, { offset: 3 }))).toBeNull();
    expect(backwardStepUs(anomaly('time_gap', 6, { gap_us: 5 }))).toBeNull();
  });

  it('describes the step with an adaptive unit', async () => {
    expect(anomalyDetail(t, backwards(6, 1_234))).toBe(`Goes back 1.2${NBSP}ms`);
    expect(anomalyDetail(t, backwards(6, 42))).toBe(`Goes back 42${NBSP}µs`);
    expect(anomalyDetail(t, backwards(6, 3_600_000_000))).toBe(`Goes back 1${NBSP}h 00${NBSP}min`);
    expect(anomalyDetail(t, anomaly('timestamp_backwards', 6, {}))).toBe('');
    expect(anomalyDetail(t, anomaly('out_of_order', null, { packets: 1500, max_backstep_us: 2_500_000 }))).toBe(
      `1,500 packets, up to 2.5${NBSP}s back`,
    );
    expect(anomalyDetail(t, anomaly('out_of_order', null, { packets: 3 }))).toBe('3 packets');
    await i18n.changeLanguage('fr');
    expect(anomalyDetail(t, backwards(6, 1_234))).toBe(`Recule de 1,2${NBSP}ms`);
  });
});

describe('groupAnomalies', () => {
  it('puts identical warnings on one line with their count and largest step', async () => {
    const warnings = [
      backwards(6, 800, 1),
      anomaly('missing_sequence', 12, { first: 13, last: 13 }),
      backwards(6, 1_200, 2),
      backwards(7, 5_000_000, 3),
      backwards(6, 300, 4),
      anomaly('truncated_tail', 6, { offset: 9 }),
    ];
    const groups = groupAnomalies(t, warnings);
    // Order of first appearance.
    expect(groups.map((g) => [g.first.code, g.first.chunk, g.count])).toEqual([
      ['timestamp_backwards', 6, 3],
      ['missing_sequence', 12, 1],
      ['timestamp_backwards', 7, 1],
      ['truncated_tail', 6, 1],
    ]);
    expect(groups.map((g) => g.detail)).toEqual([
      `Goes back up to 1.2${NBSP}ms`,
      'Number 13',
      `Goes back 5${NBSP}s`,
      '',
    ]);
    await i18n.changeLanguage('fr');
    expect(groupAnomalies(t, warnings)[0]?.detail).toBe(`Recule jusqu'à 1,2${NBSP}ms`);
  });

  it('gives lower bounds for a group the API stopped sending', async () => {
    const full = Array.from({ length: WARNINGS_PER_KIND }, (_, i) => backwards(6, 100 * (i + 1), i));
    const short = full.slice(1);
    // Warnings were dropped (`warnings_found` larger than received): the full group is capped.
    expect(groupAnomalies(t, [...full, backwards(7, 5, 0)], true)).toMatchObject([
      { count: WARNINGS_PER_KIND, capped: true, detail: `Goes back at least 1${NBSP}ms` },
      { count: 1, capped: false, detail: `Goes back 5${NBSP}µs` },
    ]);
    // Below the cap, or nothing dropped: the count and the maximum are exact.
    expect(groupAnomalies(t, short, true)).toMatchObject([{ count: WARNINGS_PER_KIND - 1, capped: false }]);
    expect(groupAnomalies(t, full, false)).toMatchObject([{ capped: false, detail: `Goes back up to 1${NBSP}ms` }]);
    await i18n.changeLanguage('fr');
    expect(groupAnomalies(t, full, true)[0]?.detail).toBe(`Recule d'au moins 1${NBSP}ms`);
  });

  it('treats every group as cut short once the API stopped sending repeats', () => {
    // 176 distinct warnings, then a group of 4 when the list reached the repeat limit.
    const others = Array.from({ length: REPEAT_LIMIT - 4 }, (_, i) => anomaly('time_gap', i, { gap_us: 6e6 }));
    const group = [800, 2_000, 1_500, 300].map((step, i) => backwards(500, step, i));
    const groups = groupAnomalies(t, [...others, ...group], true);
    expect(groups.at(-1)).toMatchObject({ count: 4, capped: true, detail: `Goes back at least 2${NBSP}ms` });
    expect(groups[0]).toMatchObject({ count: 1, capped: true, detail: `6${NBSP}s without packets` });
    // Nothing dropped: exact counts.
    expect(groupAnomalies(t, [...others, ...group], false).at(-1)).toMatchObject({ count: 4, capped: false });
  });

  it('keeps a shared detail of other repeated codes, drops differing ones', () => {
    const same = groupAnomalies(t, [
      anomaly('linktype_change', 3, { previous: 1, current: 113 }),
      anomaly('linktype_change', 3, { previous: 1, current: 113 }),
    ]);
    expect(same).toMatchObject([{ count: 2, detail: '1 to 113' }]);
    const differing = groupAnomalies(t, [
      anomaly('skipped_record', 3, { reason: 'bad length' }),
      anomaly('skipped_record', 3, { reason: 'unknown block' }),
      anomaly('skipped_record', null, { reason: 'bad length' }),
    ]);
    expect(differing).toMatchObject([
      { count: 2, detail: '' },
      { count: 1, detail: 'bad length' },
    ]);
    expect(groupAnomalies(t, [])).toEqual([]);
  });
});

describe('anomalySummary', () => {
  it('gives the largest backward step', async () => {
    const list = [backwards(6, 800), backwards(6, 1_200), backwards(9, 40), anomaly('time_gap', 3, { gap_us: 43e6 })];
    expect(anomalySummary(t, list)).toEqual([`1 time gap of 43${NBSP}s`, `3 timestamps going backwards (up to 1.2${NBSP}ms)`]);
    expect(anomalySummary(t, [backwards(6, 40)])).toEqual([`1 timestamp going backwards (40${NBSP}µs)`]);
    expect(
      anomalySummary(t, [anomaly('out_of_order', null, { packets: 1500, max_backstep_us: 2_500 }), anomaly('out_of_order', null, { packets: 3 })]),
    ).toEqual([`1,500 packets out of order (up to 2.5${NBSP}ms back)`, '1 other anomaly']);
    expect(anomalySummary(t, [anomaly('timestamp_backwards', 6, {}), anomaly('timestamp_backwards', 7, {})])).toEqual([
      '2 timestamps going backwards',
    ]);
    await i18n.changeLanguage('fr');
    expect(anomalySummary(t, list)).toEqual([
      `1 trou temporel de 43${NBSP}s`,
      `3 horodatages qui reculent (jusqu'à 1,2${NBSP}ms)`,
    ]);
  });
});
