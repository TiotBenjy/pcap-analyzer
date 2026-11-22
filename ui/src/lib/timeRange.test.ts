import { describe, expect, it } from 'vitest';
import { dnsKeys } from '../api/dnsQueries';
import { httpKeys } from '../api/httpQueries';
import { overviewKeys } from '../api/overviewQueries';
import { parseRange, parseRangeInput, rangeKey, rangeText, sameRange, widen, withRange } from './timeRange';

const T0 = Date.UTC(2026, 10, 8, 10, 0, 0) * 1000;

describe('time range', () => {
  it('reads the search params, both bounds or nothing', () => {
    expect(parseRange({ from_us: T0, to_us: T0 + 5 })).toEqual({ fromUs: T0, toUs: T0 + 5 });
    expect(parseRange({ from_us: String(T0), to_us: String(T0) })).toEqual({ fromUs: T0, toUs: T0 });
    expect(parseRange({ from_us: T0 })).toBeNull();
    expect(parseRange({ from_us: T0 + 1, to_us: T0 })).toBeNull();
    expect(parseRange({ from_us: 'abc', to_us: T0 })).toBeNull();
    expect(parseRange({ from_us: 1.5, to_us: 2 })).toBeNull();
    expect(parseRange({ from_us: 2 ** 60, to_us: 2 ** 61 })).toBeNull();
  });

  it('appends the bounds to a path', () => {
    const r = { fromUs: 10, toUs: 20 };
    expect(withRange('/sessions/a/dns/stats', r)).toBe('/sessions/a/dns/stats?from_us=10&to_us=20');
    expect(withRange('/sessions/a/dns/pairs?limit=5', r)).toBe('/sessions/a/dns/pairs?limit=5&from_us=10&to_us=20');
    expect(withRange('/x', null)).toBe('/x');
  });

  it('puts the range in the query keys of filtered routes only', () => {
    const r = { fromUs: 10, toUs: 20 };
    expect(rangeKey(null)).toBeNull();
    expect(dnsKeys.stats('s', r)).toEqual(['sessions', 'detail', 's', 'dns', 'stats', [10, 20]]);
    expect(dnsKeys.stats('s')).toEqual(['sessions', 'detail', 's', 'dns', 'stats', null]);
    expect(overviewKeys.summary('s', r).at(-1)).toEqual([10, 20]);
    // Detail of one transaction: not filtered, same key whatever the range.
    expect(httpKeys.detail('s', 4)).toEqual(['sessions', 'detail', 's', 'http', 'tx', 4]);
    // Every key stays under the session detail key (invalidating a session refreshes them).
    expect(httpKeys.list('s', {}, r).slice(0, 3)).toEqual(['sessions', 'detail', 's']);
  });

  it('parses a typed range with the rules of Save PCAP', () => {
    expect(parseRangeInput('x', '2026-11-08 10:00:00')).toEqual({ error: 'invalidTime' });
    expect(parseRangeInput('2026-11-08 10:00:01', '2026-11-08 10:00:00')).toEqual({ error: 'reversed' });
    const ok = parseRangeInput('2026-11-08 10:00:00', '2026-11-08 10:00:00');
    expect('range' in ok && ok.range.toUs - ok.range.fromUs).toBe(999_999);
  });

  it('zooms out around the center, bounded to the session', () => {
    expect(widen({ fromUs: 100, toUs: 199 }, 0, 1000)).toEqual({ fromUs: 50, toUs: 249 });
    expect(widen({ fromUs: 10, toUs: 199 }, 0, 1000)).toEqual({ fromUs: 0, toUs: 294 });
    expect(widen({ fromUs: 0, toUs: 900 }, 0, 1000)).toBeNull();
    expect(sameRange({ fromUs: 1, toUs: 2 }, { fromUs: 1, toUs: 2 })).toBe(true);
    expect(sameRange({ fromUs: 1, toUs: 2 }, null)).toBe(false);
  });

  it('writes the date once for a range within one day', () => {
    const join = (a: string, b: string) => `${a} to ${b}`;
    const r = { fromUs: T0, toUs: T0 + 3_600_000_000 };
    expect(rangeText(r, false, join)).toMatch(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} to \d{2}:\d{2}:\d{2}$/);
    expect(rangeText(r, true, join)).toMatch(/^\d{2}:\d{2}:\d{2} to \d{2}:\d{2}:\d{2}$/);
    const days = { fromUs: T0, toUs: T0 + 3 * 86_400_000_000 };
    expect(rangeText(days, true, join)).toMatch(/^\d{4}-\d{2}-\d{2} to \d{4}-\d{2}-\d{2}$/);
  });
});
