import { formatClock, formatDate, formatTimestamp, parseTimestamp, sameLocalDay } from './format';

/**
 * Time range of the global time filter (docs/specs/time-filter.md, ADR-030): microseconds since
 * the epoch, both bounds inclusive, as the API reads `from_us` / `to_us`.
 */
export interface TimeRange {
  fromUs: number;
  toUs: number;
}

/** Largest absolute bound the API accepts (its nanoseconds fit an i64). */
const MAX_ABS_US = 9_223_372_036_854_774;

function bound(raw: unknown): number | null {
  const n = typeof raw === 'number' ? raw : typeof raw === 'string' && /^-?\d+$/.test(raw) ? Number(raw) : NaN;
  return Number.isSafeInteger(n) && Math.abs(n) <= MAX_ABS_US ? n : null;
}

/** The range of URL search params (`from_us`, `to_us`), `null` when absent or invalid. */
export function parseRange(search: Record<string, unknown>): TimeRange | null {
  const fromUs = bound(search.from_us);
  const toUs = bound(search.to_us);
  if (fromUs === null || toUs === null || toUs < fromUs) return null;
  return { fromUs, toUs };
}

/** `path` with the range appended as `from_us` / `to_us` (nothing without range). */
export function withRange<P extends string>(path: P, range: TimeRange | null | undefined): P {
  if (range === null || range === undefined) return path;
  const sep = path.includes('?') ? '&' : '?';
  return `${path}${sep}from_us=${Math.floor(range.fromUs)}&to_us=${Math.floor(range.toUs)}` as P;
}

/** Part of a TanStack Query key that identifies the range (`null` without range). */
export function rangeKey(range: TimeRange | null | undefined): readonly [number, number] | null {
  return range === null || range === undefined ? null : [range.fromUs, range.toUs];
}

export function sameRange(a: TimeRange | null, b: TimeRange | null): boolean {
  return a === b || (a !== null && b !== null && a.fromUs === b.fromUs && a.toUs === b.toUs);
}

/**
 * A range typed in the form of Save PCAP and of the range dialog (local ISO time, fraction
 * optional; an end without fraction covers its whole second), or the reason it is invalid.
 */
export function parseRangeInput(
  from: string,
  to: string,
): { range: TimeRange } | { error: 'invalidTime' | 'reversed' } {
  const fromUs = parseTimestamp(from);
  const toUs = parseTimestamp(to, true);
  if (fromUs === null || toUs === null) return { error: 'invalidTime' };
  if (toUs < fromUs) return { error: 'reversed' };
  return { range: { fromUs, toUs } };
}

/** Bounds of the form fields for a range (`formatTimestamp`, to the second). */
export function rangeInput(range: TimeRange): { from: string; to: string } {
  return { from: formatTimestamp(range.fromUs), to: formatTimestamp(range.toUs) };
}

/**
 * The range twice as wide around its center, bounded to `[firstUs, lastUs]` when known
 * (Zoom out of the overview). `null` when it would cover the whole period.
 */
export function widen(range: TimeRange, firstUs: number | null, lastUs: number | null): TimeRange | null {
  const half = Math.max(1, Math.ceil((range.toUs - range.fromUs + 1) / 2));
  let fromUs = range.fromUs - half;
  let toUs = range.toUs + half;
  if (firstUs !== null) fromUs = Math.max(fromUs, firstUs);
  if (lastUs !== null) toUs = Math.min(toUs, lastUs);
  if (firstUs !== null && lastUs !== null && fromUs <= firstUs && toUs >= lastUs) return null;
  return { fromUs, toUs };
}

/** Short text of a range: the date once when both ends fall on the same day. */
export function rangeText(range: TimeRange, compact: boolean, join: (from: string, to: string) => string): string {
  const oneDay = sameLocalDay(range.fromUs, range.toUs);
  if (compact) {
    return oneDay
      ? join(formatClock(range.fromUs), formatClock(range.toUs))
      : join(formatDate(range.fromUs), formatDate(range.toUs));
  }
  return join(formatTimestamp(range.fromUs), formatTimestamp(range.toUs, !oneDay));
}
