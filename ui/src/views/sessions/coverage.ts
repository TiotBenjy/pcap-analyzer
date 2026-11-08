import type { AnomalyInfo } from '../../api/types/AnomalyInfo';
import type { ChunkInfo } from '../../api/types/ChunkInfo';
import { detailSeconds, missingRange } from './anomalies';

// Geometry-free model of the chunk coverage timeline (one segment per chunk, time gaps, overlaps,
// missing sequence numbers). Times are microseconds; the component maps them to pixels.

export interface Interval {
  start: number;
  end: number;
}

export interface Segment extends Interval {
  chunk: ChunkInfo;
  /** Row of the segment: overlapping chunks are stacked on separate lanes. */
  lane: number;
  /** Truncated, duplicate or skipped chunk. */
  issue: boolean;
}

export interface Gap extends Interval {
  seconds: number;
}

export interface MissingMark {
  /** Position of the marker, in the middle of the hole when it can be located. */
  at: number;
  first: number;
  last: number;
}

export interface Coverage extends Interval {
  lanes: number;
  /** The last lane holds every chunk that found no free lane (multiple overlaps). */
  crowded: boolean;
  /** Chunks whose timestamps lie far outside the capture: clamped to the displayed range. */
  outliers: number;
  segments: Segment[];
  gaps: Gap[];
  overlaps: Interval[];
  missing: MissingMark[];
}

/** Maximum number of lanes; further overlapping chunks share the last one. */
export const MAX_LANES = 8;
/** Fence factor of the robust range (Tukey's "far out" values use 3). */
const FENCE = 3;

function quantile(sorted: readonly number[], q: number): number {
  const pos = (sorted.length - 1) * q;
  const lo = Math.floor(pos);
  const a = sorted[lo] ?? 0;
  const b = sorted[Math.min(lo + 1, sorted.length - 1)] ?? a;
  return a + (b - a) * (pos - lo);
}

/**
 * Displayed time range, robust to aberrant timestamps (a chunk dated 1970 would otherwise squash
 * the whole capture into a pixel): chunk midpoints beyond Q1 - 3 IQR or Q3 + 3 IQR are outliers.
 * The spread is at least the median chunk duration, so a regular capture never loses a chunk.
 */
function robustRange(spans: readonly Interval[]): Interval & { inside: (s: Interval) => boolean } {
  const mids = spans.map((s) => (s.start + s.end) / 2).sort((a, b) => a - b);
  const durations = spans.map((s) => s.end - s.start).sort((a, b) => a - b);
  const q1 = quantile(mids, 0.25);
  const q3 = quantile(mids, 0.75);
  const spread = Math.max(q3 - q1, quantile(durations, 0.5), 1_000_000);
  const lo = q1 - FENCE * spread;
  const hi = q3 + FENCE * spread;
  const inside = (s: Interval) => (s.start + s.end) / 2 >= lo && (s.start + s.end) / 2 <= hi;
  let start = Infinity;
  let end = -Infinity;
  for (const s of spans) {
    if (!inside(s)) continue;
    start = Math.min(start, s.start);
    end = Math.max(end, s.end);
  }
  return { start, end, inside };
}

/** Builds the timeline model; `null` when no chunk has timestamps. */
export function buildCoverage(chunks: readonly ChunkInfo[], anomalies: readonly AnomalyInfo[]): Coverage | null {
  const timed = chunks
    .filter((c): c is ChunkInfo & { first_ts_us: number; last_ts_us: number } => c.first_ts_us !== null && c.last_ts_us !== null)
    .map((c) => ({ chunk: c, start: c.first_ts_us, end: Math.max(c.first_ts_us, c.last_ts_us) }))
    .sort((a, b) => a.start - b.start || a.chunk.id - b.chunk.id);
  if (timed.length === 0) return null;
  const range = robustRange(timed);
  const clamp = (v: number) => Math.min(Math.max(v, range.start), range.end);
  let outliers = 0;

  // Greedy lane assignment (bounded) and overlap detection, in start order.
  const laneEnds: number[] = [];
  const segments: Segment[] = [];
  const overlaps: Interval[] = [];
  let crowded = false;
  let maxEnd = -Infinity;
  for (const raw of timed) {
    const t = range.inside(raw) ? raw : { ...raw, start: clamp(raw.start), end: clamp(raw.end) };
    if (t !== raw) outliers += 1;
    let lane = laneEnds.findIndex((end) => end <= t.start);
    if (lane < 0 && laneEnds.length < MAX_LANES) {
      lane = laneEnds.length;
      laneEnds.push(t.end);
    } else if (lane < 0) {
      lane = MAX_LANES - 1;
      crowded = true;
      laneEnds[lane] = Math.max(laneEnds[lane] ?? t.end, t.end);
    } else {
      laneEnds[lane] = t.end;
    }
    segments.push({ chunk: t.chunk, start: t.start, end: t.end, lane, issue: t.chunk.state !== 'ok' || t !== raw });
    if (t.start < maxEnd) {
      const o = { start: t.start, end: Math.min(t.end, maxEnd) };
      const last = overlaps.at(-1);
      if (last !== undefined && o.start <= last.end) last.end = Math.max(last.end, o.end);
      else overlaps.push(o);
    }
    maxEnd = Math.max(maxEnd, t.end);
  }

  const byId = new Map(chunks.map((c) => [c.id, c]));
  const startOf = (a: AnomalyInfo): number | null => {
    const c = a.chunk === null ? undefined : byId.get(a.chunk);
    return c?.first_ts_us ?? a.ts_us;
  };
  // Latest chunk end at or before `t`: start of the hole that ends at `t`.
  const previousEnd = (t: number): number | null => {
    let best: number | null = null;
    for (const s of segments) if (s.end <= t && (best === null || s.end > best)) best = s.end;
    return best;
  };

  const gaps: Gap[] = [];
  const missing: MissingMark[] = [];
  for (const a of anomalies) {
    if (a.code === 'time_gap') {
      const end = startOf(a);
      if (end === null) continue;
      const seconds = detailSeconds(a.detail, 'gap');
      const start = seconds === null ? previousEnd(end) : end - seconds * 1e6;
      if (start === null || start >= end) continue;
      // The duration is the real one; the drawn interval stays inside the displayed range.
      if (clamp(start) < clamp(end)) gaps.push({ start: clamp(start), end: clamp(end), seconds: (end - start) / 1e6 });
    } else if (a.code === 'missing_sequence') {
      const seqRange = missingRange(a);
      const next = startOf(a);
      if (seqRange === null || next === null) continue;
      const prev = previousEnd(next);
      missing.push({ at: clamp(prev === null ? next : (prev + next) / 2), ...seqRange });
    }
  }

  return {
    start: range.start,
    end: Math.max(range.end, range.start),
    lanes: Math.max(1, laneEnds.length),
    crowded,
    outliers,
    segments,
    gaps,
    overlaps,
    missing,
  };
}

const SECOND = 1_000_000;
/** Round tick steps: 1, 2, 5, 10, 15, 30 s; 1, 2, 5, 10, 15, 30 min; 1, 2, 3, 6, 12 h; 1, 2, 7 days. */
export const TICK_STEPS_US = [
  1, 2, 5, 10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600, 7200, 10_800, 21_600, 43_200, 86_400, 172_800, 604_800,
].map((s) => s * SECOND);

/**
 * Ticks on round local times (e.g. every 15 min at :00, :15, :30, :45) inside `[start, end]`,
 * using the smallest round step at least `minSpacing` px apart on a `width` px axis.
 * `tzOffsetMin` is `Date#getTimezoneOffset()` (local alignment of day and hour steps).
 */
export function ticks(
  start: number,
  end: number,
  width: number,
  minSpacing: number,
  tzOffsetMin: number = new Date(start / 1000).getTimezoneOffset(),
): { values: number[]; step: number } {
  const span = Math.max(1, end - start);
  const usPerPx = span / Math.max(1, width);
  const week = TICK_STEPS_US.at(-1) ?? 604_800 * SECOND;
  const step =
    TICK_STEPS_US.find((s) => s / usPerPx >= minSpacing) ?? Math.ceil((minSpacing * usPerPx) / week) * week;
  const offset = tzOffsetMin * 60 * SECOND;
  const values: number[] = [];
  for (let v = Math.ceil((start - offset) / step) * step + offset; v <= end && values.length < 100; v += step) {
    values.push(v);
  }
  return { values: values.length === 0 ? [start] : values, step };
}
