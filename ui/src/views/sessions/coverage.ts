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
  segments: Segment[];
  gaps: Gap[];
  overlaps: Interval[];
  missing: MissingMark[];
}

/** Builds the timeline model; `null` when no chunk has timestamps. */
export function buildCoverage(chunks: readonly ChunkInfo[], anomalies: readonly AnomalyInfo[]): Coverage | null {
  const timed = chunks
    .filter((c): c is ChunkInfo & { first_ts_us: number; last_ts_us: number } => c.first_ts_us !== null && c.last_ts_us !== null)
    .map((c) => ({ chunk: c, start: c.first_ts_us, end: Math.max(c.first_ts_us, c.last_ts_us) }))
    .sort((a, b) => a.start - b.start || a.chunk.id - b.chunk.id);
  const first = timed[0];
  if (first === undefined) return null;

  // Greedy lane assignment and overlap detection, in start order.
  const laneEnds: number[] = [];
  const segments: Segment[] = [];
  const overlaps: Interval[] = [];
  let maxEnd = -Infinity;
  for (const t of timed) {
    let lane = laneEnds.findIndex((end) => end <= t.start);
    if (lane < 0) {
      lane = laneEnds.length;
      laneEnds.push(t.end);
    } else {
      laneEnds[lane] = t.end;
    }
    segments.push({ ...t, lane, issue: t.chunk.state !== 'ok' });
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
      gaps.push({ start, end, seconds: (end - start) / 1e6 });
    } else if (a.code === 'missing_sequence') {
      const range = missingRange(a);
      const next = startOf(a);
      if (range === null || next === null) continue;
      const prev = previousEnd(next);
      missing.push({ at: prev === null ? next : (prev + next) / 2, ...range });
    }
  }

  return {
    start: first.start,
    end: Math.max(maxEnd, first.start),
    lanes: Math.max(1, laneEnds.length),
    segments,
    gaps,
    overlaps,
    missing,
  };
}

/** `count` evenly spaced tick times over `[start, end]` (both ends included). */
export function ticks(start: number, end: number, count: number): number[] {
  if (count < 2 || end <= start) return [start];
  return Array.from({ length: count }, (_, i) => start + ((end - start) * i) / (count - 1));
}
