import type { TFunction } from 'i18next';
import type { AnomalyInfo } from '../../api/types/AnomalyInfo';
import { en } from '../../i18n/en';
import { formatCount, formatDuration, formatPreciseDuration } from '../../lib/format';

// Human-readable anomalies (codes and `detail` shapes: netsift-engine/src/translate.rs).

type KnownCode = keyof (typeof en)['anomalies']['codes'];
const KNOWN = new Set<string>(Object.keys(en.anomalies.codes));

function isKnown(code: string): code is KnownCode {
  return KNOWN.has(code);
}

/**
 * Translated label of an anomaly, with a generic fallback for codes added later. Missing files
 * are counted when the range is known (`1 missing file`, `3 missing files`).
 */
export function anomalyLabel(t: TFunction, a: Pick<AnomalyInfo, 'code' | 'detail'>): string {
  if (a.code === 'missing_sequence') {
    const r = missingRange(a);
    if (r !== null) return t('anomalies.missingFiles', { count: Math.max(1, r.last - r.first + 1) });
  }
  return isKnown(a.code) ? t(`anomalies.codes.${a.code}`) : t('anomalies.unknown', { code: a.code });
}

function num(detail: Record<string, unknown>, key: string): number | null {
  const v = detail[key];
  return typeof v === 'number' && Number.isFinite(v) ? v : null;
}

function text(detail: Record<string, unknown>, key: string): string | null {
  const v = detail[key];
  if (typeof v === 'string') return v;
  if (typeof v === 'number') return String(v);
  if (Array.isArray(v)) return v.map(String).join(', ');
  return null;
}

/** Duration in seconds of a `<name>_us` (or legacy `<name>_ns`) detail field. */
export function detailSeconds(detail: Record<string, unknown>, name: string): number | null {
  // The API converts `*_ns` detail keys to microseconds (ADR-008); `_ns` is still accepted.
  const us = num(detail, `${name}_us`);
  if (us !== null) return us / 1e6;
  const ns = num(detail, `${name}_ns`);
  return ns === null ? null : ns / 1e9;
}

/** Microseconds of a `<name>_us` (or legacy `<name>_ns`) detail field. */
function detailUs(detail: Record<string, unknown>, name: string): number | null {
  const us = num(detail, `${name}_us`);
  if (us !== null) return us;
  const ns = num(detail, `${name}_ns`);
  return ns === null ? null : ns / 1e3;
}

/**
 * How far the clock went back, in microseconds: `previous - ts` of a `timestamp_backwards`
 * anomaly, the largest step of an `out_of_order` one; `null` for other codes or without detail.
 * Microseconds or milliseconds usually come from a multi-interface capture or NIC timestamping;
 * seconds or more, from a clock correction (docs/CHUNKED_CAPTURES.md).
 */
export function backwardStepUs(a: Pick<AnomalyInfo, 'code' | 'detail'>): number | null {
  if (a.code === 'out_of_order') return detailUs(a.detail, 'max_backstep');
  if (a.code !== 'timestamp_backwards') return null;
  const previous = detailUs(a.detail, 'previous');
  const ts = detailUs(a.detail, 'ts');
  return previous === null || ts === null ? null : Math.max(0, previous - ts);
}

/** Missing sequence numbers `first..=last` of a `missing_sequence` anomaly. */
export function missingRange(a: Pick<AnomalyInfo, 'detail'>): { first: number; last: number } | null {
  const first = num(a.detail, 'first');
  const last = num(a.detail, 'last') ?? first;
  return first === null || last === null ? null : { first, last };
}

export function missingRangeText(t: TFunction, a: AnomalyInfo): string {
  const r = missingRange(a);
  if (r === null) return '';
  return r.first === r.last
    ? t('anomalies.missingOne', { first: r.first })
    : t('anomalies.missingRange', { first: r.first, last: r.last });
}

/** One-line description of the anomaly details (empty when there is nothing to add). */
export function anomalyDetail(t: TFunction, a: AnomalyInfo): string {
  const d = a.detail;
  switch (a.code) {
    case 'missing_sequence':
      return missingRangeText(t, a);
    case 'time_gap': {
      const s = detailSeconds(d, 'gap');
      return s === null ? '' : t('anomalies.gap', { duration: formatDuration(s) });
    }
    case 'overlap': {
      const s = detailSeconds(d, 'overlap');
      return s === null ? '' : t('anomalies.overlap', { duration: formatDuration(s), previous: text(d, 'previous') ?? '' });
    }
    case 'duplicate': {
      const of = text(d, 'of');
      return of === null ? '' : t('anomalies.duplicate', { of });
    }
    case 'sequence_reused': {
      const seq = text(d, 'seq');
      return seq === null ? '' : t('anomalies.seq', { seq });
    }
    case 'linktype_change':
    case 'snaplen_change': {
      const previous = text(d, 'previous');
      const current = text(d, 'current');
      return previous === null || current === null ? '' : t('anomalies.change', { previous, current });
    }
    case 'timestamp_backwards': {
      const step = backwardStepUs(a);
      return step === null ? '' : t('anomalies.backwards', { duration: formatPreciseDuration(step) });
    }
    case 'out_of_order': {
      const packets = num(d, 'packets');
      if (packets === null) return '';
      const step = backwardStepUs(a);
      return step === null || step <= 0
        ? t('anomalies.packets', { packets: formatCount(packets) })
        : t('anomalies.packetsBackwards', { packets: formatCount(packets), duration: formatPreciseDuration(step) });
    }
    case 'limit_reached':
    case 'merge_fanout_limit': {
      const limit = text(d, 'limit');
      return limit === null ? '' : t('anomalies.limit', { limit });
    }
    case 'analyzer_panicked': {
      // The panic message is not shown: it may quote packet content.
      const analyzer = text(d, 'analyzer');
      return analyzer === null ? '' : t('anomalies.analyzer', { analyzer });
    }
    default:
      return text(d, 'reason') ?? '';
  }
}

/** Where the anomaly applies: a chunk, or the whole capture. */
export function anomalyWhere(t: TFunction, a: AnomalyInfo): string {
  return a.chunk === null ? t('anomalies.capture') : t('anomalies.chunk', { chunk: a.chunk });
}

/** Anomalies of the same code and chunk, shown as one line (import warnings). */
export interface AnomalyGroup {
  /** First anomaly of the group, in arrival order. */
  first: AnomalyInfo;
  count: number;
  /** Details of the whole group: the largest backward step, or the common detail. */
  detail: string;
}

/**
 * Groups anomalies of the same code and chunk, in order of first appearance. A repeated group
 * shows its largest backward step ("up to 1.2 ms") or, for other codes, the detail its members
 * share (none when they differ).
 */
export function groupAnomalies(t: TFunction, anomalies: readonly AnomalyInfo[]): AnomalyGroup[] {
  const groups = new Map<string, { first: AnomalyInfo; count: number; maxStep: number | null; details: Set<string> }>();
  for (const a of anomalies) {
    const key = `${a.code}\u0000${a.chunk === null ? '' : String(a.chunk)}`;
    let g = groups.get(key);
    if (g === undefined) {
      g = { first: a, count: 0, maxStep: null, details: new Set() };
      groups.set(key, g);
    }
    g.count += 1;
    const step = backwardStepUs(a);
    if (step !== null) g.maxStep = Math.max(g.maxStep ?? 0, step);
    if (g.details.size < 2) g.details.add(anomalyDetail(t, a));
  }
  return [...groups.values()].map(({ first, count, maxStep, details }) => {
    let detail: string;
    if (count === 1) detail = anomalyDetail(t, first);
    else if (maxStep !== null && first.code === 'timestamp_backwards')
      detail = t('anomalies.backwardsUpTo', { duration: formatPreciseDuration(maxStep) });
    else detail = details.size === 1 ? [...details][0] ?? '' : '';
    return { first, count, detail };
  });
}

/**
 * Short summary such as "2 missing files in the sequence, 1 time gap of 43 s"
 * (docs/CHUNKED_CAPTURES.md, "Ce que l'UI montre").
 */
export function anomalySummary(t: TFunction, anomalies: readonly AnomalyInfo[]): string[] {
  let missing = 0;
  let gaps = 0;
  let longestGap = 0;
  let overlaps = 0;
  let backwards = 0;
  let largestStep: number | null = null;
  let other = 0;
  for (const a of anomalies) {
    if (a.code === 'missing_sequence') {
      const r = missingRange(a);
      missing += r === null ? 1 : Math.max(1, r.last - r.first + 1);
    } else if (a.code === 'time_gap') {
      gaps += 1;
      longestGap = Math.max(longestGap, detailSeconds(a.detail, 'gap') ?? 0);
    } else if (a.code === 'overlap') {
      overlaps += 1;
    } else if (a.code === 'timestamp_backwards') {
      backwards += 1;
      const step = backwardStepUs(a);
      if (step !== null) largestStep = Math.max(largestStep ?? 0, step);
    } else {
      other += 1;
    }
  }
  const parts: string[] = [];
  if (missing > 0) parts.push(t('views.sources.summaryMissing', { count: missing }));
  if (gaps > 0) parts.push(t('views.sources.summaryGap', { count: gaps, duration: formatDuration(longestGap) }));
  if (overlaps > 0) parts.push(t('views.sources.summaryOverlap', { count: overlaps }));
  if (backwards > 0) {
    parts.push(
      largestStep === null
        ? t('views.sources.summaryBackwardsCount', { count: backwards })
        : t('views.sources.summaryBackwards', { count: backwards, duration: formatPreciseDuration(largestStep) }),
    );
  }
  if (other > 0) parts.push(t('views.sources.summaryOther', { count: other }));
  return parts;
}
