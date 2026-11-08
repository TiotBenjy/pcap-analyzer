import type { TFunction } from 'i18next';
import type { AnomalyInfo } from '../../api/types/AnomalyInfo';
import { en } from '../../i18n/en';
import { formatCount, formatDuration } from '../../lib/format';

// Human-readable anomalies (codes and `detail` shapes: netsift-engine/src/translate.rs).

type KnownCode = keyof (typeof en)['anomalies']['codes'];
const KNOWN = new Set<string>(Object.keys(en.anomalies.codes));

function isKnown(code: string): code is KnownCode {
  return KNOWN.has(code);
}

/** Translated label of an anomaly code, with a generic fallback for codes added later. */
export function anomalyLabel(t: TFunction, code: string): string {
  return isKnown(code) ? t(`anomalies.codes.${code}`) : t('anomalies.unknown', { code });
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

/** Duration in seconds of a `<name>_ns` (or `<name>_us`) detail field. */
export function detailSeconds(detail: Record<string, unknown>, name: string): number | null {
  const ns = num(detail, `${name}_ns`);
  if (ns !== null) return ns / 1e9;
  const us = num(detail, `${name}_us`);
  return us === null ? null : us / 1e6;
}

/** Missing sequence numbers `first..=last` of a `missing_sequence` anomaly. */
export function missingRange(a: AnomalyInfo): { first: number; last: number } | null {
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
    case 'out_of_order': {
      const packets = num(d, 'packets');
      return packets === null ? '' : t('anomalies.packets', { packets: formatCount(packets) });
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

/**
 * Short summary such as "2 missing files in the sequence, 1 time gap of 43 s"
 * (docs/CHUNKED_CAPTURES.md, "Ce que l'UI montre").
 */
export function anomalySummary(t: TFunction, anomalies: readonly AnomalyInfo[]): string[] {
  let missing = 0;
  let gaps = 0;
  let longestGap = 0;
  let overlaps = 0;
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
    } else {
      other += 1;
    }
  }
  const parts: string[] = [];
  if (missing > 0) parts.push(t('views.sources.summaryMissing', { count: missing }));
  if (gaps > 0) parts.push(t('views.sources.summaryGap', { count: gaps, duration: formatDuration(longestGap) }));
  if (overlaps > 0) parts.push(t('views.sources.summaryOverlap', { count: overlaps }));
  if (other > 0) parts.push(t('views.sources.summaryOther', { count: other }));
  return parts;
}
