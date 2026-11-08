import { type ReactNode, useEffect, useId, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { baseName, formatCount, formatDuration, formatPeriod, formatTimestamp, sameLocalDay } from '../../lib/format';
import { CATEGORICAL, OTHER_COLOR } from '../../charts/palette';
import { type Coverage, ticks } from './coverage';

const PAD = 8; // horizontal padding inside the SVG, px
const TOP = 12; // band reserved for missing-file markers
const LANE = 20;
const LANE_GAP = 4;
const MIN_PX_PER_CHUNK = 6;
const MAX_WIDTH = 40_000;
const TICK_SPACING = 180;
const EDGE = 56; // px from an edge under which a tick label is aligned inward
const FALLBACK_WIDTH = 640;

// Data colors (charts/palette.ts), legible in both themes and distinct from each other:
// chunks neutral grey (not the accent, reserved for interactive elements), problem chunks amber,
// overlaps violet; gaps are hatched and missing files red (semantic danger).
const CHUNK = { fill: OTHER_COLOR, fillOpacity: 0.6 } as const;
const ISSUE = { fill: CATEGORICAL[2], fillOpacity: 0.85 } as const;
const OVERLAP = { fill: CATEGORICAL[3], fillOpacity: 0.25, stroke: CATEGORICAL[3] } as const;

/**
 * Chunk coverage timeline (custom SVG): one segment per chunk, hatched time gaps, highlighted
 * overlaps, markers for missing sequence numbers. Text lives outside the SVG (axis and legend in
 * HTML), details are in `<title>` tooltips. Scrolls horizontally inside its own container when
 * there are too many chunks for the width.
 */
interface CoverageTimelineProps {
  coverage: Coverage;
  /** Id of the chunk table, the detailed equivalent of the timeline (`aria-details`). */
  detailsId?: string;
}

export function CoverageTimeline({ coverage, detailsId }: CoverageTimelineProps) {
  const { t, i18n } = useTranslation();
  const summaryId = useId();
  const scrollRef = useRef<HTMLDivElement>(null);
  const [available, setAvailable] = useState(0);
  const hatchId = `hatch-${useId().replace(/[^a-zA-Z0-9_-]/g, '')}`;

  useEffect(() => {
    const el = scrollRef.current;
    if (el === null) return undefined;
    // Floor of the layout width: a rounded-up clientWidth would add a needless scrollbar.
    const measure = () => {
      setAvailable(Math.floor(el.getBoundingClientRect().width));
    };
    measure();
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    return () => {
      ro.disconnect();
    };
  }, []);

  const base = available > 0 ? available : FALLBACK_WIDTH;
  const width = Math.max(base, Math.min(coverage.segments.length * MIN_PX_PER_CHUNK + 2 * PAD, MAX_WIDTH));
  const height = TOP + coverage.lanes * LANE + (coverage.lanes - 1) * LANE_GAP + 4;
  const span = Math.max(1, coverage.end - coverage.start);
  const x = (us: number) => PAD + ((us - coverage.start) / span) * (width - 2 * PAD);
  const laneY = (lane: number) => TOP + lane * (LANE + LANE_GAP);
  const bandBottom = height - 2;

  // Tooltips are formatted once per data set, not on every resize.
  const segmentTitles = useMemo(
    () =>
      coverage.segments.map((s) =>
        t('views.sources.segmentTitle', {
          name: baseName(s.chunk.path),
          period: formatPeriod(s.start, s.end),
          packets: formatCount(s.chunk.packets),
        }),
      ),
    // i18n.language: titles follow a language switch.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [coverage, t, i18n.language],
  );
  const summary = t('views.sources.coverageSummary', {
    count: coverage.segments.length,
    start: formatTimestamp(coverage.start),
    end: formatTimestamp(coverage.end),
    gaps: coverage.gaps.length,
    overlaps: coverage.overlaps.length,
    missing: coverage.missing.reduce((n, m) => n + Math.max(1, m.last - m.first + 1), 0),
  });

  const axis = ticks(coverage.start, coverage.end, width - 2 * PAD, TICK_SPACING);
  const sameDay = sameLocalDay(coverage.start, coverage.end);
  const tickLabel = (us: number) => {
    if (axis.step < 60_000_000) return formatTimestamp(us, false);
    const hm = formatTimestamp(us, false).slice(0, 5);
    return sameDay ? hm : `${formatTimestamp(us).slice(5, 10)} ${hm}`;
  };

  return (
    <div className="flex min-w-0 flex-col gap-3">
      <div ref={scrollRef} className="w-full min-w-0 overflow-x-auto" data-testid="coverage-scroll">
        <div className="relative" style={{ width, height: height + 20 }}>
          <svg
            width={width}
            height={height}
            role="img"
            aria-label={t('views.sources.coverageLabel', { count: coverage.segments.length })}
            aria-describedby={summaryId}
            {...(detailsId === undefined ? {} : { 'aria-details': detailsId })}
            className="block"
          >
            <defs>
              <pattern id={hatchId} width="6" height="6" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">
                <line x1="0" y1="0" x2="0" y2="6" strokeWidth="2" className="stroke-faint" />
              </pattern>
            </defs>

            {coverage.gaps.map((g, i) => {
              const gx = x(g.start);
              const w = Math.max(4, x(g.end) - gx);
              return (
                <rect
                  key={`gap-${i}`}
                  data-testid="coverage-gap"
                  x={Math.min(gx, width - PAD - w)}
                  y={TOP}
                  width={w}
                  height={bandBottom - TOP}
                  fill={`url(#${hatchId})`}
                  className="stroke-faint"
                  strokeWidth={1}
                >
                  <title>{t('views.sources.gapTitle', { duration: formatDuration(g.seconds) })}</title>
                </rect>
              );
            })}

            {coverage.segments.map((s, i) => {
              const sx = x(s.start);
              const raw = x(s.end) - sx;
              const w = raw > 3 ? raw - 1 : Math.max(2, raw);
              return (
                <rect
                  key={s.chunk.id}
                  data-testid="coverage-segment"
                  x={sx}
                  y={laneY(s.lane)}
                  width={w}
                  height={LANE}
                  rx={2}
                  {...(s.issue ? ISSUE : CHUNK)}
                >
                  <title>{segmentTitles[i]}</title>
                </rect>
              );
            })}

            {coverage.overlaps.map((o, i) => {
              const ox = x(o.start);
              return (
                <rect
                  key={`overlap-${i}`}
                  data-testid="coverage-overlap"
                  x={ox}
                  y={TOP - 2}
                  width={Math.max(2, x(o.end) - ox)}
                  height={bandBottom - TOP + 2}
                  {...OVERLAP}
                  strokeWidth={1.5}
                >
                  <title>{t('views.sources.overlapTitle', { duration: formatDuration((o.end - o.start) / 1e6) })}</title>
                </rect>
              );
            })}

            {coverage.missing.map((m, i) => {
              const mx = Math.min(Math.max(x(m.at), PAD), width - PAD);
              const range = m.first === m.last ? `#${m.first}` : `#${m.first}-${m.last}`;
              return (
                <g key={`missing-${i}`} data-testid="coverage-missing" className="stroke-danger fill-danger">
                  <title>{t('views.sources.missingTitle', { range })}</title>
                  <path d={`M ${mx - 5} 1 L ${mx + 5} 1 L ${mx} ${TOP - 2} Z`} strokeWidth={1} />
                  <line x1={mx} y1={TOP - 2} x2={mx} y2={bandBottom} strokeWidth={1.5} strokeDasharray="3 2" />
                </g>
              );
            })}
          </svg>

          {/* Time axis (HTML: never overlaps chart text, aligned to the SVG scale). */}
          <div aria-hidden className="absolute inset-x-0 bottom-0 h-4 text-meta text-muted">
            {axis.values.map((us) => {
              // Labels near an edge are aligned inward so that they never leave the axis.
              const lx = x(us);
              const align = lx < EDGE ? 'translate-x-0' : lx > width - EDGE ? '-translate-x-full' : '-translate-x-1/2';
              return (
                <span key={us} className={`num absolute top-0 whitespace-nowrap ${align}`} style={{ left: x(us) }}>
                  {tickLabel(us)}
                </span>
              );
            })}
          </div>
        </div>
      </div>

      <p id={summaryId} className="sr-only">
        {summary}
      </p>
      {(coverage.crowded || coverage.outliers > 0) && (
        <div className="flex flex-col gap-0.5 text-meta text-muted">
          {coverage.crowded && <p>{t('views.sources.crowded')}</p>}
          {coverage.outliers > 0 && <p>{t('views.sources.outliers', { count: coverage.outliers })}</p>}
        </div>
      )}
      <ul className="flex flex-wrap gap-x-4 gap-y-1 text-meta text-muted">
        <LegendItem label={t('views.sources.legendChunk')}>
          <rect x="1" y="2" width="14" height="8" rx="2" {...CHUNK} />
        </LegendItem>
        <LegendItem label={t('views.sources.legendIssue')}>
          <rect x="1" y="2" width="14" height="8" rx="2" {...ISSUE} />
        </LegendItem>
        <LegendItem label={t('views.sources.legendGap')}>
          <rect x="1" y="1" width="14" height="10" fill={`url(#${hatchId})`} className="stroke-faint" />
        </LegendItem>
        <LegendItem label={t('views.sources.legendOverlap')}>
          <rect x="1" y="1" width="14" height="10" {...OVERLAP} strokeWidth={1.5} />
        </LegendItem>
        <LegendItem label={t('views.sources.legendMissing')}>
          <g className="stroke-danger fill-danger">
            <path d="M 3 1 L 13 1 L 8 6 Z" strokeWidth={1} />
            <line x1="8" y1="6" x2="8" y2="12" strokeWidth={1.5} strokeDasharray="3 2" />
          </g>
        </LegendItem>
      </ul>
    </div>
  );
}

function LegendItem({ label, children }: { label: string; children: ReactNode }) {
  return (
    <li className="inline-flex items-center gap-1.5">
      <svg aria-hidden width="16" height="12" className="shrink-0">
        {children}
      </svg>
      <span>{label}</span>
    </li>
  );
}
