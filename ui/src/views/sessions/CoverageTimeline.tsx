import { type ReactNode, useEffect, useId, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { baseName, formatCount, formatDuration, formatPeriod, formatTimestamp, sameLocalDay } from '../../lib/format';
import { type Coverage, ticks } from './coverage';

const PAD = 8; // horizontal padding inside the SVG, px
const TOP = 12; // band reserved for missing-file markers
const LANE = 20;
const LANE_GAP = 4;
const MIN_PX_PER_CHUNK = 6;
const MAX_WIDTH = 40_000;
const TICK_SPACING = 180;
const FALLBACK_WIDTH = 640;

/**
 * Chunk coverage timeline (custom SVG): one segment per chunk, hatched time gaps, highlighted
 * overlaps, markers for missing sequence numbers. Text lives outside the SVG (axis and legend in
 * HTML), details are in `<title>` tooltips. Scrolls horizontally inside its own container when
 * there are too many chunks for the width.
 */
export function CoverageTimeline({ coverage }: { coverage: Coverage }) {
  const { t } = useTranslation();
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

  const tickCount = Math.max(2, Math.min(12, Math.floor(width / TICK_SPACING)));
  const sameDay = sameLocalDay(coverage.start, coverage.end);
  const tickLabel = (us: number) => (sameDay ? formatTimestamp(us, false) : formatTimestamp(us).slice(5, 16));

  return (
    <div className="flex min-w-0 flex-col gap-3">
      <div ref={scrollRef} className="w-full min-w-0 overflow-x-auto" data-testid="coverage-scroll">
        <div className="relative" style={{ width, height: height + 20 }}>
          <svg
            width={width}
            height={height}
            role="img"
            aria-label={t('views.sources.coverageLabel', { count: coverage.segments.length })}
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

            {coverage.segments.map((s) => {
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
                  className={s.issue ? 'fill-warning/60' : 'fill-accent/70'}
                >
                  <title>
                    {t('views.sources.segmentTitle', {
                      name: baseName(s.chunk.path),
                      period: formatPeriod(s.start, s.end),
                      packets: formatCount(s.chunk.packets),
                    })}
                  </title>
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
                  className="fill-warning/25 stroke-warning"
                  strokeWidth={1}
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
            {ticks(coverage.start, coverage.end, tickCount).map((us, i, all) => {
              const align = i === 0 ? 'translate-x-0' : i === all.length - 1 ? '-translate-x-full' : '-translate-x-1/2';
              return (
                <span key={i} className={`num absolute top-0 whitespace-nowrap ${align}`} style={{ left: x(us) }}>
                  {tickLabel(us)}
                </span>
              );
            })}
          </div>
        </div>
      </div>

      <ul className="flex flex-wrap gap-x-4 gap-y-1 text-meta text-muted">
        <LegendItem label={t('views.sources.legendChunk')}>
          <rect x="1" y="2" width="14" height="8" rx="2" className="fill-accent/70" />
        </LegendItem>
        <LegendItem label={t('views.sources.legendIssue')}>
          <rect x="1" y="2" width="14" height="8" rx="2" className="fill-warning/60" />
        </LegendItem>
        <LegendItem label={t('views.sources.legendGap')}>
          <rect x="1" y="1" width="14" height="10" fill={`url(#${hatchId})`} className="stroke-faint" />
        </LegendItem>
        <LegendItem label={t('views.sources.legendOverlap')}>
          <rect x="1" y="1" width="14" height="10" className="fill-warning/25 stroke-warning" />
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
