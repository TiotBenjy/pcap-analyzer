import type { EChartsCoreOption } from 'echarts/core';
import type { ProtocolSeries } from '../../api/types/ProtocolSeries';
import type { TrafficProtocol } from '../../api/types/TrafficProtocol';
import type { TrafficSeries } from '../../api/types/TrafficSeries';
import { colorFor } from '../../charts/palette';

// ECharts option of the Overview "Traffic by protocol" chart (pure: unit-tested without ECharts).

export type Metric = 'bytes' | 'packets';
export type Scale = 'linear' | 'log';
/** Legend placement: none below 640 px (the protocol selector replaces it). */
export type LegendLayout = 'none' | 'bottom' | 'right';

/** Zoom window in percent of the whole period (ECharts dataZoom `start` / `end`). */
export interface Zoom {
  start: number;
  end: number;
}

export const FULL_ZOOM: Zoom = { start: 0, end: 100 };

export const isZoomed = (z: Zoom) => z.start > 0 || z.end < 100;

export interface TrafficFormat {
  protocol: (p: TrafficProtocol) => string;
  value: (v: number) => string;
  /** Short axis label of a value (IEC bytes or compact count). */
  axis: (v: number) => string;
  /** Tooltip header of the bucket starting at `ms`. */
  bucket: (ms: number) => string;
  total: string;
}

export interface TrafficChartInput {
  data: TrafficSeries;
  selected: ReadonlySet<TrafficProtocol>;
  metric: Metric;
  scale: Scale;
  legend: LegendLayout;
  /** Narrow chart (below 640 px): fewer time ticks. */
  compact: boolean;
  format: TrafficFormat;
}

/** Width reserved on the right for a vertical legend. */
const LEGEND_WIDTH = 132;
const SLIDER_HEIGHT = 16;
const LEGEND_HEIGHT = 24;

/** Series of the response that are selected, in display order (the server's order). */
export function visibleSeries(data: TrafficSeries, selected: ReadonlySet<TrafficProtocol>): ProtocolSeries[] {
  return data.series.filter((s) => selected.has(s.protocol));
}

/** Multipliers of a byte axis step, within one IEC unit (1 B, 2 B, 5 B... 500 KiB, 1 MiB...). */
const BYTE_STEPS = [1, 2, 5, 10, 20, 50, 100, 200, 500] as const;
const Y_TICKS = 4;

/**
 * Round linear byte axis for values up to `peak`: a step of 1, 2 or 5 x 10^n x 1024^k bytes
 * (20 KiB, not 19.5 KiB) giving the number of intervals closest to `ticks` (the larger step on
 * a tie), and the first multiple of it at or above `peak`.
 */
export function byteAxis(peak: number, ticks: number = Y_TICKS): { interval: number; max: number } | null {
  if (!Number.isFinite(peak) || peak <= 0) return null;
  let best: { interval: number; max: number; miss: number } | null = null;
  for (let unit = 1; unit <= 1024 ** 5; unit *= 1024) {
    for (const m of BYTE_STEPS) {
      const interval = m * unit;
      const count = Math.ceil(peak / interval);
      const miss = Math.abs(count - ticks);
      if (best === null || miss <= best.miss) best = { interval, max: count * interval, miss };
    }
  }
  return best === null ? null : { interval: best.interval, max: best.max };
}

/** Highest stacked value of a bucket (the top of the linear chart). */
function stackedPeak(series: readonly (readonly number[])[], points: number): number {
  let peak = 0;
  for (let i = 0; i < points; i++) {
    let sum = 0;
    for (const values of series) sum += values[i] ?? 0;
    if (sum > peak) peak = sum;
  }
  return peak;
}

/** Bucket start times, in milliseconds. */
export function bucketTimes(data: TrafficSeries): number[] {
  return Array.from({ length: data.points }, (_, i) => (data.start_us + i * data.step_us) / 1000);
}

interface TooltipParam {
  seriesName?: string;
  marker?: string;
  value?: unknown;
  axisValue?: unknown;
}

const escapeHtml = (s: string) =>
  s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c] ?? c);

/** Tooltip of one bucket: protocols sorted by value (zeros omitted), share of the bucket, total. */
export function tooltipHtml(params: readonly TooltipParam[], format: TrafficFormat): string {
  const rows = params
    .map((p) => {
      const v = Array.isArray(p.value) ? Number(p.value[1]) : Number(p.value);
      return { name: p.seriesName ?? '', marker: p.marker ?? '', value: Number.isFinite(v) ? v : 0 };
    })
    .filter((r) => r.value > 0)
    .sort((a, b) => b.value - a.value);
  const first = params[0];
  const ms = Array.isArray(first?.value) ? Number(first.value[0]) : Number(first?.axisValue);
  const total = rows.reduce((sum, r) => sum + r.value, 0);
  const pct = (v: number) => (total > 0 ? `${((v / total) * 100).toFixed(v === total ? 0 : 1)}\u00a0%` : '');
  const line = (left: string, right: string, extra = '') =>
    `<div style="display:flex;gap:12px;justify-content:space-between;align-items:center"><span>${left}</span>` +
    `<span style="font-variant-numeric:tabular-nums">${right}${extra}</span></div>`;
  return [
    `<div style="margin-bottom:4px;font-weight:600">${escapeHtml(format.bucket(ms))}</div>`,
    ...rows.map((r) =>
      line(`${r.marker}${escapeHtml(r.name)}`, escapeHtml(format.value(r.value)), `<span style="opacity:.7"> ${pct(r.value)}</span>`),
    ),
    rows.length > 1 ? line(escapeHtml(format.total), escapeHtml(format.value(total))) : '',
  ].join('');
}

export function buildTrafficOption(input: TrafficChartInput): EChartsCoreOption {
  const { data, selected, metric, scale, legend, compact, format } = input;
  const log = scale === 'log';
  const times = bucketTimes(data);
  const visible = visibleSeries(data, selected);
  const valuesOf = (s: ProtocolSeries) => (metric === 'bytes' ? s.bytes : s.packets) ?? [];
  const bytes = metric === 'bytes';
  // Round byte ticks; packets keep ECharts' decimal ticks. A log byte axis has a tick per unit.
  const byteTicks = bytes && !log ? byteAxis(stackedPeak(visible.map(valuesOf), data.points)) : null;

  const series = visible.map((s) => {
    const values = valuesOf(s);
    const name = format.protocol(s.protocol);
    const color = colorFor(s.protocol);
    return {
      type: 'line',
      name,
      color,
      // Stacked areas show the composition on a linear axis; on a log axis stacked bands would
      // misrepresent the values, so each protocol is drawn on its own (zeros left out).
      ...(log ? {} : { stack: 'traffic' }),
      areaStyle: { opacity: log ? 0.08 : 0.85 },
      lineStyle: { width: log ? 2 : 1 },
      showSymbol: false,
      symbol: 'none',
      emphasis: { disabled: true },
      data: times.map((t, i) => {
        const v = values[i] ?? 0;
        return [t, log && v <= 0 ? null : v];
      }),
    };
  });

  const sliderBottom = legend === 'bottom' ? LEGEND_HEIGHT + 4 : 4;
  const first = times[0] ?? 0;
  const last = (times[times.length - 1] ?? first) + data.step_us / 1000;

  return {
    grid: {
      left: 4,
      right: legend === 'right' ? LEGEND_WIDTH : 12,
      top: 12,
      bottom: sliderBottom + SLIDER_HEIGHT + 8,
      containLabel: true,
    },
    ...(legend === 'none'
      ? {}
      : {
          legend: {
            type: 'scroll',
            data: series.map((s) => s.name),
            // The selector above the chart is the only way to show or hide protocols.
            selectedMode: false,
            icon: 'roundRect',
            itemWidth: 10,
            itemHeight: 10,
            ...(legend === 'right'
              ? { orient: 'vertical', right: 0, top: 'middle', width: LEGEND_WIDTH - 16 }
              : { orient: 'horizontal', left: 'center', bottom: 0 }),
          },
        }),
    tooltip: {
      trigger: 'axis',
      axisPointer: { type: 'line' },
      formatter: (params: unknown) => tooltipHtml(Array.isArray(params) ? (params as TooltipParam[]) : [], format),
    },
    xAxis: {
      type: 'time',
      min: first,
      max: last,
      // ECharts rounds the time step down (13 min / 3 gives 2 min ticks): 2 keeps narrow axes airy.
      ...(compact ? { splitNumber: 2 } : {}),
      axisLabel: {
        // Level-based format: the axis picks the unit from its ticks, so it adapts to the
        // captured duration and to the zoom. Local time, ISO-like, no localized month names.
        formatter: {
          year: '{yyyy}',
          month: '{yyyy}-{MM}',
          day: '{MM}-{dd}',
          hour: '{HH}:{mm}',
          minute: '{HH}:{mm}',
          second: '{HH}:{mm}:{ss}',
          millisecond: '{HH}:{mm}:{ss}',
        },
      },
      splitLine: { show: false },
    },
    yAxis: {
      type: log ? 'log' : 'value',
      ...(log ? { logBase: bytes ? 1024 : 10, min: 1 } : { min: 0 }),
      ...(byteTicks ?? {}),
      splitNumber: Y_TICKS,
      axisLabel: { formatter: (v: number) => format.axis(v) },
      splitLine: { show: true },
    },
    dataZoom: [
      // No start / end: the window belongs to the user and survives option changes (the
      // renderer keeps it); the view resets it with a `dataZoom` action.
      { type: 'inside', filterMode: 'none' },
      {
        type: 'slider',
        filterMode: 'none',
        height: SLIDER_HEIGHT,
        bottom: sliderBottom,
        left: 48,
        right: legend === 'right' ? LEGEND_WIDTH : 24,
        showDetail: false,
        brushSelect: false,
      },
    ],
    series,
  };
}

/** Zoom window of an ECharts `datazoom` event (slider: top level; inside / dispatch: `batch`). */
export function zoomOfEvent(params: unknown): Zoom | null {
  if (typeof params !== 'object' || params === null) return null;
  const p = params as { start?: unknown; end?: unknown; batch?: { start?: unknown; end?: unknown }[] };
  const src = Array.isArray(p.batch) && p.batch.length > 0 ? p.batch[0] : p;
  const start = Number(src?.start);
  const end = Number(src?.end);
  if (!Number.isFinite(start) || !Number.isFinite(end)) return null;
  return { start: Math.max(0, Math.min(100, start)), end: Math.max(0, Math.min(100, end)) };
}
