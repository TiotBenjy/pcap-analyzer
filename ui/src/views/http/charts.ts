import type { EChartsCoreOption } from 'echarts/core';
import type { HttpCount } from '../../api/types/HttpCount';
import { CATEGORICAL, OTHER_COLOR } from '../../charts/palette';
import { CHART_HEIGHT } from '../../charts/sizes';
import { statusClass } from './format';

// Option builders of the HTTP charts (methods, status codes, content types). Labels come from
// the capture (hostile input): tooltips are built from escaped text only.

/** Fixed colors of the method groups, shared by both HTTP views. */
export const METHOD_COLORS: Readonly<Record<string, string>> = {
  GET: CATEGORICAL[0],
  POST: CATEGORICAL[1],
  HEAD: CATEGORICAL[2],
  OPTIONS: CATEGORICAL[3],
  PUT: CATEGORICAL[4],
  PATCH: CATEGORICAL[5],
  DELETE: CATEGORICAL[6],
  CONNECT: CATEGORICAL[6],
  other: OTHER_COLOR,
};

/** Fixed colors of the status classes. */
export const STATUS_CLASS_COLORS: Readonly<Record<string, string>> = {
  '1xx': CATEGORICAL[6],
  '2xx': CATEGORICAL[1],
  '3xx': CATEGORICAL[0],
  '4xx': CATEGORICAL[2],
  '5xx': CATEGORICAL[4],
  other: OTHER_COLOR,
};

/** Color of the bar charts (one series, no category colors); `other` is grey. */
export const BAR_COLOR = CATEGORICAL[0];

export const barColor = (key: string) => (key === 'other' ? OTHER_COLOR : BAR_COLOR);

/** Up to this many categories, a part-of-whole chart is a donut; beyond, horizontal bars. */
export const DONUT_MAX = 5;
/** Height of the donut and of the status chart. */
export const PART_HEIGHT = CHART_HEIGHT.donut;
/** Vertical center of the donut, in px (the total is drawn there, over the chart). */
export const DONUT_CENTER_Y = 104;
const LABEL_MAX = 24;

export interface ChartFormat {
  count: (n: number) => string;
  /** Display label of a key (`other` -> translated). */
  label: (key: string) => string;
}

export const escapeHtml = (s: string) =>
  s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c] ?? c);

export const truncateLabel = (s: string, max = LABEL_MAX) => (s.length > max ? `${s.slice(0, max - 1)}…` : s);

interface TooltipParam {
  name?: string;
  value?: unknown;
  marker?: string;
  seriesName?: string;
}

const first = (p: unknown): TooltipParam => (Array.isArray(p) ? ((p[0] as TooltipParam | undefined) ?? {}) : (p as TooltipParam));

function tooltipLine(marker: string, label: string, value: number, total: number, fmt: ChartFormat): string {
  const pct = total > 0 ? ` <span style="opacity:.7">${((value / total) * 100).toFixed(1)}%</span>` : '';
  return `${marker}${escapeHtml(label)}: <b>${escapeHtml(fmt.count(value))}</b>${pct}`;
}

export function barsHeight(n: number): number {
  return Math.max(80, CHART_HEIGHT.bars(n));
}

/** Donut of at most [`DONUT_MAX`] categories, total drawn by the view in the middle. */
export function donutOption(counts: readonly HttpCount[], colors: Readonly<Record<string, string>>, fmt: ChartFormat): EChartsCoreOption {
  const total = counts.reduce((s, c) => s + c.count, 0);
  const names = counts.map((c) => fmt.label(c.key));
  return {
    tooltip: {
      trigger: 'item',
      formatter: (p: unknown) => {
        const t = first(p);
        return tooltipLine(t.marker ?? '', t.name ?? '', Number(t.value), total, fmt);
      },
    },
    legend: { data: names },
    series: [
      {
        type: 'pie',
        radius: [52, 78],
        center: ['50%', DONUT_CENTER_Y],
        avoidLabelOverlap: true,
        label: { show: false },
        labelLine: { show: false },
        data: counts.map((c, i) => ({
          name: names[i] ?? c.key,
          value: c.count,
          itemStyle: { color: colors[c.key] ?? OTHER_COLOR },
        })),
      },
    ],
  };
}

/**
 * Horizontal bars, in the given order (top first), the value at the end of each bar (no value
 * axis; label color and outline come from the shared chart theme).
 */
export function barsOption(
  counts: readonly HttpCount[],
  colors: (key: string) => string,
  fmt: ChartFormat,
): EChartsCoreOption {
  const total = counts.reduce((s, c) => s + c.count, 0);
  const labels = counts.map((c) => fmt.label(c.key));
  return {
    // Room on the right for the value labels (not counted by `containLabel`).
    grid: { left: 8, right: 64, top: 4, bottom: 4, containLabel: true },
    tooltip: {
      trigger: 'axis',
      axisPointer: { type: 'shadow' },
      formatter: (p: unknown) => {
        const t = first(p);
        return tooltipLine(t.marker ?? '', t.name ?? '', Number(t.value), total, fmt);
      },
    },
    xAxis: { type: 'value', show: false },
    yAxis: {
      type: 'category',
      inverse: true,
      data: labels,
      axisTick: { show: false },
      axisLabel: { formatter: (v: string) => truncateLabel(v) },
    },
    series: [
      {
        type: 'bar',
        barMaxWidth: 20,
        label: {
          show: true,
          position: 'right',
          formatter: (p: { value?: unknown }) => fmt.count(Number(p.value)),
        },
        data: counts.map((c) => ({ value: c.count, itemStyle: { color: colors(c.key) } })),
      },
    ],
  };
}

/** Status codes in ascending order, one bar each, colored (and stacked in a legend) by class. */
export function statusOption(statuses: readonly HttpCount[], fmt: ChartFormat): EChartsCoreOption {
  const sorted = [...statuses].sort((a, b) => Number(a.key) - Number(b.key));
  const codes = sorted.map((s) => s.key);
  const classes = [...new Set(codes.map((c) => statusClass(Number(c))))];
  const total = sorted.reduce((s, c) => s + c.count, 0);
  return {
    grid: { left: 8, right: 16, top: 12, bottom: 32, containLabel: true },
    legend: { data: classes },
    tooltip: {
      trigger: 'axis',
      axisPointer: { type: 'shadow' },
      formatter: (p: unknown) => {
        const list = (Array.isArray(p) ? p : [p]) as TooltipParam[];
        const hit = list.find((x) => typeof x.value === 'number');
        return hit === undefined ? '' : tooltipLine(hit.marker ?? '', hit.name ?? '', Number(hit.value), total, fmt);
      },
    },
    xAxis: { type: 'category', data: codes, axisTick: { alignWithLabel: true } },
    yAxis: { type: 'value', minInterval: 1, axisLabel: { formatter: (v: number) => fmt.count(v) } },
    series: classes.map((cls) => ({
      name: cls,
      type: 'bar',
      stack: 'status',
      barMaxWidth: 28,
      itemStyle: { color: STATUS_CLASS_COLORS[cls] ?? OTHER_COLOR },
      data: sorted.map((s) => (statusClass(Number(s.key)) === cls ? s.count : '-')),
    })),
  };
}
