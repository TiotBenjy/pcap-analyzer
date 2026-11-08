import type { EChartsCoreOption } from 'echarts/core';
import { CATEGORICAL, NEUTRAL, OTHER_COLOR } from '../../charts/palette';
import { CHART_HEIGHT } from '../../charts/sizes';

/** One slice or bar. */
export interface ChartEntry {
  /** Stable key (protocol id, response code...). */
  key: string;
  label: string;
  value: number;
  color?: string;
}

/** Axis labels are cut at this many characters (full text in the tooltip). */
export const LABEL_MAX = 24;

export function truncateLabel(s: string, max = LABEL_MAX): string {
  return s.length <= max ? s : `${s.slice(0, max - 1)}…`;
}

interface ItemParam {
  name: string;
  value: number;
  percent?: number;
}

const pct = (value: number, total: number) => (total > 0 ? (100 * value) / total : 0);

function tooltipLine(label: string, value: number, total: number, format: (n: number) => string): string {
  const share = pct(value, total);
  const shareText = share >= 10 || share === 0 ? share.toFixed(0) : share.toFixed(1);
  // ECharts renders tooltips as HTML: escape the label (names come from the capture).
  return `${escapeHtml(label)}: ${format(value)} (${shareText}\u00a0%)`;
}

export function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
}

/** Vertical position of the donut center, in percent of the chart height (the total goes there). */
export const DONUT_CENTER_Y = 42;

/**
 * Donut, labels in the legend only (<= 5 categories). The total is drawn in its center by the
 * view, as HTML (theme colors), at `DONUT_CENTER_Y`.
 */
export function donutOption(entries: readonly ChartEntry[], format: (n: number) => string): EChartsCoreOption {
  const total = entries.reduce((s, e) => s + e.value, 0);
  const byName = new Map(entries.map((e) => [e.label, e.value]));
  return {
    tooltip: {
      trigger: 'item',
      formatter: (p: ItemParam) => tooltipLine(p.name, byName.get(p.name) ?? p.value, total, format),
    },
    legend: { data: entries.map((e) => e.label) },
    series: [
      {
        type: 'pie',
        radius: ['46%', '66%'],
        center: ['50%', `${DONUT_CENTER_Y}%`],
        avoidLabelOverlap: true,
        label: { show: false },
        labelLine: { show: false },
        emphasis: { label: { show: false }, scale: false },
        data: entries.map((e, i) => ({
          name: e.label,
          value: e.value,
          itemStyle: { color: e.color ?? CATEGORICAL[i % (CATEGORICAL.length - 1)] },
        })),
      },
    ],
  };
}

/** Height of a horizontal bar chart of `n` bars, at least `min` (the donut of the same row). */
export function barsHeight(n: number, min = CHART_HEIGHT.donut): number {
  return Math.max(CHART_HEIGHT.bars(n), min);
}

/** Horizontal bars, largest first, value at the end of each bar, labels cut with a tooltip. */
export function barsOption(
  entries: readonly ChartEntry[],
  format: (n: number) => string,
  color: string = NEUTRAL,
): EChartsCoreOption {
  const total = entries.reduce((s, e) => s + e.value, 0);
  return {
    grid: { left: 8, right: 56, top: 4, bottom: 4, containLabel: true },
    tooltip: {
      trigger: 'item',
      formatter: (p: { dataIndex: number }) => {
        const e = entries[p.dataIndex];
        return e === undefined ? '' : tooltipLine(e.label, e.value, total, format);
      },
    },
    xAxis: { type: 'value', show: false, max: 'dataMax' },
    yAxis: {
      type: 'category',
      inverse: true,
      data: entries.map((e) => e.label),
      axisTick: { show: false },
      axisLabel: { formatter: (s: string) => truncateLabel(s), width: 160, overflow: 'truncate' },
    },
    series: [
      {
        type: 'bar',
        barMaxWidth: 18,
        data: entries.map((e) => ({
          value: e.value,
          // "Other" is lighter than the ranked values (same neutral hue family).
          itemStyle: {
            color: e.color ?? color,
            opacity: e.key === '__other' ? 0.5 : 1,
            borderRadius: [0, 3, 3, 0],
          },
        })),
        label: {
          show: true,
          position: 'right',
          formatter: (p: { value: number }) => format(p.value),
        },
      },
    ],
  };
}

/** `entries` plus an "Other" entry when `other` is positive. */
export function withOther(entries: ChartEntry[], other: number, label: string): ChartEntry[] {
  return other > 0 ? [...entries, { key: '__other', label, value: other, color: OTHER_COLOR }] : entries;
}
