import type { EChartsCoreOption } from 'echarts/core';
import type { BarItem } from '../../components/BarList';
import { CATEGORICAL, NEUTRAL, OTHER_COLOR } from '../../charts/palette';
import { escapeHtml } from '../../charts/text';
import { formatShare, labelled } from '../../lib/format';

/** One slice or bar. */
export interface ChartEntry {
  /** Stable key (protocol id, response code...). */
  key: string;
  label: string;
  value: number;
  color?: string;
}

interface ItemParam {
  name: string;
  value: number;
  percent?: number;
}

/** `label: value (share)` as plain text (a `title` attribute, or HTML once escaped). */
function shareLine(label: string, value: number, total: number, format: (n: number) => string): string {
  const share = formatShare(value, total);
  return labelled(label, share === '' ? format(value) : `${format(value)} (${share})`);
}

function tooltipLine(label: string, value: number, total: number, format: (n: number) => string): string {
  // ECharts renders tooltips as HTML: escape the label (names come from the capture).
  return shareLine(escapeHtml(label), value, total, format);
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

/** Rows of a `BarList`, largest first; the "Other" row is lighter. */
export function entryBars(entries: readonly ChartEntry[], format: (n: number) => string, color: string = NEUTRAL): BarItem[] {
  const total = entries.reduce((s, e) => s + e.value, 0);
  return entries.map((e) => ({
    key: e.key,
    label: e.label,
    // A `title` attribute is plain text: no HTML escaping.
    title: shareLine(e.label, e.value, total, format),
    value: e.value,
    valueText: format(e.value),
    color: e.color ?? color,
    muted: e.key === '__other',
  }));
}

/** `entries` plus an "Other" entry when `other` is positive. */
export function withOther(entries: ChartEntry[], other: number, label: string): ChartEntry[] {
  return other > 0 ? [...entries, { key: '__other', label, value: other, color: OTHER_COLOR }] : entries;
}
