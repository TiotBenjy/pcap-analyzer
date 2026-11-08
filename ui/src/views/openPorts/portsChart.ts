import type { EChartsCoreOption } from 'echarts/core';
import type { OpenPortStats } from '../../api/types/OpenPortStats';
import { CATEGORICAL } from '../../charts/palette';
import { barLabel } from './services';

// ECharts option of the "Most exposed ports" bars (pure: unit-tested without ECharts).

/** Axis labels are cut to this many characters (full label in the tooltip). */
export const MAX_LABEL = 24;

export function truncateLabel(s: string, max = MAX_LABEL): string {
  return s.length <= max ? s : `${s.slice(0, max - 1)}…`;
}

const escapeHtml = (s: string) =>
  s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c] ?? c);

export function portsTooltip(label: string, value: string): string {
  return `<div style="font-weight:600">${escapeHtml(label)}</div><div>${escapeHtml(value)}</div>`;
}

export interface PortsFormat {
  /** Tooltip value: `3 hosts`. */
  hosts: (n: number) => string;
}

export function buildPortsOption(stats: OpenPortStats, format: PortsFormat): EChartsCoreOption {
  const labels = stats.top.map(barLabel);
  return {
    grid: { left: 8, right: 40, top: 4, bottom: 4, containLabel: true },
    // Counts are printed at the end of each bar: no value axis labels.
    xAxis: { type: 'value', minInterval: 1, splitNumber: 4, axisLabel: { show: false } },
    yAxis: {
      type: 'category',
      inverse: true,
      data: labels,
      axisTick: { show: false },
      axisLabel: { fontFamily: 'JetBrains Mono, ui-monospace, monospace', formatter: (v: string) => truncateLabel(v) },
    },
    tooltip: {
      trigger: 'axis',
      axisPointer: { type: 'shadow' },
      formatter: (params: unknown) => {
        const p = (Array.isArray(params) ? params[0] : params) as { dataIndex?: number } | undefined;
        const i = p?.dataIndex ?? 0;
        return portsTooltip(labels[i] ?? '', format.hosts(stats.top[i]?.hosts ?? 0));
      },
    },
    series: [
      {
        type: 'bar',
        data: stats.top.map((p) => p.hosts),
        itemStyle: { color: CATEGORICAL[0], borderRadius: [0, 3, 3, 0] },
        barMaxWidth: 18,
        // Text color of the theme, without the outline ECharts adds to bar labels.
        label: { show: true, position: 'right', fontSize: 12, textBorderWidth: 0 },
      },
    ],
  };
}
