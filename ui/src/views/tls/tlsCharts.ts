import type { EChartsCoreOption } from 'echarts/core';
import type { TlsStats } from '../../api/types/TlsStats';
import { CATEGORICAL, OTHER_COLOR, SEQUENTIAL } from '../../charts/palette';
import { suiteLabel, truncateLabel } from './tlsFormat';

// ECharts options of the TLS view (pure functions, unit tested).

/** Amber of the weak-suite marker (semantic warning color). */
export const WEAK_COLOR = '#d97706';

/** One color per version, fixed everywhere (TLS 1.3 takes the TLS hue of the palette). */
export function versionColor(v: number | null): string {
  switch (v) {
    case 0x0304:
      return CATEGORICAL[1];
    case 0x0303:
      return CATEGORICAL[0];
    case 0x0302:
      return CATEGORICAL[3];
    case 0x0301:
      return CATEGORICAL[2];
    case 0x0300:
    case 0x0002:
      return CATEGORICAL[4];
    default:
      return OTHER_COLOR;
  }
}

export interface TlsChartFormat {
  /** Name of a version, `null` = no ServerHello. */
  version: (v: number | null) => string;
  /** Tooltip line: count and share. */
  share: (count: number, total: number) => string;
  /** Label of the "other suites" row. */
  other: string;
  /** Text under the total of the donut. */
  sessions: (count: number) => string;
  /** Localized weakness label. */
  weak: (w: string) => string;
}

/** Plain text for tooltips (names come from the capture). */
function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
}

export const DONUT_CENTER_Y = 0.42;

/** Donut item name of the sessions without `ServerHello`. */
const NO_VERSION = 'none';

function versionOfName(name: string): number | null {
  if (name === NO_VERSION) return null;
  const v = Number(name);
  return Number.isInteger(v) ? v : null;
}

/**
 * Donut of the negotiated versions (the view draws the total in the center, in HTML: SVG title
 * boxes overlap). Item names are the version values.
 */
export function buildVersionsOption(stats: TlsStats, fmt: TlsChartFormat): EChartsCoreOption {
  const total = stats.versions.reduce((n, v) => n + v.count, 0);
  return {
    tooltip: {
      trigger: 'item',
      formatter: (p: { name: string; value: number }) =>
        `${escapeHtml(fmt.version(versionOfName(p.name)))}<br/>${escapeHtml(fmt.share(p.value, total))}`,
    },
    // A plain legend wraps on narrow cards (a scrolled one leaves entries outside the SVG).
    legend: {
      type: 'plain',
      formatter: (name: string) => fmt.version(versionOfName(name)),
    },
    series: [
      {
        type: 'pie',
        radius: ['52%', '72%'],
        center: ['50%', `${DONUT_CENTER_Y * 100}%`],
        label: { show: false },
        labelLine: { show: false },
        data: stats.versions.map((v) => ({
          // ECharts drops legend entries with an empty name: `none` stands for no ServerHello.
          name: v.version === null ? NO_VERSION : String(v.version),
          value: v.count,
          itemStyle: { color: versionColor(v.version) },
        })),
      },
    ],
  };
}

/** Category label of a suite row (top first). */
export function suiteRowLabel(s: { suite: number | null; name: string | null }, other: string): string {
  return s.suite === null ? other : suiteLabel(s.name, s.suite);
}

/** Horizontal bars of the top suites; weak ones get an amber dot before their label. */
export function buildSuitesOption(stats: TlsStats, fmt: TlsChartFormat): EChartsCoreOption {
  const total = stats.suites.reduce((n, s) => n + s.count, 0);
  // Category axes draw from the bottom: reverse so that the most frequent is on top.
  const rows = [...stats.suites].reverse();
  return {
    // Generous outer margins: axis label boxes must stay inside the SVG (visual tests).
    grid: { left: 4, right: 16, top: 8, bottom: 28, containLabel: true },
    tooltip: {
      trigger: 'item',
      formatter: (p: { dataIndex: number }) => {
        const s = rows[p.dataIndex];
        if (s === undefined) return '';
        const weak = s.weak === null ? '' : `<br/>${escapeHtml(fmt.weak(s.weak))}`;
        return `${escapeHtml(s.suite === null ? fmt.other : (s.name ?? suiteLabel(null, s.suite)))}<br/>${escapeHtml(fmt.share(s.count, total))}${weak}`;
      },
    },
    xAxis: { type: 'value', minInterval: 1, axisLabel: { hideOverlap: true } },
    yAxis: {
      type: 'category',
      data: rows.map((s) => suiteRowLabel(s, fmt.other)),
      axisTick: { show: false },
      axisLabel: {
        formatter: (value: string, index: number) => {
          const weak = rows[index]?.weak !== null && rows[index]?.weak !== undefined;
          return `{${weak ? 'w' : 's'}|}{n|${truncateLabel(value)}}`;
        },
        rich: {
          w: { width: 8, height: 8, borderRadius: 4, backgroundColor: WEAK_COLOR },
          s: { width: 8, height: 8 },
          n: { padding: [0, 0, 0, 6] },
        },
      },
    },
    series: [
      {
        type: 'bar',
        barMaxWidth: 20,
        data: rows.map((s) => ({
          value: s.count,
          itemStyle: { color: s.suite === null ? OTHER_COLOR : CATEGORICAL[1] },
        })),
      },
    ],
  };
}

/** Height of the heatmap for `rows` suites. */
export function matrixHeight(rows: number): number {
  return Math.min(32 * Math.max(rows, 1) + 56, 560);
}

/** Columns of the heatmap: the versions of the matrix, oldest first. */
export function matrixVersions(stats: TlsStats): (number | null)[] {
  return [...new Set(stats.matrix.map((c) => c.version))].sort(
    (a, b) => (a ?? Number.MAX_SAFE_INTEGER) - (b ?? Number.MAX_SAFE_INTEGER),
  );
}

/** Version (columns) x suite (rows) heatmap over the suites of the bars chart. */
export function buildMatrixOption(stats: TlsStats, fmt: TlsChartFormat): EChartsCoreOption {
  const versions = matrixVersions(stats);
  const rows = [...stats.suites].reverse();
  const max = Math.max(1, ...stats.matrix.map((c) => c.count));
  const data = stats.matrix.flatMap((c) => {
    const x = versions.indexOf(c.version);
    const y = rows.findIndex((s) => s.suite === c.suite);
    if (x < 0 || y < 0) return [];
    const dark = c.count / max > 0.5;
    return [{ value: [x, y, c.count], label: { color: dark ? '#ffffff' : '#1e3a8a' } }];
  });
  return {
    grid: { left: 4, right: 12, top: 32, bottom: 8, containLabel: true },
    tooltip: {
      trigger: 'item',
      formatter: (p: { value: [number, number, number] }) => {
        const [x, y, count] = p.value;
        const s = rows[y];
        const name = s === undefined ? '' : s.suite === null ? fmt.other : (s.name ?? suiteLabel(null, s.suite));
        return `${escapeHtml(fmt.version(versions[x] ?? null))}<br/>${escapeHtml(name)}<br/>${escapeHtml(fmt.sessions(count))}`;
      },
    },
    xAxis: {
      type: 'category',
      position: 'top',
      // Short labels (`1.2`): the card title names the axis, and four columns fit at 375 px.
      data: versions.map((v) => fmt.version(v).replace(/^TLS /, '')),
      splitArea: { show: false },
      axisTick: { show: false },
      axisLabel: { interval: 0, hideOverlap: true },
    },
    yAxis: {
      type: 'category',
      data: rows.map((s) => suiteRowLabel(s, fmt.other)),
      axisTick: { show: false },
      axisLabel: { interval: 0, formatter: (v: string) => truncateLabel(v) },
    },
    visualMap: {
      show: false,
      min: 0,
      max,
      dimension: 2,
      inRange: { color: [...SEQUENTIAL] },
    },
    series: [
      {
        type: 'heatmap',
        data,
        label: { show: true, fontSize: 11 },
        itemStyle: { borderColor: 'transparent', borderWidth: 2 },
      },
    ],
  };
}

/** Version of a donut click (`undefined` for the sessions without `ServerHello`). */
export function versionOfPie(params: unknown): number | undefined {
  const name = (params as { name?: unknown }).name;
  return typeof name === 'string' ? (versionOfName(name) ?? undefined) : undefined;
}

/** Suite of a bar or heatmap row click (`undefined` for the "other" row). */
export function suiteOfRow(stats: TlsStats, rowIndex: number): number | undefined {
  const s = [...stats.suites].reverse()[rowIndex];
  return s?.suite ?? undefined;
}
