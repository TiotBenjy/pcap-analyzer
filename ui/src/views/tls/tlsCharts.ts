import type { EChartsCoreOption } from 'echarts/core';
import type { TlsStats } from '../../api/types/TlsStats';
import { CATEGORICAL, OTHER_COLOR, SEQUENTIAL, SEQUENTIAL_DARK } from '../../charts/palette';
import { suiteLabel, truncateMiddle } from './tlsFormat';

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
  /** Localized count (bar value labels). */
  count: (n: number) => string;
}

/** Plain text for tooltips (names come from the capture). */
function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
}

/** Donut item names that are not versions (ECharts drops legend entries with an empty name). */
const NO_VERSION = 'none';
const OTHER_VERSIONS = 'other';

/** Version of a donut item name; `null` for "no ServerHello" and for the other versions. */
function versionOfName(name: string): number | null {
  if (name === NO_VERSION || name === OTHER_VERSIONS) return null;
  const v = Number(name);
  return Number.isInteger(v) ? v : null;
}

/** Donut of the negotiated versions (top 8, then the other versions summed). */
export function buildVersionsOption(stats: TlsStats, fmt: TlsChartFormat): EChartsCoreOption {
  const total = stats.versions.reduce((n, v) => n + v.count, 0) + stats.other_versions;
  const label = (name: string) => (name === OTHER_VERSIONS ? fmt.other : fmt.version(versionOfName(name)));
  const data = stats.versions.map((v) => ({
    name: v.version === null ? NO_VERSION : String(v.version),
    value: v.count,
    itemStyle: { color: versionColor(v.version) },
  }));
  if (stats.other_versions > 0) {
    data.push({ name: OTHER_VERSIONS, value: stats.other_versions, itemStyle: { color: OTHER_COLOR } });
  }
  return {
    tooltip: {
      trigger: 'item',
      formatter: (p: { name: string; value: number }) =>
        `${escapeHtml(label(p.name))}<br/>${escapeHtml(fmt.share(p.value, total))}`,
    },
    // A plain legend wraps on narrow cards (a scrolled one leaves entries outside the SVG).
    legend: { type: 'plain', formatter: label },
    series: [
      {
        type: 'pie',
        radius: ['50%', '72%'],
        center: ['50%', '42%'],
        label: { show: false },
        labelLine: { show: false },
        data,
      },
    ],
  };
}

/** Category label of a suite row (top first). */
export function suiteRowLabel(s: { suite: number | null; name: string | null }, other: string): string {
  return s.suite === null ? other : suiteLabel(s.name, s.suite);
}

/**
 * Horizontal bars of the top suites: weak ones get an amber dot before their label (cut in the
 * middle, full name in the tooltip), the count is written at the end of each bar (no value axis,
 * so that narrow cards keep a useful plot area). `labelColor`: theme text color.
 */
export function buildSuitesOption(stats: TlsStats, fmt: TlsChartFormat, labelColor: string): EChartsCoreOption {
  const total = stats.suites.reduce((n, s) => n + s.count, 0);
  // Category axes draw from the bottom: reverse so that the most frequent is on top.
  const rows = [...stats.suites].reverse();
  return {
    // The right margin holds the value labels (series labels are outside `containLabel`).
    grid: { left: 4, right: 56, top: 4, bottom: 4, containLabel: true },
    tooltip: {
      trigger: 'item',
      formatter: (p: { dataIndex: number }) => {
        const s = rows[p.dataIndex];
        if (s === undefined) return '';
        const weak = s.weak === null ? '' : `<br/>${escapeHtml(fmt.weak(s.weak))}`;
        return `${escapeHtml(s.suite === null ? fmt.other : (s.name ?? suiteLabel(null, s.suite)))}<br/>${escapeHtml(fmt.share(s.count, total))}${weak}`;
      },
    },
    xAxis: { type: 'value', show: false },
    yAxis: {
      type: 'category',
      data: rows.map((s) => suiteRowLabel(s, fmt.other)),
      axisTick: { show: false },
      axisLabel: {
        formatter: (value: string, index: number) => {
          const weak = rows[index]?.weak !== null && rows[index]?.weak !== undefined;
          return `{${weak ? 'w' : 's'}|}{n|${truncateMiddle(value)}}`;
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
        label: {
          show: true,
          position: 'right',
          color: labelColor,
          // zrender ignores `textBorderWidth: 0`: a transparent border keeps the text plain.
          textBorderColor: 'transparent',
          formatter: (p: { value: number }) => fmt.count(p.value),
        },
        data: rows.map((s) => ({
          value: s.count,
          itemStyle: { color: s.suite === null ? OTHER_COLOR : CATEGORICAL[1] },
        })),
      },
    ],
  };
}

/** Height of the heatmap for `rows` suites (plus the column labels). */
export function matrixHeight(rows: number): number {
  return Math.min(32 * Math.max(rows, 1) + 30, 540);
}

/** Columns of the heatmap: the versions of the matrix, oldest first. */
export function matrixVersions(stats: TlsStats): (number | null)[] {
  return [...new Set(stats.matrix.map((c) => c.version))].sort(
    (a, b) => (a ?? Number.MAX_SAFE_INTEGER) - (b ?? Number.MAX_SAFE_INTEGER),
  );
}

/**
 * Version (columns) x suite (rows) heatmap over the folded suites and versions. The blue scale
 * follows the theme (`dark`: dark to bright, so that light cells do not glare).
 */
export function buildMatrixOption(stats: TlsStats, fmt: TlsChartFormat, dark: boolean): EChartsCoreOption {
  const versions = matrixVersions(stats);
  const rows = [...stats.suites].reverse();
  const max = Math.max(1, ...stats.matrix.map((c) => c.count));
  const data = stats.matrix.flatMap((c) => {
    const x = versions.indexOf(c.version);
    const y = rows.findIndex((s) => s.suite === c.suite);
    if (x < 0 || y < 0) return [];
    const high = c.count / max > 0.5;
    // Light text on dark cells: high values in the light theme, low ones in the dark theme.
    const lightText = dark ? !high : high;
    return [{ value: [x, y, c.count], label: { color: lightText ? '#ffffff' : '#172554' } }];
  });
  const columnLabel = (v: number | null) => (v === null ? fmt.other : fmt.version(v).replace(/^TLS /, ''));
  return {
    // `containLabel` ignores the labels of a top axis: the top margin holds them.
    grid: { left: 4, right: 12, top: 22, bottom: 4, containLabel: true },
    tooltip: {
      trigger: 'item',
      formatter: (p: { value: [number, number, number] }) => {
        const [x, y, count] = p.value;
        const s = rows[y];
        const name = s === undefined ? '' : s.suite === null ? fmt.other : (s.name ?? suiteLabel(null, s.suite));
        const v = versions[x] ?? null;
        return `${escapeHtml(v === null ? fmt.other : fmt.version(v))}<br/>${escapeHtml(name)}<br/>${escapeHtml(fmt.sessions(count))}`;
      },
    },
    xAxis: {
      type: 'category',
      position: 'top',
      // Short labels (`1.2`): the card title names the axis, and four columns fit at 375 px.
      data: versions.map(columnLabel),
      splitArea: { show: false },
      axisTick: { show: false },
      axisLabel: { interval: 0, hideOverlap: true },
    },
    yAxis: {
      type: 'category',
      data: rows.map((s) => suiteRowLabel(s, fmt.other)),
      axisTick: { show: false },
      axisLabel: { interval: 0, formatter: (v: string) => truncateMiddle(v) },
    },
    visualMap: {
      show: false,
      min: 0,
      max,
      dimension: 2,
      inRange: { color: dark ? [...SEQUENTIAL_DARK] : [...SEQUENTIAL] },
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

/** Version of a donut click (`undefined` without `ServerHello` and for the other versions). */
export function versionOfPie(params: unknown): number | undefined {
  const name = (params as { name?: unknown }).name;
  return typeof name === 'string' ? (versionOfName(name) ?? undefined) : undefined;
}

/** Suite of a bar or heatmap row click (`undefined` for the "other" row). */
export function suiteOfRow(stats: TlsStats, rowIndex: number): number | undefined {
  const s = [...stats.suites].reverse()[rowIndex];
  return s?.suite ?? undefined;
}
