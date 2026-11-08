import type { EChartsCoreOption } from 'echarts/core';

// Readability rules every chart gets for free (docs/UI_GUIDELINES.md, "Implémentation des
// graphiques"). Explicit values in a view's option always win.

/** Below this container width the legend goes under the chart, otherwise on the right. */
export const LEGEND_SIDE_MIN_WIDTH = 1024;

type Obj = Record<string, unknown>;

function isObj(v: unknown): v is Obj {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function asList(v: unknown): Obj[] | null {
  if (Array.isArray(v)) return v.filter(isObj);
  return isObj(v) ? [v] : null;
}

/** `base` under `over`, one level deep for nested objects (`lineStyle`, `textStyle`...). */
function mergeUnder(base: Obj, over: Obj): Obj {
  const out: Obj = { ...base, ...over };
  for (const [k, v] of Object.entries(base)) {
    const o = over[k];
    if (isObj(v) && isObj(o)) out[k] = { ...v, ...o };
  }
  return out;
}

function withAxisDefaults(axis: Obj, theme: Readonly<Obj>): Obj {
  const out: Obj = { ...axis };
  for (const [key, value] of Object.entries(theme)) {
    if (isObj(value)) out[key] = mergeUnder(value, isObj(axis[key]) ? axis[key] : {});
  }
  const label = isObj(out.axisLabel) ? out.axisLabel : {};
  return { ...out, axisLabel: { hideOverlap: true, ...label } };
}

function withSeriesDefaults(series: Obj, label: Readonly<Obj> | undefined): Obj {
  const layout = isObj(series.labelLayout) ? series.labelLayout : {};
  const out: Obj = { ...series, labelLayout: { hideOverlap: true, ...layout } };
  if (label !== undefined) out.label = mergeUnder({ ...label }, isObj(series.label) ? series.label : {});
  return out;
}

/** Theme colors merged under every option (the view's values win). */
export interface ChartTheme {
  /** Legend text (only when the view asks for a legend). */
  legend?: Readonly<Obj>;
  /** Every axis: `axisLabel`, `axisLine`, `splitLine`... */
  axis?: Readonly<Obj>;
  /** Slider data zooms: `borderColor`, `fillerColor`, `handleStyle`, `dataBackground`... */
  slider?: Readonly<Obj>;
  /**
   * Series labels (values at the end of bars...). ECharts does not apply the global
   * `textStyle.color` to them and outlines them by default: the theme sets their color and a
   * transparent outline (a zero outline width is replaced by the default one).
   */
  seriesLabel?: Readonly<Obj>;
}

export function normalizeOption(option: EChartsCoreOption, width: number, theme: ChartTheme = {}): EChartsCoreOption {
  const out: Obj = { ...(option as Obj) };

  for (const key of ['xAxis', 'yAxis'] as const) {
    const axes = asList(out[key]);
    if (axes !== null) out[key] = axes.map((a) => withAxisDefaults(a, theme.axis ?? {}));
  }
  const series = asList(out.series);
  if (series !== null) out.series = series.map((x) => withSeriesDefaults(x, theme.seriesLabel));

  const zooms = asList(out.dataZoom);
  if (zooms !== null) {
    out.dataZoom = zooms.map((z) => (z.type === 'slider' ? mergeUnder({ ...theme.slider }, z) : z));
  }

  const legend = asList(out.legend);
  if (legend !== null) {
    const side = width >= LEGEND_SIDE_MIN_WIDTH;
    const placement = side
      ? { orient: 'vertical', right: 0, top: 'middle' }
      : { orient: 'horizontal', left: 'center', bottom: 0 };
    // A legend is only styled when the view asks for one (none is added otherwise).
    out.legend = legend.map((l) => ({ type: 'scroll', ...placement, ...theme.legend, ...l }));
  }
  return out as EChartsCoreOption;
}

/** Window of a data zoom, in percent (`null`: not known). */
export interface ZoomWindow {
  start: number;
  end: number;
}

/** Current windows of the data zooms of an applied option (`chart.getOption()`), in order. */
export function zoomWindows(applied: unknown): (ZoomWindow | null)[] {
  const zooms = isObj(applied) ? asList(applied.dataZoom) : null;
  return (zooms ?? []).map((z) => {
    const start = Number(z.start);
    const end = Number(z.end);
    return Number.isFinite(start) && Number.isFinite(end) ? { start, end } : null;
  });
}

/**
 * `option` with the zoom windows the user left (same number of data zooms only): re-applying
 * an option must not reset the zoom. Views change it with a `dataZoom` action.
 */
export function keepZoomWindows(option: EChartsCoreOption, windows: readonly (ZoomWindow | null)[]): EChartsCoreOption {
  const zooms = asList((option as Obj).dataZoom);
  if (zooms === null || zooms.length !== windows.length) return option;
  return {
    ...option,
    dataZoom: zooms.map((z, i) => {
      const w = windows[i];
      return w === null || w === undefined ? z : { ...z, start: w.start, end: w.end };
    }),
  } as EChartsCoreOption;
}
