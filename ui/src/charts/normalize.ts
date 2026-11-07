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

function withAxisDefaults(axis: Obj): Obj {
  const label = isObj(axis.axisLabel) ? axis.axisLabel : {};
  return { ...axis, axisLabel: { hideOverlap: true, ...label } };
}

function withSeriesDefaults(series: Obj): Obj {
  const layout = isObj(series.labelLayout) ? series.labelLayout : {};
  return { ...series, labelLayout: { hideOverlap: true, ...layout } };
}

export function normalizeOption(
  option: EChartsCoreOption,
  width: number,
  legendDefaults: Readonly<Obj> = {},
): EChartsCoreOption {
  const out: Obj = { ...(option as Obj) };

  for (const key of ['xAxis', 'yAxis'] as const) {
    const axes = asList(out[key]);
    if (axes !== null) out[key] = axes.map(withAxisDefaults);
  }
  const series = asList(out.series);
  if (series !== null) out.series = series.map(withSeriesDefaults);

  const legend = asList(out.legend);
  if (legend !== null) {
    const side = width >= LEGEND_SIDE_MIN_WIDTH;
    const placement = side
      ? { orient: 'vertical', right: 0, top: 'middle' }
      : { orient: 'horizontal', left: 'center', bottom: 0 };
    // A legend is only styled when the view asks for one (none is added otherwise).
    out.legend = legend.map((l) => ({ type: 'scroll', ...placement, ...legendDefaults, ...l }));
  }
  return out as EChartsCoreOption;
}
