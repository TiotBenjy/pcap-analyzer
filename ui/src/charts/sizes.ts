/** Fixed heights per chart type (docs/UI_GUIDELINES.md) to avoid layout jumps. */
export const CHART_HEIGHT = {
  donut: 240,
  timeseries: 320,
  bars: (n: number) => Math.min(40 * Math.max(n, 1), 400),
} as const;
