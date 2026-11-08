import { BarChart, HeatmapChart, LineChart, PieChart } from 'echarts/charts';
import {
  DataZoomComponent,
  GridComponent,
  LegendComponent,
  TitleComponent,
  TooltipComponent,
  VisualMapComponent,
} from 'echarts/components';
import type { EChartsCoreOption, EChartsType } from 'echarts/core';
import * as echarts from 'echarts/core';
import { SVGRenderer } from 'echarts/renderers';
import { useEffect, useRef, useState } from 'react';
import { useTheme } from '../theme/theme';
import { LEGEND_SIDE_MIN_WIDTH, normalizeOption } from './normalize';
import { CATEGORICAL } from './palette';

// Explicit registration keeps the chunk small (no full `echarts` import).
echarts.use([
  BarChart,
  HeatmapChart,
  LineChart,
  PieChart,
  DataZoomComponent,
  GridComponent,
  LegendComponent,
  TitleComponent,
  TooltipComponent,
  VisualMapComponent,
  SVGRenderer,
]);

function cssVar(name: string): string {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

/** Theme-dependent defaults merged under every option. No animation (sobriety). */
function baseOption(): EChartsCoreOption {
  const fg = cssVar('--ns-fg');
  const line = cssVar('--ns-line');
  const surface = cssVar('--ns-surface');
  return {
    color: [...CATEGORICAL],
    backgroundColor: 'transparent',
    animation: false,
    textStyle: { color: fg, fontFamily: 'Inter Variable, ui-sans-serif, sans-serif', fontSize: 12 },
    tooltip: {
      backgroundColor: surface,
      borderColor: line,
      textStyle: { color: fg, fontSize: 12 },
      confine: true,
    },
  };
}

/** ECharts event handlers by event name (`datazoom`, `click`...). */
export type ChartEvents = Readonly<Record<string, (params: unknown) => void>>;

interface Props {
  option: EChartsCoreOption;
  height: number;
  ariaLabel: string;
  onEvents?: ChartEvents | undefined;
}

export default function EChartsRenderer({ option, height, ariaLabel, onEvents }: Props) {
  const ref = useRef<HTMLDivElement>(null);
  const chartRef = useRef<EChartsType | null>(null);
  const { theme } = useTheme();
  // Only the legend side matters, so re-render when crossing the threshold, not on every pixel.
  const [wide, setWide] = useState(false);

  // Create once; dispose on unmount.
  useEffect(() => {
    const el = ref.current;
    if (el === null) return;
    const chart = echarts.init(el, null, { renderer: 'svg' });
    chartRef.current = chart;
    const ro = new ResizeObserver((entries) => {
      chart.resize();
      const w = entries[0]?.contentRect.width ?? 0;
      setWide(w >= LEGEND_SIDE_MIN_WIDTH);
    });
    ro.observe(el);
    return () => {
      ro.disconnect();
      chart.dispose();
      chartRef.current = null;
    };
  }, []);

  // Re-apply on option or theme change (CSS variables differ per theme).
  useEffect(() => {
    const chart = chartRef.current;
    if (chart === null) return;
    chart.setOption(baseOption(), { notMerge: true });
    const muted = cssVar('--ns-muted');
    const line = cssVar('--ns-line');
    const legendDefaults = { textStyle: { color: muted }, pageTextStyle: { color: muted } };
    const axisDefaults = {
      axisLabel: { color: muted },
      axisLine: { lineStyle: { color: line } },
      axisTick: { lineStyle: { color: line } },
      splitLine: { lineStyle: { color: line } },
    };
    chart.setOption(normalizeOption(option, wide ? LEGEND_SIDE_MIN_WIDTH : 0, legendDefaults, axisDefaults));
  }, [option, theme, wide]);

  // Handlers are (re)bound when they change; the chart instance outlives them.
  useEffect(() => {
    const chart = chartRef.current;
    if (chart === null || onEvents === undefined) return;
    const entries = Object.entries(onEvents);
    for (const [name, handler] of entries) chart.on(name, handler);
    return () => {
      for (const [name, handler] of entries) chart.off(name, handler);
    };
  }, [onEvents]);

  return <div ref={ref} role="img" aria-label={ariaLabel} style={{ height }} className="w-full min-w-0" />;
}
