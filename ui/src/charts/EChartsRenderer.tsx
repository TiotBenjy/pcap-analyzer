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
import { useEffect, useRef } from 'react';
import { useTheme } from '../theme/theme';
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
  const muted = cssVar('--ns-muted');
  const line = cssVar('--ns-line');
  const surface = cssVar('--ns-surface');
  return {
    color: [...CATEGORICAL],
    backgroundColor: 'transparent',
    animation: false,
    textStyle: { color: fg, fontFamily: 'Inter Variable, ui-sans-serif, sans-serif', fontSize: 12 },
    legend: { textStyle: { color: muted }, type: 'scroll' },
    tooltip: {
      backgroundColor: surface,
      borderColor: line,
      textStyle: { color: fg, fontSize: 12 },
      confine: true,
    },
  };
}

interface Props {
  option: EChartsCoreOption;
  height: number;
  ariaLabel: string;
}

export default function EChartsRenderer({ option, height, ariaLabel }: Props) {
  const ref = useRef<HTMLDivElement>(null);
  const chartRef = useRef<EChartsType | null>(null);
  const { theme } = useTheme();

  // Create once; dispose on unmount.
  useEffect(() => {
    const el = ref.current;
    if (el === null) return;
    const chart = echarts.init(el, null, { renderer: 'svg' });
    chartRef.current = chart;
    const ro = new ResizeObserver(() => {
      chart.resize();
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
    chart.setOption(option);
  }, [option, theme]);

  return <div ref={ref} role="img" aria-label={ariaLabel} style={{ height }} className="w-full min-w-0" />;
}
