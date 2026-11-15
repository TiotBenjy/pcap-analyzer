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
import { type Ref, useEffect, useImperativeHandle, useRef, useState } from 'react';
import { useTheme } from '../theme/theme';
import { type ChartTheme, keepZoomWindows, LEGEND_SIDE_MIN_WIDTH, normalizeOption, zoomWindows } from './normalize';
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

/** Theme colors of axes, legends and zoom sliders (`normalizeOption`). */
function chartTheme(): ChartTheme {
  const fg = cssVar('--ns-fg');
  const muted = cssVar('--ns-muted');
  const faint = cssVar('--ns-faint');
  const line = cssVar('--ns-line');
  const surface = cssVar('--ns-surface');
  const subtle = cssVar('--ns-subtle');
  const accent = cssVar('--ns-accent');
  const tint = (pct: number) => `color-mix(in oklab, ${accent} ${pct}%, transparent)`;
  return {
    legend: { textStyle: { color: muted }, pageTextStyle: { color: muted } },
    seriesLabel: { color: fg, textBorderColor: 'transparent' },
    axis: {
      axisLabel: { color: muted },
      axisLine: { lineStyle: { color: line } },
      axisTick: { lineStyle: { color: line } },
      splitLine: { lineStyle: { color: line } },
    },
    slider: {
      borderColor: line,
      backgroundColor: 'transparent',
      fillerColor: tint(15),
      handleStyle: { color: surface, borderColor: muted },
      moveHandleStyle: { color: subtle, borderColor: line },
      emphasis: { handleStyle: { borderColor: accent }, moveHandleStyle: { color: faint } },
      dataBackground: { lineStyle: { color: faint }, areaStyle: { color: subtle } },
      selectedDataBackground: { lineStyle: { color: accent }, areaStyle: { color: tint(25) } },
      textStyle: { color: muted },
    },
  };
}

/** ECharts event handlers by event name (`datazoom`, `click`...). */
export type ChartEvents = Readonly<Record<string, (params: unknown) => void>>;

/** Imperative access to a drawn chart (for instance `{ type: 'dataZoom', start: 0, end: 100 }`). */
export interface ChartHandle {
  dispatchAction: (action: { type: string } & Record<string, unknown>) => void;
}

interface Props {
  option: EChartsCoreOption;
  height: number;
  ariaLabel: string;
  onEvents?: ChartEvents | undefined;
  handleRef?: Ref<ChartHandle> | undefined;
}

export default function EChartsRenderer({ option, height, ariaLabel, onEvents, handleRef }: Props) {
  const ref = useRef<HTMLDivElement>(null);
  const chartRef = useRef<EChartsType | null>(null);
  const { theme } = useTheme();
  // Only the legend side matters: the option is re-applied when the width crosses the
  // threshold (the side is read from the element, so the first drawing already has it right).
  const wide = useRef(false);
  const [layout, setLayout] = useState(0);

  // Create once; dispose on unmount.
  useEffect(() => {
    const el = ref.current;
    if (el === null) return;
    const chart = echarts.init(el, null, { renderer: 'svg' });
    chartRef.current = chart;
    const box = el.getBoundingClientRect();
    let size = { width: box.width, height: box.height };
    wide.current = box.width >= LEGEND_SIDE_MIN_WIDTH;
    const ro = new ResizeObserver((entries) => {
      const rect = entries[0]?.contentRect;
      if (rect === undefined) return;
      // The first notification comes right after the first drawing, at the same size: redrawing
      // every series then was a tenth of the Overview display time (P4.8).
      if (rect.width !== size.width || rect.height !== size.height) {
        size = { width: rect.width, height: rect.height };
        chart.resize();
      }
      const side = rect.width >= LEGEND_SIDE_MIN_WIDTH;
      if (side !== wide.current) {
        wide.current = side;
        setLayout((n) => n + 1);
      }
    });
    ro.observe(el);
    return () => {
      ro.disconnect();
      chart.dispose();
      chartRef.current = null;
    };
  }, []);

  useImperativeHandle(
    handleRef,
    () => ({
      dispatchAction: (action) => {
        chartRef.current?.dispatchAction(action);
      },
    }),
    [],
  );

  // Re-apply on option or theme change (CSS variables differ per theme). The zoom window the
  // user left is kept: zooming itself never goes through here.
  useEffect(() => {
    const chart = chartRef.current;
    if (chart === null) return;
    const windows = zoomWindows(chart.getOption());
    // Lazy: the theme defaults alone are never drawn, the next call draws everything once.
    chart.setOption(baseOption(), { notMerge: true, lazyUpdate: true });
    const next = normalizeOption(option, wide.current ? LEGEND_SIDE_MIN_WIDTH : 0, chartTheme());
    chart.setOption(keepZoomWindows(next, windows));
  }, [option, theme, layout]);

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

  // `data-chart`: the visual tests wait for its SVG before a capture.
  return <div ref={ref} role="img" aria-label={ariaLabel} data-chart style={{ height }} className="w-full min-w-0" />;
}
