import type { EChartsCoreOption } from 'echarts/core';
import { BarChart3 } from 'lucide-react';
import { type ComponentProps, createElement, type Ref } from 'react';
import type { ChartEvents, ChartHandle } from '../charts/EChartsRenderer';
import { type ChartRenderer, loadedChartRenderer, useChartRendererReady } from '../charts/loadRenderer';
import { useTranslation } from 'react-i18next';
import { EmptyState } from './EmptyState';
import { ErrorState } from './ErrorState';
import { Skeleton } from './Skeleton';

/** The loaded renderer (rendered once `useChartRendererReady` is true). */
function LoadedChartRenderer(props: ComponentProps<ChartRenderer>) {
  const renderer = loadedChartRenderer();
  return renderer === null ? null : createElement(renderer, props);
}

interface ChartProps {
  option: EChartsCoreOption;
  height: number;
  /** Accessible description of what the chart shows. */
  ariaLabel: string;
  loading?: boolean;
  error?: string | null;
  onRetry?: () => void;
  /** True when there is nothing to plot: an explicit empty state replaces the chart. */
  empty?: boolean;
  emptyText?: string;
  /** ECharts event handlers (keep the object stable: handlers are rebound when it changes). */
  onEvents?: ChartEvents;
  /** Imperative access to the chart once drawn (`null` while loading, empty or in error). */
  handleRef?: Ref<ChartHandle>;
}

/**
 * The only way views draw charts: SVG renderer, shared palette, theme-aware text colors,
 * ResizeObserver, and the loading / empty / error states.
 */
export function Chart({
  option,
  height,
  ariaLabel,
  loading,
  error,
  onRetry,
  empty,
  emptyText,
  onEvents,
  handleRef,
}: ChartProps) {
  const { t } = useTranslation();
  // Loaded while the data is fetched (ECharts chunk, on demand).
  const ready = useChartRendererReady();
  if (loading === true) return <Skeleton height={height} />;
  if (error !== undefined && error !== null) {
    return (
      <div style={{ minHeight: height }} className="flex items-center justify-center">
        <ErrorState message={error} {...(onRetry === undefined ? {} : { onRetry })} />
      </div>
    );
  }
  if (empty === true) {
    return (
      <div style={{ minHeight: height }} className="flex items-center justify-center">
        <EmptyState icon={BarChart3} title={emptyText ?? t('common.noData')} />
      </div>
    );
  }
  if (!ready) return <Skeleton height={height} />;
  return (
    <LoadedChartRenderer option={option} height={height} ariaLabel={ariaLabel} onEvents={onEvents} handleRef={handleRef} />
  );
}
