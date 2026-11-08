import type { EChartsCoreOption } from 'echarts/core';
import { BarChart3 } from 'lucide-react';
import { lazy, Suspense } from 'react';
import type { ChartEvents } from '../charts/EChartsRenderer';
import { useTranslation } from 'react-i18next';
import { EmptyState } from './EmptyState';
import { ErrorState } from './ErrorState';
import { Skeleton } from './Skeleton';

// ECharts is heavy: it is loaded on demand in its own chunk (see vite.config.ts manualChunks).
const EChartsRenderer = lazy(() => import('../charts/EChartsRenderer'));

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
}

/**
 * The only way views draw charts: SVG renderer, shared palette, theme-aware text colors,
 * ResizeObserver, and the loading / empty / error states.
 */
export function Chart({ option, height, ariaLabel, loading, error, onRetry, empty, emptyText, onEvents }: ChartProps) {
  const { t } = useTranslation();
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
  return (
    <Suspense fallback={<Skeleton height={height} />}>
      <EChartsRenderer option={option} height={height} ariaLabel={ariaLabel} onEvents={onEvents} />
    </Suspense>
  );
}
