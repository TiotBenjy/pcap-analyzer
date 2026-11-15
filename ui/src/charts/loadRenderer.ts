import { useEffect, useSyncExternalStore } from 'react';
import type EChartsRenderer from './EChartsRenderer';

// ECharts is heavy: it lives in its own chunk (vite.config.ts manualChunks), loaded on demand.
// The renderer is loaded once, outside React: a chart whose data arrives first shows its
// skeleton until it is there, then renders it directly. `React.lazy` suspended instead, and React
// reveals suspended content at least 300 ms after its fallback appeared (fallback throttling):
// most of the Overview display time on a large session (P4.8, docs/PERFORMANCE.md).

export type ChartRenderer = typeof EChartsRenderer;

let renderer: ChartRenderer | null = null;
let failure: unknown = null;
let loading: Promise<void> | null = null;
const listeners = new Set<() => void>();

function notify(): void {
  listeners.forEach((l) => {
    l();
  });
}

/** Starts loading the chart renderer (idempotent; a failed load is retried on the next call). */
export function loadChartRenderer(): Promise<void> {
  loading ??= import('./EChartsRenderer').then(
    (m) => {
      renderer = m.default;
      failure = null;
      notify();
    },
    (e: unknown) => {
      failure = e;
      loading = null;
      notify();
    },
  );
  return loading;
}

/**
 * Loads the chart renderer when the browser is idle, so that the first chart of a session does
 * not wait for it (called when a session opens; most of its views draw charts).
 */
export function preloadChartRenderer(): () => void {
  if (renderer !== null) return () => undefined;
  if (typeof window.requestIdleCallback === 'function') {
    const id = window.requestIdleCallback(
      () => {
        void loadChartRenderer();
      },
      { timeout: 2000 },
    );
    return () => {
      window.cancelIdleCallback(id);
    };
  }
  const id = window.setTimeout(() => {
    void loadChartRenderer();
  }, 200);
  return () => {
    window.clearTimeout(id);
  };
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

const ready = () => renderer !== null;
const failed = () => failure;

/**
 * True once the chart renderer is loaded (loading starts on mount). A failed load is thrown to
 * the nearest error boundary, as a failed lazy component would be.
 */
export function useChartRendererReady(): boolean {
  const loaded = useSyncExternalStore(subscribe, ready, ready);
  const error = useSyncExternalStore(subscribe, failed, failed);
  useEffect(() => {
    if (!loaded) void loadChartRenderer();
  }, [loaded]);
  if (!loaded && error !== null) throw error;
  return loaded;
}

/** The chart renderer once loaded (see [`useChartRendererReady`]), `null` before. */
export function loadedChartRenderer(): ChartRenderer | null {
  return renderer;
}
