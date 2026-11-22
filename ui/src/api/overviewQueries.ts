import { useQuery } from '@tanstack/react-query';
import { useViewRange } from '../app/timeRange';
import { rangeKey, type TimeRange } from '../lib/timeRange';
import { getModuleCounts, getOverviewSummary, getTraffic, type TrafficParams } from './overview';
import type { ModuleCount } from './types/ModuleCount';

// Query hooks of the overview. Keys live under the session detail key, so invalidating a
// session refreshes its overview too.

export const overviewKeys = {
  summary: (id: string, range: TimeRange | null = null) => ['sessions', 'detail', id, 'summary', rangeKey(range)] as const,
  modules: (id: string, range: TimeRange | null = null) => ['sessions', 'detail', id, 'modules', rangeKey(range)] as const,
  traffic: (id: string, params: TrafficParams) => ['sessions', 'detail', id, 'traffic', params] as const,
};

/** `enabled`: false while the session is importing or failed (the routes answer 409). */
export function useOverviewSummary(id: string, enabled: boolean) {
  const range = useViewRange();
  return useQuery({
    queryKey: overviewKeys.summary(id, range),
    queryFn: ({ signal }) => getOverviewSummary(id, signal, range),
    enabled,
  });
}

/**
 * The module counters to show: those of the summary, with the `pending` ones (aggregated views
 * under a range) replaced by `/modules` once it answers. Asked only while some are pending; if it
 * fails, they fall back to their session count, labelled as such.
 */
export function useModuleCounts(id: string, summary: readonly ModuleCount[] | null): readonly ModuleCount[] | null {
  const range = useViewRange();
  const pending = summary?.some((m) => m.scope === 'pending') ?? false;
  const query = useQuery({
    queryKey: overviewKeys.modules(id, range),
    queryFn: ({ signal }) => getModuleCounts(id, signal, range),
    enabled: pending && range !== null,
  });
  if (summary === null || !pending) return summary;
  const ranged = new Map((query.data?.modules ?? []).map((m) => [m.id, m]));
  return summary.map((m) => {
    if (m.scope !== 'pending') return m;
    if (query.isError) return { ...m, scope: 'session' };
    return ranged.get(m.id) ?? m;
  });
}

export function useTraffic(id: string, params: TrafficParams, enabled: boolean) {
  return useQuery({
    queryKey: overviewKeys.traffic(id, params),
    queryFn: ({ signal }) => getTraffic(id, params, signal),
    enabled,
  });
}
