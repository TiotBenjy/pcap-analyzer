import { useQuery } from '@tanstack/react-query';
import { useViewRange } from '../app/timeRange';
import { rangeKey, type TimeRange } from '../lib/timeRange';
import { getOverviewSummary, getTraffic, type TrafficParams } from './overview';

// Query hooks of the overview. Keys live under the session detail key, so invalidating a
// session refreshes its overview too.

export const overviewKeys = {
  summary: (id: string, range: TimeRange | null = null) => ['sessions', 'detail', id, 'summary', rangeKey(range)] as const,
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

export function useTraffic(id: string, params: TrafficParams, enabled: boolean) {
  return useQuery({
    queryKey: overviewKeys.traffic(id, params),
    queryFn: ({ signal }) => getTraffic(id, params, signal),
    enabled,
  });
}
