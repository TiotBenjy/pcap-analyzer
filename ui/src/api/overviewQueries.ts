import { useQuery } from '@tanstack/react-query';
import { getOverviewSummary, getTraffic, type TrafficParams } from './overview';

// Query hooks of the overview. Keys live under the session detail key, so invalidating a
// session refreshes its overview too.

export const overviewKeys = {
  summary: (id: string) => ['sessions', 'detail', id, 'summary'] as const,
  traffic: (id: string, params: TrafficParams) => ['sessions', 'detail', id, 'traffic', params] as const,
};

/** `enabled`: false while the session is importing or failed (the routes answer 409). */
export function useOverviewSummary(id: string, enabled: boolean) {
  return useQuery({
    queryKey: overviewKeys.summary(id),
    queryFn: ({ signal }) => getOverviewSummary(id, signal),
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
