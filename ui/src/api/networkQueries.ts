import { keepPreviousData, useQuery } from '@tanstack/react-query';
import { useViewRange } from '../app/timeRange';
import { rangeKey, type TimeRange } from '../lib/timeRange';
import { type GraphParams, getNetworkGraph, getNetworkNode } from './network';

// Query hooks of the Network view. Keys live under the session detail key, so invalidating a
// session refreshes these too.
export const networkKeys = {
  graph: (id: string, p: GraphParams, range: TimeRange | null = null) => ['sessions', 'detail', id, 'network-graph', p, rangeKey(range)] as const,
  node: (id: string, ip: string, range: TimeRange | null = null) => ['sessions', 'detail', id, 'network-node', ip, rangeKey(range)] as const,
};

/** `enabled`: false while the session is importing or failed (the routes answer 409). */
export function useNetworkGraph(id: string, params: GraphParams, enabled: boolean) {
  const range = useViewRange();
  return useQuery({
    queryKey: networkKeys.graph(id, params, range),
    queryFn: ({ signal }) => getNetworkGraph(id, params, signal, range),
    placeholderData: keepPreviousData,
    enabled,
  });
}

/** Detail of a host node; `ip` null when no host is selected. */
export function useNetworkNode(id: string, ip: string | null) {
  const range = useViewRange();
  return useQuery({
    queryKey: networkKeys.node(id, ip ?? '', range),
    queryFn: ({ signal }) => getNetworkNode(id, ip ?? '', signal, range),
    enabled: ip !== null,
  });
}
