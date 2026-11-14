import { keepPreviousData, useQuery } from '@tanstack/react-query';
import { type GraphParams, getNetworkGraph, getNetworkNode } from './network';

// Query hooks of the Network view. Keys live under the session detail key, so invalidating a
// session refreshes these too.
export const networkKeys = {
  graph: (id: string, p: GraphParams) => ['sessions', 'detail', id, 'network-graph', p] as const,
  node: (id: string, ip: string) => ['sessions', 'detail', id, 'network-node', ip] as const,
};

/** `enabled`: false while the session is importing or failed (the routes answer 409). */
export function useNetworkGraph(id: string, params: GraphParams, enabled: boolean) {
  return useQuery({
    queryKey: networkKeys.graph(id, params),
    queryFn: ({ signal }) => getNetworkGraph(id, params, signal),
    placeholderData: keepPreviousData,
    enabled,
  });
}

/** Detail of a host node; `ip` null when no host is selected. */
export function useNetworkNode(id: string, ip: string | null) {
  return useQuery({
    queryKey: networkKeys.node(id, ip ?? ''),
    queryFn: ({ signal }) => getNetworkNode(id, ip ?? '', signal),
    enabled: ip !== null,
  });
}
