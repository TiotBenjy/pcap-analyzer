import { keepPreviousData, useInfiniteQuery, useQuery } from '@tanstack/react-query';
import { useViewRange } from '../app/timeRange';
import { rangeKey, type TimeRange } from '../lib/timeRange';
import { getEthernetStats, listMacPairs, listMacs, type MacFilters, type PairFilters } from './ethernet';

// Query hooks of the Ethernet view, keyed under the session detail so a session refresh covers them.

export const ethernetKeys = {
  stats: (id: string, range: TimeRange | null = null) => ['sessions', 'detail', id, 'ethernet', 'stats', rangeKey(range)] as const,
  macs: (id: string, f: MacFilters, range: TimeRange | null = null) =>
    ['sessions', 'detail', id, 'ethernet', 'macs', f, rangeKey(range)] as const,
  pairs: (id: string, f: PairFilters, range: TimeRange | null = null) =>
    ['sessions', 'detail', id, 'ethernet', 'pairs', f, rangeKey(range)] as const,
};

/** `enabled`: false while the session is importing or failed (the routes answer 409). */
export function useEthernetStats(id: string, enabled: boolean) {
  const range = useViewRange();
  return useQuery({
    queryKey: ethernetKeys.stats(id, range),
    queryFn: ({ signal }) => getEthernetStats(id, signal, range),
    placeholderData: keepPreviousData,
    enabled,
  });
}

export function useMacs(id: string, filters: MacFilters, enabled: boolean) {
  const range = useViewRange();
  return useInfiniteQuery({
    queryKey: ethernetKeys.macs(id, filters, range),
    queryFn: ({ pageParam, signal }) => listMacs(id, filters, pageParam, signal, range),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
    placeholderData: keepPreviousData,
    enabled,
  });
}

export function useMacPairs(id: string, filters: PairFilters, enabled: boolean) {
  const range = useViewRange();
  return useInfiniteQuery({
    queryKey: ethernetKeys.pairs(id, filters, range),
    queryFn: ({ pageParam, signal }) => listMacPairs(id, filters, pageParam, signal, range),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
    placeholderData: keepPreviousData,
    enabled,
  });
}
