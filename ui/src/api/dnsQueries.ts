import { useViewRange } from '../app/timeRange';
import { rangeKey, type TimeRange } from '../lib/timeRange';
import { useInfiniteQuery, useQuery } from '@tanstack/react-query';
import { type DnsFilter, getDnsMessages, getDnsPairs, getDnsServers, getDnsStats } from './dns';

// Query hooks of the DNS view, under the session detail key (invalidating a session refreshes
// them). `enabled`: false while the session is importing or failed (the routes answer 409).

/** Rows per page of the grouped table and of an expanded pair. */
export const PAIRS_PAGE = 50;
export const MESSAGES_PAGE = 50;
/** Servers plotted on the map (most queried first). */
export const MAP_SERVERS = 500;

export const dnsKeys = {
  all: (id: string) => ['sessions', 'detail', id, 'dns'] as const,
  stats: (id: string, range: TimeRange | null = null) => ['sessions', 'detail', id, 'dns', 'stats', rangeKey(range)] as const,
  pairs: (id: string, filter: DnsFilter, range: TimeRange | null = null) =>
    ['sessions', 'detail', id, 'dns', 'pairs', filter, rangeKey(range)] as const,
  messages: (id: string, pair: string, filter: DnsFilter, range: TimeRange | null = null) =>
    ['sessions', 'detail', id, 'dns', 'messages', pair, filter, rangeKey(range)] as const,
  servers: (id: string, range: TimeRange | null = null) => ['sessions', 'detail', id, 'dns', 'servers', rangeKey(range)] as const,
};

export function useDnsStats(id: string, enabled: boolean) {
  const range = useViewRange();
  return useQuery({
    queryKey: dnsKeys.stats(id, range),
    queryFn: ({ signal }) => getDnsStats(id, signal, range),
    enabled,
  });
}

export function useDnsPairs(id: string, filter: DnsFilter, enabled: boolean) {
  const range = useViewRange();
  return useInfiniteQuery({
    queryKey: dnsKeys.pairs(id, filter, range),
    queryFn: ({ signal, pageParam }) => getDnsPairs(id, { ...filter, limit: PAIRS_PAGE, cursor: pageParam }, signal, range),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
    enabled,
  });
}

export function useDnsMessages(id: string, pair: string, filter: DnsFilter, enabled: boolean) {
  const range = useViewRange();
  return useInfiniteQuery({
    queryKey: dnsKeys.messages(id, pair, filter, range),
    queryFn: ({ signal, pageParam }) =>
      getDnsMessages(id, { ...filter, pair, limit: MESSAGES_PAGE, cursor: pageParam }, signal, range),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
    enabled,
  });
}

export function useDnsServers(id: string, enabled: boolean) {
  const range = useViewRange();
  return useQuery({
    queryKey: dnsKeys.servers(id, range),
    queryFn: ({ signal }) => getDnsServers(id, { limit: MAP_SERVERS }, signal, range),
    enabled,
  });
}
