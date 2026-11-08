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
  stats: (id: string) => ['sessions', 'detail', id, 'dns', 'stats'] as const,
  pairs: (id: string, filter: DnsFilter) => ['sessions', 'detail', id, 'dns', 'pairs', filter] as const,
  messages: (id: string, pair: string, filter: DnsFilter) =>
    ['sessions', 'detail', id, 'dns', 'messages', pair, filter] as const,
  servers: (id: string) => ['sessions', 'detail', id, 'dns', 'servers'] as const,
};

export function useDnsStats(id: string, enabled: boolean) {
  return useQuery({
    queryKey: dnsKeys.stats(id),
    queryFn: ({ signal }) => getDnsStats(id, signal),
    enabled,
  });
}

export function useDnsPairs(id: string, filter: DnsFilter, enabled: boolean) {
  return useInfiniteQuery({
    queryKey: dnsKeys.pairs(id, filter),
    queryFn: ({ signal, pageParam }) => getDnsPairs(id, { ...filter, limit: PAIRS_PAGE, cursor: pageParam }, signal),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
    enabled,
  });
}

export function useDnsMessages(id: string, pair: string, filter: DnsFilter, enabled: boolean) {
  return useInfiniteQuery({
    queryKey: dnsKeys.messages(id, pair, filter),
    queryFn: ({ signal, pageParam }) =>
      getDnsMessages(id, { ...filter, pair, limit: MESSAGES_PAGE, cursor: pageParam }, signal),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
    enabled,
  });
}

export function useDnsServers(id: string, enabled: boolean) {
  return useQuery({
    queryKey: dnsKeys.servers(id),
    queryFn: ({ signal }) => getDnsServers(id, { limit: MAP_SERVERS }, signal),
    enabled,
  });
}
