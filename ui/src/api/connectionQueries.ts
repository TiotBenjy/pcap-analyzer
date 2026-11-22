import { keepPreviousData, useInfiniteQuery, useQuery } from '@tanstack/react-query';
import { useViewRange } from '../app/timeRange';
import { rangeKey, type TimeRange } from '../lib/timeRange';
import {
  type ConversationFilters,
  getConnectionStats,
  getConnectionTop,
  getOpenPortStats,
  listConversations,
  listOpenPorts,
  type PortFilters,
  type TopSize,
} from './connections';
import type { AddressCategory } from './types/AddressCategory';

// Query hooks of the Connections and Open Ports views.

// Keys live under the session detail key, so invalidating a session refreshes these too. The time
// range (`useViewRange`) is the last element of every key.
export const connectionKeys = {
  conversations: (id: string, f: ConversationFilters, range: TimeRange | null = null) =>
    ['sessions', 'detail', id, 'conversations', f, rangeKey(range)] as const,
  stats: (id: string, range: TimeRange | null = null) => ['sessions', 'detail', id, 'connection-stats', rangeKey(range)] as const,
  top: (id: string, n: TopSize, excludeDns: boolean, range: TimeRange | null = null) =>
    ['sessions', 'detail', id, 'connection-top', n, excludeDns, rangeKey(range)] as const,
  ports: (id: string, f: PortFilters, range: TimeRange | null = null) => ['sessions', 'detail', id, 'open-ports', f, rangeKey(range)] as const,
  portStats: (id: string, categories: readonly AddressCategory[] | undefined, range: TimeRange | null = null) =>
    ['sessions', 'detail', id, 'open-port-stats', categories, rangeKey(range)] as const,
};

/** `enabled`: false while the session is importing or failed (the routes answer 409). */
export function useConversations(id: string, filters: ConversationFilters, enabled: boolean) {
  const range = useViewRange();
  return useInfiniteQuery({
    queryKey: connectionKeys.conversations(id, filters, range),
    queryFn: ({ pageParam, signal }) => listConversations(id, filters, pageParam, signal, range),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
    placeholderData: keepPreviousData,
    enabled,
  });
}

export function useConnectionStats(id: string, enabled: boolean) {
  const range = useViewRange();
  return useQuery({
    queryKey: connectionKeys.stats(id, range),
    queryFn: ({ signal }) => getConnectionStats(id, signal, range),
    enabled,
  });
}

export function useConnectionTop(id: string, n: TopSize, excludeDns: boolean, enabled: boolean) {
  const range = useViewRange();
  return useQuery({
    queryKey: connectionKeys.top(id, n, excludeDns, range),
    queryFn: ({ signal }) => getConnectionTop(id, n, excludeDns, signal, range),
    placeholderData: keepPreviousData,
    enabled,
  });
}

export function useOpenPorts(id: string, filters: PortFilters, enabled: boolean) {
  const range = useViewRange();
  return useInfiniteQuery({
    queryKey: connectionKeys.ports(id, filters, range),
    queryFn: ({ pageParam, signal }) => listOpenPorts(id, filters, pageParam, signal, range),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
    placeholderData: keepPreviousData,
    enabled,
  });
}

export function useOpenPortStats(id: string, categories: readonly AddressCategory[] | undefined, enabled: boolean) {
  const range = useViewRange();
  return useQuery({
    queryKey: connectionKeys.portStats(id, categories, range),
    queryFn: ({ signal }) => getOpenPortStats(id, categories, signal, range),
    placeholderData: keepPreviousData,
    enabled,
  });
}
