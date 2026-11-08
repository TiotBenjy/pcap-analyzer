import { keepPreviousData, useInfiniteQuery, useQuery } from '@tanstack/react-query';
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

// Keys live under the session detail key, so invalidating a session refreshes these too.
export const connectionKeys = {
  conversations: (id: string, f: ConversationFilters) => ['sessions', 'detail', id, 'conversations', f] as const,
  stats: (id: string) => ['sessions', 'detail', id, 'connection-stats'] as const,
  top: (id: string, n: TopSize, excludeDns: boolean) => ['sessions', 'detail', id, 'connection-top', n, excludeDns] as const,
  ports: (id: string, f: PortFilters) => ['sessions', 'detail', id, 'open-ports', f] as const,
  portStats: (id: string, categories: readonly AddressCategory[] | undefined) =>
    ['sessions', 'detail', id, 'open-port-stats', categories] as const,
};

/** `enabled`: false while the session is importing or failed (the routes answer 409). */
export function useConversations(id: string, filters: ConversationFilters, enabled: boolean) {
  return useInfiniteQuery({
    queryKey: connectionKeys.conversations(id, filters),
    queryFn: ({ pageParam, signal }) => listConversations(id, filters, pageParam, signal),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
    placeholderData: keepPreviousData,
    enabled,
  });
}

export function useConnectionStats(id: string, enabled: boolean) {
  return useQuery({
    queryKey: connectionKeys.stats(id),
    queryFn: ({ signal }) => getConnectionStats(id, signal),
    enabled,
  });
}

export function useConnectionTop(id: string, n: TopSize, excludeDns: boolean, enabled: boolean) {
  return useQuery({
    queryKey: connectionKeys.top(id, n, excludeDns),
    queryFn: ({ signal }) => getConnectionTop(id, n, excludeDns, signal),
    placeholderData: keepPreviousData,
    enabled,
  });
}

export function useOpenPorts(id: string, filters: PortFilters, enabled: boolean) {
  return useInfiniteQuery({
    queryKey: connectionKeys.ports(id, filters),
    queryFn: ({ pageParam, signal }) => listOpenPorts(id, filters, pageParam, signal),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
    placeholderData: keepPreviousData,
    enabled,
  });
}

export function useOpenPortStats(id: string, categories: readonly AddressCategory[] | undefined, enabled: boolean) {
  return useQuery({
    queryKey: connectionKeys.portStats(id, categories),
    queryFn: ({ signal }) => getOpenPortStats(id, categories, signal),
    placeholderData: keepPreviousData,
    enabled,
  });
}
