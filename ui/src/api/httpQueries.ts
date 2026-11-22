import { useViewRange } from '../app/timeRange';
import { rangeKey, type TimeRange } from '../lib/timeRange';
import { keepPreviousData, useInfiniteQuery, useQuery } from '@tanstack/react-query';
import {
  getHttpHeaderStats,
  getHttpStats,
  getHttpTransaction,
  type HttpHeaderListParams,
  type HttpListParams,
  listHttpHeaders,
  listHttpTransactions,
} from './http';

// Query hooks of the HTTP views. Keys live under the session detail key.

/** Rows fetched per page of the transaction lists. */
export const HTTP_PAGE_SIZE = 200;

export const httpKeys = {
  stats: (id: string, range: TimeRange | null = null) => ['sessions', 'detail', id, 'http', 'stats', rangeKey(range)] as const,
  list: (id: string, params: HttpListParams, range: TimeRange | null = null) => ['sessions', 'detail', id, 'http', 'list', params, rangeKey(range)] as const,
  detail: (id: string, tid: number) => ['sessions', 'detail', id, 'http', 'tx', tid] as const,
  headerStats: (id: string, range: TimeRange | null = null) => ['sessions', 'detail', id, 'http', 'header-stats', rangeKey(range)] as const,
  headers: (id: string, params: HttpHeaderListParams, range: TimeRange | null = null) => ['sessions', 'detail', id, 'http', 'headers', params, rangeKey(range)] as const,
};

/** `enabled`: false while the session is importing or failed (the routes answer 409). */
export function useHttpStats(id: string, enabled: boolean) {
  const range = useViewRange();
  return useQuery({ queryKey: httpKeys.stats(id, range), queryFn: ({ signal }) => getHttpStats(id, signal, range), enabled });
}

export function useHttpTransactions(id: string, params: HttpListParams, enabled: boolean) {
  const range = useViewRange();
  return useInfiniteQuery({
    queryKey: httpKeys.list(id, params, range),
    queryFn: ({ pageParam, signal }) =>
      listHttpTransactions(id, { ...params, limit: HTTP_PAGE_SIZE, cursor: pageParam }, signal, range),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
    placeholderData: keepPreviousData,
    enabled,
  });
}

export function useHttpTransaction(id: string, tid: number, enabled: boolean) {
  return useQuery({
    queryKey: httpKeys.detail(id, tid),
    queryFn: ({ signal }) => getHttpTransaction(id, tid, signal),
    enabled,
  });
}

export function useHttpHeaderStats(id: string, enabled: boolean) {
  const range = useViewRange();
  return useQuery({
    queryKey: httpKeys.headerStats(id, range),
    queryFn: ({ signal }) => getHttpHeaderStats(id, signal, range),
    enabled,
  });
}

export function useHttpHeaders(id: string, params: HttpHeaderListParams, enabled: boolean) {
  const range = useViewRange();
  return useInfiniteQuery({
    queryKey: httpKeys.headers(id, params, range),
    queryFn: ({ pageParam, signal }) => listHttpHeaders(id, { ...params, limit: HTTP_PAGE_SIZE, cursor: pageParam }, signal, range),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
    placeholderData: keepPreviousData,
    enabled,
  });
}
