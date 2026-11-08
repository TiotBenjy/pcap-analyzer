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
  stats: (id: string) => ['sessions', 'detail', id, 'http', 'stats'] as const,
  list: (id: string, params: HttpListParams) => ['sessions', 'detail', id, 'http', 'list', params] as const,
  detail: (id: string, tid: number) => ['sessions', 'detail', id, 'http', 'tx', tid] as const,
  headerStats: (id: string) => ['sessions', 'detail', id, 'http', 'header-stats'] as const,
  headers: (id: string, params: HttpHeaderListParams) => ['sessions', 'detail', id, 'http', 'headers', params] as const,
};

/** `enabled`: false while the session is importing or failed (the routes answer 409). */
export function useHttpStats(id: string, enabled: boolean) {
  return useQuery({ queryKey: httpKeys.stats(id), queryFn: ({ signal }) => getHttpStats(id, signal), enabled });
}

export function useHttpTransactions(id: string, params: HttpListParams, enabled: boolean) {
  return useInfiniteQuery({
    queryKey: httpKeys.list(id, params),
    queryFn: ({ pageParam, signal }) =>
      listHttpTransactions(id, { ...params, limit: HTTP_PAGE_SIZE, cursor: pageParam }, signal),
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
  return useQuery({
    queryKey: httpKeys.headerStats(id),
    queryFn: ({ signal }) => getHttpHeaderStats(id, signal),
    enabled,
  });
}

export function useHttpHeaders(id: string, params: HttpHeaderListParams, enabled: boolean) {
  return useInfiniteQuery({
    queryKey: httpKeys.headers(id, params),
    queryFn: ({ pageParam, signal }) => listHttpHeaders(id, { ...params, limit: HTTP_PAGE_SIZE, cursor: pageParam }, signal),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
    placeholderData: keepPreviousData,
    enabled,
  });
}
