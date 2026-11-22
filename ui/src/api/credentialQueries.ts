import { useViewRange } from '../app/timeRange';
import { rangeKey, type TimeRange } from '../lib/timeRange';
import { keepPreviousData, useInfiniteQuery, useQuery } from '@tanstack/react-query';
import { type CredentialFilters, getCredential, getCredentialPaths, getCredentialStats, listCredentials } from './credentials';

// Query hooks of the Credentials view, keyed under the session detail so a session refresh covers them.

/** Cards loaded per page of the list. */
export const CREDENTIALS_PAGE_SIZE = 50;
/** Paths of the aggregated client -> protocol -> server list. */
export const CREDENTIAL_PATHS = 12;

export const credentialKeys = {
  list: (id: string, f: CredentialFilters, range: TimeRange | null = null) => ['sessions', 'detail', id, 'credentials', 'list', f, rangeKey(range)] as const,
  stats: (id: string, range: TimeRange | null = null) => ['sessions', 'detail', id, 'credentials', 'stats', rangeKey(range)] as const,
  paths: (id: string, range: TimeRange | null = null) => ['sessions', 'detail', id, 'credentials', 'paths', rangeKey(range)] as const,
  detail: (id: string, entry: string) => ['sessions', 'detail', id, 'credentials', 'entry', entry] as const,
};

/** `enabled`: false while the session is importing or failed (the routes answer 409). */
export function useCredentialStats(id: string, enabled: boolean) {
  const range = useViewRange();
  return useQuery({ queryKey: credentialKeys.stats(id, range), queryFn: ({ signal }) => getCredentialStats(id, signal, range), enabled });
}

export function useCredentialPaths(id: string, enabled: boolean) {
  const range = useViewRange();
  return useQuery({
    queryKey: credentialKeys.paths(id, range),
    queryFn: ({ signal }) => getCredentialPaths(id, CREDENTIAL_PATHS, signal, range),
    enabled,
  });
}

export function useCredentials(id: string, filters: CredentialFilters, enabled: boolean) {
  const range = useViewRange();
  return useInfiniteQuery({
    queryKey: credentialKeys.list(id, filters, range),
    queryFn: ({ pageParam, signal }) =>
      listCredentials(id, { ...filters, limit: CREDENTIALS_PAGE_SIZE, cursor: pageParam }, signal, range),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
    placeholderData: keepPreviousData,
    enabled,
  });
}

/** Secret of one entry, fetched when its card is expanded; never kept once the card is gone. */
export function useCredential(id: string, entry: string, enabled: boolean) {
  return useQuery({
    queryKey: credentialKeys.detail(id, entry),
    queryFn: ({ signal }) => getCredential(id, entry, signal),
    enabled,
    gcTime: 0,
    staleTime: 0,
  });
}
