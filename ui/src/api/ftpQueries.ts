import { keepPreviousData, useInfiniteQuery, useQuery } from '@tanstack/react-query';
import { useViewRange } from '../app/timeRange';
import { rangeKey, type TimeRange } from '../lib/timeRange';
import { getFtpSession, getFtpStats, listFtpSessions, listFtpTransfers, type FtpSessionParams, type FtpTransferParams } from './ftp';

// Query hooks of the FTP view, keyed under the session detail so a session refresh covers them.
// The list and statistics routes apply the time range (ADR-030): it is the last element of their
// keys. The detail of a session does not depend on it.

/** Rows fetched per page of the session and transfer lists. */
export const FTP_PAGE_SIZE = 200;

export const ftpKeys = {
  stats: (id: string, range: TimeRange | null = null) => ['sessions', 'detail', id, 'ftp', 'stats', rangeKey(range)] as const,
  sessions: (id: string, params: FtpSessionParams, range: TimeRange | null = null) =>
    ['sessions', 'detail', id, 'ftp', 'sessions', params, rangeKey(range)] as const,
  session: (id: string, flow: string) => ['sessions', 'detail', id, 'ftp', 'session', flow] as const,
  transfers: (id: string, params: FtpTransferParams, range: TimeRange | null = null) =>
    ['sessions', 'detail', id, 'ftp', 'transfers', params, rangeKey(range)] as const,
};

/** `enabled`: false while the session is importing or failed (the routes answer 409). */
export function useFtpStats(id: string, enabled: boolean) {
  const range = useViewRange();
  return useQuery({ queryKey: ftpKeys.stats(id, range), queryFn: ({ signal }) => getFtpStats(id, signal, range), enabled });
}

export function useFtpSessions(id: string, params: FtpSessionParams, enabled: boolean) {
  const range = useViewRange();
  return useInfiniteQuery({
    queryKey: ftpKeys.sessions(id, params, range),
    queryFn: ({ pageParam, signal }) => listFtpSessions(id, { ...params, limit: FTP_PAGE_SIZE, cursor: pageParam }, signal, range),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
    placeholderData: keepPreviousData,
    enabled,
  });
}

/** Transcript and transfers of one session, fetched when its row is expanded. */
export function useFtpSession(id: string, flow: string, enabled: boolean) {
  return useQuery({ queryKey: ftpKeys.session(id, flow), queryFn: ({ signal }) => getFtpSession(id, flow, signal), enabled });
}

export function useFtpTransfers(id: string, params: FtpTransferParams, enabled: boolean) {
  const range = useViewRange();
  return useInfiniteQuery({
    queryKey: ftpKeys.transfers(id, params, range),
    queryFn: ({ pageParam, signal }) => listFtpTransfers(id, { ...params, limit: FTP_PAGE_SIZE, cursor: pageParam }, signal, range),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
    placeholderData: keepPreviousData,
    enabled,
  });
}
