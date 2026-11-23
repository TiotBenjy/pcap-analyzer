import { keepPreviousData, useInfiniteQuery, useQuery } from '@tanstack/react-query';
import { useViewRange } from '../app/timeRange';
import { rangeKey, type TimeRange } from '../lib/timeRange';
import { getTelnetSession, getTelnetStats, listTelnetSessions, type TelnetSessionParams } from './telnet';

// Query hooks of the Telnet view, keyed under the session detail so a session refresh covers them.
// The list and statistics apply the time range (ADR-030, last element of their keys); the detail
// of one session does not.

/** Rows fetched per page of the session list. */
export const TELNET_PAGE_SIZE = 200;

export const telnetKeys = {
  stats: (id: string, range: TimeRange | null = null) => ['sessions', 'detail', id, 'telnet', 'stats', rangeKey(range)] as const,
  sessions: (id: string, params: TelnetSessionParams, range: TimeRange | null = null) =>
    ['sessions', 'detail', id, 'telnet', 'sessions', params, rangeKey(range)] as const,
  session: (id: string, flow: number) => ['sessions', 'detail', id, 'telnet', 'session', flow] as const,
};

/** `enabled`: false while the session is importing or failed (the routes answer 409). */
export function useTelnetStats(id: string, enabled: boolean) {
  const range = useViewRange();
  return useQuery({ queryKey: telnetKeys.stats(id, range), queryFn: ({ signal }) => getTelnetStats(id, signal, range), enabled });
}

export function useTelnetSessions(id: string, params: TelnetSessionParams, enabled: boolean) {
  const range = useViewRange();
  return useInfiniteQuery({
    queryKey: telnetKeys.sessions(id, params, range),
    queryFn: ({ pageParam, signal }) => listTelnetSessions(id, { ...params, limit: TELNET_PAGE_SIZE, cursor: pageParam }, signal, range),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
    placeholderData: keepPreviousData,
    enabled,
  });
}

/** Transcript of one session, fetched when its row is unfolded. */
export function useTelnetSession(id: string, flow: number, enabled: boolean) {
  return useQuery({ queryKey: telnetKeys.session(id, flow), queryFn: ({ signal }) => getTelnetSession(id, flow, signal), enabled });
}
