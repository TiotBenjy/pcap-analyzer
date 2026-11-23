import { keepPreviousData, useInfiniteQuery, useQuery } from '@tanstack/react-query';
import { useViewRange } from '../app/timeRange';
import { rangeKey, type TimeRange } from '../lib/timeRange';
import { getSipStats, listSipDialogs, listSipMessages, listSipScanners, type SipDialogParams, type SipMessageParams } from './sip';

// Query hooks of the SIP view, keyed under the session detail so a session refresh covers them.
// Every route applies the time range (ADR-030): it is the last element of each key.

/** Rows fetched per page of the dialog and message lists. */
export const SIP_PAGE_SIZE = 200;

export const sipKeys = {
  stats: (id: string, range: TimeRange | null = null) => ['sessions', 'detail', id, 'sip', 'stats', rangeKey(range)] as const,
  scanners: (id: string, range: TimeRange | null = null) => ['sessions', 'detail', id, 'sip', 'scanners', rangeKey(range)] as const,
  dialogs: (id: string, params: SipDialogParams, range: TimeRange | null = null) =>
    ['sessions', 'detail', id, 'sip', 'dialogs', params, rangeKey(range)] as const,
  messages: (id: string, params: SipMessageParams, range: TimeRange | null = null) =>
    ['sessions', 'detail', id, 'sip', 'messages', params, rangeKey(range)] as const,
};

/** `enabled`: false while the session is importing or failed (the routes answer 409). */
export function useSipStats(id: string, enabled: boolean) {
  const range = useViewRange();
  return useQuery({ queryKey: sipKeys.stats(id, range), queryFn: ({ signal }) => getSipStats(id, signal, range), enabled });
}

export function useSipScanners(id: string, enabled: boolean) {
  const range = useViewRange();
  return useQuery({ queryKey: sipKeys.scanners(id, range), queryFn: ({ signal }) => listSipScanners(id, signal, range), enabled });
}

export function useSipDialogs(id: string, params: SipDialogParams, enabled: boolean) {
  const range = useViewRange();
  return useInfiniteQuery({
    queryKey: sipKeys.dialogs(id, params, range),
    queryFn: ({ pageParam, signal }) => listSipDialogs(id, { ...params, limit: SIP_PAGE_SIZE, cursor: pageParam }, signal, range),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
    placeholderData: keepPreviousData,
    enabled,
  });
}

export function useSipMessages(id: string, params: SipMessageParams, enabled: boolean) {
  const range = useViewRange();
  return useInfiniteQuery({
    queryKey: sipKeys.messages(id, params, range),
    queryFn: ({ pageParam, signal }) => listSipMessages(id, { ...params, limit: SIP_PAGE_SIZE, cursor: pageParam }, signal, range),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
    placeholderData: keepPreviousData,
    enabled,
  });
}
