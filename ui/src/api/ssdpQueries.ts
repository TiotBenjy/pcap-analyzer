import { keepPreviousData, useInfiniteQuery, useQuery } from '@tanstack/react-query';
import { useViewRange } from '../app/timeRange';
import { rangeKey, type TimeRange } from '../lib/timeRange';
import { getSsdpStats, listSsdpDevices, listSsdpMessages, type SsdpDeviceParams, type SsdpMessageParams } from './ssdp';

// Query hooks of the SSDP view, keyed under the session detail so a session refresh covers them.
// Every route applies the time range (ADR-030): it is the last element of each key.

/** Rows fetched per page of the device and message lists. */
export const SSDP_PAGE_SIZE = 200;

export const ssdpKeys = {
  stats: (id: string, range: TimeRange | null = null) => ['sessions', 'detail', id, 'ssdp', 'stats', rangeKey(range)] as const,
  devices: (id: string, params: SsdpDeviceParams, range: TimeRange | null = null) =>
    ['sessions', 'detail', id, 'ssdp', 'devices', params, rangeKey(range)] as const,
  messages: (id: string, params: SsdpMessageParams, range: TimeRange | null = null) =>
    ['sessions', 'detail', id, 'ssdp', 'messages', params, rangeKey(range)] as const,
};

/** `enabled`: false while the session is importing or failed (the routes answer 409). */
export function useSsdpStats(id: string, enabled: boolean) {
  const range = useViewRange();
  return useQuery({ queryKey: ssdpKeys.stats(id, range), queryFn: ({ signal }) => getSsdpStats(id, signal, range), enabled });
}

export function useSsdpDevices(id: string, params: SsdpDeviceParams, enabled: boolean) {
  const range = useViewRange();
  return useInfiniteQuery({
    queryKey: ssdpKeys.devices(id, params, range),
    queryFn: ({ pageParam, signal }) => listSsdpDevices(id, { ...params, limit: SSDP_PAGE_SIZE, cursor: pageParam }, signal, range),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
    placeholderData: keepPreviousData,
    enabled,
  });
}

export function useSsdpMessages(id: string, params: SsdpMessageParams, enabled: boolean) {
  const range = useViewRange();
  return useInfiniteQuery({
    queryKey: ssdpKeys.messages(id, params, range),
    queryFn: ({ pageParam, signal }) => listSsdpMessages(id, { ...params, limit: SSDP_PAGE_SIZE, cursor: pageParam }, signal, range),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
    placeholderData: keepPreviousData,
    enabled,
  });
}
