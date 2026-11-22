import { keepPreviousData, useQuery } from '@tanstack/react-query';
import { useViewRange } from '../app/timeRange';
import { rangeKey, type TimeRange } from '../lib/timeRange';
import {
  type ArpBindingFilters,
  type ArpMessageFilters,
  getArpConflicts,
  getArpStats,
  listArpBindings,
  listArpMessages,
} from './arp';
import { fetchAll } from './sessionQueries';

// Query hooks of the ARP view, under the session detail key (invalidated with the session).

/** Rows loaded in the tables (the view tells when the list is cut). */
export const ARP_LIST_LIMIT = 5000;

export const arpKeys = {
  stats: (id: string, range: TimeRange | null = null) => ['sessions', 'detail', id, 'arp', 'stats', rangeKey(range)] as const,
  conflicts: (id: string, range: TimeRange | null = null) => ['sessions', 'detail', id, 'arp', 'conflicts', rangeKey(range)] as const,
  messages: (id: string, filters: ArpMessageFilters, range: TimeRange | null = null) =>
    ['sessions', 'detail', id, 'arp', 'messages', filters, rangeKey(range)] as const,
  bindings: (id: string, filters: ArpBindingFilters, range: TimeRange | null = null) =>
    ['sessions', 'detail', id, 'arp', 'bindings', filters, rangeKey(range)] as const,
};

/** `enabled`: false while the session is importing or failed (the routes answer 409). */
export function useArpStats(id: string, enabled: boolean) {
  const range = useViewRange();
  return useQuery({ queryKey: arpKeys.stats(id, range), queryFn: ({ signal }) => getArpStats(id, signal, range), enabled });
}

export function useArpConflicts(id: string, enabled: boolean) {
  const range = useViewRange();
  return useQuery({ queryKey: arpKeys.conflicts(id, range), queryFn: ({ signal }) => getArpConflicts(id, signal, range), enabled });
}

export function useArpMessages(id: string, filters: ArpMessageFilters, enabled: boolean) {
  const range = useViewRange();
  return useQuery({
    queryKey: arpKeys.messages(id, filters, range),
    queryFn: ({ signal }) => fetchAll((p) => listArpMessages(id, filters, p, signal, range), ARP_LIST_LIMIT),
    enabled,
    placeholderData: keepPreviousData,
  });
}

export function useArpBindings(id: string, filters: ArpBindingFilters, enabled: boolean) {
  const range = useViewRange();
  return useQuery({
    queryKey: arpKeys.bindings(id, filters, range),
    queryFn: ({ signal }) => fetchAll((p) => listArpBindings(id, filters, p, signal, range), ARP_LIST_LIMIT),
    enabled,
    placeholderData: keepPreviousData,
  });
}
