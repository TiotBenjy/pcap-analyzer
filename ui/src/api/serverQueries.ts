import { keepPreviousData, useQuery } from '@tanstack/react-query';
import { useViewRange } from '../app/timeRange';
import { rangeKey, type TimeRange } from '../lib/timeRange';
import { getServers, type ServerFilters } from './servers';

// Query hook of the Servers view, keyed under the session detail so a session refresh covers it.

export const serverKeys = {
  list: (id: string, f: ServerFilters, range: TimeRange | null = null) => ['sessions', 'detail', id, 'servers', f, rangeKey(range)] as const,
};

/** `enabled`: false while the session is importing or failed (the route answers 409). */
export function useServers(id: string, filters: ServerFilters, enabled: boolean) {
  const range = useViewRange();
  return useQuery({
    queryKey: serverKeys.list(id, filters, range),
    queryFn: ({ signal }) => getServers(id, filters, signal, range),
    placeholderData: keepPreviousData,
    enabled,
  });
}
