import { keepPreviousData, useQuery } from '@tanstack/react-query';
import { getServers, type ServerFilters } from './servers';

// Query hook of the Servers view, keyed under the session detail so a session refresh covers it.

export const serverKeys = {
  list: (id: string, f: ServerFilters) => ['sessions', 'detail', id, 'servers', f] as const,
};

/** `enabled`: false while the session is importing or failed (the route answers 409). */
export function useServers(id: string, filters: ServerFilters, enabled: boolean) {
  return useQuery({
    queryKey: serverKeys.list(id, filters),
    queryFn: ({ signal }) => getServers(id, filters, signal),
    placeholderData: keepPreviousData,
    enabled,
  });
}
