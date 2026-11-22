import { useViewRange } from '../app/timeRange';
import { rangeKey, type TimeRange } from '../lib/timeRange';
import { useQuery } from '@tanstack/react-query';
import { fetchAll } from './sessionQueries';
import { getSmbStats, listSmbAnnounces, listSmbAuth } from './smb';

// Query hooks of the SMB view, keyed under the session detail so a session refresh covers them.

export const smbKeys = {
  announces: (id: string, range: TimeRange | null = null) => ['sessions', 'detail', id, 'smb', 'announces', rangeKey(range)] as const,
  auth: (id: string, range: TimeRange | null = null) => ['sessions', 'detail', id, 'smb', 'auth', rangeKey(range)] as const,
  stats: (id: string, range: TimeRange | null = null) => ['sessions', 'detail', id, 'smb', 'stats', rangeKey(range)] as const,
};

/** `enabled`: false while the session is importing or failed (the routes answer 409). */
export function useSmbAnnounces(id: string, enabled: boolean) {
  const range = useViewRange();
  return useQuery({
    queryKey: smbKeys.announces(id, range),
    queryFn: ({ signal }) => fetchAll((p) => listSmbAnnounces(id, p, signal, range)),
    enabled,
  });
}

export function useSmbAuth(id: string, enabled: boolean) {
  const range = useViewRange();
  return useQuery({
    queryKey: smbKeys.auth(id, range),
    queryFn: ({ signal }) => fetchAll((p) => listSmbAuth(id, p, signal, range)),
    enabled,
  });
}

export function useSmbStats(id: string, enabled: boolean) {
  const range = useViewRange();
  return useQuery({
    queryKey: smbKeys.stats(id, range),
    queryFn: ({ signal }) => getSmbStats(id, signal, range),
    enabled,
  });
}
