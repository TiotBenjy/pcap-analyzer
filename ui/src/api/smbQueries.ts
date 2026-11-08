import { useQuery } from '@tanstack/react-query';
import { fetchAll } from './sessionQueries';
import { getSmbStats, listSmbAnnounces, listSmbAuth } from './smb';

// Query hooks of the SMB view, keyed under the session detail so a session refresh covers them.

export const smbKeys = {
  announces: (id: string) => ['sessions', 'detail', id, 'smb', 'announces'] as const,
  auth: (id: string) => ['sessions', 'detail', id, 'smb', 'auth'] as const,
  stats: (id: string) => ['sessions', 'detail', id, 'smb', 'stats'] as const,
};

/** `enabled`: false while the session is importing or failed (the routes answer 409). */
export function useSmbAnnounces(id: string, enabled: boolean) {
  return useQuery({
    queryKey: smbKeys.announces(id),
    queryFn: ({ signal }) => fetchAll((p) => listSmbAnnounces(id, p, signal)),
    enabled,
  });
}

export function useSmbAuth(id: string, enabled: boolean) {
  return useQuery({
    queryKey: smbKeys.auth(id),
    queryFn: ({ signal }) => fetchAll((p) => listSmbAuth(id, p, signal)),
    enabled,
  });
}

export function useSmbStats(id: string, enabled: boolean) {
  return useQuery({
    queryKey: smbKeys.stats(id),
    queryFn: ({ signal }) => getSmbStats(id, signal),
    enabled,
  });
}
