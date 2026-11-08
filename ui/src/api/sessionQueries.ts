import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import type { PageParams } from './sessions';
import { deleteSession, getSession, listAnomalies, listChunks, listSessions, renameSession } from './sessions';
import type { Page } from './types/Page';
import type { SessionSummary } from './types/SessionSummary';

// Query hooks of the sessions API (shared by Captures, Sources and the session-scoped views).

export const sessionKeys = {
  all: ['sessions'] as const,
  list: () => ['sessions', 'list'] as const,
  detail: (id: string) => ['sessions', 'detail', id] as const,
  chunks: (id: string) => ['sessions', 'detail', id, 'chunks'] as const,
  anomalies: (id: string) => ['sessions', 'detail', id, 'anomalies'] as const,
};

/** Upper bound of rows gathered by `fetchAll` (the UI never holds unbounded lists). */
export const FETCH_ALL_LIMIT = 20_000;
const PAGE_SIZE = 1000;

/** Follows keyset cursors until the last page or `max` rows. `truncated` tells if rows were left. */
export async function fetchAll<T>(
  fetchPage: (params: PageParams) => Promise<Page<T>>,
  max: number = FETCH_ALL_LIMIT,
): Promise<{ items: T[]; truncated: boolean }> {
  const items: T[] = [];
  let cursor: string | null = null;
  for (;;) {
    const page: Page<T> = await fetchPage({ limit: PAGE_SIZE, cursor });
    items.push(...page.items);
    cursor = page.next_cursor;
    if (cursor === null) return { items, truncated: false };
    if (items.length >= max) return { items: items.slice(0, max), truncated: true };
  }
}

export function useSessions() {
  return useQuery({
    queryKey: sessionKeys.list(),
    queryFn: async ({ signal }) => (await fetchAll((p) => listSessions(p, signal), 5000)).items,
    // Keep the list fresh while an import runs (state, packets and sizes change).
    refetchInterval: (q) => (q.state.data?.some((s) => s.state === 'importing') === true ? 3000 : false),
  });
}

export function useSession(id: string) {
  return useQuery({
    queryKey: sessionKeys.detail(id),
    queryFn: ({ signal }) => getSession(id, signal),
    refetchInterval: (q) => (q.state.data?.state === 'importing' ? 3000 : false),
  });
}

export function useChunks(id: string) {
  return useQuery({
    queryKey: sessionKeys.chunks(id),
    queryFn: ({ signal }) => fetchAll((p) => listChunks(id, p, signal)),
  });
}

export function useAnomalies(id: string) {
  return useQuery({
    queryKey: sessionKeys.anomalies(id),
    queryFn: ({ signal }) => fetchAll((p) => listAnomalies(id, p, signal)),
  });
}

export function useRenameSession() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, name }: { id: string; name: string }) => renameSession(id, name),
    onSuccess: (updated: SessionSummary) => {
      qc.setQueryData(sessionKeys.detail(updated.id), updated);
      qc.setQueryData<SessionSummary[]>(sessionKeys.list(), (old) =>
        old?.map((s) => (s.id === updated.id ? updated : s)),
      );
    },
  });
}

export function useDeleteSession() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => deleteSession(id),
    onSuccess: (_void, id) => {
      qc.setQueryData<SessionSummary[]>(sessionKeys.list(), (old) => old?.filter((s) => s.id !== id));
      qc.removeQueries({ queryKey: sessionKeys.detail(id) });
    },
  });
}
