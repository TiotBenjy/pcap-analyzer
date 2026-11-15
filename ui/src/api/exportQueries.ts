import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { cancelExport, listConversationFlows, listExports, startPcapExport } from './exports';
import type { ExportRequest } from './types/ExportRequest';

// Query hooks of the Save PCAP export and of the flows of a conversation.

/** Polling interval of the exports list while one runs. */
export const EXPORT_POLL_MS = 500;

export const exportKeys = {
  list: (id: string) => ['sessions', 'detail', id, 'exports'] as const,
  flows: (id: string, conversation: string) => ['sessions', 'detail', id, 'conversation-flows', conversation] as const,
};

/** Exports of the session, polled while one of them runs. */
export function useSessionExports(sessionId: string, enabled: boolean) {
  return useQuery({
    queryKey: exportKeys.list(sessionId),
    queryFn: ({ signal }) => listExports(sessionId, signal),
    refetchInterval: (q) => (q.state.data?.some((j) => j.state === 'running') === true ? EXPORT_POLL_MS : false),
    enabled,
  });
}

export function useStartExport(sessionId: string) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (request: ExportRequest) => startPcapExport(sessionId, request),
    onSuccess: () => client.invalidateQueries({ queryKey: exportKeys.list(sessionId) }),
  });
}

export function useCancelExport(sessionId: string) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (jobId: string) => cancelExport(jobId),
    onSettled: () => client.invalidateQueries({ queryKey: exportKeys.list(sessionId) }),
  });
}

export function useConversationFlows(sessionId: string, conversationId: string, enabled: boolean) {
  return useInfiniteQuery({
    queryKey: exportKeys.flows(sessionId, conversationId),
    queryFn: ({ pageParam, signal }) => listConversationFlows(sessionId, conversationId, pageParam, signal),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
    enabled,
  });
}
