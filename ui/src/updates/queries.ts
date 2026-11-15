import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { checkUpdates, getUpdateDownload, getUpdates, startUpdateDownload } from '../api/updates';
import type { UpdateCheck } from '../api/types/UpdateCheck';
import type { UpdateDownload } from '../api/types/UpdateDownload';
import type { UpdateState } from '../api/types/UpdateState';

// Query hooks of the update check, shared by the banner and Settings > About: a check made in
// one place shows in the other.

export const updateKeys = {
  state: ['updates'] as const,
  download: ['updates', 'download'] as const,
};

/** Polling interval while the server checks or downloads. */
const POLL_MS = 500;

/**
 * Last result kept by the server. Read once (a local request, no network), then again every
 * 500 ms while a check runs (the startup one ends after the page loads).
 */
export function useUpdates() {
  return useQuery({
    queryKey: updateKeys.state,
    queryFn: ({ signal }) => getUpdates(signal),
    staleTime: Infinity,
    refetchInterval: (query) => (query.state.data?.checking === true ? POLL_MS : false),
  });
}

/** Click on "Check for updates": the result replaces the kept one. */
export function useCheckUpdates() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: () => checkUpdates(),
    onSuccess: (check: UpdateCheck) => {
      client.setQueryData<UpdateState>(updateKeys.state, (old) => (old === undefined ? old : { ...old, check }));
    },
  });
}

/** The running or last download, polled while it runs. `enabled`: only where downloads exist. */
export function useUpdateDownload(enabled: boolean) {
  return useQuery({
    queryKey: updateKeys.download,
    queryFn: ({ signal }) => getUpdateDownload(signal),
    enabled,
    staleTime: Infinity,
    refetchInterval: (query) => (query.state.data?.phase === 'downloading' ? POLL_MS : false),
  });
}

export function useStartDownload() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: ({ asset, path }: { asset: string; path: string }) => startUpdateDownload(asset, path),
    onSuccess: (download: UpdateDownload) => {
      client.setQueryData<UpdateDownload>(updateKeys.download, download);
    },
  });
}
