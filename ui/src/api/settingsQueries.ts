import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { dismissNotice, getSettings, updateSettings } from './settings';
import type { Settings } from './types/Settings';
import type { SettingsUpdate } from './types/SettingsUpdate';

// Query hooks of the server settings, shared by Settings > Online and the notices.

export const settingsKeys = {
  all: ['settings'] as const,
};

/** `enabled`: false when nothing needs the settings yet (no active notice). */
export function useSettings(enabled = true) {
  return useQuery({
    queryKey: settingsKeys.all,
    queryFn: ({ signal }) => getSettings(signal),
    staleTime: 60_000,
    enabled,
  });
}

export function useUpdateSettings() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (update: SettingsUpdate) => updateSettings(update),
    onSuccess: (settings) => {
      client.setQueryData<Settings>(settingsKeys.all, settings);
    },
  });
}

export function useDismissNotice() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: ({ id, key }: { id: string; key: string }) => dismissNotice(id, key),
    onSuccess: (settings) => {
      client.setQueryData<Settings>(settingsKeys.all, settings);
    },
  });
}
