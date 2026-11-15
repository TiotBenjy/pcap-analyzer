import { apiGet, apiSend } from './client';
import type { Settings } from './types/Settings';
import type { SettingsUpdate } from './types/SettingsUpdate';

// Settings kept by the server (`<data>/settings.json`, ADR-025): online checks and dismissed
// notices. Display preferences (theme, language) stay in the webview storage (lib/storage.ts).

export function getSettings(signal?: AbortSignal): Promise<Settings> {
  return apiGet<Settings>('/settings', signal);
}

/** Changes the fields present in `update`; resolves to the new settings. */
export function updateSettings(update: SettingsUpdate): Promise<Settings> {
  return apiSend<Settings>('PUT', '/settings', update);
}

/** Hides the notice `id` until its key differs from `key`; resolves to the new settings. */
export function dismissNotice(id: string, key: string): Promise<Settings> {
  return apiSend<Settings>('PUT', `/settings/notices/${encodeURIComponent(id)}`, { key });
}
