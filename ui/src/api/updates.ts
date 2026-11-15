import { apiGet, apiSend } from './client';
import type { UpdateCheck } from './types/UpdateCheck';
import type { UpdateDownload } from './types/UpdateDownload';
import type { UpdateState } from './types/UpdateState';

// New versions from the GitHub releases (ADR-025). The backend makes every request: the webview
// never contacts any outside host.

/** Last check result kept by the server (startup check or a previous click). */
export function getUpdates(signal?: AbortSignal): Promise<UpdateState> {
  return apiGet<UpdateState>('/updates', signal);
}

/** Checks now (button "Check for updates"). */
export function checkUpdates(): Promise<UpdateCheck> {
  return apiSend<UpdateCheck>('POST', '/updates/check');
}

/** Downloads `asset` (an installer of the checked release) to `path` (desktop only). */
export function startUpdateDownload(asset: string, path: string): Promise<UpdateDownload> {
  return apiSend<UpdateDownload>('POST', '/updates/download', { asset, path });
}

/** The running or last download. */
export function getUpdateDownload(signal?: AbortSignal): Promise<UpdateDownload> {
  return apiGet<UpdateDownload>('/updates/download', signal);
}
