// Typed client for the sessions / import API (contract: crates/netsift-api/src/contract.rs, ADR-008).
//
// FROZEN SIGNATURES shared by the backend task (P2.1, which implements the bodies) and the
// Captures view (P2.3, which consumes them and mocks this module in its tests). Change a
// signature only by agreement.

import { apiGet, apiSend, apiSendEmpty, apiStream } from './client';
import type { AnomalyInfo } from './types/AnomalyInfo';
import type { BrowseResponse } from './types/BrowseResponse';
import type { ChunkInfo } from './types/ChunkInfo';
import type { ImportEvent } from './types/ImportEvent';
import type { ImportRequest } from './types/ImportRequest';
import type { ImportResponse } from './types/ImportResponse';
import type { Page } from './types/Page';
import type { RenameRequest } from './types/RenameRequest';
import type { ScanRequest } from './types/ScanRequest';
import type { ScanResponse } from './types/ScanResponse';
import type { SessionSummary } from './types/SessionSummary';

export interface PageParams {
  limit?: number;
  cursor?: string | null;
}

function pageQuery(params?: PageParams): string {
  const q = new URLSearchParams();
  if (params?.limit !== undefined) q.set('limit', String(params.limit));
  if (params?.cursor !== undefined && params.cursor !== null) q.set('cursor', params.cursor);
  const text = q.toString();
  return text === '' ? '' : `?${text}`;
}

function sessionPath(id: string): `/${string}` {
  return `/sessions/${encodeURIComponent(id)}`;
}

export function listSessions(params?: PageParams, signal?: AbortSignal): Promise<Page<SessionSummary>> {
  return apiGet(`/sessions${pageQuery(params)}`, signal);
}

export function getSession(id: string, signal?: AbortSignal): Promise<SessionSummary> {
  return apiGet(sessionPath(id), signal);
}

export function renameSession(id: string, name: string): Promise<SessionSummary> {
  const body: RenameRequest = { name };
  return apiSend('PATCH', sessionPath(id), body);
}

/** Deletes the session database and extracted objects, never the source captures. */
export function deleteSession(id: string): Promise<void> {
  return apiSendEmpty('DELETE', sessionPath(id));
}

/** Inventories a file or folder without importing it. */
export function scanImport(req: ScanRequest, signal?: AbortSignal): Promise<ScanResponse> {
  return apiSend('POST', '/sessions/import/scan', req, signal);
}

/** Starts an import in the background; follow it with `streamImportEvents`. */
export function startImport(req: ImportRequest): Promise<ImportResponse> {
  return apiSend('POST', '/sessions/import', req);
}

export function cancelImport(id: string): Promise<void> {
  return apiSendEmpty('POST', `${sessionPath(id)}/cancel`);
}

export function listChunks(id: string, params?: PageParams, signal?: AbortSignal): Promise<Page<ChunkInfo>> {
  return apiGet(`${sessionPath(id)}/chunks${pageQuery(params)}`, signal);
}

export function listAnomalies(
  id: string,
  params?: PageParams,
  signal?: AbortSignal,
): Promise<Page<AnomalyInfo>> {
  return apiGet(`${sessionPath(id)}/anomalies${pageQuery(params)}`, signal);
}

/** Dev web mode folder browser (allowed roots only). `path` omitted: first allowed root. */
export function browse(path?: string, signal?: AbortSignal): Promise<BrowseResponse> {
  const query = path === undefined || path === '' ? '' : `?${new URLSearchParams({ path }).toString()}`;
  return apiGet(`/fs/browse${query}`, signal);
}

const EVENT_TYPES = new Set(['progress', 'warning', 'done', 'failed']);

/**
 * Reads the import event stream (SSE over `fetch`, so the bearer token can be sent) and calls
 * `onEvent` for each event until `done` / `failed`, the end of the stream, or `signal` aborts.
 * Resolves when the stream ends; rejects with `ApiError` on HTTP or network errors.
 */
export function streamImportEvents(
  id: string,
  onEvent: (event: ImportEvent) => void,
  signal: AbortSignal,
): Promise<void> {
  return apiStream(
    `${sessionPath(id)}/events`,
    (message) => {
      let event: ImportEvent;
      try {
        event = JSON.parse(message.data) as ImportEvent;
      } catch {
        return true; // malformed data: skipped
      }
      if (!EVENT_TYPES.has(event.type)) return true;
      onEvent(event);
      return event.type !== 'done' && event.type !== 'failed';
    },
    signal,
  );
}
