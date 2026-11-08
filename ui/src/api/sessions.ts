// Typed client for the sessions / import API (contract: crates/netsift-api/src/contract.rs, ADR-008).
//
// FROZEN SIGNATURES shared by the backend task (P2.1, which implements the bodies) and the
// Captures view (P2.3, which consumes them and mocks this module in its tests). Change a
// signature only by agreement.

import { ApiError } from './client';
import type { AnomalyInfo } from './types/AnomalyInfo';
import type { BrowseResponse } from './types/BrowseResponse';
import type { ChunkInfo } from './types/ChunkInfo';
import type { ImportEvent } from './types/ImportEvent';
import type { ImportRequest } from './types/ImportRequest';
import type { ImportResponse } from './types/ImportResponse';
import type { Page } from './types/Page';
import type { ScanRequest } from './types/ScanRequest';
import type { ScanResponse } from './types/ScanResponse';
import type { SessionSummary } from './types/SessionSummary';

export interface PageParams {
  limit?: number;
  cursor?: string | null;
}

function notImplemented(): never {
  throw new ApiError(501, 'not_implemented', 'Implemented by task P2.1');
}

export function listSessions(_params?: PageParams, _signal?: AbortSignal): Promise<Page<SessionSummary>> {
  notImplemented();
}

export function getSession(_id: string, _signal?: AbortSignal): Promise<SessionSummary> {
  notImplemented();
}

export function renameSession(_id: string, _name: string): Promise<SessionSummary> {
  notImplemented();
}

/** Deletes the session database and extracted objects, never the source captures. */
export function deleteSession(_id: string): Promise<void> {
  notImplemented();
}

/** Inventories a file or folder without importing it. */
export function scanImport(_req: ScanRequest, _signal?: AbortSignal): Promise<ScanResponse> {
  notImplemented();
}

/** Starts an import in the background; follow it with `streamImportEvents`. */
export function startImport(_req: ImportRequest): Promise<ImportResponse> {
  notImplemented();
}

export function cancelImport(_id: string): Promise<void> {
  notImplemented();
}

export function listChunks(_id: string, _params?: PageParams, _signal?: AbortSignal): Promise<Page<ChunkInfo>> {
  notImplemented();
}

export function listAnomalies(
  _id: string,
  _params?: PageParams,
  _signal?: AbortSignal,
): Promise<Page<AnomalyInfo>> {
  notImplemented();
}

/** Dev web mode folder browser (allowed roots only). `path` omitted: first allowed root. */
export function browse(_path?: string, _signal?: AbortSignal): Promise<BrowseResponse> {
  notImplemented();
}

/**
 * Reads the import event stream (SSE over `fetch`, so the bearer token can be sent) and calls
 * `onEvent` for each event until `done` / `failed`, the end of the stream, or `signal` aborts.
 * Resolves when the stream ends; rejects with `ApiError` on HTTP or network errors.
 */
export function streamImportEvents(
  _id: string,
  _onEvent: (event: ImportEvent) => void,
  _signal: AbortSignal,
): Promise<void> {
  notImplemented();
}
