// Typed client of the Save PCAP routes (crates/netsift-api/src/exports.rs, ADR-021) and of the
// flows of a conversation (connections.rs). Query hooks: exportQueries.ts.

import { withRange, type TimeRange } from '../lib/timeRange';
import { ApiError, apiGet, apiSend, isDesktop } from './client';
import type { ExportJob } from './types/ExportJob';
import type { ExportRequest } from './types/ExportRequest';
import type { FlowInfo } from './types/FlowInfo';
import type { Page } from './types/Page';

/** API prefix of the web build (`client.ts`). */
const WEB_BASE = '/api/v1';

const sessionPath = (id: string): `/${string}` => `/sessions/${encodeURIComponent(id)}`;
const jobPath = (id: string): `/${string}` => `/exports/${encodeURIComponent(id)}`;

/** Flows listed per page in the flows dialog. */
export const FLOWS_PAGE_SIZE = 50;

/** Starts an export; the server checks the sources first (409 when one is missing or changed). */
export function startPcapExport(sessionId: string, request: ExportRequest): Promise<ExportJob> {
  return apiSend<ExportJob>('POST', `${sessionPath(sessionId)}/exports/pcap`, request);
}

/** Exports of a session known to the server, newest first. */
export function listExports(sessionId: string, signal?: AbortSignal): Promise<ExportJob[]> {
  return apiGet<ExportJob[]>(`${sessionPath(sessionId)}/exports`, signal);
}

/** Asks a running export to stop (its partial file is removed). */
export function cancelExport(jobId: string): Promise<ExportJob> {
  return apiSend<ExportJob>('POST', `${jobPath(jobId)}/cancel`);
}

export function listConversationFlows(
  sessionId: string,
  conversationId: string,
  cursor: string | null,
  signal?: AbortSignal,
  range: TimeRange | null = null,
): Promise<Page<FlowInfo>> {
  const q = new URLSearchParams({ limit: String(FLOWS_PAGE_SIZE) });
  if (cursor !== null) q.set('cursor', cursor);
  return apiGet(
    withRange(`${sessionPath(sessionId)}/connections/${encodeURIComponent(conversationId)}/flows?${q.toString()}`, range),
    signal,
  );
}

/** The failure of a job as an `ApiError`, so that `describeError` translates it. */
export function jobError(job: ExportJob): ApiError | null {
  const e = job.error;
  if (e === null) return null;
  return new ApiError(e.status, e.type, e.detail ?? e.title);
}

/**
 * Web mode only: same-origin URL of the file (the Vite proxy adds the token), downloaded by the
 * browser itself and streamed to disk without passing through page memory. The desktop app
 * opens the exports folder instead (its API needs the token in a header).
 */
export function exportFileUrl(jobId: string): string {
  return `${WEB_BASE}${jobPath(jobId)}/file`;
}

type Opener = (folder: string) => Promise<void>;
let openerOverride: Opener | undefined;

/** Desktop: opens the exports folder with the system file manager (opener plugin, scope ADR-012). */
export async function openExportFolder(folder: string): Promise<void> {
  if (openerOverride !== undefined) return openerOverride(folder);
  const { invoke } = await import('@tauri-apps/api/core');
  await invoke('plugin:opener|open_path', { path: folder });
}

/** Tests: replaces the folder opener (`undefined` restores it). */
export function setFolderOpener(opener: Opener | undefined): void {
  openerOverride = opener;
}

/** Desktop delivers by opening the folder, the web build by downloading the file. */
export function deliversByFolder(): boolean {
  return isDesktop();
}
