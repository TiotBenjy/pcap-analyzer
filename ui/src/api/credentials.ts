// Typed client of the Credentials routes (crates/netsift-api/src/credentials.rs, ADR-019).
// The list, stats and paths never carry a secret: the detail and the export do, on demand.

import { withRange, type TimeRange } from '../lib/timeRange';
import { apiFetch, apiGet } from './client';
import { attachmentName } from './tls';
import type { CredentialDetail } from './types/CredentialDetail';
import type { CredentialInfo } from './types/CredentialInfo';
import type { CredentialPaths } from './types/CredentialPaths';
import type { CredentialStats } from './types/CredentialStats';
import type { Page } from './types/Page';

export type SecretState = 'plaintext' | 'recoverable' | 'metadata-only';

export interface CredentialFilters {
  protocol?: string | null;
  state?: SecretState | null;
}

export interface CredentialListParams extends CredentialFilters {
  limit?: number;
  cursor?: string | null;
}

export interface CredentialExport extends CredentialFilters {
  format: 'csv' | 'hashcat';
  /** hashcat mode (required for `hashcat`: one mode per file). */
  mode?: number | null;
  /** Selected entries; every entry matching the filters when absent. */
  ids?: readonly string[];
  /** Time range of the list (ignored with `ids`). */
  range?: TimeRange | null;
}

/** Most ids sent by one export (`MAX_IDS` of the API). */
export const MAX_EXPORT_IDS = 500;
/** Most entries of one export (`MAX_EXPORT` of the store): beyond, the API refuses it. */
export const MAX_EXPORT = 10_000;

const sessionPath = (id: string): `/${string}` => `/sessions/${encodeURIComponent(id)}/credentials`;

function query(entries: Record<string, string | number | null | undefined>): string {
  const q = new URLSearchParams();
  for (const [key, value] of Object.entries(entries)) {
    if (value !== undefined && value !== null && value !== '') q.set(key, String(value));
  }
  const text = q.toString();
  return text === '' ? '' : `?${text}`;
}

export function listCredentials(id: string, params: CredentialListParams = {}, signal?: AbortSignal, range: TimeRange | null = null): Promise<Page<CredentialInfo>> {
  const q = query({ limit: params.limit, cursor: params.cursor, protocol: params.protocol, state: params.state });
  return apiGet(withRange(`${sessionPath(id)}${q}`, range), signal);
}

export function getCredentialStats(id: string, signal?: AbortSignal, range: TimeRange | null = null): Promise<CredentialStats> {
  return apiGet(withRange(`${sessionPath(id)}/stats`, range), signal);
}

export function getCredentialPaths(id: string, limit?: number, signal?: AbortSignal, range: TimeRange | null = null): Promise<CredentialPaths> {
  return apiGet(withRange(`${sessionPath(id)}/paths${query({ limit })}`, range), signal);
}

/** One entry with its secret and hashcat line (sensitive: render through `SecretValue`). */
export function getCredential(id: string, entry: string, signal?: AbortSignal): Promise<CredentialDetail> {
  return apiGet(`${sessionPath(id)}/${encodeURIComponent(entry)}`, signal);
}

/** URL of an export. Never truncates a selection: more than `MAX_EXPORT_IDS` ids is an error. */
export function exportPath(id: string, e: CredentialExport): `/${string}` {
  if (e.ids !== undefined && e.ids.length > MAX_EXPORT_IDS) {
    throw new RangeError(`at most ${MAX_EXPORT_IDS} entries per selection`);
  }
  const ids = e.ids?.join(',');
  const path: `/${string}` = `${sessionPath(id)}/export${query({ format: e.format, mode: e.mode, protocol: e.protocol, state: e.state, ids })}`;
  // A selection is exported as is; otherwise the filters of the list apply, range included.
  return ids === undefined ? withRange(path, e.range) : path;
}

/**
 * Downloads an export as a file (fetched with the token, saved through a temporary object URL,
 * never displayed). Resolves to the file name.
 */
export async function downloadCredentials(id: string, e: CredentialExport): Promise<string> {
  const res = await apiFetch(exportPath(id, e), { accept: '*/*' });
  const name = attachmentName(res.headers.get('Content-Disposition')) ?? (e.format === 'csv' ? 'credentials.csv' : 'credentials.txt');
  const url = URL.createObjectURL(await res.blob());
  try {
    const a = document.createElement('a');
    a.href = url;
    a.download = name;
    a.rel = 'noopener';
    document.body.append(a);
    a.click();
    a.remove();
  } finally {
    setTimeout(() => {
      URL.revokeObjectURL(url);
    }, 1000);
  }
  return name;
}
