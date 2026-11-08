// Typed client of the TLS routes (crates/netsift-api/src/tls/mod.rs).

import { apiFetch, apiGet } from './client';
import type { PageParams } from './sessions';
import type { Page } from './types/Page';
import type { TlsCertificateItem } from './types/TlsCertificateItem';
import type { TlsSessionDetail } from './types/TlsSessionDetail';
import type { TlsSessionItem } from './types/TlsSessionItem';
import type { TlsStats } from './types/TlsStats';

/** Server-side filters of the sessions list. */
export interface TlsSessionFilters {
  /** Negotiated version (IANA value, 771 = TLS 1.2). */
  version?: number | undefined;
  /** Negotiated cipher suite. */
  suite?: number | undefined;
  /** Substring of the SNI or of the server address. */
  q?: string | undefined;
  weak?: boolean | undefined;
  certIssues?: boolean | undefined;
}

export interface TlsCertificateFilters {
  q?: string | undefined;
  problems?: boolean | undefined;
}

const tlsPath = (id: string): `/${string}` => `/sessions/${encodeURIComponent(id)}/tls`;

function query(entries: Record<string, string | number | boolean | null | undefined>): string {
  const q = new URLSearchParams();
  for (const [key, value] of Object.entries(entries)) {
    if (value === undefined || value === null || value === false || value === '') continue;
    q.set(key, String(value));
  }
  const text = q.toString();
  return text === '' ? '' : `?${text}`;
}

export function getTlsStats(id: string, signal?: AbortSignal): Promise<TlsStats> {
  return apiGet(`${tlsPath(id)}/stats`, signal);
}

export function listTlsSessions(
  id: string,
  filters: TlsSessionFilters,
  params: PageParams = {},
  signal?: AbortSignal,
): Promise<Page<TlsSessionItem>> {
  const q = query({
    limit: params.limit,
    cursor: params.cursor,
    order: 'asc',
    version: filters.version,
    suite: filters.suite,
    q: filters.q?.trim(),
    weak: filters.weak,
    cert_issues: filters.certIssues,
  });
  return apiGet(`${tlsPath(id)}/sessions${q}`, signal);
}

export function getTlsSession(id: string, flow: string, signal?: AbortSignal): Promise<TlsSessionDetail> {
  return apiGet(`${tlsPath(id)}/sessions/${encodeURIComponent(flow)}`, signal);
}

export function listTlsCertificates(
  id: string,
  filters: TlsCertificateFilters,
  params: PageParams = {},
  signal?: AbortSignal,
): Promise<Page<TlsCertificateItem>> {
  const q = query({ limit: params.limit, cursor: params.cursor, q: filters.q?.trim(), problems: filters.problems });
  return apiGet(`${tlsPath(id)}/certificates${q}`, signal);
}

/** Path of a certificate file (`der` or `pem`). */
export function certificateFilePath(id: string, sha256: string, format: 'der' | 'pem'): `/${string}` {
  return `${tlsPath(id)}/certificates/${encodeURIComponent(sha256)}/${format}`;
}

/** File name announced by `Content-Disposition`, if any. */
export function attachmentName(header: string | null): string | null {
  const match = header === null ? null : /filename="([^"]+)"/.exec(header);
  return match?.[1] ?? null;
}

/**
 * Downloads a certificate as a file: fetched with the token, then saved through a temporary
 * object URL. The content is never displayed by the webview.
 */
export async function downloadCertificate(id: string, sha256: string, format: 'der' | 'pem'): Promise<void> {
  const res = await apiFetch(certificateFilePath(id, sha256, format), { accept: '*/*' });
  const name = attachmentName(res.headers.get('Content-Disposition')) ?? `${sha256.slice(0, 12)}.${format}`;
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
    // Revoked after the click has been handled.
    setTimeout(() => {
      URL.revokeObjectURL(url);
    }, 1000);
  }
}
