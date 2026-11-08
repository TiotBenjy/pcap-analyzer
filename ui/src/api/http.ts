// Typed client of the HTTP routes (crates/netsift-api/src/http.rs).

import { apiGet } from './client';
import type { HttpHeaderStats } from './types/HttpHeaderStats';
import type { HttpStats } from './types/HttpStats';
import type { HttpTransactionDetail } from './types/HttpTransactionDetail';
import type { HttpTransactionSummary } from './types/HttpTransactionSummary';
import type { Page } from './types/Page';

/** Method groups of the filters, in display order (`other`: any other method, or no request). */
export const METHOD_GROUPS = ['GET', 'POST', 'HEAD', 'OPTIONS', 'PUT', 'PATCH', 'DELETE', 'CONNECT', 'other'] as const;
export type MethodGroup = (typeof METHOD_GROUPS)[number];

export type HttpSort = 'time' | 'size' | 'status';

export interface HttpListParams {
  limit?: number;
  cursor?: string | null;
  /** Method groups; all when omitted, none when empty. */
  methods?: readonly string[];
  /** Status classes (`2xx`, `none`...) or codes (`404`); all when omitted. */
  statuses?: readonly string[];
  host?: string;
  /** Text in the host, target or user agent. */
  q?: string;
  sort?: HttpSort;
  order?: 'asc' | 'desc';
}

export interface HttpHeaderListParams {
  limit?: number;
  cursor?: string | null;
  methods?: readonly string[];
  /** Header name (case-insensitive). */
  name?: string;
  /** Text in header names or values. */
  q?: string;
}

const sessionPath = (id: string): `/${string}` => `/sessions/${encodeURIComponent(id)}`;

function query(entries: Record<string, string | number | readonly string[] | null | undefined>): string {
  const q = new URLSearchParams();
  for (const [key, value] of Object.entries(entries)) {
    if (value === undefined || value === null) continue;
    // Empty lists are sent (`method=`: nothing matches), empty texts are not.
    if (typeof value === 'string' && value.trim() === '') continue;
    q.set(key, Array.isArray(value) ? value.join(',') : String(value as string | number));
  }
  const text = q.toString();
  return text === '' ? '' : `?${text}`;
}

export function httpListQuery(p: HttpListParams = {}): string {
  return query({
    limit: p.limit,
    cursor: p.cursor,
    sort: p.sort,
    order: p.order,
    method: p.methods,
    status: p.statuses,
    host: p.host,
    q: p.q,
  });
}

export function httpHeaderListQuery(p: HttpHeaderListParams = {}): string {
  return query({ limit: p.limit, cursor: p.cursor, method: p.methods, name: p.name, q: p.q });
}

export function getHttpStats(id: string, signal?: AbortSignal): Promise<HttpStats> {
  return apiGet(`${sessionPath(id)}/http/stats`, signal);
}

export function listHttpTransactions(
  id: string,
  params?: HttpListParams,
  signal?: AbortSignal,
): Promise<Page<HttpTransactionSummary>> {
  return apiGet(`${sessionPath(id)}/http/transactions${httpListQuery(params)}`, signal);
}

export function getHttpTransaction(id: string, tid: number, signal?: AbortSignal): Promise<HttpTransactionDetail> {
  return apiGet(`${sessionPath(id)}/http/transactions/${tid}`, signal);
}

export function getHttpHeaderStats(id: string, signal?: AbortSignal): Promise<HttpHeaderStats> {
  return apiGet(`${sessionPath(id)}/http/headers/stats`, signal);
}

export function listHttpHeaders(
  id: string,
  params?: HttpHeaderListParams,
  signal?: AbortSignal,
): Promise<Page<HttpTransactionSummary>> {
  return apiGet(`${sessionPath(id)}/http/headers${httpHeaderListQuery(params)}`, signal);
}
