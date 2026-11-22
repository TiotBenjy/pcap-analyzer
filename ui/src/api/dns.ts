// Typed client of the DNS routes (crates/netsift-api/src/dns.rs).

import { withRange, type TimeRange } from '../lib/timeRange';
import { apiGet } from './client';
import type { DnsMessage } from './types/DnsMessage';
import type { DnsPair } from './types/DnsPair';
import type { DnsProtocol } from './types/DnsProtocol';
import type { DnsServer } from './types/DnsServer';
import type { DnsStats } from './types/DnsStats';
import type { Page } from './types/Page';

/** Every protocol of the DNS view, in display order. */
export const DNS_PROTOCOLS: readonly DnsProtocol[] = ['dns', 'mdns', 'nbns', 'llmnr'];

/** Filters shared by the pair and message lists. */
export interface DnsFilter {
  /** Shown protocols; all when omitted, none when empty. */
  protocols?: readonly DnsProtocol[];
  /** Only transactions with an error (pairs with at least one). */
  errors?: boolean;
  /** Substring of a name, an address or an answer. */
  q?: string;
}

export interface DnsListParams extends DnsFilter {
  limit?: number;
  cursor?: string | null;
  /** Messages of one pair (`DnsPair.id`). */
  pair?: string;
}

const dnsPath = (id: string): `/${string}` => `/sessions/${encodeURIComponent(id)}/dns`;

export function dnsListQuery(p: DnsListParams = {}): string {
  const q = new URLSearchParams();
  if (p.pair !== undefined) q.set('pair', p.pair);
  if (p.protocols !== undefined) q.set('protocols', p.protocols.join(','));
  if (p.errors === true) q.set('errors', 'true');
  const text = p.q?.trim() ?? '';
  if (text !== '') q.set('q', text);
  if (p.limit !== undefined) q.set('limit', String(p.limit));
  if (p.cursor !== undefined && p.cursor !== null) q.set('cursor', p.cursor);
  const s = q.toString();
  return s === '' ? '' : `?${s}`;
}

export function getDnsStats(id: string, signal?: AbortSignal, range: TimeRange | null = null): Promise<DnsStats> {
  return apiGet(withRange(`${dnsPath(id)}/stats`, range), signal);
}

export function getDnsPairs(id: string, params: DnsListParams, signal?: AbortSignal, range: TimeRange | null = null): Promise<Page<DnsPair>> {
  return apiGet(withRange(`${dnsPath(id)}/pairs${dnsListQuery(params)}`, range), signal);
}

export function getDnsMessages(id: string, params: DnsListParams, signal?: AbortSignal, range: TimeRange | null = null): Promise<Page<DnsMessage>> {
  return apiGet(withRange(`${dnsPath(id)}/messages${dnsListQuery(params)}`, range), signal);
}

export function getDnsServers(
  id: string,
  params: Pick<DnsListParams, 'limit' | 'cursor'>,
  signal?: AbortSignal,
  range: TimeRange | null = null,
): Promise<Page<DnsServer>> {
  const paging: DnsListParams = {};
  if (params.limit !== undefined) paging.limit = params.limit;
  if (params.cursor !== undefined) paging.cursor = params.cursor;
  return apiGet(withRange(`${dnsPath(id)}/servers${dnsListQuery(paging)}`, range), signal);
}
