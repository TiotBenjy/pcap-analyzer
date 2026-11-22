// Typed client of the Ethernet routes (crates/netsift-api/src/ethernet.rs; hooks: ethernetQueries.ts).

import { withRange, type TimeRange } from '../lib/timeRange';
import { apiGet } from './client';
import type { EthernetStats } from './types/EthernetStats';
import type { MacInfo } from './types/MacInfo';
import type { MacPairInfo } from './types/MacPairInfo';
import type { Page } from './types/Page';

/** Rows per page of the tables (the server allows up to 1000). */
export const ETHERNET_PAGE_SIZE = 100;

export const MAC_SORTS = ['frames', 'bytes', 'last_seen', 'first_seen', 'mac'] as const;
export type MacSort = (typeof MAC_SORTS)[number];
export const PAIR_SORTS = ['frames', 'bytes', 'last_seen', 'first_seen'] as const;
export type PairSort = (typeof PAIR_SORTS)[number];
export type MacClass = 'unicast' | 'local' | 'group';

export interface MacFilters {
  sort: MacSort;
  /** Part of the address (any notation) or of the vendor name. */
  q?: string;
  class?: MacClass;
  /** Key of a vendor bar (`VendorSlice.key`). */
  vendor?: string;
  /** VLAN stack (`10`, `100.20`). */
  vlan?: string;
}

export interface PairFilters {
  sort: PairSort;
  q?: string;
  /** Pairs of this address, as source or destination. */
  mac?: string;
  vlan?: string;
  /** EtherType key (`EtherTypeRef.value`). */
  ethertype?: number;
}

const sessionPath = (id: string): `/${string}` => `/sessions/${encodeURIComponent(id)}/ethernet`;

function query(params: Record<string, string | number | undefined | null>): string {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === '') continue;
    q.set(k, String(v));
  }
  const text = q.toString();
  return text === '' ? '' : `?${text}`;
}

const trimmed = (s: string | undefined) => (s === undefined || s.trim() === '' ? undefined : s.trim());

export function getEthernetStats(id: string, signal?: AbortSignal, range: TimeRange | null = null): Promise<EthernetStats> {
  return apiGet(withRange(`${sessionPath(id)}/stats`, range), signal);
}

export function listMacs(
  id: string,
  filters: MacFilters,
  cursor: string | null,
  signal?: AbortSignal,
  range: TimeRange | null = null,
): Promise<Page<MacInfo>> {
  const q = query({
    limit: ETHERNET_PAGE_SIZE,
    cursor,
    sort: filters.sort,
    q: trimmed(filters.q),
    class: filters.class,
    vendor: filters.vendor,
    vlan: filters.vlan,
  });
  return apiGet(withRange(`${sessionPath(id)}/macs${q}`, range), signal);
}

export function listMacPairs(
  id: string,
  filters: PairFilters,
  cursor: string | null,
  signal?: AbortSignal,
  range: TimeRange | null = null,
): Promise<Page<MacPairInfo>> {
  const q = query({
    limit: ETHERNET_PAGE_SIZE,
    cursor,
    sort: filters.sort,
    q: trimmed(filters.q),
    mac: filters.mac,
    vlan: filters.vlan,
    ethertype: filters.ethertype,
  });
  return apiGet(withRange(`${sessionPath(id)}/pairs${q}`, range), signal);
}
