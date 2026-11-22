// Typed client of the ARP routes (crates/netsift-api/src/arp.rs).

import { withRange, type TimeRange } from '../lib/timeRange';
import { apiGet } from './client';
import type { PageParams } from './sessions';
import type { ArpBindingInfo } from './types/ArpBindingInfo';
import type { ArpConflicts } from './types/ArpConflicts';
import type { ArpMessageInfo } from './types/ArpMessageInfo';
import type { ArpStats } from './types/ArpStats';
import type { Page } from './types/Page';

/** Message types, in display order (`ArpMessageInfo.kind`). */
export const ARP_KINDS = ['request', 'reply', 'gratuitous', 'probe', 'other'] as const;
export type ArpKind = (typeof ARP_KINDS)[number];

/** Server-side filters of the message list. */
export interface ArpMessageFilters {
  /** Types kept; all when empty. */
  kinds: readonly ArpKind[];
  /** Sender or target address. */
  ip?: string | undefined;
  /** Sender MAC address. */
  mac?: string | undefined;
  unsolicited?: boolean | undefined;
}

export interface ArpBindingFilters {
  /** Substring of the IP or MAC address. */
  q?: string | undefined;
  conflicts?: boolean | undefined;
}

const arpPath = (id: string): `/${string}` => `/sessions/${encodeURIComponent(id)}/arp`;

function query(entries: Record<string, string | number | boolean | null | undefined>): string {
  const q = new URLSearchParams();
  for (const [key, value] of Object.entries(entries)) {
    if (value === undefined || value === null || value === false || value === '') continue;
    q.set(key, String(value));
  }
  const text = q.toString();
  return text === '' ? '' : `?${text}`;
}

export function getArpStats(id: string, signal?: AbortSignal, range: TimeRange | null = null): Promise<ArpStats> {
  return apiGet(withRange(`${arpPath(id)}/stats`, range), signal);
}

export function getArpConflicts(id: string, signal?: AbortSignal, range: TimeRange | null = null): Promise<ArpConflicts> {
  return apiGet(withRange(`${arpPath(id)}/conflicts`, range), signal);
}

export function listArpMessages(
  id: string,
  filters: ArpMessageFilters,
  params: PageParams = {},
  signal?: AbortSignal,
  range: TimeRange | null = null,
): Promise<Page<ArpMessageInfo>> {
  const q = query({
    limit: params.limit,
    cursor: params.cursor,
    kind: filters.kinds.join(','),
    ip: filters.ip,
    mac: filters.mac,
    unsolicited: filters.unsolicited,
  });
  return apiGet(withRange(`${arpPath(id)}/messages${q}`, range), signal);
}

export function listArpBindings(
  id: string,
  filters: ArpBindingFilters,
  params: PageParams = {},
  signal?: AbortSignal,
  range: TimeRange | null = null,
): Promise<Page<ArpBindingInfo>> {
  const q = query({ limit: params.limit, cursor: params.cursor, q: filters.q?.trim(), conflicts: filters.conflicts });
  return apiGet(withRange(`${arpPath(id)}/bindings${q}`, range), signal);
}
