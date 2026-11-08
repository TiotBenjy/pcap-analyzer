// Typed client of the Connections and Open Ports routes (query hooks: connectionQueries.ts)
// (crates/netsift-api/src/connections.rs, ports.rs).

import { apiGet } from './client';
import type { AddressCategory } from './types/AddressCategory';
import type { ConnectionMatrix } from './types/ConnectionMatrix';
import type { ConnectionStats } from './types/ConnectionStats';
import type { ConversationInfo } from './types/ConversationInfo';
import type { HostOpenPorts } from './types/HostOpenPorts';
import type { OpenPortStats } from './types/OpenPortStats';
import type { Page } from './types/Page';

/** Sizes accepted by `/connections/top`. */
export const TOP_SIZES = [10, 20, 50] as const;
export type TopSize = (typeof TOP_SIZES)[number];

/** Rows per page of the tables (the server allows up to 1000). */
export const PAGE_SIZE = 100;

export interface ConversationFilters {
  /** Substring of the source IP or name. */
  from?: string;
  /** Substring of the destination IP or name. */
  to?: string;
}

export interface PortFilters {
  /** Address categories of the host; `undefined` = all, empty = none. */
  categories?: readonly AddressCategory[];
  /** Host IP or name, service name or port number. */
  q?: string;
}

const sessionPath = (id: string): `/${string}` => `/sessions/${encodeURIComponent(id)}`;

function query(params: Record<string, string | number | boolean | undefined | null>): string {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null) continue;
    q.set(k, String(v));
  }
  const text = q.toString();
  return text === '' ? '' : `?${text}`;
}

const trimmed = (s: string | undefined) => (s === undefined || s.trim() === '' ? undefined : s.trim());

export function listConversations(
  id: string,
  filters: ConversationFilters,
  cursor: string | null,
  signal?: AbortSignal,
): Promise<Page<ConversationInfo>> {
  const q = query({ limit: PAGE_SIZE, cursor, from: trimmed(filters.from), to: trimmed(filters.to) });
  return apiGet(`${sessionPath(id)}/connections${q}`, signal);
}

export function getConnectionStats(id: string, signal?: AbortSignal): Promise<ConnectionStats> {
  return apiGet(`${sessionPath(id)}/connections/stats`, signal);
}

export function getConnectionTop(id: string, n: TopSize, excludeDns: boolean, signal?: AbortSignal): Promise<ConnectionMatrix> {
  return apiGet(`${sessionPath(id)}/connections/top${query({ n, exclude_dns: excludeDns })}`, signal);
}

export function listOpenPorts(
  id: string,
  filters: PortFilters,
  cursor: string | null,
  signal?: AbortSignal,
): Promise<Page<HostOpenPorts>> {
  const q = query({
    limit: PAGE_SIZE,
    cursor,
    category: filters.categories?.join(','),
    q: trimmed(filters.q),
  });
  return apiGet(`${sessionPath(id)}/open-ports${q}`, signal);
}

export function getOpenPortStats(
  id: string,
  categories: readonly AddressCategory[] | undefined,
  signal?: AbortSignal,
): Promise<OpenPortStats> {
  return apiGet(`${sessionPath(id)}/open-ports/stats${query({ category: categories?.join(','), n: 15 })}`, signal);
}
