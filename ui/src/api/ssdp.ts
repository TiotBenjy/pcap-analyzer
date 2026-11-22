// Typed client of the SSDP routes (crates/netsift-api/src/ssdp.rs).

import { withRange, type TimeRange } from '../lib/timeRange';
import { apiGet } from './client';
import type { Page } from './types/Page';
import type { SsdpDeviceInfo } from './types/SsdpDeviceInfo';
import type { SsdpKind } from './types/SsdpKind';
import type { SsdpMessageInfo } from './types/SsdpMessageInfo';
import type { SsdpStats } from './types/SsdpStats';

/** Message kinds of the type filter, in display order. */
export const SSDP_KINDS: readonly SsdpKind[] = ['notify', 'search', 'response', 'invalid'];

export interface SsdpDeviceParams {
  limit?: number;
  cursor?: string | null;
  /** Text in the UUID, address, type, server or location. */
  q?: string;
}

export interface SsdpMessageParams {
  limit?: number;
  cursor?: string | null;
  kind?: SsdpKind;
  /** Messages of one device: its UUID and announcing address. */
  uuid?: string;
  src?: string;
  /** Exact `NT` / `ST`. */
  target?: string;
  /** Text in the target, USN, server, user agent or location. */
  q?: string;
}

const sessionPath = (id: string): `/${string}` => `/sessions/${encodeURIComponent(id)}/ssdp`;

function query(entries: Record<string, string | number | null | undefined>): string {
  const q = new URLSearchParams();
  for (const [key, value] of Object.entries(entries)) {
    if (value === undefined || value === null) continue;
    if (typeof value === 'string' && value.trim() === '') continue;
    q.set(key, String(value));
  }
  const text = q.toString();
  return text === '' ? '' : `?${text}`;
}

export function getSsdpStats(id: string, signal?: AbortSignal, range: TimeRange | null = null): Promise<SsdpStats> {
  return apiGet(withRange(`${sessionPath(id)}/stats`, range), signal);
}

export function listSsdpDevices(
  id: string,
  params: SsdpDeviceParams = {},
  signal?: AbortSignal,
  range: TimeRange | null = null,
): Promise<Page<SsdpDeviceInfo>> {
  const q = query({ limit: params.limit, cursor: params.cursor, q: params.q });
  return apiGet(withRange(`${sessionPath(id)}/devices${q}`, range), signal);
}

export function listSsdpMessages(
  id: string,
  params: SsdpMessageParams = {},
  signal?: AbortSignal,
  range: TimeRange | null = null,
): Promise<Page<SsdpMessageInfo>> {
  const q = query({
    limit: params.limit,
    cursor: params.cursor,
    kind: params.kind,
    uuid: params.uuid,
    src: params.src,
    target: params.target,
    q: params.q,
  });
  return apiGet(withRange(`${sessionPath(id)}/messages${q}`, range), signal);
}
