// Typed client of the Telnet routes (crates/netsift-api/src/telnet.rs).

import { withRange, type TimeRange } from '../lib/timeRange';
import { apiGet } from './client';
import type { Page } from './types/Page';
import type { TelnetSessionDetail } from './types/TelnetSessionDetail';
import type { TelnetSessionInfo } from './types/TelnetSessionInfo';
import type { TelnetStats } from './types/TelnetStats';

/** Values of the login filter, in display order. */
export const TELNET_LOGINS = ['accepted', 'rejected', 'unknown', 'none'] as const;
export type TelnetLoginFilter = (typeof TELNET_LOGINS)[number];

export interface TelnetSessionParams {
  limit?: number;
  cursor?: string | null;
  /** Text in the addresses, user names, terminal or transcript (never the secrets). */
  q?: string;
  login?: TelnetLoginFilter;
}

const sessionPath = (id: string): `/${string}` => `/sessions/${encodeURIComponent(id)}/telnet`;

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

export function getTelnetStats(id: string, signal?: AbortSignal, range: TimeRange | null = null): Promise<TelnetStats> {
  return apiGet(withRange(`${sessionPath(id)}/stats`, range), signal);
}

export function listTelnetSessions(
  id: string,
  params: TelnetSessionParams = {},
  signal?: AbortSignal,
  range: TimeRange | null = null,
): Promise<Page<TelnetSessionInfo>> {
  const q = query({ limit: params.limit, cursor: params.cursor, q: params.q, login: params.login });
  return apiGet(withRange(`${sessionPath(id)}/sessions${q}`, range), signal);
}

/** A session and its transcript, secrets included (not filtered by the time range). */
export function getTelnetSession(id: string, flow: number, signal?: AbortSignal): Promise<TelnetSessionDetail> {
  return apiGet(`${sessionPath(id)}/sessions/${flow}`, signal);
}
