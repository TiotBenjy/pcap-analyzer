// Typed client of the FTP routes (crates/netsift-api/src/ftp.rs).

import { withRange, type TimeRange } from '../lib/timeRange';
import { apiGet } from './client';
import type { FtpDirection } from './types/FtpDirection';
import type { FtpLogin } from './types/FtpLogin';
import type { FtpSessionDetail } from './types/FtpSessionDetail';
import type { FtpSessionInfo } from './types/FtpSessionInfo';
import type { FtpStats } from './types/FtpStats';
import type { FtpTransferInfo } from './types/FtpTransferInfo';
import type { Page } from './types/Page';

/** Login filter values, in display order. */
export const FTP_LOGINS: readonly FtpLogin[] = ['accepted', 'rejected', 'none'];
/** Transfer directions of the filter, in display order. */
export const FTP_DIRECTIONS: readonly FtpDirection[] = ['download', 'upload', 'listing'];

export interface FtpSessionParams {
  limit?: number;
  cursor?: string | null;
  /** Text in the addresses, the user name or the banner. */
  q?: string;
  login?: FtpLogin;
}

export interface FtpTransferParams {
  limit?: number;
  cursor?: string | null;
  direction?: FtpDirection;
  /** Text in the path. */
  q?: string;
  /** Control flow of one session. */
  session?: string;
}

const sessionPath = (id: string): `/${string}` => `/sessions/${encodeURIComponent(id)}/ftp`;

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

export function getFtpStats(id: string, signal?: AbortSignal, range: TimeRange | null = null): Promise<FtpStats> {
  return apiGet(withRange(`${sessionPath(id)}/stats`, range), signal);
}

export function listFtpSessions(
  id: string,
  params: FtpSessionParams = {},
  signal?: AbortSignal,
  range: TimeRange | null = null,
): Promise<Page<FtpSessionInfo>> {
  const q = query({ limit: params.limit, cursor: params.cursor, q: params.q, login: params.login });
  return apiGet(withRange(`${sessionPath(id)}/sessions${q}`, range), signal);
}

/** A session with its transcript (password included, flagged `secret`) and transfers; no range. */
export function getFtpSession(id: string, flow: string, signal?: AbortSignal): Promise<FtpSessionDetail> {
  return apiGet(`${sessionPath(id)}/sessions/${encodeURIComponent(flow)}`, signal);
}

export function listFtpTransfers(
  id: string,
  params: FtpTransferParams = {},
  signal?: AbortSignal,
  range: TimeRange | null = null,
): Promise<Page<FtpTransferInfo>> {
  const q = query({
    limit: params.limit,
    cursor: params.cursor,
    direction: params.direction,
    q: params.q,
    session: params.session,
  });
  return apiGet(withRange(`${sessionPath(id)}/transfers${q}`, range), signal);
}
