// Typed client of the SIP routes (crates/netsift-api/src/sip.rs).

import { withRange, type TimeRange } from '../lib/timeRange';
import { apiGet } from './client';
import type { Page } from './types/Page';
import type { SipDialogInfo } from './types/SipDialogInfo';
import type { SipDialogState } from './types/SipDialogState';
import type { SipDialogType } from './types/SipDialogType';
import type { SipMessageInfo } from './types/SipMessageInfo';
import type { SipMessageKind } from './types/SipMessageKind';
import type { SipScannerInfo } from './types/SipScannerInfo';
import type { SipStats } from './types/SipStats';

/** Dialog types of the segmented control, in display order. */
export const SIP_DIALOG_TYPES: readonly SipDialogType[] = ['call', 'register', 'other'];
/** Message kinds of the kind filter, in display order. */
export const SIP_MESSAGE_KINDS: readonly SipMessageKind[] = ['request', 'response'];

export interface SipDialogParams {
  limit?: number;
  cursor?: string | null;
  type?: SipDialogType;
  state?: SipDialogState;
  /** Text in the Call-ID, From, To, user agents or user name. */
  q?: string;
}

export interface SipMessageParams {
  limit?: number;
  cursor?: string | null;
  kind?: SipMessageKind;
  method?: string;
  call_id?: string;
  src?: string;
  /** Exact user agent. */
  agent?: string;
  /** Only the messages of scanners. */
  scanner?: boolean;
  /** Text in the Call-ID, From, To, request URI or user agent. */
  q?: string;
}

const sessionPath = (id: string): `/${string}` => `/sessions/${encodeURIComponent(id)}/sip`;

function query(entries: Record<string, string | number | boolean | null | undefined>): string {
  const q = new URLSearchParams();
  for (const [key, value] of Object.entries(entries)) {
    if (value === undefined || value === null || value === false) continue;
    if (typeof value === 'string' && value.trim() === '') continue;
    q.set(key, String(value));
  }
  const text = q.toString();
  return text === '' ? '' : `?${text}`;
}

export function getSipStats(id: string, signal?: AbortSignal, range: TimeRange | null = null): Promise<SipStats> {
  return apiGet(withRange(`${sessionPath(id)}/stats`, range), signal);
}

export function listSipScanners(id: string, signal?: AbortSignal, range: TimeRange | null = null): Promise<SipScannerInfo[]> {
  return apiGet(withRange(`${sessionPath(id)}/scanners`, range), signal);
}

export function listSipDialogs(
  id: string,
  params: SipDialogParams = {},
  signal?: AbortSignal,
  range: TimeRange | null = null,
): Promise<Page<SipDialogInfo>> {
  const q = query({ limit: params.limit, cursor: params.cursor, type: params.type, state: params.state, q: params.q });
  return apiGet(withRange(`${sessionPath(id)}/dialogs${q}`, range), signal);
}

export function listSipMessages(
  id: string,
  params: SipMessageParams = {},
  signal?: AbortSignal,
  range: TimeRange | null = null,
): Promise<Page<SipMessageInfo>> {
  const q = query({
    limit: params.limit,
    cursor: params.cursor,
    kind: params.kind,
    method: params.method,
    call_id: params.call_id,
    src: params.src,
    agent: params.agent,
    scanner: params.scanner,
    q: params.q,
  });
  return apiGet(withRange(`${sessionPath(id)}/messages${q}`, range), signal);
}
