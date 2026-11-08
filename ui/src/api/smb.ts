// Typed client of the SMB routes (crates/netsift-api/src/smb.rs).

import { apiGet } from './client';
import type { Page } from './types/Page';
import type { SmbAnnounceInfo } from './types/SmbAnnounceInfo';
import type { SmbAuthInfo } from './types/SmbAuthInfo';
import type { SmbStats } from './types/SmbStats';

export interface PageParams {
  limit?: number;
  cursor?: string | null;
}

const sessionPath = (id: string): `/${string}` => `/sessions/${encodeURIComponent(id)}/smb`;

function pageQuery(params?: PageParams): string {
  const q = new URLSearchParams();
  if (params?.limit !== undefined) q.set('limit', String(params.limit));
  if (params?.cursor !== undefined && params.cursor !== null) q.set('cursor', params.cursor);
  const text = q.toString();
  return text === '' ? '' : `?${text}`;
}

export function listSmbAnnounces(id: string, params?: PageParams, signal?: AbortSignal): Promise<Page<SmbAnnounceInfo>> {
  return apiGet(`${sessionPath(id)}/announces${pageQuery(params)}`, signal);
}

export function listSmbAuth(id: string, params?: PageParams, signal?: AbortSignal): Promise<Page<SmbAuthInfo>> {
  return apiGet(`${sessionPath(id)}/auth${pageQuery(params)}`, signal);
}

export function getSmbStats(id: string, signal?: AbortSignal): Promise<SmbStats> {
  return apiGet(`${sessionPath(id)}/stats`, signal);
}
