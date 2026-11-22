// Typed client of the Network routes (query hooks: networkQueries.ts)
// (crates/netsift-api/src/network.rs).

import { withRange, type TimeRange } from '../lib/timeRange';
import { apiGet } from './client';
import type { NetworkGraph } from './types/NetworkGraph';
import type { NetworkMode } from './types/NetworkMode';
import type { NetworkNodeDetail } from './types/NetworkNodeDetail';
import type { NetworkProtocol } from './types/NetworkProtocol';

/** Protocol filters, in display order (same order as the API counters). */
export const NETWORK_PROTOCOLS: readonly NetworkProtocol[] = [
  'dns',
  'http',
  'https',
  'ssh',
  'ftp',
  'telnet',
  'rdp',
  'smb',
  'tcp',
  'udp',
  'other',
];

export interface GraphParams {
  mode: NetworkMode;
  /** Selected protocols; `undefined` = all (no filter), empty = none. */
  protocols?: readonly NetworkProtocol[] | undefined;
  ipv6: boolean;
  /** Also draw hosts without matching traffic (host mode). */
  includeOrphans: boolean;
  /** Country code of a cluster whose hosts are drawn (host mode). */
  expand?: string | null | undefined;
}

const sessionPath = (id: string): `/${string}` => `/sessions/${encodeURIComponent(id)}`;

/** Query string of `/network/graph`; default values are left out. */
export function graphQuery(p: GraphParams): string {
  const q = new URLSearchParams();
  if (p.mode !== 'hosts') q.set('mode', p.mode);
  if (p.protocols !== undefined) q.set('protocols', p.protocols.join(','));
  if (!p.ipv6) q.set('ipv6', 'false');
  if (p.includeOrphans && p.mode === 'hosts') q.set('include_orphans', 'true');
  if (p.expand !== undefined && p.expand !== null && p.mode === 'hosts') q.set('expand', p.expand);
  const text = q.toString();
  return text === '' ? '' : `?${text}`;
}

export function getNetworkGraph(id: string, p: GraphParams, signal?: AbortSignal, range: TimeRange | null = null): Promise<NetworkGraph> {
  return apiGet(withRange(`${sessionPath(id)}/network/graph${graphQuery(p)}`, range), signal);
}

export function getNetworkNode(id: string, ip: string, signal?: AbortSignal, range: TimeRange | null = null): Promise<NetworkNodeDetail> {
  return apiGet(withRange(`${sessionPath(id)}/network/node/${encodeURIComponent(ip)}`, range), signal);
}
