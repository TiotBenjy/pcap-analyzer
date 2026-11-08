// Typed client of the overview routes (crates/netsift-api/src/overview.rs).

import { apiGet } from './client';
import type { OverviewSummary } from './types/OverviewSummary';
import type { TrafficProtocol } from './types/TrafficProtocol';
import type { TrafficSeries } from './types/TrafficSeries';

/** Upper bound of the points of a series (the server clamps to it as well). */
export const MAX_TRAFFIC_POINTS = 2000;

export interface TrafficParams {
  /** Period in microseconds (`to_us` inclusive); the whole session when omitted. */
  from_us?: number;
  to_us?: number;
  /** At most this many buckets (default 1000 on the server). */
  points?: number;
  /** Only one metric; both when omitted. */
  metric?: 'bytes' | 'packets';
  /** Only these protocols; all when omitted, none when empty. */
  protocols?: readonly TrafficProtocol[];
}

const sessionPath = (id: string): `/${string}` => `/sessions/${encodeURIComponent(id)}`;

export function getOverviewSummary(id: string, signal?: AbortSignal): Promise<OverviewSummary> {
  return apiGet(`${sessionPath(id)}/summary`, signal);
}

export function trafficQuery(params: TrafficParams = {}): string {
  const q = new URLSearchParams();
  if (params.from_us !== undefined) q.set('from_us', String(Math.floor(params.from_us)));
  if (params.to_us !== undefined) q.set('to_us', String(Math.floor(params.to_us)));
  if (params.points !== undefined) q.set('points', String(Math.min(Math.max(1, Math.round(params.points)), MAX_TRAFFIC_POINTS)));
  if (params.metric !== undefined) q.set('metric', params.metric);
  if (params.protocols !== undefined) q.set('protocols', params.protocols.join(','));
  const text = q.toString();
  return text === '' ? '' : `?${text}`;
}

export function getTraffic(id: string, params?: TrafficParams, signal?: AbortSignal): Promise<TrafficSeries> {
  return apiGet(`${sessionPath(id)}/timeseries${trafficQuery(params)}`, signal);
}
