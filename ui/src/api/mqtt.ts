// Typed client of the MQTT routes (crates/netsift-api/src/mqtt.rs).

import { withRange, type TimeRange } from '../lib/timeRange';
import { apiGet } from './client';
import type { MqttAuth } from './types/MqttAuth';
import type { MqttBrokerInfo } from './types/MqttBrokerInfo';
import type { MqttClientInfo } from './types/MqttClientInfo';
import type { MqttConnectionDetail } from './types/MqttConnectionDetail';
import type { MqttConnectionInfo } from './types/MqttConnectionInfo';
import type { MqttDir } from './types/MqttDir';
import type { MqttPacketInfo } from './types/MqttPacketInfo';
import type { MqttSignal } from './types/MqttSignal';
import type { MqttSignalKind } from './types/MqttSignalKind';
import type { MqttStats } from './types/MqttStats';
import type { MqttTopicDetail } from './types/MqttTopicDetail';
import type { MqttTopicNode } from './types/MqttTopicNode';
import type { Page } from './types/Page';

/** Values of the result filter of the connections, in display order. */
export const MQTT_LOGINS = ['accepted', 'rejected', 'none'] as const;
export type MqttLoginFilter = (typeof MQTT_LOGINS)[number];
/** Values of the authentication filter, in display order. */
export const MQTT_AUTHS = ['none', 'username', 'password', 'enhanced'] as const satisfies readonly MqttAuth[];
/** Values of the version filter, in display order. */
export const MQTT_VERSIONS = ['3.1', '3.1.1', '5.0', 'unknown'] as const;
export type MqttVersionFilter = (typeof MQTT_VERSIONS)[number];

/** A broker endpoint as a filter. */
export interface MqttBrokerFilter {
  ip: string;
  port: number;
}

export interface MqttConnectionParams {
  limit?: number;
  cursor?: string | null;
  /** Text in the addresses, client identifier, user name or WebSocket path. */
  q?: string;
  login?: MqttLoginFilter;
  auth?: MqttAuth;
  version?: MqttVersionFilter;
  broker?: MqttBrokerFilter;
  /** Client key (`id:<client id>` or `ip:<address>`). */
  client?: string;
  signal?: MqttSignalKind;
  /** One connection (flow id). */
  flow?: number;
}

export interface MqttMessageParams {
  limit?: number;
  cursor?: string | null;
  /** Text in the topic or the client identifier. */
  q?: string;
  topic?: string;
  /** The topic or any topic below it. */
  prefix?: string;
  dir?: MqttDir;
  qos?: number;
  retain?: boolean;
  client?: string;
  broker?: MqttBrokerFilter;
  flow?: number;
}

export interface MqttGroupParams {
  limit?: number;
  cursor?: string | null;
  q?: string;
}

const sessionPath = (id: string): `/${string}` => `/sessions/${encodeURIComponent(id)}/mqtt`;

function query(entries: Record<string, string | number | boolean | null | undefined>): string {
  const q = new URLSearchParams();
  for (const [key, value] of Object.entries(entries)) {
    if (value === undefined || value === null) continue;
    if (typeof value === 'string' && value === '') continue;
    q.set(key, String(value));
  }
  const text = q.toString();
  return text === '' ? '' : `?${text}`;
}

export function getMqttStats(id: string, signal?: AbortSignal, range: TimeRange | null = null): Promise<MqttStats> {
  return apiGet(withRange(`${sessionPath(id)}/stats`, range), signal);
}

export function getMqttSignals(id: string, signal?: AbortSignal, range: TimeRange | null = null): Promise<MqttSignal[]> {
  return apiGet(withRange(`${sessionPath(id)}/signals`, range), signal);
}

export function listMqttConnections(
  id: string,
  params: MqttConnectionParams = {},
  signal?: AbortSignal,
  range: TimeRange | null = null,
): Promise<Page<MqttConnectionInfo>> {
  const q = query({
    limit: params.limit,
    cursor: params.cursor,
    q: params.q,
    login: params.login,
    auth: params.auth,
    version: params.version,
    broker: params.broker?.ip,
    broker_port: params.broker?.port,
    client: params.client,
    signal: params.signal,
    flow: params.flow,
  });
  return apiGet(withRange(`${sessionPath(id)}/connections${q}`, range), signal);
}

/** A connection with its password (sensitive), not filtered by the time range. */
export function getMqttConnection(id: string, flow: number, signal?: AbortSignal): Promise<MqttConnectionDetail> {
  return apiGet(`${sessionPath(id)}/connections/${flow}`, signal);
}

export function listMqttPackets(
  id: string,
  flow: number,
  params: { limit?: number; cursor?: string | null } = {},
  signal?: AbortSignal,
  range: TimeRange | null = null,
): Promise<Page<MqttPacketInfo>> {
  const q = query({ limit: params.limit, cursor: params.cursor });
  return apiGet(withRange(`${sessionPath(id)}/connections/${flow}/packets${q}`, range), signal);
}

export function listMqttClients(
  id: string,
  params: MqttGroupParams = {},
  signal?: AbortSignal,
  range: TimeRange | null = null,
): Promise<Page<MqttClientInfo>> {
  const q = query({ limit: params.limit, cursor: params.cursor, q: params.q });
  return apiGet(withRange(`${sessionPath(id)}/clients${q}`, range), signal);
}

export function listMqttBrokers(
  id: string,
  params: MqttGroupParams = {},
  signal?: AbortSignal,
  range: TimeRange | null = null,
): Promise<Page<MqttBrokerInfo>> {
  const q = query({ limit: params.limit, cursor: params.cursor, q: params.q });
  return apiGet(withRange(`${sessionPath(id)}/brokers${q}`, range), signal);
}

/** Children of `parent` (`null`: first level), or the topics containing `q`. */
export function listMqttTopics(
  id: string,
  params: { parent: string | null; q?: string; limit?: number; cursor?: string | null },
  signal?: AbortSignal,
  range: TimeRange | null = null,
): Promise<Page<MqttTopicNode>> {
  const q = new URLSearchParams();
  if (params.q !== undefined && params.q !== '') q.set('q', params.q);
  // An empty parent (`/x` has an empty first level) is kept: `parent=` differs from no parent.
  else if (params.parent !== null) q.set('parent', params.parent);
  if (params.limit !== undefined) q.set('limit', String(params.limit));
  if (params.cursor !== undefined && params.cursor !== null) q.set('cursor', params.cursor);
  const text = q.toString();
  return apiGet(withRange(`${sessionPath(id)}/topics${text === '' ? '' : `?${text}`}`, range), signal);
}

export function getMqttTopic(id: string, path: string, signal?: AbortSignal, range: TimeRange | null = null): Promise<MqttTopicDetail> {
  const q = `?path=${encodeURIComponent(path)}`;
  return apiGet(withRange(`${sessionPath(id)}/topics/node${q}`, range), signal);
}

export function listMqttMessages(
  id: string,
  params: MqttMessageParams = {},
  signal?: AbortSignal,
  range: TimeRange | null = null,
): Promise<Page<MqttPacketInfo>> {
  const q = query({
    limit: params.limit,
    cursor: params.cursor,
    q: params.q,
    topic: params.topic,
    prefix: params.prefix,
    dir: params.dir,
    qos: params.qos,
    retain: params.retain,
    client: params.client,
    broker: params.broker?.ip,
    broker_port: params.broker?.port,
    flow: params.flow,
  });
  return apiGet(withRange(`${sessionPath(id)}/messages${q}`, range), signal);
}
