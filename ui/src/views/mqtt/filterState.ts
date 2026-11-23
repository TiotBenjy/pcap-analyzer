// Filters of the MQTT lists set from the other blocks of the view.

import type { MqttSignalKind } from '../../api/types/MqttSignalKind';

/** Filters of the connection list set from the other blocks (signals, clients, brokers, messages). */
export interface ConnectionFilters {
  client: { key: string; label: string } | null;
  broker: { ip: string; port: number } | null;
  signal: MqttSignalKind | null;
  flow: { id: number; label: string } | null;
}

/** Filters of the message list set from the other blocks (topics, clients). */
export interface MessageFilters {
  topic: string | null;
  prefix: string | null;
  client: { key: string; label: string } | null;
}

export const NO_CONNECTION_FILTERS: ConnectionFilters = { client: null, broker: null, signal: null, flow: null };

export const NO_MESSAGE_FILTERS: MessageFilters = { topic: null, prefix: null, client: null };

/** `ip:port`, IPv6 in brackets. */
export function hostPort(ip: string, port: number): string {
  return ip.includes(':') ? `[${ip}]:${port}` : `${ip}:${port}`;
}
