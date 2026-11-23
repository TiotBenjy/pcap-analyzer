import { keepPreviousData, useInfiniteQuery, useQuery } from '@tanstack/react-query';
import { useViewRange } from '../app/timeRange';
import { rangeKey, type TimeRange } from '../lib/timeRange';
import {
  getMqttConnection,
  getMqttSignals,
  getMqttStats,
  getMqttTopic,
  listMqttBrokers,
  listMqttClients,
  listMqttConnections,
  listMqttMessages,
  listMqttPackets,
  listMqttTopics,
  type MqttConnectionParams,
  type MqttGroupParams,
  type MqttMessageParams,
} from './mqtt';

// Query hooks of the MQTT view, keyed under the session detail so a session refresh covers them.
// Lists and statistics apply the time range (ADR-030, last element of their keys); the detail of
// a connection does not.

/** Rows fetched per page of the lists. */
export const MQTT_PAGE_SIZE = 200;
/** Packets fetched per page of a transcript. */
export const MQTT_PACKET_PAGE = 500;

const base = (id: string) => ['sessions', 'detail', id, 'mqtt'] as const;

export const mqttKeys = {
  stats: (id: string, range: TimeRange | null = null) => [...base(id), 'stats', rangeKey(range)] as const,
  signals: (id: string, range: TimeRange | null = null) => [...base(id), 'signals', rangeKey(range)] as const,
  connections: (id: string, params: MqttConnectionParams, range: TimeRange | null = null) =>
    [...base(id), 'connections', params, rangeKey(range)] as const,
  connection: (id: string, flow: number) => [...base(id), 'connection', flow] as const,
  packets: (id: string, flow: number, range: TimeRange | null = null) => [...base(id), 'packets', flow, rangeKey(range)] as const,
  clients: (id: string, params: MqttGroupParams, range: TimeRange | null = null) => [...base(id), 'clients', params, rangeKey(range)] as const,
  brokers: (id: string, params: MqttGroupParams, range: TimeRange | null = null) => [...base(id), 'brokers', params, rangeKey(range)] as const,
  topics: (id: string, parent: string | null, q: string, range: TimeRange | null = null) =>
    [...base(id), 'topics', parent, q, rangeKey(range)] as const,
  topic: (id: string, path: string, range: TimeRange | null = null) => [...base(id), 'topic', path, rangeKey(range)] as const,
  messages: (id: string, params: MqttMessageParams, range: TimeRange | null = null) =>
    [...base(id), 'messages', params, rangeKey(range)] as const,
};

/** `enabled`: false while the session is importing or failed (the routes answer 409). */
export function useMqttStats(id: string, enabled: boolean) {
  const range = useViewRange();
  return useQuery({ queryKey: mqttKeys.stats(id, range), queryFn: ({ signal }) => getMqttStats(id, signal, range), enabled });
}

export function useMqttSignals(id: string, enabled: boolean) {
  const range = useViewRange();
  return useQuery({ queryKey: mqttKeys.signals(id, range), queryFn: ({ signal }) => getMqttSignals(id, signal, range), enabled });
}

export function useMqttConnections(id: string, params: MqttConnectionParams, enabled: boolean) {
  const range = useViewRange();
  return useInfiniteQuery({
    queryKey: mqttKeys.connections(id, params, range),
    queryFn: ({ pageParam, signal }) => listMqttConnections(id, { ...params, limit: MQTT_PAGE_SIZE, cursor: pageParam }, signal, range),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
    placeholderData: keepPreviousData,
    enabled,
  });
}

/** Detail of one connection, fetched when its row is unfolded. */
export function useMqttConnection(id: string, flow: number, enabled: boolean) {
  return useQuery({ queryKey: mqttKeys.connection(id, flow), queryFn: ({ signal }) => getMqttConnection(id, flow, signal), enabled });
}

export function useMqttPackets(id: string, flow: number, enabled: boolean) {
  const range = useViewRange();
  return useInfiniteQuery({
    queryKey: mqttKeys.packets(id, flow, range),
    queryFn: ({ pageParam, signal }) => listMqttPackets(id, flow, { limit: MQTT_PACKET_PAGE, cursor: pageParam }, signal, range),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
    enabled,
  });
}

export function useMqttClients(id: string, params: MqttGroupParams, enabled: boolean) {
  const range = useViewRange();
  return useInfiniteQuery({
    queryKey: mqttKeys.clients(id, params, range),
    queryFn: ({ pageParam, signal }) => listMqttClients(id, { ...params, limit: MQTT_PAGE_SIZE, cursor: pageParam }, signal, range),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
    placeholderData: keepPreviousData,
    enabled,
  });
}

export function useMqttBrokers(id: string, params: MqttGroupParams, enabled: boolean) {
  const range = useViewRange();
  return useInfiniteQuery({
    queryKey: mqttKeys.brokers(id, params, range),
    queryFn: ({ pageParam, signal }) => listMqttBrokers(id, { ...params, limit: MQTT_PAGE_SIZE, cursor: pageParam }, signal, range),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
    placeholderData: keepPreviousData,
    enabled,
  });
}

/** Children of `parent` (`null`: first level), or the topics containing `q` when set. */
export function useMqttTopics(id: string, parent: string | null, q: string, enabled: boolean) {
  const range = useViewRange();
  return useInfiniteQuery({
    queryKey: mqttKeys.topics(id, parent, q, range),
    queryFn: ({ pageParam, signal }) =>
      listMqttTopics(id, { parent, ...(q === '' ? {} : { q }), limit: MQTT_PAGE_SIZE, cursor: pageParam }, signal, range),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
    placeholderData: keepPreviousData,
    enabled,
  });
}

export function useMqttTopic(id: string, path: string | null, enabled: boolean) {
  const range = useViewRange();
  return useQuery({
    queryKey: mqttKeys.topic(id, path ?? '', range),
    queryFn: ({ signal }) => getMqttTopic(id, path ?? '', signal, range),
    enabled: enabled && path !== null,
  });
}

export function useMqttMessages(id: string, params: MqttMessageParams, enabled: boolean) {
  const range = useViewRange();
  return useInfiniteQuery({
    queryKey: mqttKeys.messages(id, params, range),
    queryFn: ({ pageParam, signal }) => listMqttMessages(id, { ...params, limit: MQTT_PAGE_SIZE, cursor: pageParam }, signal, range),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
    placeholderData: keepPreviousData,
    enabled,
  });
}
