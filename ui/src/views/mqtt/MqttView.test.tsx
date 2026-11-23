import { screen, waitFor, within } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import * as mqttApi from '../../api/mqtt';
import * as api from '../../api/sessions';
import type { Endpoint } from '../../api/types/Endpoint';
import type { MqttConnectionDetail } from '../../api/types/MqttConnectionDetail';
import type { MqttConnectionInfo } from '../../api/types/MqttConnectionInfo';
import type { MqttPacketInfo } from '../../api/types/MqttPacketInfo';
import type { MqttStats } from '../../api/types/MqttStats';
import type { MqttTopicNode } from '../../api/types/MqttTopicNode';
import { renderApp, setViewportWide } from '../../test/renderApp';
import { page, session } from '../../test/sessionFixtures';
import { setupUser } from '../../test/user';

vi.mock('../../api/sessions');
vi.mock('../../api/mqtt', async (importOriginal) => {
  const actual = await importOriginal<typeof mqttApi>();
  return {
    ...actual,
    getMqttStats: vi.fn(),
    getMqttSignals: vi.fn(),
    listMqttConnections: vi.fn(),
    getMqttConnection: vi.fn(),
    listMqttPackets: vi.fn(),
    listMqttClients: vi.fn(),
    listMqttBrokers: vi.fn(),
    listMqttTopics: vi.fn(),
    getMqttTopic: vi.fn(),
    listMqttMessages: vi.fn(),
  };
});

const ID = '01JC0FFEE0000000000000000A';
const T0 = Date.UTC(2026, 10, 8, 10, 0, 0) * 1000;
const SECRET = 'sensor-fixture';

function endpoint(ip: string, category: Endpoint['category'] = 'private'): Endpoint {
  return { ip, names: [], category, country: null };
}

function stats(): MqttStats {
  return {
    connections: 3,
    tcp: 3,
    ws: 0,
    v31: 1,
    v311: 1,
    v5: 1,
    unknown_version: 0,
    clients: 3,
    brokers: 2,
    public_brokers: 1,
    accepted: 2,
    rejected: 1,
    no_answer: 0,
    anonymous_accepted: 1,
    with_password: 1,
    publish_c2s: 12,
    publish_s2c: 4,
    payload_bytes: 2048,
    subscriptions: 2,
    topics: 6,
    unfollowed: 0,
    connack_codes: [],
    signals: [{ kind: 'anonymous', connections: 1 }],
  };
}

function info(overrides: Partial<MqttConnectionInfo> = {}): MqttConnectionInfo {
  return {
    flow_id: 7,
    first_ts_us: T0,
    last_ts_us: T0 + 42_000_000,
    client: endpoint('192.168.1.60'),
    client_port: 49_152,
    broker: endpoint('192.168.1.40'),
    broker_port: 1883,
    transport: 'tcp',
    ws_path: null,
    version: '3.1.1',
    bridge: false,
    partial: false,
    client_id: 'sensor-01',
    assigned_client_id: null,
    username: 'sensor-01',
    has_password: true,
    auth: 'password',
    login: 'accepted',
    connack_code: 0,
    publish_c2s: 4,
    publish_s2c: 1,
    payload_bytes_c2s: 38,
    payload_bytes_s2c: 6,
    end: 'disconnect',
    packets_truncated: false,
    malformed: 0,
    signals: ['cleartext-credentials'],
    client_key: 'id:sensor-01',
    ...overrides,
  };
}

function packet(overrides: Partial<MqttPacketInfo> = {}): MqttPacketInfo {
  return {
    id: 1,
    flow_id: 7,
    seq: 0,
    ts_us: T0,
    dir: 'client',
    type: 'CONNECT',
    packet_id: null,
    qos: null,
    retain: false,
    dup: false,
    topic: null,
    topic_alias: null,
    topic_source: null,
    size: 89,
    payload: null,
    payload_format: null,
    content_type: null,
    reason_code: null,
    reason_string: null,
    ack: null,
    filters: [],
    props: [],
    malformed: false,
    client_id: null,
    client: null,
    broker: null,
    broker_port: null,
    ...overrides,
  };
}

const NOTE = packet({
  id: 3,
  seq: 4,
  ts_us: T0 + 1_000_000,
  type: 'PUBLISH',
  qos: 1,
  packet_id: 2,
  topic: 'plant/line1/note',
  payload: { len: 32, excerpt_len: 32, truncated: false, hex: '3c7363726970743e', text: '<script>alert(1)</script> \\u{202e}' },
  ack: { state: 'acked', reason: null, delay_us: 3000 },
  client_id: 'sensor-01',
  client: endpoint('192.168.1.60'),
  broker: endpoint('192.168.1.40'),
  broker_port: 1883,
});

function detail(): MqttConnectionDetail {
  return {
    connection: info(),
    protocol_name: 'MQTT',
    clean_start: true,
    keep_alive: 60,
    server_keep_alive: null,
    session_expiry: null,
    auth_method: null,
    password: SECRET,
    password_len: 14,
    will: {
      topic: 'plant/line1/sensor-01/status',
      qos: 1,
      retain: true,
      payload: { len: 7, excerpt_len: 7, truncated: false, hex: '6f66666c696e65', text: 'offline' },
    },
    connect_props: [],
    connack_ts_us: T0 + 1000,
    session_present: false,
    connack_props: [],
    disconnect_ts_us: T0 + 42_000_000,
    disconnect_by: 'client',
    disconnect_reason: null,
    broker_software: null,
    pings: 2,
    last_ping_ts_us: T0 + 30_000_000,
    packets_c2s: 9,
    packets_s2c: 6,
    bytes_c2s: 900,
    bytes_s2c: 300,
    subscribe_count: 1,
    stored_packets: 3,
    protocol_errors: 0,
    gaps: 0,
    state_dropped: 0,
    subscriptions: [
      {
        ts_us: T0,
        filter: '#',
        qos: 0,
        options: 0,
        granted: 0,
        shared_group: null,
        wildcard: true,
        unsubscribed_ts_us: null,
      },
    ],
    topics: [{ topic: 'plant/line1/note', dir: 'client', messages: 1, payload_bytes: 32, retained: 0 }],
  };
}

function node(overrides: Partial<MqttTopicNode> = {}): MqttTopicNode {
  return {
    path: 'plant',
    name: 'plant',
    depth: 1,
    is_topic: false,
    children: 2,
    topics: 5,
    messages_pub: 10,
    messages_del: 3,
    payload_bytes: 400,
    retained: 0,
    first_ts_us: T0,
    last_ts_us: T0 + 5_000_000,
    ...overrides,
  };
}

beforeEach(() => {
  setViewportWide(true);
  window.location.hash = '';
  vi.mocked(api.getSession).mockResolvedValue(session({ state: 'ready' }));
  vi.mocked(mqttApi.getMqttStats).mockResolvedValue(stats());
  vi.mocked(mqttApi.getMqttSignals).mockResolvedValue([
    {
      kind: 'anonymous',
      connections: 1,
      items: [{ client: null, broker: endpoint('82.165.30.12', 'public'), broker_port: 1883, filter: null, connections: 1 }],
    },
  ]);
  vi.mocked(mqttApi.listMqttConnections).mockResolvedValue(
    page([
      info(),
      info({
        flow_id: 9,
        client_id: 'legacy-gw',
        version: '3.1',
        auth: 'none',
        username: null,
        has_password: false,
        broker: endpoint('82.165.30.12', 'public'),
        signals: ['anonymous', 'public-broker'],
        client_key: 'id:legacy-gw',
      }),
      info({ flow_id: 11, client_id: 'probe', login: 'rejected', connack_code: 4, client_key: 'id:probe' }),
    ]),
  );
  vi.mocked(mqttApi.getMqttConnection).mockResolvedValue(detail());
  vi.mocked(mqttApi.listMqttPackets).mockResolvedValue(page([packet(), packet({ id: 2, seq: 1, dir: 'broker', type: 'CONNACK', reason_code: 0 }), NOTE]));
  vi.mocked(mqttApi.listMqttTopics).mockImplementation((_id, params) =>
    Promise.resolve(
      params.parent === 'plant'
        ? { ...page([node({ path: 'plant/line1', name: 'line1', depth: 2, children: 0, is_topic: true, topics: 1 })]), partial: false }
        : { ...page([node()]), partial: false },
    ),
  );
  vi.mocked(mqttApi.getMqttTopic).mockResolvedValue({
    node: node({ path: 'plant/line1', name: 'line1', is_topic: true, topics: 1, children: 0 }),
    qos: [3, 7, 0],
    publishers: [{ client_id: 'sensor-01', client: endpoint('192.168.1.60'), messages: 10 }],
    publisher_count: 1,
    subscribers: [{ filter: '#', client_id: 'dashboard', client: endpoint('192.168.1.10') }],
    recent: [NOTE],
  });
  vi.mocked(mqttApi.listMqttMessages).mockResolvedValue(page([NOTE]));
});

describe('MQTT view', () => {
  it('shows the figures, the signals and the connections with their status', async () => {
    renderApp(`/sessions/${ID}/mqtt`);
    const summary = await screen.findByTestId('mqtt-summary');
    expect(within(summary).getByText('2 accepted, 1 rejected')).toBeInTheDocument();
    expect(within(summary).getByText('1 public')).toBeInTheDocument();
    const signals = await screen.findByTestId('mqtt-signals');
    expect(within(signals).getByText('Anonymous access accepted')).toBeInTheDocument();
    const list = await screen.findByRole('list', { name: 'MQTT connections' });
    expect(within(list).getByText('legacy-gw')).toBeInTheDocument();
    expect(within(list).getByText('Anonymous')).toBeInTheDocument();
    expect(within(list).getByText('Rejected')).toBeInTheDocument();
    expect(within(list).getByText('Bad user name or password')).toBeInTheDocument();
    // The list never fetches a password.
    expect(mqttApi.getMqttConnection).not.toHaveBeenCalled();
    // Every connection followed: no note.
    expect(screen.queryByTestId('mqtt-unfollowed')).not.toBeInTheDocument();
  });

  it('notes the connections not analyzed during the import', async () => {
    vi.mocked(mqttApi.getMqttStats).mockResolvedValue({ ...stats(), unfollowed: 1240 });
    renderApp(`/sessions/${ID}/mqtt`);
    const note = await screen.findByTestId('mqtt-unfollowed');
    expect(note.textContent).toBe('At least 1,240 MQTT connections not analyzed (connection or memory bound reached during the import)');
  });

  it('expands a connection: password masked, transcript, escaped payload', async () => {
    const user = setupUser();
    renderApp(`/sessions/${ID}/mqtt`);
    const list = await screen.findByRole('list', { name: 'MQTT connections' });
    await user.click(within(list).getAllByRole('button', { expanded: false })[0] as HTMLElement);
    const transcript = await screen.findByTestId('mqtt-transcript');
    expect(mqttApi.getMqttConnection).toHaveBeenCalledWith(ID, 7, expect.anything());
    expect(document.body.textContent).not.toContain(SECRET);
    expect(screen.getByText('offline')).toBeInTheDocument();
    expect(transcript.textContent).toContain('PUBLISH');
    expect(transcript.textContent).toContain('plant/line1/note');
    expect(transcript.textContent).toContain('PUBACK');
    await user.click(within(transcript).getByRole('button', { name: 'Payload of the packet 4' }));
    const payload = await within(transcript).findByTestId('mqtt-payload');
    expect(payload.textContent).toContain('<script>alert(1)</script>');
    expect(payload.querySelector('script')).toBeNull();
    await user.click(screen.getByRole('button', { name: 'Show Password' }));
    expect(document.body.textContent).toContain(SECRET);
  });

  it('filters the connections from a signal and removes the chip', async () => {
    const user = setupUser();
    renderApp(`/sessions/${ID}/mqtt`);
    const signals = await screen.findByTestId('mqtt-signals');
    await user.click(within(signals).getByRole('button', { name: 'Show the connections: Anonymous access accepted' }));
    await waitFor(() => {
      expect(mqttApi.listMqttConnections).toHaveBeenLastCalledWith(
        ID,
        expect.objectContaining({ signal: 'anonymous' }),
        expect.anything(),
        null,
      );
    });
    await user.click(screen.getByRole('button', { name: 'Remove the filter Signal: Anonymous access accepted' }));
    await waitFor(() => {
      expect(mqttApi.listMqttConnections).toHaveBeenLastCalledWith(ID, expect.not.objectContaining({ signal: 'anonymous' }), expect.anything(), null);
    });
  });

  it('browses the topic tree and shows a topic', async () => {
    const user = setupUser();
    window.location.hash = `#/sessions/${ID}/mqtt?tab=topics`;
    renderApp(`/sessions/${ID}/mqtt?tab=topics`);
    const table = await screen.findByRole('table', { name: 'Topics of the level' });
    await user.click(within(table).getByText('plant'));
    await waitFor(() => {
      expect(mqttApi.listMqttTopics).toHaveBeenLastCalledWith(ID, expect.objectContaining({ parent: 'plant' }), expect.anything(), null);
    });
    await user.click(await within(screen.getByRole('table', { name: 'Topics of the level' })).findByText('line1'));
    const detail = await screen.findByTestId('mqtt-topic-detail');
    expect(within(detail).getByText('QoS 0: 3, QoS 1: 7, QoS 2: 0')).toBeInTheDocument();
    expect(within(detail).getByText('#')).toBeInTheDocument();
    await user.click(within(detail).getByRole('button', { name: 'Show the messages' }));
    const messages = await screen.findByRole('list', { name: 'MQTT messages' });
    expect(messages.textContent).toContain('plant/line1/note');
    expect(mqttApi.listMqttMessages).toHaveBeenLastCalledWith(ID, expect.objectContaining({ topic: 'plant/line1' }), expect.anything(), null);
  });

  it('shows a whole-session mention under a time range', async () => {
    renderApp(`/sessions/${ID}/mqtt?from_us=${T0}&to_us=${T0 + 10_000_000}`);
    await screen.findByRole('list', { name: 'MQTT connections' });
    expect(screen.getAllByText(/whole session/i).length).toBeGreaterThan(0);
  });
});
