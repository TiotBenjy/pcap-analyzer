import type { HttpHeaderStats } from '../api/types/HttpHeaderStats';
import type { HttpStats } from '../api/types/HttpStats';
import type { HttpTransactionDetail } from '../api/types/HttpTransactionDetail';
import type { HttpTransactionSummary } from '../api/types/HttpTransactionSummary';

// Synthetic HTTP payloads for the view tests (no real capture data).

export const SESSION_ID = '01JC0FFEE0000000000000000A';
const T0 = Date.UTC(2026, 10, 8, 10, 0, 0) * 1000;

export function stats(overrides: Partial<HttpStats> = {}): HttpStats {
  return {
    transactions: 3,
    methods: [
      { key: 'GET', count: 2 },
      { key: 'POST', count: 1 },
    ],
    status_classes: [
      { key: '2xx', count: 1 },
      { key: '3xx', count: 1 },
      { key: '4xx', count: 1 },
    ],
    statuses: [
      { key: '404', count: 1 },
      { key: '200', count: 1 },
      { key: '302', count: 1 },
    ],
    content_types: [{ key: 'text/html', count: 2 }],
    content_types_other: 0,
    hosts: [
      { key: 'portal.example.test', count: 2 },
      { key: 'api.example.test', count: 1 },
    ],
    host_count: 2,
    user_agents: [{ key: 'curl/8.5.0', count: 3 }],
    user_agent_count: 1,
    rare_headers: [{ key: 'x-request-id', count: 1 }],
    header_count: 12,
    ...overrides,
  };
}

export function tx(id: number, overrides: Partial<HttpTransactionSummary> = {}): HttpTransactionSummary {
  return {
    id,
    flow_id: '4223190445238569362',
    seq: id - 1,
    client: { ip: '192.168.1.20', names: [], category: 'private', country: null },
    client_port: 49152,
    server: { ip: '203.0.113.10', names: ['portal.example.test'], category: 'public', country: 'FR' },
    server_port: 80,
    ts_us: T0 + id * 1_000_000,
    end_ts_us: T0 + id * 1_000_000 + 4000,
    method: 'GET',
    uri: `/page/${id}?x=1`,
    host: 'portal.example.test',
    path: `/page/${id}`,
    query: 'x=1',
    version: 'HTTP/1.1',
    status: 200,
    reason: 'OK',
    content_type: 'text/html',
    user_agent: 'curl/8.5.0',
    request_size: 0,
    response_size: 2048,
    response_state: 'complete',
    response_time_us: 3000,
    ...overrides,
  };
}

export function detail(summary: HttpTransactionSummary): HttpTransactionDetail {
  return {
    summary,
    referer: null,
    request: {
      ts_us: summary.ts_us,
      frame: 10,
      head_size: 120,
      body_wire_size: 33,
      body_size: 33,
      body_state: 'complete',
      chunked: false,
      content_encoding: null,
      content_type: 'application/x-www-form-urlencoded',
      mime_magic: null,
      sha256: null,
      preview: 'username=alice&password=demo-only',
      headers: [
        { name: 'Host', value: 'portal.example.test' },
        { name: 'Authorization', value: 'Basic ZGVtbzpkZW1v' },
        { name: 'Cookie', value: 'session=7f3a9c2e41b8d605' },
      ],
    },
    response: {
      ts_us: summary.ts_us + 3000,
      frame: 12,
      head_size: 90,
      body_wire_size: 900,
      body_size: 2048,
      body_state: 'complete',
      chunked: true,
      content_encoding: 'gzip',
      content_type: 'text/html',
      mime_magic: 'text/html',
      sha256: null,
      preview: '<p>hello</p>',
      headers: [
        { name: 'Server', value: 'nginx/1.24.0' },
        { name: 'X-Long', value: 'v'.repeat(400) },
      ],
    },
    flow_first_ts_us: summary.ts_us - 1000,
    flow_last_ts_us: summary.end_ts_us + 1000,
  };
}

export function headerStats(): HttpHeaderStats {
  return {
    transactions: 3,
    header_count: 12,
    methods: [
      { key: 'GET', count: 2 },
      { key: 'POST', count: 1 },
    ],
    names: [
      { key: 'host', count: 3 },
      { key: 'cookie', count: 2 },
    ],
  };
}
