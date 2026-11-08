import type { AnomalyInfo } from '../api/types/AnomalyInfo';
import type { ChunkInfo } from '../api/types/ChunkInfo';
import type { Page } from '../api/types/Page';
import type { ScanResponse } from '../api/types/ScanResponse';
import type { SessionSummary } from '../api/types/SessionSummary';

// Synthetic API payloads for the UI tests (no real capture data).

const T0 = Date.UTC(2026, 10, 8, 10, 0, 0) * 1000; // microseconds

export function page<T>(items: T[]): Page<T> {
  return { items, next_cursor: null, total_estimate: items.length };
}

export function session(overrides: Partial<SessionSummary> = {}): SessionSummary {
  return {
    id: '01JC0FFEE0000000000000000A',
    name: 'office-uplink',
    sources: ['/captures/office'],
    created_us: T0,
    state: 'ready',
    state_detail: null,
    first_ts_us: T0,
    last_ts_us: T0 + 3_600_000_000,
    source_bytes: 50 * 1024 * 1024,
    packets: 123_456,
    chunk_count: 49,
    anomaly_count: 2,
    ...overrides,
  };
}

/** Chunks of one minute each, seq 1..n; `skip` sequence numbers are absent (missing files). */
export function chunks(n: number, skip: number[] = [], gapAfterSeq: number | null = null, gapUs = 43_000_000): ChunkInfo[] {
  const out: ChunkInfo[] = [];
  let t = T0;
  let id = 0;
  for (let seq = 1; seq <= n; seq++) {
    if (skip.includes(seq)) {
      t += 60_000_000;
      continue;
    }
    out.push({
      id,
      seq,
      path: `/captures/office/ring_${String(seq).padStart(5, '0')}_20261108.pcapng`,
      format: 'pcapng',
      compressed: false,
      linktypes: [1],
      first_ts_us: t,
      last_ts_us: t + 59_000_000,
      packets: 1000 + seq,
      bytes: 1024 * 1024,
      state: 'ok',
    });
    id += 1;
    t += 60_000_000;
    if (gapAfterSeq === seq) t += gapUs;
  }
  return out;
}

export function anomaly(code: string, chunk: number | null, detail: Record<string, unknown> = {}): AnomalyInfo {
  return { id: `${code}-${chunk ?? 'g'}`, code, chunk, ts_us: null, detail };
}

export function twoGroupScan(): ScanResponse {
  return {
    path: '/captures/office',
    groups: [
      {
        id: 0,
        pattern: 'dumpcap',
        prefix: 'ring',
        file_count: 49,
        total_bytes: 49 * 1024 * 1024,
        first_ts_us: T0,
        last_ts_us: T0 + 3_000_000_000,
        anomalies: [anomaly('missing_sequence', 12, { first: 13, last: 13 })],
      },
      {
        id: 1,
        pattern: 'tcpdump_c',
        prefix: 'dmz.pcap',
        file_count: 3,
        total_bytes: 3 * 1024 * 1024,
        first_ts_us: T0,
        last_ts_us: T0 + 600_000_000,
        anomalies: [],
      },
    ],
    skipped: [{ name: 'notes.txt', reason: 'unrecognized' }],
    truncated: false,
  };
}
