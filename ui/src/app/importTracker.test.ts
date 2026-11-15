import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiError } from '../api/client';
import * as api from '../api/sessions';
import type { ImportEvent } from '../api/types/ImportEvent';
import {
  cancelTrackedImport,
  closeImportWizard,
  getImportState,
  MAX_WARNINGS,
  onImportSettled,
  openImportWizard,
  resetImportTracker,
  trackImport,
  warningTotal,
} from './importTracker';

vi.mock('../api/sessions');
const m = vi.mocked(api);

const flush = () => new Promise((r) => setTimeout(r, 0));

beforeEach(() => {
  vi.resetAllMocks();
  resetImportTracker();
});

describe('import tracker', () => {
  it('reports a stream that ends without a result as lost', async () => {
    m.streamImportEvents.mockResolvedValue(undefined);
    const settled = vi.fn();
    const off = onImportSettled(settled);
    trackImport('S1', 'office');
    await flush();
    expect(getImportState().current).toMatchObject({ status: 'lost', error: null, streamError: null });
    expect(settled).toHaveBeenCalledTimes(1);
    off();
  });

  it('fails on a 404 stream, treats other stream errors as a lost connection', async () => {
    const http = new ApiError(404, 'urn:netsift:problem:not-found', 'no such session');
    m.streamImportEvents.mockRejectedValue(http);
    trackImport('S1', 'office');
    await flush();
    expect(getImportState().current).toMatchObject({ status: 'failed', streamError: http });

    for (const err of [
      new ApiError(0, 'network', 'Backend unreachable'),
      new ApiError(401, 'urn:netsift:problem:unauthorized', 'Authentication required'),
      new ApiError(500, 'urn:netsift:problem:internal', 'Internal error'),
      new ApiError(502, 'http', 'Bad Gateway'),
    ]) {
      m.streamImportEvents.mockRejectedValue(err);
      trackImport('S1', 'office');
      await flush();
      expect(getImportState().current?.status, String(err.status)).toBe('lost');
    }
  });

  it('reconnects a lost import with a fresh stream', async () => {
    m.streamImportEvents.mockResolvedValueOnce(undefined);
    trackImport('S1', 'office');
    await flush();
    expect(getImportState().current?.status).toBe('lost');
    m.streamImportEvents.mockReturnValue(new Promise(() => undefined));
    trackImport('S1', 'office');
    expect(getImportState().current?.status).toBe('running');
    expect(m.streamImportEvents).toHaveBeenCalledTimes(2);
  });

  it('aborts the previous stream when another import is tracked and ignores its late events', () => {
    const streams: { signal: AbortSignal; emit: (e: ImportEvent) => void }[] = [];
    m.streamImportEvents.mockImplementation((_id, onEvent, signal) => {
      streams.push({ signal, emit: onEvent });
      return new Promise(() => undefined);
    });
    trackImport('S1', 'office');
    trackImport('S2', 'dmz');
    expect(streams[0]?.signal.aborted).toBe(true);
    expect(streams[1]?.signal.aborted).toBe(false);
    streams[0]?.emit({ type: 'failed', message: 'late' });
    expect(getImportState().current).toMatchObject({ sessionId: 'S2', status: 'running' });
  });

  it('caps the warning log but counts every warning', async () => {
    m.streamImportEvents.mockImplementation((_id, onEvent) => {
      const w: ImportEvent = { type: 'warning', id: null, code: 'time_gap', chunk: 1, ts_us: null, detail: {} };
      for (let i = 0; i < MAX_WARNINGS + 5; i++) onEvent(w);
      onEvent({ type: 'done', state: 'ready', packets: 1, flows: 1, anomalies: 1, duration_s: 1 });
      return Promise.resolve();
    });
    trackImport('S1', 'office');
    await flush();
    const cur = getImportState().current;
    expect(cur?.warnings).toHaveLength(MAX_WARNINGS);
    expect(cur?.warningCount).toBe(MAX_WARNINGS + 5);
    expect(cur?.status).toBe('done');
  });

  it('takes the warning total from the progress and the final event', () => {
    const base = { warningCount: 12, progress: null, result: null };
    expect(warningTotal(base)).toBe(12);
    const progress = {
      bytes_done: 1,
      bytes_total: 2,
      chunk_index: 0,
      chunk_count: 1,
      chunk_name: '',
      packets: 0,
      rate_bps: 0,
      eta_s: null,
      phase: 'reading',
      step: null,
      steps_done: 0,
      steps_total: 0,
      warnings_found: 582,
    };
    expect(warningTotal({ ...base, progress })).toBe(582);
    const result = { type: 'done', state: 'ready', packets: 1, flows: 1, anomalies: 600, duration_s: 1 } as const;
    expect(warningTotal({ ...base, progress, result })).toBe(600);
  });

  it('goes back to running when the cancel request fails', async () => {
    m.streamImportEvents.mockReturnValue(new Promise(() => undefined));
    m.cancelImport.mockRejectedValue(new Error('refused'));
    trackImport('S1', 'office');
    await cancelTrackedImport();
    expect(getImportState().current).toMatchObject({ status: 'running' });
    expect(getImportState().current?.cancelError?.message).toBe('refused');
  });

  it('keeps a running import when the wizard closes, forgets a finished one', async () => {
    m.streamImportEvents.mockReturnValue(new Promise(() => undefined));
    trackImport('S1', 'office');
    openImportWizard('folder');
    closeImportWizard();
    expect(getImportState().current?.status).toBe('running');

    m.streamImportEvents.mockImplementation((_id, onEvent) => {
      onEvent({ type: 'failed', message: 'disk full' });
      return Promise.resolve();
    });
    trackImport('S2', 'dmz');
    await flush();
    expect(getImportState().current?.status).toBe('failed');
    closeImportWizard();
    expect(getImportState().current).toBeNull();
  });
});
