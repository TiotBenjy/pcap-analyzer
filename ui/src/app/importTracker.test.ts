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
    expect(getImportState().current).toMatchObject({ status: 'failed', lost: true, error: null });
    expect(settled).toHaveBeenCalledTimes(1);
    off();
  });

  it('reports HTTP errors of the stream', async () => {
    m.streamImportEvents.mockRejectedValue(new ApiError(404, 'not_found', 'no such session'));
    trackImport('S1', 'office');
    await flush();
    expect(getImportState().current).toMatchObject({ status: 'failed', lost: false, error: 'no such session' });
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

  it('goes back to running when the cancel request fails', async () => {
    m.streamImportEvents.mockReturnValue(new Promise(() => undefined));
    m.cancelImport.mockRejectedValue(new Error('refused'));
    trackImport('S1', 'office');
    await cancelTrackedImport();
    expect(getImportState().current).toMatchObject({ status: 'running', cancelError: 'refused' });
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
