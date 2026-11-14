import { afterEach, describe, expect, it, vi } from 'vitest';
import { computeLayout, WORKER_TIMEOUT_MS } from './layout';

const input = {
  nodes: [
    { id: 'a', x: 1, y: 0, size: 4 },
    { id: 'b', x: -1, y: 0, size: 4 },
  ],
  edges: [{ source: 'a', target: 'b', weight: 10 }],
};

/** Worker stub: `mode` decides how it answers. */
function stubWorker(mode: 'silent' | 'error' | 'answer') {
  const terminated = vi.fn();
  class FakeWorker {
    onmessage: ((e: { data: unknown }) => void) | null = null;
    onerror: ((e: { preventDefault: () => void }) => void) | null = null;
    terminate = terminated;
    postMessage() {
      queueMicrotask(() => {
        if (mode === 'error') this.onerror?.({ preventDefault: () => undefined });
        if (mode === 'answer') this.onmessage?.({ data: { a: { x: 5, y: 5 }, b: { x: 6, y: 6 } } });
      });
    }
  }
  vi.stubGlobal('Worker', FakeWorker);
  return terminated;
}

describe('layout worker', () => {
  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it('uses the answer of the worker', async () => {
    const terminated = stubWorker('answer');
    await expect(computeLayout(input)).resolves.toEqual({ a: { x: 5, y: 5 }, b: { x: 6, y: 6 } });
    expect(terminated).toHaveBeenCalled();
  });

  it('falls back to the main thread when the worker fails', async () => {
    stubWorker('error');
    const positions = await computeLayout(input);
    expect(Object.keys(positions).sort()).toEqual(['a', 'b']);
  });

  it('falls back to the main thread when the worker does not answer in time', async () => {
    vi.useFakeTimers();
    const terminated = stubWorker('silent');
    const pending = computeLayout(input);
    await vi.advanceTimersByTimeAsync(WORKER_TIMEOUT_MS);
    const positions = await pending;
    expect(Object.keys(positions).sort()).toEqual(['a', 'b']);
    expect(terminated).toHaveBeenCalled();
  });
});
