import { type LayoutInput, type Positions, runLayout } from './forceLayout';

/** Past this delay, the worker is abandoned and the layout runs on the main thread. */
export const WORKER_TIMEOUT_MS = 5_000;

/** Layout on the main thread; the start positions if ForceAtlas2 fails. */
function fallback(input: LayoutInput): Positions {
  try {
    return runLayout(input);
  } catch {
    return Object.fromEntries(input.nodes.map((n) => [n.id, { x: n.x, y: n.y }]));
  }
}

/**
 * Positions of the force layout, computed in a web worker (`layout.worker.ts`, ADR-018). Falls
 * back to the main thread when workers are unavailable, the worker fails or does not answer
 * within {@link WORKER_TIMEOUT_MS}: the graph is bounded, the iterations too. Always resolves.
 */
export function computeLayout(input: LayoutInput): Promise<Positions> {
  if (typeof Worker === 'undefined') return Promise.resolve(fallback(input));
  return new Promise((resolve) => {
    let worker: Worker;
    try {
      worker = new Worker(new URL('./layout.worker.ts', import.meta.url), { type: 'module' });
    } catch {
      resolve(fallback(input));
      return;
    }
    let settled = false;
    const settle = (positions: () => Positions) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      worker.terminate();
      resolve(positions());
    };
    const timer = setTimeout(() => {
      settle(() => fallback(input));
    }, WORKER_TIMEOUT_MS);
    worker.onmessage = (event: MessageEvent<Positions>) => {
      settle(() => event.data);
    };
    worker.onerror = (event) => {
      event.preventDefault();
      settle(() => fallback(input));
    };
    worker.postMessage(input);
  });
}
