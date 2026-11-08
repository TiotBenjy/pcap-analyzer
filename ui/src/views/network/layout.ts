import { type LayoutInput, type Positions, runLayout } from './forceLayout';

/**
 * Positions of the force layout, computed in a web worker (`layout.worker.ts`, ADR-018). Falls
 * back to the main thread when workers are unavailable or the worker fails: the graph is
 * bounded, the iterations too.
 */
export function computeLayout(input: LayoutInput): Promise<Positions> {
  if (typeof Worker === 'undefined') return Promise.resolve(runLayout(input));
  return new Promise((resolve) => {
    let worker: Worker;
    try {
      worker = new Worker(new URL('./layout.worker.ts', import.meta.url), { type: 'module' });
    } catch {
      resolve(runLayout(input));
      return;
    }
    worker.onmessage = (event: MessageEvent<Positions>) => {
      worker.terminate();
      resolve(event.data);
    };
    worker.onerror = (event) => {
      event.preventDefault();
      worker.terminate();
      resolve(runLayout(input));
    };
    worker.postMessage(input);
  });
}
