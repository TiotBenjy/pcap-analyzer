import '@testing-library/jest-dom/vitest';
import { cleanup, configure } from '@testing-library/react';
import { afterEach } from 'vitest';

// Safety net for `findBy*` / `waitFor` when parallel gates saturate the CPU. The root causes are
// handled elsewhere (lazy modules preloaded by renderApp, one QueryClient per test, no real
// timers); this only keeps a slow-but-correct render from failing at the 1 s default. Must stay
// below `testTimeout` (vite.config.ts) so a missing element reports which query failed.
configure({ asyncUtilTimeout: 5000 });

// jsdom lacks these browser APIs used by the theme store and charts.
if (typeof window.matchMedia !== 'function') {
  window.matchMedia = (query: string) =>
    ({
      matches: false,
      media: query,
      onchange: null,
      addEventListener: () => undefined,
      removeEventListener: () => undefined,
      addListener: () => undefined,
      removeListener: () => undefined,
      dispatchEvent: () => false,
    }) as MediaQueryList;
}
if (typeof globalThis.ResizeObserver === 'undefined') {
  globalThis.ResizeObserver = class {
    observe(): void {
      /* no layout in jsdom */
    }
    unobserve(): void {
      /* no layout in jsdom */
    }
    disconnect(): void {
      /* no layout in jsdom */
    }
  };
}

afterEach(() => {
  cleanup();
});
