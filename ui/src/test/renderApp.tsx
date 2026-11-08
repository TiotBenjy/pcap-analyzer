import '../i18n';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { createMemoryHistory, RouterProvider } from '@tanstack/react-router';
import { render } from '@testing-library/react';
import { createAppRouter, router as appRouter } from '../app/router';

/**
 * Loads the code-split views (every route component and the import wizard) once per test file,
 * before its first test.
 *
 * Without this, the first test of a file that reaches a lazy view pays for transforming and
 * importing that view's whole module graph *inside* its `findBy*` / `waitFor` window: about 1 s
 * on an idle machine, several seconds when parallel gates load the CPU. That cost belongs to the
 * module loader, not to the behaviour under test. Later tests in the file hit the module cache.
 *
 * The ECharts renderer is deliberately left out: importing it costs about 2 s and no app-level
 * test looks at a chart. A test that renders a view with charts mocks `components/Chart`.
 */
async function preloadLazyModules(): Promise<void> {
  const routeComponents = Object.values(appRouter.routesById).map((route) => {
    const component = route.options.component as { preload?: () => Promise<void> | undefined } | undefined;
    return component?.preload?.();
  });
  await Promise.all([
    ...routeComponents,
    // React.lazy module (no preload handle): importing it fills the shared module cache.
    import('../views/sessions/import/ImportWizard'),
  ]);
}

await preloadLazyModules();
// jsdom parses its built-in stylesheet on the first getComputedStyle() call (0.15 to 0.3 s on a
// busy machine). Role queries call it to skip hidden elements: pay it here, not in the first query.
getComputedStyle(document.documentElement);

/** A fresh query cache per test: no retries, no garbage-collection timers left behind. */
function createTestQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: { retry: false, staleTime: 0, gcTime: Infinity, refetchOnWindowFocus: false },
      mutations: { retry: false, gcTime: Infinity },
    },
  });
}

/** Renders the whole application (AppShell + routes) at `path`, with a fresh query cache. */
export function renderApp(path: string) {
  const qc = createTestQueryClient();
  const router = createAppRouter(createMemoryHistory({ initialEntries: [path] }));
  const utils = render(
    <QueryClientProvider client={qc}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
  return { ...utils, router, qc };
}

/** Makes `matchMedia` report `wide` for min-width queries (table vs cards layouts). */
export function setViewportWide(wide: boolean): void {
  window.matchMedia = (query: string) =>
    ({
      matches: query.includes('min-width') ? wide : false,
      media: query,
      onchange: null,
      addEventListener: () => undefined,
      removeEventListener: () => undefined,
      addListener: () => undefined,
      removeListener: () => undefined,
      dispatchEvent: () => false,
    }) as MediaQueryList;
}
