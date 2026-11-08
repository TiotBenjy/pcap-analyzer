import {
  createHashHistory,
  type RouterHistory,
  createRootRoute,
  createRoute,
  createRouter,
  lazyRouteComponent,
  redirect,
} from '@tanstack/react-router';
import type { ComponentType } from 'react';
import { AppShell } from '../components/AppShell';
import { RootRouteError, RouteError } from '../components/RouteError';
import { NotFoundView } from '../views/NotFoundView';
import { NAV_ITEMS } from './nav';
import { getLastSessionId } from './session';

// Every view is code-split: its module (and any chart library it uses) loads on navigation.
//
// Route layout (ADR-010):
//   /captures                         sessions list and import (no session)
//   /settings                         preferences (no session)
//   /sessions/$sessionId/<view>       analysis views of one session (overview, sources, dns...)
//   /overview, /dns, ...              legacy entry points: redirect to the last opened session
//
// Errors: every route renders `RouteError` (inside the shell, so the navigation stays usable);
// an error in the shell itself falls back to `RootRouteError`, a full page. Never the TanStack
// default screen, which a release build cannot diagnose (no devtools).
const rootRoute = createRootRoute({
  component: AppShell,
  notFoundComponent: NotFoundView,
  errorComponent: RootRouteError,
});

const indexRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/',
  beforeLoad: () => {
    throw redirect({ to: '/captures' });
  },
});

const capturesRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/captures',
  component: lazyRouteComponent(() => import('../views/sessions/CapturesView')),
});

const settingsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/settings',
  component: lazyRouteComponent(() => import('../views/settings/SettingsView')),
});

// --- Session-scoped views ---------------------------------------------------------------------

const sessionRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/sessions/$sessionId',
  component: lazyRouteComponent(() => import('../views/sessions/SessionLayout')),
});

const sessionIndexRoute = createRoute({
  getParentRoute: () => sessionRoute,
  path: '/',
  beforeLoad: ({ params }) => {
    throw redirect({ to: '/sessions/$sessionId/overview', params });
  },
});

// REGISTRATION POINT (ADR-010): one line per implemented session view, sorted by path, so that
// views developed in parallel merge without conflicts. A session nav item (src/app/nav.ts) without
// an entry gets the shared placeholder module. Every module stays code-split.
const SESSION_VIEWS: Partial<Record<string, () => Promise<{ default: ComponentType }>>> = {
  '/connections': () => import('../views/connections/ConnectionsView'),
  '/dns': () => import('../views/dns/DnsView'),
  '/http': () => import('../views/http/HttpView'),
  '/http-headers': () => import('../views/http/HttpHeadersView'),
  '/open-ports': () => import('../views/openPorts/OpenPortsView'),
  '/overview': () => import('../views/overview/OverviewView'),
  '/servers': () => import('../views/servers/ServersView'),
  '/smb': () => import('../views/smb/SmbView'),
  '/sources': () => import('../views/sessions/SourcesView'),
  '/tls': () => import('../views/tls/TlsView'),
};

const loadPlaceholder = () => import('../views/PlaceholderView');
const SESSION_ITEMS = NAV_ITEMS.filter((i) => i.scope === 'session');
const sessionViewRoutes = SESSION_ITEMS.map((item) =>
  createRoute({
    getParentRoute: () => sessionRoute,
    path: item.path,
    component: lazyRouteComponent(SESSION_VIEWS[item.path] ?? loadPlaceholder),
  }),
);

// Legacy top-level paths (`/overview`, `/dns`...): last opened session, else the sessions list.
const legacyRoutes = SESSION_ITEMS.map((item) =>
  createRoute({
    getParentRoute: () => rootRoute,
    path: item.path,
    beforeLoad: () => {
      const sessionId = getLastSessionId();
      if (sessionId === null) throw redirect({ to: '/captures' });
      throw redirect({ to: `/sessions/$sessionId${item.path}`, params: { sessionId } });
    },
  }),
);

const routeTree = rootRoute.addChildren([
  indexRoute,
  capturesRoute,
  settingsRoute,
  sessionRoute.addChildren([
    sessionIndexRoute,
    ...sessionViewRoutes,
  ]),
  ...legacyRoutes,
]);

/** Application router; tests pass a memory history. */
export function createAppRouter(history: RouterHistory = createHashHistory()) {
  return createRouter({ routeTree, history, defaultPreload: 'intent', defaultErrorComponent: RouteError });
}

// Hash history: works identically under Vite, a static build, and the Tauri custom protocol.
export const router = createAppRouter();

declare module '@tanstack/react-router' {
  interface Register {
    router: typeof router;
  }
}
