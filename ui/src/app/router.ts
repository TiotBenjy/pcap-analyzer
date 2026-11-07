import {
  createHashHistory,
  createRootRoute,
  createRoute,
  createRouter,
  lazyRouteComponent,
  redirect,
} from '@tanstack/react-router';
import { AppShell } from '../components/AppShell';
import { NotFoundView } from '../views/NotFoundView';
import { NAV_ITEMS } from './nav';

// Every view is code-split: its module (and any chart library it uses) loads on navigation.
const rootRoute = createRootRoute({ component: AppShell, notFoundComponent: NotFoundView });

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
  component: lazyRouteComponent(() => import('../views/captures/CapturesView')),
});

const overviewRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/overview',
  component: lazyRouteComponent(() => import('../views/overview/OverviewView')),
});

const settingsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/settings',
  component: lazyRouteComponent(() => import('../views/settings/SettingsView')),
});

// Views planned for later phases: empty routes sharing one placeholder module.
const IMPLEMENTED = new Set(['/captures', '/overview']);
const placeholderRoutes = NAV_ITEMS.filter((i) => !IMPLEMENTED.has(i.path)).map((item) =>
  createRoute({
    getParentRoute: () => rootRoute,
    path: item.path,
    component: lazyRouteComponent(() => import('../views/PlaceholderView')),
  }),
);

const routeTree = rootRoute.addChildren([indexRoute, capturesRoute, overviewRoute, settingsRoute, ...placeholderRoutes]);

// Hash history: works identically under Vite, a static build, and the Tauri custom protocol.
export const router = createRouter({ routeTree, history: createHashHistory(), defaultPreload: 'intent' });

declare module '@tanstack/react-router' {
  interface Register {
    router: typeof router;
  }
}
