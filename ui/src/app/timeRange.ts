import { useNavigate, useRouter, useRouterState } from '@tanstack/react-router';
import { useCallback, useEffect, useMemo } from 'react';
import { parseRange, type TimeRange } from '../lib/timeRange';
import { findNavItem } from './nav';
import { parseSessionPath } from './session';
import { TIME_FILTER_VIEWS } from './timeFilterViews';

/**
 * Session that the range of the URL belongs to, per router (tests create several). The session
 * route keeps the range across views (`retainSearchParams`), including on a navigation to another
 * session (import wizard, links built elsewhere): a range seen with another session than its own
 * is ignored at once and removed from the URL by `useRangeGuard`, so it never leaks.
 */
const owners = new WeakMap<object, string>();

function leaked(router: object, pathname: string, range: TimeRange | null): boolean {
  if (range === null) return false;
  const owner = owners.get(router);
  const session = parseSessionPath(pathname)?.sessionId;
  return owner !== undefined && session !== undefined && owner !== session;
}

function useUrlRange(): TimeRange | null {
  const search = useRouterState({ select: (s) => s.location.search as Record<string, unknown> });
  const fromUs = search.from_us;
  const toUs = search.to_us;
  return useMemo(() => parseRange({ from_us: fromUs, to_us: toUs }), [fromUs, toUs]);
}

/**
 * Global time filter of the session views (docs/specs/time-filter.md, ADR-030). The range lives
 * in the URL of the session (`from_us`, `to_us` search params, kept across the views of that
 * session), so it is shared by every view, survives a reload and follows the back button.
 */
export function useTimeRange(): {
  range: TimeRange | null;
  /** Replaces the range (`null` clears it); a new history entry unless `replace`. */
  setRange: (range: TimeRange | null, options?: { replace?: boolean }) => void;
} {
  const urlRange = useUrlRange();
  const router = useRouter();
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  const range = leaked(router, pathname, urlRange) ? null : urlRange;
  const navigate = useNavigate();
  const setRange = useCallback(
    (next: TimeRange | null, options?: { replace?: boolean }) => {
      void navigate({
        to: '.',
        search: ((prev: Record<string, unknown>) => ({
          ...prev,
          from_us: next?.fromUs,
          to_us: next?.toUs,
        })) as never,
        replace: options?.replace ?? false,
      });
    },
    [navigate],
  );
  return { range, setRange };
}

/**
 * Mounted once by the session layout: records which session the range of the URL belongs to,
 * and removes a range brought from another session (replacing the history entry).
 */
export function useRangeGuard(sessionId: string): void {
  const urlRange = useUrlRange();
  const router = useRouter();
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  const navigate = useNavigate();
  const isLeaked = leaked(router, pathname, urlRange);
  useEffect(() => {
    if (urlRange === null) {
      owners.delete(router);
    } else if (isLeaked) {
      // The owner stays until the range is gone from the URL: renders in between still see
      // the range as foreign. The location shown (not `.`, which may still resolve
      // from the previous session).
      void navigate({
        to: pathname,
        search: ((prev: Record<string, unknown>) => ({ ...prev, from_us: undefined, to_us: undefined })) as never,
        replace: true,
      } as never);
    } else {
      // The session of the location, not the route param, which may lag one render behind.
      owners.set(router, parseSessionPath(pathname)?.sessionId ?? sessionId);
    }
  }, [router, sessionId, urlRange, isLeaked, navigate, pathname]);
}

/** True when the view of `pathname` applies the time range (registry `timeFilterViews.ts`). */
export function appliesTimeRange(pathname: string): boolean {
  if (parseSessionPath(pathname) === null) return false;
  const item = findNavItem(pathname);
  return item !== undefined && TIME_FILTER_VIEWS.has(item.id);
}

/**
 * The range a view should send to the API: the active one when the current view applies it,
 * else `null` (a view outside the registry shows the whole session).
 */
export function useViewRange(): TimeRange | null {
  const { range } = useTimeRange();
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  return appliesTimeRange(pathname) ? range : null;
}

/**
 * Search validation of the session route: the two bounds, or neither; other parameters (the tab
 * of a view, for example) pass through untouched.
 */
export function validateRangeSearch(search: Record<string, unknown>): { from_us?: number; to_us?: number } {
  const rest = Object.fromEntries(Object.entries(search).filter(([k]) => k !== 'from_us' && k !== 'to_us'));
  const range = parseRange(search);
  return range === null ? rest : { ...rest, from_us: range.fromUs, to_us: range.toUs };
}
