import { useNavigate, useRouterState } from '@tanstack/react-router';
import { useCallback, useMemo } from 'react';
import { parseRange, type TimeRange } from '../lib/timeRange';
import { findNavItem } from './nav';
import { parseSessionPath } from './session';
import { TIME_FILTER_VIEWS } from './timeFilterViews';

/**
 * Global time filter of the session views (docs/specs/time-filter.md, ADR-030). The range lives
 * in the URL of the session (`from_us`, `to_us` search params, kept across views by the session
 * route), so it is shared by every view, survives a reload and follows the back button.
 */
export function useTimeRange(): {
  range: TimeRange | null;
  /** Replaces the range (`null` clears it); a new history entry unless `replace`. */
  setRange: (range: TimeRange | null, options?: { replace?: boolean }) => void;
} {
  const search = useRouterState({ select: (s) => s.location.search as Record<string, unknown> });
  const fromUs = search.from_us;
  const toUs = search.to_us;
  const range = useMemo(() => parseRange({ from_us: fromUs, to_us: toUs }), [fromUs, toUs]);
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

/** Search validation of the session route: the two bounds, or nothing. */
export function validateRangeSearch(search: Record<string, unknown>): { from_us?: number; to_us?: number } {
  const range = parseRange(search);
  return range === null ? {} : { from_us: range.fromUs, to_us: range.toUs };
}
