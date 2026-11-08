import { useEffect, useState } from 'react';
import { METHOD_GROUPS, type MethodGroup } from '../../api/http';
import { useSession } from '../../api/sessionQueries';
import type { HttpCount } from '../../api/types/HttpCount';
import type { FilterOption } from '../../components/FilterBar';
import { sameLocalDay } from '../../lib/format';

/** Value of `value` once it stopped changing for `ms`. */
export function useDebounced<T>(value: T, ms = 300): T {
  const [settled, setSettled] = useState(value);
  useEffect(() => {
    const id = window.setTimeout(() => {
      setSettled(value);
    }, ms);
    return () => {
      window.clearTimeout(id);
    };
  }, [value, ms]);
  return settled;
}

/** Session state of an HTTP view: data can be requested only when the session is ready. */
export function useViewableSession(sessionId: string) {
  const session = useSession(sessionId);
  const state = session.data?.state;
  const first = session.data?.first_ts_us ?? null;
  const last = session.data?.last_ts_us ?? null;
  return {
    session,
    viewable: state === 'ready' || state === 'incomplete',
    /** The whole capture fits in one local day: times are shown without the date. */
    oneDay: first !== null && last !== null && sameLocalDay(first, last),
  };
}

/** Method toggles of the filter bars: every group, with its count (0 when absent). */
export function methodFilters(
  counts: readonly HttpCount[] | undefined,
  disabled: ReadonlySet<string>,
  otherLabel: string,
): FilterOption[] {
  return METHOD_GROUPS.map((m) => ({
    id: m,
    label: m === 'other' ? otherLabel : m,
    count: counts?.find((c) => c.key === m)?.count ?? 0,
    active: !disabled.has(m),
  }));
}

/** `methods` parameter of the list routes: omitted when every group is on. */
export function methodParam(disabled: ReadonlySet<string>): MethodGroup[] | undefined {
  return disabled.size === 0 ? undefined : METHOD_GROUPS.filter((m) => !disabled.has(m));
}
