import { NAV_ITEMS, type NavItem } from '../../app/nav';
import type { CountScope } from '../../api/types/CountScope';
import type { en } from '../../i18n/en';

/**
 * Views shown as module cards: every analysis view (phase 3, implemented or not), plus the later
 * views once they are implemented (`enabled`).
 */
export const MODULE_ITEMS: readonly NavItem[] = NAV_ITEMS.filter(
  (i) => i.scope === 'session' && (i.group === 'analysis' || (i.group === 'more' && i.enabled)),
);

/** Views with a module description (every session view but Overview and Sources). */
export type ModuleId = keyof (typeof en)['views']['overview']['modules'];

interface ModuleState {
  count: number | null;
  /** Card is a link: the view exists and found something (in the session, under a range). */
  active: boolean;
  /** Dimmed: nothing to show (a link stays a link when only the range is empty). */
  dimmed: boolean;
  /** Why the card is dimmed, `null` when active. */
  reason: 'empty' | 'later' | 'notRun' | null;
}

/**
 * State of a module card. `scope`: `range` when the count is that of the active time range
 * (docs/specs/time-filter.md): a card empty in the range stays a link, dimmed.
 */
export function moduleState(item: NavItem, counts: ReadonlyMap<string, number>, scope: CountScope | null = null): ModuleState {
  const count = counts.get(item.id) ?? null;
  if (!item.enabled) return { count, active: false, dimmed: true, reason: 'later' };
  if (count === null) return { count, active: false, dimmed: true, reason: 'notRun' };
  if (count === 0 && scope === 'range') return { count, active: true, dimmed: true, reason: null };
  if (count === 0) return { count, active: false, dimmed: true, reason: 'empty' };
  return { count, active: true, dimmed: false, reason: null };
}

export const REASON_KEYS = {
  empty: 'views.overview.moduleEmpty',
  later: 'views.overview.moduleLater',
  notRun: 'views.overview.moduleNotRun',
} as const;
