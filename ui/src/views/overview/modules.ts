import { NAV_ITEMS, type NavItem } from '../../app/nav';
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
  /** Card is a link: the view exists and found something. */
  active: boolean;
  /** Why the card is dimmed, `null` when active. */
  reason: 'empty' | 'later' | 'notRun' | null;
}

export function moduleState(item: NavItem, counts: ReadonlyMap<string, number>): ModuleState {
  const count = counts.get(item.id) ?? null;
  if (!item.enabled) return { count, active: false, reason: 'later' };
  if (count === null) return { count, active: false, reason: 'notRun' };
  if (count === 0) return { count, active: false, reason: 'empty' };
  return { count, active: true, reason: null };
}

export const REASON_KEYS = {
  empty: 'views.overview.moduleEmpty',
  later: 'views.overview.moduleLater',
  notRun: 'views.overview.moduleNotRun',
} as const;
