import { useRouterState } from '@tanstack/react-router';
import { CalendarRange, X } from 'lucide-react';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { appliesTimeRange, useTimeRange } from '../app/timeRange';
import { parseSessionPath } from '../app/session';
import { cn } from '../lib/cn';
import { formatPreciseTimestamp, timeZoneLabel } from '../lib/format';
import { rangeText } from '../lib/timeRange';
import { useMediaQuery } from '../lib/useMediaQuery';
import { Button } from './Button';
import { TimeRangeDialog } from './TimeRangeDialog';

/** Below this width the chip shows times only (or dates only for a range over several days). */
const SM_QUERY = '(min-width: 640px)';


/**
 * Active time range of the session views, in the header (docs/specs/time-filter.md): the range
 * (click to edit it) and a button that clears it. Dimmed on a view that does not apply it.
 */
export function TimeRangeChip() {
  const { t } = useTranslation();
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  const { range, setRange } = useTimeRange();
  const [editing, setEditing] = useState(false);
  const wide = useMediaQuery(SM_QUERY);
  if (range === null || parseSessionPath(pathname) === null) return null;
  const applied = appliesTimeRange(pathname);
  const join = (from: string, to: string) => t('timeRange.rangeText', { from, to });
  const precise = `${join(formatPreciseTimestamp(range.fromUs), formatPreciseTimestamp(range.toUs))} ${timeZoneLabel()}`;
  return (
    <div
      data-testid="time-range-chip"
      data-applied={String(applied)}
      className={cn('flex shrink-0 items-center rounded-md border border-line', !applied && 'opacity-60')}
    >
      <button
        type="button"
        title={applied ? precise : `${t('timeRange.notApplied')}. ${precise}`}
        aria-label={t('timeRange.chipLabel', { range: precise })}
        onClick={() => {
          setEditing(true);
        }}
        className="flex h-8 min-w-0 items-center gap-1.5 rounded-l-md pr-1 pl-2 text-fg hover:bg-subtle"
      >
        <CalendarRange aria-hidden size={16} strokeWidth={1.75} className="shrink-0 text-muted" />
        <span className="num truncate">{rangeText(range, !wide, join)}</span>
      </button>
      <Button
        variant="ghost"
        icon
        className="rounded-l-none"
        aria-label={t('timeRange.clear')}
        title={t('timeRange.clear')}
        onClick={() => {
          setRange(null);
        }}
      >
        <X aria-hidden size={16} strokeWidth={1.75} />
      </Button>
      <TimeRangeDialog
        open={editing}
        onClose={() => {
          setEditing(false);
        }}
        initial={range}
        onApply={(next) => {
          setRange(next);
        }}
      />
    </div>
  );
}
