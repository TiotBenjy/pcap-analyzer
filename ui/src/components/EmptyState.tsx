import type { LucideIcon } from 'lucide-react';
import { Inbox } from 'lucide-react';
import { type ReactNode, useContext } from 'react';
import { useTranslation } from 'react-i18next';
import { useTimeRange, useViewRange } from '../app/timeRange';
import { InRouterContext } from '../app/timeRangeContext';
import { Button } from './Button';

interface EmptyStateProps {
  title: string;
  description?: string;
  icon?: LucideIcon;
  action?: ReactNode;
}

/**
 * Explicit empty state: neutral icon, one short sentence, optional action. Never a blank block.
 * Under the time range of a view that applies it, a plain empty state (no explanation nor action
 * of its own: nothing at all to show) says that the range is empty and offers to clear it
 * (docs/specs/time-filter.md).
 */
export function EmptyState({ title, description, icon: Icon = Inbox, action }: EmptyStateProps) {
  // Rendered outside the router in some tests: the range part needs it.
  const inRouter = useContext(InRouterContext);
  return (
    <div role="status" className="flex flex-col items-center justify-center gap-2 px-4 py-10 text-center">
      <Icon aria-hidden size={20} strokeWidth={1.75} className="text-faint" />
      <p className="font-medium">{title}</p>
      {description !== undefined && <p className="max-w-prose text-muted">{description}</p>}
      {action !== undefined && <div className="mt-2">{action}</div>}
      {action === undefined && description === undefined && inRouter && <RangeHint />}
    </div>
  );
}

function RangeHint() {
  const { t } = useTranslation();
  const range = useViewRange();
  const { setRange } = useTimeRange();
  if (range === null) return null;
  return (
    <>
      <p className="max-w-prose text-muted">{t('timeRange.emptyText')}</p>
      <div className="mt-2">
        <Button
          onClick={() => {
            setRange(null);
          }}
        >
          {t('timeRange.clear')}
        </Button>
      </div>
    </>
  );
}
