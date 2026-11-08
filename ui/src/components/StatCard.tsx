import type { LucideIcon } from 'lucide-react';
import { cn } from '../lib/cn';

interface StatCardProps {
  label: string;
  /** Formatted value; `null` shows a loading placeholder of the final size. */
  value: string | null;
  /** Full value or explanation shown on hover (the value may be truncated). */
  title?: string;
  /** Secondary text under the value (period, anomalies...): up to two lines, full text on hover. */
  hint?: string;
  icon?: LucideIcon;
  /** Colors the hint text only (never a large fill). */
  tone?: 'neutral' | 'warning';
}

/** One key figure of a summary band: label, value (tabular), optional hint. */
export function StatCard({ label, value, title, hint, icon: Icon, tone = 'neutral' }: StatCardProps) {
  return (
    <div className="flex min-w-0 flex-col gap-1 rounded-lg border border-line bg-surface px-3 py-2.5 sm:px-4 sm:py-3">
      <div className="flex min-w-0 items-center gap-1.5 text-meta text-muted">
        {Icon !== undefined && <Icon aria-hidden size={16} strokeWidth={1.75} className="shrink-0 text-faint" />}
        <span className="truncate">{label}</span>
      </div>
      {value === null ? (
        <div aria-hidden className="h-7 w-20 animate-pulse rounded-md bg-subtle" />
      ) : (
        <p data-testid="truncatable" title={title ?? value} className="num truncate text-page leading-7 font-semibold">
          {value}
        </p>
      )}
      {hint !== undefined && (
        <p
          // A blank hint only keeps the card heights even: nothing to truncate.
          {...(hint.trim() === '' ? {} : { 'data-testid': 'truncatable', title: hint })}
          className={cn('line-clamp-2 min-w-0 break-words text-meta', tone === 'warning' ? 'text-warning' : 'text-muted')}
        >
          {hint}
        </p>
      )}
    </div>
  );
}
