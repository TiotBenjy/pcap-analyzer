import { BarChart3 } from 'lucide-react';
import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { cn } from '../lib/cn';
import { EmptyState } from './EmptyState';
import { ErrorState } from './ErrorState';
import { MiddleTruncate } from './MiddleTruncate';
import { Skeleton } from './Skeleton';

/** Part of a stacked bar (both directions of a pair, for instance). */
export interface BarSegment {
  value: number;
  color: string;
}

export interface BarItem {
  /** Stable key, passed to `onSelect`. */
  key: string;
  label: string;
  /** Full description on hover (exact value, share, full name); the label by default. */
  title?: string;
  value: number;
  /** Formatted value, written at the end of the row: never truncated. */
  valueText: string;
  /** Secondary text before the value, in grey (hosts, share). */
  detail?: string;
  /** Element before the label (flag, status dot). */
  lead?: ReactNode;
  /** Bar color (CSS color); the accent by default. */
  color?: string;
  /** Stacked parts of the bar instead of a single one (their sum is the value). */
  segments?: readonly BarSegment[];
  /** "Other" or "unknown" row: lighter bar. */
  muted?: boolean;
  /** `false` keeps the row plain text in a list with `onSelect` ("other" rows). */
  selectable?: boolean;
  /** Highlighted row (current filter, rows of the selected node). */
  active?: boolean;
  mono?: boolean;
  /** `middle` keeps both ends of long identifiers (cipher suites). */
  truncate?: 'end' | 'middle';
}

interface BarListProps {
  items: readonly BarItem[];
  /** Accessible name of the list. */
  ariaLabel: string;
  /** Value of a full bar; the largest value by default (bars of several lists can share it). */
  max?: number;
  /** Makes every row a button (filter on that entry). */
  onSelect?: (key: string) => void;
  /** Accessible label of the action of a row. */
  selectLabel?: (item: BarItem) => string;
  loading?: boolean;
  /** Rows of the loading skeleton. */
  loadingRows?: number;
  error?: string | null;
  onRetry?: () => void;
  emptyText?: string;
  className?: string;
}

/**
 * The only horizontal bar chart of the UI (rankings, top N, countries, pairs): one row per entry
 * with its label (truncated, full text on hover), a value that is always fully visible, and a
 * proportional bar below. HTML rather than a chart: flags and dots fit, labels never overlap,
 * rows can be buttons, and narrow cards keep readable values.
 */
export function BarList({
  items,
  ariaLabel,
  max,
  onSelect,
  selectLabel,
  loading = false,
  loadingRows = 4,
  error = null,
  onRetry,
  emptyText,
  className,
}: BarListProps) {
  const { t } = useTranslation();
  if (loading) {
    return (
      <div className={cn('flex flex-col gap-2', className)} aria-busy="true">
        <span className="sr-only">{t('common.loading')}</span>
        {Array.from({ length: loadingRows }, (_, i) => (
          <Skeleton key={i} height={28} />
        ))}
      </div>
    );
  }
  if (error !== null) return <ErrorState message={error} {...(onRetry === undefined ? {} : { onRetry })} />;
  if (items.length === 0) return <EmptyState icon={BarChart3} title={emptyText ?? t('common.noData')} />;

  const full = Math.max(max ?? 0, ...items.map((i) => i.value), 1);
  const width = (v: number) => `${Math.min(100, Math.max(0, (100 * v) / full))}%`;
  return (
    <ol aria-label={ariaLabel} className={cn('flex min-w-0 flex-col gap-1', className)}>
      {items.map((item) => {
        const title = item.title ?? item.label;
        const segments = item.segments ?? [{ value: item.value, color: item.color ?? 'var(--color-accent)' }];
        const content = (
          <>
            <span className="flex min-w-0 items-center gap-2">
              {item.lead}
              {item.truncate === 'middle' ? (
                <MiddleTruncate text={item.label} title={title} className={cn('flex-1', item.mono && 'font-mono')} />
              ) : (
                <span data-testid="truncatable" title={title} className={cn('min-w-0 flex-1 truncate', item.mono && 'font-mono')}>
                  {item.label}
                </span>
              )}
              {item.detail !== undefined && <span className="num shrink-0 text-meta text-muted">{item.detail}</span>}
              <span className="num shrink-0">{item.valueText}</span>
            </span>
            <span aria-hidden className="flex h-1.5 w-full overflow-hidden rounded-full bg-subtle">
              {segments.map((s, i) => (
                <span
                  key={i}
                  className={cn('block h-full', item.muted && 'opacity-50')}
                  style={{ width: width(s.value), backgroundColor: s.color }}
                />
              ))}
            </span>
          </>
        );
        const row = cn('flex w-full min-w-0 flex-col gap-1 rounded-md px-2 py-1 text-left', item.active === true && 'bg-accent-soft');
        return (
          <li key={item.key} className="min-w-0" {...(item.active === true ? { 'data-active': 'true' } : {})}>
            {onSelect === undefined || item.selectable === false ? (
              <div className={row}>{content}</div>
            ) : (
              <button
                type="button"
                aria-label={selectLabel?.(item)}
                aria-pressed={item.active === true}
                onClick={() => {
                  onSelect(item.key);
                }}
                className={cn(row, 'min-h-8 hover:bg-subtle')}
              >
                {content}
              </button>
            )}
          </li>
        );
      })}
    </ol>
  );
}
