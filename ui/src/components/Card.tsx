import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { cn } from '../lib/cn';

interface CardProps {
  title?: ReactNode;
  /** Right-aligned header content (display options, counters, exports). Wraps under the title on narrow widths. */
  actions?: ReactNode;
  /**
   * Filters of the card content (search, toggles, selects, active filter chips): a band of the
   * header, under the title, in every view (docs/UI_GUIDELINES.md).
   */
  filters?: ReactNode;
  children: ReactNode;
  className?: string;
  /** Removes body padding (tables, charts that manage their own spacing). */
  flush?: boolean;
}

export function Card({ title, actions, filters, children, className, flush = false }: CardProps) {
  const { t } = useTranslation();
  const hasTop = title !== undefined || actions !== undefined;
  return (
    <section className={cn('min-w-0 rounded-lg border border-line bg-surface', className)}>
      {(hasTop || filters !== undefined) && (
        <header className="border-b border-line">
          {hasTop && (
            <div className="flex flex-wrap items-center justify-between gap-2 px-3 py-2.5 sm:px-4">
              {title !== undefined && <h2 className="min-w-0 truncate text-card font-medium">{title}</h2>}
              {actions !== undefined && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
            </div>
          )}
          {filters !== undefined && (
            <div
              role="group"
              aria-label={t('common.filters')}
              data-testid="card-filters"
              className={cn('relative flex min-w-0 flex-col gap-2 px-3 py-2.5 sm:px-4', hasTop && 'border-t border-line')}
            >
              {filters}
            </div>
          )}
        </header>
      )}
      <div className={cn(!flush && 'p-3 sm:p-4')}>{children}</div>
    </section>
  );
}
