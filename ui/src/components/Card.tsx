import type { ReactNode } from 'react';
import { cn } from '../lib/cn';

interface CardProps {
  title?: ReactNode;
  /** Right-aligned header content (actions, counters). Wraps under the title on narrow widths. */
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  /** Removes body padding (tables, charts that manage their own spacing). */
  flush?: boolean;
}

export function Card({ title, actions, children, className, flush = false }: CardProps) {
  return (
    <section className={cn('min-w-0 rounded-lg border border-line bg-surface', className)}>
      {(title !== undefined || actions !== undefined) && (
        <header className="flex flex-wrap items-center justify-between gap-2 border-b border-line px-3 py-2.5 sm:px-4">
          {title !== undefined && <h2 className="min-w-0 truncate text-card font-medium">{title}</h2>}
          {actions !== undefined && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className={cn(!flush && 'p-3 sm:p-4')}>{children}</div>
    </section>
  );
}
