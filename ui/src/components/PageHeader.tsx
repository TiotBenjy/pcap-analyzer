import type { ReactNode } from 'react';

interface PageHeaderProps {
  title: string;
  subtitle?: string;
  /** Total counter shown next to the title. */
  count?: ReactNode;
  actions?: ReactNode;
}

export function PageHeader({ title, subtitle, count, actions }: PageHeaderProps) {
  return (
    <header className="flex flex-wrap items-start justify-between gap-x-4 gap-y-2">
      <div className="min-w-0">
        <div className="flex min-w-0 items-center gap-2">
          <h1 className="truncate text-page font-semibold">{title}</h1>
          {count}
        </div>
        {subtitle !== undefined && <p className="mt-0.5 text-muted [overflow-wrap:anywhere]">{subtitle}</p>}
      </div>
      {actions !== undefined && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </header>
  );
}
