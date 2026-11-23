import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { Skeleton } from '../../components/Skeleton';

/** Placeholder rows of a list being loaded. */
export function ListLoading() {
  const { t } = useTranslation();
  return (
    <div className="flex flex-col gap-2 p-3 sm:p-4" aria-busy="true">
      <span className="sr-only">{t('common.loading')}</span>
      {[0, 1, 2, 3].map((i) => (
        <Skeleton key={i} height={32} />
      ))}
    </div>
  );
}

/** One labelled value of a detail panel. */
export function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex min-w-0 flex-col gap-0.5 sm:flex-row sm:gap-3">
      <dt className="shrink-0 text-meta text-muted sm:w-40">{label}</dt>
      <dd className="min-w-0 flex-1">{children}</dd>
    </div>
  );
}
