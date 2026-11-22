import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { cn } from '../lib/cn';

/**
 * The short "Whole session" line, in faint text on a line of its own: under a time range, the
 * value above it (column header, count of a row) was folded at import and stays that of the
 * session (ADR-030, docs/specs/time-filter.md).
 */
export function WholeSessionLine({ className }: { className?: string | undefined }) {
  const { t } = useTranslation();
  return <span className={cn('block leading-tight font-normal text-faint', className)}>{t('timeRange.wholeSession')}</span>;
}

interface WholeSessionHeaderProps {
  /** Short column title ("Messages", "Frames"). */
  label: ReactNode;
  /** A time range applies to the view: the "Whole session" line is shown under the label. */
  ranged: boolean;
  /** Extra classes of the "Whole session" line (`xl:whitespace-nowrap`...). */
  className?: string | undefined;
}

/**
 * Header of a column whose values were folded at import (counters, first and last seen): the
 * short label, and under a time range the "Whole session" line below it. Use it for every such
 * column, in a DataTable (`wholeSessionHeader`) or a hand-made table header.
 */
export function WholeSessionHeader({ label, ranged, className }: WholeSessionHeaderProps) {
  return (
    <>
      {label}
      {ranged && <WholeSessionLine className={className} />}
    </>
  );
}
