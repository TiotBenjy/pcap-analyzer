import { CircleAlert, CircleCheck, LoaderCircle } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { importFraction, isActive, reopenImportProgress, useImportState } from '../app/importTracker';
import { cn } from '../lib/cn';

/**
 * Discreet header indicator of the tracked import: percentage while it runs, final state once it
 * ends. Clicking it reopens the import progress.
 */
export function ImportIndicator() {
  const { t, i18n } = useTranslation();
  const { current } = useImportState();
  if (current === null) return null;

  const active = isActive(current);
  const failed = current.status === 'failed';
  const fraction = importFraction(current.progress?.bytes_done ?? 0, current.progress?.bytes_total ?? 0);
  const percent = new Intl.NumberFormat(i18n.language, { style: 'percent', maximumFractionDigits: 0 }).format(fraction);
  const text = active
    ? t('views.import.indicator', { percent })
    : failed
      ? t('views.import.indicatorFailed')
      : t('views.import.indicatorDone');
  const Icon = active ? LoaderCircle : failed ? CircleAlert : CircleCheck;

  return (
    <button
      type="button"
      onClick={reopenImportProgress}
      aria-label={`${t('views.import.indicatorLabel')}: ${text}`}
      title={t('views.import.indicatorLabel')}
      data-testid="import-indicator"
      className="inline-flex h-8 min-w-0 shrink items-center gap-1.5 rounded-md px-2 text-meta font-medium text-muted hover:bg-subtle hover:text-fg"
    >
      <Icon
        aria-hidden
        size={16}
        strokeWidth={1.75}
        className={cn(
          'shrink-0',
          active && 'text-accent motion-safe:animate-spin',
          failed && 'text-danger',
          !active && !failed && 'text-success',
        )}
      />
      <span className="num truncate">{text}</span>
    </button>
  );
}
