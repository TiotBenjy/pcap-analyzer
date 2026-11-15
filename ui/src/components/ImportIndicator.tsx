import { CircleAlert, CircleCheck, LoaderCircle, Unplug } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { importFraction, isActive, isFinalizing, reopenImportProgress, stepNumber, useImportState } from '../app/importTracker';
import { cn } from '../lib/cn';
import { formatPercent, labelled } from '../lib/format';

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
  const lost = current.status === 'lost';
  const fraction = importFraction(current.progress?.bytes_done ?? 0, current.progress?.bytes_total ?? 0);
  const percent = formatPercent(fraction, 0, i18n.language);
  let text: string = t('views.import.indicatorDone');
  let Icon = CircleCheck;
  const progress = current.progress;
  if (active && progress !== null && isFinalizing(progress)) {
    text = t('views.import.indicatorFinalizing', { n: stepNumber(progress), total: progress.steps_total });
    Icon = LoaderCircle;
  } else if (active) {
    text = t('views.import.indicator', { percent });
    Icon = LoaderCircle;
  } else if (lost) {
    text = t('views.import.indicatorLost');
    Icon = Unplug;
  } else if (failed) {
    text = t('views.import.indicatorFailed');
    Icon = CircleAlert;
  }

  return (
    <button
      type="button"
      onClick={reopenImportProgress}
      aria-label={labelled(t('views.import.indicatorLabel'), text, i18n.language)}
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
          lost && 'text-warning',
          !active && !failed && !lost && 'text-success',
        )}
      />
      <span className="num truncate">{text}</span>
    </button>
  );
}
