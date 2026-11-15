import { useTranslation } from 'react-i18next';
import type { GeoipUpdate } from '../api/types/GeoipUpdate';
import { formatBytes } from '../lib/format';

// Progress and result of a country database update, shown the same way wherever the update
// starts (Settings > About, GeoIP notice).

export interface GeoipUpdateFeedbackProps {
  pending: boolean;
  downloading: boolean;
  progress: GeoipUpdate | undefined;
  error: string | null;
  success: boolean;
  /** The download succeeded but brought nothing newer than the previous database. */
  notNewer?: boolean;
}

export function GeoipUpdateFeedback({
  pending,
  downloading,
  progress,
  error,
  success,
  notNewer = false,
}: GeoipUpdateFeedbackProps) {
  const { t, i18n } = useTranslation();
  if (pending) {
    // Only the phase is announced (role="status"); the byte counter changes twice a second and
    // stays out of the live region.
    const fetching = downloading && progress?.phase !== 'installing';
    const phase = fetching ? t('views.settings.geoip.downloading') : t('views.settings.geoip.installing');
    let counter: string | null = null;
    let ratio: number | null = null;
    if (fetching) {
      const received = progress?.received_bytes ?? 0;
      const total = progress?.total_bytes ?? null;
      if (total !== null && total > 0) {
        ratio = Math.min(1, received / total);
        counter = t('views.settings.geoip.progressOf', {
          received: formatBytes(received, i18n.language),
          total: formatBytes(total, i18n.language),
        });
      } else if (received > 0) {
        counter = t('views.settings.geoip.progressBytes', { received: formatBytes(received, i18n.language) });
      }
    }
    return (
      <div className="flex min-w-0 flex-col gap-1" data-testid="geoip-progress">
        <span role="status" className="break-words text-meta">
          {phase}
        </span>
        {counter !== null && (
          <span className="num break-words text-meta text-muted" data-testid="geoip-progress-bytes">
            {counter}
          </span>
        )}
        {ratio !== null && (
          <div className="h-1.5 w-full max-w-xs overflow-hidden rounded-full bg-subtle" aria-hidden>
            <div className="h-full bg-accent" style={{ width: `${Math.round(ratio * 100)}%` }} />
          </div>
        )}
      </div>
    );
  }
  if (error !== null) {
    return (
      <p role="alert" className="break-words text-meta text-danger">
        {error}
      </p>
    );
  }
  if (success && notNewer) {
    return (
      <p role="status" className="break-words text-meta">
        {t('views.geoipPrompt.notNewer')}
      </p>
    );
  }
  if (success) {
    return (
      <p role="status" className="break-words text-meta text-success">
        {t('views.settings.geoip.updated')}
      </p>
    );
  }
  return null;
}
