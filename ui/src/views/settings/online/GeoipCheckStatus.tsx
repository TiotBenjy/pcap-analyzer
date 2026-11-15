import { useTranslation } from 'react-i18next';
import { useGeoipStatus } from '../../../api/geoipQueries';
import { KeepTogether } from '../../../components/KeepTogether';
import { DB_IP_HOST, formatMonth } from '../../../lib/geoip';
import type { OnlineExtensionProps } from './extensions';

/**
 * Under "Check for a new GeoIP database at startup": month of the installed database and, when
 * the check is on, its result at this start (P4.9). Plain, muted text: a failure is not an error.
 * The check runs once, at startup, with the setting of that time.
 */
export function GeoipCheckStatus({ enabled, readOnly }: OnlineExtensionProps) {
  const { t, i18n } = useTranslation();
  const status = useGeoipStatus();
  const data = status.data;
  if (data === undefined || typeof data.current_month !== 'string') return null;
  const month = (key: string) => formatMonth(key, i18n.language);

  let check: string | null = null;
  if (enabled) {
    switch (data.online) {
      case 'off':
        // On now but not run: turned on during this run (a read-only server never runs it).
        check = readOnly ? null : t('views.geoipPrompt.checkOff');
        break;
      case 'not_needed':
        check = t('views.geoipPrompt.checkNotNeeded');
        break;
      case 'pending':
        check = t('views.geoipPrompt.checkPending');
        break;
      case 'published':
        check =
          data.published_month === null
            ? null
            : t('views.geoipPrompt.checkPublished', { month: month(data.published_month) });
        break;
      case 'not_published':
        check = t('views.geoipPrompt.checkNotPublished');
        break;
      case 'failed':
        check = t('views.geoipPrompt.checkFailed');
        break;
    }
  }

  return (
    <div className="flex min-w-0 flex-col gap-0.5 text-meta text-muted" data-testid="geoip-check-status">
      <span className="break-words">
        {data.built_month === null
          ? t('views.geoipPrompt.installedNone')
          : t('views.geoipPrompt.installed', { month: month(data.built_month) })}
      </span>
      {check !== null && (
        <span className="break-words">
          <KeepTogether text={check} word={DB_IP_HOST} />
        </span>
      )}
    </div>
  );
}
