import { useTranslation } from 'react-i18next';
import { useGeoipStatus, useGeoipUpdate } from '../api/geoipQueries';
import { useServerInfo } from '../api/queries';
import type { GeoipFreshness } from '../api/types/GeoipFreshness';
import { GeoipUpdateFeedback } from '../components/GeoipUpdateFeedback';
import { formatMonth, geoipUpdateErrorMessage } from '../lib/geoip';
import { NoticeSlot } from './NoticeSlot';
import type { Notice, NoticeSlotProps } from './types';

// GeoIP notice (P4.9): no database, or one built before the current month. The offer comes from
// the server (local check, confirmed by DB-IP when the user enabled the startup check); the
// button starts the download of ADR-015. Dismissed until the month changes.

/** The offer of a status, if it is a well-formed one. */
function offerOf(status: GeoipFreshness | undefined): GeoipFreshness['offer'] {
  // Defensive: a test double may answer another shape.
  const offer: unknown = status?.offer;
  if ((offer === 'download' || offer === 'update') && typeof status?.current_month === 'string') return offer;
  return null;
}

export function GeoipNotice(slot: NoticeSlotProps) {
  const { t, i18n } = useTranslation();
  const status = useGeoipStatus();
  const info = useServerInfo();
  const { mutation, downloading, progress } = useGeoipUpdate();

  const data = status.data;
  const offer = offerOf(data);
  let notice: Notice | null = null;
  if (data !== undefined && offer !== null) {
    const month = (key: string | null) => (key === null ? '' : formatMonth(key, i18n.language));
    let message: string;
    if (offer === 'download' || data.built_month === null) message = t('views.geoipPrompt.missing');
    else if (data.published_month !== null && data.published_month !== data.built_month)
      message = t('views.geoipPrompt.outdatedPublished', {
        month: month(data.built_month),
        published: month(data.published_month),
      });
    else message = t('views.geoipPrompt.outdated', { month: month(data.built_month) });

    const busy = mutation.isPending;
    const readOnly = info.data?.read_only ?? false;
    let disabledReason: string | undefined;
    if (readOnly) disabledReason = t('views.settings.geoip.readOnly');
    else if (busy) disabledReason = t('views.settings.geoip.errors.running');
    const feedback = busy || mutation.isError || mutation.isSuccess;

    notice = {
      dismissKey: data.current_month,
      message,
      detail: feedback ? (
        <GeoipUpdateFeedback
          pending={busy}
          downloading={downloading}
          progress={progress}
          error={mutation.isError ? geoipUpdateErrorMessage(t, mutation.error) : null}
          success={mutation.isSuccess}
        />
      ) : (
        t('views.geoipPrompt.host')
      ),
      actions: [
        {
          label: offer === 'download' ? t('views.geoipPrompt.download') : t('views.geoipPrompt.update'),
          primary: true,
          disabled: busy || readOnly,
          ...(disabledReason === undefined ? {} : { title: disabledReason }),
          onClick: () => {
            mutation.mutate({ kind: 'download' });
          },
        },
      ],
    };
  }
  return <NoticeSlot slot={slot} notice={notice} />;
}
