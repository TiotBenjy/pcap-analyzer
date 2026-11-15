import type { TFunction } from 'i18next';
import { ApiError } from '../api/client';
import { describeError } from './errors';

/** Host contacted by the download and the startup check (ADR-015, ADR-025). */
export const DB_IP_HOST = 'download.db-ip.com';

/** Problem types of the GeoIP routes (`netsift-api/src/error.rs`). */
const GEOIP_PROBLEMS = {
  'urn:netsift:problem:geoip-download-failed': 'views.settings.geoip.errors.downloadFailed',
  'urn:netsift:problem:geoip-invalid': 'views.settings.geoip.errors.invalid',
  'urn:netsift:problem:geoip-too-large': 'views.settings.geoip.errors.tooLarge',
  'urn:netsift:problem:geoip-update-running': 'views.settings.geoip.errors.running',
} as const;

/** Message of a failed database update. */
export function geoipUpdateErrorMessage(t: TFunction, error: unknown): string {
  if (error instanceof ApiError && error.kind in GEOIP_PROBLEMS) {
    return t(GEOIP_PROBLEMS[error.kind as keyof typeof GEOIP_PROBLEMS]);
  }
  return describeError(t, error).message;
}

/**
 * Long month of a `YYYY-MM` key (UTC, the publisher's calendar): `October 2026`,
 * `octobre 2026`. The key itself when it is not a month.
 */
export function formatMonth(key: string, lang: string): string {
  const m = /^(\d{4})-(\d{2})$/.exec(key);
  if (m === null) return key;
  const date = Date.UTC(Number(m[1]), Number(m[2]) - 1, 1);
  const options: Intl.DateTimeFormatOptions = { month: 'long', year: 'numeric', timeZone: 'UTC' };
  try {
    return new Intl.DateTimeFormat(lang, options).format(date);
  } catch {
    return new Intl.DateTimeFormat('en', options).format(date);
  }
}
