import type { TFunction } from 'i18next';
import { ApiError } from '../api/client';

export interface DescribedError {
  /** Translated, user-facing sentence. */
  message: string;
  /** Raw backend or runtime message, shown only as a secondary detail. */
  detail: string | null;
}

/** Translates the common client errors by HTTP status; the raw message becomes a detail. */
export function describeError(t: TFunction, error: unknown): DescribedError {
  const raw = error instanceof Error ? error.message : typeof error === 'string' ? error : null;
  const detail = raw === null || raw.trim() === '' ? null : raw;
  if (!(error instanceof ApiError)) return { message: t('errors.generic'), detail };
  switch (error.status) {
    case 0:
      return { message: t('errors.network'), detail: null };
    case 400:
      return { message: t('errors.badRequest'), detail };
    case 401:
      return { message: t('errors.unauthorized'), detail: null };
    case 403:
      return { message: t('errors.forbidden'), detail };
    case 404:
      return { message: t('errors.notFound'), detail };
    case 409:
      return { message: t('errors.conflict'), detail };
    default:
      return { message: t('errors.generic'), detail };
  }
}
