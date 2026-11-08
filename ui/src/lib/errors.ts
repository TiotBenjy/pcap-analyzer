import type { TFunction } from 'i18next';
import { ApiError } from '../api/client';

export interface DescribedError {
  /** Translated, user-facing sentence. */
  message: string;
  /** Raw backend or runtime message, shown only as a secondary detail. */
  detail: string | null;
}

/** Problem types of the backend (`netsift-api/src/error.rs`). */
export const PROBLEM = {
  readOnly: 'urn:netsift:problem:read-only',
  forbidden: 'urn:netsift:problem:forbidden',
  tooManyImports: 'urn:netsift:problem:too-many-imports',
} as const;

/**
 * Translates the common client errors by HTTP status and problem type; the raw message becomes
 * a detail.
 */
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
      if (error.kind === PROBLEM.readOnly) return { message: t('errors.readOnly'), detail: null };
      // `forbidden` is also used for refused cross-site requests, which the UI never sends.
      if (error.kind === PROBLEM.forbidden && !/cross-site/i.test(raw ?? '')) {
        return { message: t('errors.outsideRoots'), detail };
      }
      return { message: t('errors.forbidden'), detail };
    case 404:
      return { message: t('errors.notFound'), detail };
    case 409:
      if (error.kind === PROBLEM.tooManyImports) return { message: t('errors.tooManyImports'), detail: null };
      return { message: t('errors.conflict'), detail };
    default:
      return { message: t('errors.generic'), detail };
  }
}
