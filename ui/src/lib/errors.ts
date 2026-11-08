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
  sessionTooNew: 'urn:netsift:problem:session-too-new',
  sessionUpgradeFailed: 'urn:netsift:problem:session-upgrade-failed',
  sessionUpgradeNeeded: 'urn:netsift:problem:session-upgrade-needed',
  sessionBusy: 'urn:netsift:problem:session-busy',
} as const;

/**
 * Message of a session that this version cannot open as is (created by a newer version, upgrade
 * failed, needed on a read-only server, or running elsewhere), `null` for any other error. Views with their own error text use it to tell these apart.
 */
export function sessionVersionMessage(t: TFunction, error: unknown): string | null {
  if (!(error instanceof ApiError)) return null;
  if (error.kind === PROBLEM.sessionTooNew) return t('errors.sessionTooNew');
  if (error.kind === PROBLEM.sessionUpgradeFailed) return t('errors.sessionUpgradeFailed');
  if (error.kind === PROBLEM.sessionUpgradeNeeded) return t('errors.sessionUpgradeNeeded');
  if (error.kind === PROBLEM.sessionBusy) return t('errors.sessionBusy');
  return null;
}

/**
 * Translates the common client errors by HTTP status and problem type; the raw message becomes
 * a detail.
 */
export function describeError(t: TFunction, error: unknown): DescribedError {
  const raw = error instanceof Error ? error.message : typeof error === 'string' ? error : null;
  const detail = raw === null || raw.trim() === '' ? null : raw;
  if (!(error instanceof ApiError)) return { message: t('errors.generic'), detail };
  const version = sessionVersionMessage(t, error);
  if (version !== null) return { message: version, detail: null };
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
