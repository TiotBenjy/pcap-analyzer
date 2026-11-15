import type { NoticeProvider } from './types';

/** Banners shown at most at once under the header; the others wait for a dismissal. */
export const MAX_NOTICES = 2;

/**
 * Registration point of the notices: one import and one line per feature, sorted by id. The
 * order is also the display priority. Example providers live in the tests only.
 */
export const NOTICE_PROVIDERS: readonly NoticeProvider[] = [];
