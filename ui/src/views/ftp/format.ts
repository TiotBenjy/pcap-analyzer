import type { FtpTransferInfo } from '../../api/types/FtpTransferInfo';

/** Outcome of a transfer, from its final reply (RFC 959 4.2). */
export type TransferStatus = 'complete' | 'interrupted' | 'failed' | 'noReply';

/** `426` (connection closed, transfer aborted) and `451` / `452` (local error) cut a transfer short. */
const INTERRUPTED = new Set([426, 451, 452]);

export function transferStatus(t: Pick<FtpTransferInfo, 'status'>): TransferStatus {
  if (t.status === null) return 'noReply';
  if (t.status >= 200 && t.status < 300) return 'complete';
  if (INTERRUPTED.has(t.status)) return 'interrupted';
  return 'failed';
}

/** A reply code that reports an error (`4xx`, `5xx`). */
export function isErrorCode(head: string | null): boolean {
  return head !== null && /^[45]\d\d/.test(head);
}

/**
 * Name of a downloaded file when the server gives none: the last segment of the path, with the
 * same filter as the server (letters, digits, `.`, `-`, `_`; no leading dot, at most 64
 * characters), else `ftp-file`.
 */
export function baseName(path: string | null): string {
  const segment = (path ?? '').split(/[\\/]/).filter((s) => s !== '').at(-1) ?? '';
  const safe = [...segment]
    .map((c) => (/[A-Za-z0-9._-]/.test(c) ? c : '_'))
    .join('')
    .replace(/^[._]+/, '')
    .slice(0, 64);
  return /[A-Za-z0-9]/.test(safe) ? safe : 'ftp-file';
}
