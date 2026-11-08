import type { BadgeTone } from '../../components/Badge';

/** Header names whose values are masked by default (credentials, session cookies, tokens). */
const SENSITIVE_HEADERS = new Set([
  'authorization',
  'proxy-authorization',
  'cookie',
  'set-cookie',
  'x-api-key',
  'x-auth-token',
]);

export function isSensitiveHeader(name: string): boolean {
  return SENSITIVE_HEADERS.has(name.trim().toLowerCase());
}

/** Status class of a status code (`2xx`...), `none` without response. */
export function statusClass(status: number | null): string {
  if (status === null) return 'none';
  if (status >= 100 && status < 600) return `${Math.floor(status / 100)}xx`;
  return 'other';
}

/** Badge tone of a status: errors stand out, the rest stays neutral. */
export function statusTone(status: number | null): BadgeTone {
  if (status === null) return 'neutral';
  if (status >= 500) return 'danger';
  if (status >= 400) return 'warning';
  if (status >= 200 && status < 300) return 'success';
  return 'neutral';
}

/** Parts of `text` with the occurrences of `term` (case-insensitive) flagged. */
export function highlightParts(text: string, term: string): { text: string; match: boolean }[] {
  const needle = term.trim().toLowerCase();
  if (needle === '') return [{ text, match: false }];
  const lower = text.toLowerCase();
  const parts: { text: string; match: boolean }[] = [];
  let from = 0;
  for (;;) {
    const at = lower.indexOf(needle, from);
    if (at === -1) break;
    if (at > from) parts.push({ text: text.slice(from, at), match: false });
    parts.push({ text: text.slice(at, at + needle.length), match: true });
    from = at + needle.length;
  }
  if (from < text.length) parts.push({ text: text.slice(from), match: false });
  return parts.length === 0 ? [{ text, match: false }] : parts;
}

/** Path and query of a transaction as displayed (`*` and authorities as sent). */
export function displayTarget(t: { path: string | null; query: string | null; uri: string | null }): string {
  if (t.path === null) return t.uri ?? '';
  return t.query === null ? t.path : `${t.path}?${t.query}`;
}
