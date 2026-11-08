import type { BadgeTone } from '../../components/Badge';

// Display helpers of TLS code points. Registry names (alerts, versions) are technical
// identifiers, shown as they are in every language.

const VERSIONS: Readonly<Record<number, string>> = {
  0x0002: 'SSL 2.0',
  0x0300: 'SSL 3.0',
  0x0301: 'TLS 1.0',
  0x0302: 'TLS 1.1',
  0x0303: 'TLS 1.2',
  0x0304: 'TLS 1.3',
};

/** Four-digit hexadecimal code point (`0x1301`). */
export function hex4(v: number): string {
  return `0x${v.toString(16).padStart(4, '0')}`;
}

/** `TLS 1.2`, or the hexadecimal value for an unknown version; `null` for no version. */
export function versionLabel(v: number | null): string | null {
  if (v === null) return null;
  return VERSIONS[v] ?? hex4(v);
}

/** TLS 1.3 reads as good, TLS 1.1 and older as weak. */
export function versionTone(v: number | null): BadgeTone {
  if (v === null) return 'neutral';
  if (v >= 0x0304 && v < 0x7f00) return 'success';
  if (v <= 0x0302) return 'warning';
  return 'neutral';
}

/** Suite name without the `TLS_` prefix (shorter labels); hexadecimal when unknown. */
export function suiteLabel(name: string | null, id: number | null): string {
  if (name !== null) return name.replace(/^TLS_/, '');
  return id === null ? '' : hex4(id);
}

/** Labels longer than this are cut in charts (with the full text in the tooltip). */
export const MAX_LABEL = 24;

export function truncateLabel(s: string, max = MAX_LABEL): string {
  return s.length <= max ? s : `${s.slice(0, max - 1)}…`;
}

/** Cut in the middle (`ECDHE_ECDSA…GCM_SHA256`): both ends of a suite name tell it apart. */
export function truncateMiddle(s: string, max = MAX_LABEL): string {
  if (s.length <= max) return s;
  const tail = Math.floor((max - 1) / 2);
  const head = max - 1 - tail;
  return `${s.slice(0, head)}…${s.slice(s.length - tail)}`;
}

/** RFC 8446 6.2 alert descriptions (and the TLS 1.2 ones still seen). */
const ALERTS: Readonly<Record<number, string>> = {
  0: 'close_notify',
  10: 'unexpected_message',
  20: 'bad_record_mac',
  21: 'decryption_failed',
  22: 'record_overflow',
  40: 'handshake_failure',
  41: 'no_certificate',
  42: 'bad_certificate',
  43: 'unsupported_certificate',
  44: 'certificate_revoked',
  45: 'certificate_expired',
  46: 'certificate_unknown',
  47: 'illegal_parameter',
  48: 'unknown_ca',
  49: 'access_denied',
  50: 'decode_error',
  51: 'decrypt_error',
  70: 'protocol_version',
  71: 'insufficient_security',
  80: 'internal_error',
  86: 'inappropriate_fallback',
  90: 'user_canceled',
  100: 'no_renegotiation',
  109: 'missing_extension',
  110: 'unsupported_extension',
  112: 'unrecognized_name',
  113: 'bad_certificate_status_response',
  115: 'unknown_psk_identity',
  116: 'certificate_required',
  120: 'no_application_protocol',
};

export function alertName(description: number): string {
  return ALERTS[description] ?? `alert ${description}`;
}

/** Weakness identifiers sent by the backend (`crates/netsift-analyze/src/tls/suites.rs`). */
export const WEAKNESSES = ['rc4', '3des', 'null', 'export', 'anon', 'des', 'rc2', 'md5', 'cbc_sha1'] as const;
export type Weakness = (typeof WEAKNESSES)[number];

export function isWeakness(s: string): s is Weakness {
  return (WEAKNESSES as readonly string[]).includes(s);
}

/** Certificate issues of a session (`TlsSessionItem.cert_issues`). */
export const CERT_ISSUES = ['expired', 'not_yet_valid', 'self_signed', 'weak_key'] as const;
export type CertIssue = (typeof CERT_ISSUES)[number];

export const CERT_ISSUE_KEYS = {
  expired: 'views.tls.cert.expired',
  not_yet_valid: 'views.tls.cert.notYetValid',
  self_signed: 'views.tls.cert.selfSigned',
  weak_key: 'views.tls.cert.weakKey',
} as const;

export function isCertIssue(s: string): s is CertIssue {
  return (CERT_ISSUES as readonly string[]).includes(s);
}

/** Local calendar date of a microsecond timestamp (`2026-11-08`). */
export function formatDate(us: number): string {
  const d = new Date(Math.floor(us / 1000));
  if (Number.isNaN(d.getTime())) return '';
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}
