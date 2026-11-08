import type { TFunction } from 'i18next';
import type { BadgeTone } from '../../components/Badge';
import type { DnsProtocol } from '../../api/types/DnsProtocol';
import { colorFor } from '../../charts/palette';
import i18n from '../../i18n';
import type { en } from '../../i18n/en';

/** Display name of a protocol. */
export function protocolLabel(t: TFunction, p: DnsProtocol): string {
  return t(`views.dns.protocols.${p}`);
}

/** Chart color of a protocol (shared palette). */
export function protocolColor(p: DnsProtocol): string {
  return colorFor(p);
}

/** Outcome of a transaction: response code, `timeout`, or `null` (no response expected). */
export function rcodeLabel(t: TFunction, rcode: string | null): string {
  if (rcode === null) return t('views.dns.rcode.none');
  if (rcode === 'timeout') return t('views.dns.rcode.timeout');
  return rcode;
}

export function rcodeTone(rcode: string | null): BadgeTone {
  if (rcode === null) return 'neutral';
  if (rcode === 'NOERROR') return 'success';
  if (rcode === 'timeout') return 'warning';
  return 'danger';
}

/** NetBIOS suffixes with a well-known meaning (MS-NBTE). */
type SuffixKey = keyof (typeof en)['views']['dns']['suffix'];

const SUFFIXES: Readonly<Record<number, SuffixKey>> = {
  0x00: 'workstation',
  0x03: 'messenger',
  0x1b: 'domainMaster',
  0x1c: 'domainControllers',
  0x1d: 'masterBrowser',
  0x1e: 'browserElection',
  0x20: 'fileServer',
};

/** `<20>`, followed by the meaning of the suffix when known. */
export function suffixLabel(t: TFunction, suffix: number): string {
  const hex = `<${suffix.toString(16).toUpperCase().padStart(2, '0')}>`;
  const key = SUFFIXES[suffix];
  return key === undefined ? hex : `${hex} ${t(`views.dns.suffix.${key}`)}`;
}

/** Response time in microseconds: `0.4 ms`, `12 ms`, `1.2 s`. */
export function formatLatency(us: number, lang: string = i18n.language): string {
  const ms = us / 1000;
  if (ms >= 1000) {
    return `${new Intl.NumberFormat(lang, { maximumFractionDigits: 1 }).format(ms / 1000)}\u00a0s`;
  }
  const digits = ms < 10 ? 1 : 0;
  return `${new Intl.NumberFormat(lang, { maximumFractionDigits: digits }).format(ms)}\u00a0ms`;
}

/** Display name of an answer value: `NB` records list addresses, others are shown as they are. */
export function answerText(a: { type: string; value: string }): string {
  return a.value === '' ? a.type : `${a.type} ${a.value}`;
}
