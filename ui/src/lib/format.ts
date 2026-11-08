import i18n from '../i18n';

/** Locale-aware integer formatting (tabular in the UI via the `num` utility). */
export function formatCount(n: number): string {
  return new Intl.NumberFormat(i18n.language).format(n);
}

const UNITS = {
  en: ['B', 'KiB', 'MiB', 'GiB', 'TiB'],
  fr: ['o', 'Kio', 'Mio', 'Gio', 'Tio'],
} as const;

/** IEC byte sizes: KiB/MiB/GiB in English, Kio/Mio/Gio in French (docs/UI_GUIDELINES.md). */
export function formatBytes(bytes: number, lang: string = i18n.language): string {
  const units = lang.startsWith('fr') ? UNITS.fr : UNITS.en;
  let value = Math.max(0, bytes);
  let i = 0;
  while (value >= 1024 && i < units.length - 1) {
    value /= 1024;
    i++;
  }
  const digits = i === 0 || value >= 100 ? 0 : 1;
  const num = new Intl.NumberFormat(lang, { maximumFractionDigits: digits, minimumFractionDigits: digits }).format(
    value,
  );
  return `${num}\u00a0${units[i] ?? units[0]}`;
}

const pad2 = (n: number) => String(n).padStart(2, '0');

/**
 * Local ISO-like date and time of a microsecond timestamp (`2026-11-08 14:03:12`), in the
 * browser's time zone (shown separately, see `timeZoneLabel`). `withDate: false` drops the date.
 */
export function formatTimestamp(us: number, withDate = true): string {
  const d = new Date(Math.floor(us / 1000));
  if (Number.isNaN(d.getTime())) return '';
  const time = `${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}`;
  if (!withDate) return time;
  return `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())} ${time}`;
}

/** True when both microsecond timestamps fall on the same local day. */
export function sameLocalDay(aUs: number, bUs: number): boolean {
  const a = new Date(Math.floor(aUs / 1000));
  const b = new Date(Math.floor(bUs / 1000));
  return a.getFullYear() === b.getFullYear() && a.getMonth() === b.getMonth() && a.getDate() === b.getDate();
}

/** Captured period `start - end` (end without its date when on the same day); empty when unknown. */
export function formatPeriod(firstUs: number | null, lastUs: number | null): string {
  if (firstUs === null || lastUs === null) return '';
  return `${formatTimestamp(firstUs)} \u2013 ${formatTimestamp(lastUs, !sameLocalDay(firstUs, lastUs))}`;
}

/** IANA name of the display time zone (e.g. `Europe/Paris`, `UTC`). */
export function timeZoneLabel(): string {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone;
  } catch {
    return 'UTC';
  }
}

/** Compact duration: `0.4 s`, `43 s`, `12 min 05 s`, `3 h 02 min`, `2 d 03 h` (fr: `j`). */
export function formatDuration(seconds: number, lang: string = i18n.language): string {
  const fr = lang.startsWith('fr');
  const day = fr ? 'j' : 'd';
  const s = Math.max(0, seconds);
  const nb = '\u00a0';
  if (s < 10) {
    const v = new Intl.NumberFormat(lang, { maximumFractionDigits: s < 1 ? 3 : 1 }).format(s);
    return `${v}${nb}s`;
  }
  const total = Math.round(s);
  if (total < 60) return `${total}${nb}s`;
  if (total < 3600) return `${Math.floor(total / 60)}${nb}min ${pad2(total % 60)}${nb}s`;
  if (total < 86_400) return `${Math.floor(total / 3600)}${nb}h ${pad2(Math.floor((total % 3600) / 60))}${nb}min`;
  return `${Math.floor(total / 86_400)}${nb}${day} ${pad2(Math.floor((total % 86_400) / 3600))}${nb}h`;
}

/** Duration between two microsecond timestamps, empty when either is unknown. */
export function formatSpan(firstUs: number | null, lastUs: number | null): string {
  if (firstUs === null || lastUs === null) return '';
  return formatDuration((lastUs - firstUs) / 1e6);
}

/** Last path component (handles `/` and `\` separators). */
export function baseName(path: string): string {
  const trimmed = path.replace(/[/\\]+$/, '');
  const i = Math.max(trimmed.lastIndexOf('/'), trimmed.lastIndexOf('\\'));
  return i < 0 ? trimmed : trimmed.slice(i + 1);
}
