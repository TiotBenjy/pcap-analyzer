import i18n from '../i18n';

// The only place where numbers, sizes, durations and dates are turned into text
// (docs/UI_GUIDELINES.md, "Formats"). Every function takes the language as its last argument,
// defaulting to the active one: a component that calls them re-renders on a language switch as
// long as it uses `useTranslation()` (or passes `i18n.language` in its memo dependencies).
//
// Rules:
// - numbers: `Intl.NumberFormat` of the language (`12,345.6` / `12 345,6`), tabular in the UI;
// - byte sizes: IEC units, `KiB/MiB/GiB` in English, `Kio/Mio/Gio` in French;
// - percentages: `Intl` percent style (`12.5%` / `12,5 %`);
// - dates and times: ISO-like and 24-hour in every language (`2026-11-08 14:03:12`), in the
//   local time zone shown next to them; no month names, so a time is never ambiguous;
// - durations: compact unit pairs (`12 min 05 s`, `2 d 03 h` / `2 j 03 h`).

const NBSP = ' ';

/** Active language of the UI (`en`, `fr`). */
export function currentLanguage(): string {
  return i18n.language;
}

const isFrench = (lang: string) => lang.startsWith('fr');

// Building an `Intl.NumberFormat` costs far more than using one: tables format thousands of cells.
const numberFormats = new Map<string, Intl.NumberFormat>();

function numberFormat(lang: string, options: Intl.NumberFormatOptions = {}): Intl.NumberFormat {
  const key = `${lang}|${JSON.stringify(options)}`;
  let format = numberFormats.get(key);
  if (format === undefined) {
    try {
      format = new Intl.NumberFormat(lang, options);
    } catch {
      format = new Intl.NumberFormat('en', options);
    }
    numberFormats.set(key, format);
  }
  return format;
}

/** Integer or count with the grouping of the language (`12,345` / `12 345`). */
export function formatCount(n: number, lang: string = currentLanguage()): string {
  return numberFormat(lang).format(n);
}

/** Decimal number with at most `maxDigits` fraction digits (`1.5` / `1,5`). */
export function formatNumber(n: number, maxDigits = 1, lang: string = currentLanguage()): string {
  return numberFormat(lang, { maximumFractionDigits: maxDigits }).format(n);
}

/** Short count for axes and tight cards (`12K`, `3.4M` / `12 k`, `3,4 M`). */
export function formatCompact(n: number, lang: string = currentLanguage()): string {
  return numberFormat(lang, { notation: 'compact', maximumFractionDigits: 1 }).format(n);
}

/** Percentage of a fraction in [0, 1] (`12.5%` / `12,5 %`). */
export function formatPercent(fraction: number, maxDigits = 1, lang: string = currentLanguage()): string {
  return numberFormat(lang, { style: 'percent', maximumFractionDigits: maxDigits }).format(
    Number.isFinite(fraction) ? fraction : 0,
  );
}

/**
 * Share of `value` in `total` as a percentage: one decimal below 10 %, none above (and for 0 or
 * the whole); empty when the total is not positive.
 */
export function formatShare(value: number, total: number, lang: string = currentLanguage()): string {
  if (!(total > 0)) return '';
  const fraction = value / total;
  const digits = fraction === 0 || fraction >= 0.1 ? 0 : 1;
  return formatPercent(fraction, digits, lang);
}

/** Colon introducing a value, spaced as the language wants it (`Total:` / `Total :`). */
export function colon(lang: string = currentLanguage()): string {
  return isFrench(lang) ? `${NBSP}:` : ':';
}

/** `label: value` with the colon of the language. */
export function labelled(label: string, value: string, lang: string = currentLanguage()): string {
  return `${label}${colon(lang)} ${value}`;
}

const BYTE_UNITS = {
  en: ['B', 'KiB', 'MiB', 'GiB', 'TiB'],
  fr: ['o', 'Kio', 'Mio', 'Gio', 'Tio'],
} as const;

/**
 * IEC byte sizes: KiB/MiB/GiB in English, Kio/Mio/Gio in French (docs/UI_GUIDELINES.md).
 * `trimZeros` drops a zero decimal (`20 KiB`, not `20.0 KiB`), for axis ticks.
 */
export function formatBytes(bytes: number, lang: string = currentLanguage(), trimZeros = false): string {
  const units = isFrench(lang) ? BYTE_UNITS.fr : BYTE_UNITS.en;
  let value = Math.max(0, Number.isFinite(bytes) ? bytes : 0);
  let i = 0;
  while (value >= 1024 && i < units.length - 1) {
    value /= 1024;
    i++;
  }
  const digits = i === 0 || value >= 100 ? 0 : 1;
  const num = numberFormat(lang, {
    maximumFractionDigits: digits,
    minimumFractionDigits: trimZeros ? 0 : digits,
  }).format(value);
  return `${num}${NBSP}${units[i] ?? units[0]}`;
}

/** Exact byte count with the byte unit (`98,765,432 B` / `98 765 432 o`), for tooltips. */
export function formatByteCount(bytes: number, lang: string = currentLanguage()): string {
  return `${formatCount(bytes, lang)}${NBSP}${isFrench(lang) ? BYTE_UNITS.fr[0] : BYTE_UNITS.en[0]}`;
}

/** Throughput in bytes per second (`12.5 MiB/s` / `12,5 Mio/s`). */
export function formatRate(bytesPerSecond: number, lang: string = currentLanguage()): string {
  return `${formatBytes(bytesPerSecond, lang)}/s`;
}

const pad2 = (n: number) => String(n).padStart(2, '0');

/** Local date of a microsecond timestamp, or null when it is not a valid date. */
function localDate(us: number): Date | null {
  const d = new Date(Math.floor(us / 1000));
  return Number.isNaN(d.getTime()) ? null : d;
}

/**
 * Local ISO-like date and time of a microsecond timestamp (`2026-11-08 14:03:12`), in the
 * browser's time zone (shown separately, see `timeZoneLabel`). `withDate: false` drops the date.
 */
export function formatTimestamp(us: number, withDate = true): string {
  const d = localDate(us);
  if (d === null) return '';
  const time = `${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}`;
  if (!withDate) return time;
  return `${formatDate(us)} ${time}`;
}

/** Local calendar date of a microsecond timestamp (`2026-11-08`). */
export function formatDate(us: number): string {
  const d = localDate(us);
  if (d === null) return '';
  return `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())}`;
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
  return `${formatTimestamp(firstUs)} – ${formatTimestamp(lastUs, !sameLocalDay(firstUs, lastUs))}`;
}

/** IANA name of the display time zone (e.g. `Europe/Paris`, `UTC`). */
export function timeZoneLabel(): string {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone;
  } catch {
    return 'UTC';
  }
}

/**
 * Calendar date written out for metadata outside the capture (`Nov 8, 2026` / `8 nov. 2026`):
 * the build date of a database, not a packet time. `utc` for dates without a time of day.
 */
export function formatLongDate(ms: number, utc = false, lang: string = currentLanguage()): string {
  const d = new Date(ms);
  if (Number.isNaN(d.getTime())) return '';
  const options: Intl.DateTimeFormatOptions = utc ? { dateStyle: 'medium', timeZone: 'UTC' } : { dateStyle: 'medium' };
  try {
    return new Intl.DateTimeFormat(lang, options).format(d);
  } catch {
    return new Intl.DateTimeFormat('en', options).format(d);
  }
}

/** Compact duration: `0.4 s`, `43 s`, `12 min 05 s`, `3 h 02 min`, `2 d 03 h` (fr: `j`). */
export function formatDuration(seconds: number, lang: string = currentLanguage()): string {
  const day = isFrench(lang) ? 'j' : 'd';
  const s = Math.max(0, Number.isFinite(seconds) ? seconds : 0);
  if (s < 10) return `${formatNumber(s, s < 1 ? 3 : 1, lang)}${NBSP}s`;
  const total = Math.round(s);
  if (total < 60) return `${total}${NBSP}s`;
  if (total < 3600) return `${Math.floor(total / 60)}${NBSP}min ${pad2(total % 60)}${NBSP}s`;
  if (total < 86_400) return `${Math.floor(total / 3600)}${NBSP}h ${pad2(Math.floor((total % 3600) / 60))}${NBSP}min`;
  return `${Math.floor(total / 86_400)}${NBSP}${day} ${pad2(Math.floor((total % 86_400) / 3600))}${NBSP}h`;
}

/** Duration between two microsecond timestamps, empty when either is unknown. */
export function formatSpan(firstUs: number | null, lastUs: number | null, lang: string = currentLanguage()): string {
  if (firstUs === null || lastUs === null) return '';
  return formatDuration((lastUs - firstUs) / 1e6, lang);
}

/** Short delay in microseconds: `0.4 ms`, `12 ms`, `1.2 s` (response times). */
export function formatLatency(us: number, lang: string = currentLanguage()): string {
  const ms = us / 1000;
  if (ms >= 1000) return `${formatNumber(ms / 1000, 1, lang)}${NBSP}s`;
  return `${formatNumber(ms, ms < 10 ? 1 : 0, lang)}${NBSP}ms`;
}

/** Last path component (handles `/` and `\` separators). */
export function baseName(path: string): string {
  const trimmed = path.replace(/[/\\]+$/, '');
  const i = Math.max(trimmed.lastIndexOf('/'), trimmed.lastIndexOf('\\'));
  return i < 0 ? trimmed : trimmed.slice(i + 1);
}
