import { describe, expect, it } from 'vitest';
import i18n from '../i18n';
import {
  baseName,
  colon,
  compressionSuffix,
  formatByteCount,
  formatClock,
  formatBytes,
  formatCompact,
  formatCount,
  formatDate,
  formatDuration,
  formatFixedDuration,
  formatLatency,
  formatLongDate,
  formatMonthDay,
  formatNumber,
  formatPercent,
  formatPreciseDuration,
  formatPreciseTimestamp,
  formatPeriod,
  formatRate,
  formatShare,
  formatSpan,
  formatTimestamp,
  isoTimestamp,
  labelled,
  parseTimestamp,
} from './format';

// French groups digits with a narrow no-break space (U+202F); `%` takes a no-break space.
const NNBSP = '\u202f';

describe('formatBytes', () => {
  it('uses IEC units in English', () => {
    expect(formatBytes(0, 'en')).toBe('0\u00a0B');
    expect(formatBytes(1536, 'en')).toBe('1.5\u00a0KiB');
    expect(formatBytes(5 * 1024 ** 3, 'en')).toBe('5.0\u00a0GiB');
  });
  it('uses French IEC units and decimal comma', () => {
    expect(formatBytes(1536, 'fr')).toBe('1,5\u00a0Kio');
    expect(formatBytes(200 * 1024 ** 2, 'fr')).toBe('200\u00a0Mio');
  });
  it('clamps negative values', () => {
    expect(formatBytes(-5, 'en')).toBe('0\u00a0B');
  });
});

describe('formatDuration', () => {
  it('picks a compact unit pair', () => {
    expect(formatDuration(0.25, 'en')).toBe('0.25\u00a0s');
    expect(formatFixedDuration(0.01, 'en')).toBe('0.010\u00a0s');
    expect(formatFixedDuration(0.232, 'fr')).toBe('0,232\u00a0s');
    expect(formatFixedDuration(12.3456, 'en')).toBe('12.346\u00a0s');
    expect(formatFixedDuration(725, 'en')).toBe('12\u00a0min 05\u00a0s');
    expect(formatDuration(43, 'en')).toBe('43\u00a0s');
    expect(formatDuration(725, 'en')).toBe('12\u00a0min 05\u00a0s');
    expect(formatDuration(3 * 3600 + 120, 'en')).toBe('3\u00a0h 02\u00a0min');
    expect(formatDuration(2 * 86_400 + 3 * 3600, 'fr')).toBe('2\u00a0j 03\u00a0h');
  });
});

describe('formatPreciseDuration', () => {
  it('adapts the unit from microseconds to minutes', () => {
    expect(formatPreciseDuration(0.4, 'en')).toBe('<\u00a01\u00a0µs');
    expect(formatPreciseDuration(850, 'en')).toBe('850\u00a0µs');
    expect(formatPreciseDuration(1_234, 'en')).toBe('1.2\u00a0ms');
    expect(formatPreciseDuration(1_234, 'fr')).toBe('1,2\u00a0ms');
    expect(formatPreciseDuration(45_400, 'en')).toBe('45\u00a0ms');
    expect(formatPreciseDuration(999.4, 'en')).toBe('999\u00a0µs');
    expect(formatPreciseDuration(999.5, 'en')).toBe('1\u00a0ms');
    expect(formatPreciseDuration(999.7, 'en')).toBe('1\u00a0ms');
    expect(formatPreciseDuration(999_499, 'en')).toBe('999\u00a0ms');
    expect(formatPreciseDuration(999_500, 'en')).toBe('1\u00a0s');
    expect(formatPreciseDuration(999_999, 'en')).toBe('1\u00a0s');
    expect(formatPreciseDuration(1_200_000, 'en')).toBe('1.2\u00a0s');
    expect(formatPreciseDuration(725_000_000, 'fr')).toBe('12\u00a0min 05\u00a0s');
    expect(formatPreciseDuration(-5, 'en')).toBe('<\u00a01\u00a0µs');
    expect(formatPreciseDuration(Number.NaN, 'en')).not.toMatch(/NaN/);
  });
});

describe('timestamps', () => {
  it('formats local ISO dates and periods', () => {
    const start = new Date(2026, 10, 8, 14, 3, 12).getTime() * 1000;
    const end = new Date(2026, 10, 8, 15, 0, 0).getTime() * 1000;
    const next = new Date(2026, 10, 9, 1, 0, 0).getTime() * 1000;
    expect(formatTimestamp(start)).toBe('2026-11-08 14:03:12');
    expect(formatPeriod(start, end)).toBe('2026-11-08 14:03:12 \u2013 15:00:00');
    expect(formatPeriod(start, next)).toBe('2026-11-08 14:03:12 \u2013 2026-11-09 01:00:00');
    expect(formatPeriod(null, end)).toBe('');
    expect(formatSpan(start, end)).toBe('56\u00a0min 48\u00a0s');
  });

  it('writes microseconds, clock times, month-days and ISO instants', () => {
    const us = new Date(2026, 10, 8, 14, 3, 12).getTime() * 1000 + 4_567;
    expect(formatPreciseTimestamp(us)).toBe('2026-11-08 14:03:12.004567');
    expect(formatPreciseTimestamp(Number.NaN)).toBe('');
    expect(formatClock(us)).toBe('14:03:12');
    expect(formatClock(us, false)).toBe('14:03');
    expect(formatMonthDay(us)).toBe('11-08');
    expect(isoTimestamp(Date.UTC(2026, 10, 8, 13, 3, 12) * 1000)).toBe('2026-11-08T13:03:12.000Z');
    expect(isoTimestamp(Number.NaN)).toBe('');
  });
});

describe('baseName', () => {
  it('handles both separators and trailing slashes', () => {
    expect(baseName('/captures/run1/')).toBe('run1');
    expect(baseName('C:\\caps\\a.pcap')).toBe('a.pcap');
    expect(baseName('file.pcap')).toBe('file.pcap');
  });
});

describe('numbers', () => {
  it('groups digits and writes decimals as the language does', () => {
    expect(formatCount(1234567, 'en')).toBe('1,234,567');
    expect(formatCount(1234567, 'fr')).toBe(`1${NNBSP}234${NNBSP}567`);
    expect(formatNumber(1.25, 1, 'en')).toBe('1.3');
    expect(formatNumber(1.25, 2, 'fr')).toBe('1,25');
    expect(formatCompact(12_400, 'en')).toBe('12.4K');
    expect(formatCompact(12_400, 'fr')).toBe('12,4\u00a0k');
  });
  it('never prints NaN', () => {
    for (const f of [formatCount, formatCompact, formatLatency, formatBytes, formatDuration]) {
      expect(f(Number.NaN, 'en')).not.toMatch(/NaN|∞/);
    }
    expect(formatNumber(Number.POSITIVE_INFINITY, 1, 'en')).toBe('0');
    expect(formatPercent(Number.NaN, 1, 'en')).toBe('0%');
  });
  it('formats percentages and shares', () => {
    expect(formatPercent(0.125, 1, 'en')).toBe('12.5%');
    expect(formatPercent(0.125, 1, 'fr')).toBe('12,5\u00a0%');
    expect(formatShare(1, 4, 'en')).toBe('25%');
    expect(formatShare(1, 40, 'fr')).toBe('2,5\u00a0%');
    expect(formatShare(0, 40, 'en')).toBe('0%');
    expect(formatShare(1, 0, 'en')).toBe('');
  });
  it('spaces the colon of a label for French', () => {
    expect(colon('en')).toBe(':');
    expect(labelled('Total', '3', 'en')).toBe('Total: 3');
    expect(labelled('Total', '3', 'fr')).toBe('Total\u00a0: 3');
  });
  it('writes exact byte counts with the unit of the language', () => {
    expect(formatByteCount(1234, 'en')).toBe('1,234\u00a0B');
    expect(formatByteCount(1234, 'fr')).toBe(`1${NNBSP}234\u00a0o`);
  });
  it('formats rates and latencies', () => {
    expect(formatRate(1536, 'en')).toBe('1.5\u00a0KiB/s');
    expect(formatRate(1536, 'fr')).toBe('1,5\u00a0Kio/s');
    expect(formatLatency(420, 'fr')).toBe('0,4\u00a0ms');
    expect(formatLatency(1_500_000, 'fr')).toBe('1,5\u00a0s');
  });
  it('follows the active language by default', async () => {
    await i18n.changeLanguage('fr');
    try {
      expect(formatBytes(1536)).toBe('1,5\u00a0Kio');
      expect(formatDuration(0.5)).toBe('0,5\u00a0s');
    } finally {
      await i18n.changeLanguage('en');
    }
    expect(formatBytes(1536)).toBe('1.5\u00a0KiB');
  });
});

describe('dates', () => {
  it('keeps ISO-like dates in every language, and writes metadata dates out', () => {
    const us = new Date(2026, 10, 8, 9, 5, 0).getTime() * 1000;
    expect(formatDate(us)).toBe('2026-11-08');
    expect(formatTimestamp(us, false)).toBe('09:05:00');
    const ms = Date.UTC(2026, 10, 8);
    expect(formatLongDate(ms, true, 'en')).toBe('Nov 8, 2026');
    expect(formatLongDate(ms, true, 'fr')).toBe('8 nov. 2026');
    expect(formatLongDate(Number.NaN, true, 'en')).toBe('');
  });
});

describe('interpolated quantities', () => {
  it('formats counts for the language and keeps identifiers as they are', async () => {
    await i18n.changeLanguage('fr');
    try {
      expect(i18n.t('views.import.files', { count: 12_345 })).toBe(`12${NNBSP}345 fichiers`);
      expect(i18n.t('views.credentials.export.hashcat', { mode: 5600 })).toBe('Exporter hashcat 5600');
    } finally {
      await i18n.changeLanguage('en');
    }
    expect(i18n.t('views.import.files', { count: 12_345 })).toBe('12,345 files');
    expect(i18n.t('views.import.files', { count: 1 })).toBe('1 file');
  });
});

describe('parseTimestamp', () => {
  it('reads back what formatTimestamp writes, in local time', () => {
    const us = new Date(2026, 10, 8, 14, 3, 12).getTime() * 1000;
    expect(parseTimestamp(formatTimestamp(us))).toBe(us);
    expect(parseTimestamp('2026-11-08T14:03:12')).toBe(us);
    expect(parseTimestamp(' 2026-11-08 14:03:12 ')).toBe(us);
  });

  it('keeps fractions and makes a range end inclusive to the second', () => {
    const us = new Date(2026, 10, 8, 14, 3, 12).getTime() * 1000;
    expect(parseTimestamp('2026-11-08 14:03:12.5')).toBe(us + 500_000);
    expect(parseTimestamp('2026-11-08 14:03:12.000001')).toBe(us + 1);
    expect(parseTimestamp('2026-11-08 14:03:12', true)).toBe(us + 999_999);
    expect(parseTimestamp('2026-11-08 14:03:12.25', true)).toBe(us + 250_000);
  });

  it('rejects anything else', () => {
    for (const bad of ['', '2026-11-08', '14:03:12', '2026-02-30 10:00:00', '2026-11-08 25:00:00', '2026-11-08 14:03:12.1234567', 'abc']) {
      expect(parseTimestamp(bad)).toBeNull();
    }
  });
});

describe('compressionSuffix', () => {
  it('takes the suffix of compressed files from their name', () => {
    expect(compressionSuffix('/c/cap_00001_20260101000000.pcapng.gz', true)).toBe('.gz');
    expect(compressionSuffix('/c/cap.pcap.ZST', true)).toBe('.zst');
    expect(compressionSuffix('C:\\c\\cap.pcap1.lz4', true)).toBe('.lz4');
  });

  it('is empty for plain files and unknown suffixes', () => {
    expect(compressionSuffix('/c/cap.pcap.gz', false)).toBe('');
    expect(compressionSuffix('/c/cap.pcap', true)).toBe('');
    expect(compressionSuffix('/c/gz', true)).toBe('');
  });
});
