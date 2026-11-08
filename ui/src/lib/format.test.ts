import { describe, expect, it } from 'vitest';
import { baseName, formatBytes, formatDuration, formatPeriod, formatSpan, formatTimestamp } from './format';

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
    expect(formatDuration(43, 'en')).toBe('43\u00a0s');
    expect(formatDuration(725, 'en')).toBe('12\u00a0min 05\u00a0s');
    expect(formatDuration(3 * 3600 + 120, 'en')).toBe('3\u00a0h 02\u00a0min');
    expect(formatDuration(2 * 86_400 + 3 * 3600, 'fr')).toBe('2\u00a0j 03\u00a0h');
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
});

describe('baseName', () => {
  it('handles both separators and trailing slashes', () => {
    expect(baseName('/captures/run1/')).toBe('run1');
    expect(baseName('C:\\caps\\a.pcap')).toBe('a.pcap');
    expect(baseName('file.pcap')).toBe('file.pcap');
  });
});
