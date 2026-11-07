import { describe, expect, it } from 'vitest';
import { formatBytes } from './format';

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
