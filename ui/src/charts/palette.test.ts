import { describe, expect, it } from 'vitest';
import { CATEGORICAL, colorFor, OTHER_COLOR } from './palette';

describe('palette', () => {
  it('has the 8 documented colors, last one for Other', () => {
    expect(CATEGORICAL).toHaveLength(8);
    expect(OTHER_COLOR).toBe('#737373');
  });
  it('gives fixed protocols a fixed color, case-insensitively', () => {
    expect(colorFor('HTTP')).toBe(colorFor('http'));
    expect(colorFor('other')).toBe(OTHER_COLOR);
  });
  it('is deterministic and never assigns Other to unknown categories', () => {
    for (const c of ['ldap', 'kerberos', 'ntp', 'ssdp', 'sip']) {
      expect(colorFor(c)).toBe(colorFor(c));
      expect(colorFor(c)).not.toBe(OTHER_COLOR);
      expect(CATEGORICAL).toContain(colorFor(c));
    }
  });
});
