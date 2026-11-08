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
  it('gives every traffic series of the Overview a fixed color, Other only to "other"', () => {
    const series = ['dns', 'http', 'tls', 'smb', 'netbios', 'ssh', 'quic', 'dhcp', 'snmp', 'wifi_mgmt', 'other_tcp', 'other_udp'];
    for (const s of series) expect(CATEGORICAL.slice(0, 7)).toContain(colorFor(s));
    expect(colorFor('other_tcp')).toBe(colorFor('tcp'));
    expect(colorFor('other_udp')).toBe(colorFor('udp'));
    expect(new Set(['dns', 'http', 'tls', 'netbios'].map(colorFor)).size).toBe(4);
  });
  it('is deterministic and never assigns Other to unknown categories', () => {
    for (const c of ['ldap', 'kerberos', 'ntp', 'ssdp', 'sip']) {
      expect(colorFor(c)).toBe(colorFor(c));
      expect(colorFor(c)).not.toBe(OTHER_COLOR);
      expect(CATEGORICAL).toContain(colorFor(c));
    }
  });
});
