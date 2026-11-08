import { describe, expect, it } from 'vitest';
import { ADDRESS_CATEGORIES, ADDRESS_CATEGORY_ORDER, CATEGORICAL, colorFor, OTHER_COLOR, SERVER_ROLE } from './palette';

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
  it('gives every address category a color and a shape, distinct for the legend categories', () => {
    expect(Object.keys(ADDRESS_CATEGORIES).sort()).toEqual([...ADDRESS_CATEGORY_ORDER].sort());
    const legend = ['private', 'public', 'broadcast', 'multicast', 'link_local', 'loopback'] as const;
    expect(new Set(legend.map((c) => ADDRESS_CATEGORIES[c].color)).size).toBe(legend.length);
    for (const c of legend) expect(ADDRESS_CATEGORIES[c].color).not.toBe(OTHER_COLOR);
    // The server role is a shape only.
    expect(Object.values(ADDRESS_CATEGORIES).map((c) => c.shape)).not.toContain(SERVER_ROLE.shape);
  });
});
