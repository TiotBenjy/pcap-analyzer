import { describe, expect, it } from 'vitest';
import type { OpenPortStats } from '../../api/types/OpenPortStats';
import { portBars } from './portsChart';
import { barLabel, portLabel, serviceMismatch, serviceName } from './services';

describe('open port services', () => {
  it('flags detected services that differ from the IANA name', () => {
    expect(serviceMismatch('tls', 'https')).toBe(false);
    expect(serviceMismatch('tls', 'imaps')).toBe(false);
    expect(serviceMismatch('http', 'http-alt')).toBe(false);
    expect(serviceMismatch('smb', 'microsoft-ds')).toBe(false);
    expect(serviceMismatch('smtp', 'submission')).toBe(false);
    expect(serviceMismatch('ssh', 'ssh')).toBe(false);
    expect(serviceMismatch('http', 'https')).toBe(false);
    expect(serviceMismatch('ssh', 'https')).toBe(true);
    expect(serviceMismatch('tls', 'http')).toBe(true);
    expect(serviceMismatch('http', 'msnp')).toBe(true);
    // Unknown on either side: nothing to compare.
    expect(serviceMismatch(null, 'https')).toBe(false);
    expect(serviceMismatch('ssh', null)).toBe(false);
  });

  it('labels ports with the IANA name, the detected one when it differs', () => {
    expect(serviceName({ service: 'https', detected: 'tls' })).toBe('https');
    expect(serviceName({ service: 'ethernet-ip-1', detected: 'ssh' })).toBe('ssh');
    expect(serviceName({ service: null, detected: 'http' })).toBe('http');
    expect(serviceName({ service: null, detected: null })).toBeNull();
    expect(portLabel({ port: 53, transport: 'udp' })).toBe('53/udp');
    expect(portLabel({ port: 443, transport: 'tcp' })).toBe('443');
    expect(barLabel({ port: 61863, transport: 'tcp', service: null, detected: null, hosts: 1 })).toBe('61863');
    expect(barLabel({ port: 1863, transport: 'tcp', service: 'msnp', detected: null, hosts: 1 })).toBe('1863 msnp');
  });

  it('builds one bar per port, most exposed first, the host count on hover', () => {
    const stats: OpenPortStats = {
      top: [
        { port: 80, transport: 'tcp', service: 'http', detected: 'http', hosts: 4 },
        { port: 53, transport: 'udp', service: 'domain', detected: null, hosts: 2 },
      ],
      distinct_ports: 5,
      open_ports: 9,
    };
    const bars = portBars(stats, { hosts: (n) => `${n} hosts`, count: String });
    expect(bars.map((b) => [b.label, b.value, b.valueText, b.title])).toEqual([
      ['80 http', 4, '4', '80 http: 4 hosts'],
      ['53/udp domain', 2, '2', '53/udp domain: 2 hosts'],
    ]);
    expect(bars.every((b) => b.mono === true)).toBe(true);
  });
});
