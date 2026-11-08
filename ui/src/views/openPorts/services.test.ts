import { describe, expect, it } from 'vitest';
import type { OpenPortStats } from '../../api/types/OpenPortStats';
import { buildPortsOption, portsTooltip, truncateLabel } from './portsChart';
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

  it('builds horizontal bars, largest first, with escaped tooltips', () => {
    const stats: OpenPortStats = {
      top: [
        { port: 80, transport: 'tcp', service: 'http', detected: 'http', hosts: 4 },
        { port: 53, transport: 'udp', service: 'domain', detected: null, hosts: 2 },
      ],
      distinct_ports: 5,
      open_ports: 9,
    };
    const option = buildPortsOption(stats, { hosts: (n) => `${n} hosts` }) as {
      yAxis: { data: string[]; inverse: boolean };
      series: { data: number[] }[];
    };
    expect(option.yAxis.data).toEqual(['80 http', '53/udp domain']);
    expect(option.yAxis.inverse).toBe(true);
    expect(option.series[0]?.data).toEqual([4, 2]);
    expect(portsTooltip('<b>', '1 host')).toBe('<div style="font-weight:600">&lt;b&gt;</div><div>1 host</div>');
    expect(truncateLabel('x'.repeat(30))).toHaveLength(24);
  });
});
