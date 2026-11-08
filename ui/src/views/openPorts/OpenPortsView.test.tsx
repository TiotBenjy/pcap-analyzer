import { screen, waitFor, within } from '@testing-library/react';
import type { ComponentProps } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import * as connectionsApi from '../../api/connections';
import * as api from '../../api/sessions';
import type { HostOpenPorts } from '../../api/types/HostOpenPorts';
import type { OpenPortInfo } from '../../api/types/OpenPortInfo';
import type { Chart } from '../../components/Chart';
import { renderApp, setViewportWide } from '../../test/renderApp';
import { session } from '../../test/sessionFixtures';
import { setupUser } from '../../test/user';
import { categoriesOf, PRIVATE_CATEGORIES } from './categories';

vi.mock('../../api/sessions');
vi.mock('../../api/connections', async (importOriginal) => ({
  ...(await importOriginal<typeof connectionsApi>()),
  listOpenPorts: vi.fn(),
  getOpenPortStats: vi.fn(),
}));

type ChartProps = ComponentProps<typeof Chart>;
const chart = { props: null as ChartProps | null };
vi.mock('../../components/Chart', () => ({
  Chart: (props: ChartProps) => {
    chart.props = props;
    return <div data-testid="chart" data-empty={String(props.empty === true)} />;
  },
}));

const ID = '01JC0FFEE0000000000000000A';
const T0 = Date.UTC(2026, 10, 8, 10, 0, 0) * 1000;

function port(p: Partial<OpenPortInfo> & Pick<OpenPortInfo, 'port'>): OpenPortInfo {
  return {
    transport: 'tcp',
    service: null,
    detected: null,
    evidence: 'syn_ack',
    clients: 1,
    first_ts_us: T0,
    last_ts_us: T0 + 1_000_000,
    banner: null,
    ...p,
  };
}

function hosts(): HostOpenPorts[] {
  return [
    {
      host: { ip: '192.168.1.50', names: ['files.lan'], category: 'private', country: null },
      clients: 3,
      ports: [
        port({ port: 22, service: 'ssh', detected: 'ssh', banner: 'SSH-2.0-OpenSSH_9.6' }),
        port({ port: 443, service: 'https', detected: 'tls' }),
        port({ port: 1863, service: 'msnp', detected: 'http' }),
        port({ port: 61863 }),
      ],
    },
    {
      host: { ip: '81.2.3.4', names: [], category: 'public', country: 'FR' },
      clients: 1,
      ports: [port({ port: 53, transport: 'udp', service: 'domain', evidence: 'udp_reply' })],
    },
  ];
}

describe('Open Ports view', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    chart.props = null;
    setViewportWide(true);
    vi.mocked(api.getSession).mockResolvedValue(session());
    vi.mocked(connectionsApi.listOpenPorts).mockResolvedValue({ items: hosts(), next_cursor: null, total_estimate: 2 });
    vi.mocked(connectionsApi.getOpenPortStats).mockResolvedValue({
      top: [
        { port: 443, transport: 'tcp', service: 'https', detected: 'tls', hosts: 2 },
        { port: 53, transport: 'udp', service: 'domain', detected: null, hosts: 1 },
      ],
      distinct_ports: 6,
      open_ports: 7,
    });
  });

  it('groups ports by host with IANA names, mismatches in amber and banners', async () => {
    renderApp(`/sessions/${ID}/open-ports`);
    const table = await screen.findByRole('table', { name: 'Hosts with open ports' });
    const rows = within(table).getAllByRole('row');
    expect(rows).toHaveLength(3);
    const first = within(rows[1] as HTMLElement);
    expect(first.getByText('files.lan')).toBeInTheDocument();
    expect(first.getByText('22 ssh')).toBeInTheDocument();
    expect(first.getByText('443 https')).not.toHaveClass('text-warning');
    // Detected HTTP on the MSN port: the detected service, flagged.
    const msnp = first.getByText('1863 http');
    expect(msnp).toHaveClass('text-warning');
    expect(msnp.getAttribute('title')).toContain('IANA service: msnp');
    expect(first.getByText('61863')).toBeInTheDocument();
    expect(first.getByText('SSH-2.0-OpenSSH_9.6')).toBeInTheDocument();
    expect(first.getByText('3')).toBeInTheDocument();
    const second = within(rows[2] as HTMLElement);
    expect(second.getByText('53/udp domain')).toBeInTheDocument();
    expect(second.getByText('None')).toBeInTheDocument();
    // Chart: top ports, others counted below.
    expect(chart.props?.empty).toBe(false);
    expect(screen.getByText('4 other ports not shown')).toBeInTheDocument();
  });

  it('filters by category and text, and hides names on demand', async () => {
    const user = setupUser();
    renderApp(`/sessions/${ID}/open-ports`);
    await screen.findByRole('table', { name: 'Hosts with open ports' });
    expect(connectionsApi.listOpenPorts).toHaveBeenLastCalledWith(ID, { q: '' }, null, expect.anything());

    await user.click(screen.getAllByRole('switch', { name: 'Public' })[0] as HTMLElement);
    await waitFor(() => {
      expect(connectionsApi.listOpenPorts).toHaveBeenLastCalledWith(
        ID,
        { categories: PRIVATE_CATEGORIES, q: '' },
        null,
        expect.anything(),
      );
    });
    expect(connectionsApi.getOpenPortStats).toHaveBeenLastCalledWith(ID, PRIVATE_CATEGORIES, expect.anything());

    await user.type(screen.getByRole('searchbox'), '443');
    await waitFor(() => {
      expect(connectionsApi.listOpenPorts).toHaveBeenLastCalledWith(
        ID,
        { categories: PRIVATE_CATEGORIES, q: '443' },
        null,
        expect.anything(),
      );
    });

    await user.click(screen.getAllByRole('switch', { name: 'Show names' })[0] as HTMLElement);
    expect(await screen.findByText('192.168.1.50')).toBeInTheDocument();
    expect(screen.queryByText('files.lan')).toBeNull();
  });

  it('stacks hosts as cards below 768 px', async () => {
    setViewportWide(false);
    renderApp(`/sessions/${ID}/open-ports`);
    const list = await screen.findByRole('list', { name: 'Hosts with open ports' });
    expect(within(list).getAllByRole('listitem')).toHaveLength(2);
    expect(within(list).getByText('3 clients')).toBeInTheDocument();
  });

  it('says when nothing answered', async () => {
    vi.mocked(connectionsApi.listOpenPorts).mockResolvedValue({ items: [], next_cursor: null, total_estimate: 0 });
    vi.mocked(connectionsApi.getOpenPortStats).mockResolvedValue({ top: [], distinct_ports: 0, open_ports: 0 });
    renderApp(`/sessions/${ID}/open-ports`);
    expect(await screen.findByText('No open port detected in this session')).toBeInTheDocument();
    await waitFor(() => {
      expect(chart.props?.empty).toBe(true);
    });
  });

  it('maps the switches to address categories', () => {
    expect(categoriesOf(true, true)).toBeUndefined();
    expect(categoriesOf(false, true)).toEqual(['public']);
    expect(categoriesOf(false, false)).toEqual([]);
    expect(categoriesOf(true, false)).not.toContain('public');
  });
});
