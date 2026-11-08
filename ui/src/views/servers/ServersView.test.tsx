import { screen, waitFor, within } from '@testing-library/react';
import { beforeEach, expect, it, vi } from 'vitest';
import * as serversApi from '../../api/servers';
import * as api from '../../api/sessions';
import type { Endpoint } from '../../api/types/Endpoint';
import type { RoleServer } from '../../api/types/RoleServer';
import type { RoleServers } from '../../api/types/RoleServers';
import type { ServerRole } from '../../api/types/ServerRole';
import type { ServersOverview } from '../../api/types/ServersOverview';
import { renderApp, setViewportWide } from '../../test/renderApp';
import { session } from '../../test/sessionFixtures';
import { setupUser } from '../../test/user';

vi.mock('../../api/sessions');
vi.mock('../../api/servers');

const ID = '01JC0FFEE0000000000000000A';
const T0 = Date.UTC(2026, 10, 8, 10, 0, 0) * 1000;
const ROLES: ServerRole[] = ['dns', 'dhcp', 'ldap', 'ntp', 'kerberos', 'smb', 'http'];

function endpoint(ip: string, names: string[] = []): Endpoint {
  return { ip, names, category: 'private', country: null };
}

const router: RoleServer = {
  endpoint: endpoint('192.168.1.1'),
  count: 19,
  first_ts_us: T0,
  last_ts_us: T0 + 60_000_000,
  evidence: [
    { kind: 'dns_response', count: 18, clients: 2, first_ts_us: T0, last_ts_us: T0 + 60_000_000, example: null },
    { kind: 'open_port', count: 1, clients: 1, first_ts_us: T0, last_ts_us: T0, example: '53/udp' },
  ],
};

const dhcpServer: RoleServer = {
  endpoint: endpoint('192.168.1.1'),
  count: 2,
  first_ts_us: T0,
  last_ts_us: T0,
  evidence: [
    { kind: 'dhcp_offer', count: 1, clients: 1, first_ts_us: T0, last_ts_us: T0, example: '192.168.1.30' },
    { kind: 'dhcp_ack', count: 1, clients: 1, first_ts_us: T0, last_ts_us: T0, example: '192.168.1.30' },
  ],
};

function overview(overrides: Partial<ServersOverview> = {}, filled: Partial<Record<ServerRole, RoleServer[]>> = {}): ServersOverview {
  const roles: RoleServers[] = ROLES.map((role) => {
    const servers = filled[role] ?? [];
    return { role, total: servers.length, servers };
  });
  return { analyzed: true, roles, truncated: false, ...overrides };
}

beforeEach(() => {
  setViewportWide(true);
  vi.mocked(api.getSession).mockResolvedValue(session({ state: 'ready' }));
  vi.mocked(serversApi.getServers).mockResolvedValue(overview({}, { dns: [router], dhcp: [dhcpServer] }));
});

it('shows populated role cards with their evidence and an empty state for the others', async () => {
  renderApp(`/sessions/${ID}/servers`);
  const dns = await screen.findByRole('table', { name: 'DNS servers' });
  expect(within(dns).getByText('192.168.1.1')).toBeInTheDocument();
  expect(within(dns).getByText('DNS responses')).toBeInTheDocument();
  expect(within(dns).getByText('Open port 53/udp')).toBeInTheDocument();
  // The same host also plays the DHCP role: shown as a badge.
  expect(within(dns).getByText('DHCP')).toBeInTheDocument();
  expect(screen.getByRole('table', { name: 'DHCP servers' })).toBeInTheDocument();
  expect(screen.getByText('No LDAP server detected')).toBeInTheDocument();
  expect(screen.getByText('No Kerberos server detected')).toBeInTheDocument();
  const badges = screen.getByRole('list', { name: 'Detected roles' });
  expect(within(badges).getAllByRole('listitem')).toHaveLength(7);
});

it('expands the evidence of a server', async () => {
  const user = setupUser();
  renderApp(`/sessions/${ID}/servers`);
  await screen.findByRole('table', { name: 'DHCP servers' });
  const dhcp = screen.getByRole('table', { name: 'DHCP servers' });
  await user.click(within(dhcp).getByRole('button', { name: 'Show the evidence of 192.168.1.1' }));
  const detail = await screen.findByRole('table', { name: 'Evidence of 192.168.1.1' });
  expect(within(detail).getByText('DHCP offers')).toBeInTheDocument();
  expect(within(detail).getAllByText('192.168.1.30')).toHaveLength(2);
});

it('renders cards below md', async () => {
  setViewportWide(false);
  renderApp(`/sessions/${ID}/servers`);
  const list = await screen.findByRole('list', { name: 'DNS servers' });
  expect(within(list).getByText('192.168.1.1')).toBeInTheDocument();
  expect(screen.queryByRole('table', { name: 'DNS servers' })).toBeNull();
});

it('sends the category filter to the API', async () => {
  const user = setupUser();
  renderApp(`/sessions/${ID}/servers`);
  await screen.findByRole('table', { name: 'DNS servers' });
  await user.click(screen.getByRole('button', { name: /Address categories/ }));
  await user.click(screen.getByRole('checkbox', { name: 'Public' }));
  await waitFor(() =>
    expect(vi.mocked(serversApi.getServers)).toHaveBeenLastCalledWith(
      ID,
      { categories: ['private', 'broadcast', 'multicast', 'link_local', 'loopback', 'cgnat', 'unspecified', 'reserved'] },
      expect.anything(),
    ),
  );
});

it('presents a session imported before the view as not analyzed', async () => {
  vi.mocked(serversApi.getServers).mockResolvedValue(overview({ analyzed: false }));
  renderApp(`/sessions/${ID}/servers`);
  expect(await screen.findByText('Not analyzed in this session')).toBeInTheDocument();
  expect(screen.queryByText('No DNS server detected')).toBeNull();
});

it('offers a retry when the servers cannot be loaded', async () => {
  vi.mocked(serversApi.getServers).mockRejectedValue(new Error('boom'));
  renderApp(`/sessions/${ID}/servers`);
  expect(await screen.findByText('Could not load the servers')).toBeInTheDocument();
});
