import { screen, waitFor, within } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import * as connectionsApi from '../../api/connections';
import * as api from '../../api/sessions';
import type { ConnectionMatrix } from '../../api/types/ConnectionMatrix';
import type { ConnectionStats } from '../../api/types/ConnectionStats';
import type { ConversationInfo } from '../../api/types/ConversationInfo';
import type { Endpoint } from '../../api/types/Endpoint';
import { renderApp, setViewportWide } from '../../test/renderApp';
import { session } from '../../test/sessionFixtures';
import { setupUser } from '../../test/user';

vi.mock('../../api/sessions');
vi.mock('../../api/connections', async (importOriginal) => ({
  ...(await importOriginal<typeof connectionsApi>()),
  getConnectionStats: vi.fn(),
  getConnectionTop: vi.fn(),
  listConversations: vi.fn(),
}));

const ID = '01JC0FFEE0000000000000000A';
const T0 = Date.UTC(2026, 10, 8, 10, 0, 0) * 1000;

const ep = (ip: string, category: Endpoint['category'], country: string | null = null, names: string[] = []): Endpoint => ({
  ip,
  names,
  category,
  country,
});

function stats(): ConnectionStats {
  return {
    sources: {
      countries: [
        { country: 'FR', bytes: 6_000, hosts: 2 },
        { country: 'DE', bytes: 1_000, hosts: 1 },
      ],
      unknown: { bytes: 500, hosts: 1 },
      local: { bytes: 2_500, hosts: 3 },
      total_bytes: 10_000,
    },
    destinations: {
      countries: [],
      unknown: { bytes: 0, hosts: 0 },
      local: { bytes: 10_000, hosts: 4 },
      total_bytes: 10_000,
    },
  };
}

function matrix(): ConnectionMatrix {
  return {
    nodes: [
      { endpoint: ep('192.168.1.10', 'private', null, ['ws.lan']), bytes: 9_000 },
      { endpoint: ep('81.2.3.4', 'public', 'FR'), bytes: 6_000 },
      { endpoint: ep('192.168.1.1', 'private'), bytes: 3_000 },
      { endpoint: null, bytes: 100 },
    ],
    matrix: [
      [0, 1_000, 500, 50],
      [5_000, 0, 0, 0],
      [0, 2_500, 0, 0],
      [50, 0, 0, 0],
    ],
    conversations: 4,
    total_bytes: 9_100,
    exclude_dns: false,
  };
}

function conversation(i: number): ConversationInfo {
  return {
    id: String(i),
    src: ep(`192.168.1.${i}`, 'private'),
    dst: ep('81.2.3.4', 'public', 'FR', ['cdn.example.test']),
    bytes_fwd: 1_000 * i,
    bytes_rev: 100 * i,
    bytes_total: 1_100 * i,
    packets_fwd: 10,
    packets_rev: 5,
    packets_total: 15,
    flows: 2,
    protocols: ['dns', 'tls'],
    first_ts_us: T0,
    last_ts_us: T0 + 90_000_000,
    duration_us: 90_000_000,
  };
}

describe('Connections view', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    setViewportWide(false);
    vi.mocked(api.getSession).mockResolvedValue(session());
    vi.mocked(connectionsApi.getConnectionStats).mockResolvedValue(stats());
    vi.mocked(connectionsApi.getConnectionTop).mockResolvedValue(matrix());
    vi.mocked(connectionsApi.listConversations).mockImplementation((_id, filters) =>
      Promise.resolve({
        items: filters.from === undefined || filters.from === '' ? [conversation(3), conversation(2)] : [conversation(2)],
        next_cursor: null,
        total_estimate: filters.from === undefined || filters.from === '' ? 2 : 1,
      }),
    );
  });

  it('lists the top countries with the hosts without country apart', async () => {
    renderApp(`/sessions/${ID}/connections`);
    const sources = await screen.findByRole('list', { name: 'Countries of Download sources' });
    const items = within(sources).getAllByRole('listitem');
    expect(items).toHaveLength(2);
    expect(items[0]).toHaveTextContent('France');
    expect(items[0]).toHaveTextContent('2 hosts');
    expect(screen.getByText('Public, country unknown')).toBeInTheDocument();
    expect(screen.getAllByText('Private and local addresses')).toHaveLength(2);
    // Destinations: no geolocated host, said explicitly.
    expect(screen.getByText('No geolocated host')).toBeInTheDocument();
  });

  it('shows the ranked pairs below 768 px and reloads the matrix with the controls', async () => {
    const user = setupUser();
    renderApp(`/sessions/${ID}/connections`);
    const pairs = await screen.findByRole('list', { name: 'Pairs of endpoints ranked by bytes' });
    const items = within(pairs).getAllByRole('listitem');
    // Largest pair first: the workstation and the public host (1 000 + 5 000 bytes).
    expect(items[0]).toHaveTextContent('ws.lan / 81.2.3.4');
    expect(items[0]).toHaveTextContent('5.9 KiB');
    expect(within(pairs).getByText(/Other hosts/)).toBeInTheDocument();
    expect(screen.getByText('4 conversations, 8.9 KiB')).toBeInTheDocument();
    expect(connectionsApi.getConnectionTop).toHaveBeenLastCalledWith(ID, 10, false, expect.anything());

    await user.click(screen.getByRole('radio', { name: 'Top 50' }));
    await waitFor(() => {
      expect(connectionsApi.getConnectionTop).toHaveBeenLastCalledWith(ID, 50, false, expect.anything());
    });
    await user.click(screen.getByRole('switch', { name: 'Include DNS' }));
    await waitFor(() => {
      expect(connectionsApi.getConnectionTop).toHaveBeenLastCalledWith(ID, 50, true, expect.anything());
    });
    // The legend lists the address categories of the network legends.
    const legend = screen.getByRole('list', { name: 'Address categories' });
    for (const c of ['LAN', 'Public', 'Broadcast', 'Multicast', 'Link-local', 'Loopback', 'Other']) {
      expect(within(legend).getByText(c)).toBeInTheDocument();
    }
  });

  it('lists the conversations sorted by the server and filters them by source', async () => {
    const user = setupUser();
    renderApp(`/sessions/${ID}/connections`);
    const table = await screen.findByRole('table', { name: 'Conversations between hosts' });
    const rows = within(table).getAllByRole('row');
    expect(rows).toHaveLength(3);
    expect(rows[1]).toHaveTextContent('192.168.1.3');
    expect(rows[1]).toHaveTextContent('cdn.example.test');
    expect(rows[1]).toHaveTextContent('3.2 KiB');
    expect(rows[1]).toHaveTextContent('dns, tls');
    expect(rows[1]).toHaveTextContent('1 min 30 s');

    await user.type(screen.getByRole('searchbox', { name: 'Filter sources' }), '1.2');
    await waitFor(() => {
      expect(connectionsApi.listConversations).toHaveBeenLastCalledWith(ID, { from: '1.2', to: '' }, null, expect.anything());
    });
    await waitFor(() => {
      expect(within(screen.getByRole('table', { name: 'Conversations between hosts' })).getAllByRole('row')).toHaveLength(2);
    });
  });

  it('shows explicit empty states for a session without traffic', async () => {
    vi.mocked(connectionsApi.getConnectionStats).mockResolvedValue({
      sources: { countries: [], unknown: { bytes: 0, hosts: 0 }, local: { bytes: 0, hosts: 0 }, total_bytes: 0 },
      destinations: { countries: [], unknown: { bytes: 0, hosts: 0 }, local: { bytes: 0, hosts: 0 }, total_bytes: 0 },
    });
    vi.mocked(connectionsApi.getConnectionTop).mockResolvedValue({ ...matrix(), nodes: [], matrix: [], conversations: 0, total_bytes: 0 });
    vi.mocked(connectionsApi.listConversations).mockResolvedValue({ items: [], next_cursor: null, total_estimate: 0 });
    renderApp(`/sessions/${ID}/connections`);
    expect(await screen.findByText('No traffic between hosts')).toBeInTheDocument();
    expect(await screen.findAllByText('No traffic')).toHaveLength(2);
    expect(await screen.findByText('No conversation in this session')).toBeInTheDocument();
  });

  it('waits for the end of an import without calling the connection routes', async () => {
    vi.mocked(api.getSession).mockResolvedValue(session({ state: 'importing' }));
    renderApp(`/sessions/${ID}/connections`);
    expect(await screen.findByText('Import in progress')).toBeInTheDocument();
    expect(connectionsApi.getConnectionStats).not.toHaveBeenCalled();
    expect(connectionsApi.listConversations).not.toHaveBeenCalled();
  });
});
