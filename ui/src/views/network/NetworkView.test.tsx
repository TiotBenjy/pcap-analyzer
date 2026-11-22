import { screen, waitFor, within } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import * as networkApi from '../../api/network';
import * as api from '../../api/sessions';
import type { Endpoint } from '../../api/types/Endpoint';
import type { NetworkGraph } from '../../api/types/NetworkGraph';
import type { NetworkNode } from '../../api/types/NetworkNode';
import type { NetworkNodeDetail } from '../../api/types/NetworkNodeDetail';
import { renderApp, setViewportWide } from '../../test/renderApp';
import { session } from '../../test/sessionFixtures';
import { setupUser } from '../../test/user';
import * as webgl from './webgl';

vi.mock('../../api/sessions');
vi.mock('../../api/network', async (importOriginal) => ({
  ...(await importOriginal<typeof networkApi>()),
  getNetworkGraph: vi.fn(),
  getNetworkNode: vi.fn(),
}));
vi.mock('./webgl', () => ({ hasWebGL: vi.fn(() => false) }));
// sigma needs WebGL, absent from jsdom: a stub stands for the canvas.
vi.mock('./SigmaGraph', () => ({
  SigmaGraph: ({ ariaLabel, graph }: { ariaLabel: string; graph: { order: number; getNodeAttribute: (id: string, k: string) => number } }) => (
    <div role="img" aria-label={ariaLabel} data-x={String(graph.getNodeAttribute('h:192.168.1.1', 'x'))} data-order={graph.order} />
  ),
}));

const ID = '01JC0FFEE0000000000000000A';
const HOSTILE = '<img src=x onerror=alert(1)>';

const ep = (ip: string, category: Endpoint['category'], names: string[] = [], country: string | null = null): Endpoint => ({
  ip,
  names,
  category,
  country,
});

function host(e: Endpoint, bytes: number): NetworkNode {
  return {
    id: `h:${e.ip}`,
    kind: 'host',
    endpoint: e,
    country: null,
    hosts: 1,
    bytes,
    bytes_sent: bytes / 2,
    bytes_received: bytes / 2,
    packets: 10,
    protocols: ['tcp', 'tls'],
    roles: [],
  };
}

function graph(): NetworkGraph {
  return {
    mode: 'hosts',
    nodes: [
      host(ep('192.168.1.1', 'private', ['server.lan']), 10_000),
      { ...host(ep('81.2.3.4', 'public', [HOSTILE], 'FR'), 6_000), roles: ['http'] },
      {
        id: 'k:US',
        kind: 'cluster',
        endpoint: null,
        country: 'US',
        hosts: 12,
        bytes: 4_000,
        bytes_sent: 1_000,
        bytes_received: 3_000,
        packets: 40,
        protocols: ['tls'],
        roles: [],
      },
    ],
    edges: [
      {
        source: 'h:192.168.1.1',
        target: 'h:81.2.3.4',
        bytes: 6_000,
        bytes_fwd: 5_000,
        bytes_rev: 1_000,
        packets: 10,
        flows: 2,
        conversations: 1,
        protocols: ['tls'],
      },
      {
        source: 'h:192.168.1.1',
        target: 'k:US',
        bytes: 4_000,
        bytes_fwd: 1_000,
        bytes_rev: 3_000,
        packets: 40,
        flows: 12,
        conversations: 12,
        protocols: ['tls'],
      },
    ],
    hosts: 14,
    hosts_shown: 2,
    edges_total: 2,
    max_edges: 400,
    orphans: 3,
    total_bytes: 10_000,
    protocols: networkApi.NETWORK_PROTOCOLS.map((protocol, i) => ({ protocol, conversations: i === 2 ? 13 : 0 })),
  };
}

function detail(): NetworkNodeDetail {
  return {
    endpoint: ep('81.2.3.4', 'public', [HOSTILE], 'FR'),
    macs: ['02:00:5e:00:00:01'],
    first_ts_us: 1_700_000_000_000_000,
    last_ts_us: 1_700_000_060_000_000,
    bytes_sent: 1_000,
    bytes_received: 5_000,
    packets_sent: 4,
    packets_received: 6,
    peers: 1,
    protocols: ['tcp', 'tls'],
    open_ports: [{ port: 443, transport: 'tcp', service: 'https' }],
    neighbors: [{ endpoint: ep('192.168.1.1', 'private', ['server.lan']), bytes_sent: 1_000, bytes_received: 5_000, protocols: ['tls'] }],
    roles: ['http', 'smb'],
  };
}

describe('Network view', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    setViewportWide(false);
    vi.mocked(webgl.hasWebGL).mockReturnValue(false);
    vi.mocked(api.getSession).mockResolvedValue(session());
    vi.mocked(networkApi.getNetworkGraph).mockResolvedValue(graph());
    vi.mocked(networkApi.getNetworkNode).mockResolvedValue(detail());
  });

  it('lists the links ranked by bytes below 768 px, labels escaped', async () => {
    const { container } = renderApp(`/sessions/${ID}/network`);
    const list = await screen.findByRole('list', { name: 'Links ranked by bytes' });
    const items = within(list).getAllByRole('listitem');
    expect(items).toHaveLength(2);
    // The hostile name is plain text, never markup.
    expect(items[0]).toHaveTextContent(`server.lan / ${HOSTILE}`);
    expect(items[1]).toHaveTextContent('server.lan / United States, 12 hosts');
    expect(container.querySelector('img[src="x"]')).toBeNull();
    expect(screen.getByTestId('network-summary')).toHaveTextContent('2 of 14 hosts drawn, 2 links, 9.8 KiB');
    expect(networkApi.getNetworkGraph).toHaveBeenLastCalledWith(
      ID,
      { mode: 'hosts', protocols: undefined, ipv6: true, includeOrphans: false, expand: null },
      expect.anything(), null,
    );
    // The legend names the address categories.
    expect(within(screen.getByRole('list', { name: 'Node colors' })).getByText('LAN')).toBeInTheDocument();
  });

  it('reloads the graph with the protocol, orphan and mode controls', async () => {
    const user = setupUser();
    renderApp(`/sessions/${ID}/network`);
    await screen.findByRole('list', { name: 'Links ranked by bytes' });
    // Counters next to the protocols (the menu copy below 768 px is the second one).
    const https = screen.getAllByRole('switch', { name: /^HTTPS/ })[0];
    expect(https).toHaveTextContent('13');
    if (https === undefined) throw new Error('no HTTPS toggle');
    await user.click(https);
    await waitFor(() => {
      expect(networkApi.getNetworkGraph).toHaveBeenLastCalledWith(
        ID,
        expect.objectContaining({ protocols: ['dns', 'http', 'ssh', 'ftp', 'telnet', 'rdp', 'smb', 'tcp', 'udp', 'other'] }),
        expect.anything(), null,
      );
    });
    // With a protocol filter, volumes are those of whole conversations: said so.
    expect(screen.getByText(/^Volumes of whole conversations/)).toBeInTheDocument();
    await user.click(screen.getAllByRole('button', { name: 'Disable all' })[0] ?? https);
    await waitFor(() => {
      expect(networkApi.getNetworkGraph).toHaveBeenLastCalledWith(ID, expect.objectContaining({ protocols: [] }), expect.anything(), null);
    });
    const orphans = screen.getByRole('switch', { name: /^Hide orphans/ });
    expect(orphans).toHaveTextContent('3');
    await user.click(orphans);
    await waitFor(() => {
      expect(networkApi.getNetworkGraph).toHaveBeenLastCalledWith(ID, expect.objectContaining({ includeOrphans: true }), expect.anything(), null);
    });
    await user.click(screen.getByRole('switch', { name: 'Show IPv6' }));
    await waitFor(() => {
      expect(networkApi.getNetworkGraph).toHaveBeenLastCalledWith(ID, expect.objectContaining({ ipv6: false }), expect.anything(), null);
    });
    await user.click(screen.getByRole('radio', { name: 'Countries' }));
    await waitFor(() => {
      expect(networkApi.getNetworkGraph).toHaveBeenLastCalledWith(ID, expect.objectContaining({ mode: 'countries' }), expect.anything(), null);
    });
  });

  it('selects the searched host and shows its detail', async () => {
    const user = setupUser();
    const { container } = renderApp(`/sessions/${ID}/network`);
    await screen.findByRole('list', { name: 'Links ranked by bytes' });
    const panel = screen.getByRole('complementary', { name: 'Node details' });
    expect(panel).toHaveTextContent('Search an address or a name to see its details.');
    await user.type(screen.getByRole('searchbox'), '81.2.3');
    await waitFor(() => {
      expect(networkApi.getNetworkNode).toHaveBeenCalledWith(ID, '81.2.3.4', expect.anything(), null);
    });
    expect(await within(panel).findByText('443/tcp')).toBeInTheDocument();
    // The links of the found host are highlighted in the list.
    const rows = within(screen.getByRole('list', { name: 'Links ranked by bytes' })).getAllByRole('listitem');
    expect(rows[0]).toHaveAttribute('data-active', 'true');
    expect(rows[1]).not.toHaveAttribute('data-active');
    expect(within(panel).getByText('Public')).toBeInTheDocument();
    expect(within(panel).getByText('France')).toBeInTheDocument();
    expect(within(panel).getByText('HTTP server')).toBeInTheDocument();
    // The roles of the loaded detail win over those of the graph.
    expect(within(panel).getByText('SMB server')).toBeInTheDocument();
    expect(within(panel).getByRole('list', { name: 'Main peers' })).toHaveTextContent('server.lan');
    expect(panel).toHaveTextContent(HOSTILE);
    expect(container.querySelector('img[src="x"]')).toBeNull();

    await user.clear(screen.getByRole('searchbox'));
    await user.type(screen.getByRole('searchbox'), 'nothing here');
    expect(await screen.findByText('No node matches the search')).toBeInTheDocument();
  });

  it('expands a country cluster from its detail', async () => {
    const user = setupUser();
    renderApp(`/sessions/${ID}/network`);
    await screen.findByRole('list', { name: 'Links ranked by bytes' });
    await user.type(screen.getByRole('searchbox'), 'united');
    const panel = screen.getByRole('complementary', { name: 'Node details' });
    await user.click(await within(panel).findByRole('button', { name: 'Show its hosts' }));
    await waitFor(() => {
      expect(networkApi.getNetworkGraph).toHaveBeenLastCalledWith(ID, expect.objectContaining({ expand: 'US' }), expect.anything(), null);
    });
    await user.click(await screen.findByRole('button', { name: 'Group United States again' }));
    await waitFor(() => {
      expect(networkApi.getNetworkGraph).toHaveBeenLastCalledWith(ID, expect.objectContaining({ expand: null }), expect.anything(), null);
    });
  });

  it('draws the graph from 768 px once the layout is computed, the list without WebGL', async () => {
    setViewportWide(true);
    vi.mocked(webgl.hasWebGL).mockReturnValue(true);
    const first = renderApp(`/sessions/${ID}/network`);
    const canvas = await screen.findByRole('img', { name: 'Communication graph: 3 nodes, 2 links' });
    // Positions come from the force layout, not the start circle (x = 1 for the first node).
    expect(Number(canvas.getAttribute('data-x'))).not.toBe(1);
    expect(screen.queryByRole('list', { name: 'Links ranked by bytes' })).toBeNull();
    first.unmount();

    vi.mocked(webgl.hasWebGL).mockReturnValue(false);
    renderApp(`/sessions/${ID}/network`);
    expect(await screen.findByText('WebGL is unavailable: the links are listed instead of drawn')).toBeInTheDocument();
    expect(screen.getByRole('list', { name: 'Links ranked by bytes' })).toBeInTheDocument();
  });

  it('keeps a country group without links in country mode', async () => {
    const local: NetworkGraph = {
      ...graph(),
      mode: 'countries',
      nodes: graph()
        .nodes.filter((n) => n.id === 'k:US')
        .map((n) => ({ ...n, id: 'local', kind: 'local' as const, country: null, hosts: 14 })),
      edges: [],
      hosts_shown: 0,
      edges_total: 0,
    };
    vi.mocked(networkApi.getNetworkGraph).mockResolvedValue(local);
    renderApp(`/sessions/${ID}/network`);
    expect(await screen.findByText('No link between the nodes drawn')).toBeInTheDocument();
    expect(screen.queryByText('No communication matches the filters')).toBeNull();
    expect(screen.getByTestId('network-summary')).toHaveTextContent('14 hosts, 0 links');
    expect(screen.getByText(/^No geolocated public host/)).toBeInTheDocument();
  });

  it('says so when nothing matches the filters', async () => {
    vi.mocked(networkApi.getNetworkGraph).mockResolvedValue({ ...graph(), nodes: [], edges: [], hosts: 0, hosts_shown: 0, edges_total: 0, total_bytes: 0 });
    renderApp(`/sessions/${ID}/network`);
    expect(await screen.findByText('No communication matches the filters')).toBeInTheDocument();
  });

  it('asks the graph and the node detail for the time range of the URL', async () => {
    const user = setupUser();
    const range = { fromUs: 1_000_000, toUs: 60_999_999 };
    renderApp(`/sessions/${ID}/network?from_us=${range.fromUs}&to_us=${range.toUs}`);
    await screen.findByRole('list', { name: 'Links ranked by bytes' });
    expect(screen.getByText('Flows active in the range are counted in full.')).toBeInTheDocument();
    expect(networkApi.getNetworkGraph).toHaveBeenLastCalledWith(ID, expect.anything(), expect.anything(), range);
    await user.type(screen.getByRole('searchbox'), '81.2.3');
    await waitFor(() => {
      expect(networkApi.getNetworkNode).toHaveBeenCalledWith(ID, '81.2.3.4', expect.anything(), range);
    });
  });
});
