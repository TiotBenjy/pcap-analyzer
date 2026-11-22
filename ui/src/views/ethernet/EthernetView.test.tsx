import { screen, waitFor, within } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import * as ethApi from '../../api/ethernet';
import * as api from '../../api/sessions';
import type { EthernetStats } from '../../api/types/EthernetStats';
import type { MacAddress } from '../../api/types/MacAddress';
import type { MacInfo } from '../../api/types/MacInfo';
import type { MacPairInfo } from '../../api/types/MacPairInfo';
import { renderApp, setViewportWide } from '../../test/renderApp';
import { page, session } from '../../test/sessionFixtures';
import { setupUser } from '../../test/user';

vi.mock('../../api/sessions');
vi.mock('../../api/ethernet', async (importOriginal) => ({
  ...(await importOriginal<typeof ethApi>()),
  getEthernetStats: vi.fn(),
  listMacs: vi.fn(),
  listMacPairs: vi.fn(),
}));

const ID = '01JC0FFEE0000000000000000A';
const T0 = Date.UTC(2026, 10, 8, 10, 0, 0) * 1000;

function address(mac: string, overrides: Partial<MacAddress> = {}): MacAddress {
  return { mac, vendor: null, kind: 'unicast', local: false, group: null, ...overrides };
}

const VBOX = address('08:00:27:09:d9:cb', { vendor: 'PCS Systemtechnik GmbH' });
const QEMU = address('52:55:0a:00:02:01', { local: true });
const V6 = address('33:33:00:00:00:01', { kind: 'multicast', local: true, group: 'ipv6_multicast' });
const BCAST = address('ff:ff:ff:ff:ff:ff', { kind: 'broadcast', local: true });

function mac(addr: MacAddress, overrides: Partial<MacInfo> = {}): MacInfo {
  return {
    address: addr,
    registry: addr.vendor === null ? null : 'ma-l',
    frames_sent: 12,
    bytes_sent: 1200,
    frames_received: 3,
    bytes_received: 300,
    first_ts_us: T0,
    last_ts_us: T0 + 60_000_000,
    vlans: [],
    ...overrides,
  };
}

function pair(id: string, src: MacAddress, dst: MacAddress, overrides: Partial<MacPairInfo> = {}): MacPairInfo {
  return {
    id,
    src,
    dst,
    frames: 5,
    bytes: 500,
    first_ts_us: T0,
    last_ts_us: T0 + 1_000_000,
    ethertypes: [{ value: 0x0800, kind: 'ethertype', code: '0x0800', name: 'IPv4' }],
    vlans: [],
    ...overrides,
  };
}

function stats(overrides: Partial<EthernetStats> = {}): EthernetStats {
  return {
    mac_count: 4,
    unicast_count: 2,
    local_count: 1,
    group_count: 2,
    vendor_count: 1,
    pair_count: 2,
    vlan_count: 1,
    frames: 40,
    bytes: 4000,
    tagged_frames: 10,
    vendors: [
      { key: 'PCS Systemtechnik GmbH', kind: 'named', name: 'PCS Systemtechnik GmbH', count: 1 },
      { key: '~local', kind: 'local', name: null, count: 1 },
    ],
    vendors_other: 0,
    ethertypes: [
      { ethertype: { value: 0x0800, kind: 'ethertype', code: '0x0800', name: 'IPv4' }, frames: 30, bytes: 3000, first_ts_us: T0, last_ts_us: T0 + 1 },
      { ethertype: { value: 0x42, kind: 'llc', code: '0x42', name: 'Spanning tree' }, frames: 10, bytes: 1000, first_ts_us: T0, last_ts_us: T0 + 1 },
    ],
    vlans: [
      { stack: '100.20', outer_id: 100, inner_id: 20, depth: 2, outer_tpid: 0x88a8, frames: 10, bytes: 1000, first_ts_us: T0, last_ts_us: T0 + 1 },
    ],
    ...overrides,
  };
}

beforeEach(() => {
  setViewportWide(true);
  vi.mocked(api.getSession).mockResolvedValue(session({ state: 'ready' }));
  vi.mocked(ethApi.getEthernetStats).mockResolvedValue(stats());
  vi.mocked(ethApi.listMacs).mockResolvedValue(page([mac(VBOX, { vlans: ['100.20'] }), mac(QEMU), mac(V6), mac(BCAST)]));
  vi.mocked(ethApi.listMacPairs).mockResolvedValue(page([pair('1', VBOX, QEMU), pair('2', QEMU, BCAST)]));
});

describe('EthernetView', () => {
  it('shows the vendors, EtherTypes, VLANs, addresses and pairs', async () => {
    renderApp(`/sessions/${ID}/ethernet`);
    const table = await screen.findByRole('table', { name: 'MAC addresses' });
    expect(within(table).getByText('08:00:27:09:d9:cb')).toBeInTheDocument();
    // Address classes: local, broadcast, well-known multicast group.
    expect(within(table).getAllByText('Local').length).toBeGreaterThan(0);
    expect(within(table).getByText('Broadcast')).toBeInTheDocument();
    expect(within(table).getByText('IPv6 multicast')).toBeInTheDocument();
    expect(within(table).getAllByText('PCS Systemtechnik GmbH').length).toBeGreaterThan(0);

    const vendors = screen.getByRole('list', { name: 'Unicast addresses per vendor' });
    expect(within(vendors).getByText('Locally administered')).toBeInTheDocument();
    const types = screen.getByRole('list', { name: 'Frames per EtherType' });
    expect(within(types).getByText('Spanning tree')).toBeInTheDocument();
    const vlans = screen.getByRole('table', { name: 'VLAN stacks' });
    expect(within(vlans).getByText('802.1ad (Q-in-Q)')).toBeInTheDocument();
    const pairs = screen.getByRole('table', { name: 'Frames from a source to a destination' });
    expect(within(pairs).getAllByText('IPv4').length).toBe(2);
    // No range: the counter columns are plain.
    expect(screen.queryByText(/whole session/)).not.toBeInTheDocument();
  });

  it('filters the addresses by vendor and class, and the pairs by address, VLAN and EtherType', async () => {
    const user = setupUser();
    renderApp(`/sessions/${ID}/ethernet`);
    await screen.findByRole('table', { name: 'MAC addresses' });

    await user.click(screen.getByRole('button', { name: 'Show the addresses of PCS Systemtechnik GmbH' }));
    await waitFor(() => {
      expect(ethApi.listMacs).toHaveBeenLastCalledWith(ID, { sort: 'frames', vendor: 'PCS Systemtechnik GmbH' }, null, expect.anything(), null);
    });
    expect(screen.getByText('Vendor: PCS Systemtechnik GmbH')).toBeInTheDocument();

    await user.click(screen.getByRole('radio', { name: 'Local' }));
    await waitFor(() => {
      expect(ethApi.listMacs).toHaveBeenLastCalledWith(
        ID,
        { sort: 'frames', class: 'local', vendor: 'PCS Systemtechnik GmbH' },
        null,
        expect.anything(),
        null,
      );
    });

    await user.click(screen.getByRole('button', { name: 'Show the pairs of Spanning tree' }));
    await waitFor(() => {
      expect(ethApi.listMacPairs).toHaveBeenLastCalledWith(ID, { sort: 'frames', ethertype: 0x42 }, null, expect.anything(), null);
    });

    // A VLAN row filters the addresses and the pairs.
    const vlans = screen.getByRole('table', { name: 'VLAN stacks' });
    await user.click(within(vlans).getByText('100.20'));
    await waitFor(() => {
      expect(ethApi.listMacPairs).toHaveBeenLastCalledWith(ID, { sort: 'frames', vlan: '100.20', ethertype: 0x42 }, null, expect.anything(), null);
    });
    expect(ethApi.listMacs).toHaveBeenLastCalledWith(
      ID,
      { sort: 'frames', class: 'local', vendor: 'PCS Systemtechnik GmbH', vlan: '100.20' },
      null,
      expect.anything(),
      null,
    );

    // An address row filters the pairs on that address.
    const table = screen.getByRole('table', { name: 'MAC addresses' });
    await user.click(within(table).getByText('52:55:0a:00:02:01'));
    await waitFor(() => {
      expect(ethApi.listMacPairs).toHaveBeenLastCalledWith(
        ID,
        { sort: 'frames', mac: '52:55:0a:00:02:01', vlan: '100.20', ethertype: 0x42 },
        null,
        expect.anything(),
        null,
      );
    });
    await user.click(screen.getByRole('button', { name: 'Remove the filter 52:55:0a:00:02:01' }));
    await waitFor(() => {
      expect(ethApi.listMacPairs).toHaveBeenLastCalledWith(ID, { sort: 'frames', vlan: '100.20', ethertype: 0x42 }, null, expect.anything(), null);
    });
  });

  it('sorts on the server', async () => {
    const user = setupUser();
    renderApp(`/sessions/${ID}/ethernet`);
    await screen.findByRole('table', { name: 'MAC addresses' });
    const [macSort, pairSort] = screen.getAllByRole('combobox', { name: 'Order' });
    await user.selectOptions(macSort as HTMLElement, 'mac');
    await waitFor(() => {
      expect(ethApi.listMacs).toHaveBeenLastCalledWith(ID, { sort: 'mac' }, null, expect.anything(), null);
    });
    await user.selectOptions(pairSort as HTMLElement, 'bytes');
    await waitFor(() => {
      expect(ethApi.listMacPairs).toHaveBeenLastCalledWith(ID, { sort: 'bytes' }, null, expect.anything(), null);
    });
  });

  it('asks for the time range and marks the session counters', async () => {
    const range = { fromUs: T0, toUs: T0 + 59_999_999 };
    renderApp(`/sessions/${ID}/ethernet?from_us=${range.fromUs}&to_us=${range.toUs}`);
    await screen.findByRole('table', { name: 'MAC addresses' });
    expect(ethApi.getEthernetStats).toHaveBeenCalledWith(ID, expect.anything(), range);
    expect(ethApi.listMacs).toHaveBeenCalledWith(ID, { sort: 'frames' }, null, expect.anything(), range);
    expect(ethApi.listMacPairs).toHaveBeenCalledWith(ID, { sort: 'frames' }, null, expect.anything(), range);
    // Wide: a second line in the counter headers (VLANs, addresses, pairs); no card note.
    expect(screen.getAllByText('Whole session').length).toBeGreaterThanOrEqual(7);
    expect(screen.queryByText('In a time range, frames and bytes are those of the whole session.')).not.toBeInTheDocument();
    expect(screen.getByText('EtherTypes (whole session)')).toBeInTheDocument();
    // The counter columns of 100 px widen so that the second line is not cut at 768 px; EtherTypes
    // gives them that room, so that the table keeps its width.
    const pairs = await screen.findByRole('table', { name: 'Frames from a source to a destination' });
    expect(within(pairs).getByRole('columnheader', { name: /Frames\s*Whole session/ })).toHaveStyle({ width: '112px' });
    expect(within(pairs).getByRole('columnheader', { name: /Bytes\s*Whole session/ })).toHaveStyle({ width: '112px' });
    expect(within(pairs).getByRole('columnheader', { name: 'EtherTypes' })).toHaveStyle({ width: '106px' });
  });

  it('says when the session has no Ethernet frame', async () => {
    vi.mocked(ethApi.getEthernetStats).mockResolvedValue(
      stats({ mac_count: 0, unicast_count: 0, local_count: 0, group_count: 0, vendor_count: 0, pair_count: 0, vlan_count: 0, vendors: [], ethertypes: [], vlans: [] }),
    );
    renderApp(`/sessions/${ID}/ethernet`);
    expect(await screen.findByText('No Ethernet frame in this session')).toBeInTheDocument();
    expect(screen.queryByRole('table', { name: 'MAC addresses' })).not.toBeInTheDocument();
  });

  it('says in a note of each card that the counters cover the session, on narrow screens', async () => {
    setViewportWide(false);
    renderApp(`/sessions/${ID}/ethernet?from_us=${T0}&to_us=${T0 + 59_999_999}`);
    await screen.findByRole('list', { name: 'MAC addresses' });
    expect(screen.getAllByText('In a time range, frames and bytes are those of the whole session.')).toHaveLength(3);
  });

  it('shows the addresses as cards on narrow screens', async () => {
    setViewportWide(false);
    renderApp(`/sessions/${ID}/ethernet`);
    const list = await screen.findByRole('list', { name: 'MAC addresses' });
    expect(within(list).getByText('08:00:27:09:d9:cb')).toBeInTheDocument();
  });

  it('waits for a running import', async () => {
    vi.mocked(api.getSession).mockResolvedValue(session({ state: 'importing' }));
    renderApp(`/sessions/${ID}/ethernet`);
    expect(await screen.findByText(/appears when the import ends/)).toBeInTheDocument();
    expect(ethApi.getEthernetStats).not.toHaveBeenCalled();
  });
});
