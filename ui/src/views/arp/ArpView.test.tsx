import { screen, waitFor, within } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import * as arpApi from '../../api/arp';
import * as api from '../../api/sessions';
import type { ArpBindingInfo } from '../../api/types/ArpBindingInfo';
import type { ArpConflicts } from '../../api/types/ArpConflicts';
import type { ArpMessageInfo } from '../../api/types/ArpMessageInfo';
import type { ArpStats } from '../../api/types/ArpStats';
import type { Endpoint } from '../../api/types/Endpoint';
import { renderApp, setViewportWide } from '../../test/renderApp';
import { page, session } from '../../test/sessionFixtures';
import { setupUser } from '../../test/user';
import { ipSortKey } from './format';

vi.mock('../../api/sessions');
vi.mock('../../api/arp', async (importOriginal) => {
  const real = await importOriginal<typeof arpApi>();
  return {
    ...real,
    getArpStats: vi.fn(),
    getArpConflicts: vi.fn(),
    listArpMessages: vi.fn(),
    listArpBindings: vi.fn(),
  };
});

const ID = '01JC0FFEE0000000000000000A';
const T0 = Date.UTC(2026, 10, 8, 10, 0, 0) * 1000;
const ROUTER_MAC = '02:00:5e:10:00:01';
const INTRUDER_MAC = '02:00:5e:10:00:66';

function endpoint(ip: string): Endpoint {
  return { ip, names: [], category: 'private', country: null };
}

function stats(overrides: Partial<ArpStats> = {}): ArpStats {
  return {
    messages: 26,
    kinds: { request: 9, reply: 14, gratuitous: 2, probe: 1, other: 0 },
    unsolicited: 6,
    bindings: 7,
    addresses: 5,
    conflicts: 1,
    first_ts_us: T0,
    last_ts_us: T0 + 60_000_000,
    top_senders: [
      { ip: endpoint('192.168.1.10'), mac: '02:00:5e:10:00:10', messages: 6 },
      { ip: endpoint('192.168.1.1'), mac: INTRUDER_MAC, messages: 3 },
    ],
    ...overrides,
  };
}

function conflicts(): ArpConflicts {
  return {
    total: 1,
    items: [
      {
        ip: endpoint('192.168.1.1'),
        mac_count: 2,
        macs: [
          { mac: ROUTER_MAC, first_ts_us: T0, last_ts_us: T0 + 60_000_000, messages: 5, gratuitous: 0, unsolicited: 0, other_ips: 0 },
          { mac: INTRUDER_MAC, first_ts_us: T0 + 13_000_000, last_ts_us: T0 + 15_000_000, messages: 3, gratuitous: 0, unsolicited: 3, other_ips: 2 },
        ],
        signs: ['simultaneous', 'unsolicited', 'multiple_ips'],
      },
    ],
  };
}

function binding(overrides: Partial<ArpBindingInfo> = {}): ArpBindingInfo {
  return {
    ip: endpoint('192.168.1.1'),
    mac: ROUTER_MAC,
    first_ts_us: T0,
    last_ts_us: T0 + 60_000_000,
    messages: 5,
    requests: 0,
    replies: 5,
    gratuitous: 0,
    unsolicited: 0,
    conflict: true,
    ...overrides,
  };
}

function message(overrides: Partial<ArpMessageInfo> = {}): ArpMessageInfo {
  return {
    id: '1',
    ts_us: T0,
    operation: 2,
    kind: 'reply',
    sender_mac: INTRUDER_MAC,
    sender: endpoint('192.168.1.1'),
    target_mac: '02:00:5e:10:00:10',
    target: endpoint('192.168.1.10'),
    unsolicited: true,
    ...overrides,
  };
}

beforeEach(() => {
  setViewportWide(true);
  vi.mocked(api.getSession).mockResolvedValue(session({ state: 'ready' }));
  vi.mocked(arpApi.getArpStats).mockResolvedValue(stats());
  vi.mocked(arpApi.getArpConflicts).mockResolvedValue(conflicts());
  vi.mocked(arpApi.listArpBindings).mockResolvedValue(page([binding(), binding({ mac: INTRUDER_MAC, messages: 3 })]));
  vi.mocked(arpApi.listArpMessages).mockResolvedValue(
    page([message(), message({ id: '2', kind: 'request', operation: 1, unsolicited: false, target_mac: '00:00:00:00:00:00' })]),
  );
});

describe('ARP view', () => {
  it('shows the figures, the conflict with its signs and the tables', async () => {
    renderApp(`/sessions/${ID}/arp`);
    const conflict = await screen.findByTestId('arp-conflict');
    expect(within(conflict).getByText('2 MAC addresses')).toBeInTheDocument();
    expect(within(conflict).getByText('Simultaneous')).toBeInTheDocument();
    expect(within(conflict).getByText(/the usual way to poison a cache/)).toBeInTheDocument();
    expect(within(conflict).getByText('Also claims 2 other addresses')).toBeInTheDocument();
    expect(screen.getByText('How to confirm ARP spoofing')).toBeInTheDocument();
    const summary = screen.getByTestId('arp-summary');
    expect(within(summary).getByText('Unsolicited replies')).toBeInTheDocument();
    expect(within(summary).getByText('6')).toBeInTheDocument();
    await waitFor(() => expect(screen.getByRole('table', { name: 'ARP messages' })).toBeInTheDocument());
    expect(screen.getByRole('table', { name: 'IP to MAC address pairs' })).toBeInTheDocument();
    expect(screen.getAllByText('Unsolicited').length).toBeGreaterThan(0);
  });

  it('filters the messages by type, unsolicited replies and address', async () => {
    const user = setupUser();
    renderApp(`/sessions/${ID}/arp`);
    await screen.findByRole('table', { name: 'ARP messages' });
    const filters = screen.getByTestId('arp-message-filters');

    // The toggles are drawn twice (inline, and in the menu used below 768 px).
    await user.click(within(filters).getAllByRole('switch', { name: /Probes/ })[0] as HTMLElement);
    await waitFor(() => {
      expect(arpApi.listArpMessages).toHaveBeenLastCalledWith(
        ID,
        expect.objectContaining({ kinds: ['request', 'reply', 'gratuitous', 'other'] }),
        expect.anything(),
        expect.anything(),
        null,
      );
    });

    await user.click(within(filters).getAllByRole('switch', { name: /Unsolicited only/ })[0] as HTMLElement);
    await waitFor(() => {
      expect(arpApi.listArpMessages).toHaveBeenLastCalledWith(ID, expect.objectContaining({ unsolicited: true }), expect.anything(), expect.anything(), null);
    });

    // "Show messages" of a conflict sets the address filter, which can be cleared.
    await user.click(screen.getByRole('button', { name: 'Show messages' }));
    await waitFor(() => {
      expect(arpApi.listArpMessages).toHaveBeenLastCalledWith(ID, expect.objectContaining({ ip: '192.168.1.1' }), expect.anything(), expect.anything(), null);
    });
    expect(within(filters).getByText('Address 192.168.1.1')).toBeInTheDocument();
    await user.click(within(filters).getByRole('button', { name: 'Clear the address filter' }));
    await waitFor(() => {
      expect(arpApi.listArpMessages).toHaveBeenLastCalledWith(ID, expect.objectContaining({ ip: undefined }), expect.anything(), expect.anything(), null);
    });

    // A sender of the ranking filters on its IP and MAC.
    await user.click(screen.getByRole('button', { name: `Show the messages of 192.168.1.1 ${INTRUDER_MAC}` }));
    await waitFor(() => {
      expect(arpApi.listArpMessages).toHaveBeenLastCalledWith(
        ID,
        expect.objectContaining({ ip: '192.168.1.1', mac: INTRUDER_MAC }),
        expect.anything(),
        expect.anything(),
        null,
      );
    });
  });

  it('searches the bindings and keeps the conflicts only', async () => {
    const user = setupUser();
    renderApp(`/sessions/${ID}/arp`);
    const filters = await screen.findByTestId('arp-binding-filters');
    await user.click(within(filters).getByRole('switch', { name: 'Conflicts only' }));
    await waitFor(() => {
      expect(arpApi.listArpBindings).toHaveBeenLastCalledWith(ID, expect.objectContaining({ conflicts: true }), expect.anything(), expect.anything(), null);
    });
    await user.type(within(filters).getByRole('searchbox'), '00:66');
    await waitFor(() => {
      expect(arpApi.listArpBindings).toHaveBeenLastCalledWith(ID, expect.objectContaining({ q: '00:66' }), expect.anything(), expect.anything(), null);
    });
  });

  it('applies the time range and marks the session counters', async () => {
    const range = { fromUs: T0, toUs: T0 + 59_999_999 };
    renderApp(`/sessions/${ID}/arp?from_us=${range.fromUs}&to_us=${range.toUs}`);
    await waitFor(() => {
      expect(arpApi.getArpStats).toHaveBeenCalledWith(ID, expect.anything(), range);
    });
    await waitFor(() => {
      expect(arpApi.getArpConflicts).toHaveBeenCalledWith(ID, expect.anything(), range);
      expect(arpApi.listArpBindings).toHaveBeenCalledWith(ID, expect.anything(), expect.anything(), expect.anything(), range);
    });
    expect(arpApi.listArpMessages).toHaveBeenCalledWith(ID, expect.anything(), expect.anything(), expect.anything(), range);
    expect(await screen.findByText('Messages (whole session)')).toBeInTheDocument();
  });

  it('says when the range is empty', async () => {
    vi.mocked(arpApi.getArpStats).mockResolvedValue(
      stats({ messages: 0, kinds: { request: 0, reply: 0, gratuitous: 0, probe: 0, other: 0 }, unsolicited: 0, bindings: 0, addresses: 0, conflicts: 0, first_ts_us: null, last_ts_us: null, top_senders: [] }),
    );
    renderApp(`/sessions/${ID}/arp?from_us=${T0}&to_us=${T0 + 1}`);
    expect(await screen.findByText('Nothing in the range')).toBeInTheDocument();
    expect(screen.getByText('Nothing was recorded between these times.')).toBeInTheDocument();
  });

  it('waits for a running import', async () => {
    vi.mocked(api.getSession).mockResolvedValue(session({ state: 'importing' }));
    renderApp(`/sessions/${ID}/arp`);
    expect(await screen.findByText('Import in progress')).toBeInTheDocument();
    expect(arpApi.getArpStats).not.toHaveBeenCalled();
  });
});

describe('ARP helpers', () => {
  it('sorts IPv4 addresses numerically', () => {
    const ips = ['192.168.1.10', '192.168.1.2', '10.0.0.1', 'fe80::1'];
    expect([...ips].sort((a, b) => (ipSortKey(a) < ipSortKey(b) ? -1 : 1))).toEqual(['10.0.0.1', '192.168.1.2', '192.168.1.10', 'fe80::1']);
  });
});
