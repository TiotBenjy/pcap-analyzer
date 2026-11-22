import { screen, waitFor, within } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import * as api from '../../api/sessions';
import * as ssdpApi from '../../api/ssdp';
import type { Endpoint } from '../../api/types/Endpoint';
import type { SsdpDeviceInfo } from '../../api/types/SsdpDeviceInfo';
import type { SsdpMessageInfo } from '../../api/types/SsdpMessageInfo';
import type { SsdpStats } from '../../api/types/SsdpStats';
import { renderApp, setViewportWide } from '../../test/renderApp';
import { page, session } from '../../test/sessionFixtures';
import { setupUser } from '../../test/user';
import { deviceKey, shortType } from './format';

vi.mock('../../api/sessions');
vi.mock('../../api/ssdp', async (importOriginal) => {
  const actual = await importOriginal<typeof ssdpApi>();
  return { ...actual, getSsdpStats: vi.fn(), listSsdpDevices: vi.fn(), listSsdpMessages: vi.fn() };
});

const ID = '01JC0FFEE0000000000000000A';
const T0 = Date.UTC(2026, 10, 8, 10, 0, 0) * 1000;
const IGD = 'urn:schemas-upnp-org:device:InternetGatewayDevice:1';

function endpoint(ip: string, names: string[] = []): Endpoint {
  return { ip, names, category: 'private', country: null };
}

function stats(overrides: Partial<SsdpStats> = {}): SsdpStats {
  return {
    messages: 12,
    notify: 8,
    alive: 7,
    byebye: 1,
    update: 0,
    search: 2,
    response: 1,
    invalid: 1,
    devices: 2,
    senders: 3,
    targets: [
      { name: 'upnp:rootdevice', count: 4 },
      { name: IGD, count: 2 },
    ],
    software: [{ name: 'Linux/5.10 UPnP/1.0 ExampleGateway/2.1', count: 6 }],
    top_senders: [{ address: endpoint('192.168.1.1'), count: 6 }],
    ...overrides,
  };
}

function device(overrides: Partial<SsdpDeviceInfo> = {}): SsdpDeviceInfo {
  return {
    uuid: '6f1c2a40-1dd2-11b2-a5c3-020000000001',
    address: endpoint('192.168.1.1'),
    device_type: IGD,
    server: 'Linux/5.10 UPnP/1.0 ExampleGateway/2.1',
    location: 'http://192.168.1.1:5000/rootDesc.xml',
    targets: ['upnp:rootdevice', IGD],
    message_count: 6,
    alive_count: 5,
    byebye_count: 0,
    response_count: 1,
    first_ts_us: T0,
    last_ts_us: T0 + 60_000_000,
    ...overrides,
  };
}

const RAW = 'NOTIFY * HTTP/1.1\nHOST: 239.255.255.250:1900\nNT: upnp:rootdevice\nSERVER: <script>alert(1)</script>\n';

function message(overrides: Partial<SsdpMessageInfo> = {}): SsdpMessageInfo {
  return {
    id: 1,
    ts_us: T0,
    source: endpoint('192.168.1.1'),
    src_port: 1900,
    destination: { ...endpoint('239.255.255.250'), category: 'multicast' },
    dst_port: 1900,
    multicast: true,
    kind: 'notify',
    nts: 'alive',
    status: null,
    target: 'upnp:rootdevice',
    usn: 'uuid:6f1c2a40-1dd2-11b2-a5c3-020000000001::upnp:rootdevice',
    uuid: '6f1c2a40-1dd2-11b2-a5c3-020000000001',
    server: '<script>alert(1)</script>',
    user_agent: null,
    location: 'http://192.168.1.1:5000/rootDesc.xml',
    max_age: 120,
    mx: null,
    size: RAW.length,
    raw: RAW,
    raw_truncated: false,
    ...overrides,
  };
}

beforeEach(() => {
  setViewportWide(true);
  vi.mocked(api.getSession).mockResolvedValue(session({ state: 'ready' }));
  vi.mocked(ssdpApi.getSsdpStats).mockResolvedValue(stats());
  vi.mocked(ssdpApi.listSsdpDevices).mockResolvedValue(page([device(), device({ uuid: 'tv', address: endpoint('192.168.1.40'), device_type: '' })]));
  vi.mocked(ssdpApi.listSsdpMessages).mockResolvedValue(
    page([
      message(),
      message({ id: 2, kind: 'search', nts: null, target: 'ssdp:all', source: endpoint('192.168.1.10'), src_port: 50_000 }),
      message({ id: 3, kind: 'response', nts: null, status: 200, multicast: false }),
    ]),
  );
});

describe('SSDP view', () => {
  it('shows the figures, rankings, devices and messages', async () => {
    renderApp(`/sessions/${ID}/ssdp`);
    const summary = await screen.findByTestId('ssdp-summary');
    expect(await within(summary).findByText('7 alive, 1 byebye')).toBeInTheDocument();
    expect(screen.getByRole('list', { name: 'Most frequent NT and ST values' })).toBeInTheDocument();
    expect(screen.getByRole('list', { name: 'Addresses sending the most messages' })).toBeInTheDocument();
    const devices = await screen.findByRole('list', { name: 'UPnP devices' });
    expect(within(devices).getByText('InternetGatewayDevice:1')).toBeInTheDocument();
    expect(within(devices).getByText('Unknown type')).toBeInTheDocument();
    const messages = await screen.findByRole('list', { name: 'SSDP messages' });
    expect(within(messages).getByText('NOTIFY alive')).toBeInTheDocument();
    expect(within(messages).getByText('M-SEARCH')).toBeInTheDocument();
    expect(within(messages).getByText('Response 200')).toBeInTheDocument();
  });

  it('expands the raw message as escaped text with a copy action', async () => {
    const user = setupUser();
    renderApp(`/sessions/${ID}/ssdp`);
    const messages = await screen.findByRole('list', { name: 'SSDP messages' });
    await user.click(within(messages).getAllByRole('button', { expanded: false })[0] as HTMLElement);
    const raw = await screen.findByTestId('ssdp-raw');
    expect(raw.textContent).toBe(RAW);
    // Never interpreted: no element is created from the captured text.
    expect(raw.querySelector('script')).toBeNull();
    expect(document.querySelector('script:not([src])')).toBeNull();
    expect(screen.getByRole('button', { name: 'Copy raw message' })).toBeInTheDocument();
    // The location is text with a copy button, never a link.
    expect(screen.getAllByText('http://192.168.1.1:5000/rootDesc.xml').length).toBeGreaterThan(0);
    expect(document.querySelector('a[href^="http://192.168.1.1"]')).toBeNull();
  });

  it('filters the messages by type, device and target', async () => {
    const user = setupUser();
    renderApp(`/sessions/${ID}/ssdp`);
    await screen.findByRole('list', { name: 'SSDP messages' });
    await user.click(screen.getByRole('radio', { name: 'M-SEARCH' }));
    await waitFor(() => {
      expect(ssdpApi.listSsdpMessages).toHaveBeenLastCalledWith(ID, expect.objectContaining({ kind: 'search' }), expect.anything(), null);
    });
    await user.click(screen.getByRole('button', { name: `Show the messages of ${IGD}` }));
    await waitFor(() => {
      expect(ssdpApi.listSsdpMessages).toHaveBeenLastCalledWith(ID, expect.objectContaining({ kind: 'search', target: IGD }), expect.anything(), null);
    });
    const devices = screen.getByRole('list', { name: 'UPnP devices' });
    await user.click(within(devices).getAllByRole('button', { expanded: false })[0] as HTMLElement);
    await user.click(await screen.findByRole('button', { name: 'Show its messages' }));
    await waitFor(() => {
      expect(ssdpApi.listSsdpMessages).toHaveBeenLastCalledWith(
        ID,
        expect.objectContaining({ uuid: device().uuid, src: '192.168.1.1' }),
        expect.anything(),
        null,
      );
    });
    await user.click(screen.getByRole('button', { name: 'Remove the filter: Device InternetGatewayDevice:1, 192.168.1.1' }));
    await waitFor(() => {
      expect(ssdpApi.listSsdpMessages).toHaveBeenLastCalledWith(ID, expect.not.objectContaining({ uuid: expect.anything() }), expect.anything(), null);
    });
  });

  it('marks the device counters as whole session under a range', async () => {
    const range = { fromUs: T0, toUs: T0 + 59_999_999 };
    renderApp(`/sessions/${ID}/ssdp?from_us=${range.fromUs}&to_us=${range.toUs}`);
    await waitFor(() => {
      expect(ssdpApi.getSsdpStats).toHaveBeenCalledWith(ID, expect.anything(), range);
    });
    expect(ssdpApi.listSsdpDevices).toHaveBeenCalledWith(ID, expect.anything(), expect.anything(), range);
    await screen.findByRole('list', { name: 'UPnP devices' });
    expect(screen.getAllByText('Whole session').length).toBeGreaterThan(0);
  });

  it('shows the range empty state without messages', async () => {
    vi.mocked(ssdpApi.getSsdpStats).mockResolvedValue(stats({ messages: 0, notify: 0, alive: 0, byebye: 0, search: 0, response: 0, invalid: 0, devices: 0, senders: 0, targets: [], software: [], top_senders: [] }));
    renderApp(`/sessions/${ID}/ssdp?from_us=${T0}&to_us=${T0 + 1}`);
    expect(await screen.findByText('No SSDP message')).toBeInTheDocument();
    expect(screen.getAllByText('Nothing was recorded between these times.').length).toBeGreaterThan(0);
  });
});

describe('SSDP helpers', () => {
  it('shortens device types and keys devices stably', () => {
    expect(shortType(IGD)).toBe('InternetGatewayDevice:1');
    expect(shortType('upnp:rootdevice')).toBe('upnp:rootdevice');
    expect(deviceKey(device())).toBe(deviceKey(device({ message_count: 99 })));
    expect(deviceKey(device())).not.toBe(deviceKey(device({ address: endpoint('192.168.1.2') })));
  });
});
