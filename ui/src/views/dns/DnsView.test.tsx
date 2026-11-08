import { screen, waitFor, within } from '@testing-library/react';
import type { ComponentProps } from 'react';
import { beforeEach, describe, expect, it, onTestFinished, vi } from 'vitest';
import * as client from '../../api/client';
import * as dnsApi from '../../api/dns';
import { dnsListQuery } from '../../api/dns';
import * as api from '../../api/sessions';
import type { DnsMessage } from '../../api/types/DnsMessage';
import type { DnsPair } from '../../api/types/DnsPair';
import type { DnsServer } from '../../api/types/DnsServer';
import type { DnsStats } from '../../api/types/DnsStats';
import type { Chart } from '../../components/Chart';
import { renderApp, setViewportWide } from '../../test/renderApp';
import { page, session } from '../../test/sessionFixtures';
import { setupUser } from '../../test/user';
import { barsOption, donutOption, escapeHtml, truncateLabel, withOther } from './dnsCharts';
import { formatLatency, rcodeLabel, suffixLabel } from './dnsFormat';
import { worldMapHeight, stepOf } from '../../charts/worldMapOption';
import { groupByCountry } from './serverMap';
import i18n from '../../i18n';

vi.mock('../../api/sessions');
vi.mock('../../api/dns', async (importOriginal) => ({
  ...(await importOriginal<typeof dnsApi>()),
  getDnsStats: vi.fn(),
  getDnsPairs: vi.fn(),
  getDnsMessages: vi.fn(),
  getDnsServers: vi.fn(),
}));
vi.mock('../../api/client', async (importOriginal) => ({
  ...(await importOriginal<typeof client>()),
  apiGet: vi.fn(),
}));
// The world map (ECharts geo) does not run in jsdom.
vi.mock('../../charts/worldMap', () => ({ loadWorldMap: () => ({ anchors: new Map([['US', [-100, 40]]]) }) }));

type ChartProps = ComponentProps<typeof Chart>;
const charts: ChartProps[] = [];
vi.mock('../../components/Chart', () => ({
  Chart: (props: ChartProps) => {
    charts.push(props);
    return <div data-testid="chart" aria-label={props.ariaLabel} data-empty={String(props.empty === true)} />;
  },
}));

const ID = '01JC0FFEE0000000000000000A';
const T0 = Date.UTC(2026, 10, 8, 10, 0, 0) * 1000;

function stats(overrides: Partial<DnsStats> = {}): DnsStats {
  return {
    total: 19,
    errors: 4,
    answered: 15,
    protocols: [
      { protocol: 'dns', count: 12, errors: 3 },
      { protocol: 'nbns', count: 7, errors: 1 },
    ],
    rcodes: [
      { key: 'NOERROR', count: 12 },
      { key: 'NXDOMAIN', count: 3 },
      { key: null, count: 3 },
      { key: 'timeout', count: 1 },
    ],
    rcode_other: 0,
    qtypes: [
      { key: 'A', count: 9 },
      { key: 'NB', count: 7 },
      { key: 'AAAA', count: 3 },
    ],
    qtype_other: 0,
    countries: [],
    country_unknown: { country: null, servers: 3, messages: 19 },
    latency_p50_us: 500,
    latency_p95_us: 2_500,
    ...overrides,
  };
}

function pair(overrides: Partial<DnsPair> = {}): DnsPair {
  return {
    id: '1',
    protocol: 'dns',
    client: { ip: '192.168.1.10', country: null, category: 'private', names: [] },
    server: { ip: '192.168.1.1', country: null, category: 'private', names: ['router.lan'] },
    messages: 9,
    errors: 3,
    name_count: 7,
    top_names: ['www.example.test', 'secure.example.test', 'missing.example.test', 'a.test', 'b.test'],
    first_ts_us: T0,
    last_ts_us: T0 + 1_000_000,
    ...overrides,
  };
}

function message(overrides: Partial<DnsMessage> = {}): DnsMessage {
  return {
    id: '10',
    pair_id: '2',
    ts_us: T0,
    flow_id: '123',
    transport: 'udp',
    protocol: 'nbns',
    client_ip: '192.168.1.10',
    client_port: 137,
    server_ip: '192.168.1.255',
    server_port: 137,
    responder_ip: null,
    txid: 0x4444,
    opcode: 'QUERY',
    qname: 'WPAD',
    qtype: 'NB',
    nb_suffix: 0,
    flags: 0x0110,
    rcode: 'timeout',
    latency_us: null,
    answers: [],
    has_query: true,
    has_response: false,
    ...overrides,
  };
}

function server(ip: string, country: string | null, messages: number): DnsServer {
  return { host: { ip, country, category: 'public', names: [] }, messages, errors: 0, clients: 1, protocols: ['dns'] };
}

const lastPairsCall = () => vi.mocked(dnsApi.getDnsPairs).mock.calls.at(-1)?.[1];

describe('DNS view', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    charts.length = 0;
    setViewportWide(true);
    vi.mocked(client.apiGet).mockResolvedValue({ version: 'test', read_only: true, can_browse: false, status: 'ok' });
    vi.mocked(api.getSession).mockResolvedValue(session());
    vi.mocked(dnsApi.getDnsStats).mockResolvedValue(stats());
    vi.mocked(dnsApi.getDnsPairs).mockResolvedValue({
      items: [
        pair(),
        pair({
          id: '2',
          protocol: 'nbns',
          server: { ip: '192.168.1.255', country: null, category: 'broadcast', names: [] },
          messages: 4,
          errors: 1,
          name_count: 2,
          top_names: ['FILESRV01', 'WPAD'],
        }),
      ],
      next_cursor: 'c1',
      total_estimate: 4,
    });
    vi.mocked(dnsApi.getDnsMessages).mockResolvedValue(
      page([
        message({ id: '11', qname: 'FILESRV01', nb_suffix: 0x20, rcode: 'NOERROR', responder_ip: '192.168.1.20', latency_us: 500, answers: [{ name: 'FILESRV01', type: 'NB', value: '192.168.1.20', ttl: 300 }] }),
        message(),
      ]),
    );
    vi.mocked(dnsApi.getDnsServers).mockResolvedValue(page([server('192.168.1.1', null, 9)]));
  });

  it('shows the charts, the filters with counters and the grouped table', async () => {
    renderApp(`/sessions/${ID}/dns`);
    expect(await screen.findByRole('heading', { level: 1, name: 'DNS' })).toBeInTheDocument();
    expect(await screen.findByText('office-uplink')).toBeInTheDocument();
    const table = await screen.findByRole('table', { name: 'DNS clients and servers' });
    const rows = within(table).getAllByRole('row');
    expect(rows).toHaveLength(3);
    expect(within(table).getByText('www.example.test')).toBeInTheDocument();
    expect(within(table).getByText('2 more')).toBeInTheDocument();
    expect(within(table).getByTitle('192.168.1.1 router.lan')).toBeInTheDocument();
    expect(screen.getByText('2 of 4')).toBeInTheDocument();

    // Toggles with counters: four protocols and the errors.
    const dns = screen.getAllByRole('switch', { name: /^DNS/ })[0];
    expect(dns).toHaveTextContent('12');
    expect(screen.getAllByRole('switch', { name: /^mDNS/ })[0]).toHaveTextContent('0');
    expect(screen.getAllByRole('switch', { name: /^Errors only/ })[0]).toHaveTextContent('4');

    // Charts: protocols donut, results and query types bars.
    await waitFor(() => {
      expect(charts.some((c) => c.ariaLabel === 'DNS transactions by result')).toBe(true);
    });
    expect(screen.getByText('Response time: median 0.5 ms, 95th percentile 2.5 ms')).toBeInTheDocument();
    expect(screen.getByTestId('donut-total')).toHaveTextContent('19');
    // No public server: an explicit empty state in the country list, no map.
    expect(await screen.findByText('No server located in a country')).toBeInTheDocument();
    expect(screen.queryByText('Server locations')).toBeNull();
  });

  it('places located servers on the map and in the country list', async () => {
    vi.mocked(dnsApi.getDnsStats).mockResolvedValue(
      stats({
        countries: [{ country: 'US', servers: 2, messages: 12 }],
        country_unknown: { country: null, servers: 1, messages: 7 },
      }),
    );
    vi.mocked(dnsApi.getDnsServers).mockResolvedValue(
      page([server('1.1.1.1', 'US', 7), server('8.8.8.8', 'US', 5), server('192.168.1.1', null, 7)]),
    );
    // A laid out map card (jsdom has no layout): the map height follows its width.
    const original = globalThis.ResizeObserver;
    globalThis.ResizeObserver = class {
      constructor(private readonly callback: ResizeObserverCallback) {}
      observe(): void {
        this.callback([{ contentRect: { width: 960 } } as ResizeObserverEntry], this as unknown as ResizeObserver);
      }
      unobserve(): void {
        /* nothing to follow */
      }
      disconnect(): void {
        /* nothing to follow */
      }
    };
    onTestFinished(() => {
      globalThis.ResizeObserver = original;
    });
    renderApp(`/sessions/${ID}/dns`);
    const list = await screen.findByRole('list', { name: 'Queries by country of the server' });
    expect(within(list).getByText('United States')).toBeInTheDocument();
    expect(within(list).getByText('Local or unknown')).toBeInTheDocument();
    expect(await screen.findByText('Server locations')).toBeInTheDocument();
    await waitFor(() => {
      expect(charts.some((c) => c.ariaLabel.startsWith('World map'))).toBe(true);
    });
    const map = charts.findLast((c) => c.ariaLabel.startsWith('World map'));
    expect(map?.height).toBe(300);
    const option = map?.option as { series: { data: { name: string; value: number[] }[] }[]; tooltip: { formatter: (p: unknown) => string } };
    expect(option.series[0]?.data).toEqual([{ name: 'US', value: [-100, 40, 12] }]);
    expect(option.tooltip.formatter({ name: 'US' })).toBe('<b>United States</b>: 12 queries<br/>1.1.1.1: 7 queries<br/>8.8.8.8: 5 queries');
  });

  it('expands a pair into its queries', async () => {
    const user = setupUser();
    renderApp(`/sessions/${ID}/dns`);
    const expand = await screen.findByRole('button', { name: 'Show the queries of 192.168.1.10 to 192.168.1.255' });
    await user.click(expand);
    const detail = await screen.findByRole('table', { name: 'Queries of 192.168.1.10 to 192.168.1.255' });
    expect(vi.mocked(dnsApi.getDnsMessages).mock.calls[0]?.[1]).toMatchObject({ pair: '2' });
    expect(within(detail).getByText('WPAD')).toBeInTheDocument();
    expect(within(detail).getByText('No response')).toBeInTheDocument();
    expect(within(detail).getByText('NOERROR')).toBeInTheDocument();
    expect(within(detail).getByText('Answered by 192.168.1.20')).toBeInTheDocument();
    expect(within(detail).getByText('<20> file server')).toBeInTheDocument();
    expect(within(detail).getByText('NB 192.168.1.20')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Hide the queries' }));
    expect(screen.queryByRole('table', { name: /^Queries of/ })).toBeNull();
  });

  it('sends the filters and the search to the server', async () => {
    const user = setupUser();
    renderApp(`/sessions/${ID}/dns`);
    await screen.findByRole('table', { name: 'DNS clients and servers' });
    await user.click(screen.getAllByRole('switch', { name: /^NBNS/ })[0] as HTMLElement);
    await waitFor(() => {
      expect(lastPairsCall()).toMatchObject({ protocols: ['dns', 'mdns', 'llmnr'], errors: false });
    });
    await user.click(screen.getAllByRole('switch', { name: /^Errors only/ })[0] as HTMLElement);
    await waitFor(() => {
      expect(lastPairsCall()).toMatchObject({ errors: true });
    });
    await user.type(screen.getByRole('searchbox'), 'wpad');
    await waitFor(() => {
      expect(lastPairsCall()).toMatchObject({ q: 'wpad' });
    });
  });

  it('loads the next page of pairs', async () => {
    const user = setupUser();
    renderApp(`/sessions/${ID}/dns`);
    await user.click(await screen.findByRole('button', { name: 'Show more' }));
    await waitFor(() => {
      expect(lastPairsCall()).toMatchObject({ cursor: 'c1' });
    });
  });

  it('shows the cards layout on narrow screens', async () => {
    setViewportWide(false);
    renderApp(`/sessions/${ID}/dns`);
    const list = await screen.findByRole('list', { name: 'DNS clients and servers' });
    expect(within(list).getAllByRole('listitem')).toHaveLength(2);
    expect(within(list).getByText('9 queries, 3 errors')).toBeInTheDocument();
  });

  it('explains an empty session and a filter without match', async () => {
    vi.mocked(dnsApi.getDnsStats).mockResolvedValue(
      stats({ total: 0, errors: 0, answered: 0, protocols: [], rcodes: [], qtypes: [], latency_p50_us: null, latency_p95_us: null, country_unknown: { country: null, servers: 0, messages: 0 } }),
    );
    vi.mocked(dnsApi.getDnsPairs).mockResolvedValue(page([]));
    vi.mocked(dnsApi.getDnsServers).mockResolvedValue(page([]));
    renderApp(`/sessions/${ID}/dns`);
    expect(await screen.findByText('No DNS traffic in this session')).toBeInTheDocument();
    // The last render of each chart shows its empty state.
    await waitFor(() => {
      const last = new Map(charts.map((c) => [c.ariaLabel, c]));
      expect(last.size).toBe(3);
      expect([...last.values()].every((c) => c.empty === true && c.loading !== true)).toBe(true);
    });
  });

  it('waits for a running import', async () => {
    vi.mocked(api.getSession).mockResolvedValue(session({ state: 'importing' }));
    renderApp(`/sessions/${ID}/dns`);
    expect(await screen.findByText('The DNS analysis appears when the import ends.')).toBeInTheDocument();
    expect(dnsApi.getDnsStats).not.toHaveBeenCalled();
  });
});

describe('DNS charts and formats', () => {
  it('builds the donut with the total and escaped tooltips', () => {
    const option = donutOption(
      [
        { key: 'dns', label: 'DNS', value: 3 },
        { key: 'nbns', label: '<b>NBNS</b>', value: 1 },
      ],
      String,
    ) as { tooltip: { formatter: (p: unknown) => string }; legend: { data: string[] } };
    expect(option.legend.data).toEqual(['DNS', '<b>NBNS</b>']);
    expect(option.tooltip.formatter({ name: '<b>NBNS</b>', value: 1 })).toBe('&#60;b&#62;NBNS&#60;/b&#62;: 1 (25\u00a0%)');
  });

  it('builds bars, largest first, with truncated labels and an Other bar', () => {
    const entries = withOther([{ key: 'A', label: 'A', value: 9 }], 2, 'Other');
    expect(entries.map((e) => e.key)).toEqual(['A', '__other']);
    const option = barsOption(entries, String) as {
      yAxis: { data: string[]; inverse: boolean; axisLabel: { formatter: (s: string) => string } };
    };
    expect(option.yAxis.data).toEqual(['A', 'Other']);
    expect(option.yAxis.inverse).toBe(true);
    expect(option.yAxis.axisLabel.formatter('x'.repeat(30))).toHaveLength(24);
    expect(truncateLabel('short')).toBe('short');
    expect(escapeHtml(`a&<>"'`)).toBe('a&#38;&#60;&#62;&#34;&#39;');
    expect(withOther([], 0, 'Other')).toEqual([]);
  });

  it('formats latencies, outcomes and NetBIOS suffixes', () => {
    expect(formatLatency(420, 'en')).toBe('0.4\u00a0ms');
    expect(formatLatency(12_345, 'en')).toBe('12\u00a0ms');
    expect(formatLatency(1_500_000, 'en')).toBe('1.5\u00a0s');
    const t = i18n.getFixedT('en');
    expect(rcodeLabel(t, null)).toBe('No response expected');
    expect(rcodeLabel(t, 'timeout')).toBe('No response');
    expect(rcodeLabel(t, 'SERVFAIL')).toBe('SERVFAIL');
    expect(suffixLabel(t, 0x1c)).toBe('<1C> domain controllers');
    expect(suffixLabel(t, 0x42)).toBe('<42>');
  });

  it('groups servers by country for the map', () => {
    const groups = groupByCountry([server('8.8.8.8', 'US', 5), server('1.1.1.1', 'US', 7), server('9.9.9.9', 'CH', 3), server('10.0.0.1', null, 50)]);
    expect(groups.map((g) => [g.code, g.messages])).toEqual([
      ['US', 12],
      ['CH', 3],
    ]);
    expect(groups[0]?.servers.map((s) => s.ip)).toEqual(['1.1.1.1', '8.8.8.8']);
    expect(worldMapHeight(960)).toBe(300);
    expect(worldMapHeight(100)).toBe(110);
    expect(stepOf(0, 10)).toBe(0);
    expect(stepOf(10, 10)).toBe(2);
    expect(stepOf(1, 1000)).toBe(0);
  });

  it('builds list query strings', () => {
    expect(dnsListQuery({})).toBe('');
    expect(dnsListQuery({ protocols: ['dns', 'nbns'], errors: true, q: ' wpad ', limit: 50, cursor: 'abc', pair: '3' })).toBe(
      '?pair=3&protocols=dns%2Cnbns&errors=true&q=wpad&limit=50&cursor=abc',
    );
    expect(dnsListQuery({ protocols: [], errors: false, q: '  ' })).toBe('?protocols=');
  });
});
