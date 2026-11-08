import { act, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { ComponentProps } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import * as client from '../../api/client';
import { ApiError } from '../../api/client';
import * as overviewApi from '../../api/overview';
import { trafficQuery } from '../../api/overview';
import * as api from '../../api/sessions';
import type { OverviewSummary } from '../../api/types/OverviewSummary';
import type { TrafficSeries } from '../../api/types/TrafficSeries';
import type { Chart } from '../../components/Chart';
import { renderApp, setViewportWide } from '../../test/renderApp';
import { session } from '../../test/sessionFixtures';
import { moduleState, MODULE_ITEMS } from './modules';
import { buildTrafficOption, FULL_ZOOM, tooltipHtml, type TrafficFormat, zoomOfEvent } from './trafficChart';

vi.mock('../../api/sessions');
vi.mock('../../api/overview', async (importOriginal) => ({
  ...(await importOriginal<typeof overviewApi>()),
  getOverviewSummary: vi.fn(),
  getTraffic: vi.fn(),
}));
vi.mock('../../api/client', async (importOriginal) => ({
  ...(await importOriginal<typeof client>()),
  apiGet: vi.fn(),
}));

// ECharts does not run in jsdom: the chart is replaced by a probe exposing its props.
type ChartProps = ComponentProps<typeof Chart>;
const chart: { props: ChartProps | null } = { props: null };
vi.mock('../../components/Chart', () => ({
  Chart: (props: ChartProps) => {
    chart.props = props;
    return <div data-testid="chart" data-empty={String(props.empty === true)} />;
  },
}));

const ID = '01JC0FFEE0000000000000000A';
const T0 = Date.UTC(2026, 10, 8, 10, 0, 0) * 1_000_000;

function summary(overrides: Partial<OverviewSummary> = {}): OverviewSummary {
  return {
    id: ID,
    name: 'office-uplink',
    state: 'ready',
    first_ts_us: T0,
    last_ts_us: T0 + 3_600_000_000,
    duration_us: 3_600_000_000,
    packets: 123_456,
    bytes: 98_765_432,
    chunk_count: 49,
    linktypes: [1],
    host_count: 42,
    flow_count: 1_234,
    anomaly_count: 2,
    modules: [
      { id: 'connections', count: 1_234 },
      { id: 'hosts', count: 42 },
    ],
    ...overrides,
  };
}

function traffic(): TrafficSeries {
  return {
    start_us: T0,
    step_us: 60_000_000,
    points: 3,
    series: [
      { protocol: 'dns', bytes: [100, 0, 300], packets: [1, 0, 3], total_bytes: 400, total_packets: 4 },
      { protocol: 'http', bytes: [2000, 1000, 0], packets: [4, 2, 0], total_bytes: 3000, total_packets: 6 },
      { protocol: 'tls', bytes: [5000, 5000, 5000], packets: [5, 5, 5], total_bytes: 15000, total_packets: 15 },
    ],
  };
}

interface SeriesProbe {
  name: string;
  stack?: string;
  data: [number, number | null][];
}

const optionOf = () => (chart.props?.option ?? {}) as { series?: SeriesProbe[]; legend?: unknown; dataZoom?: { start: number }[] };
const seriesNames = () => (optionOf().series ?? []).map((s) => s.name);

describe('Overview view', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    chart.props = null;
    setViewportWide(true);
    vi.mocked(client.apiGet).mockResolvedValue({ version: 'test', read_only: true, can_browse: false, status: 'ok' });
    vi.mocked(api.getSession).mockResolvedValue(session());
    vi.mocked(overviewApi.getOverviewSummary).mockResolvedValue(summary());
    vi.mocked(overviewApi.getTraffic).mockResolvedValue(traffic());
  });

  it('shows the session name, the summary band and the module cards', async () => {
    renderApp(`/sessions/${ID}/overview`);
    expect(await screen.findByText('office-uplink')).toBeInTheDocument();
    const band = within(await screen.findByTestId('overview-summary'));
    expect(await band.findByText('123,456')).toBeInTheDocument();
    expect(band.getByText('1 h 00 min')).toBeInTheDocument();
    expect(band.getByText('94.2 MiB')).toBeInTheDocument();
    expect(band.getByText('2 anomalies')).toBeInTheDocument();
    expect(band.getByText('Link: Ethernet')).toBeInTheDocument();
    // Module cards: phase 3 views listed, none clickable until their view exists.
    expect(screen.getByRole('heading', { name: 'Connections' })).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Telnet' })).toBeNull();
    expect(screen.getByRole('heading', { name: 'Connections' }).closest('a')).toBeNull();
    expect(screen.getByRole('heading', { name: 'Connections' }).closest('[aria-disabled]')).toHaveAttribute(
      'title',
      'Available in a later version',
    );
  });

  it('stacks the selected protocols and toggles them with the selector, All and None', async () => {
    renderApp(`/sessions/${ID}/overview`);
    await waitFor(() => {
      expect(seriesNames()).toEqual(['DNS', 'HTTP', 'TLS']);
    });
    expect(optionOf().series?.every((s) => s.stack === 'traffic')).toBe(true);
    expect(overviewApi.getTraffic).toHaveBeenCalledWith(ID, { points: 500 }, expect.anything());

    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: /Protocols/ }));
    const panel = within(screen.getByRole('group', { name: 'Protocols' }));
    await user.click(panel.getByRole('checkbox', { name: /HTTP/ }));
    expect(seriesNames()).toEqual(['DNS', 'TLS']);
    expect(screen.getByRole('button', { name: /Protocols/ })).toHaveTextContent('2/3');

    await user.click(panel.getByRole('button', { name: 'None' }));
    expect(screen.getByTestId('chart')).toHaveAttribute('data-empty', 'true');
    expect(chart.props?.emptyText).toBe('No protocol selected');

    await user.click(panel.getByRole('button', { name: 'All' }));
    expect(seriesNames()).toEqual(['DNS', 'HTTP', 'TLS']);
    await user.keyboard('{Escape}');
    expect(screen.queryByRole('group', { name: 'Protocols' })).toBeNull();
  });

  it('switches between bytes and packets and between linear and log scales', async () => {
    renderApp(`/sessions/${ID}/overview`);
    await waitFor(() => {
      expect(optionOf().series?.[0]?.data.map((d) => d[1])).toEqual([100, 0, 300]);
    });
    const user = userEvent.setup();
    await user.click(screen.getByRole('radio', { name: 'Packets' }));
    expect(optionOf().series?.[0]?.data.map((d) => d[1])).toEqual([1, 0, 3]);

    await user.click(screen.getByRole('radio', { name: 'Log' }));
    const dns = optionOf().series?.[0];
    expect(dns?.stack).toBeUndefined();
    expect(dns?.data.map((d) => d[1])).toEqual([1, null, 3]);
  });

  it('follows the zoom and resets it', async () => {
    renderApp(`/sessions/${ID}/overview`);
    await waitFor(() => {
      expect(chart.props?.onEvents).toBeDefined();
    });
    const reset = screen.getByRole('button', { name: 'Reset zoom' });
    expect(reset).toBeDisabled();
    act(() => {
      chart.props?.onEvents?.datazoom?.({ batch: [{ start: 20, end: 60 }] });
    });
    await waitFor(() => {
      expect(optionOf().dataZoom?.[0]?.start).toBe(20);
    });
    expect(reset).toBeEnabled();
    await userEvent.click(reset);
    expect(optionOf().dataZoom?.[0]?.start).toBe(0);
    expect(reset).toBeDisabled();
  });

  it('hides the legend below 640 px', async () => {
    setViewportWide(false);
    renderApp(`/sessions/${ID}/overview`);
    await waitFor(() => {
      expect(seriesNames()).toHaveLength(3);
    });
    expect(optionOf().legend).toBeUndefined();
    expect(chart.props?.height).toBe(240);
  });

  it('shows an explicit empty state for a session without traffic', async () => {
    vi.mocked(overviewApi.getTraffic).mockResolvedValue({ start_us: 0, step_us: 1_000_000, points: 0, series: [] });
    renderApp(`/sessions/${ID}/overview`);
    await waitFor(() => {
      expect(chart.props?.empty).toBe(true);
    });
    expect(chart.props?.emptyText).toBe('No traffic recorded in this session');
  });

  it('reports load errors with retry', async () => {
    vi.mocked(overviewApi.getOverviewSummary).mockRejectedValue(new ApiError(500, 'internal', 'boom'));
    vi.mocked(overviewApi.getTraffic).mockRejectedValue(new ApiError(500, 'internal', 'boom'));
    renderApp(`/sessions/${ID}/overview`);
    expect(await screen.findByText('The overview could not be loaded')).toBeInTheDocument();
    await waitFor(() => {
      expect(chart.props?.error).toBe('The traffic series could not be loaded');
    });
    vi.mocked(overviewApi.getOverviewSummary).mockResolvedValue(summary());
    await userEvent.click(screen.getByRole('button', { name: 'Retry' }));
    expect(await screen.findByText('123,456')).toBeInTheDocument();
  });

  it('waits for the end of an import without calling the overview routes', async () => {
    vi.mocked(api.getSession).mockResolvedValue(session({ state: 'importing' }));
    renderApp(`/sessions/${ID}/overview`);
    expect(await screen.findByText('Import in progress')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Go to Captures' })).toBeInTheDocument();
    expect(overviewApi.getOverviewSummary).not.toHaveBeenCalled();
    expect(overviewApi.getTraffic).not.toHaveBeenCalled();
  });

  it('explains a failed import', async () => {
    vi.mocked(api.getSession).mockResolvedValue(session({ state: 'failed', state_detail: 'import failed (details in the application log)' }));
    renderApp(`/sessions/${ID}/overview`);
    expect(await screen.findByText('Import failed')).toBeInTheDocument();
    expect(screen.getByText('import failed (details in the application log)')).toBeInTheDocument();
    expect(overviewApi.getTraffic).not.toHaveBeenCalled();
  });
});

const FORMAT: TrafficFormat = {
  protocol: (p) => p.toUpperCase(),
  value: (v) => `${v} B`,
  axis: (v) => `${v}`,
  bucket: () => '10:00:00',
  total: 'Total',
};

describe('traffic chart option', () => {
  it('places one point per bucket at its start time and a right legend on wide charts', () => {
    const option = buildTrafficOption({
      data: traffic(),
      selected: new Set(['tls', 'dns']),
      metric: 'bytes',
      scale: 'linear',
      zoom: FULL_ZOOM,
      legend: 'right',
      format: FORMAT,
    }) as { series: SeriesProbe[]; legend: { orient: string; data: string[]; selectedMode: boolean } };
    expect(option.series.map((s) => s.name)).toEqual(['DNS', 'TLS']);
    expect(option.series[1]?.data.map((d) => d[0])).toEqual([T0 / 1000, T0 / 1000 + 60_000, T0 / 1000 + 120_000]);
    expect(option.legend).toMatchObject({ orient: 'vertical', data: ['DNS', 'TLS'], selectedMode: false });
  });

  it('sorts the tooltip by value, drops zeros and adds the share and total', () => {
    const html = tooltipHtml(
      [
        { seriesName: 'DNS', marker: '', value: [0, 100] },
        { seriesName: 'HTTP', marker: '', value: [0, 0] },
        { seriesName: 'TLS', marker: '', value: [0, 300] },
      ],
      FORMAT,
    );
    expect(html.indexOf('TLS')).toBeLessThan(html.indexOf('DNS'));
    expect(html).not.toContain('HTTP');
    expect(html).toContain('75.0 %');
    expect(html).toContain('400 B');
    expect(tooltipHtml([{ seriesName: '<b>', value: [0, 1] }], FORMAT)).toContain('&lt;b&gt;');
  });

  it('reads the zoom window of slider and inside events', () => {
    expect(zoomOfEvent({ start: 10, end: 90 })).toEqual({ start: 10, end: 90 });
    expect(zoomOfEvent({ batch: [{ start: -5, end: 120 }] })).toEqual({ start: 0, end: 100 });
    expect(zoomOfEvent({ batch: [{}] })).toBeNull();
    expect(zoomOfEvent(null)).toBeNull();
  });
});

describe('overview helpers', () => {
  it('builds the time series query string', () => {
    expect(trafficQuery()).toBe('');
    expect(trafficQuery({ from_us: 1.5, to_us: 9, points: 5000, metric: 'bytes', protocols: ['dns', 'tls'] })).toBe(
      '?from_us=1&to_us=9&points=2000&metric=bytes&protocols=dns%2Ctls',
    );
    expect(trafficQuery({ protocols: [] })).toBe('?protocols=');
  });

  it('dims modules without view, without table or without rows', () => {
    const connections = MODULE_ITEMS.find((i) => i.id === 'connections');
    if (connections === undefined) throw new Error('connections module');
    const counts = new Map([['connections', 3]]);
    expect(moduleState(connections, counts)).toEqual({ count: 3, active: false, reason: 'later' });
    const enabled = { ...connections, enabled: true };
    expect(moduleState(enabled, counts)).toEqual({ count: 3, active: true, reason: null });
    expect(moduleState(enabled, new Map([['connections', 0]])).reason).toBe('empty');
    expect(moduleState(enabled, new Map()).reason).toBe('notRun');
    expect(MODULE_ITEMS.every((i) => i.group === 'analysis' || i.enabled)).toBe(true);
  });
});
