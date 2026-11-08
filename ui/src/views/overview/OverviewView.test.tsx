import { act, screen, waitFor, within } from '@testing-library/react';
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
import { setupUser } from '../../test/user';
import { moduleState, MODULE_ITEMS } from './modules';
import { buildTrafficOption, byteAxis, tooltipHtml, type TrafficFormat, zoomOfEvent } from './trafficChart';

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
const chart = {
  props: null as ChartProps | null,
  dispatchAction: vi.fn<(action: { type: string } & Record<string, unknown>) => void>(),
};
vi.mock('../../components/Chart', () => ({
  Chart: (props: ChartProps) => {
    chart.props = props;
    const handle = props.handleRef;
    if (typeof handle === 'object' && handle !== null) handle.current = { dispatchAction: chart.dispatchAction };
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

const optionOf = () => (chart.props?.option ?? {}) as { series?: SeriesProbe[]; legend?: unknown };
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
    // Module cards: phase 3 views listed, clickable once their view exists and found something.
    expect(screen.queryByRole('heading', { name: 'Telnet' })).toBeNull();
    expect(screen.getByRole('heading', { name: 'Connections' }).closest('a')).toHaveAttribute(
      'href',
      `/sessions/${ID}/connections`,
    );
    // Open Ports exists but the session has no count for it (not analyzed).
    expect(screen.getByRole('heading', { name: 'Open Ports' }).closest('[aria-disabled]')).toHaveAttribute(
      'title',
      'Not analyzed in this session',
    );
    expect(screen.getByRole('heading', { name: 'Pictures' }).closest('[aria-disabled]')).toHaveAttribute(
      'title',
      'Not analyzed in this session',
    );
  });

  it('stacks the selected protocols and toggles them with the selector, All and None', async () => {
    renderApp(`/sessions/${ID}/overview`);
    await waitFor(() => {
      expect(seriesNames()).toEqual(['DNS', 'HTTP', 'TLS']);
    });
    expect(optionOf().series?.every((s) => s.stack === 'traffic')).toBe(true);
    expect(overviewApi.getTraffic).toHaveBeenCalledWith(ID, { points: 500 }, expect.anything());

    const user = setupUser();
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
    const user = setupUser();
    await user.click(screen.getByRole('radio', { name: 'Packets' }));
    expect(optionOf().series?.[0]?.data.map((d) => d[1])).toEqual([1, 0, 3]);

    await user.click(screen.getByRole('radio', { name: 'Log' }));
    const dns = optionOf().series?.[0];
    expect(dns?.stack).toBeUndefined();
    expect(dns?.data.map((d) => d[1])).toEqual([1, null, 3]);
  });

  it('follows the zoom without rebuilding the option and resets it through the chart', async () => {
    renderApp(`/sessions/${ID}/overview`);
    await waitFor(() => {
      expect(seriesNames()).toHaveLength(3);
    });
    const reset = screen.getByRole('button', { name: 'Reset zoom' });
    expect(reset).toBeDisabled();
    const before = chart.props?.option;
    act(() => {
      chart.props?.onEvents?.datazoom?.({ batch: [{ start: 20, end: 60 }] });
    });
    await waitFor(() => {
      expect(reset).toBeEnabled();
    });
    // Same option object: the renderer does not re-apply it while the user drags.
    expect(chart.props?.option).toBe(before);
    const user = setupUser();
    await user.click(reset);
    expect(chart.dispatchAction).toHaveBeenCalledWith({ type: 'dataZoom', start: 0, end: 100 });
    expect(reset).toBeDisabled();
    expect(chart.props?.option).toBe(before);
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
    const user = setupUser();
    await user.click(screen.getByRole('button', { name: 'Retry' }));
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

  it('explains a session this version cannot open', async () => {
    vi.mocked(overviewApi.getOverviewSummary).mockRejectedValue(
      new ApiError(409, 'urn:netsift:problem:session-too-new', 'newer'),
    );
    renderApp(`/sessions/${ID}/overview`);
    expect(
      await screen.findByText('This session was created by a newer version of NetSift. Update the application to open it.'),
    ).toBeInTheDocument();
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
      legend: 'right',
      compact: false,
      format: FORMAT,
    }) as {
      series: SeriesProbe[];
      legend: { orient: string; data: string[]; selectedMode: boolean };
      yAxis: { interval?: number; max?: number };
      dataZoom: Record<string, unknown>[];
    };
    expect(option.series.map((s) => s.name)).toEqual(['DNS', 'TLS']);
    // Stacked peak 5300 B (DNS 300 + TLS 5000): round 2 KiB ticks up to 6 KiB.
    expect(option.yAxis).toMatchObject({ interval: 2048, max: 6144 });
    // The zoom window is not part of the option.
    expect(option.dataZoom.every((z) => !('start' in z) && !('end' in z))).toBe(true);
    expect(option.series[1]?.data.map((d) => d[0])).toEqual([T0 / 1000, T0 / 1000 + 60_000, T0 / 1000 + 120_000]);
    expect(option.legend).toMatchObject({ orient: 'vertical', data: ['DNS', 'TLS'], selectedMode: false });
  });

  it('uses round byte ticks only for bytes, and fewer time ticks on narrow charts', () => {
    const base = { data: traffic(), selected: new Set(['dns', 'http', 'tls'] as const), legend: 'none', format: FORMAT } as const;
    interface Axes {
      xAxis: { splitNumber?: number };
      yAxis: { interval?: number; logBase?: number };
    }
    const axes = (option: unknown) => option as Axes;
    const packets = axes(buildTrafficOption({ ...base, metric: 'packets', scale: 'linear', compact: true }));
    expect(packets.yAxis.interval).toBeUndefined();
    expect(packets.xAxis.splitNumber).toBe(2);
    const log = axes(buildTrafficOption({ ...base, metric: 'bytes', scale: 'log', compact: false }));
    expect(log.yAxis).toMatchObject({ logBase: 1024 });
    expect(log.yAxis.interval).toBeUndefined();
    expect(log.xAxis.splitNumber).toBeUndefined();
  });

  it('picks byte steps of 1, 2 or 5 x 10^n in the right IEC unit', () => {
    expect(byteAxis(0)).toBeNull();
    expect(byteAxis(3)).toEqual({ interval: 1, max: 3 });
    expect(byteAxis(78_000)).toEqual({ interval: 20 * 1024, max: 80 * 1024 });
    // 85 KiB: five 20 KiB steps rather than two 50 KiB ones.
    expect(byteAxis(85 * 1024)).toEqual({ interval: 20 * 1024, max: 100 * 1024 });
    expect(byteAxis(3 * 1024 ** 2)).toEqual({ interval: 1024 ** 2, max: 3 * 1024 ** 2 });
    expect(byteAxis(1.9 * 1024 ** 3)).toEqual({ interval: 500 * 1024 ** 2, max: 2000 * 1024 ** 2 });
    // Past 500 of a unit, the next unit.
    expect(byteAxis(3000 * 1024)).toEqual({ interval: 1024 * 1024, max: 3 * 1024 * 1024 });
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
    expect(moduleState({ ...connections, enabled: false }, counts)).toEqual({ count: 3, active: false, reason: 'later' });
    const enabled = { ...connections, enabled: true };
    expect(moduleState(enabled, counts)).toEqual({ count: 3, active: true, reason: null });
    expect(moduleState(enabled, new Map([['connections', 0]])).reason).toBe('empty');
    expect(moduleState(enabled, new Map()).reason).toBe('notRun');
    expect(MODULE_ITEMS.every((i) => i.group === 'analysis' || i.enabled)).toBe(true);
  });
});
