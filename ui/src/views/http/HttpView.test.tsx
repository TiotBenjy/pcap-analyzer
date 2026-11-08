import { act, screen, waitFor, within } from '@testing-library/react';
import type { ComponentProps } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import * as client from '../../api/client';
import * as httpApi from '../../api/http';
import * as api from '../../api/sessions';
import type { Chart } from '../../components/Chart';
import { detail, SESSION_ID, stats, tx } from '../../test/httpFixtures';
import { renderApp, setViewportWide } from '../../test/renderApp';
import { session } from '../../test/sessionFixtures';
import { setupUser } from '../../test/user';

vi.mock('../../api/sessions');
vi.mock('../../api/http', async (importOriginal) => ({
  ...(await importOriginal<typeof httpApi>()),
  getHttpStats: vi.fn(),
  listHttpTransactions: vi.fn(),
  getHttpTransaction: vi.fn(),
}));
vi.mock('../../api/client', async (importOriginal) => ({
  ...(await importOriginal<typeof client>()),
  apiGet: vi.fn(),
}));

// ECharts does not run in jsdom: charts are probes keeping their props by accessible name.
type ChartProps = ComponentProps<typeof Chart>;
const charts = new Map<string, ChartProps>();
vi.mock('../../components/Chart', () => ({
  Chart: (props: ChartProps) => {
    charts.set(props.ariaLabel, props);
    return <div data-testid="chart" aria-label={props.ariaLabel} />;
  },
}));

const lastListParams = () => vi.mocked(httpApi.listHttpTransactions).mock.lastCall?.[1];

describe('HTTP view', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    charts.clear();
    setViewportWide(true);
    vi.mocked(client.apiGet).mockResolvedValue({ version: 'test', read_only: true, can_browse: false, status: 'ok' });
    vi.mocked(api.getSession).mockResolvedValue(session());
    vi.mocked(httpApi.getHttpStats).mockResolvedValue(stats());
    vi.mocked(httpApi.listHttpTransactions).mockResolvedValue({
      items: [tx(3, { method: 'POST', path: '/login', query: null, status: 302 }), tx(2), tx(1, { status: 404 })],
      next_cursor: null,
      total_estimate: 3,
    });
    vi.mocked(httpApi.getHttpTransaction).mockImplementation((_id, tid) => Promise.resolve(detail(tx(tid))));
  });

  it('shows the charts, the tops and the transactions', async () => {
    renderApp(`/sessions/${SESSION_ID}/http`);
    const list = await screen.findByRole('list', { name: 'HTTP transactions' });
    expect(within(list).getAllByRole('listitem')).toHaveLength(3);
    expect(within(list).getByText('/login')).toBeInTheDocument();
    expect(screen.getByTestId('http-row-count')).toHaveTextContent('3 rows');
    // Two methods: a donut with the total in the middle.
    await waitFor(() => {
      expect(charts.get('Transactions by request method')?.option).toHaveProperty('series.0.type', 'pie');
    });
    expect(screen.getByText('requests')).toBeInTheDocument();
    // Status codes in ascending order, one series per class.
    const status = charts.get('Responses by status code, colored by class')?.option as {
      xAxis: { data: string[] };
      series: { name: string }[];
    };
    expect(status.xAxis.data).toEqual(['200', '302', '404']);
    expect(status.series.map((s) => s.name)).toEqual(['2xx', '3xx', '4xx']);
    expect(screen.getByRole('heading', { name: 'Most contacted hosts' })).toBeInTheDocument();
    expect(screen.getByText('2 distinct hosts')).toBeInTheDocument();
    expect(within(screen.getByTestId('filterbar-inline')).getByRole('switch', { name: /GET/ })).toHaveAttribute(
      'aria-checked',
      'true',
    );
  });

  it('filters by method, host, status and text', async () => {
    renderApp(`/sessions/${SESSION_ID}/http`);
    await screen.findByRole('list', { name: 'HTTP transactions' });
    expect(lastListParams()).toEqual({ sort: 'time', order: 'desc', limit: 200, cursor: null });
    const user = setupUser();
    const bar = within(screen.getByTestId('filterbar-inline'));

    await user.click(bar.getByRole('switch', { name: /POST/ }));
    await waitFor(() => {
      expect(lastListParams()?.methods).toEqual(['GET', 'HEAD', 'OPTIONS', 'PUT', 'PATCH', 'DELETE', 'CONNECT', 'other']);
    });
    await user.click(bar.getByRole('button', { name: 'Disable all' }));
    await waitFor(() => {
      expect(lastListParams()?.methods).toEqual([]);
    });
    await user.click(bar.getByRole('button', { name: 'Enable all' }));
    await waitFor(() => {
      expect(lastListParams()?.methods).toBeUndefined();
    });

    await user.click(screen.getByRole('button', { name: 'Show the transactions of api.example.test' }));
    await waitFor(() => {
      expect(lastListParams()?.host).toBe('api.example.test');
    });
    act(() => {
      charts.get('Responses by status code, colored by class')?.onEvents?.click?.({ name: '404' });
    });
    await waitFor(() => {
      expect(lastListParams()?.statuses).toEqual(['404']);
    });
    await user.click(screen.getByRole('button', { name: 'Remove filter api.example.test' }));
    await waitFor(() => {
      expect(lastListParams()?.host).toBeUndefined();
    });

    await user.type(screen.getByRole('searchbox'), 'login');
    await waitFor(() => {
      expect(lastListParams()?.q).toBe('login');
    });
    await user.click(screen.getByRole('radio', { name: 'Size' }));
    await waitFor(() => {
      expect(lastListParams()?.sort).toBe('size');
    });
  });

  it('expands a transaction with masked credentials', async () => {
    renderApp(`/sessions/${SESSION_ID}/http`);
    const list = await screen.findByRole('list', { name: 'HTTP transactions' });
    const user = setupUser();
    const row = within(list).getByRole('button', { name: /GET \/page\/2\?x=1, status 200/ });
    await user.click(row);
    expect(row).toHaveAttribute('aria-expanded', 'true');
    const headers = await screen.findByRole('table', { name: 'Request headers' });
    expect(within(headers).getByText('portal.example.test')).toBeInTheDocument();
    // Authorization and Cookie are hidden until revealed.
    expect(within(headers).queryByText('Basic ZGVtbzpkZW1v')).toBeNull();
    expect(within(headers).getByText('Hidden (18 characters)')).toBeInTheDocument();
    await user.click(within(headers).getByRole('button', { name: 'Show Authorization' }));
    expect(within(headers).getByText('Basic ZGVtbzpkZW1v')).toBeInTheDocument();

    await user.click(screen.getByRole('tab', { name: 'Response' }));
    const response = await screen.findByRole('table', { name: 'Response headers' });
    expect(within(response).getByRole('button', { name: 'Show all (400 characters)' })).toBeInTheDocument();

    await user.click(screen.getByRole('tab', { name: 'Body' }));
    // The request body may hold credentials: shown on demand only. The response preview is text.
    expect(screen.queryByText('username=alice&password=demo-only')).toBeNull();
    expect(screen.getByText('<p>hello</p>')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Show content' }));
    expect(screen.getByText('username=alice&password=demo-only')).toBeInTheDocument();

    await user.click(screen.getByRole('tab', { name: 'Connection' }));
    expect(screen.getByText('4223190445238569362')).toBeInTheDocument();
    expect(httpApi.getHttpTransaction).toHaveBeenCalledWith(SESSION_ID, 2, expect.anything());
  });

  it('shows an explicit empty state without HTTP traffic', async () => {
    vi.mocked(httpApi.getHttpStats).mockResolvedValue(stats({ transactions: 0, methods: [], statuses: [] }));
    renderApp(`/sessions/${SESSION_ID}/http`);
    expect(await screen.findByText('No HTTP traffic')).toBeInTheDocument();
    expect(screen.queryByRole('list', { name: 'HTTP transactions' })).toBeNull();
  });

  it('waits for the end of an import', async () => {
    vi.mocked(api.getSession).mockResolvedValue(session({ state: 'importing' }));
    renderApp(`/sessions/${SESSION_ID}/http`);
    expect(await screen.findByText('HTTP transactions appear when the import ends.')).toBeInTheDocument();
    expect(httpApi.getHttpStats).not.toHaveBeenCalled();
  });

  it('reports load errors with retry', async () => {
    vi.mocked(httpApi.listHttpTransactions).mockRejectedValue(new client.ApiError(500, 'http', 'boom'));
    renderApp(`/sessions/${SESSION_ID}/http`);
    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent('HTTP data could not be loaded');
    expect(within(alert).getByRole('button', { name: 'Retry' })).toBeInTheDocument();
  });
});
