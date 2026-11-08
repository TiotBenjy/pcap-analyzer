import { screen, waitFor, within } from '@testing-library/react';
import type { ComponentProps } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import * as client from '../../api/client';
import * as httpApi from '../../api/http';
import * as api from '../../api/sessions';
import type { Chart } from '../../components/Chart';
import { detail, headerStats, SESSION_ID, tx } from '../../test/httpFixtures';
import { renderApp, setViewportWide } from '../../test/renderApp';
import { session } from '../../test/sessionFixtures';
import { setupUser } from '../../test/user';

vi.mock('../../api/sessions');
vi.mock('../../api/http', async (importOriginal) => ({
  ...(await importOriginal<typeof httpApi>()),
  getHttpHeaderStats: vi.fn(),
  listHttpHeaders: vi.fn(),
  getHttpTransaction: vi.fn(),
}));
vi.mock('../../api/client', async (importOriginal) => ({
  ...(await importOriginal<typeof client>()),
  apiGet: vi.fn(),
}));
vi.mock('../../components/Chart', () => ({
  Chart: (props: ComponentProps<typeof Chart>) => <div data-testid="chart" aria-label={props.ariaLabel} />,
}));

const lastParams = () => vi.mocked(httpApi.listHttpHeaders).mock.lastCall?.[1];

describe('HTTP Headers view', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    setViewportWide(true);
    vi.mocked(client.apiGet).mockResolvedValue({ version: 'test', read_only: true, can_browse: false, status: 'ok' });
    vi.mocked(api.getSession).mockResolvedValue(session());
    vi.mocked(httpApi.getHttpHeaderStats).mockResolvedValue(headerStats());
    vi.mocked(httpApi.listHttpHeaders).mockResolvedValue({ items: [tx(1), tx(2)], next_cursor: null, total_estimate: 2 });
    vi.mocked(httpApi.getHttpTransaction).mockImplementation((_id, tid) => Promise.resolve(detail(tx(tid))));
  });

  it('searches a cookie value and highlights it, the value staying masked by default', async () => {
    renderApp(`/sessions/${SESSION_ID}/http-headers`);
    const list = await screen.findByRole('list', { name: 'HTTP transactions and their headers' });
    expect(screen.getByText('12')).toBeInTheDocument();
    const user = setupUser();
    await user.type(screen.getByRole('searchbox'), '7f3a9c');
    await waitFor(() => {
      expect(lastParams()).toEqual({ q: '7f3a9c', limit: 200, cursor: null });
    });

    await user.click(within(list).getAllByRole('button', { name: /show details/ })[0] as HTMLElement);
    const request = await screen.findByRole('table', { name: 'Request headers' });
    expect(screen.getByRole('table', { name: 'Response headers' })).toBeInTheDocument();
    // Masked: the cookie value is not in the page until revealed, then highlighted.
    expect(within(request).queryByText(/7f3a9c/)).toBeNull();
    await user.click(within(request).getByRole('button', { name: 'Show Cookie' }));
    const mark = within(request).getByText('7f3a9c');
    expect(mark.tagName).toBe('MARK');
    // Long values are folded.
    const response = screen.getByRole('table', { name: 'Response headers' });
    await user.click(within(response).getByRole('button', { name: 'Show all (400 characters)' }));
    expect(within(response).getByRole('button', { name: 'Show less' })).toBeInTheDocument();
  });

  it('filters by header name, taken from the address, and by method', async () => {
    renderApp(`/sessions/${SESSION_ID}/http-headers?name=authorization`);
    await screen.findByRole('list', { name: 'HTTP transactions and their headers' });
    await waitFor(() => {
      expect(lastParams()?.name).toBe('authorization');
    });
    expect(screen.getByRole('combobox', { name: 'Header name' })).toHaveValue('authorization');
    const user = setupUser();
    await user.click(within(screen.getByTestId('filterbar-inline')).getByRole('switch', { name: /GET/ }));
    await waitFor(() => {
      expect(lastParams()?.methods).not.toContain('GET');
    });
  });

  it('shows an explicit state when nothing matches', async () => {
    vi.mocked(httpApi.listHttpHeaders).mockResolvedValue({ items: [], next_cursor: null, total_estimate: 0 });
    renderApp(`/sessions/${SESSION_ID}/http-headers`);
    expect(await screen.findByText('No transaction matches the filters')).toBeInTheDocument();
  });
});
