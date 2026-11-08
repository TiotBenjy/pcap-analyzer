import { screen, waitFor, within } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import * as client from '../api/client';
import { ApiError } from '../api/client';
import * as api from '../api/sessions';
import { renderApp, setViewportWide } from '../test/renderApp';
import { page, session } from '../test/sessionFixtures';
import { findNavItem, NAV_ITEMS, navHref } from './nav';
import { forgetSession, getLastSessionId, parseSessionPath, rememberSession } from './session';

vi.mock('../api/sessions');
vi.mock('../api/client', async (importOriginal) => ({
  ...(await importOriginal<typeof client>()),
  apiGet: vi.fn(),
}));

const m = vi.mocked(api);
const ID = '01JC0FFEE0000000000000000A';

async function sidebar() {
  // Desktop sidebar (>= 1024 px).
  return within((await screen.findAllByRole('navigation', { name: 'NetSift' }))[0] as HTMLElement);
}

beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(client.apiGet).mockResolvedValue({ version: 'test', read_only: false, can_browse: true, status: 'ok' });
  m.listSessions.mockResolvedValue(page([]));
  m.getSession.mockResolvedValue(session());
  m.listChunks.mockResolvedValue(page([]));
  m.listAnomalies.mockResolvedValue(page([]));
  forgetSession(getLastSessionId() ?? '');
  setViewportWide(true);
});

describe('session paths', () => {
  it('parses and resolves session-scoped locations', () => {
    expect(parseSessionPath(`/sessions/${ID}/dns`)).toEqual({ sessionId: ID, rest: '/dns' });
    expect(parseSessionPath('/captures')).toBeNull();
    expect(findNavItem(`/sessions/${ID}/sources`)?.id).toBe('sources');
    expect(findNavItem('/captures')?.id).toBe('captures');
    const overview = NAV_ITEMS.find((i) => i.id === 'overview');
    if (overview === undefined) throw new Error('missing overview');
    expect(navHref(overview, null)).toBeNull();
    expect(navHref(overview, ID)).toBe(`/sessions/${ID}/overview`);
    // Only ULIDs reach the storage.
    rememberSession('../../etc');
    expect(getLastSessionId()).toBeNull();
    rememberSession(ID);
    expect(getLastSessionId()).toBe(ID);
    forgetSession(ID);
  });
});

describe('session routes', () => {
  it('disables the analysis entries without a session and sends /overview to Captures', async () => {
    const { router } = renderApp('/overview');
    await waitFor(() => {
      expect(router.state.location.pathname).toBe('/captures');
    });
    const nav = await sidebar();
    expect(nav.getByRole('link', { name: /Captures/ })).toBeInTheDocument();
    expect(nav.queryByRole('link', { name: /Overview/ })).not.toBeInTheDocument();
    expect(nav.getByText('Overview').closest('[aria-disabled]')).toHaveAttribute(
      'title',
      'Overview: open a session first',
    );
  });

  it('remembers the opened session and points the sidebar and /overview to it', async () => {
    const first = renderApp(`/sessions/${ID}/sources`);
    expect(await screen.findByRole('heading', { level: 1, name: 'Sources' })).toBeInTheDocument();
    await waitFor(() => {
      expect(getLastSessionId()).toBe(ID);
    });
    expect((await sidebar()).getByRole('link', { name: /Overview/ })).toHaveAttribute('href', `/sessions/${ID}/overview`);
    expect((await sidebar()).getByRole('link', { name: /Sources/ })).toHaveAttribute('aria-current', 'page');
    first.unmount();

    const second = renderApp('/overview');
    await waitFor(() => {
      expect(second.router.state.location.pathname).toBe(`/sessions/${ID}/overview`);
    });
    // Code-split placeholder of a later view, still inside the session.
    await second.router.navigate({ to: `/sessions/${ID}/dns` });
    expect(await screen.findByText('Not available yet')).toBeInTheDocument();
  });

  it('forgets an unknown session and shows a not-found state', async () => {
    rememberSession('01JD0NE00000000000000000GZ');
    m.getSession.mockRejectedValue(new ApiError(404, 'not_found', 'no such session'));
    renderApp('/sessions/01JD0NE00000000000000000GZ/overview');
    expect(await screen.findByRole('heading', { level: 1, name: 'Session not found' })).toBeInTheDocument();
    await waitFor(() => {
      expect(getLastSessionId()).toBeNull();
    });
  });
});
