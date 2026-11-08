import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import * as client from '../../api/client';
import { ApiError } from '../../api/client';
import * as api from '../../api/sessions';
import { resetImportTracker } from '../../app/importTracker';
import { getLastSessionId, rememberSession } from '../../app/session';
import { renderApp, setViewportWide } from '../../test/renderApp';
import { page, session } from '../../test/sessionFixtures';

vi.mock('../../api/sessions');
vi.mock('../../api/client', async (importOriginal) => ({
  ...(await importOriginal<typeof client>()),
  apiGet: vi.fn(),
}));

const m = vi.mocked(api);

beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(client.apiGet).mockResolvedValue({ version: 'test', read_only: false, can_browse: true, status: 'ok' });
  resetImportTracker();
  setViewportWide(true);
});
afterEach(() => {
  setViewportWide(false);
});

describe('Captures view', () => {
  it('lists the sessions in a table with state, sizes and anomalies', async () => {
    m.listSessions.mockResolvedValue(
      page([session(), session({ id: 'S2', name: 'dmz-tap', state: 'incomplete', anomaly_count: 0 })]),
    );
    renderApp('/captures');
    const table = await screen.findByRole('table', { name: 'Sessions' });
    const rows = within(table).getAllByRole('row');
    expect(rows).toHaveLength(3);
    expect(within(table).getByText('office-uplink')).toHaveAttribute('title', 'office-uplink');
    expect(within(table).getByText('Ready')).toBeInTheDocument();
    expect(within(table).getByText('Incomplete')).toBeInTheDocument();
    expect(within(table).getAllByText('50.0 MiB')).toHaveLength(2);
    expect(within(table).getAllByText('123,456')).toHaveLength(2);
    expect(screen.getByRole('button', { name: 'Import folder' })).toBeEnabled();
  });

  it('switches to stacked cards below 768 px', async () => {
    setViewportWide(false);
    m.listSessions.mockResolvedValue(page([session()]));
    renderApp('/captures');
    const list = await screen.findByRole('list', { name: 'Sessions' });
    expect(within(list).getByRole('button', { name: 'office-uplink' })).toBeInTheDocument();
    expect(screen.queryByRole('table')).not.toBeInTheDocument();
  });

  it('shows an explicit empty state with the import actions', async () => {
    m.listSessions.mockResolvedValue(page([]));
    renderApp('/captures');
    expect(await screen.findByText('No capture imported')).toBeInTheDocument();
    expect(screen.getAllByRole('button', { name: 'Import folder' })).toHaveLength(2);
  });

  it('shows an error state with retry', async () => {
    m.listSessions.mockRejectedValueOnce(new Error('boom')).mockResolvedValue(page([session()]));
    renderApp('/captures');
    expect(await screen.findByText('Sessions could not be loaded')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Retry' }));
    expect(await screen.findByRole('table', { name: 'Sessions' })).toBeInTheDocument();
  });

  it('opens the session overview when a row is clicked', async () => {
    m.listSessions.mockResolvedValue(page([session()]));
    m.getSession.mockResolvedValue(session());
    const { router } = renderApp('/captures');
    await userEvent.click(await screen.findByText('office-uplink'));
    await waitFor(() => {
      expect(router.state.location.pathname).toBe('/sessions/01JC0FFEE0000000000000000A/overview');
    });
  });

  it('renames a session from its dialog', async () => {
    const s = session();
    m.listSessions.mockResolvedValue(page([s]));
    m.renameSession.mockResolvedValue({ ...s, name: 'hq-uplink' });
    const { router } = renderApp('/captures');
    await userEvent.click(await screen.findByRole('button', { name: 'Rename office-uplink' }));
    const dialog = screen.getByRole('dialog', { name: 'Rename session' });
    const input = within(dialog).getByLabelText('Name');
    expect(input).toHaveFocus();
    await userEvent.clear(input);
    await userEvent.type(input, 'hq-uplink{Enter}');
    expect(m.renameSession).toHaveBeenCalledWith(s.id, 'hq-uplink');
    await waitFor(() => {
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    });
    expect(screen.getByText('hq-uplink')).toBeInTheDocument();
    // The action does not trigger the row navigation.
    expect(router.state.location.pathname).toBe('/captures');
  });

  it('deletes a session only after confirmation', async () => {
    const s = session();
    rememberSession(s.id);
    m.listSessions.mockResolvedValue(page([s]));
    m.deleteSession.mockResolvedValue(undefined);
    renderApp('/captures');

    // Escape cancels, focus starts on Cancel.
    await userEvent.click(await screen.findByRole('button', { name: 'Delete office-uplink' }));
    const dialog = screen.getByRole('dialog', { name: 'Delete session' });
    expect(within(dialog).getByRole('button', { name: 'Cancel' })).toHaveFocus();
    expect(dialog).toHaveTextContent('source capture files are not modified');
    await userEvent.keyboard('{Escape}');
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(m.deleteSession).not.toHaveBeenCalled();

    await userEvent.click(screen.getByRole('button', { name: 'Delete office-uplink' }));
    await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Delete' }));
    expect(m.deleteSession).toHaveBeenCalledWith(s.id);
    await waitFor(() => {
      expect(screen.queryByText('office-uplink')).not.toBeInTheDocument();
    });
    expect(getLastSessionId()).toBeNull();
  });

  it('reconnects to an importing session whose progress stream was lost', async () => {
    const s = session({ state: 'importing' });
    m.listSessions.mockResolvedValue(page([s]));
    m.streamImportEvents.mockResolvedValue(undefined); // ends without a final event: lost
    renderApp('/captures');
    const action = await screen.findByRole('button', { name: 'Show the import progress of office-uplink' });
    expect(screen.queryByRole('button', { name: 'Delete office-uplink' })).not.toBeInTheDocument();
    await userEvent.click(action);
    const dialog = await screen.findByRole('dialog', { name: 'Import progress' });
    expect(await within(dialog).findByText('Connection lost')).toBeInTheDocument();
    await userEvent.keyboard('{Escape}');
    await userEvent.click(screen.getByRole('button', { name: 'Show the import progress of office-uplink' }));
    await waitFor(() => {
      expect(m.streamImportEvents).toHaveBeenCalledTimes(2);
    });
  });

  it('shows translated errors with the raw message as a detail', async () => {
    const s = session();
    m.listSessions.mockResolvedValue(page([s]));
    m.renameSession.mockRejectedValue(new ApiError(409, 'urn:netsift:problem:conflict', 'import running'));
    renderApp('/captures');
    await userEvent.click(await screen.findByRole('button', { name: 'Rename office-uplink' }));
    await userEvent.type(screen.getByLabelText('Name'), 'x{Enter}');
    const alert = await within(screen.getByRole('dialog')).findByRole('alert');
    expect(alert).toHaveTextContent('Rename failed: Conflict with an operation in progress');
    expect(alert).toHaveTextContent('import running');
  });

  it('keeps focus inside a dialog with Tab', async () => {
    m.listSessions.mockResolvedValue(page([session()]));
    renderApp('/captures');
    await userEvent.click(await screen.findByRole('button', { name: 'Delete office-uplink' }));
    const dialog = screen.getByRole('dialog');
    for (let i = 0; i < 5; i++) {
      await userEvent.tab();
      expect(dialog.contains(document.activeElement)).toBe(true);
    }
    await userEvent.tab({ shift: true });
    expect(dialog.contains(document.activeElement)).toBe(true);
  });
});
