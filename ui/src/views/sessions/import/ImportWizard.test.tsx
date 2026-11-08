import { act, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import * as client from '../../../api/client';
import * as api from '../../../api/sessions';
import type { BrowseResponse } from '../../../api/types/BrowseResponse';
import type { ImportEvent } from '../../../api/types/ImportEvent';
import { resetImportTracker } from '../../../app/importTracker';
import { renderApp } from '../../../test/renderApp';
import { page, session, twoGroupScan } from '../../../test/sessionFixtures';
import { setNativePicker } from './pickers';

vi.mock('../../../api/sessions');
vi.mock('../../../api/client', async (importOriginal) => ({
  ...(await importOriginal<typeof client>()),
  apiGet: vi.fn(),
}));

const m = vi.mocked(api);

const ROOT: BrowseResponse = {
  path: '/captures',
  parent: null,
  roots: ['/captures'],
  entries: [
    { name: 'office', is_dir: true, size: 0 },
    { name: 'single.pcap', is_dir: false, size: 2048 },
  ],
};
const OFFICE: BrowseResponse = {
  path: '/captures/office',
  parent: '/captures',
  roots: ['/captures'],
  entries: [{ name: 'ring_00001_20261108.pcapng', is_dir: false, size: 1048576 }],
};

/** Controllable import event stream. */
function mockStream() {
  const ctl: { emit: (e: ImportEvent) => void; end: () => void } = { emit: () => undefined, end: () => undefined };
  m.streamImportEvents.mockImplementation(
    (_id, onEvent) =>
      new Promise<void>((resolve) => {
        ctl.emit = (e) => {
          act(() => {
            onEvent(e);
          });
        };
        ctl.end = resolve;
      }),
  );
  return ctl;
}

const progress = (done: number): ImportEvent => ({
  type: 'progress',
  bytes_done: done,
  bytes_total: 100,
  chunk_index: 24,
  chunk_count: 49,
  chunk_name: 'ring_00025_20261108.pcapng',
  packets: 5000,
  rate_bps: 80 * 1024 * 1024,
  eta_s: 30,
  phase: 'reading',
});

async function startTwoGroupImport() {
  const user = userEvent.setup();
  const app = renderApp('/captures');
  await user.click((await screen.findAllByRole('button', { name: 'Import folder' }))[0] as HTMLElement);

  // Step 1: in-app folder browser (web mode).
  let dialog = await screen.findByRole('dialog', { name: 'Import a folder' });
  expect(dialog).toHaveAccessibleDescription('Step 1 of 3: Select');
  await user.click(await within(dialog).findByRole('button', { name: /office/ }));
  await within(dialog).findByText('ring_00001_20261108.pcapng');
  expect(m.browse).toHaveBeenLastCalledWith('/captures/office', expect.anything());
  await user.click(within(dialog).getByRole('button', { name: 'Select this folder' }));

  // Step 2: two groups, the first preselected; selecting both merges them.
  dialog = await screen.findByRole('dialog', { name: 'Import a folder' });
  expect(dialog).toHaveAccessibleDescription('Step 2 of 3: Review');
  expect(m.scanImport).toHaveBeenCalledWith({ path: '/captures/office', recursive: false }, expect.anything());
  const groups = await within(dialog).findAllByTestId('scan-group');
  expect(groups).toHaveLength(2);
  expect(within(dialog).getByText('dumpcap ring buffer')).toBeInTheDocument();
  expect(within(dialog).getByText('tcpdump -C')).toBeInTheDocument();
  expect(within(dialog).getByText('1 expected anomaly')).toBeInTheDocument();
  expect(within(dialog).getByText('1 file ignored')).toBeInTheDocument();
  const [first, second] = within(dialog).getAllByRole('checkbox', { name: /dumpcap|tcpdump/ });
  expect(first).toBeChecked();
  expect(second).not.toBeChecked();
  expect(within(dialog).queryByText(/merged into one session/)).not.toBeInTheDocument();
  await user.click(second as HTMLElement);
  expect(within(dialog).getByText(/merged into one session/)).toBeInTheDocument();
  expect(within(dialog).getByLabelText('Session name')).toHaveValue('office');

  await user.click(within(dialog).getByRole('button', { name: 'Start import' }));
  expect(m.startImport).toHaveBeenCalledWith({
    path: '/captures/office',
    group_ids: [0, 1],
    name: 'office',
    recursive: false,
  });
  return { user, ...app };
}

beforeAll(async () => {
  // Warm the code-split wizard module so that the first test does not time out on its import.
  await import('./ImportWizard');
});

beforeEach(() => {
  vi.resetAllMocks();
  resetImportTracker();
  setNativePicker(undefined);
  vi.mocked(client.apiGet).mockResolvedValue({ version: 'test', read_only: false, can_browse: true, status: 'ok' });
  m.listSessions.mockResolvedValue(page([]));
  m.getSession.mockResolvedValue(session({ id: 'S1', name: 'office' }));
  m.browse.mockImplementation((path) => Promise.resolve(path === '/captures/office' ? OFFICE : ROOT));
  m.scanImport.mockResolvedValue(twoGroupScan());
  m.startImport.mockResolvedValue({ session_id: 'S1' });
  m.cancelImport.mockResolvedValue(undefined);
});

describe('Import wizard', () => {
  it('scans, merges two groups, follows the progress and opens the session', async () => {
    const stream = mockStream();
    const { user, router } = await startTwoGroupImport();

    // Step 3: progress.
    const dialog = await screen.findByRole('dialog', { name: 'Import progress' });
    expect(m.streamImportEvents).toHaveBeenCalledWith('S1', expect.any(Function), expect.any(AbortSignal));
    expect(within(dialog).getByText('Waiting for the first progress event')).toBeInTheDocument();

    stream.emit(progress(50));
    expect(within(dialog).getByRole('progressbar')).toHaveAttribute('aria-valuenow', '50');
    expect(within(dialog).getByText('Chunk 25 of 49')).toBeInTheDocument();
    expect(within(dialog).getByText('80.0 MiB/s')).toBeInTheDocument();
    expect(within(dialog).getByText('30 s')).toBeInTheDocument();
    expect(within(dialog).getByText('ring_00025_20261108.pcapng')).toHaveAttribute('title');

    stream.emit({ type: 'warning', id: null, code: 'missing_sequence', chunk: 12, ts_us: null, detail: { first: 13, last: 13 } });
    expect(within(dialog).getByText('Missing files in the sequence')).toBeInTheDocument();

    // Closing the wizard keeps the import running; the header indicator reopens it.
    await user.click(within(dialog).getByRole('button', { name: 'Continue in background' }));
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    const indicator = screen.getByTestId('import-indicator');
    expect(indicator).toHaveTextContent('Import 50%');
    await user.click(indicator);
    const reopened = await screen.findByRole('dialog', { name: 'Import progress' });

    stream.emit({ type: 'done', state: 'ready', packets: 9000, flows: 120, anomalies: 1, duration_s: 12 });
    stream.end();
    expect(await within(reopened).findByText('Import finished')).toBeInTheDocument();
    expect(within(reopened).getByRole('progressbar')).toHaveAttribute('aria-valuenow', '100');
    await user.click(within(reopened).getByRole('button', { name: 'Open session' }));
    await waitFor(() => {
      expect(router.state.location.pathname).toBe('/sessions/S1/overview');
    });
    expect(screen.queryByTestId('import-indicator')).not.toBeInTheDocument();
  });

  it('cancels a running import, which ends as an incomplete session', async () => {
    const stream = mockStream();
    const { user } = await startTwoGroupImport();
    const dialog = await screen.findByRole('dialog', { name: 'Import progress' });
    stream.emit(progress(50));

    await user.click(within(dialog).getByRole('button', { name: 'Cancel import' }));
    expect(m.cancelImport).toHaveBeenCalledWith('S1');
    expect(within(dialog).getByRole('button', { name: 'Cancelling' })).toBeDisabled();

    stream.emit({ type: 'done', state: 'incomplete', packets: 4000, flows: 50, anomalies: 0, duration_s: 6 });
    expect(await within(dialog).findByText('Import stopped: the session is incomplete')).toBeInTheDocument();
    expect(within(dialog).getByText('Incomplete')).toBeInTheDocument();
  });

  it('reports a failed import', async () => {
    const stream = mockStream();
    await startTwoGroupImport();
    const dialog = await screen.findByRole('dialog', { name: 'Import progress' });
    stream.emit({ type: 'failed', message: 'disk full' });
    expect(await within(dialog).findByText('Import failed')).toBeInTheDocument();
    expect(within(dialog).getByText('disk full')).toBeInTheDocument();
  });

  it('closes with Escape and returns to the sessions list', async () => {
    const user = userEvent.setup();
    renderApp('/captures');
    await user.click((await screen.findAllByRole('button', { name: 'Import file' }))[0] as HTMLElement);
    const dialog = await screen.findByRole('dialog', { name: 'Import a file' });
    // File mode: a file must be chosen before going on.
    const select = within(dialog).getByRole('button', { name: 'Select file' });
    expect(select).toBeDisabled();
    await user.click(await within(dialog).findByRole('button', { name: /single\.pcap/ }));
    expect(select).toBeEnabled();
    await user.keyboard('{Escape}');
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });

  it('uses the native picker when the platform provides one (desktop extension point)', async () => {
    const picker = vi.fn(() => Promise.resolve('/home/user/caps'));
    setNativePicker(picker);
    const user = userEvent.setup();
    renderApp('/captures');
    await user.click((await screen.findAllByRole('button', { name: 'Import folder' }))[0] as HTMLElement);
    await user.click(await screen.findByRole('button', { name: 'Choose a folder' }));
    expect(picker).toHaveBeenCalledWith('folder');
    await screen.findByText('Step 2 of 3: Review');
    expect(m.scanImport).toHaveBeenCalledWith({ path: '/home/user/caps', recursive: false }, expect.anything());
    expect(m.browse).not.toHaveBeenCalled();
  });
});
