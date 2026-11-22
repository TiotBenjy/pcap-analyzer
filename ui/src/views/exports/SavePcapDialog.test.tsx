import '../../i18n';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiError } from '../../api/client';
import * as exportsApi from '../../api/exports';
import * as queries from '../../api/queries';
import type { ExportJob } from '../../api/types/ExportJob';
import { formatTimestamp } from '../../lib/format';
import { setupUser } from '../../test/user';
import { rangeRequest } from './range';
import { SavePcapDialog } from './SavePcapDialog';

vi.mock('../../api/exports', async (importOriginal) => ({
  ...(await importOriginal<typeof exportsApi>()),
  startPcapExport: vi.fn(),
  listExports: vi.fn(),
  cancelExport: vi.fn(),
  openExportFolder: vi.fn(),
  deliversByFolder: vi.fn(),
}));
vi.mock('../../api/queries', () => ({ useServerInfo: vi.fn() }));

const SESSION = '01JC0FFEE0000000000000000A';
const FIRST = new Date(2026, 10, 8, 10, 0, 0).getTime() * 1000 + 123_456;
const LAST = new Date(2026, 10, 8, 11, 30, 15).getTime() * 1000 + 654_321;

function job(over: Partial<ExportJob> = {}): ExportJob {
  return {
    id: '01JC0FFEE0000000000000JOB1',
    session_id: SESSION,
    scope: 'session',
    from_us: null,
    to_us: null,
    flow_id: null,
    state: 'running',
    file_name: 'netsift-01jc0ffe-session-00000job1.pcapng',
    folder: '/data/exports',
    path: null,
    packets: 0,
    bytes_written: 0,
    bytes_read: 512,
    bytes_total: 2048,
    read_errors: 0,
    error: null,
    created_at_us: 0,
    ...over,
  };
}

function renderDialog(onClose = vi.fn(), activeRange: { fromUs: number; toUs: number } | null = null) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <SavePcapDialog open onClose={onClose} sessionId={SESSION} firstUs={FIRST} lastUs={LAST} activeRange={activeRange} />
    </QueryClientProvider>,
  );
  return onClose;
}

function serverInfo(readOnly: boolean) {
  vi.mocked(queries.useServerInfo).mockReturnValue({ data: { read_only: readOnly } } as ReturnType<typeof queries.useServerInfo>);
}

describe('Save PCAP dialog', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    serverInfo(false);
    vi.mocked(exportsApi.deliversByFolder).mockReturnValue(false);
  });

  it('opens on the active time range of the views', () => {
    const range = { fromUs: FIRST + 60_000_000, toUs: FIRST + 120_000_000 };
    renderDialog(vi.fn(), range);
    expect(screen.getByRole('radio', { name: 'Time range' })).toBeChecked();
    expect(screen.getByLabelText('From')).toHaveValue(formatTimestamp(range.fromUs));
    expect(screen.getByLabelText('To')).toHaveValue(formatTimestamp(range.toUs));
  });

  it('exports the whole session, shows the progress then a download link', async () => {
    const user = setupUser();
    vi.mocked(exportsApi.startPcapExport).mockResolvedValue(job());
    vi.mocked(exportsApi.listExports)
      .mockResolvedValueOnce([job()])
      .mockResolvedValue([job({ state: 'done', packets: 1234, bytes_written: 4096, bytes_read: 2048, path: '/data/exports/x' })]);
    renderDialog();
    expect(screen.getByRole('radio', { name: 'Whole session' })).toBeChecked();
    await user.click(screen.getByRole('button', { name: 'Save' }));
    expect(exportsApi.startPcapExport).toHaveBeenCalledWith(SESSION, { scope: 'session' });
    expect(await screen.findByText('Saving, 25% of the source files read')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled();
    expect(await screen.findByText('Saved: 1,234 packets, 4.0 KiB', {}, { timeout: 3000 })).toBeInTheDocument();
    const link = screen.getByRole('link', { name: 'Download' });
    expect(link).toHaveAttribute('href', '/api/v1/exports/01JC0FFEE0000000000000JOB1/file');
    expect(link).toHaveAttribute('download', 'netsift-01jc0ffe-session-00000job1.pcapng');
    expect(screen.getByTitle('netsift-01jc0ffe-session-00000job1.pcapng')).toBeInTheDocument();
  });

  it('validates the time range, prefilled with the captured period, ends included', async () => {
    const user = setupUser();
    vi.mocked(exportsApi.startPcapExport).mockResolvedValue(job({ scope: 'range' }));
    vi.mocked(exportsApi.listExports).mockResolvedValue([job({ scope: 'range', state: 'cancelled' })]);
    renderDialog();
    await user.click(screen.getByRole('radio', { name: 'Time range' }));
    const from = screen.getByRole('textbox', { name: 'From' });
    const to = screen.getByRole('textbox', { name: 'To' });
    expect(screen.queryByRole('alert')).toBeNull();
    expect(from).toHaveValue(formatTimestamp(FIRST));
    expect(to).toHaveValue(formatTimestamp(LAST));

    await user.clear(from);
    await user.type(from, '2026-11-08 9:00');
    await user.click(screen.getByRole('button', { name: 'Save' }));
    expect(screen.getByRole('alert')).toHaveTextContent('Enter a date and time as YYYY-MM-DD hh:mm:ss');
    expect(exportsApi.startPcapExport).not.toHaveBeenCalled();

    await user.clear(from);
    await user.type(from, '2026-11-08 12:00:00');
    expect(screen.getByRole('alert')).toHaveTextContent('The end is before the start');

    await user.clear(from);
    await user.type(from, formatTimestamp(FIRST));
    await user.click(screen.getByRole('button', { name: 'Save' }));
    const secondFloor = (us: number) => Math.floor(us / 1_000_000) * 1_000_000;
    expect(exportsApi.startPcapExport).toHaveBeenCalledWith(SESSION, {
      scope: 'range',
      from_us: secondFloor(FIRST),
      to_us: secondFloor(LAST) + 999_999,
    });
    expect(await screen.findByText('Export cancelled')).toBeInTheDocument();
  });

  it('explains a refused export and a failed one', async () => {
    const user = setupUser();
    vi.mocked(exportsApi.startPcapExport).mockRejectedValueOnce(
      new ApiError(409, 'urn:netsift:problem:export-source-missing', 'source file cap_00003.pcapng is missing or unreadable'),
    );
    renderDialog();
    await user.click(screen.getByRole('button', { name: 'Save' }));
    expect(await screen.findByText(/A capture file of the session is missing or unreadable/)).toBeInTheDocument();
    expect(screen.getByText('source file cap_00003.pcapng is missing or unreadable')).toBeInTheDocument();

    const failed = job({
      state: 'failed',
      error: {
        type: 'urn:netsift:problem:export-source-modified',
        title: 'A capture file of the session changed since the import',
        status: 409,
        detail: 'source file cap_00001.pcapng changed since the import (size)',
      },
    });
    vi.mocked(exportsApi.startPcapExport).mockResolvedValue(failed);
    vi.mocked(exportsApi.listExports).mockResolvedValue([failed]);
    await user.click(screen.getByRole('button', { name: 'Save' }));
    expect(await screen.findByText(/^The export failed: A capture file of the session changed since the import/)).toBeInTheDocument();
    expect(screen.getByText('source file cap_00001.pcapng changed since the import (size)')).toBeInTheDocument();
  });

  it('opens the exports folder on the desktop', async () => {
    const user = setupUser();
    vi.mocked(exportsApi.deliversByFolder).mockReturnValue(true);
    vi.mocked(exportsApi.openExportFolder).mockResolvedValue();
    const done = job({ state: 'done', packets: 1, bytes_written: 100, read_errors: 2 });
    vi.mocked(exportsApi.startPcapExport).mockResolvedValue(done);
    vi.mocked(exportsApi.listExports).mockResolvedValue([done]);
    renderDialog();
    await user.click(screen.getByRole('button', { name: 'Save' }));
    await user.click(await screen.findByRole('button', { name: 'Open folder' }));
    expect(exportsApi.openExportFolder).toHaveBeenCalledWith('/data/exports');
    expect(screen.queryByRole('link', { name: 'Download' })).toBeNull();
    expect(screen.getByText('Saved: 1 packet, 100 B')).toBeInTheDocument();
    expect(screen.getByText('2 read errors in the capture files: packets may be missing, as in the analysis.')).toBeInTheDocument();
  });

  it('cannot start on a read-only server, and closes', async () => {
    const user = setupUser();
    serverInfo(true);
    const onClose = renderDialog();
    const save = screen.getByRole('button', { name: 'Save' });
    expect(save).toBeDisabled();
    expect(save).toHaveAttribute('title', 'Not available: the server is read-only');
    await user.click(screen.getAllByRole('button', { name: 'Close' })[1] ?? save);
    await waitFor(() => {
      expect(onClose).toHaveBeenCalled();
    });
  });
});

describe('rangeRequest', () => {
  it('rejects unreadable and reversed ranges', () => {
    expect(rangeRequest('x', '2026-11-08 10:00:00')).toEqual({ error: 'invalidTime' });
    expect(rangeRequest('2026-11-08 10:00:01', '2026-11-08 10:00:00')).toEqual({ error: 'reversed' });
    // Same second: the end is the last microsecond of that second.
    const r = rangeRequest('2026-11-08 10:00:00', '2026-11-08 10:00:00');
    expect('request' in r && r.request.scope === 'range' && r.request.to_us - r.request.from_us).toBe(999_999);
  });
});
