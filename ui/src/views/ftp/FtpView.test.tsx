import { screen, waitFor, within } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import * as ftpApi from '../../api/ftp';
import * as objectsApi from '../../api/objects';
import * as api from '../../api/sessions';
import type { Endpoint } from '../../api/types/Endpoint';
import type { FtpSessionInfo } from '../../api/types/FtpSessionInfo';
import type { FtpStats } from '../../api/types/FtpStats';
import type { FtpTransferInfo } from '../../api/types/FtpTransferInfo';
import { renderApp, setViewportWide } from '../../test/renderApp';
import { page, session } from '../../test/sessionFixtures';
import { setupUser } from '../../test/user';
import { baseName, isErrorCode, transferStatus } from './format';

vi.mock('../../api/sessions');
vi.mock('../../api/ftp', async (importOriginal) => {
  const actual = await importOriginal<typeof ftpApi>();
  return { ...actual, getFtpStats: vi.fn(), listFtpSessions: vi.fn(), getFtpSession: vi.fn(), listFtpTransfers: vi.fn() };
});
vi.mock('../../api/objects', async (importOriginal) => {
  const actual = await importOriginal<typeof objectsApi>();
  return { ...actual, fetchRendition: vi.fn(), downloadObject: vi.fn() };
});

const ID = '01JC0FFEE0000000000000000A';
const T0 = Date.UTC(2026, 10, 8, 10, 0, 0) * 1000;
const SECRET = 'hunter2-secret';
const SHA = 'ab'.repeat(32);
const PNG_URL = 'data:image/png;base64,iVBORw0KGgo=';

function endpoint(ip: string): Endpoint {
  return { ip, names: [], category: 'private', country: null };
}

function stats(overrides: Partial<FtpStats> = {}): FtpStats {
  return {
    sessions: 2,
    servers: 1,
    clients: 2,
    users: 2,
    logins_accepted: 1,
    logins_rejected: 1,
    tls_sessions: 0,
    transfers: 2,
    downloads: 1,
    uploads: 0,
    listings: 1,
    failed: 0,
    bytes: 2048,
    stored: 1,
    ...overrides,
  };
}

function ftpSession(overrides: Partial<FtpSessionInfo> = {}): FtpSessionInfo {
  return {
    flow_id: '7',
    client: endpoint('192.168.1.31'),
    client_port: 50_000,
    server: endpoint('192.168.1.33'),
    server_port: 21,
    first_ts_us: T0,
    last_ts_us: T0 + 4_000_000,
    banner: '(vsFTPd 3.0.5)',
    username: 'alice',
    login: 'accepted',
    tls: false,
    commands: 6,
    replies: 7,
    files: 1,
    listings: 0,
    bytes: 2048,
    lines: 4,
    transcript_truncated: false,
    gaps: 0,
    ...overrides,
  };
}

function transfer(overrides: Partial<FtpTransferInfo> = {}): FtpTransferInfo {
  return {
    id: 1,
    flow_id: '7',
    seq: 0,
    ts_us: T0 + 2_000_000,
    end_ts_us: T0 + 3_000_000,
    command: 'RETR',
    path: 'photos/harbour.png',
    direction: 'download',
    mode: 'passive',
    data_flow_id: '9',
    status: 226,
    status_text: 'Transfer complete.',
    bytes: 2048,
    restart_offset: null,
    truncated: false,
    sha256: SHA,
    mime: 'image/png',
    listing: null,
    client: endpoint('192.168.1.31'),
    server: endpoint('192.168.1.33'),
    server_port: 21,
    username: 'alice',
    ...overrides,
  };
}

const LISTING = 'drwxr-xr-x 2 ftp ftp 4096 <b>archive</b>\n';

beforeEach(() => {
  setViewportWide(true);
  vi.mocked(api.getSession).mockResolvedValue(session({ state: 'ready' }));
  vi.mocked(ftpApi.getFtpStats).mockResolvedValue(stats());
  vi.mocked(ftpApi.listFtpSessions).mockResolvedValue(
    page([ftpSession(), ftpSession({ flow_id: '20', username: 'admin', login: 'rejected', files: 0, client: endpoint('192.168.1.32') })]),
  );
  vi.mocked(ftpApi.listFtpTransfers).mockResolvedValue(
    page([
      transfer(),
      transfer({ id: 2, seq: 1, command: 'LIST', path: null, direction: 'listing', sha256: null, mime: null, listing: LISTING, status: 426, status_text: 'Aborted.' }),
    ]),
  );
  vi.mocked(ftpApi.getFtpSession).mockResolvedValue({
    session: ftpSession(),
    lines: [
      { seq: 0, ts_us: T0, kind: 'reply', head: '220', text: '(vsFTPd 3.0.5)', secret: false, truncated: false },
      { seq: 1, ts_us: T0, kind: 'command', head: 'USER', text: 'alice', secret: false, truncated: false },
      { seq: 2, ts_us: T0, kind: 'command', head: 'PASS', text: SECRET, secret: true, truncated: false },
      { seq: 3, ts_us: T0, kind: 'reply', head: '530', text: 'Login incorrect.', secret: false, truncated: false },
      { seq: 4, ts_us: T0, kind: 'note', head: null, text: 'tls', secret: false, truncated: false },
    ],
    transfers: [transfer()],
  });
  vi.mocked(objectsApi.fetchRendition).mockResolvedValue(PNG_URL);
  vi.mocked(objectsApi.downloadObject).mockResolvedValue(undefined);
});

describe('FTP view', () => {
  it('shows the figures, sessions and transfers', async () => {
    renderApp(`/sessions/${ID}/ftp`);
    const summary = await screen.findByTestId('ftp-summary');
    expect(await within(summary).findByText('1 refused')).toBeInTheDocument();
    expect(within(summary).getByText('1 file stored')).toBeInTheDocument();
    const sessions = await screen.findByRole('list', { name: 'FTP control sessions' });
    expect(within(sessions).getByText('alice')).toBeInTheDocument();
    expect(within(sessions).getByText('Refused')).toBeInTheDocument();
    const transfers = await screen.findByRole('list', { name: 'FTP transfers' });
    expect(within(transfers).getByText('photos/harbour.png')).toBeInTheDocument();
    expect(within(transfers).getByText('226 Complete')).toBeInTheDocument();
    expect(within(transfers).getByText('426 Interrupted')).toBeInTheDocument();
  });

  it('expands a transcript with the password masked', async () => {
    const user = setupUser();
    renderApp(`/sessions/${ID}/ftp`);
    const sessions = await screen.findByRole('list', { name: 'FTP control sessions' });
    await user.click(within(sessions).getAllByRole('button', { expanded: false })[0] as HTMLElement);
    const transcript = await screen.findByTestId('ftp-transcript');
    expect(within(transcript).getByText('USER')).toBeInTheDocument();
    expect(within(transcript).getByText('alice')).toBeInTheDocument();
    expect(within(transcript).getByText('530')).toHaveClass('text-danger');
    expect(within(transcript).getByText('AUTH TLS accepted: the rest of the session is encrypted')).toBeInTheDocument();
    expect(document.body.textContent).not.toContain(SECRET);
    await user.click(within(transcript).getByRole('button', { name: 'Show password' }));
    expect(within(transcript).getByText(SECRET)).toBeInTheDocument();
    expect(ftpApi.getFtpSession).toHaveBeenCalledWith(ID, '7', expect.anything());
    expect(screen.getByRole('link', { name: 'Open Credentials' })).toBeInTheDocument();
  });

  it('shows a stored image as a backend thumbnail with download, and a listing as text', async () => {
    const user = setupUser();
    renderApp(`/sessions/${ID}/ftp`);
    const transfers = await screen.findByRole('list', { name: 'FTP transfers' });
    const rows = within(transfers).getAllByRole('button', { expanded: false });
    await user.click(rows[0] as HTMLElement);
    const img = await screen.findByRole('img', { name: 'Thumbnail of harbour.png' });
    expect(img.getAttribute('src')).toBe(PNG_URL);
    expect(screen.getByRole('link', { name: 'Open Pictures' })).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Download' }));
    expect(objectsApi.downloadObject).toHaveBeenCalledWith(ID, { sha256: SHA, file_name: 'harbour.png' });
    await user.click(rows[1] as HTMLElement);
    const listing = await screen.findByTestId('ftp-listing');
    expect(listing.textContent).toBe(LISTING);
    expect(listing.querySelector('b')).toBeNull();
  });

  it('filters sessions by login and transfers by direction', async () => {
    const user = setupUser();
    renderApp(`/sessions/${ID}/ftp`);
    await screen.findByRole('list', { name: 'FTP control sessions' });
    await user.click(screen.getByRole('radio', { name: 'Refused' }));
    await waitFor(() => {
      expect(ftpApi.listFtpSessions).toHaveBeenLastCalledWith(ID, expect.objectContaining({ login: 'rejected' }), expect.anything(), null);
    });
    await user.click(screen.getByRole('radio', { name: 'Listings' }));
    await waitFor(() => {
      expect(ftpApi.listFtpTransfers).toHaveBeenLastCalledWith(ID, expect.objectContaining({ direction: 'listing' }), expect.anything(), null);
    });
  });

  it('marks the session counters as whole session under a range', async () => {
    const range = { fromUs: T0, toUs: T0 + 59_999_999 };
    renderApp(`/sessions/${ID}/ftp?from_us=${range.fromUs}&to_us=${range.toUs}`);
    await waitFor(() => {
      expect(ftpApi.getFtpStats).toHaveBeenCalledWith(ID, expect.anything(), range);
    });
    expect(ftpApi.listFtpSessions).toHaveBeenCalledWith(ID, expect.anything(), expect.anything(), range);
    expect(ftpApi.listFtpTransfers).toHaveBeenCalledWith(ID, expect.anything(), expect.anything(), range);
    await screen.findByRole('list', { name: 'FTP control sessions' });
    expect(screen.getAllByText('Whole session').length).toBeGreaterThan(0);
  });

  it('shows the empty state without FTP', async () => {
    vi.mocked(ftpApi.getFtpStats).mockResolvedValue(
      stats({ sessions: 0, servers: 0, clients: 0, users: 0, logins_accepted: 0, logins_rejected: 0, transfers: 0, downloads: 0, listings: 0, bytes: 0, stored: 0 }),
    );
    renderApp(`/sessions/${ID}/ftp`);
    expect(await screen.findByText('No FTP session')).toBeInTheDocument();
  });
});

describe('FTP helpers', () => {
  it('classifies replies and names files', () => {
    expect(transferStatus({ status: 226 })).toBe('complete');
    expect(transferStatus({ status: 426 })).toBe('interrupted');
    expect(transferStatus({ status: 550 })).toBe('failed');
    expect(transferStatus({ status: null })).toBe('noReply');
    expect(isErrorCode('530')).toBe(true);
    expect(isErrorCode('211-')).toBe(false);
    expect(isErrorCode(null)).toBe(false);
    expect(baseName('a/b/c.txt')).toBe('c.txt');
    expect(baseName('dir/')).toBe('dir');
    expect(baseName(null)).toBe('ftp-file');
  });
});
