import { screen, waitFor, within } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import * as api from '../../api/sessions';
import * as telnetApi from '../../api/telnet';
import type { Endpoint } from '../../api/types/Endpoint';
import type { TelnetSessionDetail } from '../../api/types/TelnetSessionDetail';
import type { TelnetSessionInfo } from '../../api/types/TelnetSessionInfo';
import type { TelnetStats } from '../../api/types/TelnetStats';
import { renderApp, setViewportWide } from '../../test/renderApp';
import { page, session } from '../../test/sessionFixtures';
import { setupUser } from '../../test/user';

vi.mock('../../api/sessions');
vi.mock('../../api/telnet', async (importOriginal) => {
  const actual = await importOriginal<typeof telnetApi>();
  return { ...actual, getTelnetStats: vi.fn(), listTelnetSessions: vi.fn(), getTelnetSession: vi.fn() };
});

const ID = '01JC0FFEE0000000000000000A';
const T0 = Date.UTC(2026, 10, 8, 10, 0, 0) * 1000;
const SECRET = 'user-fixture';

function endpoint(ip: string): Endpoint {
  return { ip, names: [], category: 'private', country: null };
}

function stats(overrides: Partial<TelnetStats> = {}): TelnetStats {
  return { sessions: 2, clients: 1, servers: 2, logins: 2, accepted: 1, rejected: 1, truncated: 1, ...overrides };
}

function info(overrides: Partial<TelnetSessionInfo> = {}): TelnetSessionInfo {
  return {
    flow_id: 7,
    first_ts_us: T0,
    last_ts_us: T0 + 42_000_000,
    client: endpoint('192.168.1.10'),
    client_port: 49_152,
    server: endpoint('192.168.1.23'),
    server_port: 23,
    client_bytes: 1200,
    server_bytes: 5400,
    username: 'fake',
    env_user: null,
    login: 'accepted',
    login_attempts: 1,
    terminal: 'XTERM',
    window: { cols: 80, rows: 24 },
    options: ['ECHO', 'SGA', 'TTYPE', 'NAWS'],
    transcript_bytes: 300,
    transcript_lines: 12,
    truncated: false,
    ...overrides,
  };
}

function detail(): TelnetSessionDetail {
  return {
    session: info(),
    runs: [
      { speaker: 'server', text: 'OpenBSD/i386 (oof)\n\nlogin: ' },
      { speaker: 'client', text: 'fake\n' },
      { speaker: 'server', text: 'Password:' },
      { speaker: 'secret', text: SECRET },
      { speaker: 'client', text: '\n' },
      { speaker: 'server', text: '<script>alert(1)</script>\n$ ' },
      { speaker: 'client', text: 'ls -a\n' },
    ],
  };
}

beforeEach(() => {
  setViewportWide(true);
  vi.mocked(api.getSession).mockResolvedValue(session({ state: 'ready' }));
  vi.mocked(telnetApi.getTelnetStats).mockResolvedValue(stats());
  vi.mocked(telnetApi.listTelnetSessions).mockResolvedValue(
    page([
      info(),
      info({ flow_id: 9, server: endpoint('192.168.1.70'), server_port: 2323, username: 'admin', login: 'rejected', login_attempts: 3, truncated: true }),
    ]),
  );
  vi.mocked(telnetApi.getTelnetSession).mockResolvedValue(detail());
});

describe('Telnet view', () => {
  it('shows the figures and the sessions with their status', async () => {
    renderApp(`/sessions/${ID}/telnet`);
    const summary = await screen.findByTestId('telnet-summary');
    expect(within(summary).getByText('1 accepted, 1 rejected')).toBeInTheDocument();
    const list = await screen.findByRole('list', { name: 'Telnet sessions' });
    expect(within(list).getByText('fake')).toBeInTheDocument();
    expect(within(list).getByText('admin')).toBeInTheDocument();
    expect(within(list).getByText('Rejected')).toBeInTheDocument();
    expect(within(list).getByText('Truncated')).toBeInTheDocument();
    // The list never fetches a transcript.
    expect(telnetApi.getTelnetSession).not.toHaveBeenCalled();
  });

  it('expands a transcript with the password masked, as escaped text', async () => {
    const user = setupUser();
    renderApp(`/sessions/${ID}/telnet`);
    const list = await screen.findByRole('list', { name: 'Telnet sessions' });
    await user.click(within(list).getAllByRole('button', { expanded: false })[0] as HTMLElement);
    const transcript = await screen.findByTestId('telnet-transcript');
    expect(telnetApi.getTelnetSession).toHaveBeenCalledWith(ID, 7, expect.anything());
    expect(transcript.textContent).toContain('login: fake');
    expect(transcript.textContent).toContain('<script>alert(1)</script>');
    expect(transcript.querySelector('script')).toBeNull();
    expect(transcript.textContent).not.toContain(SECRET);
    expect(within(transcript).getByText('Hidden (12 characters)')).toBeInTheDocument();
    expect(screen.getByText('80 x 24')).toBeInTheDocument();
    expect(screen.getByText('NAWS')).toBeInTheDocument();
    await user.click(within(transcript).getByRole('button', { name: 'Show Password' }));
    expect(transcript.textContent).toContain(SECRET);
  });

  it('filters by login result and search text', async () => {
    const user = setupUser();
    renderApp(`/sessions/${ID}/telnet`);
    await screen.findByRole('list', { name: 'Telnet sessions' });
    await user.selectOptions(screen.getByRole('combobox', { name: 'Login result' }), 'rejected');
    await waitFor(() => {
      expect(telnetApi.listTelnetSessions).toHaveBeenLastCalledWith(ID, expect.objectContaining({ login: 'rejected' }), expect.anything(), null);
    });
    await user.type(screen.getByRole('searchbox', { name: 'Search address, user, command' }), 'uname');
    await waitFor(() => {
      expect(telnetApi.listTelnetSessions).toHaveBeenLastCalledWith(
        ID,
        expect.objectContaining({ login: 'rejected', q: 'uname' }),
        expect.anything(),
        null,
      );
    });
  });

  it('marks the byte counters as whole session under a range', async () => {
    const range = { fromUs: T0, toUs: T0 + 59_999_999 };
    renderApp(`/sessions/${ID}/telnet?from_us=${range.fromUs}&to_us=${range.toUs}`);
    await waitFor(() => {
      expect(telnetApi.getTelnetStats).toHaveBeenCalledWith(ID, expect.anything(), range);
    });
    await screen.findByRole('list', { name: 'Telnet sessions' });
    expect(telnetApi.listTelnetSessions).toHaveBeenCalledWith(ID, expect.anything(), expect.anything(), range);
    expect(screen.getAllByText('Whole session').length).toBeGreaterThan(0);
  });

  it('shows the range empty state without sessions', async () => {
    vi.mocked(telnetApi.getTelnetStats).mockResolvedValue(stats({ sessions: 0, clients: 0, servers: 0, logins: 0, accepted: 0, rejected: 0, truncated: 0 }));
    renderApp(`/sessions/${ID}/telnet?from_us=${T0}&to_us=${T0 + 1}`);
    expect(await screen.findByText('Nothing in the range')).toBeInTheDocument();
    expect(screen.getAllByText('Nothing was recorded between these times.').length).toBeGreaterThan(0);
  });

  it('shows the empty state of a session without Telnet', async () => {
    vi.mocked(telnetApi.getTelnetStats).mockResolvedValue(stats({ sessions: 0, clients: 0, servers: 0, logins: 0, accepted: 0, rejected: 0, truncated: 0 }));
    renderApp(`/sessions/${ID}/telnet`);
    expect(await screen.findByText('No Telnet session')).toBeInTheDocument();
  });
});
