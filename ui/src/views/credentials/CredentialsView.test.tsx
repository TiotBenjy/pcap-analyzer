import { screen, waitFor, within } from '@testing-library/react';
import { beforeEach, expect, it, vi } from 'vitest';
import * as credApi from '../../api/credentials';
import * as api from '../../api/sessions';
import type { CredentialInfo } from '../../api/types/CredentialInfo';
import type { CredentialStats } from '../../api/types/CredentialStats';
import type { Endpoint } from '../../api/types/Endpoint';
import { renderApp, setViewportWide } from '../../test/renderApp';
import { page, session } from '../../test/sessionFixtures';
import { setupUser } from '../../test/user';

vi.mock('../../api/sessions');
vi.mock('../../api/credentials', async (importOriginal) => {
  const actual = await importOriginal<typeof credApi>();
  return {
    ...actual,
    listCredentials: vi.fn(),
    getCredentialStats: vi.fn(),
    getCredentialPaths: vi.fn(),
    getCredential: vi.fn(),
    downloadCredentials: vi.fn(),
  };
});

const ID = '01JC0FFEE0000000000000000A';
const T0 = Date.UTC(2026, 10, 8, 10, 0, 0) * 1000;
const SECRET = 'fixture-ftp-secret';

function endpoint(ip: string): Endpoint {
  return { ip, names: [], category: 'private', country: null };
}

function cred(overrides: Partial<CredentialInfo> = {}): CredentialInfo {
  return {
    id: 'a'.repeat(64),
    protocol: 'ftp',
    kind: 'ftp',
    secret_state: 'plaintext',
    flow_id: '42',
    client: { endpoint: endpoint('192.168.1.10'), port: 50_000 },
    server: { endpoint: endpoint('192.168.1.21'), port: 21 },
    username: 'alice',
    domain: null,
    workstation: null,
    has_secret: true,
    hashcat_mode: null,
    details: [{ key: 'result', value: 'accepted' }],
    seen_count: 3,
    first_ts_us: T0,
    last_ts_us: T0 + 60_000_000,
    ...overrides,
  };
}

const NTLM = cred({
  id: 'b'.repeat(64),
  protocol: 'smb',
  kind: 'ntlmv2',
  secret_state: 'recoverable',
  username: 'jdoe',
  domain: 'CONTOSO',
  hashcat_mode: 5600,
  details: [{ key: 'server_challenge', value: '1122334455667788' }],
  seen_count: 1,
});
const SNMP = cred({ id: 'c'.repeat(64), protocol: 'snmp', kind: 'snmp', username: null, details: [] });

function stats(overrides: Partial<CredentialStats> = {}): CredentialStats {
  return {
    analyzed: true,
    total: 3,
    plaintext: 2,
    recoverable: 1,
    metadata_only: 0,
    handshakes: 0,
    hashcat_modes: [{ mode: 5600, count: 1 }],
    protocols: [
      { protocol: 'ftp', count: 1 },
      { protocol: 'smb', count: 1 },
      { protocol: 'snmp', count: 1 },
    ],
    ...overrides,
  };
}

beforeEach(() => {
  setViewportWide(true);
  vi.mocked(api.getSession).mockResolvedValue(session({ state: 'ready' }));
  vi.mocked(credApi.getCredentialStats).mockResolvedValue(stats());
  vi.mocked(credApi.getCredentialPaths).mockResolvedValue({
    paths: [
      {
        client: { endpoint: endpoint('192.168.1.10'), port: null },
        protocol: 'ftp',
        server: { endpoint: endpoint('192.168.1.21'), port: 21 },
        entries: 1,
        seen: 3,
        plaintext: 1,
      },
    ],
    others: 2,
  });
  vi.mocked(credApi.listCredentials).mockResolvedValue(page([cred(), NTLM, SNMP]));
  vi.mocked(credApi.getCredential).mockImplementation((_s, entry) =>
    Promise.resolve(
      entry === NTLM.id
        ? { info: NTLM, secret: null, hashcat_line: 'jdoe::CONTOSO:1122334455667788:ab:cd' }
        : { info: cred(), secret: SECRET, hashcat_line: null },
    ),
  );
  vi.mocked(credApi.downloadCredentials).mockResolvedValue('credentials-01jc0ffe.csv');
});

it('lists collapsed cards with masked secrets and the summary figures', async () => {
  renderApp(`/sessions/${ID}/credentials`);
  const list = await screen.findByRole('list', { name: 'Credentials' });
  expect(within(list).getAllByRole('listitem')).toHaveLength(3);
  expect(within(list).getByText('alice')).toBeInTheDocument();
  expect(within(list).getByText('CONTOSO\\jdoe')).toBeInTheDocument();
  // SNMP has no login.
  expect(within(list).getByText('Unavailable')).toBeInTheDocument();
  expect(screen.getByText('Clear-text secrets')).toBeInTheDocument();
  expect(screen.getByText('3 of 3')).toBeInTheDocument();
  expect(screen.getByRole('table', { name: 'Credential paths' })).toBeInTheDocument();
  expect(screen.getByText('2 other paths not shown')).toBeInTheDocument();
  // No secret is fetched nor shown until a card is expanded.
  expect(credApi.getCredential).not.toHaveBeenCalled();
  expect(document.body.textContent ?? '').not.toContain(SECRET);
});

it('fetches the secret on expansion and keeps it masked until revealed', async () => {
  const user = setupUser();
  renderApp(`/sessions/${ID}/credentials`);
  await screen.findByRole('list', { name: 'Credentials' });
  await user.click(screen.getByRole('button', { name: 'Show details of FTP USER / PASS' }));
  await waitFor(() => expect(credApi.getCredential).toHaveBeenCalledWith(ID, 'a'.repeat(64), expect.anything()));
  await screen.findByText(`Hidden (${SECRET.length} characters)`);
  expect(screen.getByText('Accepted')).toBeInTheDocument();
  expect(document.body.textContent ?? '').not.toContain(SECRET);
  await user.click(screen.getByRole('button', { name: 'Show secret' }));
  expect(screen.getByText(SECRET)).toBeInTheDocument();
});

it('masks the hashcat line of a recoverable entry', async () => {
  const user = setupUser();
  renderApp(`/sessions/${ID}/credentials`);
  await screen.findByRole('list', { name: 'Credentials' });
  await user.click(screen.getByRole('button', { name: 'Show details of SMB NetNTLMv2' }));
  await screen.findByRole('button', { name: 'Show hashcat line' });
  expect(screen.getByText('5600 (NetNTLMv2)')).toBeInTheDocument();
  expect(document.body.textContent ?? '').not.toContain('jdoe::CONTOSO');
});

it('asks for confirmation before an export and then shows the sensitive-data banner', async () => {
  const user = setupUser();
  renderApp(`/sessions/${ID}/credentials`);
  await screen.findByRole('list', { name: 'Credentials' });
  await user.click(screen.getByRole('button', { name: 'Export CSV' }));
  const dialog = await screen.findByRole('dialog', { name: 'Export sensitive data' });
  expect(within(dialog).getByText(/3 entries with their secrets in clear text/)).toBeInTheDocument();
  expect(credApi.downloadCredentials).not.toHaveBeenCalled();
  await user.click(within(dialog).getByRole('button', { name: 'Export' }));
  await waitFor(() =>
    expect(credApi.downloadCredentials).toHaveBeenCalledWith(ID, { format: 'csv', state: null, protocol: null, range: null }),
  );
  expect(await screen.findByText('credentials-01jc0ffe.csv was exported. It contains sensitive data.')).toBeInTheDocument();
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
});

it('exports one hashcat mode per file', async () => {
  const user = setupUser();
  renderApp(`/sessions/${ID}/credentials`);
  await screen.findByRole('list', { name: 'Credentials' });
  await user.click(screen.getByRole('button', { name: 'Export hashcat 5600' }));
  const dialog = await screen.findByRole('dialog');
  expect(within(dialog).getByText(/1 entry with its secret/)).toBeInTheDocument();
  await user.click(within(dialog).getByRole('button', { name: 'Export' }));
  await waitFor(() => expect(credApi.downloadCredentials).toHaveBeenCalledWith(ID, { format: 'hashcat', mode: 5600, range: null }));
});

it('filters by state and protocol', async () => {
  const user = setupUser();
  renderApp(`/sessions/${ID}/credentials`);
  await screen.findByRole('list', { name: 'Credentials' });
  await user.click(screen.getByRole('radio', { name: 'Recoverable' }));
  await waitFor(() =>
    expect(credApi.listCredentials).toHaveBeenLastCalledWith(
      ID,
      expect.objectContaining({ state: 'recoverable', protocol: null }),
      expect.anything(),
      null,
    ),
  );
  await user.selectOptions(screen.getByLabelText('Protocol'), 'smb');
  await waitFor(() =>
    expect(credApi.listCredentials).toHaveBeenLastCalledWith(
      ID,
      expect.objectContaining({ state: 'recoverable', protocol: 'smb' }),
      expect.anything(),
      null,
    ),
  );
});

it('explains a session imported before the analysis', async () => {
  vi.mocked(credApi.getCredentialStats).mockResolvedValue(stats({ analyzed: false, total: 0 }));
  renderApp(`/sessions/${ID}/credentials`);
  expect(await screen.findByText('Not analyzed')).toBeInTheDocument();
  expect(credApi.listCredentials).not.toHaveBeenCalled();
});

it('refuses an export above the server bound instead of truncating it', async () => {
  vi.mocked(credApi.listCredentials).mockResolvedValue({ items: [cred()], next_cursor: 'next', total_estimate: 12_345 });
  const user = setupUser();
  renderApp(`/sessions/${ID}/credentials`);
  await screen.findByRole('list', { name: 'Credentials' });
  await user.click(screen.getByRole('button', { name: 'Export CSV' }));
  const dialog = await screen.findByRole('dialog');
  expect(within(dialog).getByText(/12,345 entries match, more than the 10,000/)).toBeInTheDocument();
  expect(within(dialog).getByRole('button', { name: 'Export' })).toBeDisabled();
});

it('moves the filters into a menu on narrow screens and shows names next to addresses', async () => {
  setViewportWide(false);
  vi.mocked(credApi.listCredentials).mockResolvedValue(
    page([cred({ server: { endpoint: { ...endpoint('192.168.1.20'), names: ['FILESRV01'] }, port: 445 } })]),
  );
  const user = setupUser();
  renderApp(`/sessions/${ID}/credentials`);
  const list = await screen.findByRole('list', { name: 'Credentials' });
  expect(within(list).getByText('FILESRV01')).toBeInTheDocument();
  expect(within(list).getByTitle(/192\.168\.1\.20:445/)).toBeInTheDocument();
  expect(screen.queryByRole('radio', { name: 'Recoverable' })).not.toBeInTheDocument();
  await user.click(screen.getByText('Filters'));
  await user.selectOptions(screen.getByLabelText('Secret state'), 'recoverable');
  await waitFor(() =>
    expect(credApi.listCredentials).toHaveBeenLastCalledWith(
      ID,
      expect.objectContaining({ state: 'recoverable' }),
      expect.anything(),
      null,
    ),
  );
});
