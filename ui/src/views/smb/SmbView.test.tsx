import { screen, waitFor, within } from '@testing-library/react';
import type { ComponentProps } from 'react';
import { beforeEach, expect, it, vi } from 'vitest';
import * as api from '../../api/sessions';
import * as smbApi from '../../api/smb';
import type { Endpoint } from '../../api/types/Endpoint';
import type { SmbAnnounceInfo } from '../../api/types/SmbAnnounceInfo';
import type { SmbAuthInfo } from '../../api/types/SmbAuthInfo';
import type { SmbStats } from '../../api/types/SmbStats';
import type { Chart } from '../../components/Chart';
import { renderApp, setViewportWide } from '../../test/renderApp';
import { page, session } from '../../test/sessionFixtures';
import { setupUser } from '../../test/user';

vi.mock('../../api/sessions');
vi.mock('../../api/smb');

// ECharts does not run in jsdom: the chart is replaced by a probe.
type ChartProps = ComponentProps<typeof Chart>;
vi.mock('../../components/Chart', () => ({
  Chart: (props: ChartProps) => <div data-testid="chart" data-empty={String(props.empty === true)} />,
}));

const ID = '01JC0FFEE0000000000000000A';
const T0 = Date.UTC(2026, 10, 8, 10, 0, 0) * 1000;

function endpoint(ip: string, names: string[] = []): Endpoint {
  return { ip, names, category: 'private', country: null };
}

function announce(overrides: Partial<SmbAnnounceInfo> = {}): SmbAnnounceInfo {
  return {
    source: endpoint('192.168.1.50'),
    kind: 'host',
    server_name: 'FILESRV01',
    dst_name: 'WORKGROUP<1D>',
    os_label: 'Windows 10 / Server 2016+',
    os_version: '10.0',
    roles: ['workstation', 'server', 'master_browser'],
    comment: 'File server',
    announce_count: 2,
    first_ts_us: T0,
    last_ts_us: T0 + 60_000_000,
    ...overrides,
  };
}

function auth(overrides: Partial<SmbAuthInfo> = {}): SmbAuthInfo {
  return {
    flow_id: '42',
    first_ts_us: T0,
    client: endpoint('192.168.1.10'),
    client_port: 50_000,
    server: endpoint('192.168.1.20'),
    server_port: 445,
    protocol: 'smb2',
    dialect: 'SMB 3.1.1',
    signing: 'required',
    domain: 'CORP',
    account: 'alice',
    workstation: 'WS01',
    ntlm_phase: 'authenticate',
    ...overrides,
  };
}

function stats(overrides: Partial<SmbStats> = {}): SmbStats {
  return {
    os: [
      { label: 'Windows 10 / Server 2016+', count: 2 },
      { label: 'Windows XP', count: 1 },
    ],
    announce_count: 3,
    session_count: 1,
    auth_count: 1,
    ...overrides,
  };
}

beforeEach(() => {
  setViewportWide(true);
  vi.mocked(api.getSession).mockResolvedValue(session({ state: 'ready' }));
  vi.mocked(smbApi.getSmbStats).mockResolvedValue(stats());
  vi.mocked(smbApi.listSmbAnnounces).mockResolvedValue(
    page([announce(), announce({ server_name: 'LEGACYPC', os_label: 'Windows XP', os_version: '5.1', roles: ['workstation'] })]),
  );
  vi.mocked(smbApi.listSmbAuth).mockResolvedValue(page([auth()]));
});

it('shows the OS legend and the announcements with endpoints and roles', async () => {
  renderApp(`/sessions/${ID}/smb`);
  await waitFor(() => expect(screen.getByText('FILESRV01')).toBeInTheDocument());
  const legend = screen.getByTestId('os-legend');
  expect(within(legend).getByText('Windows 10 / Server 2016+')).toBeInTheDocument();
  expect(within(legend).getByText('Windows XP')).toBeInTheDocument();
  expect(screen.getAllByText(/Master browser/).length).toBeGreaterThan(0);
  // The announcing address is rendered through the shared Endpoint component.
  expect(screen.getAllByText('192.168.1.50').length).toBeGreaterThan(0);
});

it('switches to the authentications tab without exposing any secret', async () => {
  const user = setupUser();
  renderApp(`/sessions/${ID}/smb`);
  await waitFor(() => expect(screen.getByText('FILESRV01')).toBeInTheDocument());

  await user.click(screen.getByRole('radio', { name: /Authentications/ }));
  await waitFor(() => expect(screen.getByText('alice')).toBeInTheDocument());
  expect(screen.getByText('CORP')).toBeInTheDocument();
  expect(document.body.textContent ?? '').not.toMatch(/hashcat|NTLMSSP|[0-9a-f]{32}/i);
});
