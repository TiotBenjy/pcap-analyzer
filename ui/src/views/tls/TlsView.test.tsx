import { act, screen, waitFor, within } from '@testing-library/react';
import type { ComponentProps } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import * as client from '../../api/client';
import * as api from '../../api/sessions';
import * as tlsApi from '../../api/tls';
import { attachmentName } from '../../api/tls';
import type { TlsCertificateInfo } from '../../api/types/TlsCertificateInfo';
import type { TlsSessionDetail } from '../../api/types/TlsSessionDetail';
import type { TlsSessionItem } from '../../api/types/TlsSessionItem';
import type { TlsStats } from '../../api/types/TlsStats';
import type { Chart } from '../../components/Chart';
import { renderApp, setViewportWide } from '../../test/renderApp';
import { page, session } from '../../test/sessionFixtures';
import { setupUser } from '../../test/user';
import {
  buildMatrixOption,
  buildSuitesOption,
  buildVersionsOption,
  matrixVersions,
  suiteOfRow,
  type TlsChartFormat,
  versionOfPie,
} from './tlsCharts';
import { alertName, suiteLabel, truncateLabel, versionLabel, versionTone } from './tlsFormat';

vi.mock('../../api/sessions');
vi.mock('../../api/tls', async (importOriginal) => ({
  ...(await importOriginal<typeof tlsApi>()),
  getTlsStats: vi.fn(),
  listTlsSessions: vi.fn(),
  getTlsSession: vi.fn(),
  listTlsCertificates: vi.fn(),
  downloadCertificate: vi.fn(),
}));
vi.mock('../../api/client', async (importOriginal) => ({
  ...(await importOriginal<typeof client>()),
  apiGet: vi.fn(),
}));

// ECharts does not run in jsdom: each chart is replaced by a probe keyed by its label.
type ChartProps = ComponentProps<typeof Chart>;
const charts = new Map<string, ChartProps>();
vi.mock('../../components/Chart', () => ({
  Chart: (props: ChartProps) => {
    charts.set(props.ariaLabel, props);
    return <div data-testid="chart" aria-label={props.ariaLabel} />;
  },
}));

const ID = '01JC0FFEE0000000000000000A';
const T0 = Date.UTC(2026, 10, 8, 10, 0, 0) * 1000;

function stats(overrides: Partial<TlsStats> = {}): TlsStats {
  return {
    sessions: 3,
    weak_sessions: 1,
    cert_issue_sessions: 1,
    encrypted_cert_sessions: 1,
    certificates: 2,
    versions: [
      { version: 771, count: 2 },
      { version: 772, count: 1 },
    ],
    other_versions: 0,
    suites: [
      { suite: 0xc02f, name: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', weak: null, count: 1 },
      { suite: 0x1301, name: 'TLS_AES_128_GCM_SHA256', weak: null, count: 1 },
      { suite: 0x0005, name: 'TLS_RSA_WITH_RC4_128_SHA', weak: 'rc4', count: 1 },
    ],
    matrix: [
      { version: 771, suite: 0xc02f, count: 1 },
      { version: 771, suite: 0x0005, count: 1 },
      { version: 772, suite: 0x1301, count: 1 },
    ],
    sni: [{ sni: 'shop.example.test', count: 1 }],
    ...overrides,
  };
}

function item(overrides: Partial<TlsSessionItem> = {}): TlsSessionItem {
  return {
    id: '1001',
    ts_us: T0,
    client_ip: '192.168.1.10',
    client_port: 40003,
    server_ip: '203.0.113.80',
    server_port: 443,
    sni: 'shop.example.test',
    offered_version: 771,
    version: 771,
    cipher_suite: 0xc02f,
    cipher_name: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
    cipher_weak: null,
    alpn_offered: ['http/1.1'],
    alpn: 'http/1.1',
    ja3: '771,49199,0-23,29,0',
    ja3_hash: '0123456789abcdef0123456789abcdef',
    ja4: 't12d1207h1_d34a8e72043a_bb157cc35868',
    resumed: false,
    outcome: 'complete',
    alert: null,
    cert_status: 'present',
    cert_count: 2,
    leaf_sha256: 'ab'.repeat(32),
    leaf_subject_cn: 'shop.example.test',
    cert_issues: [],
    ...overrides,
  };
}

function cert(overrides: Partial<TlsCertificateInfo> = {}): TlsCertificateInfo {
  return {
    sha256: 'ab'.repeat(32),
    sha1: 'cd'.repeat(20),
    size: 412,
    downloadable: true,
    parsed: true,
    subject: 'C=FR, O=NetSift Fixtures, CN=shop.example.test',
    subject_cn: 'shop.example.test',
    issuer: 'C=FR, O=NetSift Fixtures, CN=NetSift Test CA',
    issuer_cn: 'NetSift Test CA',
    serial: '2002',
    not_before_us: Date.UTC(2023, 0, 1) * 1000,
    not_after_us: Date.UTC(2033, 0, 1) * 1000,
    san: ['DNS:shop.example.test'],
    key_algorithm: 'EC',
    key_bits: 256,
    signature_algorithm: 'ecdsa-with-SHA256',
    self_signed: false,
    is_ca: false,
    expired: false,
    not_yet_valid: false,
    ...overrides,
  };
}

const SESSIONS = [
  item(),
  item({
    id: '1002',
    sni: 'legacy.example.test',
    cipher_suite: 5,
    cipher_name: 'TLS_RSA_WITH_RC4_128_SHA',
    cipher_weak: 'rc4',
    cert_count: 1,
    leaf_subject_cn: 'legacy.example.test',
    cert_issues: ['expired', 'self_signed'],
    outcome: 'partial',
    alert: { level: 2, description: 42, from: 'client' },
  }),
  item({ id: '1003', sni: 'www.example.test', version: 772, cipher_suite: 0x1301, cert_status: 'encrypted', cert_count: 0 }),
];

function detail(): TlsSessionDetail {
  const named = (value: number, name: string | null, grease = false) => ({ value, name, grease, weak: null });
  return {
    session: item(),
    client_hello: {
      legacy_version: 771,
      random: '00'.repeat(32),
      session_id: '11'.repeat(32),
      session_ticket: false,
      cipher_suites: [named(0x0a0a, null, true), named(0xc02f, 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256')],
      compressions: [0],
      extensions: [named(0, 'server_name'), named(16, 'application_layer_protocol_negotiation')],
      groups: [named(29, 'x25519')],
      point_formats: [0],
      signature_algorithms: [named(0x0403, 'ecdsa_secp256r1_sha256')],
      supported_versions: [],
      key_share_groups: [],
    },
    server_hello: {
      legacy_version: 771,
      random: '22'.repeat(32),
      session_id: '',
      cipher_suite: named(0xc02f, 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'),
      compression: 0,
      extensions: [named(65281, 'renegotiation_info')],
      selected_version: null,
    },
    certificates: [cert(), cert({ sha256: 'ef'.repeat(32), subject_cn: 'NetSift Test CA', is_ca: true, self_signed: true })],
  };
}

const FORMAT: TlsChartFormat = {
  version: (v) => versionLabel(v) ?? 'No ServerHello',
  share: (count, total) => `${count}/${total}`,
  other: 'Other',
  sessions: (count) => `${count} sessions`,
  weak: (w) => w.toUpperCase(),
  count: (n) => String(n),
};

describe('TLS view', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    charts.clear();
    setViewportWide(true);
    vi.mocked(client.apiGet).mockResolvedValue({ version: 'test', read_only: true, can_browse: false, status: 'ok' });
    vi.mocked(api.getSession).mockResolvedValue(session());
    vi.mocked(tlsApi.getTlsStats).mockResolvedValue(stats());
    vi.mocked(tlsApi.listTlsSessions).mockResolvedValue(page(SESSIONS));
    vi.mocked(tlsApi.getTlsSession).mockResolvedValue(detail());
    vi.mocked(tlsApi.listTlsCertificates).mockResolvedValue(
      page([{ certificate: cert(), sessions: 2 }, { certificate: cert({ sha256: 'ef'.repeat(32), subject_cn: 'old', expired: true }), sessions: 1 }]),
    );
    vi.mocked(tlsApi.downloadCertificate).mockResolvedValue();
  });

  it('shows the figures, the charts and the sessions table', async () => {
    renderApp(`/sessions/${ID}/tls`);
    const band = within(await screen.findByTestId('tls-summary'));
    expect(band.getByText('Weak suites')).toBeInTheDocument();
    expect(screen.getByRole('heading', { level: 1, name: 'SSL/TLS' })).toBeInTheDocument();
    const table = await screen.findByRole('table', { name: 'TLS sessions' });
    expect(within(table).getAllByText('legacy.example.test').length).toBe(2);
    expect(within(table).getByText('Expired')).toBeInTheDocument();
    expect(within(table).getByText('Encrypted')).toBeInTheDocument();
    expect(within(table).getAllByRole('img', { name: 'RC4' }).length).toBeGreaterThan(0);
    expect(charts.has('Negotiated TLS versions')).toBe(true);
    expect(charts.has('Negotiated cipher suites, top 15')).toBe(true);
    expect(charts.has('Sessions by negotiated version and cipher suite')).toBe(true);
    expect(screen.getByText('Weak suites are marked with an amber dot.')).toBeInTheDocument();
  });

  it('filters on the server with the toggles, the selects and chart clicks', async () => {
    renderApp(`/sessions/${ID}/tls`);
    await screen.findByRole('table', { name: 'TLS sessions' });
    expect(tlsApi.listTlsSessions).toHaveBeenLastCalledWith(
      ID,
      { version: undefined, suite: undefined, q: '', weak: false, certIssues: false },
      expect.anything(),
      expect.anything(),
    );
    const user = setupUser();
    await user.click(screen.getAllByRole('switch', { name: /Weak suites only/ })[0] as HTMLElement);
    await waitFor(() => {
      expect(tlsApi.listTlsSessions).toHaveBeenLastCalledWith(
        ID,
        expect.objectContaining({ weak: true }),
        expect.anything(),
        expect.anything(),
      );
    });
    await user.click(screen.getByRole('radio', { name: 'TLS 1.3' }));
    await waitFor(() => {
      expect(tlsApi.listTlsSessions).toHaveBeenLastCalledWith(
        ID,
        expect.objectContaining({ version: 772 }),
        expect.anything(),
        expect.anything(),
      );
    });
    // A click on a bar selects its suite (rows are drawn bottom-up).
    act(() => {
      charts.get('Negotiated cipher suites, top 15')?.onEvents?.click?.({ dataIndex: 0 });
    });
    await waitFor(() => {
      expect(screen.getByRole('combobox', { name: 'Cipher suite' })).toHaveValue(String(0x0005));
    });
    await user.click(screen.getByRole('button', { name: 'Clear filters' }));
    expect(screen.getByRole('radio', { name: 'All versions' })).toBeChecked();
    expect(screen.getByRole('combobox', { name: 'Cipher suite' })).toHaveValue('');
  });

  it('opens the session details with hellos and certificates', async () => {
    renderApp(`/sessions/${ID}/tls`);
    const table = await screen.findByRole('table', { name: 'TLS sessions' });
    const user = setupUser();
    const rows = within(table).getAllByRole('row');
    await user.click(rows[1] as HTMLElement);
    const panel = within(await screen.findByTestId('tls-session-detail'));
    expect(panel.getByText('Complete')).toBeInTheDocument();
    expect(panel.getByText('t12d1207h1_d34a8e72043a_bb157cc35868')).toBeInTheDocument();

    await user.click(panel.getByRole('radio', { name: 'Client Hello' }));
    expect(await panel.findByText('x25519')).toBeInTheDocument();
    expect(panel.getByText('GREASE')).toBeInTheDocument();
    expect(tlsApi.getTlsSession).toHaveBeenCalledWith(ID, '1001', expect.anything());

    await user.click(panel.getByRole('radio', { name: 'Certificates (2)' }));
    expect(panel.getByText('Leaf')).toBeInTheDocument();
    expect(panel.getByText('CA')).toBeInTheDocument();
    await user.click(panel.getAllByRole('button', { name: 'Download shop.example.test as PEM' })[0] as HTMLElement);
    expect(tlsApi.downloadCertificate).toHaveBeenCalledWith(ID, 'ab'.repeat(32), 'pem');

    await user.click(screen.getByRole('button', { name: 'Close details' }));
    expect(screen.queryByTestId('tls-session-detail')).toBeNull();
  });

  it('lists the deduplicated certificates with their downloads', async () => {
    renderApp(`/sessions/${ID}/tls`);
    const user = setupUser();
    await user.click(await screen.findByRole('radio', { name: 'Certificates (2)' }));
    const table = await screen.findByRole('table', { name: 'Certificates' });
    expect(within(table).getByText('old')).toBeInTheDocument();
    expect(within(table).getByText('Expired')).toBeInTheDocument();
    await user.click(within(table).getByRole('button', { name: 'Download old as DER' }));
    expect(tlsApi.downloadCertificate).toHaveBeenCalledWith(ID, 'ef'.repeat(32), 'der');
    await user.click(screen.getAllByRole('switch', { name: /Problems only/ })[0] as HTMLElement);
    await waitFor(() => {
      expect(tlsApi.listTlsCertificates).toHaveBeenLastCalledWith(
        ID,
        { q: '', problems: true },
        expect.anything(),
        expect.anything(),
      );
    });
  });

  it('shows explicit empty and error states', async () => {
    vi.mocked(tlsApi.getTlsStats).mockResolvedValue(stats({ sessions: 0, versions: [], suites: [], matrix: [], sni: [] }));
    const { unmount } = renderApp(`/sessions/${ID}/tls`);
    expect(await screen.findByText('No TLS session in this capture')).toBeInTheDocument();
    unmount();
    vi.mocked(tlsApi.getTlsStats).mockRejectedValue(new client.ApiError(500, 'internal', 'boom'));
    renderApp(`/sessions/${ID}/tls`);
    expect(await screen.findByText('TLS data could not be loaded')).toBeInTheDocument();
  });
});

describe('TLS charts and formats', () => {
  it('builds a donut with one fixed color per version', () => {
    const option = buildVersionsOption(stats(), FORMAT) as {
      series: { data: { name: string; value: number }[] }[];
      legend: { formatter: (n: string) => string };
    };
    expect(option.series[0]?.data.map((d) => d.name)).toEqual(['771', '772']);
    expect(option.legend.formatter('771')).toBe('TLS 1.2');
    expect(option.legend.formatter('none')).toBe('No ServerHello');
    expect(versionOfPie({ name: '772' })).toBe(772);
    expect(versionOfPie({ name: 'none' })).toBeUndefined();
    expect(versionOfPie({ name: 'other' })).toBeUndefined();
    const others = buildVersionsOption(stats({ other_versions: 3 }), FORMAT) as typeof option;
    expect(others.series[0]?.data.at(-1)).toMatchObject({ name: 'other', value: 3 });
    expect(others.legend.formatter('other')).toBe('Other');
    const withNone = buildVersionsOption(stats({ versions: [{ version: null, count: 2 }] }), FORMAT) as {
      series: { data: { name: string }[] }[];
    };
    expect(withNone.series[0]?.data[0]?.name).toBe('none');
  });

  it('marks weak suites in the bar labels and keeps the most frequent on top', () => {
    const option = buildSuitesOption(stats(), FORMAT) as {
      xAxis: { show: boolean };
      yAxis: { data: string[]; axisLabel: { formatter: (v: string, i: number) => string } };
      series: { label: { show: boolean; position: string } }[];
    };
    expect(option.xAxis.show).toBe(false);
    expect(option.series[0]?.label).toMatchObject({ show: true, position: 'right' });
    expect(option.yAxis.data).toEqual(['RSA_WITH_RC4_128_SHA', 'AES_128_GCM_SHA256', 'ECDHE_RSA_WITH_AES_128_GCM_SHA256']);
    expect(option.yAxis.axisLabel.formatter('RSA_WITH_RC4_128_SHA', 0)).toBe('{w|}{n|RSA_WITH_RC4_128_SHA}');
    expect(option.yAxis.axisLabel.formatter('ECDHE_RSA_WITH_AES_128_GCM_SHA256', 2)).toBe(
      '{s|}{n|ECDHE_RSA_WI…_GCM_SHA256}',
    );
    expect(suiteOfRow(stats(), 0)).toBe(5);
    const withOthers = stats({ suites: [...stats().suites, { suite: null, name: null, weak: null, count: 4 }] });
    expect(suiteOfRow(withOthers, 0)).toBeUndefined();
  });

  it('places the matrix cells on version columns and suite rows', () => {
    const option = buildMatrixOption(stats(), FORMAT, false) as {
      xAxis: { data: string[] };
      visualMap: { inRange: { color: string[] } };
      series: { data: { value: [number, number, number] }[] }[];
    };
    expect(option.xAxis.data).toEqual(['1.2', '1.3']);
    expect(matrixVersions(stats())).toEqual([771, 772]);
    const dark = buildMatrixOption(stats(), FORMAT, true) as typeof option;
    expect(dark.visualMap.inRange.color[0]).toBe('#172554');
    expect(option.visualMap.inRange.color[0]).toBe('#dbeafe');
    const folded = buildMatrixOption(stats({ matrix: [{ version: null, suite: null, count: 2 }] }), FORMAT, false) as typeof option;
    expect(folded.xAxis.data).toEqual(['Other']);
    expect(option.series[0]?.data.map((d) => d.value)).toEqual([
      [0, 2, 1],
      [0, 0, 1],
      [1, 1, 1],
    ]);
  });

  it('formats versions, suites, alerts and attachment names', () => {
    expect(versionLabel(0x0304)).toBe('TLS 1.3');
    expect(versionLabel(0x7f12)).toBe('0x7f12');
    expect(versionLabel(null)).toBeNull();
    expect(versionTone(0x0301)).toBe('warning');
    expect(versionTone(0x0304)).toBe('success');
    expect(suiteLabel(null, 0xfafa)).toBe('0xfafa');
    expect(truncateLabel('x'.repeat(30))).toHaveLength(24);
    expect(alertName(42)).toBe('bad_certificate');
    expect(alertName(250)).toBe('alert 250');
    expect(attachmentName('attachment; filename="shop-ab.der"')).toBe('shop-ab.der');
    expect(attachmentName(null)).toBeNull();
  });
});
