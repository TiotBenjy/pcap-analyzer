import { screen, waitFor, within } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import * as api from '../../api/sessions';
import * as sipApi from '../../api/sip';
import type { Endpoint } from '../../api/types/Endpoint';
import type { SipDialogInfo } from '../../api/types/SipDialogInfo';
import type { SipMessageInfo } from '../../api/types/SipMessageInfo';
import type { SipScannerInfo } from '../../api/types/SipScannerInfo';
import type { SipStats } from '../../api/types/SipStats';
import { renderApp, setViewportWide } from '../../test/renderApp';
import { page, session } from '../../test/sessionFixtures';
import { setupUser } from '../../test/user';

vi.mock('../../api/sessions');
vi.mock('../../api/sip', async (importOriginal) => {
  const actual = await importOriginal<typeof sipApi>();
  return { ...actual, getSipStats: vi.fn(), listSipDialogs: vi.fn(), listSipMessages: vi.fn(), listSipScanners: vi.fn() };
});

const ID = '01JC0FFEE0000000000000000A';
const T0 = Date.UTC(2026, 10, 8, 10, 0, 0) * 1000;

function endpoint(ip: string, names: string[] = []): Endpoint {
  return { ip, names, category: 'private', country: null };
}

function stats(overrides: Partial<SipStats> = {}): SipStats {
  return {
    messages: 34,
    requests: 18,
    responses: 16,
    scanner_messages: 4,
    senders: 6,
    user_agents: 5,
    dialogs: 10,
    calls: 4,
    call_states: [
      { state: 'cancelled', count: 1 },
      { state: 'completed', count: 2 },
      { state: 'rejected', count: 1 },
    ],
    registrations: 1,
    call_duration_us: 8_000_000,
    methods: [
      { name: 'INVITE', count: 4 },
      { name: 'OPTIONS', count: 5 },
    ],
    statuses: [{ status: 200, reason: 'OK', count: 7 }],
    top_user_agents: [
      { name: 'Softphone/3.1', scanner: null, count: 9 },
      { name: 'friendly-scanner', scanner: 'SIPVicious', count: 4 },
    ],
    ...overrides,
  };
}

function dialog(overrides: Partial<SipDialogInfo> = {}): SipDialogInfo {
  return {
    id: 1,
    call_id: 'call-complete-7f3a@10.20.0.21',
    dialog_type: 'call',
    method: 'INVITE',
    first_ts_us: T0,
    last_ts_us: T0 + 6_000_000,
    client: endpoint('10.20.0.21'),
    client_port: 5060,
    server: endpoint('10.20.0.22'),
    server_port: 5060,
    transport: 'udp',
    from_name: 'Alice',
    from_uri: 'sip:201@10.20.0.21',
    to_name: null,
    to_uri: 'sip:202@10.20.0.22',
    contact: 'sip:201@10.20.0.21',
    user_agent: 'Deskphone 7.4.2',
    server_agent: 'Softphone/3.1',
    requests: 3,
    responses: 4,
    invite_ts_us: T0,
    ringing_ts_us: T0 + 800_000,
    answer_ts_us: T0 + 2_800_000,
    bye_ts_us: T0 + 5_800_000,
    cancelled: false,
    final_status: 200,
    final_reason: 'OK',
    state: 'completed',
    duration_us: 3_000_000,
    auth_user: null,
    challenged: false,
    scanner: null,
    media: [
      {
        media: 'audio',
        address: endpoint('10.20.0.21'),
        port: 40_000,
        proto: 'RTP/AVP',
        codecs: ['PCMU', 'PCMA'],
        direction: 'sendrecv',
        offered_by: '10.20.0.21',
        offer_ts_us: T0,
        flow_count: 1,
        packets: 60,
        bytes: 12_000,
        first_flow_id: 12,
      },
      {
        media: 'audio',
        address: endpoint('10.20.0.22'),
        port: 42_000,
        proto: 'RTP/AVP',
        codecs: ['PCMU'],
        direction: null,
        offered_by: '10.20.0.22',
        offer_ts_us: T0 + 2_800_000,
        flow_count: 0,
        packets: 0,
        bytes: 0,
        first_flow_id: null,
      },
    ],
    ...overrides,
  };
}

const RAW = 'OPTIONS sip:100@10.20.0.2 SIP/2.0\nUser-Agent: friendly-scanner\nSubject: <script>alert(1)</script>\n';

function message(overrides: Partial<SipMessageInfo> = {}): SipMessageInfo {
  return {
    id: 1,
    ts_us: T0,
    source: endpoint('203.0.113.66'),
    src_port: 5070,
    destination: endpoint('10.20.0.2'),
    dst_port: 5060,
    transport: 'udp',
    kind: 'request',
    method: 'OPTIONS',
    status: null,
    reason: null,
    request_uri: 'sip:100@10.20.0.2',
    call_id: '836925605399110177225200',
    from_uri: 'sip:100@203.0.113.66',
    to_uri: 'sip:100@203.0.113.66',
    cseq: 1,
    user_agent: 'friendly-scanner',
    scanner: 'SIPVicious',
    auth_user: null,
    size: RAW.length,
    raw: RAW,
    raw_truncated: false,
    ...overrides,
  };
}

function scanner(): SipScannerInfo {
  return {
    tool: 'SIPVicious',
    address: endpoint('203.0.113.66'),
    messages: 4,
    methods: ['OPTIONS'],
    targets: 4,
    first_ts_us: T0,
    last_ts_us: T0 + 60_000,
  };
}

beforeEach(() => {
  setViewportWide(true);
  vi.mocked(api.getSession).mockResolvedValue(session({ state: 'ready' }));
  vi.mocked(sipApi.getSipStats).mockResolvedValue(stats());
  vi.mocked(sipApi.listSipScanners).mockResolvedValue([scanner()]);
  vi.mocked(sipApi.listSipDialogs).mockResolvedValue(
    page([dialog(), dialog({ id: 2, call_id: 'call-rejected', state: 'rejected', final_status: 486, final_reason: 'Busy Here', duration_us: null, media: [] })]),
  );
  vi.mocked(sipApi.listSipMessages).mockResolvedValue(
    page([
      message(),
      message({ id: 2, kind: 'response', method: 'INVITE', status: 180, reason: 'Ringing', scanner: null, user_agent: 'Softphone/3.1' }),
    ]),
  );
});

describe('SIP view', () => {
  it('shows the figures, rankings, scanners, calls and messages', async () => {
    renderApp(`/sessions/${ID}/sip`);
    const summary = await screen.findByTestId('sip-summary');
    expect(await within(summary).findByText('2 answered, 2 not answered')).toBeInTheDocument();
    expect(screen.getByRole('list', { name: 'Requests per method' })).toBeInTheDocument();
    const agents = screen.getByRole('list', { name: 'Most frequent User-Agent and Server values' });
    expect(within(agents).getByText('scanner')).toBeInTheDocument();
    const scanners = await screen.findByRole('list', { name: 'Senders using a SIP scanner' });
    expect(within(scanners).getByText('SIPVicious')).toBeInTheDocument();
    expect(screen.getByText(/a hint, not a proof/)).toBeInTheDocument();
    const dialogs = await screen.findByRole('list', { name: 'SIP dialogs' });
    expect(within(dialogs).getByText('Completed')).toBeInTheDocument();
    expect(within(dialogs).getByText('Rejected')).toBeInTheDocument();
    const messages = await screen.findByRole('list', { name: 'SIP messages' });
    expect(within(messages).getByText('OPTIONS')).toBeInTheDocument();
    expect(within(messages).getByText('180 Ringing (INVITE)')).toBeInTheDocument();
  });

  it('expands a call with its steps and RTP streams', async () => {
    const user = setupUser();
    renderApp(`/sessions/${ID}/sip`);
    const dialogs = await screen.findByRole('list', { name: 'SIP dialogs' });
    await user.click(within(dialogs).getAllByRole('button', { expanded: false })[0] as HTMLElement);
    const media = await screen.findByRole('list', { name: 'Media announced in SDP and their flows' });
    expect(within(media).getByText('1 flow')).toBeInTheDocument();
    expect(within(media).getByText('60 packets')).toBeInTheDocument();
    expect(within(media).getByText('No flow observed')).toBeInTheDocument();
    expect(screen.getByText('Ringing')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'View messages' }));
    await waitFor(() => {
      expect(sipApi.listSipMessages).toHaveBeenLastCalledWith(ID, expect.objectContaining({ call_id: dialog().call_id }), expect.anything(), null);
    });
    expect(screen.getByText(`Call-ID ${dialog().call_id}`)).toBeInTheDocument();
  });

  it('switches the dialog type', async () => {
    const user = setupUser();
    renderApp(`/sessions/${ID}/sip`);
    await screen.findByRole('list', { name: 'SIP dialogs' });
    expect(sipApi.listSipDialogs).toHaveBeenLastCalledWith(ID, expect.objectContaining({ type: 'call' }), expect.anything(), null);
    await user.click(screen.getByRole('radio', { name: 'Registrations' }));
    await waitFor(() => {
      expect(sipApi.listSipDialogs).toHaveBeenLastCalledWith(ID, expect.objectContaining({ type: 'register' }), expect.anything(), null);
    });
  });

  it('expands the raw message as escaped text with a copy action', async () => {
    const user = setupUser();
    renderApp(`/sessions/${ID}/sip`);
    const messages = await screen.findByRole('list', { name: 'SIP messages' });
    await user.click(within(messages).getAllByRole('button', { expanded: false })[0] as HTMLElement);
    const raw = await screen.findByTestId('sip-raw');
    // Trailing empty lines are not displayed.
    expect(raw.textContent).toBe(RAW.replace(/\n+$/, ''));
    expect(raw.querySelector('script')).toBeNull();
    expect(screen.getByRole('button', { name: 'Copy raw message' })).toBeInTheDocument();
  });

  it('filters the messages from the rankings and the scanners, with removable chips', async () => {
    const user = setupUser();
    renderApp(`/sessions/${ID}/sip`);
    await screen.findByRole('list', { name: 'SIP messages' });
    await user.click(screen.getByRole('radio', { name: 'Requests' }));
    await waitFor(() => {
      expect(sipApi.listSipMessages).toHaveBeenLastCalledWith(ID, expect.objectContaining({ kind: 'request' }), expect.anything(), null);
    });
    await user.click(screen.getByRole('button', { name: 'Show the INVITE messages' }));
    await waitFor(() => {
      expect(sipApi.listSipMessages).toHaveBeenLastCalledWith(ID, expect.objectContaining({ method: 'INVITE' }), expect.anything(), null);
    });
    await user.click(await screen.findByRole('button', { name: 'View messages of SIPVicious from 203.0.113.66' }));
    await waitFor(() => {
      expect(sipApi.listSipMessages).toHaveBeenLastCalledWith(
        ID,
        expect.objectContaining({ src: '203.0.113.66', scanner: true }),
        expect.anything(),
        null,
      );
    });
    expect(sipApi.listSipMessages).toHaveBeenLastCalledWith(ID, expect.not.objectContaining({ method: expect.anything() }), expect.anything(), null);
    await user.click(screen.getByRole('button', { name: 'Clear the filter: Scanners only' }));
    await waitFor(() => {
      expect(sipApi.listSipMessages).toHaveBeenLastCalledWith(ID, expect.not.objectContaining({ scanner: true }), expect.anything(), null);
    });
  });

  it('marks the dialog counters as whole session under a range', async () => {
    const range = { fromUs: T0, toUs: T0 + 59_999_999 };
    renderApp(`/sessions/${ID}/sip?from_us=${range.fromUs}&to_us=${range.toUs}`);
    await waitFor(() => {
      expect(sipApi.getSipStats).toHaveBeenCalledWith(ID, expect.anything(), range);
    });
    expect(sipApi.listSipDialogs).toHaveBeenCalledWith(ID, expect.anything(), expect.anything(), range);
    expect(sipApi.listSipScanners).toHaveBeenCalledWith(ID, expect.anything(), range);
    await screen.findByRole('list', { name: 'SIP dialogs' });
    expect(screen.getAllByText('Whole session').length).toBeGreaterThan(0);
  });

  it('shows the empty state without SIP traffic', async () => {
    vi.mocked(sipApi.getSipStats).mockResolvedValue(
      stats({ messages: 0, requests: 0, responses: 0, dialogs: 0, calls: 0, call_states: [], methods: [], statuses: [], top_user_agents: [] }),
    );
    vi.mocked(sipApi.listSipScanners).mockResolvedValue([]);
    renderApp(`/sessions/${ID}/sip`);
    expect(await screen.findByText('No SIP message')).toBeInTheDocument();
  });
});
