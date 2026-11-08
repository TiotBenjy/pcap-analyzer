//! The `smb` analyzer: NetBIOS browser announcements (UDP 138) and SMB1/2/3 sessions over TCP
//! (139/445), including NTLMSSP challenge/response pairing.
//!
//! One instance per flow shard. Captures are hostile input, so the NetBIOS session service
//! framing is bounded:
//! - only the small handshake PDUs we read (`NEGOTIATE`, `SESSION_SETUP`) are buffered, capped at
//!   [`SmbConfig::max_pdu`]; a larger PDU (READ/WRITE, up to several MiB) is skipped with a
//!   byte counter rather than buffered;
//! - buffered bytes across all flows of the shard stay under [`SmbConfig::max_total_buffer`];
//! - a keep-alive or an unexpected byte resynchronizes on the next `00 .. .. .. (fe|ff|fd)SMB`;
//! - the challenge is paired with its response by SMB2 `SessionId` and consumed on use, so one
//!   credential is emitted per AUTHENTICATE, not per flow.

use std::collections::HashMap;

use netsift_dissect::Decoded;
use netsift_flow::{Direction, Endpoint, FlowCtx, FlowId, PacketCtx, StreamCtx};

use super::browser;
use super::bytes::to_hex;
use super::message::{
    self, NBSS_POSITIVE_RESPONSE, NBSS_SESSION_KEEPALIVE, NBSS_SESSION_MESSAGE, SmbEvent,
};
use super::ntlmssp::{self, NtlmAuth, NtlmMessage};
use super::os;
use crate::analyzer::{Analyzer, AnalyzerId, RecordSink};
use crate::record::{
    Credential, NtlmPhase, Record, SecretState, Signing, SmbAnnounce, SmbProtocol, SmbRecord,
    SmbSession,
};
use crate::registry::AnalyzerConfig;

/// NetBIOS datagram service port (browser announcements).
const NETBIOS_DGM_PORT: u16 = 138;
/// SMB over TCP: NetBIOS session service and direct SMB.
const SMB_PORTS: [u16; 2] = [139, 445];
/// Largest number of outstanding challenges kept per flow (bounds adversarial memory). A real
/// client authenticates one session at a time, so a handful is plenty.
const MAX_PENDING_CHALLENGES: usize = 8;

/// Settings of the `smb` analyzer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmbConfig {
    /// Largest PDU buffered and parsed (`NEGOTIATE`/`SESSION_SETUP` are small); larger ones are
    /// skipped without buffering.
    pub max_pdu: usize,
    /// Maximum SMB flows tracked at once per shard.
    pub max_flows: usize,
    /// Byte budget for reassembly buffers across all flows of the shard.
    pub max_total_buffer: usize,
}

impl Default for SmbConfig {
    fn default() -> Self {
        Self {
            max_pdu: 64 * 1024,
            max_flows: 100_000,
            max_total_buffer: 16 * 1024 * 1024,
        }
    }
}

/// Reassembly state of one direction of a flow.
#[derive(Debug, Default)]
struct DirBuf {
    buf: Vec<u8>,
    /// Bytes still to discard from an oversized PDU being skipped.
    skip: u64,
    /// The stream desynchronized (gap, overflow, bad framing): realign before parsing.
    resync: bool,
}

/// Per-flow SMB state.
#[derive(Debug)]
struct SmbFlow {
    client: Endpoint,
    server: Endpoint,
    first_ts: i64,
    last_ts: i64,
    seen: bool,
    protocol: Option<SmbProtocol>,
    dialect: Option<String>,
    signing: Signing,
    server_guid: Option<[u8; 16]>,
    domain: Option<String>,
    account: Option<String>,
    workstation: Option<String>,
    ntlm_phase: Option<NtlmPhase>,
    /// Server challenges awaiting their response, keyed by SMB2 `SessionId` (0 for SMB1).
    pending: HashMap<u64, [u8; 8]>,
    to_server: DirBuf,
    to_client: DirBuf,
}

impl SmbFlow {
    fn new(client: Endpoint, server: Endpoint, ts: i64) -> Self {
        Self {
            client,
            server,
            first_ts: ts,
            last_ts: ts,
            seen: false,
            protocol: None,
            dialect: None,
            signing: Signing::Unknown,
            server_guid: None,
            domain: None,
            account: None,
            workstation: None,
            ntlm_phase: None,
            pending: HashMap::new(),
            to_server: DirBuf::default(),
            to_client: DirBuf::default(),
        }
    }

    fn buffered(&self) -> usize {
        self.to_server.buf.len() + self.to_client.buf.len()
    }
}

/// See the module documentation.
#[derive(Debug)]
pub struct SmbAnalyzer {
    config: SmbConfig,
    flows: HashMap<FlowId, SmbFlow>,
    /// Total bytes held by every flow's reassembly buffers (kept under `max_total_buffer`).
    buffered: usize,
}

impl SmbAnalyzer {
    pub const ID: AnalyzerId = AnalyzerId("smb");

    pub fn new(config: &AnalyzerConfig) -> Self {
        Self {
            config: config.smb.clone(),
            flows: HashMap::new(),
            buffered: 0,
        }
    }

    /// [`crate::registry::Factory`] of this analyzer.
    pub fn boxed(config: &AnalyzerConfig) -> Box<dyn Analyzer> {
        Box::new(Self::new(config))
    }

    /// Appends stream data (bounded), frames every complete NBSS PDU and handles it.
    fn ingest(
        &mut self,
        id: FlowId,
        dir: Direction,
        ts: i64,
        gap: u64,
        data: &[u8],
        out: &mut dyn RecordSink,
    ) {
        let Some(flow) = self.flows.get_mut(&id) else {
            return;
        };
        flow.last_ts = ts;
        let max_pdu = self.config.max_pdu;
        let budget = self.config.max_total_buffer;
        let buffered = &mut self.buffered;

        let mut events: Vec<SmbEvent> = Vec::new();
        {
            let d = match dir {
                Direction::ToServer => &mut flow.to_server,
                Direction::ToClient => &mut flow.to_client,
            };
            frame_direction(d, buffered, max_pdu, budget, gap, data, &mut events);
        }
        for ev in events {
            handle_event(flow, id, ts, ev, out);
        }
    }
}

/// Appends `data`, discarding oversized PDUs, and pushes the parsed events of every complete
/// handshake PDU. Updates `*buffered` to stay exact.
fn frame_direction(
    d: &mut DirBuf,
    buffered: &mut usize,
    max_pdu: usize,
    budget: usize,
    gap: u64,
    data: &[u8],
    events: &mut Vec<SmbEvent>,
) {
    if gap != 0 {
        *buffered -= d.buf.len();
        d.buf = Vec::new();
        d.skip = 0;
        d.resync = true;
    }

    // Discard the tail of a skipped PDU first.
    let mut data = data;
    if d.skip > 0 {
        let n = usize::try_from(d.skip.min(data.len() as u64)).unwrap_or(0);
        data = data.get(n..).unwrap_or_default();
        d.skip -= n as u64;
        if d.skip > 0 {
            return;
        }
    }

    // Append within the per-shard budget. On overflow, drop what we hold; if the current PDU is
    // a session message whose length we can read, arm `skip` for its remainder so `realign` does
    // not walk the payload of a large READ/WRITE, otherwise realign on the next frame start.
    if !data.is_empty() {
        if *buffered + data.len() > budget {
            let head: Vec<u8> = d.buf.iter().chain(data.iter()).take(4).copied().collect();
            let seen = d.buf.len() + data.len();
            match message::nbss_header(&head) {
                Some((NBSS_SESSION_MESSAGE, _, total)) if total > seen => {
                    d.skip = (total - seen) as u64;
                }
                _ => d.resync = true,
            }
            *buffered -= d.buf.len();
            d.buf = Vec::new();
            return;
        }
        *buffered += data.len();
        d.buf.extend_from_slice(data);
    }

    if d.resync && !realign(d, buffered) {
        return;
    }

    let mut pos = 0usize;
    while let Some(rem) = d.buf.get(pos..) {
        let Some((nbss_type, len, total)) = message::nbss_header(rem) else {
            break;
        };
        match nbss_type {
            NBSS_SESSION_KEEPALIVE | NBSS_POSITIVE_RESPONSE => {
                pos += 4;
                continue;
            }
            NBSS_SESSION_MESSAGE => {}
            _ => {
                d.resync = true;
                break;
            }
        }
        if len == 0 {
            pos += 4;
            continue;
        }
        if total > max_pdu {
            // Oversized PDU (READ/WRITE...): skip it without buffering the rest.
            if rem.len() >= total {
                pos += total;
                continue;
            }
            d.skip = (total - rem.len()) as u64;
            pos = d.buf.len();
            break;
        }
        if rem.len() < total {
            break;
        }
        if let Some(pdu) = d.buf.get(pos + 4..pos + total)
            && let Some(ev) = message::parse_pdu(pdu)
        {
            events.push(ev);
        }
        pos += total;
    }

    if pos > 0 {
        d.buf.drain(..pos);
        *buffered -= pos;
    }
    if d.buf.is_empty() {
        d.buf = Vec::new();
    }
}

/// Realigns a desynchronized buffer on the next `00 .. .. .. (fe|ff|fd)SMB`. Returns `false` when
/// no start is in the buffer yet (a short tail is kept for the next segment).
fn realign(d: &mut DirBuf, buffered: &mut usize) -> bool {
    if let Some(k) = frame_start(&d.buf) {
        d.buf.drain(..k);
        *buffered -= k;
        d.resync = false;
        true
    } else {
        let keep = d.buf.len().min(7);
        let drop = d.buf.len() - keep;
        d.buf.drain(..drop);
        *buffered -= drop;
        false
    }
}

/// First offset where an NBSS session message carrying an SMB header begins.
fn frame_start(buf: &[u8]) -> Option<usize> {
    let last = buf.len().saturating_sub(8);
    (0..=last).find(|&i| {
        buf.get(i) == Some(&NBSS_SESSION_MESSAGE)
            && matches!(buf.get(i + 4), Some(0xfd..=0xff))
            && buf.get(i + 5..i + 8) == Some(b"SMB".as_slice())
    })
}

/// Raises `phase` to `next` when `next` is further along.
fn raise_phase(phase: &mut Option<NtlmPhase>, next: NtlmPhase) {
    let rank = |p: NtlmPhase| match p {
        NtlmPhase::Negotiate => 0u8,
        NtlmPhase::Challenge => 1,
        NtlmPhase::Authenticate => 2,
    };
    if phase.is_none_or(|p| rank(p) < rank(next)) {
        *phase = Some(next);
    }
}

/// Applies one parsed SMB event to the flow, emitting a credential for a real AUTHENTICATE.
fn handle_event(flow: &mut SmbFlow, id: FlowId, ts: i64, ev: SmbEvent, out: &mut dyn RecordSink) {
    flow.seen = true;
    match ev {
        SmbEvent::Magic(proto) => {
            flow.protocol.get_or_insert(proto);
        }
        SmbEvent::Negotiate {
            protocol,
            dialect,
            signing,
            server_guid,
        } => {
            flow.protocol = Some(protocol);
            if dialect.is_some() {
                flow.dialect = dialect;
            }
            if signing != Signing::Unknown {
                flow.signing = signing;
            }
            if server_guid.is_some() {
                flow.server_guid = server_guid;
            }
        }
        SmbEvent::SessionSetup {
            protocol,
            session_id,
            ntlm,
        } => {
            flow.protocol.get_or_insert(protocol);
            match ntlm {
                Some(NtlmMessage::Negotiate) => {
                    raise_phase(&mut flow.ntlm_phase, NtlmPhase::Negotiate);
                }
                Some(NtlmMessage::Challenge { server_challenge }) => {
                    raise_phase(&mut flow.ntlm_phase, NtlmPhase::Challenge);
                    if flow.pending.len() < MAX_PENDING_CHALLENGES
                        || flow.pending.contains_key(&session_id)
                    {
                        flow.pending.insert(session_id, server_challenge);
                    }
                }
                Some(NtlmMessage::Authenticate(auth)) => {
                    raise_phase(&mut flow.ntlm_phase, NtlmPhase::Authenticate);
                    if auth.domain.is_some() {
                        flow.domain.clone_from(&auth.domain);
                    }
                    if auth.workstation.is_some() {
                        flow.workstation.clone_from(&auth.workstation);
                    }
                    // Pair with (and consume) the matching challenge: one credential per response.
                    let challenge = flow.pending.remove(&session_id);
                    if !auth.anonymous {
                        if auth.user.is_some() {
                            flow.account.clone_from(&auth.user);
                        }
                        out.emit(Record::Credential(build_credential(
                            id, flow, ts, &auth, challenge,
                        )));
                    }
                }
                None => {}
            }
        }
    }
}

/// Builds the generic credential for a non-anonymous AUTHENTICATE.
fn build_credential(
    id: FlowId,
    flow: &SmbFlow,
    ts: i64,
    auth: &NtlmAuth,
    challenge: Option<[u8; 8]>,
) -> Credential {
    let line = challenge.and_then(|c| ntlmssp::hashcat(c, auth));
    let (kind, mode, hashcat_line, state) = match &line {
        Some(l) => (
            l.kind,
            Some(l.mode),
            Some(l.line.clone()),
            SecretState::Recoverable,
        ),
        None => ("ntlm", None, None, SecretState::MetadataOnly),
    };
    let mut details = Vec::new();
    if let Some(d) = &flow.dialect {
        details.push(("dialect".to_owned(), d.clone()));
    }
    if let Some(c) = challenge {
        details.push(("server_challenge".to_owned(), to_hex(&c)));
    }
    Credential {
        source_protocol: "smb",
        kind,
        flow_id: Some(id),
        client: Some(flow.client),
        server: Some(flow.server),
        ts,
        username: auth.user.clone(),
        domain: auth.domain.clone(),
        workstation: auth.workstation.clone(),
        secret_state: state,
        secret: None,
        hashcat_mode: mode,
        hashcat_line,
        details,
    }
}

/// True when a flow key is an SMB-over-TCP conversation.
fn is_smb_flow(client: Endpoint, server: Endpoint) -> bool {
    SMB_PORTS.contains(&server.port) || SMB_PORTS.contains(&client.port)
}

impl Analyzer for SmbAnalyzer {
    fn id(&self) -> AnalyzerId {
        Self::ID
    }

    fn on_packet(&mut self, ctx: &PacketCtx, pkt: &Decoded<'_>, out: &mut dyn RecordSink) {
        let Some((src_port, dst_port)) = pkt.ports() else {
            return;
        };
        if pkt.udp().is_none() || (src_port != NETBIOS_DGM_PORT && dst_port != NETBIOS_DGM_PORT) {
            return;
        }
        let Some(ip) = pkt.ip() else { return };
        if pkt.payload.len() < browser::MIN_DATAGRAM_LEN {
            return;
        }
        if let Some(ann) = browser::parse_datagram(pkt.payload) {
            out.emit(Record::Smb(SmbRecord::Announce(SmbAnnounce {
                ts: ctx.ts_ns,
                src_ip: ip.src,
                kind: ann.kind,
                server_name: ann.server_name,
                dst_name: ann.destination.display(),
                os_major: ann.os_major,
                os_minor: ann.os_minor,
                os_label: os::os_label(ann.os_major, ann.os_minor),
                server_type: ann.server_type,
                comment: ann.comment,
            })));
        }
    }

    fn on_stream(
        &mut self,
        ctx: &StreamCtx,
        dir: Direction,
        data: &[u8],
        out: &mut dyn RecordSink,
    ) {
        let (client, server) = (ctx.key.client, ctx.key.server);
        if !is_smb_flow(client, server) {
            return;
        }
        if !self.flows.contains_key(&ctx.id) {
            if self.flows.len() >= self.config.max_flows {
                return;
            }
            self.flows
                .insert(ctx.id, SmbFlow::new(client, server, ctx.ts_ns));
        }
        self.ingest(ctx.id, dir, ctx.ts_ns, ctx.gap_before, data, out);
    }

    fn on_flow_end(&mut self, ctx: &FlowCtx, out: &mut dyn RecordSink) {
        if let Some(flow) = self.flows.remove(&ctx.id) {
            self.buffered -= flow.buffered();
            emit_session(ctx.id, &flow, out);
        }
    }

    fn finish(&mut self, out: &mut dyn RecordSink) {
        for (id, flow) in std::mem::take(&mut self.flows) {
            emit_session(id, &flow, out);
        }
        self.buffered = 0;
    }
}

/// Emits the `smb_sessions` record for a flow that carried SMB, if any.
fn emit_session(id: FlowId, flow: &SmbFlow, out: &mut dyn RecordSink) {
    if !flow.seen {
        return;
    }
    out.emit(Record::Smb(SmbRecord::Session(SmbSession {
        flow_id: id,
        client: flow.client,
        server: flow.server,
        first_ts: flow.first_ts,
        last_ts: flow.last_ts,
        protocol: flow.protocol.unwrap_or(SmbProtocol::Smb2),
        dialect: flow.dialect.clone(),
        signing: flow.signing,
        server_guid: flow.server_guid,
        domain: flow.domain.clone(),
        account: flow.account.clone(),
        workstation: flow.workstation.clone(),
        ntlm_phase: flow.ntlm_phase,
    })));
}
