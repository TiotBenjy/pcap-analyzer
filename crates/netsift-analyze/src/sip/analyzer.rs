//! The `sip` analyzer: every SIP message on UDP or TCP port 5060 becomes one [`SipRecord`].
//!
//! - UDP: one datagram is one message (RFC 3261 section 18.1.1).
//! - TCP: the reassembled stream of each direction is framed by `Content-Length`
//!   ([`sip::message_len`]), with a buffer of at most [`sip::MAX_MESSAGE`] bytes per direction. A
//!   direction is abandoned after a gap, a content that is not SIP or a message too large.
//!
//! Per-flow state (TCP buffers, credential counters) is dropped at the end of the flow, so memory
//! is bounded by the active flows. SIP over TLS (5061) is not decrypted.

use std::collections::HashMap;
use std::fmt;

use netsift_dissect::Decoded;
use netsift_dissect::sip::{self, SipMessage};
use netsift_flow::{Direction, Endpoint, FlowCtx, FlowId, PacketCtx, StreamCtx};

use super::scanner;
use crate::analyzer::{Analyzer, AnalyzerId, RecordSink};
use crate::credentials::MAX_PER_FLOW;
use crate::record::{Credential, Record, SecretState};
use crate::registry::AnalyzerConfig;

/// SIP port (RFC 3261 section 19.1.2).
pub const SIP_PORT: u16 = 5060;

/// Transport of a SIP message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SipTransport {
    Udp,
    Tcp,
}

impl SipTransport {
    /// Stable label stored in the database.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
        }
    }
}

/// One SIP message (`sip_messages`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SipRecord {
    pub ts: i64,
    pub src: Endpoint,
    pub dst: Endpoint,
    pub transport: SipTransport,
    /// Flow of the message, when it belongs to a tracked flow.
    pub flow_id: Option<FlowId>,
    pub message: SipMessage,
    /// Scanning tool named by the user agent ([`scanner::tool`]).
    pub scanner: Option<&'static str>,
}

/// Most bytes buffered per direction of a TCP flow: one message of at most `MAX_MESSAGE` plus
/// the next piece of data.
const BUFFER_LIMIT: usize = sip::MAX_MESSAGE.saturating_mul(2);

/// Cuts the complete messages at the start of `side.buf` (keep-alive line ends skipped) into
/// `out`, with one cursor and a single drain; abandons the direction on a framing error.
fn frame(side: &mut DirBuf, out: &mut Vec<SipMessage>) {
    let mut pos = 0usize;
    loop {
        let rest = side.buf.get(pos..).unwrap_or_default();
        let skip = sip::keepalive_len(rest);
        pos = pos.saturating_add(skip);
        let rest = side.buf.get(pos..).unwrap_or_default();
        if rest.is_empty() {
            break;
        }
        match sip::message_len(rest) {
            Ok(Some(n)) if n > 0 => {
                if let Some(m) = rest.get(..n).and_then(sip::parse) {
                    out.push(m);
                }
                pos = pos.saturating_add(n);
            }
            Ok(_) => break,
            Err(_) => {
                side.dead = true;
                side.buf = Vec::new();
                return;
            }
        }
    }
    side.buf.drain(..pos.min(side.buf.len()));
}

/// Reassembly state of one direction of a TCP flow.
#[derive(Default)]
struct DirBuf {
    buf: Vec<u8>,
    /// Abandoned: gap, content that is not SIP, or message too large.
    dead: bool,
}

/// State of one flow: TCP buffers (both directions) and credentials emitted.
#[derive(Default)]
struct FlowState {
    to_server: DirBuf,
    to_client: DirBuf,
    credentials: usize,
}

/// See the module documentation. `Debug` shows counts only: buffers may hold credentials.
#[derive(Default)]
pub struct SipAnalyzer {
    flows: HashMap<FlowId, FlowState>,
}

impl fmt::Debug for SipAnalyzer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SipAnalyzer")
            .field("flows", &self.flows.len())
            .finish()
    }
}

impl SipAnalyzer {
    pub const ID: AnalyzerId = AnalyzerId("sip");

    pub fn new(_config: &AnalyzerConfig) -> Self {
        Self::default()
    }

    /// [`crate::registry::Factory`] of this analyzer.
    pub fn boxed(config: &AnalyzerConfig) -> Box<dyn Analyzer> {
        Box::new(Self::new(config))
    }

    /// Emits the record of one message and, for a request with a Digest authorization, its
    /// credential (at most [`MAX_PER_FLOW`] per flow).
    fn emit(&mut self, record: SipRecord, out: &mut dyn RecordSink) {
        if let Some(cred) = credential(&record) {
            let allowed = match record.flow_id {
                Some(id) => {
                    let state = self.flows.entry(id).or_default();
                    state.credentials = state.credentials.saturating_add(1);
                    state.credentials <= MAX_PER_FLOW
                }
                None => true,
            };
            if allowed {
                out.emit(Record::Credential(cred));
            }
        }
        out.emit(Record::Sip(Box::new(record)));
    }
}

fn record(
    ts: i64,
    src: Endpoint,
    dst: Endpoint,
    transport: SipTransport,
    flow_id: Option<FlowId>,
    message: SipMessage,
) -> SipRecord {
    let scanner = message.software().and_then(scanner::tool);
    SipRecord {
        ts,
        src,
        dst,
        transport,
        flow_id,
        message,
        scanner,
    }
}

/// `sip-digest` credential of a request carrying `Authorization` / `Proxy-Authorization:
/// Digest` with a user name: identity and context only (`metadata-only`).
fn credential(r: &SipRecord) -> Option<Credential> {
    let auth = r.message.auth.as_ref().filter(|_| r.message.is_request())?;
    let username = auth.username.clone()?;
    let mut details = Vec::new();
    if let Some(m) = r.message.method() {
        details.push(("method".to_owned(), m.to_owned()));
    }
    for (key, value) in [
        ("uri", &auth.uri),
        ("algorithm", &auth.algorithm),
        ("qop", &auth.qop),
    ] {
        if let Some(v) = value {
            details.push((key.to_owned(), v.clone()));
        }
    }
    details.push(("header".to_owned(), auth.header.as_str().to_owned()));
    Some(Credential {
        source_protocol: "sip",
        kind: "sip-digest",
        flow_id: r.flow_id,
        client: Some(r.src),
        server: Some(r.dst),
        ts: r.ts,
        username: Some(username),
        domain: auth.realm.clone(),
        workstation: None,
        secret_state: SecretState::MetadataOnly,
        secret: None,
        hashcat_mode: None,
        hashcat_line: None,
        details,
    })
}

impl Analyzer for SipAnalyzer {
    fn id(&self) -> AnalyzerId {
        Self::ID
    }

    fn on_packet(&mut self, ctx: &PacketCtx, pkt: &Decoded<'_>, out: &mut dyn RecordSink) {
        let Some(udp) = pkt.udp() else { return };
        if udp.src_port != SIP_PORT && udp.dst_port != SIP_PORT {
            return;
        }
        let Some(ip) = pkt.ip() else { return };
        let Some(message) = sip::parse(pkt.payload) else {
            return;
        };
        let src = Endpoint {
            ip: ip.src,
            port: udp.src_port,
        };
        let dst = Endpoint {
            ip: ip.dst,
            port: udp.dst_port,
        };
        let flow = ctx.flow.map(|f| f.id);
        self.emit(
            record(ctx.ts_ns, src, dst, SipTransport::Udp, flow, message),
            out,
        );
    }

    fn on_stream(
        &mut self,
        ctx: &StreamCtx,
        dir: Direction,
        data: &[u8],
        out: &mut dyn RecordSink,
    ) {
        if ctx.key.client.port != SIP_PORT && ctx.key.server.port != SIP_PORT {
            return;
        }
        let (src, dst) = match dir {
            Direction::ToServer => (ctx.key.client, ctx.key.server),
            Direction::ToClient => (ctx.key.server, ctx.key.client),
        };
        let state = self.flows.entry(ctx.id).or_default();
        let side = match dir {
            Direction::ToServer => &mut state.to_server,
            Direction::ToClient => &mut state.to_client,
        };
        if side.dead {
            return;
        }
        if ctx.gap_before > 0 {
            side.dead = true;
            side.buf = Vec::new();
            return;
        }
        // Data is taken in pieces so that the buffer never exceeds BUFFER_LIMIT, whatever the
        // amount delivered at once; complete messages are cut after each piece.
        let mut messages = Vec::new();
        let mut rest = data;
        while !rest.is_empty() && !side.dead {
            let room = BUFFER_LIMIT.saturating_sub(side.buf.len());
            if room == 0 {
                side.dead = true;
                side.buf = Vec::new();
                break;
            }
            let (piece, next) = rest.split_at(room.min(rest.len()));
            rest = next;
            side.buf.extend_from_slice(piece);
            frame(side, &mut messages);
        }
        for m in messages {
            self.emit(
                record(ctx.ts_ns, src, dst, SipTransport::Tcp, Some(ctx.id), m),
                out,
            );
        }
    }

    fn on_flow_end(&mut self, ctx: &FlowCtx, _out: &mut dyn RecordSink) {
        self.flows.remove(&ctx.id);
    }
}
