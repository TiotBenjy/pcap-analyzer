//! The `http` analyzer: HTTP/1.0 and HTTP/1.1 transactions over reassembled TCP streams.
//!
//! - **Detection by content**, whatever the port: a connection is HTTP when its first data
//!   (within the first few segments) starts a request (`METHOD target HTTP/1.x`) or a response
//!   (`HTTP/1.x`). Other connections are ignored after that probe.
//! - **Pairing**: requests are queued per connection and responses are matched in order
//!   (pipelining, keep-alive). Interim responses (`1xx`) are skipped; `101` and a `2xx` answer to
//!   `CONNECT` end the HTTP part of the connection (tunnel). A request without response is
//!   emitted at the end of the connection; a response whose request was not captured is emitted
//!   alone.
//! - **Bodies** (`body`): `Content-Length`, `Transfer-Encoding: chunked` or until the close;
//!   content codings gzip, deflate (zlib or raw) and brotli decoded incrementally. Decoding stops
//!   at [`HttpConfig::max_body_bytes`] (`truncated`) or when the decompression ratio exceeds
//!   [`HttpConfig::max_decompression_ratio`] (`bomb`). Decoded bytes are kept within a shard-wide
//!   budget ([`HttpConfig::max_retained_bytes`]), only to inspect the body when it ends.
//! - **Gaps** (lost segments): inside a body of known length the framing survives (the body is
//!   `incomplete`); elsewhere the direction waits for a segment starting a new message.
//! - Hostile input: heads are bounded ([`message::MAX_HEAD`], 128 headers), every length is
//!   checked, nothing is allocated from an unverified length field.
//!
//! # Extension point (objects P3.6, credentials P3.7)
//!
//! Every finished message goes through [`inspect::inspect_message`], which receives a
//! [`MessageView`]: connection, start line, headers and the **decoded body** (with its state).
//! It fills the body figures of the record (sniffed MIME type, preview) and calls
//! [`RecordSink::put_blob`] for complete bodies, so objects appear in `http_transactions` as
//! soon as the engine stores blobs (P3.6). Credentials (`Authorization: Basic`, login forms)
//! are to be emitted from the same function as `Record::Credential` (P3.7).

mod body;
pub mod inspect;
mod message;
mod types;

use std::collections::{HashMap, VecDeque};

use netsift_dissect::{Decoded, Transport};
use netsift_flow::{Direction, FlowCtx, FlowId, FlowKey, PacketCtx, StreamCtx, TcpState};

use crate::analyzer::{Analyzer, AnalyzerId, RecordSink};
use crate::record::Record;
use crate::registry::AnalyzerConfig;
use body::{BodyReader, Shared};
use message::{MAX_HEAD, ResponseNext};

pub use inspect::{MessageView, Role};
pub use types::{
    BodyState, HttpBody, HttpConfig, HttpHeader, HttpMessage, HttpRequest, HttpResponse,
    HttpTransaction, RATIO_CHECK_MIN, media_type,
};

/// Segments looked at (per connection) before deciding that a connection is not HTTP.
const PROBE_SEGMENTS: u8 = 4;

/// The `http` analyzer (one instance per shard).
#[derive(Debug)]
pub struct HttpAnalyzer {
    shared: Shared,
    flows: HashMap<FlowId, Conn>,
}

#[derive(Debug)]
enum Conn {
    /// Not decided yet: segments seen so far, FIN seen from the server.
    Probing {
        seen: u8,
        server_fin: bool,
    },
    NotHttp,
    Http(Box<FlowState>),
}

impl HttpAnalyzer {
    pub const ID: AnalyzerId = AnalyzerId("http");

    pub fn new(config: &AnalyzerConfig) -> Self {
        Self {
            shared: Shared::new(config.http.clone()),
            flows: HashMap::new(),
        }
    }

    pub fn boxed(config: &AnalyzerConfig) -> Box<dyn Analyzer> {
        Box::new(Self::new(config))
    }
}

impl Analyzer for HttpAnalyzer {
    fn id(&self) -> AnalyzerId {
        Self::ID
    }

    fn on_stream(
        &mut self,
        ctx: &StreamCtx,
        dir: Direction,
        data: &[u8],
        out: &mut dyn RecordSink,
    ) {
        let conn = self.flows.entry(ctx.id).or_insert(Conn::Probing {
            seen: 0,
            server_fin: false,
        });
        if let Conn::Probing { seen, server_fin } = *conn {
            let starts = match dir {
                Direction::ToServer => message::starts_request(data),
                Direction::ToClient => message::starts_response(data),
            };
            if starts {
                let mut state = FlowState::new(ctx.key, ctx.id);
                state.server_fin = server_fin;
                *conn = Conn::Http(Box::new(state));
            } else {
                let seen = seen.saturating_add(1);
                *conn = if seen >= PROBE_SEGMENTS {
                    Conn::NotHttp
                } else {
                    Conn::Probing { seen, server_fin }
                };
                return;
            }
        }
        if let Conn::Http(state) = conn {
            // A gap before the first message: nothing to resynchronize from.
            let gap = if state.started { ctx.gap_before } else { 0 };
            state.started = true;
            state.feed(dir, ctx, gap, data, &mut self.shared, out);
        }
    }

    /// Only the FIN of the server matters: it ends a response read until the close.
    fn on_packet(&mut self, ctx: &PacketCtx, pkt: &Decoded<'_>, _out: &mut dyn RecordSink) {
        let (Some(flow), Some(Transport::Tcp(tcp))) = (ctx.flow, &pkt.transport) else {
            return;
        };
        if flow.dir != Direction::ToClient || !tcp.flags.fin() {
            return;
        }
        // The FIN may come with (or before) the first data of the connection.
        let conn = self.flows.entry(flow.id).or_insert(Conn::Probing {
            seen: 0,
            server_fin: false,
        });
        match conn {
            Conn::Probing { server_fin, .. } => *server_fin = true,
            Conn::Http(state) => state.server_fin = true,
            Conn::NotHttp => {}
        }
    }

    fn on_flow_end(&mut self, ctx: &FlowCtx, out: &mut dyn RecordSink) {
        if let Some(Conn::Http(mut state)) = self.flows.remove(&ctx.id) {
            // A FIN from the client alone (half close) does not end a response.
            let clean = state.server_fin || ctx.tcp_state == Some(TcpState::Closed);
            state.end(clean, ctx.last_ts_ns, &mut self.shared, out);
        }
    }

    fn finish(&mut self, out: &mut dyn RecordSink) {
        let mut left: Vec<(FlowId, Conn)> = self.flows.drain().collect();
        left.sort_unstable_by_key(|(id, _)| *id);
        for (_, conn) in left {
            if let Conn::Http(mut state) = conn {
                let at = state.last_ts;
                state.end(false, at, &mut self.shared, out);
            }
        }
    }
}

/// Head being accumulated.
#[derive(Debug, Default)]
struct HeadBuf {
    buf: Vec<u8>,
    /// Bytes already searched for the end of the head.
    scanned: usize,
    ts_ns: i64,
    frame: u64,
}

#[derive(Debug)]
enum StartLine {
    Request {
        method: String,
        target: String,
        minor_version: u8,
    },
    Response {
        minor_version: u8,
        status: u16,
        reason: String,
    },
}

/// A message whose body is being read.
#[derive(Debug)]
struct OpenMessage {
    seq: u32,
    start: StartLine,
    ts_ns: i64,
    end_ts_ns: i64,
    frame: u64,
    head_len: u64,
    headers: Vec<HttpHeader>,
    content_encoding: Option<String>,
}

#[derive(Debug)]
enum Phase {
    Head(HeadBuf),
    Body(BodyReader, Box<OpenMessage>),
    /// The connection stopped being HTTP (tunnel, protocol switch).
    Tunnel,
    /// Lost synchronization: waiting for a segment that starts a message.
    Broken,
}

/// A request and its response, while one of them is missing or being read.
#[derive(Debug)]
struct Exchange {
    seq: u32,
    /// Method of the request, known from its head (`None`: response without request).
    method: Option<String>,
    request: Option<HttpRequest>,
    request_open: bool,
    response: Option<HttpResponse>,
    response_open: bool,
}

/// One HTTP connection.
#[derive(Debug)]
struct FlowState {
    key: FlowKey,
    id: FlowId,
    started: bool,
    /// The server sent a FIN.
    server_fin: bool,
    last_ts: i64,
    req: Phase,
    resp: Phase,
    pending: VecDeque<Exchange>,
    next_seq: u32,
}

enum Finished {
    Request(HttpRequest),
    Response(HttpResponse),
}

impl FlowState {
    fn new(key: FlowKey, id: FlowId) -> Self {
        Self {
            key,
            id,
            started: false,
            server_fin: false,
            last_ts: 0,
            req: Phase::Head(HeadBuf::default()),
            resp: Phase::Head(HeadBuf::default()),
            pending: VecDeque::new(),
            next_seq: 0,
        }
    }

    fn phase_mut(&mut self, dir: Direction) -> &mut Phase {
        match dir {
            Direction::ToServer => &mut self.req,
            Direction::ToClient => &mut self.resp,
        }
    }

    fn feed(
        &mut self,
        dir: Direction,
        ctx: &StreamCtx,
        gap: u64,
        mut data: &[u8],
        sh: &mut Shared,
        out: &mut dyn RecordSink,
    ) {
        self.last_ts = self.last_ts.max(ctx.ts_ns);
        if gap > 0 {
            self.gap(dir, gap, ctx.ts_ns, sh, out);
        }
        while !data.is_empty() {
            match self.phase_mut(dir) {
                Phase::Tunnel => return,
                phase @ Phase::Broken => {
                    let starts = match dir {
                        Direction::ToServer => message::starts_request(data),
                        Direction::ToClient => message::starts_response(data),
                    };
                    if !starts {
                        return;
                    }
                    *phase = Phase::Head(HeadBuf::default());
                }
                Phase::Head(hb) => {
                    if hb.buf.is_empty() {
                        // Blank lines between messages are tolerated.
                        let skip = data
                            .iter()
                            .take_while(|b| matches!(b, b'\r' | b'\n'))
                            .count();
                        data = data.get(skip..).unwrap_or_default();
                        if data.is_empty() {
                            return;
                        }
                        hb.ts_ns = ctx.ts_ns;
                        hb.frame = ctx.frame;
                    }
                    let before = hb.buf.len();
                    let take = MAX_HEAD.saturating_sub(before).min(data.len());
                    hb.buf
                        .extend_from_slice(data.get(..take).unwrap_or_default());
                    if let Some(end) = message::head_end(&hb.buf, hb.scanned) {
                        hb.buf.truncate(end);
                        let consumed = end.saturating_sub(before);
                        data = data.get(consumed..).unwrap_or_default();
                        let head = std::mem::take(hb);
                        self.on_head(dir, &head, ctx, sh, out);
                    } else {
                        if hb.buf.len() >= MAX_HEAD {
                            *self.phase_mut(dir) = Phase::Broken;
                        } else {
                            hb.scanned = hb.buf.len();
                        }
                        return;
                    }
                }
                Phase::Body(reader, msg) => {
                    let fed = reader.feed(data, sh);
                    msg.end_ts_ns = ctx.ts_ns;
                    data = data.get(fed.used..).unwrap_or_default();
                    if fed.done {
                        self.end_body(dir, true, sh, out);
                    }
                }
            }
        }
    }

    /// `len` bytes are missing just before the next data of `dir`.
    fn gap(
        &mut self,
        dir: Direction,
        len: u64,
        ts_ns: i64,
        sh: &mut Shared,
        out: &mut dyn RecordSink,
    ) {
        let phase = self.phase_mut(dir);
        match phase {
            Phase::Tunnel | Phase::Broken => {}
            Phase::Head(_) => *phase = Phase::Broken,
            Phase::Body(reader, msg) => {
                msg.end_ts_ns = ts_ns;
                let keeps_framing = reader.gap(len, sh);
                if !keeps_framing {
                    self.end_body(dir, false, sh, out);
                    *self.phase_mut(dir) = Phase::Broken;
                } else if reader.is_done() {
                    self.end_body(dir, true, sh, out);
                }
            }
        }
    }

    fn on_head(
        &mut self,
        dir: Direction,
        head: &HeadBuf,
        ctx: &StreamCtx,
        sh: &mut Shared,
        out: &mut dyn RecordSink,
    ) {
        match dir {
            Direction::ToServer => self.on_request_head(head, ctx, sh, out),
            Direction::ToClient => self.on_response_head(head, ctx, sh, out),
        }
    }

    fn on_request_head(
        &mut self,
        head: &HeadBuf,
        ctx: &StreamCtx,
        sh: &mut Shared,
        out: &mut dyn RecordSink,
    ) {
        let Some(req) = message::parse_request(&head.buf) else {
            self.req = Phase::Broken;
            return;
        };
        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        self.push(
            Exchange {
                seq,
                method: Some(req.method.clone()),
                request: None,
                request_open: true,
                response: None,
                response_open: false,
            },
            sh,
            out,
        );
        let framing = message::request_framing(&req.headers);
        let msg = OpenMessage {
            seq,
            start: StartLine::Request {
                method: req.method,
                target: req.target,
                minor_version: req.minor_version,
            },
            ts_ns: head.ts_ns,
            end_ts_ns: ctx.ts_ns,
            frame: head.frame,
            head_len: head.buf.len() as u64,
            content_encoding: message::content_encoding(&req.headers),
            headers: req.headers,
        };
        self.open_body(Direction::ToServer, msg, framing.ok_or(()), sh, out);
    }

    fn on_response_head(
        &mut self,
        head: &HeadBuf,
        ctx: &StreamCtx,
        sh: &mut Shared,
        out: &mut dyn RecordSink,
    ) {
        let Some(resp) = message::parse_response(&head.buf) else {
            self.resp = Phase::Broken;
            return;
        };
        let waiting = self
            .pending
            .iter()
            .position(|e| e.method.is_some() && e.response.is_none() && !e.response_open);
        let method = waiting
            .and_then(|i| self.pending.get(i))
            .and_then(|e| e.method.clone());
        let next = message::response_next(resp.status, method.as_deref(), &resp.headers);
        if next == Some(ResponseNext::Interim) {
            self.resp = Phase::Head(HeadBuf::default());
            return;
        }
        let seq = if let Some(e) = waiting.and_then(|i| self.pending.get_mut(i)) {
            e.response_open = true;
            e.seq
        } else {
            let seq = self.next_seq;
            self.next_seq = self.next_seq.saturating_add(1);
            self.push(
                Exchange {
                    seq,
                    method: None,
                    request: None,
                    request_open: false,
                    response: None,
                    response_open: true,
                },
                sh,
                out,
            );
            seq
        };
        let msg = OpenMessage {
            seq,
            start: StartLine::Response {
                minor_version: resp.minor_version,
                status: resp.status,
                reason: resp.reason,
            },
            ts_ns: head.ts_ns,
            end_ts_ns: ctx.ts_ns,
            frame: head.frame,
            head_len: head.buf.len() as u64,
            content_encoding: message::content_encoding(&resp.headers),
            headers: resp.headers,
        };
        match next {
            Some(ResponseNext::Tunnel) => {
                self.open_body(
                    Direction::ToClient,
                    msg,
                    Ok(body::Framing::Length(0)),
                    sh,
                    out,
                );
                // Both directions stop being HTTP; a request body being read ends here.
                self.end_body(Direction::ToServer, false, sh, out);
                self.req = Phase::Tunnel;
                self.resp = Phase::Tunnel;
            }
            Some(ResponseNext::Body(framing)) => {
                self.open_body(Direction::ToClient, msg, Ok(framing), sh, out);
            }
            Some(ResponseNext::Interim) | None => {
                self.open_body(Direction::ToClient, msg, Err(()), sh, out);
            }
        }
    }

    /// Starts reading the body of `msg` (`Err`: invalid framing, the message is malformed and
    /// the direction is abandoned).
    fn open_body(
        &mut self,
        dir: Direction,
        msg: OpenMessage,
        framing: Result<body::Framing, ()>,
        sh: &mut Shared,
        out: &mut dyn RecordSink,
    ) {
        let reader = BodyReader::new(
            framing.unwrap_or(body::Framing::Length(0)),
            msg.content_encoding.as_deref(),
            sh,
        );
        *self.phase_mut(dir) = Phase::Body(reader, Box::new(msg));
        if framing.is_err() {
            self.end_body_with(dir, true, Some(BodyState::Malformed), sh, out);
            *self.phase_mut(dir) = Phase::Broken;
            return;
        }
        if matches!(self.phase_mut(dir), Phase::Body(r, _) if r.is_done()) {
            self.end_body(dir, true, sh, out);
        }
    }

    fn end_body(&mut self, dir: Direction, clean: bool, sh: &mut Shared, out: &mut dyn RecordSink) {
        self.end_body_with(dir, clean, None, sh, out);
    }

    /// Finishes the message whose body is being read in `dir` (no-op otherwise).
    fn end_body_with(
        &mut self,
        dir: Direction,
        clean: bool,
        forced: Option<BodyState>,
        sh: &mut Shared,
        out: &mut dyn RecordSink,
    ) {
        let phase = std::mem::replace(self.phase_mut(dir), Phase::Head(HeadBuf::default()));
        let Phase::Body(reader, msg) = phase else {
            *self.phase_mut(dir) = phase;
            return;
        };
        let done = reader.finish(clean, sh);
        let state = forced.unwrap_or(done.state);
        if state == BodyState::Malformed {
            *self.phase_mut(dir) = Phase::Broken;
        }
        let msg = *msg;
        let mut body = HttpBody {
            wire_len: done.wire_len,
            decoded_len: done.decoded_len,
            chunked: done.chunked,
            content_encoding: msg.content_encoding.clone(),
            state,
            mime_magic: None,
            preview: None,
            blob: None,
        };
        let (role, method, target, status) = match &msg.start {
            StartLine::Request { method, target, .. } => (
                Role::Request,
                Some(method.as_str()),
                Some(target.as_str()),
                None,
            ),
            StartLine::Response { status, .. } => (Role::Response, None, None, Some(*status)),
        };
        let view = MessageView {
            flow: self.id,
            key: &self.key,
            role,
            ts_ns: msg.ts_ns,
            frame: msg.frame,
            method,
            target,
            status,
            headers: &msg.headers,
            state,
            body: &done.data,
            body_complete: state == BodyState::Complete && done.fully_retained,
        };
        inspect::inspect_message(&view, &mut body, &sh.config, out);
        let message = HttpMessage {
            ts_ns: msg.ts_ns,
            end_ts_ns: msg.end_ts_ns,
            frame: msg.frame,
            head_len: msg.head_len,
            headers: msg.headers,
            body,
        };
        let finished = match msg.start {
            StartLine::Request {
                method,
                target,
                minor_version,
            } => Finished::Request(HttpRequest {
                method,
                target,
                minor_version,
                message,
            }),
            StartLine::Response {
                minor_version,
                status,
                reason,
            } => Finished::Response(HttpResponse {
                minor_version,
                status,
                reason,
                message,
            }),
        };
        self.attach(msg.seq, finished, out);
    }

    fn push(&mut self, ex: Exchange, sh: &Shared, out: &mut dyn RecordSink) {
        while self.pending.len() >= sh.config.max_pending.max(1) {
            match self.pending.pop_front() {
                Some(old) => self.emit(old, out),
                None => break,
            }
        }
        self.pending.push_back(ex);
    }

    fn attach(&mut self, seq: u32, part: Finished, out: &mut dyn RecordSink) {
        if let Some(e) = self.pending.iter_mut().find(|e| e.seq == seq) {
            match part {
                Finished::Request(r) => {
                    e.request = Some(r);
                    e.request_open = false;
                }
                Finished::Response(r) => {
                    e.response = Some(r);
                    e.response_open = false;
                }
            }
        } else {
            // Its exchange was pushed out of the queue (and emitted, with `seq`, if it had a
            // finished part): the part goes alone, under a new number.
            let (request, response) = match part {
                Finished::Request(r) => (Some(r), None),
                Finished::Response(r) => (None, Some(r)),
            };
            let fresh = self.next_seq;
            self.next_seq = self.next_seq.saturating_add(1);
            self.emit_parts(fresh, request, response, out);
        }
        self.drain(false, out);
    }

    /// Emits the finished exchanges at the front of the queue (all of them when `all`).
    fn drain(&mut self, all: bool, out: &mut dyn RecordSink) {
        while let Some(front) = self.pending.front() {
            let done = !front.request_open && !front.response_open && front.response.is_some();
            if !(done || all) {
                break;
            }
            if let Some(ex) = self.pending.pop_front() {
                self.emit(ex, out);
            }
        }
    }

    fn emit(&self, ex: Exchange, out: &mut dyn RecordSink) {
        self.emit_parts(ex.seq, ex.request, ex.response, out);
    }

    fn emit_parts(
        &self,
        seq: u32,
        request: Option<HttpRequest>,
        response: Option<HttpResponse>,
        out: &mut dyn RecordSink,
    ) {
        if request.is_none() && response.is_none() {
            return;
        }
        out.emit(Record::Http(Box::new(HttpTransaction {
            flow: self.id,
            client: self.key.client,
            server: self.key.server,
            seq,
            request,
            response,
        })));
    }

    /// End of the connection: open messages are finished, every exchange is emitted.
    fn end(&mut self, clean: bool, ts_ns: i64, sh: &mut Shared, out: &mut dyn RecordSink) {
        let at = ts_ns.min(self.last_ts);
        for dir in [Direction::ToServer, Direction::ToClient] {
            if let Phase::Body(_, msg) = self.phase_mut(dir) {
                msg.end_ts_ns = msg.end_ts_ns.max(at);
            }
            self.end_body(dir, clean, sh, out);
        }
        self.drain(true, out);
    }
}

#[cfg(test)]
mod tests;
