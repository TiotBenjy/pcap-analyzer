//! State machine of the `ftp` analyzer: control sessions, expected data connections, transfers.

use std::collections::{HashMap, VecDeque};
use std::fmt;

use netsift_dissect::Decoded;
use netsift_dissect::ftp::{
    parse_command, parse_eprt_arg, parse_epsv_reply, parse_pasv_reply, parse_port_arg, parse_reply,
};
use netsift_flow::{Direction, Endpoint, FlowCtx, FlowId, FlowKey, PacketCtx, StreamCtx};

use super::text::{Lines, clean, clean_block};
use super::{
    DataMode, FTP_PORT, FtpConfig, FtpLine, FtpRecord, FtpSession, FtpTransfer, LineKind, NOTE_GAP,
    NOTE_TLS, TransferDirection,
};
use crate::analyzer::{Analyzer, AnalyzerId, RecordSink};
use crate::record::Record;
use crate::registry::AnalyzerConfig;

/// Transcript lines stored per session.
pub const MAX_LINES: u32 = 2000;
/// Transcript text stored per session, in bytes.
pub const MAX_TRANSCRIPT_BYTES: usize = 256 * 1024;
/// Characters kept of a command argument or a reply text (one line is at most 1 024 bytes).
const MAX_TEXT: usize = 1024;
/// Characters kept of the banner and of the user name.
const MAX_SHORT: usize = 256;
/// Transfers recorded per session (later ones are counted only).
pub const MAX_TRANSFERS: u32 = 1000;
/// Transfers waiting for their reply or their data at a time, per session.
const MAX_OPEN_TRANSFERS: usize = 16;
/// Commands waiting for their final reply, per session.
const MAX_PENDING: usize = 32;
/// Bytes of a listing kept as text.
pub const LISTING_BYTES: usize = 4096;
/// Command verbs of RFC 959, 2228, 2389, 2428, 2640, 3659 and common `X` variants: after a
/// `331` (password required), a line that is not one of them is taken as the password itself.
const KNOWN_VERBS: &[&str] = &[
    "ABOR", "ACCT", "ADAT", "ALLO", "APPE", "AUTH", "CCC", "CDUP", "CLNT", "CONF", "CWD", "DELE",
    "ENC", "EPRT", "EPSV", "FEAT", "HELP", "HOST", "LANG", "LIST", "MDTM", "MIC", "MKD", "MLSD",
    "MLST", "MODE", "NLST", "NOOP", "OPTS", "PASS", "PASV", "PBSZ", "PORT", "PROT", "PWD", "QUIT",
    "REIN", "REST", "RETR", "RMD", "RNFR", "RNTO", "SITE", "SIZE", "SMNT", "STAT", "STOR", "STOU",
    "STRU", "SYST", "TYPE", "USER", "XCUP", "XCWD", "XMKD", "XPWD", "XRMD",
];

/// True for a line that starts like `PASS` or `ACCT` (any case), even when what follows is not
/// a well-formed argument: its text is a secret.
fn looks_secret(text: &str) -> bool {
    let head = text.trim_start().get(..4).unwrap_or_default();
    head.eq_ignore_ascii_case("PASS") || head.eq_ignore_ascii_case("ACCT")
}

/// Controls waiting for a data connection on one port, per shard.
const MAX_WAITERS_PER_PORT: usize = 64;

/// Which side of the control connection sent a line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Side {
    Client,
    Server,
}

const fn dir_index(dir: Direction) -> usize {
    match dir {
        Direction::ToServer => 0,
        Direction::ToClient => 1,
    }
}

/// What a command waits for in its final reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pending {
    User,
    Pass,
    Auth,
    Pasv { frame: u64 },
    Epsv { frame: u64 },
    Port,
    Rest(u64),
    Transfer(u32),
    Other,
}

/// An announced data connection expires after this long without being opened (packet time).
pub const EXPECT_TTL_NS: i64 = 60 * 1_000_000_000;

/// How a data connection was set up: the mode and the command seen (`PASV`, `EPSV`, `PORT`,
/// `EPRT`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Channel {
    mode: DataMode,
    command: &'static str,
}

/// Data connection announced and not opened yet. Its address is not kept: the data flow must
/// link the two addresses of the control, whatever the announced one (ADR-032).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Expect {
    port: u16,
    /// Frame of the command that asked for it: the data flow must be created after it.
    after_frame: u64,
    /// Time of the announcement (expiry).
    ts: i64,
    channel: Channel,
}

/// A paired data connection.
struct DataFlow {
    control: FlowId,
    id: FlowId,
    channel: Channel,
    /// Transfer it carries, once known.
    transfer: Option<u32>,
    /// Per flow direction (`ToServer`, `ToClient`).
    bytes: [u64; 2],
    buf: [Vec<u8>; 2],
    /// Bytes are missing from `buf` (lost segments, size or memory bound).
    truncated: [bool; 2],
    /// Bytes kept on purpose, below the object bound: listing preview, nothing for the direction
    /// that does not carry the transfer.
    limit: [Option<usize>; 2],
    last_ts: i64,
    ended: bool,
}

impl DataFlow {
    /// Index of the direction that carries data from the FTP server: the server opens the
    /// connection in active mode (flow client), the client in passive mode.
    const fn server_dir(&self) -> usize {
        match self.channel.mode {
            DataMode::Active => 0,
            DataMode::Passive => 1,
        }
    }

    fn retained(&self) -> usize {
        self.buf[0].len().saturating_add(self.buf[1].len())
    }
}

/// Where the data of a transfer is.
enum DataLink {
    None,
    Open(FlowId),
    Done(Box<DataFlow>),
}

struct Transfer {
    seq: u32,
    ts: i64,
    command: String,
    path: Option<String>,
    direction: TransferDirection,
    channel: Option<Channel>,
    restart_offset: Option<u64>,
    data: DataLink,
    status: Option<(u16, String)>,
    end_ts: Option<i64>,
}

impl Transfer {
    fn ready(&self) -> bool {
        self.status.is_some() && !matches!(self.data, DataLink::Open(_))
    }
}

/// A transcript line before its sequence number.
struct Entry {
    kind: LineKind,
    head: Option<String>,
    text: String,
    secret: bool,
    truncated: bool,
}

/// One control session. `Debug` shows no line content.
struct Control {
    id: FlowId,
    client: Endpoint,
    server: Endpoint,
    /// The flow key is reversed: its client side is the FTP server (flow picked up mid-stream).
    swapped: bool,
    client_lines: Lines,
    server_lines: Lines,
    seq: u32,
    stored_bytes: usize,
    transcript_truncated: bool,
    /// Code of the multi-line reply being read.
    multiline: Option<u16>,
    first_reply_text: Option<String>,
    pending: VecDeque<Pending>,
    expect: Option<Expect>,
    /// Data connection opened before its transfer command (passive mode).
    early_data: DataLink,
    transfers: Vec<Transfer>,
    next_transfer: u32,
    rest: Option<u64>,
    banner: Option<String>,
    username: Option<String>,
    login: Option<bool>,
    /// `AUTH` accepted: nothing more is read.
    tls: bool,
    /// Code of the last complete reply, until the next client line: after `331` / `332`
    /// (password required), that line may be the password itself.
    last_reply: Option<u16>,
    commands: u64,
    replies: u64,
    files: u64,
    listings: u64,
    bytes: u64,
    gaps: u32,
    /// Times of the control flow, once it ended.
    ended: Option<(i64, i64)>,
    last_ts: i64,
}

impl fmt::Debug for Control {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Control")
            .field("id", &self.id)
            .field("seq", &self.seq)
            .field("transfers", &self.transfers.len())
            .finish_non_exhaustive()
    }
}

impl Control {
    fn new(id: FlowId, key: &FlowKey) -> Self {
        let swapped = key.server.port != FTP_PORT && key.client.port == FTP_PORT;
        let (client, server) = if swapped {
            (key.server, key.client)
        } else {
            (key.client, key.server)
        };
        Self {
            id,
            client,
            server,
            swapped,
            client_lines: Lines::default(),
            server_lines: Lines::default(),
            seq: 0,
            stored_bytes: 0,
            transcript_truncated: false,
            multiline: None,
            first_reply_text: None,
            pending: VecDeque::new(),
            expect: None,
            early_data: DataLink::None,
            transfers: Vec::new(),
            next_transfer: 0,
            rest: None,
            banner: None,
            username: None,
            login: None,
            tls: false,
            last_reply: None,
            commands: 0,
            replies: 0,
            files: 0,
            listings: 0,
            bytes: 0,
            gaps: 0,
            ended: None,
            last_ts: 0,
        }
    }

    fn lines(&mut self, side: Side) -> &mut Lines {
        match side {
            Side::Client => &mut self.client_lines,
            Side::Server => &mut self.server_lines,
        }
    }

    fn side(&self, dir: Direction) -> Side {
        match (dir, self.swapped) {
            (Direction::ToServer, false) | (Direction::ToClient, true) => Side::Client,
            _ => Side::Server,
        }
    }

    /// True when the flow `id` / `key`, seen at `ts`, is the data connection this control waits
    /// for. It must link the same two addresses as the control: only that pair guarantees that
    /// both reach this shard whatever the number of shards (ADR-032). The announced address plays
    /// no part (NAT: a `227` may announce an internal address).
    fn accepts(&self, id: FlowId, key: &FlowKey, ts: i64) -> bool {
        let Some(e) = &self.expect else { return false };
        let after = u64::try_from(id.0).is_ok_and(|frame| frame > e.after_frame);
        let (a, b) = (key.client.ip, key.server.ip);
        let pair = (a == self.client.ip && b == self.server.ip)
            || (a == self.server.ip && b == self.client.ip);
        id != self.id
            && after
            && pair
            && key.server.port == e.port
            && ts.saturating_sub(e.ts) <= EXPECT_TTL_NS
    }

    fn push_line(&mut self, ts: i64, line: Entry, out: &mut dyn RecordSink) {
        let Entry {
            kind,
            head,
            text,
            secret,
            truncated,
        } = line;
        let size = text
            .len()
            .saturating_add(head.as_ref().map_or(0, String::len));
        if self.seq >= MAX_LINES || self.stored_bytes.saturating_add(size) > MAX_TRANSCRIPT_BYTES {
            self.transcript_truncated = true;
            return;
        }
        self.stored_bytes = self.stored_bytes.saturating_add(size);
        let seq = self.seq;
        self.seq = self.seq.saturating_add(1);
        out.emit(Record::Ftp(FtpRecord::Line(FtpLine {
            flow_id: self.id,
            seq,
            ts,
            kind,
            head,
            text,
            secret,
            truncated,
        })));
    }

    fn note(&mut self, ts: i64, note: &str, out: &mut dyn RecordSink) {
        let line = Entry {
            kind: LineKind::Note,
            head: None,
            text: note.to_owned(),
            secret: false,
            truncated: false,
        };
        self.push_line(ts, line, out);
    }

    fn queue(&mut self, p: Pending) {
        if self.pending.len() >= MAX_PENDING {
            self.pending.pop_front();
        }
        self.pending.push_back(p);
    }
}

/// See the module documentation of [`crate::ftp`].
pub struct FtpAnalyzer {
    config: FtpConfig,
    controls: HashMap<FlowId, Control>,
    /// Announced data ports -> controls waiting on them, in announcement order.
    expected: HashMap<u16, Vec<FlowId>>,
    data: HashMap<FlowId, DataFlow>,
}

impl fmt::Debug for FtpAnalyzer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FtpAnalyzer")
            .field("controls", &self.controls.len())
            .field("data", &self.data.len())
            .finish_non_exhaustive()
    }
}

impl FtpAnalyzer {
    pub const ID: AnalyzerId = AnalyzerId("ftp");

    pub fn new(config: &AnalyzerConfig) -> Self {
        Self {
            config: config.ftp.clone(),
            controls: HashMap::new(),
            expected: HashMap::new(),
            data: HashMap::new(),
        }
    }

    /// [`crate::registry::Factory`] of this analyzer.
    pub fn boxed(config: &AnalyzerConfig) -> Box<dyn Analyzer> {
        Box::new(Self::new(config))
    }

    fn is_control(key: &FlowKey) -> bool {
        key.proto == 6 && (key.server.port == FTP_PORT || key.client.port == FTP_PORT)
    }

    // ---- control connection ----------------------------------------------------------------

    fn control_stream(
        &mut self,
        ctx: &StreamCtx,
        dir: Direction,
        data: &[u8],
        out: &mut dyn RecordSink,
    ) {
        if !self.controls.contains_key(&ctx.id) {
            if self.controls.len() >= self.config.max_controls {
                return;
            }
            self.controls.insert(ctx.id, Control::new(ctx.id, &ctx.key));
        }
        let Some(mut control) = self.controls.remove(&ctx.id) else {
            return;
        };
        control.last_ts = control.last_ts.max(ctx.ts_ns);
        if !control.tls {
            let side = control.side(dir);
            if ctx.gap_before > 0 {
                control.gaps = control.gaps.saturating_add(1);
                control.lines(side).reset();
                if side == Side::Server {
                    control.multiline = None;
                }
                control.note(ctx.ts_ns, NOTE_GAP, out);
            }
            let mut lines: Vec<(Vec<u8>, bool)> = Vec::new();
            control
                .lines(side)
                .push(data, &mut |b, t| lines.push((b.to_vec(), t)));
            for (line, truncated) in lines {
                if control.tls {
                    break;
                }
                self.line(&mut control, side, ctx, &line, truncated, out);
            }
        }
        self.controls.insert(ctx.id, control);
    }

    fn line(
        &mut self,
        c: &mut Control,
        side: Side,
        ctx: &StreamCtx,
        line: &[u8],
        truncated: bool,
        out: &mut dyn RecordSink,
    ) {
        let (text, cut) = clean(line, MAX_TEXT);
        let truncated = truncated || cut;
        match side {
            Side::Client => self.command(c, ctx, &text, truncated, out),
            Side::Server => self.reply_line(c, ctx, &text, truncated, out),
        }
    }

    fn command(
        &mut self,
        c: &mut Control,
        ctx: &StreamCtx,
        text: &str,
        truncated: bool,
        out: &mut dyn RecordSink,
    ) {
        c.commands = c.commands.saturating_add(1);
        let ts = ctx.ts_ns;
        let after_331 = matches!(c.last_reply.take(), Some(331 | 332));
        let parsed = parse_command(text).filter(|cmd| {
            // A bare password sent after `331` may look like a verb (`hunter2`).
            !after_331 || KNOWN_VERBS.iter().any(|v| cmd.is(v))
        });
        let Some(cmd) = parsed else {
            let line = Entry {
                kind: LineKind::Command,
                head: None,
                text: text.to_owned(),
                secret: after_331 || looks_secret(text),
                truncated,
            };
            c.push_line(ts, line, out);
            c.queue(Pending::Other);
            return;
        };
        let verb = cmd.verb.to_ascii_uppercase();
        let secret = verb == "PASS" || verb == "ACCT";
        let line = Entry {
            kind: LineKind::Command,
            head: Some(verb.clone()),
            text: cmd.arg.to_owned(),
            secret,
            truncated,
        };
        c.push_line(ts, line, out);
        let pending = match verb.as_str() {
            "USER" => {
                let (user, _) = clean(cmd.arg.as_bytes(), MAX_SHORT);
                c.username = (!user.is_empty()).then_some(user);
                Pending::User
            }
            "PASS" => Pending::Pass,
            "AUTH" => Pending::Auth,
            "PASV" => Pending::Pasv { frame: ctx.frame },
            "EPSV" if !cmd.arg.eq_ignore_ascii_case("ALL") => Pending::Epsv { frame: ctx.frame },
            "PORT" | "EPRT" => {
                let addr = if verb == "PORT" {
                    parse_port_arg(cmd.arg)
                } else {
                    parse_eprt_arg(cmd.arg)
                };
                if let Some((_, port)) = addr {
                    let command = if verb == "PORT" { "PORT" } else { "EPRT" };
                    self.expect(
                        c,
                        Expect {
                            port,
                            after_frame: ctx.frame,
                            ts,
                            channel: Channel {
                                mode: DataMode::Active,
                                command,
                            },
                        },
                    );
                }
                Pending::Port
            }
            "REST" => cmd
                .arg
                .trim()
                .parse::<u64>()
                .map_or(Pending::Other, Pending::Rest),
            _ => match TransferDirection::of_verb(&verb) {
                Some(direction) => self.transfer_command(c, ts, &verb, cmd.arg, direction, out),
                None => Pending::Other,
            },
        };
        c.queue(pending);
    }

    fn transfer_command(
        &mut self,
        c: &mut Control,
        ts: i64,
        verb: &str,
        arg: &str,
        direction: TransferDirection,
        out: &mut dyn RecordSink,
    ) -> Pending {
        match direction {
            TransferDirection::Listing => c.listings = c.listings.saturating_add(1),
            _ => c.files = c.files.saturating_add(1),
        }
        let restart_offset = c.rest.take().filter(|r| *r > 0);
        if c.next_transfer >= MAX_TRANSFERS {
            return Pending::Other;
        }
        if c.transfers.len() >= MAX_OPEN_TRANSFERS {
            // A session that never answers: the oldest open transfer goes as it is.
            let oldest = c.transfers.remove(0);
            self.emit_transfer(c, oldest, out);
        }
        let seq = c.next_transfer;
        c.next_transfer = c.next_transfer.saturating_add(1);
        let (path, _) = clean(arg.as_bytes(), MAX_TEXT);
        let data = std::mem::replace(&mut c.early_data, DataLink::None);
        let channel = match &data {
            DataLink::Open(id) => self.data.get(id).map(|d| d.channel),
            DataLink::Done(d) => Some(d.channel),
            DataLink::None => c.expect.map(|e| e.channel),
        };
        match &data {
            DataLink::Open(id) => {
                if let Some(d) = self.data.get_mut(id) {
                    d.transfer = Some(seq);
                    cap(d, direction, &self.config);
                }
            }
            DataLink::Done(_) | DataLink::None => {}
        }
        let mut data = data;
        if let DataLink::Done(d) = &mut data {
            d.transfer = Some(seq);
        }
        c.transfers.push(Transfer {
            seq,
            ts,
            command: verb.to_owned(),
            path: (!path.is_empty()).then_some(path),
            direction,
            channel,
            restart_offset,
            data,
            status: None,
            end_ts: None,
        });
        Pending::Transfer(seq)
    }

    fn reply_line(
        &mut self,
        c: &mut Control,
        ctx: &StreamCtx,
        text: &str,
        truncated: bool,
        out: &mut dyn RecordSink,
    ) {
        let ts = ctx.ts_ns;
        let parsed = parse_reply(text);
        let head = parsed.map(|r| format!("{}{}", r.code, if r.more { "-" } else { "" }));
        let body = parsed.map_or(text, |r| r.text).to_owned();
        let line = Entry {
            kind: LineKind::Reply,
            head,
            text: body,
            secret: false,
            truncated,
        };
        c.push_line(ts, line, out);
        let Some(reply) = parsed else { return };
        match c.multiline {
            Some(code) if code == reply.code && !reply.more => {
                c.multiline = None;
                let first = c.first_reply_text.take();
                self.reply(
                    c,
                    ts,
                    reply.code,
                    first.as_deref().unwrap_or(reply.text),
                    out,
                );
            }
            Some(_) => {}
            None if reply.more => {
                c.multiline = Some(reply.code);
                c.first_reply_text = Some(reply.text.to_owned());
            }
            None => self.reply(c, ts, reply.code, reply.text, out),
        }
    }

    /// A complete reply.
    fn reply(&mut self, c: &mut Control, ts: i64, code: u16, text: &str, out: &mut dyn RecordSink) {
        c.replies = c.replies.saturating_add(1);
        if code == 220 && c.banner.is_none() {
            let (banner, _) = clean(text.as_bytes(), MAX_SHORT);
            c.banner = Some(banner);
        }
        c.last_reply = Some(code);
        if code < 200 {
            // Preliminary: the transfer at the front keeps waiting for its final reply.
            return;
        }
        let Some(pending) = c.pending.pop_front() else {
            return;
        };
        let ok = (200..400).contains(&code);
        match pending {
            Pending::User => {
                if code == 230 {
                    c.login = Some(true);
                } else if code >= 400 {
                    c.login = Some(false);
                }
            }
            Pending::Pass => {
                if (200..300).contains(&code) {
                    c.login = Some(true);
                } else if code >= 400 {
                    c.login = Some(false);
                }
            }
            Pending::Auth if code == 234 => {
                c.tls = true;
                c.note(ts, NOTE_TLS, out);
                self.unexpect(c);
            }
            Pending::Pasv { frame } if code == 227 => {
                if let Some((_, port)) = parse_pasv_reply(text) {
                    let e = Expect {
                        port,
                        after_frame: frame,
                        ts,
                        channel: Channel {
                            mode: DataMode::Passive,
                            command: "PASV",
                        },
                    };
                    self.expect(c, e);
                }
            }
            Pending::Epsv { frame } if code == 229 => {
                if let Some(port) = parse_epsv_reply(text) {
                    let e = Expect {
                        port,
                        after_frame: frame,
                        ts,
                        channel: Channel {
                            mode: DataMode::Passive,
                            command: "EPSV",
                        },
                    };
                    self.expect(c, e);
                }
            }
            Pending::Port if !ok => self.unexpect(c),
            Pending::Rest(offset) => c.rest = (code == 350).then_some(offset),
            Pending::Transfer(seq) => {
                // The transfer is over: an announced connection never opened is dropped, never
                // given to a later transfer.
                self.unexpect(c);
                let (status, _) = clean(text.as_bytes(), MAX_SHORT);
                if let Some(i) = c.transfers.iter().position(|t| t.seq == seq) {
                    let ready = {
                        let Some(t) = c.transfers.get_mut(i) else {
                            return;
                        };
                        t.status = Some((code, status));
                        t.end_ts = Some(t.end_ts.map_or(ts, |e| e.max(ts)));
                        t.ready()
                    };
                    if ready {
                        let t = c.transfers.remove(i);
                        self.emit_transfer(c, t, out);
                    }
                }
            }
            Pending::Auth
            | Pending::Pasv { .. }
            | Pending::Epsv { .. }
            | Pending::Port
            | Pending::Other => {}
        }
    }

    /// Records the data connection `c` now waits for (replacing the previous one). A data
    /// connection opened early for the previous announcement and never claimed is dropped: it
    /// must not go to the next transfer.
    fn expect(&mut self, c: &mut Control, e: Expect) {
        self.unexpect(c);
        let early = std::mem::replace(&mut c.early_data, DataLink::None);
        self.drop_link(early);
        let waiters = self.expected.entry(e.port).or_default();
        if waiters.len() >= MAX_WAITERS_PER_PORT {
            return;
        }
        waiters.push(c.id);
        c.expect = Some(e);
    }

    fn unexpect(&mut self, c: &mut Control) {
        if let Some(old) = c.expect.take()
            && let Some(waiters) = self.expected.get_mut(&old.port)
        {
            waiters.retain(|id| *id != c.id);
            if waiters.is_empty() {
                self.expected.remove(&old.port);
            }
        }
    }

    // ---- data connections ------------------------------------------------------------------

    /// Pairs a new flow with the control waiting for it, if any.
    fn pair(&mut self, id: FlowId, key: &FlowKey, ts: i64) -> bool {
        if key.proto != 6 || self.data.len() >= self.config.max_data_flows {
            return false;
        }
        let Some(waiters) = self.expected.get(&key.server.port) else {
            return false;
        };
        let Some(control_id) = waiters.iter().copied().find(|cid| {
            self.controls
                .get(cid)
                .is_some_and(|c| c.accepts(id, key, ts))
        }) else {
            return false;
        };
        let Some(mut c) = self.controls.remove(&control_id) else {
            return false;
        };
        let channel = c.expect.map_or(
            Channel {
                mode: DataMode::Passive,
                command: "PASV",
            },
            |e| e.channel,
        );
        self.unexpect(&mut c);
        let mut flow = DataFlow {
            control: control_id,
            id,
            channel,
            transfer: None,
            bytes: [0, 0],
            buf: [Vec::new(), Vec::new()],
            truncated: [false, false],
            limit: [None, None],
            last_ts: ts,
            ended: false,
        };
        // The latest transfer still without data and without final reply takes it; otherwise
        // it waits for the next transfer command (passive clients connect first).
        if let Some(t) = c
            .transfers
            .iter_mut()
            .rev()
            .find(|t| matches!(t.data, DataLink::None) && t.status.is_none())
        {
            t.data = DataLink::Open(id);
            t.channel = Some(channel);
            flow.transfer = Some(t.seq);
            cap(&mut flow, t.direction, &self.config);
        } else {
            let old = std::mem::replace(&mut c.early_data, DataLink::Open(id));
            self.drop_link(old);
        }
        self.data.insert(id, flow);
        self.controls.insert(control_id, c);
        true
    }

    fn data_stream(&mut self, ctx: &StreamCtx, dir: Direction, data: &[u8]) {
        let Some(flow) = self.data.get_mut(&ctx.id) else {
            return;
        };
        flow.last_ts = flow.last_ts.max(ctx.ts_ns);
        let d = dir_index(dir);
        let len = u64::try_from(data.len()).unwrap_or(u64::MAX);
        if let (Some(bytes), Some(buf), Some(truncated), Some(limit)) = (
            flow.bytes.get_mut(d),
            flow.buf.get_mut(d),
            flow.truncated.get_mut(d),
            flow.limit.get(d).copied(),
        ) {
            *bytes = bytes.saturating_add(len);
            if ctx.gap_before > 0 && !*truncated {
                *truncated = true;
                self.config.budget.give_back(buf.len());
                *buf = Vec::new();
            }
            if *truncated {
                return;
            }
            if let Some(limit) = limit {
                // Listing preview or other direction: keep the first bytes only.
                let take = limit.saturating_sub(buf.len()).min(data.len());
                if take > 0 && self.config.budget.take(take) {
                    buf.extend_from_slice(data.get(..take).unwrap_or_default());
                }
                return;
            }
            let fits = buf.len().saturating_add(data.len()) <= self.config.object_max_bytes;
            if fits && self.config.budget.take(data.len()) {
                buf.extend_from_slice(data);
            } else {
                *truncated = true;
                self.config.budget.give_back(buf.len());
                *buf = Vec::new();
            }
        }
    }

    fn data_end(&mut self, id: FlowId, end_ts: i64, out: &mut dyn RecordSink) {
        let Some(mut flow) = self.data.remove(&id) else {
            return;
        };
        flow.ended = true;
        flow.last_ts = flow.last_ts.max(end_ts);
        let Some(mut c) = self.controls.remove(&flow.control) else {
            self.release(&flow);
            return;
        };
        c.last_ts = c.last_ts.max(flow.last_ts);
        let seq = flow.transfer;
        match seq.and_then(|s| c.transfers.iter().position(|t| t.seq == s)) {
            Some(i) => {
                let ready = c.transfers.get_mut(i).is_some_and(|t| {
                    t.end_ts = Some(t.end_ts.map_or(flow.last_ts, |e| e.max(flow.last_ts)));
                    t.data = DataLink::Done(Box::new(flow));
                    t.ready()
                });
                if ready {
                    let t = c.transfers.remove(i);
                    self.emit_transfer(&mut c, t, out);
                }
            }
            None => match &c.early_data {
                DataLink::Open(open) if *open == id => {
                    c.early_data = DataLink::Done(Box::new(flow));
                }
                _ => self.release(&flow),
            },
        }
        self.finish_control(c, out);
    }

    /// Gives the memory of a data connection back to the shared budget.
    fn release(&self, flow: &DataFlow) {
        self.config.budget.give_back(flow.retained());
    }

    fn drop_link(&mut self, link: DataLink) {
        match link {
            DataLink::None => {}
            DataLink::Open(id) => {
                if let Some(flow) = self.data.remove(&id) {
                    self.release(&flow);
                }
            }
            DataLink::Done(flow) => self.release(&flow),
        }
    }

    // ---- emission --------------------------------------------------------------------------

    fn emit_transfer(&mut self, c: &mut Control, t: Transfer, out: &mut dyn RecordSink) {
        let mut record = FtpTransfer {
            flow_id: c.id,
            seq: t.seq,
            ts: t.ts,
            end_ts: t.end_ts,
            command: t.command,
            path: t.path,
            direction: t.direction,
            mode: t.channel.map(|ch| ch.mode),
            mode_command: t.channel.map(|ch| ch.command),
            data_flow: None,
            status: t.status.as_ref().map(|(code, _)| *code),
            status_text: t.status.map(|(_, text)| text),
            bytes: 0,
            restart_offset: t.restart_offset,
            truncated: false,
            object: None,
            mime: None,
            listing: None,
        };
        match t.data {
            DataLink::Done(flow) => {
                Self::fill(&mut record, &flow, out);
                self.release(&flow);
            }
            DataLink::Open(id) => {
                // The control ended first: what the data connection carried so far.
                if let Some(flow) = self.data.remove(&id) {
                    Self::fill(&mut record, &flow, out);
                    record.truncated = true;
                    self.release(&flow);
                }
            }
            DataLink::None => {}
        }
        c.bytes = c.bytes.saturating_add(record.bytes);
        out.emit(Record::Ftp(FtpRecord::Transfer(Box::new(record))));
    }

    /// Size and content of a transfer from its data connection.
    fn fill(record: &mut FtpTransfer, flow: &DataFlow, out: &mut dyn RecordSink) {
        let from_server = flow.server_dir();
        let d = match record.direction {
            TransferDirection::Upload => 1usize.saturating_sub(from_server),
            TransferDirection::Download | TransferDirection::Listing => from_server,
        };
        let bytes = flow.bytes.get(d).copied().unwrap_or(0);
        let buf = flow.buf.get(d).map_or(&[][..], Vec::as_slice);
        let truncated = flow.truncated.get(d).copied().unwrap_or(true);
        record.data_flow = Some(flow.id);
        record.bytes = bytes;
        record.truncated = truncated;
        if record.direction == TransferDirection::Listing {
            if !buf.is_empty() {
                record.listing = Some(clean_block(buf, LISTING_BYTES));
            }
            return;
        }
        let complete = record.status.is_some_and(|s| (200..300).contains(&s))
            && flow.ended
            && !truncated
            && record.restart_offset.is_none()
            && bytes > 0
            && u64::try_from(buf.len()).is_ok_and(|n| n == bytes);
        if complete && let Some(blob) = out.put_object(buf) {
            record.object = Some(blob);
            record.mime = Some(
                crate::http::inspect::sniff_mime(buf)
                    .unwrap_or("application/octet-stream")
                    .to_owned(),
            );
        }
    }

    /// Emits the session once its control flow ended and no transfer waits for its data.
    fn finish_control(&mut self, mut c: Control, out: &mut dyn RecordSink) {
        let Some((first_ts, last_ts)) = c.ended else {
            self.controls.insert(c.id, c);
            return;
        };
        // Transfers whose data is done (or absent) go now; the others wait for their data.
        let mut i = 0;
        while i < c.transfers.len() {
            if c.transfers
                .get(i)
                .is_some_and(|t| !matches!(t.data, DataLink::Open(_)))
            {
                let t = c.transfers.remove(i);
                self.emit_transfer(&mut c, t, out);
            } else {
                i = i.saturating_add(1);
            }
        }
        if !c.transfers.is_empty() {
            self.controls.insert(c.id, c);
            return;
        }
        let early = std::mem::replace(&mut c.early_data, DataLink::None);
        self.drop_link(early);
        self.unexpect(&mut c);
        out.emit(Record::Ftp(FtpRecord::Session(Box::new(FtpSession {
            flow_id: c.id,
            client: c.client,
            server: c.server,
            first_ts,
            last_ts: last_ts.max(c.last_ts),
            banner: c.banner,
            username: c.username,
            login: c.login,
            tls: c.tls,
            commands: c.commands,
            replies: c.replies,
            files: c.files,
            listings: c.listings,
            bytes: c.bytes,
            lines: c.seq,
            transcript_truncated: c.transcript_truncated,
            gaps: c.gaps,
        }))));
    }

    fn control_end(&mut self, ctx: &FlowCtx, out: &mut dyn RecordSink) {
        let Some(mut c) = self.controls.remove(&ctx.id) else {
            return;
        };
        if !c.tls {
            // Last lines without terminator.
            for side in [Side::Client, Side::Server] {
                let mut lines: Vec<(Vec<u8>, bool)> = Vec::new();
                c.lines(side).flush(&mut |b, t| lines.push((b.to_vec(), t)));
                let stream = StreamCtx {
                    ts_ns: ctx.last_ts_ns,
                    chunk_id: 0,
                    frame: u64::MAX,
                    id: ctx.id,
                    key: ctx.key,
                    gap_before: 0,
                };
                for (line, truncated) in lines {
                    if !c.tls {
                        self.line(&mut c, side, &stream, &line, truncated, out);
                    }
                }
            }
        }
        c.ended = Some((ctx.first_ts_ns, ctx.last_ts_ns));
        c.last_ts = c.last_ts.max(ctx.last_ts_ns);
        self.unexpect(&mut c);
        self.finish_control(c, out);
    }
}

/// Retention of a data connection once its transfer is known: a listing keeps its preview, the
/// direction that does not carry the transfer keeps nothing.
fn cap(flow: &mut DataFlow, direction: TransferDirection, config: &FtpConfig) {
    let from_server = flow.server_dir();
    let payload = match direction {
        TransferDirection::Upload => 1usize.saturating_sub(from_server),
        TransferDirection::Download | TransferDirection::Listing => from_server,
    };
    for d in 0..2 {
        let (Some(buf), Some(limit)) = (flow.buf.get_mut(d), flow.limit.get_mut(d)) else {
            continue;
        };
        let keep = if d != payload {
            0
        } else if direction == TransferDirection::Listing {
            LISTING_BYTES
        } else {
            continue;
        };
        *limit = Some(keep);
        if buf.len() > keep {
            config.budget.give_back(buf.len().saturating_sub(keep));
            buf.truncate(keep);
            buf.shrink_to_fit();
        }
    }
}

impl Analyzer for FtpAnalyzer {
    fn id(&self) -> AnalyzerId {
        Self::ID
    }

    /// Pairs a data connection at its first packet (its SYN), before any data and even when it
    /// carries none (empty file); `on_stream` and `on_flow_end` try again for flows picked up
    /// later.
    fn on_packet(&mut self, ctx: &PacketCtx, _pkt: &Decoded<'_>, _out: &mut dyn RecordSink) {
        if self.expected.is_empty() {
            return;
        }
        if let Some(flow) = ctx.flow
            && !self.data.contains_key(&flow.id)
            && !Self::is_control(&flow.key)
        {
            self.pair(flow.id, &flow.key, ctx.ts_ns);
        }
    }

    fn on_stream(
        &mut self,
        ctx: &StreamCtx,
        dir: Direction,
        data: &[u8],
        out: &mut dyn RecordSink,
    ) {
        if Self::is_control(&ctx.key) {
            self.control_stream(ctx, dir, data, out);
            return;
        }
        if !self.data.contains_key(&ctx.id)
            && (self.expected.is_empty() || !self.pair(ctx.id, &ctx.key, ctx.ts_ns))
        {
            return;
        }
        self.data_stream(ctx, dir, data);
    }

    fn on_flow_end(&mut self, ctx: &FlowCtx, out: &mut dyn RecordSink) {
        if self.controls.contains_key(&ctx.id) {
            self.control_end(ctx, out);
            return;
        }
        if self.data.contains_key(&ctx.id)
            || (!self.expected.is_empty()
                && !Self::is_control(&ctx.key)
                && self.pair(ctx.id, &ctx.key, ctx.first_ts_ns))
        {
            self.data_end(ctx.id, ctx.last_ts_ns, out);
        }
    }

    fn finish(&mut self, out: &mut dyn RecordSink) {
        // Every flow ended before `finish`: only sessions waiting on nothing are left, in a
        // deterministic order.
        let mut open: Vec<FlowId> = self.data.keys().copied().collect();
        open.sort_unstable();
        for id in open {
            let ts = self.data.get(&id).map_or(0, |d| d.last_ts);
            self.data_end(id, ts, out);
        }
        let mut ids: Vec<FlowId> = self.controls.keys().copied().collect();
        ids.sort_unstable();
        for id in ids {
            let Some(mut c) = self.controls.remove(&id) else {
                continue;
            };
            if c.ended.is_none() {
                c.ended = Some((c.last_ts, c.last_ts));
            }
            let transfers = std::mem::take(&mut c.transfers);
            for t in transfers {
                self.emit_transfer(&mut c, t, out);
            }
            self.finish_control(c, out);
        }
    }
}
