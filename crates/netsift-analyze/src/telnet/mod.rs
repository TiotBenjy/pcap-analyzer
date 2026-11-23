//! The `telnet` analyzer (`docs/specs/telnet.md`): one [`TelnetSession`] per TCP connection on
//! port 23 or 2323 that carried data, with its display transcript, a summary of the negotiated
//! options, and the logins typed at the server's prompts as [`Record::Credential`]s.
//!
//! - [`netsift_dissect::telnet`] removes the `IAC` layer (one decoder per direction);
//! - [`transcript`]: NVT normalization, echo merging, bounded transcript;
//! - [`login`]: user name / password prompts and their result.
//!
//! Memory is bounded per session (transcript, echo queue, login buffers) and per shard: at most
//! [`SHARD_BUDGET`] bytes of transcripts are held by the sessions in progress of one shard.

mod login;
mod transcript;

use std::collections::HashMap;
use std::fmt;

use netsift_dissect::telnet::{self as wire, Decoder, Event, Verb};
use netsift_flow::{Direction, Endpoint, FlowCtx, FlowId, FlowKey, StreamCtx};

use crate::analyzer::{Analyzer, AnalyzerId, RecordSink};
use crate::record::Record;
use crate::registry::AnalyzerConfig;
pub use login::LoginResult;
use transcript::{Echo, Nvt, Token, Transcript};
pub use transcript::{MAX_BYTES, MAX_LINES};

/// Server ports recognized as Telnet.
pub const PORTS: [u16; 2] = [23, 2323];
/// Transcript bytes held at once by the sessions in progress of one shard.
pub const SHARD_BUDGET: usize = 32 * 1024 * 1024;

/// Who produced a run of the transcript.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Speaker {
    /// Typed by the client (echo merged).
    Client,
    /// Output of the server.
    Server,
    /// Typed by the client at a password prompt (sensitive).
    Secret,
}

impl Speaker {
    /// Stable label (`client`, `server`, `secret`).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::Server => "server",
            Self::Secret => "secret",
        }
    }
}

/// One run of text of a single speaker. `Debug` hides the text of a secret run.
#[derive(Clone, PartialEq, Eq)]
pub struct TranscriptRun {
    pub speaker: Speaker,
    pub text: String,
}

impl fmt::Debug for TranscriptRun {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text: &dyn fmt::Debug = if self.speaker == Speaker::Secret {
            &"<redacted>"
        } else {
            &self.text
        };
        f.debug_struct("TranscriptRun")
            .field("speaker", &self.speaker)
            .field("text", text)
            .finish()
    }
}

/// A Telnet connection (`telnet_sessions`). `Debug` shows the transcript size only.
#[derive(Clone, PartialEq, Eq)]
pub struct TelnetSession {
    pub flow_id: FlowId,
    pub client: Endpoint,
    pub server: Endpoint,
    pub first_ts: i64,
    pub last_ts: i64,
    /// Wire bytes sent by the client and by the server.
    pub client_bytes: u64,
    pub server_bytes: u64,
    /// User of the accepted login, else of the last attempt, else `USER` of `NEW-ENVIRON`.
    pub username: Option<String>,
    /// `USER` variable sent by the client (`NEW-ENVIRON`).
    pub env_user: Option<String>,
    pub login: Option<LoginResult>,
    /// Passwords typed.
    pub login_attempts: u32,
    /// First terminal type sent by the client (`TTYPE IS`).
    pub terminal: Option<String>,
    /// Last window size sent by the client (`NAWS`): (columns, rows).
    pub window: Option<(u16, u16)>,
    /// Options offered by one side and accepted by the other, by code.
    pub options: Vec<String>,
    pub transcript: Vec<TranscriptRun>,
    /// Bytes (UTF-8 text of the runs) and lines of the transcript.
    pub transcript_bytes: u64,
    pub transcript_lines: u32,
    pub truncated: bool,
}

impl fmt::Debug for TelnetSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TelnetSession")
            .field("flow_id", &self.flow_id)
            .field("client", &self.client)
            .field("server", &self.server)
            .field("login", &self.login)
            .field("login_attempts", &self.login_attempts)
            .field("options", &self.options)
            .field("transcript_bytes", &self.transcript_bytes)
            .field("truncated", &self.truncated)
            .finish_non_exhaustive()
    }
}

/// 256-bit set of option codes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Options([u64; 4]);

impl Options {
    fn insert(&mut self, code: u8) {
        if let Some(word) = self.0.get_mut(usize::from(code >> 6)) {
            *word |= 1 << (code & 63);
        }
    }

    fn and(self, other: Self) -> Self {
        let mut out = self;
        for (a, b) in out.0.iter_mut().zip(other.0) {
            *a &= b;
        }
        out
    }

    fn or(self, other: Self) -> Self {
        let mut out = self;
        for (a, b) in out.0.iter_mut().zip(other.0) {
            *a |= b;
        }
        out
    }

    fn codes(self) -> impl Iterator<Item = u8> {
        (0..=u8::MAX).filter(move |c| {
            self.0
                .get(usize::from(c >> 6))
                .is_some_and(|w| w & (1 << (c & 63)) != 0)
        })
    }
}

/// What the client typed on its current line, for the missing-echo password heuristic.
#[derive(Debug, Clone, Copy, Default)]
struct Line {
    /// Offset in the transcript of the first character typed.
    start: Option<usize>,
    chars: usize,
    /// Characters of the line echoed by the server.
    echoed: usize,
    /// Client segments that carried characters of the line.
    segments: u32,
    /// The server sent something (not an echo) while the line was typed.
    server_spoke: bool,
}

/// A line typed without echo, waiting for the server's answer: a password unless that answer
/// starts with its echo.
#[derive(Debug, Clone, Copy)]
struct Suspect {
    /// Transcript range of the typed text (before its line end).
    start: usize,
    end: usize,
    /// Bytes of the line already seen again in the server's answer.
    matched: usize,
}

/// State of one session except the two `IAC` decoders (borrowed separately while they feed).
/// `Debug` shows no user name nor text.
struct Session {
    id: FlowId,
    /// Oriented key: `client` is the Telnet client.
    key: FlowKey,
    first_ts: i64,
    last_ts: i64,
    nvt: [Nvt; 2],
    /// `WILL` / `DO` sent, per side (0 client, 1 server).
    will: [Options; 2],
    do_: [Options; 2],
    terminal: Option<String>,
    window: Option<(u16, u16)>,
    env_user: Option<String>,
    echo: Echo,
    /// The server announced `WILL ECHO` (and not `WONT ECHO` since).
    server_echo: bool,
    line: Line,
    suspect: Option<Suspect>,
    /// The next client character starts a new segment.
    new_segment: bool,
    transcript: Transcript,
    login: login::Login,
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("id", &self.id)
            .field("key", &self.key)
            .field("server_echo", &self.server_echo)
            .field("echo", &self.echo)
            .field("transcript", &self.transcript)
            .field("login", &self.login)
            .finish_non_exhaustive()
    }
}

const CLIENT: usize = 0;
const SERVER: usize = 1;

#[derive(Debug)]
struct Flow {
    /// The flow key's client is the Telnet server (connection picked up in the middle).
    swapped: bool,
    decoders: [Decoder; 2],
    session: Session,
}

impl Session {
    fn event(
        &mut self,
        side: usize,
        event: Event<'_>,
        ts: i64,
        budget: &mut usize,
        out: &mut dyn RecordSink,
    ) {
        match event {
            Event::Data(bytes) => {
                let Some(slot) = self.nvt.get_mut(side) else {
                    return;
                };
                let mut nvt = std::mem::take(slot);
                for &b in bytes {
                    nvt.push(b, side == CLIENT, &mut |t| {
                        self.token(side, t, ts, budget, out);
                    });
                }
                if let Some(slot) = self.nvt.get_mut(side) {
                    *slot = nvt;
                }
            }
            Event::Command(wire::EC) => self.token(side, Token::Erase, ts, budget, out),
            Event::Command(wire::EL) => self.token(side, Token::EraseLine, ts, budget, out),
            Event::Command(_) => {}
            Event::Negotiation { verb, option } => {
                if side == SERVER && option == wire::opt::ECHO {
                    match verb {
                        Verb::Will => self.server_echo = true,
                        Verb::Wont => self.server_echo = false,
                        Verb::Do | Verb::Dont => {}
                    }
                }
                let set = match verb {
                    Verb::Will => self.will.get_mut(side),
                    Verb::Do => self.do_.get_mut(side),
                    Verb::Wont | Verb::Dont => None,
                };
                if let Some(set) = set {
                    set.insert(option);
                }
            }
            Event::Subnegotiation { option, data, .. } => {
                if side == CLIENT {
                    self.client_subnegotiation(option, data);
                }
            }
        }
    }

    fn client_subnegotiation(&mut self, option: u8, data: &[u8]) {
        match option {
            wire::opt::TTYPE => {
                if let Some(wire::Ttype::Is(name)) = wire::parse_ttype(data)
                    && !name.is_empty()
                    && self.terminal.is_none()
                {
                    self.terminal = Some(name);
                }
            }
            wire::opt::NAWS => {
                if let Some(size) = wire::parse_naws(data) {
                    self.window = Some(size);
                }
            }
            wire::opt::NEW_ENVIRON => {
                let Some(env) = wire::parse_environ(data) else {
                    return;
                };
                if env.kind == wire::EnvKind::Send {
                    return;
                }
                if let Some(user) = env
                    .vars
                    .into_iter()
                    .find(|v| !v.user_var && v.name == "USER")
                    .and_then(|v| v.value)
                    .filter(|v| !v.is_empty())
                {
                    self.env_user = Some(user);
                }
            }
            _ => {}
        }
    }

    fn token(
        &mut self,
        side: usize,
        token: Token,
        ts: i64,
        budget: &mut usize,
        out: &mut dyn RecordSink,
    ) {
        if side == CLIENT {
            match token {
                Token::Char(_) => {
                    self.line.start.get_or_insert(self.transcript.len());
                    self.line.chars = self.line.chars.saturating_add(1);
                    if self.new_segment {
                        self.new_segment = false;
                        self.line.segments = self.line.segments.saturating_add(1);
                    }
                }
                // Typed key by key to a server that echoes, without one key echoed nor anything
                // else from the server: a password whatever the prompt (unknown language, prompt
                // missing from the capture), unless the server's answer is its (late) echo.
                Token::Newline
                    if self.server_echo
                        && self.line.chars > 0
                        && self.line.echoed == 0
                        && !self.line.server_spoke
                        && self.line.segments >= 2
                        // One suspect at a time: later lines are read as typed until it is judged.
                        && self.suspect.is_none() =>
                {
                    self.login.defer_line();
                    self.suspect = self.line.start.map(|start| Suspect {
                        start,
                        end: self.transcript.len(),
                        matched: 0,
                    });
                }
                _ => {}
            }
            let secret = self.login.client(token, ts, self.env_user.as_deref(), out);
            self.echo.typed(token, secret);
            let speaker = if secret {
                Speaker::Secret
            } else {
                Speaker::Client
            };
            self.transcript.apply(speaker, token, budget);
            match token {
                Token::Newline => self.line = Line::default(),
                Token::Erase | Token::EraseLine | Token::EraseWord => {
                    // Erased below the first key typed: the line now starts where the text ends.
                    if let Some(start) = self.line.start.as_mut() {
                        *start = (*start).min(self.transcript.len());
                    }
                }
                Token::Char(_) => {}
            }
        } else {
            self.judge_suspect(token, ts, out);
            if self.echo.absorbs(token) {
                // An echo absorbed after the line end belongs to no line being typed.
                if matches!(token, Token::Char(_)) && self.line.start.is_some() {
                    self.line.echoed = self.line.echoed.saturating_add(1);
                }
                return;
            }
            if self.line.start.is_some() {
                self.line.server_spoke = true;
            }
            self.login.server(token, out);
            self.transcript.apply(Speaker::Server, token, budget);
        }
    }

    /// Compares the server's answer with the suspect line: its echo dismisses it, anything else
    /// makes it a password (masked in the transcript, credential emitted).
    fn judge_suspect(&mut self, token: Token, ts: i64, out: &mut dyn RecordSink) {
        let Some(mut suspect) = self.suspect else {
            return;
        };
        let Some(line) = self.login.suspect_bytes() else {
            self.suspect = None;
            return;
        };
        let echoed = match token {
            Token::Char(c) => line.get(suspect.matched) == Some(&c),
            _ => false,
        };
        if echoed {
            suspect.matched = suspect.matched.saturating_add(1);
            if suspect.matched >= line.len() {
                self.suspect = None;
                self.login.dismiss_suspect();
            } else {
                self.suspect = Some(suspect);
            }
        } else if suspect.matched > 0 {
            // Its beginning came back: echoed (then something else).
            self.suspect = None;
            self.login.dismiss_suspect();
        } else {
            self.suspect = None;
            // Its keys are not expected back any more: the line end can still match.
            self.echo.secret_pending();
            self.transcript.relabel_secret(suspect.start, suspect.end);
            self.login
                .confirm_suspect(ts, self.env_user.as_deref(), out);
        }
    }

    /// Bytes are missing in one direction: partial state is dropped.
    fn gap(&mut self, side: usize) {
        if let Some(nvt) = self.nvt.get_mut(side) {
            nvt.reset();
        }
        self.echo.clear();
        self.login.reset(side == CLIENT);
        if side == CLIENT {
            self.line = Line::default();
        }
    }

    fn options(&self) -> Vec<String> {
        let [cw, sw] = self.will;
        let [cd, sd] = self.do_;
        sw.and(cd)
            .or(cw.and(sd))
            .codes()
            .map(|c| wire::option_name(c).map_or_else(|| c.to_string(), str::to_owned))
            .collect()
    }

    fn finish(mut self, bytes: Option<(u64, u64)>, out: &mut dyn RecordSink) -> usize {
        // A suspect line never answered: masked, without credential.
        if let Some(suspect) = self.suspect.take() {
            self.transcript.relabel_secret(suspect.start, suspect.end);
            self.login.drop_suspect();
        }
        self.login.end(out);
        let options = self.options();
        let login = self.login.result();
        let username = self
            .login
            .accepted_user
            .take()
            .or_else(|| self.login.last_user.take())
            .or_else(|| self.env_user.clone());
        let charged = self.transcript.charged;
        let transcript_lines = self.transcript.lines();
        let truncated = self.transcript.truncated();
        let (client_bytes, server_bytes) = bytes.unwrap_or_default();
        let transcript = self.transcript.into_runs();
        let transcript_bytes = transcript
            .iter()
            .map(|r| u64::try_from(r.text.len()).unwrap_or(u64::MAX))
            .fold(0, u64::saturating_add);
        out.emit(Record::Telnet(Box::new(TelnetSession {
            flow_id: self.id,
            client: self.key.client,
            server: self.key.server,
            first_ts: self.first_ts,
            last_ts: self.last_ts,
            client_bytes,
            server_bytes,
            username,
            env_user: self.env_user,
            login,
            login_attempts: self.login.attempts,
            terminal: self.terminal,
            window: self.window,
            options,
            transcript,
            transcript_bytes,
            transcript_lines,
            truncated,
        })));
        charged
    }
}

/// The `telnet` analyzer (one instance per shard). `Debug` shows counts only.
#[derive(Default)]
pub struct TelnetAnalyzer {
    /// `None`: a TCP flow on another port (ignored).
    flows: HashMap<FlowId, Option<Flow>>,
    /// Transcript bytes still allowed for the sessions in progress.
    budget: usize,
}

impl fmt::Debug for TelnetAnalyzer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TelnetAnalyzer")
            .field("flows", &self.flows.len())
            .field("budget", &self.budget)
            .finish()
    }
}

impl TelnetAnalyzer {
    pub const ID: AnalyzerId = AnalyzerId("telnet");

    pub fn new(_config: &AnalyzerConfig) -> Self {
        Self {
            flows: HashMap::new(),
            budget: SHARD_BUDGET,
        }
    }

    /// [`crate::registry::Factory`] of this analyzer.
    pub fn boxed(config: &AnalyzerConfig) -> Box<dyn Analyzer> {
        Box::new(Self::new(config))
    }

    fn end(&mut self, flow: Flow, bytes: Option<(u64, u64)>, out: &mut dyn RecordSink) {
        let charged = flow.session.finish(bytes, out);
        self.budget = self.budget.saturating_add(charged).min(SHARD_BUDGET);
    }
}

/// A new session when one end of `key` is a Telnet port (the server side first).
fn open(ctx: &StreamCtx) -> Option<Flow> {
    let key = ctx.key;
    let (swapped, oriented) = if PORTS.contains(&key.server.port) {
        (false, key)
    } else if PORTS.contains(&key.client.port) {
        (
            true,
            FlowKey {
                proto: key.proto,
                client: key.server,
                server: key.client,
            },
        )
    } else {
        return None;
    };
    Some(Flow {
        swapped,
        decoders: [Decoder::new(), Decoder::new()],
        session: Session {
            id: ctx.id,
            key: oriented,
            first_ts: ctx.ts_ns,
            last_ts: ctx.ts_ns,
            nvt: [Nvt::default(), Nvt::default()],
            will: [Options::default(); 2],
            do_: [Options::default(); 2],
            terminal: None,
            window: None,
            env_user: None,
            echo: Echo::default(),
            server_echo: false,
            line: Line::default(),
            suspect: None,
            new_segment: false,
            transcript: Transcript::default(),
            login: login::Login::new(ctx.id, oriented),
        },
    })
}

impl Analyzer for TelnetAnalyzer {
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
        if ctx.key.proto != 6 {
            return;
        }
        let Some(flow) = self
            .flows
            .entry(ctx.id)
            .or_insert_with(|| open(ctx))
            .as_mut()
        else {
            return;
        };
        let side = if (dir == Direction::ToServer) == flow.swapped {
            SERVER
        } else {
            CLIENT
        };
        let Flow {
            decoders, session, ..
        } = flow;
        session.last_ts = session.last_ts.max(ctx.ts_ns);
        let Some(decoder) = decoders.get_mut(side) else {
            return;
        };
        if ctx.gap_before > 0 {
            decoder.reset();
            session.gap(side);
        }
        if side == CLIENT {
            session.new_segment = true;
        }
        let budget = &mut self.budget;
        decoder.feed(data, &mut |event| {
            session.event(side, event, ctx.ts_ns, budget, out);
        });
    }

    fn on_flow_end(&mut self, ctx: &FlowCtx, out: &mut dyn RecordSink) {
        if let Some(Some(mut flow)) = self.flows.remove(&ctx.id) {
            let (to_server, to_client) = (ctx.to_server.bytes, ctx.to_client.bytes);
            let bytes = if flow.swapped {
                (to_client, to_server)
            } else {
                (to_server, to_client)
            };
            flow.session.first_ts = flow.session.first_ts.min(ctx.first_ts_ns);
            flow.session.last_ts = flow.session.last_ts.max(ctx.last_ts_ns);
            self.end(flow, Some(bytes), out);
        }
    }

    fn finish(&mut self, out: &mut dyn RecordSink) {
        let mut left: Vec<(FlowId, Option<Flow>)> = self.flows.drain().collect();
        left.sort_unstable_by_key(|(id, _)| *id);
        for flow in left.into_iter().filter_map(|(_, f)| f) {
            self.end(flow, None, out);
        }
    }
}

#[cfg(test)]
mod tests;
