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

/// State of one session except the two `IAC` decoders (borrowed separately while they feed).
#[derive(Debug)]
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
    transcript: Transcript,
    login: login::Login,
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
            let secret = self.login.client(token, ts, self.env_user.as_deref(), out);
            self.echo.typed(token, secret);
            let speaker = if secret {
                Speaker::Secret
            } else {
                Speaker::Client
            };
            self.transcript.apply(speaker, token, budget);
        } else {
            if self.echo.absorbs(token) {
                return;
            }
            self.login.server(token, out);
            self.transcript.apply(Speaker::Server, token, budget);
        }
    }

    /// Bytes are missing in one direction: partial state is dropped.
    fn gap(&mut self, side: usize) {
        if let Some(nvt) = self.nvt.get_mut(side) {
            nvt.reset();
        }
        self.echo.clear();
        self.login.reset();
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
