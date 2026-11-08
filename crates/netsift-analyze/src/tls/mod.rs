//! The `tls` analyzer: TLS sessions over TCP, detected by content (any port).
//!
//! For each TCP flow whose first payload is a TLS `ClientHello` (or, when the client side was
//! not captured, a `ServerHello`), the analyzer follows the record layer of both directions
//! ([`stream`]) and decodes:
//! - the hellos ([`hello`]): versions (`supported_versions` included), cipher suites, SNI, ALPN,
//!   groups, signature algorithms, and the client fingerprints JA3 and JA4 ([`fingerprint`]);
//! - the server certificate chain when it is in clear (TLS 1.2 and earlier, [`cert`]): each DER
//!   certificate is stored once as a blob of the session ([`RecordSink::put_blob`]); in TLS 1.3
//!   certificates are encrypted and the session is marked so, without error;
//! - the first plaintext alert, resumption, and whether both sides reached encrypted traffic.
//!
//! One [`TlsSession`] record is emitted per flow, as soon as both sides send application data
//! (the flow is then forgotten) or when the flow ends. Every buffer is bounded per flow and per
//! shard ([`TlsConfig`]); hostile input never panics.

pub mod cert;
pub mod fingerprint;
pub mod hello;
pub mod stream;
pub mod suites;

use std::collections::{HashMap, HashSet};

use netsift_flow::{Direction, Endpoint, FlowCtx, FlowId, FlowKey, StreamCtx};
use tls_parser::{TlsMessage, TlsMessageHandshake, parse_tls_message_handshake};

use crate::analyzer::{Analyzer, AnalyzerId, RecordSink};
use crate::record::Record;
use crate::registry::AnalyzerConfig;
use cert::Certificate;
use fingerprint::Ja3;
use hello::{ClientHello, ServerHello};
use stream::{DirParser, Event};

/// Settings of the `tls` analyzer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsConfig {
    /// Handshakes followed at the same time per shard; more flows are ignored.
    pub max_flows: usize,
    /// Longest handshake message reassembled (certificate chains), in bytes.
    pub max_handshake_message: usize,
    /// Bytes buffered by all the handshakes of a shard; past it, a direction is abandoned.
    pub max_buffered: usize,
    /// Certificates kept per chain.
    pub max_chain: usize,
    /// Largest certificate decoded and stored, in bytes.
    pub max_certificate: usize,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            max_flows: 65_536,
            max_handshake_message: 128 * 1024,
            max_buffered: 64 * 1024 * 1024,
            max_chain: 10,
            max_certificate: 64 * 1024,
        }
    }
}

/// Bits of [`TlsSession::cert_issues`].
pub mod cert_issue {
    /// A certificate had expired at the time of the session.
    pub const EXPIRED: u32 = 1;
    /// A certificate was not valid yet at the time of the session.
    pub const NOT_YET_VALID: u32 = 2;
    /// The leaf certificate is self-signed.
    pub const SELF_SIGNED: u32 = 4;
    /// A public key is too short (RSA/DSA below 2048 bits, EC below 224 bits).
    pub const WEAK_KEY: u32 = 8;
}

/// How far the handshake went.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Both sides switched to encrypted traffic, without fatal alert.
    Complete,
    Partial,
}

/// Visibility of the server certificates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertStatus {
    Present,
    /// TLS 1.3: the certificates are encrypted.
    Encrypted,
    /// No certificate message seen.
    None,
}

/// First plaintext alert.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Alert {
    pub level: u8,
    pub description: u8,
    pub from_server: bool,
}

impl Alert {
    /// `fatal` level (RFC 5246 7.2).
    pub fn is_fatal(&self) -> bool {
        self.level == 2
    }
}

/// A cipher suite with its IANA name and weakness ([`suites::describe`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CipherInfo {
    pub id: u16,
    pub name: &'static str,
    pub weak: Option<&'static str>,
}

/// One TLS session (the first handshake of a TCP flow).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsSession {
    pub flow: FlowId,
    pub client: Endpoint,
    pub server: Endpoint,
    /// Packet time of the first TLS message.
    pub ts_ns: i64,
    pub client_hello: Option<ClientHello>,
    /// Final `ServerHello` (after a `HelloRetryRequest`, the second one).
    pub server_hello: Option<ServerHello>,
    /// Negotiated suite, when known to the IANA registry.
    pub cipher: Option<CipherInfo>,
    pub ja3: Option<Ja3>,
    pub ja4: Option<String>,
    pub resumed: bool,
    pub outcome: Outcome,
    pub alert: Option<Alert>,
    pub cert_status: CertStatus,
    /// Server chain, leaf first.
    pub certificates: Vec<Certificate>,
    /// Bits of [`cert_issue`].
    pub cert_issues: u32,
    /// Suites of this session whose name was not sent before by this shard.
    pub cipher_names: Vec<CipherInfo>,
}

impl TlsSession {
    pub fn sni(&self) -> Option<&str> {
        self.client_hello.as_ref()?.sni.as_deref()
    }

    pub fn offered_version(&self) -> Option<u16> {
        self.client_hello.as_ref().map(ClientHello::offered_version)
    }

    /// Negotiated version.
    pub fn version(&self) -> Option<u16> {
        self.server_hello.as_ref().map(ServerHello::version)
    }

    pub fn alpn(&self) -> Option<&str> {
        self.server_hello.as_ref()?.alpn.as_deref()
    }
}

/// Handshake being followed.
#[derive(Debug)]
struct Tracked {
    key: FlowKey,
    ts_ns: i64,
    client: DirParser,
    server: DirParser,
    client_hello: Option<ClientHello>,
    server_hello: Option<ServerHello>,
    certificates: Vec<Certificate>,
    certificate_seen: bool,
    alert: Option<Alert>,
    client_app: bool,
    server_app: bool,
    /// Approximate heap size of the decoded hellos and certificates (shard memory bound).
    decoded: usize,
}

#[derive(Debug)]
enum FlowState {
    /// Not TLS (or over the flow bound): ignored until the flow ends.
    Ignored,
    Tracked(Box<Tracked>),
    /// Session emitted: the rest of the flow is ignored.
    Done,
}

/// First bytes of a stream that start a TLS handshake record carrying `hs_type`.
fn looks_like_tls(data: &[u8], hs_type: u8) -> bool {
    let expect = [Some(22), Some(3), None, None, None, Some(hs_type)];
    !data.is_empty()
        && data
            .iter()
            .zip(expect)
            .enumerate()
            .all(|(i, (b, e))| match (i, e) {
                (2, _) => *b <= 4,
                (_, Some(e)) => *b == e,
                _ => true,
            })
}

/// See the module documentation.
#[derive(Debug)]
pub struct TlsAnalyzer {
    config: TlsConfig,
    flows: HashMap<FlowId, FlowState>,
    tracked: usize,
    buffered: usize,
    /// Suites whose name was already emitted by this shard.
    named: HashSet<u16>,
}

impl TlsAnalyzer {
    pub const ID: AnalyzerId = AnalyzerId("tls");

    pub fn new(config: &AnalyzerConfig) -> Self {
        Self {
            config: config.tls.clone(),
            flows: HashMap::new(),
            tracked: 0,
            buffered: 0,
            named: HashSet::new(),
        }
    }

    /// [`crate::registry::Factory`] of this analyzer.
    pub fn boxed(config: &AnalyzerConfig) -> Box<dyn Analyzer> {
        Box::new(Self::new(config))
    }

    fn start(&mut self, ctx: &StreamCtx, dir: Direction, data: &[u8]) -> FlowState {
        let hs_type = if dir == Direction::ToServer { 1 } else { 2 };
        if ctx.key.proto != 6
            || !looks_like_tls(data, hs_type)
            || self.tracked >= self.config.max_flows
            || self.buffered >= self.config.max_buffered
        {
            return FlowState::Ignored;
        }
        self.tracked += 1;
        FlowState::Tracked(Box::new(Tracked {
            key: ctx.key,
            ts_ns: ctx.ts_ns,
            client: DirParser::default(),
            server: DirParser::default(),
            client_hello: None,
            server_hello: None,
            certificates: Vec::new(),
            certificate_seen: false,
            alert: None,
            client_app: false,
            server_app: false,
            decoded: 0,
        }))
    }

    /// Handles the decoded events of one direction.
    fn apply(
        config: &TlsConfig,
        t: &mut Tracked,
        from_server: bool,
        events: Vec<Event>,
        out: &mut dyn RecordSink,
    ) {
        for event in events {
            match event {
                Event::Handshake(msg) => Self::message(config, t, from_server, &msg, out),
                Event::ChangeCipherSpec => {}
                Event::Alert(level, description) => {
                    if t.alert.is_none() {
                        t.alert = Some(Alert {
                            level,
                            description,
                            from_server,
                        });
                    }
                }
                Event::ApplicationData => {
                    if from_server {
                        t.server_app = true;
                    } else {
                        t.client_app = true;
                    }
                }
            }
        }
    }

    fn message(
        config: &TlsConfig,
        t: &mut Tracked,
        from_server: bool,
        msg: &[u8],
        out: &mut dyn RecordSink,
    ) {
        let (Some(&kind), Some(body)) = (msg.first(), msg.get(4..)) else {
            return;
        };
        match (from_server, kind) {
            (false, 1) if t.client_hello.is_none() => {
                t.client_hello = hello::parse_client_hello(body);
                t.decoded += t.client_hello.as_ref().map_or(0, ClientHello::approx_size);
            }
            (true, 2) if t.server_hello.as_ref().is_none_or(|sh| sh.retry) => {
                if let Some(sh) = hello::parse_server_hello(body) {
                    t.decoded += sh.approx_size();
                    t.server_hello = Some(sh);
                }
            }
            (true, 11) if !t.certificate_seen => {
                // TLS 1.3 certificates are encrypted and never reach this point in clear.
                t.certificate_seen = true;
                let Ok((_, TlsMessage::Handshake(TlsMessageHandshake::Certificate(chain)))) =
                    parse_tls_message_handshake(msg)
                else {
                    return;
                };
                for raw in chain.cert_chain.iter().take(config.max_chain) {
                    if raw.data.len() > config.max_certificate {
                        continue;
                    }
                    // The blob store hashes the content: its digest is reused.
                    let blob = out.put_blob(raw.data);
                    let mut c = Certificate::from_der_with_digest(raw.data, blob.map(|b| b.sha256));
                    c.stored = blob.is_some();
                    t.decoded += c.approx_size();
                    t.certificates.push(c);
                }
            }
            _ => {}
        }
    }

    /// The session record of a finished (or ended) handshake, `None` without any hello.
    fn session(&mut self, flow: FlowId, t: Tracked) -> Option<TlsSession> {
        if t.client_hello.is_none() && t.server_hello.is_none() {
            return None;
        }
        let version = t.server_hello.as_ref().map(ServerHello::version);
        let tls13 = version.is_some_and(|v| (0x0304..0x7f00).contains(&v));
        let side_done = |app: bool, p: &DirParser| app || (!tls13 && p.encrypted);
        let fatal = t.alert.is_some_and(|a| a.is_fatal());
        let outcome = if t.server_hello.as_ref().is_some_and(|sh| !sh.retry)
            && !fatal
            && side_done(t.client_app, &t.client)
            && side_done(t.server_app, &t.server)
        {
            Outcome::Complete
        } else {
            Outcome::Partial
        };
        let resumed = match (&t.client_hello, &t.server_hello) {
            (_, Some(sh)) if tls13 => sh.psk,
            (Some(ch), Some(sh)) => {
                (!sh.session_id.is_empty() && sh.session_id == ch.session_id)
                    || (!t.certificate_seen && t.server.encrypted && ch.session_ticket)
            }
            _ => false,
        };
        let cert_status = if tls13 {
            CertStatus::Encrypted
        } else if t.certificates.is_empty() {
            CertStatus::None
        } else {
            CertStatus::Present
        };
        let mut cert_issues = 0;
        for (i, info) in t
            .certificates
            .iter()
            .enumerate()
            .filter_map(|(i, c)| Some((i, c.info.as_ref()?)))
        {
            if info.not_after_ns < t.ts_ns {
                cert_issues |= cert_issue::EXPIRED;
            }
            if info.not_before_ns > t.ts_ns {
                cert_issues |= cert_issue::NOT_YET_VALID;
            }
            if i == 0 && info.self_signed {
                cert_issues |= cert_issue::SELF_SIGNED;
            }
            if info.weak_key() {
                cert_issues |= cert_issue::WEAK_KEY;
            }
        }
        let selected = t.server_hello.as_ref().map(|sh| sh.cipher_suite);
        let cipher = selected
            .and_then(|id| suites::describe(id).map(|(name, weak)| CipherInfo { id, name, weak }));
        let mut cipher_names = Vec::new();
        let offered = t
            .client_hello
            .as_ref()
            .map(|ch| ch.cipher_suites.as_slice())
            .unwrap_or_default();
        for &id in offered.iter().chain(selected.as_ref()) {
            if self.named.contains(&id) {
                continue;
            }
            if let Some((name, weak)) = suites::describe(id) {
                self.named.insert(id);
                cipher_names.push(CipherInfo { id, name, weak });
            }
        }
        Some(TlsSession {
            flow,
            client: t.key.client,
            server: t.key.server,
            ts_ns: t.ts_ns,
            ja3: t.client_hello.as_ref().map(fingerprint::ja3),
            ja4: t.client_hello.as_ref().map(fingerprint::ja4),
            client_hello: t.client_hello,
            server_hello: t.server_hello,
            cipher,
            resumed,
            outcome,
            alert: t.alert,
            cert_status,
            certificates: t.certificates,
            cert_issues,
            cipher_names,
        })
    }

    /// Emits the session of a tracked flow and forgets its buffers.
    fn close(&mut self, flow: FlowId, t: Tracked, out: &mut dyn RecordSink) {
        self.tracked = self.tracked.saturating_sub(1);
        self.buffered = self
            .buffered
            .saturating_sub(t.client.buffered() + t.server.buffered() + t.decoded);
        if let Some(session) = self.session(flow, t) {
            out.emit(Record::Tls(Box::new(session)));
        }
    }
}

impl Analyzer for TlsAnalyzer {
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
        if !self.flows.contains_key(&ctx.id) {
            let state = self.start(ctx, dir, data);
            self.flows.insert(ctx.id, state);
        }
        let Self {
            config,
            flows,
            buffered,
            ..
        } = self;
        let Some(FlowState::Tracked(t)) = flows.get_mut(&ctx.id) else {
            return;
        };
        let from_server = dir == Direction::ToClient;
        let mut events = Vec::new();
        {
            let parser = if from_server {
                &mut t.server
            } else {
                &mut t.client
            };
            let before = parser.buffered();
            if ctx.gap_before > 0 {
                parser.abandon();
            }
            parser.feed(data, config.max_handshake_message, &mut events);
            let after = parser.buffered();
            *buffered = buffered.saturating_sub(before).saturating_add(after);
            if *buffered > config.max_buffered {
                parser.abandon();
                *buffered = buffered.saturating_sub(after);
            }
        }
        let decoded = t.decoded;
        Self::apply(config, t, from_server, events, out);
        *buffered = buffered.saturating_add(t.decoded.saturating_sub(decoded));
        // TLS 1.3 (or a HelloRetryRequest): `ChangeCipherSpec` is a compatibility dummy on both
        // sides, so that the plaintext hellos that follow it are still parsed.
        if !t.client.tls13
            && t.server_hello
                .as_ref()
                .is_some_and(|sh| sh.retry || sh.version() == 0x0304)
        {
            t.client.set_tls13();
            t.server.set_tls13();
        }
        if t.client_app
            && t.server_app
            && let Some(FlowState::Tracked(t)) = self.flows.insert(ctx.id, FlowState::Done)
        {
            self.close(ctx.id, *t, out);
        }
    }

    fn on_flow_end(&mut self, ctx: &FlowCtx, out: &mut dyn RecordSink) {
        if let Some(FlowState::Tracked(t)) = self.flows.remove(&ctx.id) {
            self.close(ctx.id, *t, out);
        }
    }

    fn finish(&mut self, out: &mut dyn RecordSink) {
        // Every flow has ended before `finish`; flush defensively in a deterministic order.
        let mut left: Vec<(FlowId, FlowState)> = self.flows.drain().collect();
        left.sort_unstable_by_key(|(id, _)| *id);
        for (id, state) in left {
            if let FlowState::Tracked(t) = state {
                self.close(id, *t, out);
            }
        }
    }
}

#[cfg(test)]
mod tests;
