//! The `mqtt` analyzer (`docs/specs/mqtt.md`): MQTT 3.1, 3.1.1 and 5.0 connections over TCP.
//!
//! - **Detection**: on port 1883 (either side) the first data of the client must be a valid
//!   CONNECT, or, for a connection picked up in the middle, the first segments must hold at least
//!   two valid packets of types allowed in their direction; on any other port only a valid and
//!   exact CONNECT as the first data of the client ([`netsift_dissect::mqtt::starts_connect`]).
//! - [`conn`]: the connection engine, independent of the transport (TCP here; WebSocket frames
//!   of the `http` analyzer later, P5.15b): framing, topic aliases, acknowledgements merged into
//!   their packet, bounded transcript, topic aggregates, subscriptions, credentials.
//!
//! Records: one [`MqttConnection`] per connection (at its end), its stored packets
//! ([`MqttPacket`], at most [`conn::MAX_STORED`]), its topic aggregates ([`MqttTopicStat`]) and
//! subscriptions ([`MqttSubscription`]), and a [`crate::Credential`] for a CONNECT carrying a
//! user name, a password or a 5.0 authentication method. A TCP connection always reaches the same
//! shard: nothing is shared between shards except the bounds of [`MqttConfig`].

pub(crate) mod conn;

use std::collections::HashMap;
use std::fmt;

use netsift_dissect::mqtt::{self as wire, HeaderStatus, PacketType, Version};
use netsift_flow::{Direction, Endpoint, FlowCtx, FlowId, FlowKey, StreamCtx};

use crate::analyzer::{Analyzer, AnalyzerId, RecordSink};
use crate::registry::AnalyzerConfig;
use conn::{Conn, Shared};
pub use conn::{MAX_STORED, MAX_SUBSCRIPTIONS, MAX_TOPICS};

/// MQTT port (IANA `mqtt`).
pub const PORT: u16 = 1883;
/// Bytes buffered per connection while deciding whether it is MQTT.
const PROBE_BYTES: usize = wire::MAX_PACKET_PREFIX + 8;
/// Segments looked at before giving up on a connection of port 1883.
const PROBE_SEGMENTS: usize = 8;
/// Client segments accumulated for a CONNECT on another port.
const PROBE_CONNECT_SEGMENTS: usize = 4;
/// Bytes buffered by all the connections of a shard being probed; past it, new data is not probed.
const PROBE_BUDGET: usize = 16 * 1024 * 1024;

/// Settings of the `mqtt` analyzer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MqttConfig {
    /// Connections followed at a time; new ones are ignored beyond. One instance applies it as
    /// is; the engine gives each shard its share (at least 16).
    pub max_connections: usize,
    /// Bytes of packets held per shard while they wait for their acknowledgement.
    pub max_pending_bytes: usize,
}

impl Default for MqttConfig {
    fn default() -> Self {
        Self {
            max_connections: 65_536,
            max_pending_bytes: 32 * 1024 * 1024,
        }
    }
}

/// Transport of a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Transport {
    Tcp,
    /// MQTT over WebSocket (P5.15b).
    Ws,
}

impl Transport {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Ws => "ws",
        }
    }
}

/// Sender of a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Dir {
    /// Client to broker.
    Client,
    /// Broker to client.
    Broker,
}

impl Dir {
    /// Stored tag (`c`, `b`).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Client => "c",
            Self::Broker => "b",
        }
    }

    pub(crate) const fn index(self) -> usize {
        match self {
            Self::Client => 0,
            Self::Broker => 1,
        }
    }

    pub(crate) const fn other(self) -> Self {
        match self {
            Self::Client => Self::Broker,
            Self::Broker => Self::Client,
        }
    }
}

/// How the client authenticated in its CONNECT.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthKind {
    None,
    /// A user name without password.
    Username,
    Password,
    /// 5.0 authentication method (AUTH exchange).
    Enhanced,
}

impl AuthKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Username => "username",
            Self::Password => "password",
            Self::Enhanced => "enhanced",
        }
    }
}

/// Result of the CONNECT (CONNACK code).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Login {
    Accepted,
    Rejected,
}

impl Login {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
        }
    }
}

/// How a connection ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EndKind {
    /// A DISCONNECT was seen.
    Disconnect,
    /// TCP closed without DISCONNECT.
    Close,
    Reset,
    /// Idle past the flow timeout, or evicted.
    Timeout,
    /// Still open at the end of the capture.
    Capture,
}

impl EndKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Disconnect => "disconnect",
            Self::Close => "close",
            Self::Reset => "reset",
            Self::Timeout => "timeout",
            Self::Capture => "capture",
        }
    }
}

/// Where the topic of a PUBLISH comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TopicSource {
    Name,
    /// Resolved from a topic alias (5.0).
    Alias,
    /// An alias unknown to the connection (picked up in the middle).
    Unresolved,
}

impl TopicSource {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Name => "name",
            Self::Alias => "alias",
            Self::Unresolved => "unresolved",
        }
    }
}

/// Acknowledgement of a PUBLISH (`QoS` 1 and 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AckState {
    /// `QoS` 0: nothing expected.
    None,
    /// PUBACK (`QoS` 1) or PUBCOMP (`QoS` 2).
    Acked,
    /// PUBREC without PUBCOMP.
    Received,
    Missing,
    /// Reason code 0x80 or above.
    Error,
}

impl AckState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Acked => "acked",
            Self::Received => "received",
            Self::Missing => "missing",
            Self::Error => "error",
        }
    }
}

/// One filter of a SUBSCRIBE or UNSUBSCRIBE, with the code of its acknowledgement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MqttFilter {
    pub filter: String,
    pub options: u8,
    /// SUBACK / UNSUBACK code (granted `QoS`, or 0x80 and above).
    pub granted: Option<u8>,
}

/// One stored control packet (transcript of a connection).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MqttPacket {
    pub flow_id: FlowId,
    /// Order of arrival in the connection (both directions).
    pub seq: u32,
    pub ts: i64,
    pub dir: Dir,
    pub ptype: PacketType,
    pub flags: u8,
    pub packet_id: Option<u16>,
    pub qos: Option<u8>,
    pub retain: bool,
    pub dup: bool,
    pub topic: Option<String>,
    pub topic_alias: Option<u16>,
    pub topic_source: Option<TopicSource>,
    /// Whole packet, fixed header included.
    pub size: u64,
    pub payload_len: Option<u64>,
    /// At most [`wire::MAX_EXCERPT`] first bytes of the payload.
    pub payload: Option<Vec<u8>>,
    pub payload_format: Option<u8>,
    pub content_type: Option<String>,
    pub reason_code: Option<u8>,
    pub reason_string: Option<String>,
    pub ack_state: Option<AckState>,
    pub ack_reason: Option<u8>,
    pub ack_ns: Option<i64>,
    pub filters: Vec<MqttFilter>,
    /// Other 5.0 properties as ordered (name, value) pairs.
    pub props: Vec<(String, String)>,
    pub malformed: bool,
}

/// Messages of one topic in one direction of a connection (all PUBLISH, stored or not).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MqttTopicStat {
    pub flow_id: FlowId,
    pub dir: Dir,
    /// `None`: the bucket of the topics beyond [`MAX_TOPICS`] and of unresolved aliases.
    pub topic: Option<String>,
    pub messages: u64,
    pub payload_bytes: u64,
    pub first_ts: i64,
    pub last_ts: i64,
    /// Messages per `QoS` (0, 1, 2).
    pub qos: [u64; 3],
    pub retained: u64,
    pub max_payload: u64,
}

/// One filter subscribed by a connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MqttSubscription {
    pub flow_id: FlowId,
    /// `seq` of the SUBSCRIBE and index of the filter in it.
    pub seq: u32,
    pub idx: u32,
    pub ts: i64,
    pub filter: String,
    pub qos: u8,
    pub options: u8,
    pub granted: Option<u8>,
    /// Group of a 5.0 shared subscription (`$share/<group>/...`).
    pub shared_group: Option<String>,
    /// `#`, `+/#`, `$SYS/#` (directly or shared): reads everything.
    pub wildcard: bool,
    pub unsubscribed_ts: Option<i64>,
}

/// One MQTT connection, at its end. `Debug` hides the password.
#[allow(clippy::struct_excessive_bools)] // Independent facts about one connection.
#[derive(Clone, PartialEq, Eq)]
pub struct MqttConnection {
    pub flow_id: FlowId,
    pub client: Endpoint,
    pub server: Endpoint,
    pub first_ts: i64,
    pub last_ts: i64,
    pub transport: Transport,
    /// WebSocket details (P5.15b).
    pub ws_path: Option<String>,
    pub ws_host: Option<String>,
    pub ws_subprotocol: Option<String>,
    pub ws_close_code: Option<u16>,
    pub ws_compressed: bool,
    pub version: Option<Version>,
    pub bridge: bool,
    /// Picked up in the middle: no CONNECT, version guessed.
    pub partial: bool,
    pub protocol_name: Option<String>,
    pub client_id: Option<String>,
    pub assigned_client_id: Option<String>,
    pub clean_start: Option<bool>,
    pub keep_alive: Option<u16>,
    pub server_keep_alive: Option<u16>,
    pub session_expiry: Option<u32>,
    pub username: Option<String>,
    /// Password (UTF-8 text, else `hex:` and its hexadecimal). Sensitive.
    pub password: Option<String>,
    pub password_len: Option<u32>,
    pub auth_method: Option<String>,
    pub auth: Option<AuthKind>,
    pub will_topic: Option<String>,
    pub will_qos: Option<u8>,
    pub will_retain: Option<bool>,
    pub will_payload_len: Option<u64>,
    pub will_payload: Option<Vec<u8>>,
    pub connect_props: Vec<(String, String)>,
    pub connack_ts: Option<i64>,
    pub connack_code: Option<u8>,
    pub session_present: Option<bool>,
    pub connack_props: Vec<(String, String)>,
    pub login: Option<Login>,
    pub end_kind: EndKind,
    pub disconnect_ts: Option<i64>,
    pub disconnect_by: Option<Dir>,
    pub disconnect_reason: Option<u8>,
    /// Version announced on `$SYS/broker/version`.
    pub broker_software: Option<String>,
    pub packets_c2s: u64,
    pub packets_s2c: u64,
    pub publish_c2s: u64,
    pub publish_s2c: u64,
    pub payload_bytes_c2s: u64,
    pub payload_bytes_s2c: u64,
    pub subscribe_count: u64,
    pub pings: u64,
    pub last_ping_ts: Option<i64>,
    /// Wire bytes per direction (as Connections).
    pub bytes_c2s: u64,
    pub bytes_s2c: u64,
    pub stored_packets: u32,
    pub packets_truncated: bool,
    pub malformed: u32,
    pub protocol_errors: u32,
    pub gaps: u32,
}

impl fmt::Debug for MqttConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MqttConnection")
            .field("flow_id", &self.flow_id)
            .field("client", &self.client)
            .field("server", &self.server)
            .field("version", &self.version)
            .field("client_id", &self.client_id)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("login", &self.login)
            .field("end_kind", &self.end_kind)
            .finish_non_exhaustive()
    }
}

/// A record of the `mqtt` analyzer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MqttRecord {
    Connection(Box<MqttConnection>),
    Packet(Box<MqttPacket>),
    Topic(MqttTopicStat),
    Subscription(MqttSubscription),
}

/// State of a TCP flow.
#[derive(Debug)]
enum Flow {
    Probe(Probe),
    Mqtt {
        conn: Box<Conn>,
        /// The flow key's client is the broker.
        swapped: bool,
    },
    Ignored,
}

/// Data of a flow not decided yet, in arrival order.
#[derive(Debug, Default)]
struct Probe {
    segs: Vec<(Direction, StreamCtx, Vec<u8>)>,
    bytes: usize,
}

impl Probe {
    /// Concatenated data of one direction.
    fn side(&self, dir: Direction) -> Vec<u8> {
        let mut out = Vec::new();
        for (d, _, data) in &self.segs {
            if *d == dir {
                out.extend_from_slice(data);
            }
        }
        out
    }
}

/// Outcome of the probe of a connection.
enum Decision {
    Wait,
    Ignore,
    /// MQTT; `swapped`: the flow key's client is the broker; `partial`: picked up in the
    /// middle, with the guessed version.
    Mqtt {
        swapped: bool,
        partial: Option<Version>,
    },
}

/// Complete packets at the start of `buf` when every header is valid and allowed for `client`
/// (`None` when one is not, or a packet does not decode with any version). Also returns
/// whether some packet decodes as 5.0 and not as 3.1.1.
fn leading_packets(buf: &[u8], client: bool) -> Option<(usize, bool)> {
    let mut pos = 0usize;
    let mut count = 0usize;
    let mut v5_only = false;
    while let Some(rest) = buf.get(pos..) {
        if rest.is_empty() {
            break;
        }
        let header = match wire::fixed_header(rest) {
            HeaderStatus::Incomplete => break,
            HeaderStatus::Invalid => return None,
            HeaderStatus::Valid(h) => h,
        };
        let allowed = if client {
            header.ptype.from_client()
        } else {
            header.ptype.from_server()
        };
        if !allowed || header.ptype == PacketType::Connect {
            return None;
        }
        let start = usize::from(header.header_len);
        let len = usize::try_from(header.remaining).unwrap_or(usize::MAX);
        let Some(body) = rest.get(start..start.saturating_add(len)) else {
            break;
        };
        let v3 = wire::parse_packet(header, body, Version::V311).is_ok();
        let v5 = wire::parse_packet(header, body, Version::V5).is_ok();
        if !v3 && !v5 {
            return None;
        }
        v5_only |= v5 && !v3;
        count = count.saturating_add(1);
        pos = pos.saturating_add(start).saturating_add(len);
    }
    Some((count, v5_only))
}

impl Probe {
    fn decide(&self, key: &FlowKey) -> Decision {
        let port_server = key.server.port == PORT;
        let port_client = key.client.port == PORT;
        let to_server = self.side(Direction::ToServer);
        if !port_server && !port_client {
            // Any other port: the first data must come from the client and be a CONNECT.
            if self
                .segs
                .first()
                .is_some_and(|(d, _, _)| *d == Direction::ToClient)
            {
                return Decision::Ignore;
            }
            if self.segs.iter().any(|(d, _, _)| *d == Direction::ToClient) {
                return Decision::Ignore;
            }
            return match wire::starts_connect(&to_server) {
                Some(true) => Decision::Mqtt {
                    swapped: false,
                    partial: None,
                },
                Some(false) => Decision::Ignore,
                None if self.segs.len() >= PROBE_CONNECT_SEGMENTS || self.bytes >= PROBE_BYTES => {
                    Decision::Ignore
                }
                None => Decision::Wait,
            };
        }
        // Port 1883: the broker is the side of the port (the server when both are).
        let swapped = !port_server;
        let (client_dir, broker_dir) = if swapped {
            (Direction::ToClient, Direction::ToServer)
        } else {
            (Direction::ToServer, Direction::ToClient)
        };
        let client = if swapped {
            self.side(Direction::ToClient)
        } else {
            to_server
        };
        match wire::starts_connect(&client) {
            Some(true) => {
                return Decision::Mqtt {
                    swapped,
                    partial: None,
                };
            }
            None if !client.is_empty() => {
                return if self.bytes >= PROBE_BYTES {
                    Decision::Ignore
                } else {
                    Decision::Wait
                };
            }
            _ => {}
        }
        // Picked up in the middle: valid packets of the right types in both directions.
        let Some((from_client, v5_client)) = leading_packets(&self.side(client_dir), true) else {
            return Decision::Ignore;
        };
        let Some((from_broker, v5_broker)) = leading_packets(&self.side(broker_dir), false) else {
            return Decision::Ignore;
        };
        if from_client.saturating_add(from_broker) >= 2 {
            let version = if v5_client || v5_broker {
                Version::V5
            } else {
                Version::V311
            };
            return Decision::Mqtt {
                swapped,
                partial: Some(version),
            };
        }
        if self.segs.len() >= PROBE_SEGMENTS || self.bytes >= PROBE_BYTES {
            Decision::Ignore
        } else {
            Decision::Wait
        }
    }
}

/// The `mqtt` analyzer (one instance per shard). `Debug` shows counts only.
pub struct MqttAnalyzer {
    config: MqttConfig,
    flows: HashMap<FlowId, Flow>,
    /// Connections being followed (decided MQTT).
    active: usize,
    /// Bytes held by the probes of the shard (at most [`PROBE_BUDGET`]).
    probe_bytes: usize,
    shared: Shared,
}

impl fmt::Debug for MqttAnalyzer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MqttAnalyzer")
            .field("flows", &self.flows.len())
            .field("active", &self.active)
            .finish_non_exhaustive()
    }
}

impl MqttAnalyzer {
    pub const ID: AnalyzerId = AnalyzerId("mqtt");

    pub fn new(config: &AnalyzerConfig) -> Self {
        Self {
            config: config.mqtt.clone(),
            flows: HashMap::new(),
            active: 0,
            probe_bytes: 0,
            shared: Shared::new(config.mqtt.max_pending_bytes),
        }
    }

    /// [`crate::registry::Factory`] of this analyzer.
    pub fn boxed(config: &AnalyzerConfig) -> Box<dyn Analyzer> {
        Box::new(Self::new(config))
    }

    fn start(
        &mut self,
        id: FlowId,
        key: FlowKey,
        probe: &Probe,
        swapped: bool,
        partial: Option<Version>,
        out: &mut dyn RecordSink,
    ) {
        let (client, server) = if swapped {
            (key.server, key.client)
        } else {
            (key.client, key.server)
        };
        let first_ts = probe.segs.first().map_or(0, |(_, c, _)| c.ts_ns);
        let mut conn = Box::new(Conn::new(id, client, server, Transport::Tcp, first_ts));
        if let Some(v) = partial {
            conn.set_partial(v);
        }
        for (dir, ctx, data) in &probe.segs {
            let role = role(*dir, swapped);
            conn.feed(role, data, ctx.ts_ns, ctx.gap_before, &mut self.shared, out);
        }
        self.active = self.active.saturating_add(1);
        self.flows.insert(id, Flow::Mqtt { conn, swapped });
    }

    fn end(&mut self, conn: Box<Conn>, ctx: Option<(&FlowCtx, bool)>, out: &mut dyn RecordSink) {
        self.active = self.active.saturating_sub(1);
        conn.finish(ctx, &mut self.shared, out);
    }
}

/// Sender role of the data of `dir`.
fn role(dir: Direction, swapped: bool) -> Dir {
    if (dir == Direction::ToServer) == swapped {
        Dir::Broker
    } else {
        Dir::Client
    }
}

impl Analyzer for MqttAnalyzer {
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
        if ctx.key.proto != 6 || data.is_empty() {
            return;
        }
        let full = self.active >= self.config.max_connections;
        let flow = self.flows.entry(ctx.id).or_insert_with(|| {
            let port = ctx.key.server.port == PORT || ctx.key.client.port == PORT;
            // Cheap first test off port 1883: a CONNECT starts with 0x10, sent by the client.
            if full || (!port && (dir != Direction::ToServer || data.first() != Some(&0x10))) {
                Flow::Ignored
            } else {
                Flow::Probe(Probe::default())
            }
        });
        match flow {
            Flow::Ignored => {}
            Flow::Mqtt { conn, swapped } => {
                let role = role(dir, *swapped);
                conn.feed(role, data, ctx.ts_ns, ctx.gap_before, &mut self.shared, out);
            }
            Flow::Probe(probe) => {
                let room = PROBE_BYTES.saturating_sub(probe.bytes);
                let kept = data.get(..data.len().min(room)).unwrap_or_default();
                let over = self.probe_bytes.saturating_add(kept.len()) > PROBE_BUDGET;
                if over || (ctx.gap_before > 0 && !probe.segs.is_empty()) {
                    self.probe_bytes = self.probe_bytes.saturating_sub(probe.bytes);
                    *flow = Flow::Ignored;
                    return;
                }
                probe.bytes = probe.bytes.saturating_add(kept.len());
                self.probe_bytes = self.probe_bytes.saturating_add(kept.len());
                probe.segs.push((dir, *ctx, kept.to_vec()));
                let decision = probe.decide(&ctx.key);
                let release = match decision {
                    Decision::Wait if kept.len() == data.len() => 0,
                    _ => probe.bytes,
                };
                self.probe_bytes = self.probe_bytes.saturating_sub(release);
                match decision {
                    Decision::Wait => {
                        if kept.len() < data.len() {
                            *flow = Flow::Ignored;
                        }
                    }
                    Decision::Ignore => *flow = Flow::Ignored,
                    Decision::Mqtt { swapped, partial } => {
                        let Flow::Probe(probe) = std::mem::replace(flow, Flow::Ignored) else {
                            return;
                        };
                        let truncated = kept.len() < data.len();
                        self.start(ctx.id, ctx.key, &probe, swapped, partial, out);
                        if truncated
                            && let Some(Flow::Mqtt { conn, swapped }) = self.flows.get_mut(&ctx.id)
                        {
                            let rest = data.get(kept.len()..).unwrap_or_default();
                            let role = role(dir, *swapped);
                            conn.feed(role, rest, ctx.ts_ns, 0, &mut self.shared, out);
                        }
                    }
                }
            }
        }
    }

    fn on_flow_end(&mut self, ctx: &FlowCtx, out: &mut dyn RecordSink) {
        match self.flows.remove(&ctx.id) {
            Some(Flow::Mqtt { conn, swapped }) => self.end(conn, Some((ctx, swapped)), out),
            Some(Flow::Probe(probe)) => {
                self.probe_bytes = self.probe_bytes.saturating_sub(probe.bytes);
            }
            Some(Flow::Ignored) | None => {}
        }
    }

    fn finish(&mut self, out: &mut dyn RecordSink) {
        let mut left: Vec<(FlowId, Flow)> = self.flows.drain().collect();
        left.sort_unstable_by_key(|(id, _)| *id);
        for (_, flow) in left {
            if let Flow::Mqtt { conn, .. } = flow {
                self.end(conn, None, out);
            }
        }
    }
}

/// Display text: control characters and invisible or bidirectional formatting characters
/// replaced by U+FFFD.
pub(crate) fn clean(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_control()
                || matches!(c, '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{FEFF}')
            {
                char::REPLACEMENT_CHARACTER
            } else {
                c
            }
        })
        .collect()
}

#[cfg(test)]
mod tests;
