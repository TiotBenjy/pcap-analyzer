//! MQTT view routes (`docs/specs/mqtt.md`): statistics, connections and their transcript,
//! clients, brokers, topic tree, messages and signals.
//!
//! | Method | Path | Response |
//! |---|---|---|
//! | GET | `/sessions/{id}/mqtt/stats` | [`MqttStats`] |
//! | GET | `/sessions/{id}/mqtt/connections` | [`Page`]`<`[`MqttConnectionInfo`]`>` |
//! | GET | `/sessions/{id}/mqtt/connections/{flow}` | [`MqttConnectionDetail`] |
//! | GET | `/sessions/{id}/mqtt/connections/{flow}/packets` | [`Page`]`<`[`MqttPacketInfo`]`>` |
//! | GET | `/sessions/{id}/mqtt/clients` | [`Page`]`<`[`MqttClientInfo`]`>` |
//! | GET | `/sessions/{id}/mqtt/brokers` | [`Page`]`<`[`MqttBrokerInfo`]`>` |
//! | GET | `/sessions/{id}/mqtt/topics` | [`Page`]`<`[`MqttTopicNode`]`>` |
//! | GET | `/sessions/{id}/mqtt/topics/node` | [`MqttTopicDetail`] |
//! | GET | `/sessions/{id}/mqtt/messages` | [`Page`]`<`[`MqttPacketInfo`]`>` |
//! | GET | `/sessions/{id}/mqtt/signals` | `Vec<`[`MqttSignal`]`>` |
//!
//! Time range (ADR-030): connections, clients, brokers, topics and signals are folded rows that
//! overlap the range (counters of whole connections); stored packets and messages are point
//! records. The detail of a connection is not filtered and is the only route that carries a
//! password (like `/credentials/{entry}`), masked by the UI. Payloads are rendered here as
//! hexadecimal and escaped text, never interpreted.

use std::fmt::Write as _;
use std::net::IpAddr;
use std::sync::Arc;

use axum::extract::{Path as UrlPath, State};
use axum::routing::get;
use axum::{Json, Router};
use netsift_store::PageRequest;
use netsift_store::connections::EndpointInfo;
use netsift_store::mqtt::{
    self, BrokerEntry, ClientEntry, ClientKey, ConnectionEntry, ConnectionFilter, GroupFilter,
    LoginFilter, MessageFilter, PacketEntry, PacketFilter, Signal, TopicNode,
};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::contract::Page;
use crate::endpoint::{AddressCategory, Endpoint};
use crate::extract::ApiQuery;
use crate::overview::open_ready;
use crate::range::ApiRange;
use crate::sessions::parse_id;
use crate::{ApiError, AppState, blocking, convert};

/// Longest accepted search text or exact filter value, in bytes.
const MAX_FILTER_LEN: usize = 1024;

pub(crate) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/sessions/{id}/mqtt/stats", get(stats))
        .route("/sessions/{id}/mqtt/connections", get(connections))
        .route("/sessions/{id}/mqtt/connections/{flow}", get(connection))
        .route(
            "/sessions/{id}/mqtt/connections/{flow}/packets",
            get(packets),
        )
        .route("/sessions/{id}/mqtt/clients", get(clients))
        .route("/sessions/{id}/mqtt/brokers", get(brokers))
        .route("/sessions/{id}/mqtt/topics", get(topics))
        .route("/sessions/{id}/mqtt/topics/node", get(topic_node))
        .route("/sessions/{id}/mqtt/messages", get(messages))
        .route("/sessions/{id}/mqtt/signals", get(signals))
}

// ---- enums -------------------------------------------------------------------------------------

/// Protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub enum MqttVersion {
    #[serde(rename = "3.1")]
    V31,
    #[serde(rename = "3.1.1")]
    V311,
    #[serde(rename = "5.0")]
    V5,
}

impl MqttVersion {
    fn of_level(level: u8) -> Option<Self> {
        match level {
            3 => Some(Self::V31),
            4 => Some(Self::V311),
            5 => Some(Self::V5),
            _ => None,
        }
    }

    const fn level(self) -> u8 {
        match self {
            Self::V31 => 3,
            Self::V311 => 4,
            Self::V5 => 5,
        }
    }
}

/// Transport of a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "lowercase")]
#[ts(export)]
pub enum MqttTransport {
    Tcp,
    /// WebSocket (P5.15b).
    Ws,
}

impl MqttTransport {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Ws => "ws",
        }
    }
}

/// How the client authenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "lowercase")]
#[ts(export)]
pub enum MqttAuth {
    None,
    Username,
    Password,
    /// 5.0 authentication method.
    Enhanced,
}

impl MqttAuth {
    const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Username => "username",
            Self::Password => "password",
            Self::Enhanced => "enhanced",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        [Self::None, Self::Username, Self::Password, Self::Enhanced]
            .into_iter()
            .find(|a| a.as_str() == s)
    }
}

/// Result of the CONNECT.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "lowercase")]
#[ts(export)]
pub enum MqttLogin {
    Accepted,
    Rejected,
}

/// `login=` filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
enum LoginQuery {
    Accepted,
    Rejected,
    /// No CONNACK seen.
    None,
}

/// `version=` filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
enum VersionQuery {
    #[serde(rename = "3.1")]
    V31,
    #[serde(rename = "3.1.1")]
    V311,
    #[serde(rename = "5.0")]
    V5,
    #[serde(rename = "unknown")]
    Unknown,
}

/// How a connection ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "lowercase")]
#[ts(export)]
pub enum MqttEnd {
    Disconnect,
    Close,
    Reset,
    Timeout,
    Capture,
}

impl MqttEnd {
    fn parse(s: &str) -> Self {
        match s {
            "disconnect" => Self::Disconnect,
            "close" => Self::Close,
            "reset" => Self::Reset,
            "timeout" => Self::Timeout,
            _ => Self::Capture,
        }
    }
}

/// Sender of a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "lowercase")]
#[ts(export)]
pub enum MqttDir {
    /// Client to broker.
    Client,
    /// Broker to client.
    Broker,
}

impl MqttDir {
    fn parse(s: &str) -> Self {
        if s == "b" { Self::Broker } else { Self::Client }
    }

    const fn tag(self) -> &'static str {
        match self {
            Self::Client => "c",
            Self::Broker => "b",
        }
    }
}

/// A signal (`docs/specs/mqtt.md`, « Signalements »).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "kebab-case")]
#[ts(export)]
pub enum MqttSignalKind {
    Anonymous,
    PublicBroker,
    ExposedBroker,
    Wildcard,
    AuthFailures,
    CleartextCredentials,
}

impl MqttSignalKind {
    fn of(s: Signal) -> Self {
        match s {
            Signal::Anonymous => Self::Anonymous,
            Signal::PublicBroker => Self::PublicBroker,
            Signal::ExposedBroker => Self::ExposedBroker,
            Signal::Wildcard => Self::Wildcard,
            Signal::AuthFailures => Self::AuthFailures,
            Signal::CleartextCredentials => Self::CleartextCredentials,
        }
    }

    const fn signal(self) -> Signal {
        match self {
            Self::Anonymous => Signal::Anonymous,
            Self::PublicBroker => Signal::PublicBroker,
            Self::ExposedBroker => Signal::ExposedBroker,
            Self::Wildcard => Signal::Wildcard,
            Self::AuthFailures => Signal::AuthFailures,
            Self::CleartextCredentials => Signal::CleartextCredentials,
        }
    }
}

/// Acknowledgement of a PUBLISH.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "lowercase")]
#[ts(export)]
pub enum MqttAckState {
    /// `QoS` 0: nothing expected.
    None,
    Acked,
    /// PUBREC without PUBCOMP.
    Received,
    Missing,
    Error,
}

impl MqttAckState {
    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "none" => Self::None,
            "acked" => Self::Acked,
            "received" => Self::Received,
            "missing" => Self::Missing,
            "error" => Self::Error,
            _ => return None,
        })
    }
}

/// Where the topic of a PUBLISH comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "lowercase")]
#[ts(export)]
pub enum MqttTopicSource {
    Name,
    Alias,
    Unresolved,
}

/// Control packet type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "UPPERCASE")]
#[ts(export)]
pub enum MqttPacketType {
    Connect,
    Connack,
    Publish,
    Puback,
    Pubrec,
    Pubrel,
    Pubcomp,
    Subscribe,
    Suback,
    Unsubscribe,
    Unsuback,
    Pingreq,
    Pingresp,
    Disconnect,
    Auth,
}

impl MqttPacketType {
    const ALL: [Self; 15] = [
        Self::Connect,
        Self::Connack,
        Self::Publish,
        Self::Puback,
        Self::Pubrec,
        Self::Pubrel,
        Self::Pubcomp,
        Self::Subscribe,
        Self::Suback,
        Self::Unsubscribe,
        Self::Unsuback,
        Self::Pingreq,
        Self::Pingresp,
        Self::Disconnect,
        Self::Auth,
    ];

    fn of_code(code: u8) -> Self {
        Self::ALL
            .get(usize::from(code).saturating_sub(1))
            .copied()
            .unwrap_or(Self::Auth)
    }

    fn code(self) -> u8 {
        u8::try_from(Self::ALL.iter().position(|t| *t == self).unwrap_or(0) + 1).unwrap_or(15)
    }
}

// ---- payloads ----------------------------------------------------------------------------------

/// An excerpt of a payload (PUBLISH, will message), rendered on the server: hexadecimal, and
/// escaped text when it is text. Displayed as text only, never interpreted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct MqttPayload {
    /// Full length of the payload.
    pub len: u64,
    /// Bytes of the excerpt (at most 512).
    pub excerpt_len: u32,
    /// The excerpt is shorter than the payload.
    pub truncated: bool,
    /// Lower-case hexadecimal of the excerpt.
    pub hex: String,
    /// The excerpt as text when it is UTF-8 without control characters other than tab, LF and
    /// CR (or declared UTF-8 by its Payload Format Indicator); control, invisible and
    /// bidirectional formatting characters are escaped (`\x01`, `\u{202e}`). `null` otherwise.
    pub text: Option<String>,
}

/// Invisible or bidirectional formatting characters, escaped in the rendered text.
fn is_invisible(c: char) -> bool {
    matches!(c, '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{FEFF}')
}

/// Escaped text of an excerpt, or `None` when it is not text.
fn payload_text(bytes: &[u8], truncated: bool, declared_utf8: bool) -> Option<String> {
    let text = match std::str::from_utf8(bytes) {
        Ok(s) => s,
        // A character cut by the end of the excerpt.
        Err(e) if truncated && e.error_len().is_none() => {
            std::str::from_utf8(bytes.get(..e.valid_up_to())?).ok()?
        }
        Err(_) => return None,
    };
    let controls = text
        .chars()
        .any(|c| c.is_control() && !matches!(c, '\t' | '\n' | '\r'));
    if controls && !declared_utf8 {
        return None;
    }
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\t' | '\n' => out.push(c),
            // CR LF is a line end; a lone CR is shown.
            '\r' if chars.peek() == Some(&'\n') => {}
            c if c.is_control() || is_invisible(c) => {
                let code = u32::from(c);
                if code < 0x80 {
                    let _ = write!(out, "\\x{code:02x}");
                } else {
                    let _ = write!(out, "\\u{{{code:04x}}}");
                }
            }
            c => out.push(c),
        }
    }
    Some(out)
}

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

fn payload(bytes: &[u8], len: u64, payload_format: Option<u8>) -> MqttPayload {
    let kept = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    let truncated = kept < len;
    MqttPayload {
        len,
        excerpt_len: u32::try_from(bytes.len()).unwrap_or(u32::MAX),
        truncated,
        hex: hex(bytes),
        text: payload_text(bytes, truncated, payload_format == Some(1)),
    }
}

// ---- DTOs --------------------------------------------------------------------------------------

/// A 5.0 property (or another named value) as decoded, for display.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct MqttProperty {
    /// Stable name (`session_expiry`, `user_property`...).
    pub name: String,
    pub value: String,
}

fn properties(pairs: Vec<(String, String)>) -> Vec<MqttProperty> {
    pairs
        .into_iter()
        .map(|(name, value)| MqttProperty { name, value })
        .collect()
}

/// One MQTT connection (list row), without its password.
#[allow(clippy::struct_excessive_bools)] // Independent facts about one connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct MqttConnectionInfo {
    /// Flow id (key of the list and of the detail route).
    pub flow_id: i64,
    pub first_ts_us: i64,
    pub last_ts_us: i64,
    pub client: Endpoint,
    pub client_port: u16,
    pub broker: Endpoint,
    pub broker_port: u16,
    pub transport: MqttTransport,
    /// WebSocket path (P5.15b).
    pub ws_path: Option<String>,
    /// `null` for a connection picked up in the middle without a guess.
    pub version: Option<MqttVersion>,
    pub bridge: bool,
    /// Picked up in the middle: no CONNECT, version guessed.
    pub partial: bool,
    pub client_id: Option<String>,
    pub assigned_client_id: Option<String>,
    pub username: Option<String>,
    pub has_password: bool,
    pub auth: Option<MqttAuth>,
    /// `null` without CONNACK.
    pub login: Option<MqttLogin>,
    pub connack_code: Option<u8>,
    pub publish_c2s: u64,
    pub publish_s2c: u64,
    pub payload_bytes_c2s: u64,
    pub payload_bytes_s2c: u64,
    pub end: MqttEnd,
    pub packets_truncated: bool,
    pub malformed: u32,
    /// Signals of this connection.
    pub signals: Vec<MqttSignalKind>,
    /// Key of its client in `/mqtt/clients` (`id:...` or `ip:...`).
    pub client_key: String,
}

fn connection_info(e: &ConnectionEntry) -> MqttConnectionInfo {
    let client = Endpoint::new(e.client_ip, e.client.clone());
    let broker = Endpoint::new(e.server_ip, e.server.clone());
    let accepted = e.login.as_deref() == Some("accepted");
    let public_broker = broker.category == AddressCategory::Public;
    let mut signals = Vec::new();
    if accepted && e.auth.as_deref() == Some("none") {
        signals.push(MqttSignalKind::Anonymous);
    }
    if public_broker {
        signals.push(MqttSignalKind::PublicBroker);
    }
    if accepted && !public_broker && client.category == AddressCategory::Public {
        signals.push(MqttSignalKind::ExposedBroker);
    }
    if e.wildcard {
        signals.push(MqttSignalKind::Wildcard);
    }
    if e.auth_failures {
        signals.push(MqttSignalKind::AuthFailures);
    }
    if e.has_password {
        signals.push(MqttSignalKind::CleartextCredentials);
    }
    let client_key = match e.client_id.as_deref() {
        Some(id) if !id.is_empty() => ClientKey::Id(id.to_owned()),
        _ => ClientKey::Ip(e.client_ip),
    }
    .to_key();
    MqttConnectionInfo {
        flow_id: e.flow_id,
        first_ts_us: convert::us(e.first_ts),
        last_ts_us: convert::us(e.last_ts),
        client,
        client_port: e.client_port,
        broker,
        broker_port: e.server_port,
        transport: if e.transport == "ws" {
            MqttTransport::Ws
        } else {
            MqttTransport::Tcp
        },
        ws_path: e.ws_path.clone(),
        version: e.version.and_then(MqttVersion::of_level),
        bridge: e.bridge,
        partial: e.partial,
        client_id: e.client_id.clone(),
        assigned_client_id: e.assigned_client_id.clone(),
        username: e.username.clone(),
        has_password: e.has_password,
        auth: e.auth.as_deref().and_then(MqttAuth::parse),
        login: match e.login.as_deref() {
            Some("accepted") => Some(MqttLogin::Accepted),
            Some("rejected") => Some(MqttLogin::Rejected),
            _ => None,
        },
        connack_code: e.connack_code,
        publish_c2s: e.publish_c2s,
        publish_s2c: e.publish_s2c,
        payload_bytes_c2s: e.payload_bytes_c2s,
        payload_bytes_s2c: e.payload_bytes_s2c,
        end: MqttEnd::parse(&e.end_kind),
        packets_truncated: e.packets_truncated,
        malformed: e.malformed,
        signals,
        client_key,
    }
}

/// Will message of a CONNECT.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct MqttWill {
    pub topic: String,
    pub qos: u8,
    pub retain: bool,
    pub payload: MqttPayload,
}

/// A subscription of a connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct MqttSubscriptionInfo {
    pub ts_us: i64,
    pub filter: String,
    pub qos: u8,
    /// Options byte (5.0: No Local, Retain As Published, Retain Handling).
    pub options: u8,
    /// SUBACK code: granted `QoS`, or 0x80 and above when refused.
    pub granted: Option<u8>,
    pub shared_group: Option<String>,
    pub wildcard: bool,
    pub unsubscribed_ts_us: Option<i64>,
}

/// Messages of a topic in one direction of a connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct MqttConnectionTopic {
    /// `null`: the other topics (beyond the bound, unresolved aliases).
    pub topic: Option<String>,
    pub dir: MqttDir,
    pub messages: u64,
    pub payload_bytes: u64,
    pub retained: u64,
}

/// `GET /mqtt/connections/{flow}`: a connection with its password (sensitive), CONNECT,
/// CONNACK, end, subscriptions and topics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct MqttConnectionDetail {
    pub connection: MqttConnectionInfo,
    pub protocol_name: Option<String>,
    pub clean_start: Option<bool>,
    pub keep_alive: Option<u16>,
    pub server_keep_alive: Option<u16>,
    pub session_expiry: Option<u32>,
    pub auth_method: Option<String>,
    /// UTF-8 text, else `hex:` and its hexadecimal. Sensitive: masked by default.
    pub password: Option<String>,
    pub password_len: Option<u32>,
    pub will: Option<MqttWill>,
    pub connect_props: Vec<MqttProperty>,
    pub connack_ts_us: Option<i64>,
    pub session_present: Option<bool>,
    pub connack_props: Vec<MqttProperty>,
    pub disconnect_ts_us: Option<i64>,
    pub disconnect_by: Option<MqttDir>,
    pub disconnect_reason: Option<u8>,
    pub broker_software: Option<String>,
    pub pings: u64,
    pub last_ping_ts_us: Option<i64>,
    pub packets_c2s: u64,
    pub packets_s2c: u64,
    pub bytes_c2s: u64,
    pub bytes_s2c: u64,
    pub subscribe_count: u64,
    pub stored_packets: u32,
    pub protocol_errors: u32,
    pub gaps: u32,
    pub subscriptions: Vec<MqttSubscriptionInfo>,
    pub topics: Vec<MqttConnectionTopic>,
}

/// A filter of a SUBSCRIBE or UNSUBSCRIBE.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct MqttFilter {
    pub filter: String,
    pub options: u8,
    pub granted: Option<u8>,
}

/// Acknowledgement merged into a PUBLISH.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct MqttAck {
    pub state: MqttAckState,
    pub reason: Option<u8>,
    pub delay_us: Option<i64>,
}

/// A stored control packet (transcript), or a message (PUBLISH) with its connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct MqttPacketInfo {
    pub id: i64,
    pub flow_id: i64,
    pub seq: u32,
    pub ts_us: i64,
    pub dir: MqttDir,
    #[serde(rename = "type")]
    #[ts(rename = "type")]
    pub ptype: MqttPacketType,
    pub packet_id: Option<u16>,
    pub qos: Option<u8>,
    pub retain: bool,
    pub dup: bool,
    pub topic: Option<String>,
    pub topic_alias: Option<u16>,
    pub topic_source: Option<MqttTopicSource>,
    pub size: u64,
    pub payload: Option<MqttPayload>,
    pub payload_format: Option<u8>,
    pub content_type: Option<String>,
    pub reason_code: Option<u8>,
    pub reason_string: Option<String>,
    pub ack: Option<MqttAck>,
    /// Filters of a SUBSCRIBE / UNSUBSCRIBE with their acknowledgement codes.
    pub filters: Vec<MqttFilter>,
    pub props: Vec<MqttProperty>,
    pub malformed: bool,
    /// Messages list only: the connection's client identifier and ends.
    pub client_id: Option<String>,
    pub client: Option<Endpoint>,
    pub broker: Option<Endpoint>,
    pub broker_port: Option<u16>,
}

fn packet_info(p: PacketEntry) -> MqttPacketInfo {
    let ack = match p.ack_state.as_deref().and_then(MqttAckState::parse) {
        Some(state) => Some(MqttAck {
            state,
            reason: p.ack_reason,
            delay_us: p.ack_ns.map(convert::us),
        }),
        None => p.ack_ns.map(|ns| MqttAck {
            state: MqttAckState::Acked,
            reason: None,
            delay_us: Some(convert::us(ns)),
        }),
    };
    let payload = match (&p.payload, p.payload_len) {
        (Some(bytes), Some(len)) => Some(payload(bytes, len, p.payload_format)),
        _ => None,
    };
    let (client_id, client, broker, broker_port) = match p.peer {
        Some(peer) => (
            peer.client_id,
            Some(Endpoint::new(peer.client_ip, peer.client)),
            Some(Endpoint::new(peer.server_ip, peer.server)),
            Some(peer.server_port),
        ),
        None => (None, None, None, None),
    };
    MqttPacketInfo {
        id: p.id,
        flow_id: p.flow_id,
        seq: p.seq,
        ts_us: convert::us(p.ts),
        dir: MqttDir::parse(&p.dir),
        ptype: MqttPacketType::of_code(p.ptype),
        packet_id: p.packet_id,
        qos: p.qos,
        retain: p.retain,
        dup: p.dup,
        topic: p.topic,
        topic_alias: p.topic_alias,
        topic_source: match p.topic_source.as_deref() {
            Some("name") => Some(MqttTopicSource::Name),
            Some("alias") => Some(MqttTopicSource::Alias),
            Some("unresolved") => Some(MqttTopicSource::Unresolved),
            _ => None,
        },
        size: p.size,
        payload,
        payload_format: p.payload_format,
        content_type: p.content_type,
        reason_code: p.reason_code,
        reason_string: p.reason_string,
        ack,
        filters: p
            .filters
            .into_iter()
            .map(|(filter, options, granted)| MqttFilter {
                filter,
                options,
                granted,
            })
            .collect(),
        props: properties(p.props),
        malformed: p.malformed,
        client_id,
        client,
        broker,
        broker_port,
    }
}

/// One client (connections grouped by client identifier, or by address without identifier).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct MqttClientInfo {
    /// `id:<client id>` or `ip:<address>` (filter `client=` of the other lists).
    pub key: String,
    /// `null`: connections without identifier (empty, or no CONNECT) from one address.
    pub client_id: Option<String>,
    pub assigned_client_id: Option<String>,
    /// At most 8 addresses.
    pub addresses: Vec<Endpoint>,
    pub address_count: u64,
    /// At most 4 user names.
    pub usernames: Vec<String>,
    /// At most 4 brokers.
    pub brokers: Vec<MqttBrokerRef>,
    pub broker_count: u64,
    pub versions: Vec<MqttVersion>,
    pub connections: u64,
    pub accepted: u64,
    pub rejected: u64,
    pub publish_c2s: u64,
    pub publish_s2c: u64,
    pub topics_published: u64,
    pub subscriptions: u64,
    pub wildcard: bool,
    pub first_ts_us: i64,
    pub last_ts_us: i64,
}

/// A broker endpoint referenced by another row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct MqttBrokerRef {
    pub ip: String,
    pub port: u16,
}

fn versions(levels: &[u8]) -> Vec<MqttVersion> {
    levels
        .iter()
        .filter_map(|l| MqttVersion::of_level(*l))
        .collect()
}

fn client_info(c: ClientEntry) -> MqttClientInfo {
    MqttClientInfo {
        key: c.key,
        client_id: c.client_id,
        assigned_client_id: c.assigned_client_id,
        addresses: c
            .addresses
            .into_iter()
            .map(|(ip, info)| Endpoint::new(ip, info))
            .collect(),
        address_count: c.address_count,
        usernames: c.usernames,
        brokers: c
            .brokers
            .into_iter()
            .map(|(ip, port)| MqttBrokerRef {
                ip: ip.to_string(),
                port,
            })
            .collect(),
        broker_count: c.broker_count,
        versions: versions(&c.versions),
        connections: c.connections,
        accepted: c.accepted,
        rejected: c.rejected,
        publish_c2s: c.publish_c2s,
        publish_s2c: c.publish_s2c,
        topics_published: c.topics_published,
        subscriptions: c.subscriptions,
        wildcard: c.wildcard,
        first_ts_us: convert::us(c.first_ts),
        last_ts_us: convert::us(c.last_ts),
    }
}

/// One broker endpoint (address, port, transport).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct MqttBrokerInfo {
    pub broker: Endpoint,
    pub port: u16,
    pub transport: MqttTransport,
    /// Public address (signal `public-broker`).
    pub public: bool,
    /// Non-public address joined from a public one (signal `exposed-broker`).
    pub exposed: bool,
    /// Announced on `$SYS/broker/version` (declarative).
    pub software: Option<String>,
    pub versions: Vec<MqttVersion>,
    pub connections: u64,
    pub clients: u64,
    pub anonymous_accepted: u64,
    pub rejected: u64,
    pub messages: u64,
    pub topics: u64,
    pub first_ts_us: i64,
    pub last_ts_us: i64,
}

fn broker_info(b: BrokerEntry) -> MqttBrokerInfo {
    let broker = Endpoint::new(b.ip, b.info);
    let public = broker.category == AddressCategory::Public;
    MqttBrokerInfo {
        exposed: !public && b.public_clients_accepted > 0,
        public,
        broker,
        port: b.port,
        transport: if b.transport == "ws" {
            MqttTransport::Ws
        } else {
            MqttTransport::Tcp
        },
        software: b.software,
        versions: versions(&b.versions),
        connections: b.connections,
        clients: b.clients,
        anonymous_accepted: b.anonymous_accepted,
        rejected: b.rejected,
        messages: b.messages,
        topics: b.topics,
        first_ts_us: convert::us(b.first_ts),
        last_ts_us: convert::us(b.last_ts),
    }
}

/// A node of the topic tree with the totals of its subtree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct MqttTopicNode {
    /// Full path (key of `/mqtt/topics?parent=` and `/mqtt/topics/node?path=`).
    pub path: String,
    /// Last level (may be empty: `a//b`, `/a`).
    pub name: String,
    pub depth: u32,
    /// This exact path was published.
    pub is_topic: bool,
    pub children: u64,
    /// Topics of the subtree, itself included.
    pub topics: u64,
    /// Published by clients, delivered by brokers.
    pub messages_pub: u64,
    pub messages_del: u64,
    pub payload_bytes: u64,
    pub retained: u64,
    pub first_ts_us: i64,
    pub last_ts_us: i64,
}

fn node_info(n: TopicNode) -> MqttTopicNode {
    MqttTopicNode {
        path: n.path,
        name: n.name,
        depth: n.depth,
        is_topic: n.is_topic,
        children: n.children,
        topics: n.topics,
        messages_pub: n.messages_pub,
        messages_del: n.messages_del,
        payload_bytes: n.payload_bytes,
        retained: n.retained,
        first_ts_us: convert::us(n.first_ts),
        last_ts_us: convert::us(n.last_ts),
    }
}

/// A client that published under a node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct MqttTopicPublisher {
    pub client_id: Option<String>,
    pub client: Endpoint,
    pub messages: u64,
}

/// A subscription whose filter covers a node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct MqttTopicSubscriber {
    pub filter: String,
    pub client_id: Option<String>,
    pub client: Endpoint,
}

/// `GET /mqtt/topics/node`: totals, `QoS`, publishers, subscribers, latest messages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct MqttTopicDetail {
    pub node: MqttTopicNode,
    /// Messages per `QoS` (0, 1, 2).
    pub qos: Vec<u64>,
    pub publishers: Vec<MqttTopicPublisher>,
    pub publisher_count: u64,
    pub subscribers: Vec<MqttTopicSubscriber>,
    pub recent: Vec<MqttPacketInfo>,
}

/// A CONNACK code and its connections.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct MqttConnackCount {
    /// Version of the connections (3.x return codes, 5.0 reason codes).
    pub version: Option<MqttVersion>,
    pub code: u8,
    pub count: u64,
}

/// Connections of one signal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct MqttSignalCount {
    pub kind: MqttSignalKind,
    pub connections: u64,
}

/// `GET /mqtt/stats`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct MqttStats {
    pub connections: u64,
    pub tcp: u64,
    pub ws: u64,
    pub v31: u64,
    pub v311: u64,
    pub v5: u64,
    pub unknown_version: u64,
    pub clients: u64,
    pub brokers: u64,
    pub public_brokers: u64,
    pub accepted: u64,
    pub rejected: u64,
    /// Connections without CONNACK.
    pub no_answer: u64,
    pub anonymous_accepted: u64,
    /// Connections carrying a password.
    pub with_password: u64,
    pub publish_c2s: u64,
    pub publish_s2c: u64,
    pub payload_bytes: u64,
    pub subscriptions: u64,
    pub topics: u64,
    /// Most frequent CONNACK codes (at most 10).
    pub connack_codes: Vec<MqttConnackCount>,
    /// Signals with at least one connection.
    pub signals: Vec<MqttSignalCount>,
}

/// One row of a signal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct MqttSignalItem {
    pub client: Option<Endpoint>,
    pub broker: Option<Endpoint>,
    pub broker_port: Option<u16>,
    pub filter: Option<String>,
    pub connections: u64,
}

/// `GET /mqtt/signals`: one entry per signal present, with its rows (at most 50).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct MqttSignal {
    pub kind: MqttSignalKind,
    pub connections: u64,
    pub items: Vec<MqttSignalItem>,
}

// ---- queries -----------------------------------------------------------------------------------

/// A text filter: trimmed, `None` when empty, 400 when too long.
fn text(name: &str, v: Option<String>) -> Result<Option<String>, ApiError> {
    match v.map(|s| s.trim().to_owned()).filter(|s| !s.is_empty()) {
        Some(s) if s.len() > MAX_FILTER_LEN => {
            Err(ApiError::BadRequest(format!("{name}: too long")))
        }
        other => Ok(other),
    }
}

/// An exact value (not trimmed: topics may hold spaces), 400 when too long.
fn exact(name: &str, v: Option<String>) -> Result<Option<String>, ApiError> {
    match v {
        Some(s) if s.len() > MAX_FILTER_LEN => {
            Err(ApiError::BadRequest(format!("{name}: too long")))
        }
        other => Ok(other),
    }
}

fn client_key(v: Option<String>) -> Result<Option<ClientKey>, ApiError> {
    match exact("client", v)? {
        None => Ok(None),
        Some(s) => ClientKey::parse(&s).map(Some).ok_or_else(|| {
            ApiError::BadRequest("client: expected id:<id> or ip:<address>".to_owned())
        }),
    }
}

fn broker_filter(ip: Option<IpAddr>, port: Option<u16>) -> Result<Option<(IpAddr, u16)>, ApiError> {
    match (ip, port) {
        (None, None) => Ok(None),
        (Some(ip), Some(port)) => Ok(Some((ip, port))),
        _ => Err(ApiError::BadRequest(
            "broker and broker_port go together".to_owned(),
        )),
    }
}

fn page_request(limit: Option<u32>, cursor: Option<String>) -> PageRequest {
    PageRequest {
        limit: limit.unwrap_or(0),
        cursor,
    }
}

#[derive(Debug, Default, Deserialize)]
struct ConnectionsQuery {
    limit: Option<u32>,
    cursor: Option<String>,
    q: Option<String>,
    login: Option<LoginQuery>,
    auth: Option<MqttAuth>,
    version: Option<VersionQuery>,
    transport: Option<MqttTransport>,
    broker: Option<IpAddr>,
    broker_port: Option<u16>,
    client: Option<String>,
    signal: Option<MqttSignalKind>,
}

#[derive(Debug, Default, Deserialize)]
struct PacketsQuery {
    limit: Option<u32>,
    cursor: Option<String>,
    #[serde(rename = "type")]
    ptype: Option<MqttPacketType>,
}

#[derive(Debug, Default, Deserialize)]
struct GroupQuery {
    limit: Option<u32>,
    cursor: Option<String>,
    q: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct TopicsQuery {
    limit: Option<u32>,
    cursor: Option<String>,
    /// Absent: first level.
    parent: Option<String>,
    /// Search: topics containing this text (flat list).
    q: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct NodeQuery {
    path: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct MessagesQuery {
    limit: Option<u32>,
    cursor: Option<String>,
    q: Option<String>,
    topic: Option<String>,
    prefix: Option<String>,
    dir: Option<MqttDir>,
    qos: Option<u8>,
    retain: Option<bool>,
    client: Option<String>,
    broker: Option<IpAddr>,
    broker_port: Option<u16>,
    flow: Option<i64>,
}

// ---- handlers ----------------------------------------------------------------------------------

async fn stats(
    State(state): State<Arc<AppState>>,
    UrlPath(id): UrlPath<String>,
    ApiRange(range): ApiRange,
) -> Result<Json<MqttStats>, ApiError> {
    let id = parse_id(&id)?;
    blocking(&state, move |s| {
        let (_, session) = open_ready(s, &id)?;
        let range = range.resolve(&session)?;
        let conn = session.conn();
        let r = mqtt::stats(conn, range)?;
        let mut signals = Vec::new();
        for signal in Signal::ALL {
            let filter = ConnectionFilter {
                signal: Some(signal),
                range,
                ..ConnectionFilter::default()
            };
            let n = mqtt::count_connections(conn, &filter)?;
            if n > 0 {
                signals.push(MqttSignalCount {
                    kind: MqttSignalKind::of(signal),
                    connections: n,
                });
            }
        }
        Ok(MqttStats {
            connections: r.connections,
            tcp: r.tcp,
            ws: r.ws,
            v31: r.v31,
            v311: r.v311,
            v5: r.v5,
            unknown_version: r.unknown_version,
            clients: r.clients,
            brokers: r.brokers,
            public_brokers: r.public_brokers,
            accepted: r.accepted,
            rejected: r.rejected,
            no_answer: r.no_answer,
            anonymous_accepted: r.anonymous_accepted,
            with_password: r.with_password,
            publish_c2s: r.publish_c2s,
            publish_s2c: r.publish_s2c,
            payload_bytes: r.payload_bytes,
            subscriptions: r.subscriptions,
            topics: r.topics,
            connack_codes: r
                .connack_codes
                .into_iter()
                .map(|(level, code, count)| MqttConnackCount {
                    version: level.and_then(MqttVersion::of_level),
                    code,
                    count,
                })
                .collect(),
            signals,
        })
    })
    .await
    .map(Json)
}

async fn connections(
    State(state): State<Arc<AppState>>,
    UrlPath(id): UrlPath<String>,
    ApiQuery(query): ApiQuery<ConnectionsQuery>,
    ApiRange(range): ApiRange,
) -> Result<Json<Page<MqttConnectionInfo>>, ApiError> {
    let id = parse_id(&id)?;
    let mut filter = ConnectionFilter {
        q: text("q", query.q)?,
        login: query.login.map(|l| match l {
            LoginQuery::Accepted => LoginFilter::Accepted,
            LoginQuery::Rejected => LoginFilter::Rejected,
            LoginQuery::None => LoginFilter::None,
        }),
        auth: query.auth.map(MqttAuth::as_str),
        version: query.version.map(|v| match v {
            VersionQuery::V31 => Some(MqttVersion::V31.level()),
            VersionQuery::V311 => Some(MqttVersion::V311.level()),
            VersionQuery::V5 => Some(MqttVersion::V5.level()),
            VersionQuery::Unknown => None,
        }),
        transport: query.transport.map(MqttTransport::as_str),
        broker: broker_filter(query.broker, query.broker_port)?,
        client: client_key(query.client)?,
        signal: query.signal.map(MqttSignalKind::signal),
        range: None,
    };
    let request = page_request(query.limit, query.cursor);
    blocking(&state, move |s| {
        let (_, session) = open_ready(s, &id)?;
        filter.range = range.resolve(&session)?;
        let conn = session.conn();
        let page = mqtt::connections_page(conn, &filter, &request)?;
        Ok(Page {
            items: page.items.iter().map(connection_info).collect(),
            next_cursor: page.next_cursor,
            total_estimate: Some(mqtt::count_connections(conn, &filter)?),
        })
    })
    .await
    .map(Json)
}

async fn connection(
    State(state): State<Arc<AppState>>,
    UrlPath((id, flow)): UrlPath<(String, String)>,
) -> Result<Json<MqttConnectionDetail>, ApiError> {
    let id = parse_id(&id)?;
    let flow: i64 = flow.parse().map_err(|_| ApiError::NotFound)?;
    blocking(&state, move |s| {
        let (_, session) = open_ready(s, &id)?;
        let d = mqtt::connection_detail(session.conn(), flow)?.ok_or(ApiError::NotFound)?;
        let e = d.entry;
        let will = match (&e.will_topic, e.will_payload_len) {
            (Some(topic), Some(len)) => Some(MqttWill {
                topic: topic.clone(),
                qos: e.will_qos.unwrap_or(0),
                retain: e.will_retain.unwrap_or(false),
                payload: payload(e.will_payload.as_deref().unwrap_or_default(), len, None),
            }),
            _ => None,
        };
        Ok(MqttConnectionDetail {
            connection: connection_info(&e),
            protocol_name: e.protocol_name,
            clean_start: e.clean_start,
            keep_alive: e.keep_alive,
            server_keep_alive: e.server_keep_alive,
            session_expiry: e.session_expiry,
            auth_method: e.auth_method,
            password: d.password,
            password_len: e.password_len,
            will,
            connect_props: properties(e.connect_props),
            connack_ts_us: e.connack_ts.map(convert::us),
            session_present: e.session_present,
            connack_props: properties(e.connack_props),
            disconnect_ts_us: e.disconnect_ts.map(convert::us),
            disconnect_by: e.disconnect_by.as_deref().map(MqttDir::parse),
            disconnect_reason: e.disconnect_reason,
            broker_software: e.broker_software,
            pings: e.pings,
            last_ping_ts_us: e.last_ping_ts.map(convert::us),
            packets_c2s: e.packets_c2s,
            packets_s2c: e.packets_s2c,
            bytes_c2s: e.bytes_c2s,
            bytes_s2c: e.bytes_s2c,
            subscribe_count: e.subscribe_count,
            stored_packets: e.stored_packets,
            protocol_errors: e.protocol_errors,
            gaps: e.gaps,
            subscriptions: d
                .subscriptions
                .into_iter()
                .map(|s| MqttSubscriptionInfo {
                    ts_us: convert::us(s.ts),
                    filter: s.filter,
                    qos: s.qos,
                    options: s.options,
                    granted: s.granted,
                    shared_group: s.shared_group,
                    wildcard: s.wildcard,
                    unsubscribed_ts_us: s.unsubscribed_ts.map(convert::us),
                })
                .collect(),
            topics: d
                .topics
                .into_iter()
                .map(|t| MqttConnectionTopic {
                    topic: t.topic,
                    dir: MqttDir::parse(&t.dir),
                    messages: t.messages,
                    payload_bytes: t.payload_bytes,
                    retained: t.retained,
                })
                .collect(),
        })
    })
    .await
    .map(Json)
}

async fn packets(
    State(state): State<Arc<AppState>>,
    UrlPath((id, flow)): UrlPath<(String, String)>,
    ApiQuery(query): ApiQuery<PacketsQuery>,
    ApiRange(range): ApiRange,
) -> Result<Json<Page<MqttPacketInfo>>, ApiError> {
    let id = parse_id(&id)?;
    let flow: i64 = flow.parse().map_err(|_| ApiError::NotFound)?;
    let request = page_request(query.limit, query.cursor);
    let ptype = query.ptype.map(MqttPacketType::code);
    blocking(&state, move |s| {
        let (_, session) = open_ready(s, &id)?;
        let filter = PacketFilter {
            ptype,
            range: range.resolve(&session)?,
        };
        let conn = session.conn();
        let page = mqtt::packets_page(conn, flow, &filter, &request)?;
        Ok(Page {
            items: page.items.into_iter().map(packet_info).collect(),
            next_cursor: page.next_cursor,
            total_estimate: Some(mqtt::count_packets(conn, flow, &filter)?),
        })
    })
    .await
    .map(Json)
}

async fn clients(
    State(state): State<Arc<AppState>>,
    UrlPath(id): UrlPath<String>,
    ApiQuery(query): ApiQuery<GroupQuery>,
    ApiRange(range): ApiRange,
) -> Result<Json<Page<MqttClientInfo>>, ApiError> {
    let id = parse_id(&id)?;
    let q = text("q", query.q)?;
    let request = page_request(query.limit, query.cursor);
    blocking(&state, move |s| {
        let (_, session) = open_ready(s, &id)?;
        let filter = GroupFilter {
            q,
            range: range.resolve(&session)?,
        };
        let conn = session.conn();
        let page = mqtt::clients_page(conn, &filter, &request)?;
        Ok(Page {
            items: page.items.into_iter().map(client_info).collect(),
            next_cursor: page.next_cursor,
            total_estimate: Some(mqtt::count_clients(conn, &filter)?),
        })
    })
    .await
    .map(Json)
}

async fn brokers(
    State(state): State<Arc<AppState>>,
    UrlPath(id): UrlPath<String>,
    ApiQuery(query): ApiQuery<GroupQuery>,
    ApiRange(range): ApiRange,
) -> Result<Json<Page<MqttBrokerInfo>>, ApiError> {
    let id = parse_id(&id)?;
    let q = text("q", query.q)?;
    let request = page_request(query.limit, query.cursor);
    blocking(&state, move |s| {
        let (_, session) = open_ready(s, &id)?;
        let filter = GroupFilter {
            q,
            range: range.resolve(&session)?,
        };
        let conn = session.conn();
        let page = mqtt::brokers_page(conn, &filter, &request)?;
        Ok(Page {
            items: page.items.into_iter().map(broker_info).collect(),
            next_cursor: page.next_cursor,
            total_estimate: Some(mqtt::count_brokers(conn, &filter)?),
        })
    })
    .await
    .map(Json)
}

async fn topics(
    State(state): State<Arc<AppState>>,
    UrlPath(id): UrlPath<String>,
    ApiQuery(query): ApiQuery<TopicsQuery>,
    ApiRange(range): ApiRange,
) -> Result<Json<Page<MqttTopicNode>>, ApiError> {
    let id = parse_id(&id)?;
    let q = text("q", query.q)?;
    let parent = exact("parent", query.parent)?;
    let request = page_request(query.limit, query.cursor);
    blocking(&state, move |s| {
        let (_, session) = open_ready(s, &id)?;
        let range = range.resolve(&session)?;
        let conn = session.conn();
        if let Some(q) = q {
            let items: Vec<MqttTopicNode> = mqtt::topic_search(conn, &q, range)?
                .into_iter()
                .map(node_info)
                .collect();
            let total = u64::try_from(items.len()).unwrap_or(u64::MAX);
            return Ok(Page {
                items,
                next_cursor: None,
                total_estimate: Some(total),
            });
        }
        let page = mqtt::topic_children(conn, parent.as_deref(), range, &request)?;
        Ok(Page {
            items: page.items.into_iter().map(node_info).collect(),
            next_cursor: page.next_cursor,
            total_estimate: None,
        })
    })
    .await
    .map(Json)
}

async fn topic_node(
    State(state): State<Arc<AppState>>,
    UrlPath(id): UrlPath<String>,
    ApiQuery(query): ApiQuery<NodeQuery>,
    ApiRange(range): ApiRange,
) -> Result<Json<MqttTopicDetail>, ApiError> {
    let id = parse_id(&id)?;
    let path = exact("path", query.path)?
        .ok_or_else(|| ApiError::BadRequest("path: required".to_owned()))?;
    blocking(&state, move |s| {
        let (_, session) = open_ready(s, &id)?;
        let range = range.resolve(&session)?;
        let d = mqtt::topic_detail(session.conn(), &path, range)?.ok_or(ApiError::NotFound)?;
        let endpoint = |ip: IpAddr, info: EndpointInfo| Endpoint::new(ip, info);
        Ok(MqttTopicDetail {
            node: node_info(d.node),
            qos: d.qos.to_vec(),
            publishers: d
                .publishers
                .into_iter()
                .map(|p| MqttTopicPublisher {
                    client_id: p.client_id,
                    client: endpoint(p.client_ip, p.info),
                    messages: p.messages,
                })
                .collect(),
            publisher_count: d.publisher_count,
            subscribers: d
                .subscribers
                .into_iter()
                .map(|p| MqttTopicSubscriber {
                    filter: p.filter,
                    client_id: p.client_id,
                    client: endpoint(p.client_ip, p.info),
                })
                .collect(),
            recent: d.recent.into_iter().map(packet_info).collect(),
        })
    })
    .await
    .map(Json)
}

async fn messages(
    State(state): State<Arc<AppState>>,
    UrlPath(id): UrlPath<String>,
    ApiQuery(query): ApiQuery<MessagesQuery>,
    ApiRange(range): ApiRange,
) -> Result<Json<Page<MqttPacketInfo>>, ApiError> {
    let id = parse_id(&id)?;
    if query.qos.is_some_and(|q| q > 2) {
        return Err(ApiError::BadRequest("qos: 0, 1 or 2".to_owned()));
    }
    let mut filter = MessageFilter {
        q: text("q", query.q)?,
        topic: exact("topic", query.topic)?,
        prefix: exact("prefix", query.prefix)?,
        dir: query.dir.map(MqttDir::tag),
        qos: query.qos,
        retain: query.retain,
        client: client_key(query.client)?,
        broker: broker_filter(query.broker, query.broker_port)?,
        flow: query.flow,
        range: None,
    };
    let request = page_request(query.limit, query.cursor);
    blocking(&state, move |s| {
        let (_, session) = open_ready(s, &id)?;
        filter.range = range.resolve(&session)?;
        let conn = session.conn();
        let page = mqtt::messages_page(conn, &filter, &request)?;
        Ok(Page {
            items: page.items.into_iter().map(packet_info).collect(),
            next_cursor: page.next_cursor,
            total_estimate: Some(mqtt::count_messages(conn, &filter)?),
        })
    })
    .await
    .map(Json)
}

async fn signals(
    State(state): State<Arc<AppState>>,
    UrlPath(id): UrlPath<String>,
    ApiRange(range): ApiRange,
) -> Result<Json<Vec<MqttSignal>>, ApiError> {
    let id = parse_id(&id)?;
    blocking(&state, move |s| {
        let (_, session) = open_ready(s, &id)?;
        let range = range.resolve(&session)?;
        let groups = mqtt::signals(session.conn(), range)?;
        Ok(groups
            .into_iter()
            .map(|g| MqttSignal {
                kind: MqttSignalKind::of(g.signal),
                connections: g.connections,
                items: g
                    .items
                    .into_iter()
                    .map(|i| {
                        let (broker, broker_port) = match i.server {
                            Some((ip, port, info)) => (Some(Endpoint::new(ip, info)), Some(port)),
                            None => (None, None),
                        };
                        MqttSignalItem {
                            client: i.client.map(|(ip, info)| Endpoint::new(ip, info)),
                            broker,
                            broker_port,
                            filter: i.filter,
                            connections: i.connections,
                        }
                    })
                    .collect(),
            })
            .collect())
    })
    .await
    .map(Json)
}

#[cfg(test)]
mod tests;
