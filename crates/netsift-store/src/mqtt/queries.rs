//! Read queries of the MQTT view. Time range (ADR-030): connections, clients, brokers, topic
//! aggregates and signals are folded rows (overlap, counters of the whole connection); stored
//! packets and messages are point records (`ts`).

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use rusqlite::types::Value;
use rusqlite::{Connection, OptionalExtension, Row, ToSql, params, params_from_iter};

use super::{MAX_DEPTH, levels};
use crate::connections::EndpointInfo;
use crate::error::{Result, StoreError};
use crate::query::{
    Conditions, Keyset, Page, PageRequest, decode_cursor, encode_cursor, keyset_page,
};
use crate::range::TimeRange;
use crate::records::conversion;

/// Rejected connections of one client to one broker from which the pair is signalled.
pub const AUTH_FAILURES: u64 = 5;
/// Topics returned by a topic search.
pub const MAX_TOPIC_SEARCH: usize = 200;
/// Publishers and subscribers listed in a topic detail.
pub const MAX_TOPIC_PEERS: usize = 20;
/// Latest messages of a topic detail.
pub const MAX_TOPIC_RECENT: usize = 5;
/// Topics read to build a level of the tree under a time range.
pub const MAX_RANGE_TOPICS: usize = 100_000;
/// Rows per signal of [`signals`].
pub const MAX_SIGNAL_ITEMS: usize = 50;
/// Topics of a connection detail.
pub const MAX_DETAIL_TOPICS: usize = 50;
/// Distinct filters read to find the subscribers of a topic.
const MAX_FILTER_SCAN: usize = 10_000;

/// Public addresses (core analyzer category).
const PUBLIC: &str = "(SELECT ip FROM hosts WHERE category = 'public')";

fn unsigned(v: i64) -> u64 {
    u64::try_from(v).unwrap_or(0)
}

fn ip(raw: &str, col: usize) -> rusqlite::Result<IpAddr> {
    raw.parse().map_err(|e| conversion(col, e))
}

fn json_strings(raw: Option<String>, col: usize) -> rusqlite::Result<Vec<String>> {
    match raw {
        None => Ok(Vec::new()),
        Some(raw) => serde_json::from_str(&raw).map_err(|e| conversion(col, e)),
    }
}

fn json_pairs(raw: &str, col: usize) -> rusqlite::Result<Vec<(String, String)>> {
    serde_json::from_str(raw).map_err(|e| conversion(col, e))
}

/// `%q%` with LIKE wildcards escaped; `None` for an empty search.
fn like_pattern(q: Option<&str>) -> Option<String> {
    let q = q.map(str::trim).filter(|q| !q.is_empty())?;
    let mut out = String::with_capacity(q.len() + 2);
    out.push('%');
    for c in q.chars() {
        if matches!(c, '%' | '_' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('%');
    Some(out)
}

fn endpoint_info(r: &Row<'_>, prefix: &str) -> rusqlite::Result<EndpointInfo> {
    let names = format!("{prefix}_names");
    Ok(EndpointInfo {
        names: json_strings(r.get(names.as_str())?, 0)?,
        category: r.get(format!("{prefix}_category").as_str())?,
        country: r.get(format!("{prefix}_country").as_str())?,
    })
}

// ---- signals and filters -----------------------------------------------------------------------

/// A signal of `docs/specs/mqtt.md` (« Signalements »).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Signal {
    /// Accepted without user name, password nor authentication method.
    Anonymous,
    /// Broker of public address, in clear text.
    PublicBroker,
    /// Broker of non-public address, accepted connection from a public client.
    ExposedBroker,
    /// Subscription to `#`, `+/#` or `$SYS/#`.
    Wildcard,
    /// At least [`AUTH_FAILURES`] rejected connections of one client to one broker.
    AuthFailures,
    /// A password in clear text.
    CleartextCredentials,
}

impl Signal {
    pub const ALL: [Self; 6] = [
        Self::Anonymous,
        Self::PublicBroker,
        Self::ExposedBroker,
        Self::Wildcard,
        Self::AuthFailures,
        Self::CleartextCredentials,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Anonymous => "anonymous",
            Self::PublicBroker => "public-broker",
            Self::ExposedBroker => "exposed-broker",
            Self::Wildcard => "wildcard",
            Self::AuthFailures => "auth-failures",
            Self::CleartextCredentials => "cleartext-credentials",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|x| x.as_str() == s)
    }

    /// Condition on a connection `c` (the failures are counted over the whole session).
    fn sql(self) -> &'static str {
        match self {
            Self::Anonymous => "c.auth = 'none' AND c.login = 'accepted'",
            Self::PublicBroker => "c.server_ip IN (SELECT ip FROM hosts WHERE category = 'public')",
            Self::ExposedBroker => {
                "c.login = 'accepted' \
                 AND c.server_ip NOT IN (SELECT ip FROM hosts WHERE category = 'public') \
                 AND c.client_ip IN (SELECT ip FROM hosts WHERE category = 'public')"
            }
            Self::Wildcard => {
                "EXISTS (SELECT 1 FROM mqtt_subscriptions s WHERE s.flow_id = c.flow_id \
                 AND s.wildcard = 1)"
            }
            Self::AuthFailures => {
                "c.login = 'rejected' AND (SELECT count(*) FROM mqtt_connections r \
                 WHERE r.client_ip = c.client_ip AND r.server_ip = c.server_ip \
                 AND r.server_port = c.server_port AND r.login = 'rejected') >= 5"
            }
            Self::CleartextCredentials => "c.has_password = 1",
        }
    }
}

/// Result filter of the connection list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginFilter {
    Accepted,
    Rejected,
    /// No CONNACK seen.
    None,
}

/// Client of the client list (and its filter of the connection list).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientKey {
    /// A non-empty client identifier.
    Id(String),
    /// Connections without identifier (empty, or no CONNECT) from this address.
    Ip(IpAddr),
}

impl ClientKey {
    /// `id:<client id>` or `ip:<address>`.
    pub fn parse(s: &str) -> Option<Self> {
        if let Some(id) = s.strip_prefix("id:") {
            return (!id.is_empty()).then(|| Self::Id(id.to_owned()));
        }
        s.strip_prefix("ip:")?.parse().ok().map(Self::Ip)
    }

    pub fn to_key(&self) -> String {
        match self {
            Self::Id(id) => format!("id:{id}"),
            Self::Ip(ip) => format!("ip:{ip}"),
        }
    }
}

/// SQL of the client key of a connection `c`.
const CLIENT_KEY: &str = "CASE WHEN coalesce(c.client_id, '') = '' THEN 'ip:' || c.client_ip \
    ELSE 'id:' || c.client_id END";

/// Filters of the connection list (all optional, combined with AND).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConnectionFilter {
    /// Text in the addresses, client identifier, user name or WebSocket path.
    pub q: Option<String>,
    pub login: Option<LoginFilter>,
    /// `none`, `username`, `password`, `enhanced`.
    pub auth: Option<&'static str>,
    /// Protocol level (3, 4, 5); `Some(None)`: unknown.
    pub version: Option<Option<u8>>,
    pub transport: Option<&'static str>,
    pub broker: Option<(IpAddr, u16)>,
    pub client: Option<ClientKey>,
    pub signal: Option<Signal>,
    /// One connection (flow id).
    pub flow: Option<i64>,
    pub range: Option<TimeRange>,
}

fn connection_conditions(f: &ConnectionFilter) -> Conditions {
    let mut c = Conditions::new();
    if let Some(p) = like_pattern(f.q.as_deref()) {
        c.push(
            "c.client_ip LIKE ? ESCAPE '\\' OR c.server_ip LIKE ? ESCAPE '\\' \
             OR c.client_id LIKE ? ESCAPE '\\' OR c.username LIKE ? ESCAPE '\\' \
             OR c.ws_path LIKE ? ESCAPE '\\'",
            std::iter::repeat_n(Value::Text(p), 5),
        );
    }
    match f.login {
        Some(LoginFilter::Accepted) => c.push("c.login = 'accepted'", []),
        Some(LoginFilter::Rejected) => c.push("c.login = 'rejected'", []),
        Some(LoginFilter::None) => c.push("c.login IS NULL", []),
        None => {}
    }
    if let Some(a) = f.auth {
        c.push("c.auth = ?", [Value::Text(a.to_owned())]);
    }
    match f.version {
        Some(Some(v)) => c.push("c.version = ?", [Value::Integer(i64::from(v))]),
        Some(None) => c.push("c.version IS NULL", []),
        None => {}
    }
    if let Some(t) = f.transport {
        c.push("c.transport = ?", [Value::Text(t.to_owned())]);
    }
    if let Some((ip, port)) = f.broker {
        c.push(
            "c.server_ip = ? AND c.server_port = ?",
            [Value::Text(ip.to_string()), Value::Integer(i64::from(port))],
        );
    }
    match &f.client {
        Some(ClientKey::Id(id)) => c.push("c.client_id = ?", [Value::Text(id.clone())]),
        Some(ClientKey::Ip(ip)) => c.push(
            "coalesce(c.client_id, '') = '' AND c.client_ip = ?",
            [Value::Text(ip.to_string())],
        ),
        None => {}
    }
    if let Some(s) = f.signal {
        c.push(s.sql(), []);
    }
    if let Some(flow) = f.flow {
        c.push("c.flow_id = ?", [Value::Integer(flow)]);
    }
    if let Some(r) = f.range {
        r.push_overlap(&mut c, "c.first_ts", "c.last_ts");
    }
    c
}

/// Topic flows `t` overlapping `range`: their connection first (the narrow `mqtt_connections`
/// is read by its span index), then the rows of these connections by primary key. Reading the
/// span of `mqtt_topic_flows` itself would scan every row started before the end of the range.
fn push_topic_range(c: &mut Conditions, range: TimeRange) {
    c.push(
        "t.flow_id IN (SELECT r.flow_id FROM mqtt_connections r WHERE r.first_ts < ? \
         AND r.last_ts >= ?) AND t.first_ts < ? AND t.last_ts >= ?",
        [
            Value::Integer(range.to_ns()),
            Value::Integer(range.from_ns()),
            Value::Integer(range.to_ns()),
            Value::Integer(range.from_ns()),
        ],
    );
}

/// Overlap conditions alone (aggregates).
fn range_conditions(range: Option<TimeRange>) -> Conditions {
    let mut c = Conditions::new();
    if let Some(r) = range {
        r.push_overlap(&mut c, "c.first_ts", "c.last_ts");
    }
    c
}

fn where_sql(c: &Conditions) -> String {
    c.sql().map_or_else(String::new, |w| format!(" WHERE {w}"))
}

fn and_sql(c: &Conditions) -> String {
    c.sql().map_or_else(String::new, |w| format!(" AND {w}"))
}

// ---- connections -------------------------------------------------------------------------------

/// A stored connection (without its password) with what the session knows about both ends.
#[allow(clippy::struct_excessive_bools)] // Independent facts about one connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionEntry {
    pub flow_id: i64,
    pub first_ts: i64,
    pub last_ts: i64,
    pub client_ip: IpAddr,
    pub client_port: u16,
    pub server_ip: IpAddr,
    pub server_port: u16,
    pub transport: String,
    pub ws_path: Option<String>,
    pub ws_host: Option<String>,
    pub ws_subprotocol: Option<String>,
    pub ws_close_code: Option<u16>,
    pub ws_compressed: bool,
    pub version: Option<u8>,
    pub bridge: bool,
    pub partial: bool,
    pub protocol_name: Option<String>,
    pub client_id: Option<String>,
    pub assigned_client_id: Option<String>,
    pub clean_start: Option<bool>,
    pub keep_alive: Option<u16>,
    pub server_keep_alive: Option<u16>,
    pub session_expiry: Option<u32>,
    pub username: Option<String>,
    pub has_password: bool,
    pub password_len: Option<u32>,
    pub auth_method: Option<String>,
    pub auth: Option<String>,
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
    pub login: Option<String>,
    pub end_kind: String,
    pub disconnect_ts: Option<i64>,
    pub disconnect_by: Option<String>,
    pub disconnect_reason: Option<u8>,
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
    pub bytes_c2s: u64,
    pub bytes_s2c: u64,
    pub stored_packets: u32,
    pub packets_truncated: bool,
    pub malformed: u32,
    pub protocol_errors: u32,
    pub gaps: u32,
    pub state_dropped: u32,
    pub client: EndpointInfo,
    pub server: EndpointInfo,
    /// A subscription reads every topic.
    pub wildcard: bool,
    /// The pair client, broker has at least [`AUTH_FAILURES`] rejected connections.
    pub auth_failures: bool,
}

const CONNECTION_FROM: &str = "mqtt_connections c \
    LEFT JOIN hosts hc ON hc.ip = c.client_ip LEFT JOIN hosts hs ON hs.ip = c.server_ip";
const CONNECTION_SELECT: &str = "c.*, hc.names AS hc_names, hc.category AS hc_category, \
    hc.country AS hc_country, hs.names AS hs_names, hs.category AS hs_category, \
    hs.country AS hs_country, \
    EXISTS (SELECT 1 FROM mqtt_subscriptions s WHERE s.flow_id = c.flow_id AND s.wildcard = 1) \
    AS wildcard_any, \
    (c.login = 'rejected' AND (SELECT count(*) FROM mqtt_connections r \
     WHERE r.client_ip = c.client_ip AND r.server_ip = c.server_ip \
     AND r.server_port = c.server_port AND r.login = 'rejected') >= 5) AS failures";

fn connection_entry(r: &Row<'_>) -> rusqlite::Result<ConnectionEntry> {
    let client: String = r.get("client_ip")?;
    let server: String = r.get("server_ip")?;
    let connect_props: String = r.get("connect_props")?;
    let connack_props: String = r.get("connack_props")?;
    let u = |name: &str| -> rusqlite::Result<u64> { Ok(unsigned(r.get(name)?)) };
    Ok(ConnectionEntry {
        flow_id: r.get("flow_id")?,
        first_ts: r.get("first_ts")?,
        last_ts: r.get("last_ts")?,
        client_ip: ip(&client, 0)?,
        client_port: r.get("client_port")?,
        server_ip: ip(&server, 0)?,
        server_port: r.get("server_port")?,
        transport: r.get("transport")?,
        ws_path: r.get("ws_path")?,
        ws_host: r.get("ws_host")?,
        ws_subprotocol: r.get("ws_subprotocol")?,
        ws_close_code: r.get("ws_close_code")?,
        ws_compressed: r.get("ws_compressed")?,
        version: r.get("version")?,
        bridge: r.get("bridge")?,
        partial: r.get("partial")?,
        protocol_name: r.get("protocol_name")?,
        client_id: r.get("client_id")?,
        assigned_client_id: r.get("assigned_client_id")?,
        clean_start: r.get("clean_start")?,
        keep_alive: r.get("keep_alive")?,
        server_keep_alive: r.get("server_keep_alive")?,
        session_expiry: r.get("session_expiry")?,
        username: r.get("username")?,
        has_password: r.get("has_password")?,
        password_len: r.get("password_len")?,
        auth_method: r.get("auth_method")?,
        auth: r.get("auth")?,
        will_topic: r.get("will_topic")?,
        will_qos: r.get("will_qos")?,
        will_retain: r.get("will_retain")?,
        will_payload_len: r.get::<_, Option<i64>>("will_payload_len")?.map(unsigned),
        will_payload: r.get("will_payload")?,
        connect_props: json_pairs(&connect_props, 0)?,
        connack_ts: r.get("connack_ts")?,
        connack_code: r.get("connack_code")?,
        session_present: r.get("session_present")?,
        connack_props: json_pairs(&connack_props, 0)?,
        login: r.get("login")?,
        end_kind: r.get("end_kind")?,
        disconnect_ts: r.get("disconnect_ts")?,
        disconnect_by: r.get("disconnect_by")?,
        disconnect_reason: r.get("disconnect_reason")?,
        broker_software: r.get("broker_software")?,
        packets_c2s: u("packets_c2s")?,
        packets_s2c: u("packets_s2c")?,
        publish_c2s: u("publish_c2s")?,
        publish_s2c: u("publish_s2c")?,
        payload_bytes_c2s: u("payload_bytes_c2s")?,
        payload_bytes_s2c: u("payload_bytes_s2c")?,
        subscribe_count: u("subscribe_count")?,
        pings: u("pings")?,
        last_ping_ts: r.get("last_ping_ts")?,
        bytes_c2s: u("bytes_c2s")?,
        bytes_s2c: u("bytes_s2c")?,
        stored_packets: r.get("stored_packets")?,
        packets_truncated: r.get("packets_truncated")?,
        malformed: r.get("malformed")?,
        protocol_errors: r.get("protocol_errors")?,
        gaps: r.get("gaps")?,
        state_dropped: r.get("state_dropped")?,
        client: endpoint_info(r, "hc")?,
        server: endpoint_info(r, "hs")?,
        wildcard: r.get("wildcard_any")?,
        auth_failures: r.get::<_, Option<bool>>("failures")?.unwrap_or(false),
    })
}

/// One page of connections, by start time then flow id.
pub fn connections_page(
    conn: &Connection,
    filter: &ConnectionFilter,
    request: &PageRequest,
) -> Result<Page<ConnectionEntry>> {
    let c = connection_conditions(filter);
    let w = c.sql();
    let query = Keyset {
        from: CONNECTION_FROM,
        select: CONNECTION_SELECT,
        sort: "c.first_ts",
        tiebreak: "c.flow_id",
        descending: false,
        filter: w.as_deref(),
    };
    keyset_page(conn, &query, &c.params(), request, connection_entry)
}

/// Number of connections matching `filter`.
pub fn count_connections(conn: &Connection, filter: &ConnectionFilter) -> Result<u64> {
    let c = connection_conditions(filter);
    let sql = format!("SELECT count(*) FROM mqtt_connections c{}", where_sql(&c));
    let n: i64 = conn.query_row(&sql, c.params().as_slice(), |r| r.get(0))?;
    Ok(unsigned(n))
}

/// A subscription of a connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionEntry {
    pub ts: i64,
    pub filter: String,
    pub qos: u8,
    pub options: u8,
    pub granted: Option<u8>,
    pub shared_group: Option<String>,
    pub wildcard: bool,
    pub unsubscribed_ts: Option<i64>,
}

/// Messages of one topic in one direction of a connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionTopic {
    /// `None`: the other topics (beyond the bound, unresolved aliases).
    pub topic: Option<String>,
    /// `c` published by the client, `b` delivered by the broker.
    pub dir: String,
    pub messages: u64,
    pub payload_bytes: u64,
    pub retained: u64,
}

/// A connection with its password (sensitive: detail route only), subscriptions and topics.
/// `Debug` hides the password.
#[derive(Clone, PartialEq, Eq)]
pub struct ConnectionDetail {
    pub entry: ConnectionEntry,
    pub password: Option<String>,
    pub subscriptions: Vec<SubscriptionEntry>,
    pub topics: Vec<ConnectionTopic>,
}

impl std::fmt::Debug for ConnectionDetail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectionDetail")
            .field("entry", &self.entry)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("subscriptions", &self.subscriptions.len())
            .field("topics", &self.topics.len())
            .finish()
    }
}

/// The connection of flow `flow_id`, `None` when unknown.
pub fn connection_detail(conn: &Connection, flow_id: i64) -> Result<Option<ConnectionDetail>> {
    let sql = format!(
        "SELECT {CONNECTION_SELECT}, x.password AS secret FROM {CONNECTION_FROM} \
         LEFT JOIN mqtt_connect_secrets x ON x.flow_id = c.flow_id WHERE c.flow_id = ?1"
    );
    let row = conn
        .query_row(&sql, params![flow_id], |r| {
            Ok((connection_entry(r)?, r.get::<_, Option<String>>("secret")?))
        })
        .optional()?;
    let Some((entry, password)) = row else {
        return Ok(None);
    };
    let subscriptions = conn
        .prepare(
            "SELECT ts, filter, qos, options, granted, shared_group, wildcard, unsubscribed_ts \
             FROM mqtt_subscriptions WHERE flow_id = ?1 ORDER BY seq, idx",
        )?
        .query_map(params![flow_id], |r| {
            Ok(SubscriptionEntry {
                ts: r.get(0)?,
                filter: r.get(1)?,
                qos: r.get(2)?,
                options: r.get(3)?,
                granted: r.get(4)?,
                shared_group: r.get(5)?,
                wildcard: r.get(6)?,
                unsubscribed_ts: r.get(7)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let topics = conn
        .prepare(
            "SELECT topic, dir, messages, payload_bytes, retained FROM mqtt_topic_flows \
             WHERE flow_id = ?1 ORDER BY messages DESC, topic, dir LIMIT ?2",
        )?
        .query_map(params![flow_id, MAX_DETAIL_TOPICS], |r| {
            let topic: String = r.get(0)?;
            Ok(ConnectionTopic {
                topic: (!topic.is_empty()).then_some(topic),
                dir: r.get(1)?,
                messages: unsigned(r.get(2)?),
                payload_bytes: unsigned(r.get(3)?),
                retained: unsigned(r.get(4)?),
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(Some(ConnectionDetail {
        entry,
        password,
        subscriptions,
        topics,
    }))
}

// ---- packets and messages ----------------------------------------------------------------------

/// A stored packet, with its connection's client identifier and ends (messages list).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketEntry {
    pub id: i64,
    pub flow_id: i64,
    pub seq: u32,
    pub ts: i64,
    pub dir: String,
    pub ptype: u8,
    pub flags: u8,
    pub packet_id: Option<u16>,
    pub qos: Option<u8>,
    pub retain: bool,
    pub dup: bool,
    pub topic: Option<String>,
    pub topic_alias: Option<u16>,
    pub topic_source: Option<String>,
    pub size: u64,
    pub payload_len: Option<u64>,
    pub payload: Option<Vec<u8>>,
    pub payload_format: Option<u8>,
    pub content_type: Option<String>,
    pub reason_code: Option<u8>,
    pub reason_string: Option<String>,
    pub ack_state: Option<String>,
    pub ack_reason: Option<u8>,
    pub ack_ns: Option<i64>,
    /// `(filter, options, granted)`.
    pub filters: Vec<(String, u8, Option<u8>)>,
    pub props: Vec<(String, String)>,
    pub malformed: bool,
    /// From the connection (messages list only; `None` in a transcript).
    pub peer: Option<PacketPeer>,
}

/// Connection of a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketPeer {
    pub client_id: Option<String>,
    pub client_ip: IpAddr,
    pub client: EndpointInfo,
    pub server_ip: IpAddr,
    pub server_port: u16,
    pub server: EndpointInfo,
}

const PACKET_SELECT: &str = "m.id, m.flow_id, m.seq, m.ts, m.dir, m.ptype, m.flags, m.packet_id, \
    m.qos, m.retain, m.dup, m.topic, m.topic_alias, m.topic_source, m.size, m.payload_len, \
    m.payload, m.payload_format, m.content_type, m.reason_code, m.reason_string, m.ack_state, \
    m.ack_reason, m.ack_ns, m.filters, m.props, m.malformed";
const MESSAGE_SELECT: &str = "m.id, m.flow_id, m.seq, m.ts, m.dir, m.ptype, m.flags, m.packet_id, \
    m.qos, m.retain, m.dup, m.topic, m.topic_alias, m.topic_source, m.size, m.payload_len, \
    m.payload, m.payload_format, m.content_type, m.reason_code, m.reason_string, m.ack_state, \
    m.ack_reason, m.ack_ns, m.filters, m.props, m.malformed, c.client_id AS peer_client_id, \
    c.client_ip AS peer_client_ip, c.server_ip AS peer_server_ip, \
    c.server_port AS peer_server_port, hc.names AS hc_names, hc.category AS hc_category, \
    hc.country AS hc_country, hs.names AS hs_names, hs.category AS hs_category, \
    hs.country AS hs_country";
const MESSAGE_FROM: &str = "mqtt_packets m JOIN mqtt_connections c ON c.flow_id = m.flow_id \
    LEFT JOIN hosts hc ON hc.ip = c.client_ip LEFT JOIN hosts hs ON hs.ip = c.server_ip";

fn packet_entry(r: &Row<'_>, with_peer: bool) -> rusqlite::Result<PacketEntry> {
    let filters: String = r.get("filters")?;
    let props: String = r.get("props")?;
    let peer = if with_peer {
        let client: String = r.get("peer_client_ip")?;
        let server: String = r.get("peer_server_ip")?;
        Some(PacketPeer {
            client_id: r.get("peer_client_id")?,
            client_ip: ip(&client, 0)?,
            client: endpoint_info(r, "hc")?,
            server_ip: ip(&server, 0)?,
            server_port: r.get("peer_server_port")?,
            server: endpoint_info(r, "hs")?,
        })
    } else {
        None
    };
    Ok(PacketEntry {
        id: r.get("id")?,
        flow_id: r.get("flow_id")?,
        seq: r.get("seq")?,
        ts: r.get("ts")?,
        dir: r.get("dir")?,
        ptype: r.get("ptype")?,
        flags: r.get("flags")?,
        packet_id: r.get("packet_id")?,
        qos: r.get("qos")?,
        retain: r.get("retain")?,
        dup: r.get("dup")?,
        topic: r.get("topic")?,
        topic_alias: r.get("topic_alias")?,
        topic_source: r.get("topic_source")?,
        size: unsigned(r.get("size")?),
        payload_len: r.get::<_, Option<i64>>("payload_len")?.map(unsigned),
        payload: r.get("payload")?,
        payload_format: r.get("payload_format")?,
        content_type: r.get("content_type")?,
        reason_code: r.get("reason_code")?,
        reason_string: r.get("reason_string")?,
        ack_state: r.get("ack_state")?,
        ack_reason: r.get("ack_reason")?,
        ack_ns: r.get("ack_ns")?,
        filters: serde_json::from_str(&filters).map_err(|e| conversion(0, e))?,
        props: json_pairs(&props, 0)?,
        malformed: r.get("malformed")?,
        peer,
    })
}

/// Filters of a transcript.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PacketFilter {
    pub ptype: Option<u8>,
    pub range: Option<TimeRange>,
}

/// One page of the stored packets of a connection, by `seq`.
pub fn packets_page(
    conn: &Connection,
    flow_id: i64,
    filter: &PacketFilter,
    request: &PageRequest,
) -> Result<Page<PacketEntry>> {
    let mut c = Conditions::new();
    c.push("m.flow_id = ?", [Value::Integer(flow_id)]);
    if let Some(t) = filter.ptype {
        c.push("m.ptype = ?", [Value::Integer(i64::from(t))]);
    }
    if let Some(r) = filter.range {
        r.push_point_scan(&mut c, "m.ts");
    }
    let w = c.sql();
    let query = Keyset {
        from: "mqtt_packets m",
        select: PACKET_SELECT,
        sort: "m.seq",
        tiebreak: "m.id",
        descending: false,
        filter: w.as_deref(),
    };
    keyset_page(conn, &query, &c.params(), request, |r| {
        packet_entry(r, false)
    })
}

/// Number of stored packets of a connection matching `filter`.
pub fn count_packets(conn: &Connection, flow_id: i64, filter: &PacketFilter) -> Result<u64> {
    let mut c = Conditions::new();
    c.push("m.flow_id = ?", [Value::Integer(flow_id)]);
    if let Some(t) = filter.ptype {
        c.push("m.ptype = ?", [Value::Integer(i64::from(t))]);
    }
    if let Some(r) = filter.range {
        r.push_point_scan(&mut c, "m.ts");
    }
    let sql = format!("SELECT count(*) FROM mqtt_packets m{}", where_sql(&c));
    let n: i64 = conn.query_row(&sql, c.params().as_slice(), |r| r.get(0))?;
    Ok(unsigned(n))
}

/// Filters of the message list (stored PUBLISH).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MessageFilter {
    /// Text in the topic or the client identifier (never the payload).
    pub q: Option<String>,
    pub topic: Option<String>,
    /// The topic or any topic below it.
    pub prefix: Option<String>,
    /// `c` (client to broker) or `b`.
    pub dir: Option<&'static str>,
    pub qos: Option<u8>,
    pub retain: Option<bool>,
    pub client: Option<ClientKey>,
    pub broker: Option<(IpAddr, u16)>,
    pub flow: Option<i64>,
    pub range: Option<TimeRange>,
}

/// `[p/, p0)`: the topics below `p` (`0` follows `/`).
fn below(prefix: &str) -> [Value; 2] {
    [
        Value::Text(format!("{prefix}/")),
        Value::Text(format!("{prefix}0")),
    ]
}

fn message_conditions(f: &MessageFilter) -> Conditions {
    let mut c = Conditions::new();
    c.push("m.ptype = 3", []);
    if let Some(p) = like_pattern(f.q.as_deref()) {
        c.push(
            "m.topic LIKE ? ESCAPE '\\' OR c.client_id LIKE ? ESCAPE '\\'",
            [Value::Text(p.clone()), Value::Text(p)],
        );
    }
    if let Some(t) = &f.topic {
        c.push("m.topic = ?", [Value::Text(t.clone())]);
    }
    if let Some(p) = &f.prefix {
        let [lo, hi] = below(p);
        c.push(
            "m.topic = ? OR (m.topic >= ? AND m.topic < ?)",
            [Value::Text(p.clone()), lo, hi],
        );
    }
    if let Some(d) = f.dir {
        c.push("m.dir = ?", [Value::Text(d.to_owned())]);
    }
    if let Some(q) = f.qos {
        c.push("m.qos = ?", [Value::Integer(i64::from(q))]);
    }
    if let Some(r) = f.retain {
        c.push("m.retain = ?", [Value::Integer(i64::from(r))]);
    }
    match &f.client {
        Some(ClientKey::Id(id)) => c.push("c.client_id = ?", [Value::Text(id.clone())]),
        Some(ClientKey::Ip(ip)) => c.push(
            "coalesce(c.client_id, '') = '' AND c.client_ip = ?",
            [Value::Text(ip.to_string())],
        ),
        None => {}
    }
    if let Some((ip, port)) = f.broker {
        c.push(
            "c.server_ip = ? AND c.server_port = ?",
            [Value::Text(ip.to_string()), Value::Integer(i64::from(port))],
        );
    }
    if let Some(flow) = f.flow {
        c.push("m.flow_id = ?", [Value::Integer(flow)]);
    }
    if let Some(r) = f.range {
        r.push_point(&mut c, "m.ts");
    }
    c
}

/// One page of stored messages (PUBLISH), by time then id.
pub fn messages_page(
    conn: &Connection,
    filter: &MessageFilter,
    request: &PageRequest,
) -> Result<Page<PacketEntry>> {
    let c = message_conditions(filter);
    let w = c.sql();
    let query = Keyset {
        from: MESSAGE_FROM,
        select: MESSAGE_SELECT,
        sort: "m.ts",
        tiebreak: "m.id",
        descending: false,
        filter: w.as_deref(),
    };
    keyset_page(conn, &query, &c.params(), request, |r| {
        packet_entry(r, true)
    })
}

/// Number of stored messages matching `filter`.
pub fn count_messages(conn: &Connection, filter: &MessageFilter) -> Result<u64> {
    let c = message_conditions(filter);
    let sql = format!(
        "SELECT count(*) FROM mqtt_packets m JOIN mqtt_connections c ON c.flow_id = m.flow_id{}",
        where_sql(&c)
    );
    let n: i64 = conn.query_row(&sql, c.params().as_slice(), |r| r.get(0))?;
    Ok(unsigned(n))
}

// ---- grouped pages (clients, brokers) ----------------------------------------------------------

/// Text cursor of a grouped page: `(sort, key)` encoded like the keyset cursors.
fn group_cursor(sort: i64, key: &str) -> Result<String> {
    encode_cursor(&Value::Integer(sort), &Value::Text(key.to_owned()))
}

fn read_group_cursor(cursor: Option<&str>) -> Result<Option<(i64, String)>> {
    let Some(cursor) = cursor else {
        return Ok(None);
    };
    match decode_cursor(cursor)? {
        (Value::Integer(a), Value::Text(b)) => Ok(Some((a, b))),
        _ => Err(StoreError::InvalidCursor),
    }
}

/// Connections of one client (grouped by client key).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientEntry {
    pub key: String,
    /// `None`: connections without identifier (or without CONNECT) from one address.
    pub client_id: Option<String>,
    pub assigned_client_id: Option<String>,
    /// At most 8 addresses with what the session knows about them.
    pub addresses: Vec<(IpAddr, EndpointInfo)>,
    pub address_count: u64,
    pub usernames: Vec<String>,
    /// At most 4 brokers (address, port).
    pub brokers: Vec<(IpAddr, u16)>,
    pub broker_count: u64,
    /// Protocol levels seen.
    pub versions: Vec<u8>,
    pub connections: u64,
    pub accepted: u64,
    pub rejected: u64,
    pub publish_c2s: u64,
    pub publish_s2c: u64,
    pub topics_published: u64,
    pub subscriptions: u64,
    pub wildcard: bool,
    pub first_ts: i64,
    pub last_ts: i64,
}

/// Filters of the client and broker lists.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GroupFilter {
    pub q: Option<String>,
    pub range: Option<TimeRange>,
}

fn group_conditions(f: &GroupFilter) -> Conditions {
    let mut c = Conditions::new();
    if let Some(p) = like_pattern(f.q.as_deref()) {
        c.push(
            "c.client_ip LIKE ? ESCAPE '\\' OR c.server_ip LIKE ? ESCAPE '\\' \
             OR c.client_id LIKE ? ESCAPE '\\' OR c.username LIKE ? ESCAPE '\\' \
             OR c.broker_software LIKE ? ESCAPE '\\'",
            std::iter::repeat_n(Value::Text(p), 5),
        );
    }
    if let Some(r) = f.range {
        r.push_overlap(&mut c, "c.first_ts", "c.last_ts");
    }
    c
}

fn host_info(conn: &Connection, ip: &str) -> Result<EndpointInfo> {
    Ok(conn
        .query_row(
            "SELECT names, category, country FROM hosts WHERE ip = ?1",
            params![ip],
            |r| {
                Ok(EndpointInfo {
                    names: json_strings(r.get(0)?, 0)?,
                    category: r.get(1)?,
                    country: r.get(2)?,
                })
            },
        )
        .optional()?
        .unwrap_or_default())
}

/// Distinct topics published (or delivered) on the flows of a JSON array.
fn topics_of_flows(conn: &Connection, flows: &str, dir: &str) -> Result<u64> {
    let n: i64 = conn.query_row(
        "SELECT count(DISTINCT topic) FROM mqtt_topic_flows WHERE dir = ?2 AND topic != '' \
         AND flow_id IN (SELECT value FROM json_each(?1))",
        params![flows, dir],
        |r| r.get(0),
    )?;
    Ok(unsigned(n))
}

/// One page of clients, by key.
#[allow(clippy::too_many_lines, clippy::items_after_statements)] // One grouped query, then the rows.
pub fn clients_page(
    conn: &Connection,
    filter: &GroupFilter,
    request: &PageRequest,
) -> Result<Page<ClientEntry>> {
    let c = group_conditions(filter);
    let cursor = read_group_cursor(request.cursor.as_deref())?;
    let limit = request.effective_limit();
    let having = if cursor.is_some() {
        " HAVING ckey > ?"
    } else {
        ""
    };
    let sql = format!(
        "SELECT {CLIENT_KEY} AS ckey, max(nullif(c.client_id, '')), max(c.assigned_client_id), \
         json_group_array(DISTINCT c.client_ip), count(DISTINCT c.client_ip), \
         json_group_array(DISTINCT c.username) FILTER (WHERE c.username IS NOT NULL), \
         json_group_array(DISTINCT c.server_ip || ' ' || c.server_port), \
         count(DISTINCT c.server_ip || ' ' || c.server_port), \
         json_group_array(DISTINCT c.version) FILTER (WHERE c.version IS NOT NULL), count(*), \
         coalesce(sum(c.login = 'accepted'), 0), coalesce(sum(c.login = 'rejected'), 0), \
         sum(c.publish_c2s), sum(c.publish_s2c), sum(c.subscribe_count), min(c.first_ts), \
         max(c.last_ts), json_group_array(c.flow_id) FROM mqtt_connections c{} \
         GROUP BY ckey{having} ORDER BY ckey LIMIT ?",
        where_sql(&c)
    );
    let fetch = i64::from(limit) + 1;
    let mut all: Vec<&dyn ToSql> = c.params();
    if let Some((_, key)) = &cursor {
        all.push(key);
    }
    all.push(&fetch);
    struct Raw {
        key: String,
        client_id: Option<String>,
        assigned: Option<String>,
        ips: String,
        ip_count: i64,
        users: Option<String>,
        brokers: String,
        broker_count: i64,
        versions: Option<String>,
        connections: i64,
        accepted: i64,
        rejected: i64,
        c2s: i64,
        s2c: i64,
        subs: i64,
        first: i64,
        last: i64,
        flows: String,
    }
    let raws = conn
        .prepare(&sql)?
        .query_map(all.as_slice(), |r| {
            Ok(Raw {
                key: r.get(0)?,
                client_id: r.get(1)?,
                assigned: r.get(2)?,
                ips: r.get(3)?,
                ip_count: r.get(4)?,
                users: r.get(5)?,
                brokers: r.get(6)?,
                broker_count: r.get(7)?,
                versions: r.get(8)?,
                connections: r.get(9)?,
                accepted: r.get(10)?,
                rejected: r.get(11)?,
                c2s: r.get(12)?,
                s2c: r.get(13)?,
                subs: r.get(14)?,
                first: r.get(15)?,
                last: r.get(16)?,
                flows: r.get(17)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let more = raws.len() > usize::try_from(limit).unwrap_or(usize::MAX);
    let mut items = Vec::new();
    for raw in raws
        .into_iter()
        .take(usize::try_from(limit).unwrap_or(usize::MAX))
    {
        let ips: Vec<String> = serde_json::from_str(&raw.ips)?;
        let mut addresses = Vec::new();
        for text in ips.iter().take(8) {
            let addr: IpAddr = text.parse().map_err(|_| StoreError::InvalidValue {
                field: "client_ip",
                reason: "not an address",
            })?;
            addresses.push((addr, host_info(conn, text)?));
        }
        let brokers: Vec<String> = serde_json::from_str(&raw.brokers)?;
        let brokers = brokers
            .iter()
            .take(4)
            .filter_map(|b| {
                let (a, p) = b.split_once(' ')?;
                Some((a.parse().ok()?, p.parse().ok()?))
            })
            .collect();
        let mut usernames: Vec<String> = match raw.users {
            Some(u) => serde_json::from_str(&u)?,
            None => Vec::new(),
        };
        usernames.truncate(4);
        let mut versions: Vec<u8> = match raw.versions {
            Some(v) => serde_json::from_str(&v)?,
            None => Vec::new(),
        };
        versions.sort_unstable();
        let wildcard: bool = conn.query_row(
            "SELECT EXISTS (SELECT 1 FROM mqtt_subscriptions WHERE wildcard = 1 \
             AND flow_id IN (SELECT value FROM json_each(?1)))",
            params![raw.flows],
            |r| r.get(0),
        )?;
        items.push(ClientEntry {
            client_id: raw
                .key
                .starts_with("id:")
                .then(|| raw.client_id.clone())
                .flatten(),
            assigned_client_id: raw.assigned,
            addresses,
            address_count: unsigned(raw.ip_count),
            usernames,
            brokers,
            broker_count: unsigned(raw.broker_count),
            versions,
            connections: unsigned(raw.connections),
            accepted: unsigned(raw.accepted),
            rejected: unsigned(raw.rejected),
            publish_c2s: unsigned(raw.c2s),
            publish_s2c: unsigned(raw.s2c),
            topics_published: topics_of_flows(conn, &raw.flows, "c")?,
            subscriptions: unsigned(raw.subs),
            wildcard,
            first_ts: raw.first,
            last_ts: raw.last,
            key: raw.key,
        });
    }
    let next_cursor = match (more, items.last()) {
        (true, Some(last)) => Some(group_cursor(0, &last.key)?),
        _ => None,
    };
    Ok(Page { items, next_cursor })
}

/// Number of clients (client keys) matching `filter`.
pub fn count_clients(conn: &Connection, filter: &GroupFilter) -> Result<u64> {
    let c = group_conditions(filter);
    let sql = format!(
        "SELECT count(DISTINCT {CLIENT_KEY}) FROM mqtt_connections c{}",
        where_sql(&c)
    );
    let n: i64 = conn.query_row(&sql, c.params().as_slice(), |r| r.get(0))?;
    Ok(unsigned(n))
}

/// Connections of one broker endpoint (address, port, transport).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrokerEntry {
    pub ip: IpAddr,
    pub port: u16,
    pub transport: String,
    pub info: EndpointInfo,
    pub software: Option<String>,
    pub versions: Vec<u8>,
    pub connections: u64,
    pub clients: u64,
    pub anonymous_accepted: u64,
    pub rejected: u64,
    /// Accepted connections from public addresses.
    pub public_clients_accepted: u64,
    pub messages: u64,
    pub first_ts: i64,
    pub last_ts: i64,
}

const BROKER_KEY: &str = "c.server_ip || ' ' || c.server_port || ' ' || c.transport";

/// One page of brokers, by connections (descending) then key.
#[allow(clippy::too_many_lines, clippy::items_after_statements)] // One grouped query, then the rows.
pub fn brokers_page(
    conn: &Connection,
    filter: &GroupFilter,
    request: &PageRequest,
) -> Result<Page<BrokerEntry>> {
    let c = group_conditions(filter);
    let cursor = read_group_cursor(request.cursor.as_deref())?;
    let limit = request.effective_limit();
    let having = if cursor.is_some() {
        " HAVING (count(*) < ? OR (count(*) = ? AND bkey > ?))"
    } else {
        ""
    };
    let sql = format!(
        "SELECT {BROKER_KEY} AS bkey, c.server_ip, c.server_port, c.transport, \
         max(c.broker_software), json_group_array(DISTINCT c.version) FILTER \
         (WHERE c.version IS NOT NULL), count(*), count(DISTINCT c.client_ip), \
         coalesce(sum(c.auth = 'none' AND c.login = 'accepted'), 0), \
         coalesce(sum(c.login = 'rejected'), 0), \
         coalesce(sum(c.login = 'accepted' AND c.client_ip IN {PUBLIC}), 0), \
         sum(c.publish_c2s + c.publish_s2c), min(c.first_ts), max(c.last_ts) \
         FROM mqtt_connections c{} GROUP BY bkey{having} ORDER BY count(*) DESC, bkey LIMIT ?",
        where_sql(&c)
    );
    let fetch = i64::from(limit) + 1;
    let mut all: Vec<&dyn ToSql> = c.params();
    if let Some((n, key)) = &cursor {
        all.push(n);
        all.push(n);
        all.push(key);
    }
    all.push(&fetch);
    type Raw = (
        String,
        String,
        u16,
        String,
        Option<String>,
        Option<String>,
        i64,
        i64,
        i64,
        i64,
        i64,
        i64,
        i64,
        i64,
    );
    let raws: Vec<Raw> = conn
        .prepare(&sql)?
        .query_map(all.as_slice(), |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
                r.get(6)?,
                r.get(7)?,
                r.get(8)?,
                r.get(9)?,
                r.get(10)?,
                r.get(11)?,
                r.get(12)?,
                r.get(13)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let more = raws.len() > usize::try_from(limit).unwrap_or(usize::MAX);
    let mut items = Vec::new();
    let mut last_key = None;
    for raw in raws
        .into_iter()
        .take(usize::try_from(limit).unwrap_or(usize::MAX))
    {
        let (
            key,
            server_ip,
            port,
            transport,
            software,
            versions,
            connections,
            clients,
            anon,
            rejected,
            public,
            messages,
            first,
            last,
        ) = raw;
        let addr: IpAddr = server_ip.parse().map_err(|_| StoreError::InvalidValue {
            field: "server_ip",
            reason: "not an address",
        })?;
        let mut versions: Vec<u8> = match versions {
            Some(v) => serde_json::from_str(&v)?,
            None => Vec::new(),
        };
        versions.sort_unstable();
        items.push(BrokerEntry {
            ip: addr,
            port,
            transport,
            info: host_info(conn, &server_ip)?,
            software,
            versions,
            connections: unsigned(connections),
            clients: unsigned(clients),
            anonymous_accepted: unsigned(anon),
            rejected: unsigned(rejected),
            public_clients_accepted: unsigned(public),
            messages: unsigned(messages),
            first_ts: first,
            last_ts: last,
        });
        last_key = Some((connections, key));
    }
    let next_cursor = match (more, last_key) {
        (true, Some((n, key))) => Some(group_cursor(n, &key)?),
        _ => None,
    };
    Ok(Page { items, next_cursor })
}

/// Number of brokers matching `filter`.
pub fn count_brokers(conn: &Connection, filter: &GroupFilter) -> Result<u64> {
    let c = group_conditions(filter);
    let sql = format!(
        "SELECT count(DISTINCT {BROKER_KEY}) FROM mqtt_connections c{}",
        where_sql(&c)
    );
    let n: i64 = conn.query_row(&sql, c.params().as_slice(), |r| r.get(0))?;
    Ok(unsigned(n))
}

// ---- topics --------------------------------------------------------------------------------

/// A node of the topic tree with the totals of its subtree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopicNode {
    pub path: String,
    pub name: String,
    pub depth: u32,
    pub is_topic: bool,
    pub children: u64,
    pub topics: u64,
    pub messages_pub: u64,
    pub messages_del: u64,
    pub payload_bytes: u64,
    pub retained: u64,
    pub first_ts: i64,
    pub last_ts: i64,
}

fn node_row(r: &Row<'_>) -> rusqlite::Result<TopicNode> {
    Ok(TopicNode {
        path: r.get(0)?,
        name: r.get(1)?,
        depth: r.get(2)?,
        is_topic: r.get(3)?,
        children: unsigned(r.get(4)?),
        topics: unsigned(r.get(5)?),
        messages_pub: unsigned(r.get(6)?),
        messages_del: unsigned(r.get(7)?),
        payload_bytes: unsigned(r.get(8)?),
        retained: unsigned(r.get(9)?),
        first_ts: r.get(10)?,
        last_ts: r.get(11)?,
    })
}

const NODE_SELECT: &str = "path, name, depth, is_topic, children, topics, messages_pub, \
    messages_del, payload_bytes, retained, first_ts, last_ts";

/// One topic aggregated over the connections of a range.
struct TopicSum {
    topic: String,
    messages_pub: u64,
    messages_del: u64,
    payload_bytes: u64,
    retained: u64,
    first_ts: i64,
    last_ts: i64,
}

/// Topics (summed over their connections) of the topic flows overlapping `range`, below
/// `parent` and containing `q` when set: at most [`MAX_RANGE_TOPICS`] (the first by name), and
/// whether more were left out.
fn topic_sums(
    conn: &Connection,
    parent: Option<&str>,
    q: Option<&str>,
    range: TimeRange,
) -> Result<(Vec<TopicSum>, bool)> {
    let mut c = Conditions::new();
    c.push("t.topic != ''", []);
    if let Some(p) = parent {
        let [lo, hi] = below(p);
        c.push("t.topic >= ? AND t.topic < ?", [lo, hi]);
    }
    if let Some(pattern) = like_pattern(q) {
        c.push("t.topic LIKE ? ESCAPE '\\'", [Value::Text(pattern)]);
    }
    push_topic_range(&mut c, range);
    let sql = format!(
        "SELECT t.topic, sum(CASE WHEN t.dir = 'c' THEN t.messages ELSE 0 END), \
         sum(CASE WHEN t.dir = 'b' THEN t.messages ELSE 0 END), sum(t.payload_bytes), \
         sum(t.retained), min(t.first_ts), max(t.last_ts) FROM mqtt_topic_flows t{} \
         GROUP BY t.topic ORDER BY t.topic LIMIT {}",
        where_sql(&c),
        MAX_RANGE_TOPICS.saturating_add(1)
    );
    let mut sums = conn
        .prepare(&sql)?
        .query_map(c.params().as_slice(), |r| {
            Ok(TopicSum {
                topic: r.get(0)?,
                messages_pub: unsigned(r.get(1)?),
                messages_del: unsigned(r.get(2)?),
                payload_bytes: unsigned(r.get(3)?),
                retained: unsigned(r.get(4)?),
                first_ts: r.get(5)?,
                last_ts: r.get(6)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let partial = sums.len() > MAX_RANGE_TOPICS;
    sums.truncate(MAX_RANGE_TOPICS);
    Ok((sums, partial))
}

/// One page of a level of the topic tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopicLevel {
    pub page: Page<TopicNode>,
    /// Under a range, more than [`MAX_RANGE_TOPICS`] topics were below the parent: the level is
    /// built from the first ones by name.
    pub partial: bool,
}

/// Children of `parent` (`None`: first level), by name. Without range they are read from the
/// tree of the step `mqtt`; under a range they are recomputed from the topic flows that overlap
/// it (counters of whole connections).
pub fn topic_children(
    conn: &Connection,
    parent: Option<&str>,
    range: Option<TimeRange>,
    request: &PageRequest,
) -> Result<TopicLevel> {
    let Some(range) = range else {
        let mut c = Conditions::new();
        match parent {
            Some(p) => c.push("parent = ?", [Value::Text(p.to_owned())]),
            None => c.push("parent IS NULL", []),
        }
        let w = c.sql();
        let query = Keyset {
            from: "mqtt_topics",
            select: NODE_SELECT,
            sort: "name",
            tiebreak: "path",
            descending: false,
            filter: w.as_deref(),
        };
        return Ok(TopicLevel {
            page: keyset_page(conn, &query, &c.params(), request, node_row)?,
            partial: false,
        });
    };
    let depth = parent.map_or(0, |p| levels(p).len());
    let mut nodes: BTreeMap<String, (TopicNode, BTreeSet<String>)> = BTreeMap::new();
    let (sums, partial) = topic_sums(conn, parent, None, range)?;
    for t in sums {
        let parts = levels(&t.topic);
        let Some(name) = parts.get(depth) else {
            continue;
        };
        let path = parts.get(..=depth).map(|p| p.join("/")).unwrap_or_default();
        let entry = nodes.entry((*name).to_owned()).or_insert_with(|| {
            (
                TopicNode {
                    path,
                    name: (*name).to_owned(),
                    depth: u32::try_from(depth.saturating_add(1)).unwrap_or(u32::MAX),
                    is_topic: false,
                    children: 0,
                    topics: 0,
                    messages_pub: 0,
                    messages_del: 0,
                    payload_bytes: 0,
                    retained: 0,
                    first_ts: t.first_ts,
                    last_ts: t.last_ts,
                },
                BTreeSet::new(),
            )
        });
        let (node, children) = entry;
        node.topics = node.topics.saturating_add(1);
        node.messages_pub = node.messages_pub.saturating_add(t.messages_pub);
        node.messages_del = node.messages_del.saturating_add(t.messages_del);
        node.payload_bytes = node.payload_bytes.saturating_add(t.payload_bytes);
        node.retained = node.retained.saturating_add(t.retained);
        node.first_ts = node.first_ts.min(t.first_ts);
        node.last_ts = node.last_ts.max(t.last_ts);
        match parts.get(depth.saturating_add(1)) {
            Some(child) => {
                children.insert((*child).to_owned());
            }
            None => node.is_topic = true,
        }
    }
    let after = read_group_cursor(request.cursor.as_deref())?.map(|(_, k)| k);
    let limit = usize::try_from(request.effective_limit()).unwrap_or(usize::MAX);
    let mut items: Vec<TopicNode> = nodes
        .into_iter()
        .filter(|(name, _)| after.as_ref().is_none_or(|a| name > a))
        .map(|(_, (mut node, children))| {
            node.children = u64::try_from(children.len()).unwrap_or(u64::MAX);
            node
        })
        .take(limit.saturating_add(1))
        .collect();
    let more = items.len() > limit;
    items.truncate(limit);
    let next_cursor = match (more, items.last()) {
        (true, Some(last)) => Some(group_cursor(0, &last.name)?),
        _ => None,
    };
    Ok(TopicLevel {
        page: Page { items, next_cursor },
        partial,
    })
}

/// Topics containing `q` (at most [`MAX_TOPIC_SEARCH`]), as nodes, by path.
pub fn topic_search(
    conn: &Connection,
    q: &str,
    range: Option<TimeRange>,
) -> Result<Vec<TopicNode>> {
    let Some(pattern) = like_pattern(Some(q)) else {
        return Ok(Vec::new());
    };
    let Some(range) = range else {
        return Ok(conn
            .prepare(&format!(
                "SELECT {NODE_SELECT} FROM mqtt_topics WHERE is_topic = 1 \
                 AND path LIKE ?1 ESCAPE '\\' ORDER BY path LIMIT ?2"
            ))?
            .query_map(params![pattern, MAX_TOPIC_SEARCH], node_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?);
    };
    let mut out: Vec<TopicNode> = topic_sums(conn, None, Some(q), range)?
        .0
        .into_iter()
        .map(|t| {
            let parts = levels(&t.topic);
            TopicNode {
                name: parts.last().map(|s| (*s).to_owned()).unwrap_or_default(),
                depth: u32::try_from(parts.len()).unwrap_or(u32::MAX),
                path: t.topic,
                is_topic: true,
                children: 0,
                topics: 1,
                messages_pub: t.messages_pub,
                messages_del: t.messages_del,
                payload_bytes: t.payload_bytes,
                retained: t.retained,
                first_ts: t.first_ts,
                last_ts: t.last_ts,
            }
        })
        .collect();
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out.truncate(MAX_TOPIC_SEARCH);
    Ok(out)
}

/// True when the topic filter `filter` matches `topic` (OASIS MQTT 3.1.1 section 4.7):
/// `+` one level, `#` the rest (the parent level included); a topic starting with `$` is not
/// matched by a filter starting with a wildcard. The `$share/<group>/` prefix is ignored.
pub fn topic_matches(filter: &str, topic: &str) -> bool {
    let filter = filter
        .strip_prefix("$share/")
        .and_then(|rest| rest.split_once('/').map(|(_, f)| f))
        .unwrap_or(filter);
    if topic.starts_with('$') && (filter.starts_with('+') || filter.starts_with('#')) {
        return false;
    }
    let mut f = filter.split('/');
    let mut t = topic.split('/');
    loop {
        match (f.next(), t.next()) {
            (Some("#"), _) | (None, None) => return true,
            (Some("+"), Some(_)) => {}
            (Some(a), Some(b)) if a == b => {}
            _ => return false,
        }
    }
}

/// Who published under a node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopicPublisher {
    pub client_id: Option<String>,
    pub client_ip: IpAddr,
    pub info: EndpointInfo,
    pub messages: u64,
}

/// A subscription whose filter covers a node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopicSubscriber {
    pub filter: String,
    pub client_id: Option<String>,
    pub client_ip: IpAddr,
    pub info: EndpointInfo,
}

/// Detail of a node: totals, publishers, subscribers, latest messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopicDetail {
    pub node: TopicNode,
    pub qos: [u64; 3],
    pub publishers: Vec<TopicPublisher>,
    pub publisher_count: u64,
    pub subscribers: Vec<TopicSubscriber>,
    pub recent: Vec<PacketEntry>,
}

/// Detail of the node `path` (exact topic and subtree), `None` when nothing was published there.
#[allow(clippy::too_many_lines)] // Totals, publishers, subscribers, latest messages.
pub fn topic_detail(
    conn: &Connection,
    path: &str,
    range: Option<TimeRange>,
) -> Result<Option<TopicDetail>> {
    let mut c = Conditions::new();
    let [lo, hi] = below(path);
    c.push(
        "(t.topic = ? OR (t.topic >= ? AND t.topic < ?))",
        [Value::Text(path.to_owned()), lo, hi],
    );
    if let Some(r) = range {
        push_topic_range(&mut c, r);
    }
    let w = where_sql(&c);
    let sql = format!(
        "SELECT count(DISTINCT t.topic), \
         coalesce(sum(CASE WHEN t.dir = 'c' THEN t.messages ELSE 0 END), 0), \
         coalesce(sum(CASE WHEN t.dir = 'b' THEN t.messages ELSE 0 END), 0), \
         coalesce(sum(t.payload_bytes), 0), coalesce(sum(t.retained), 0), min(t.first_ts), \
         max(t.last_ts), coalesce(sum(t.qos0), 0), coalesce(sum(t.qos1), 0), \
         coalesce(sum(t.qos2), 0), max(t.topic = ?) FROM mqtt_topic_flows t{w}"
    );
    let mut all: Vec<&dyn ToSql> = vec![&path];
    // `max(t.topic = ?)` comes first in the text: bind it first.
    let params = c.params();
    all.extend(params.iter().copied());
    let totals = conn.query_row(&sql, all.as_slice(), |r| {
        Ok((
            unsigned(r.get(0)?),
            unsigned(r.get(1)?),
            unsigned(r.get(2)?),
            unsigned(r.get(3)?),
            unsigned(r.get(4)?),
            r.get::<_, Option<i64>>(5)?,
            r.get::<_, Option<i64>>(6)?,
            [
                unsigned(r.get(7)?),
                unsigned(r.get(8)?),
                unsigned(r.get(9)?),
            ],
            r.get::<_, Option<bool>>(10)?.unwrap_or(false),
        ))
    })?;
    let (topics, mpub, mdel, bytes, retained, first, last, qos, exact) = totals;
    let (Some(first_ts), Some(last_ts)) = (first, last) else {
        return Ok(None);
    };
    let parts = levels(path);
    let children: i64 = conn.query_row(
        "SELECT count(*) FROM mqtt_topics WHERE parent = ?1",
        params![path],
        |r| r.get(0),
    )?;
    let node = TopicNode {
        path: path.to_owned(),
        name: parts.last().map(|s| (*s).to_owned()).unwrap_or_default(),
        depth: u32::try_from(parts.len().min(MAX_DEPTH)).unwrap_or(u32::MAX),
        is_topic: exact,
        children: unsigned(children),
        topics,
        messages_pub: mpub,
        messages_del: mdel,
        payload_bytes: bytes,
        retained,
        first_ts,
        last_ts,
    };
    let peers = format!(
        "SELECT c.client_id, c.client_ip, sum(t.messages) AS n, hc.names AS hc_names, \
         hc.category AS hc_category, hc.country AS hc_country FROM mqtt_topic_flows t \
         JOIN mqtt_connections c ON c.flow_id = t.flow_id LEFT JOIN hosts hc ON hc.ip = c.client_ip \
         {w} AND t.dir = 'c' GROUP BY c.client_id, c.client_ip ORDER BY n DESC, c.client_ip LIMIT {MAX_TOPIC_PEERS}"
    );
    let publishers = conn
        .prepare(&peers)?
        .query_map(c.params().as_slice(), |r| {
            let addr: String = r.get(1)?;
            Ok(TopicPublisher {
                client_id: r.get(0)?,
                client_ip: ip(&addr, 1)?,
                messages: unsigned(r.get(2)?),
                info: endpoint_info(r, "hc")?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let count_sql = format!(
        "SELECT count(*) FROM (SELECT 1 FROM mqtt_topic_flows t \
         JOIN mqtt_connections c ON c.flow_id = t.flow_id {w} AND t.dir = 'c' \
         GROUP BY c.client_id, c.client_ip)"
    );
    let publisher_count: i64 = conn.query_row(&count_sql, c.params().as_slice(), |r| r.get(0))?;
    // Subscribers: the distinct filters (bounded) matched here, then their subscriptions.
    let filters: Vec<String> = conn
        .prepare("SELECT DISTINCT filter FROM mqtt_subscriptions LIMIT ?1")?
        .query_map(params![MAX_FILTER_SCAN], |r| r.get(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let matched: Vec<String> = filters
        .into_iter()
        .filter(|f| topic_matches(f, path))
        .take(MAX_TOPIC_PEERS)
        .collect();
    let subscribers = if matched.is_empty() {
        Vec::new()
    } else {
        let marks = vec!["?"; matched.len()].join(", ");
        let sql = format!(
            "SELECT s.filter, c.client_id, c.client_ip, hc.names AS hc_names, \
             hc.category AS hc_category, hc.country AS hc_country FROM mqtt_subscriptions s \
             JOIN mqtt_connections c ON c.flow_id = s.flow_id \
             LEFT JOIN hosts hc ON hc.ip = c.client_ip WHERE s.filter IN ({marks}) \
             GROUP BY s.filter, c.client_id, c.client_ip ORDER BY s.filter, c.client_ip LIMIT {MAX_TOPIC_PEERS}"
        );
        conn.prepare(&sql)?
            .query_map(params_from_iter(matched.iter()), |r| {
                let addr: String = r.get(2)?;
                Ok(TopicSubscriber {
                    filter: r.get(0)?,
                    client_id: r.get(1)?,
                    client_ip: ip(&addr, 2)?,
                    info: endpoint_info(r, "hc")?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    let mut recent_filter = MessageFilter {
        range,
        ..MessageFilter::default()
    };
    if exact && topics == 1 {
        recent_filter.topic = Some(path.to_owned());
    } else {
        recent_filter.prefix = Some(path.to_owned());
    }
    let mc = message_conditions(&recent_filter);
    let sql = format!(
        "SELECT {MESSAGE_SELECT} FROM {MESSAGE_FROM}{} ORDER BY m.ts DESC, m.id DESC LIMIT {MAX_TOPIC_RECENT}",
        where_sql(&mc)
    );
    let recent = conn
        .prepare(&sql)?
        .query_map(mc.params().as_slice(), |r| packet_entry(r, true))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(Some(TopicDetail {
        node,
        qos,
        publishers,
        publisher_count: unsigned(publisher_count),
        subscribers,
        recent,
    }))
}

// ---- statistics and signals --------------------------------------------------------------------

/// Counters of the MQTT view (connections overlapping `range` when set).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StatsRow {
    pub connections: u64,
    pub tcp: u64,
    pub ws: u64,
    /// Connections per protocol level (3, 4, 5) and unknown.
    pub v31: u64,
    pub v311: u64,
    pub v5: u64,
    pub unknown_version: u64,
    pub clients: u64,
    pub brokers: u64,
    pub public_brokers: u64,
    pub accepted: u64,
    pub rejected: u64,
    pub no_answer: u64,
    pub anonymous_accepted: u64,
    pub with_password: u64,
    pub publish_c2s: u64,
    pub publish_s2c: u64,
    pub payload_bytes: u64,
    pub subscriptions: u64,
    pub topics: u64,
    /// CONNACK codes `(level, code, connections)`, most frequent first (at most 10).
    pub connack_codes: Vec<(Option<u8>, u8, u64)>,
}

/// Counters for the view.
pub fn stats(conn: &Connection, range: Option<TimeRange>) -> Result<StatsRow> {
    let c = range_conditions(range);
    let w = where_sql(&c);
    let sql = format!(
        "SELECT count(*), coalesce(sum(c.transport = 'tcp'), 0), coalesce(sum(c.transport = 'ws'), 0), \
         coalesce(sum(c.version = 3), 0), coalesce(sum(c.version = 4), 0), \
         coalesce(sum(c.version = 5), 0), coalesce(sum(c.version IS NULL), 0), \
         count(DISTINCT {CLIENT_KEY}), count(DISTINCT {BROKER_KEY}), \
         count(DISTINCT CASE WHEN c.server_ip IN {PUBLIC} THEN {BROKER_KEY} END), \
         coalesce(sum(c.login = 'accepted'), 0), coalesce(sum(c.login = 'rejected'), 0), \
         coalesce(sum(c.login IS NULL), 0), \
         coalesce(sum(c.auth = 'none' AND c.login = 'accepted'), 0), \
         coalesce(sum(c.has_password), 0), coalesce(sum(c.publish_c2s), 0), \
         coalesce(sum(c.publish_s2c), 0), coalesce(sum(c.payload_bytes_c2s + c.payload_bytes_s2c), 0), \
         coalesce(sum(c.subscribe_count), 0) FROM mqtt_connections c{w}"
    );
    let mut s = conn.query_row(&sql, c.params().as_slice(), |r| {
        let u = |i: usize| -> rusqlite::Result<u64> { Ok(unsigned(r.get(i)?)) };
        Ok(StatsRow {
            connections: u(0)?,
            tcp: u(1)?,
            ws: u(2)?,
            v31: u(3)?,
            v311: u(4)?,
            v5: u(5)?,
            unknown_version: u(6)?,
            clients: u(7)?,
            brokers: u(8)?,
            public_brokers: u(9)?,
            accepted: u(10)?,
            rejected: u(11)?,
            no_answer: u(12)?,
            anonymous_accepted: u(13)?,
            with_password: u(14)?,
            publish_c2s: u(15)?,
            publish_s2c: u(16)?,
            payload_bytes: u(17)?,
            subscriptions: u(18)?,
            topics: 0,
            connack_codes: Vec::new(),
        })
    })?;
    let codes = format!(
        "SELECT c.version, c.connack_code, count(*) AS n FROM mqtt_connections c \
         WHERE c.connack_code IS NOT NULL{} GROUP BY c.version, c.connack_code \
         ORDER BY n DESC, c.version, c.connack_code LIMIT 10",
        and_sql(&c)
    );
    s.connack_codes = conn
        .prepare(&codes)?
        .query_map(c.params().as_slice(), |r| {
            Ok((r.get(0)?, r.get(1)?, unsigned(r.get(2)?)))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let topics: i64 = match range {
        // The tree of the step `mqtt`, plus the topics left out of it.
        None => conn.query_row(
            "SELECT (SELECT count(*) FROM mqtt_topics WHERE is_topic = 1) + coalesce((SELECT \
             CAST(value AS INTEGER) FROM meta WHERE key = ?1), 0)",
            params![super::META_TOPICS_FOLDED],
            |r| r.get(0),
        )?,
        Some(r) => {
            let mut tc = Conditions::new();
            tc.push("t.topic != ''", []);
            push_topic_range(&mut tc, r);
            conn.query_row(
                &format!(
                    "SELECT count(DISTINCT t.topic) FROM mqtt_topic_flows t{}",
                    where_sql(&tc)
                ),
                tc.params().as_slice(),
                |row| row.get(0),
            )?
        }
    };
    s.topics = unsigned(topics);
    Ok(s)
}

/// One row of a signal: a broker, a client, a pair, or a subscribed filter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignalItem {
    pub client: Option<(IpAddr, EndpointInfo)>,
    pub server: Option<(IpAddr, u16, EndpointInfo)>,
    pub filter: Option<String>,
    pub connections: u64,
}

/// Connections of one signal and its rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignalGroup {
    pub signal: Signal,
    pub connections: u64,
    pub items: Vec<SignalItem>,
}

/// Signals with at least one connection (connections overlapping `range` when set).
#[allow(clippy::items_after_statements)] // The row type next to its query.
pub fn signals(conn: &Connection, range: Option<TimeRange>) -> Result<Vec<SignalGroup>> {
    let mut out = Vec::new();
    for signal in Signal::ALL {
        let filter = ConnectionFilter {
            signal: Some(signal),
            range,
            ..ConnectionFilter::default()
        };
        let connections = count_connections(conn, &filter)?;
        if connections == 0 {
            continue;
        }
        let c = connection_conditions(&filter);
        let w = where_sql(&c);
        let (group, columns, from) = match signal {
            Signal::Anonymous | Signal::PublicBroker | Signal::CleartextCredentials => (
                "c.server_ip, c.server_port",
                "NULL, c.server_ip, c.server_port, NULL",
                "mqtt_connections c",
            ),
            Signal::ExposedBroker | Signal::AuthFailures => (
                "c.client_ip, c.server_ip, c.server_port",
                "c.client_ip, c.server_ip, c.server_port, NULL",
                "mqtt_connections c",
            ),
            Signal::Wildcard => (
                "c.client_ip, c.server_ip, c.server_port, s.filter",
                "c.client_ip, c.server_ip, c.server_port, s.filter",
                "mqtt_connections c JOIN mqtt_subscriptions s ON s.flow_id = c.flow_id AND s.wildcard = 1",
            ),
        };
        let sql = format!(
            "SELECT {columns}, count(DISTINCT c.flow_id) AS n FROM {from}{w} GROUP BY {group} \
             ORDER BY n DESC, {group} LIMIT {MAX_SIGNAL_ITEMS}"
        );
        type Raw = (
            Option<String>,
            Option<String>,
            Option<u16>,
            Option<String>,
            i64,
        );
        let raws: Vec<Raw> = conn
            .prepare(&sql)?
            .query_map(c.params().as_slice(), |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut items = Vec::new();
        for (client, server, port, filter, n) in raws {
            let client = match client {
                Some(text) => Some((
                    text.parse().map_err(|_| StoreError::InvalidValue {
                        field: "client_ip",
                        reason: "not an address",
                    })?,
                    host_info(conn, &text)?,
                )),
                None => None,
            };
            let server = match (server, port) {
                (Some(text), Some(port)) => Some((
                    text.parse().map_err(|_| StoreError::InvalidValue {
                        field: "server_ip",
                        reason: "not an address",
                    })?,
                    port,
                    host_info(conn, &text)?,
                )),
                _ => None,
            };
            items.push(SignalItem {
                client,
                server,
                filter,
                connections: unsigned(n),
            });
        }
        out.push(SignalGroup {
            signal,
            connections,
            items,
        });
    }
    Ok(out)
}
