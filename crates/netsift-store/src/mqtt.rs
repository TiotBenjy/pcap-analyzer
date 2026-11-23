//! Rows, end-of-import step and read queries of the MQTT analyzer (`docs/specs/mqtt.md`).
//!
//! Every row of a connection is written once by the shard of its TCP connection
//! (`ON CONFLICT DO NOTHING`): the tables do not depend on the arrival order nor on the number of
//! shards. The password of a CONNECT is stored apart (`mqtt_connect_secrets`) and only read by
//! [`queries::connection_detail`]. The step `mqtt` ([`finalize`]) builds the topic tree
//! (`mqtt_topics`) from the per-connection topic aggregates.

pub mod queries;

use std::fmt;
use std::net::IpAddr;

use rusqlite::{Connection, params};

use crate::error::Result;
use crate::records::sat;

pub use queries::*;

/// Levels of the topic tree; the rest of a deeper topic is the name of the last level.
pub const MAX_DEPTH: usize = 32;
/// Distinct topics put in the tree; the following ones (in tree order) are only counted.
pub const MAX_TREE_TOPICS: u64 = 1_000_000;
/// `meta` key of the topics left out of the tree.
pub const META_TOPICS_FOLDED: &str = "mqtt.topics_folded";
/// `meta` key: MQTT connections detected but not followed (connection maximum or state budget
/// reached), summed over the shards.
pub const META_UNFOLLOWED: &str = "mqtt.connections_unfollowed";

/// One MQTT connection. `Debug` hides the password.
#[allow(clippy::struct_excessive_bools)] // Independent facts about one connection.
#[derive(Clone, PartialEq, Eq)]
pub struct MqttConnectionRow {
    pub flow_id: i64,
    pub first_ts: i64,
    pub last_ts: i64,
    pub client_ip: IpAddr,
    pub client_port: u16,
    pub server_ip: IpAddr,
    pub server_port: u16,
    pub transport: &'static str,
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
    /// Sensitive: stored in `mqtt_connect_secrets`.
    pub password: Option<String>,
    pub password_len: Option<u32>,
    pub auth_method: Option<String>,
    pub auth: Option<&'static str>,
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
    pub login: Option<&'static str>,
    pub end_kind: &'static str,
    pub disconnect_ts: Option<i64>,
    pub disconnect_by: Option<&'static str>,
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
}

impl fmt::Debug for MqttConnectionRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MqttConnectionRow")
            .field("flow_id", &self.flow_id)
            .field("client_ip", &self.client_ip)
            .field("server_ip", &self.server_ip)
            .field("client_id", &self.client_id)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("login", &self.login)
            .finish_non_exhaustive()
    }
}

/// One filter of a SUBSCRIBE / UNSUBSCRIBE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MqttFilterRow {
    pub filter: String,
    pub options: u8,
    pub granted: Option<u8>,
}

/// One stored control packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MqttPacketRow {
    pub flow_id: i64,
    pub seq: u32,
    pub ts: i64,
    pub dir: &'static str,
    pub ptype: u8,
    pub flags: u8,
    pub packet_id: Option<u16>,
    pub qos: Option<u8>,
    pub retain: bool,
    pub dup: bool,
    pub topic: Option<String>,
    pub topic_alias: Option<u16>,
    pub topic_source: Option<&'static str>,
    pub size: u64,
    pub payload_len: Option<u64>,
    pub payload: Option<Vec<u8>>,
    pub payload_format: Option<u8>,
    pub content_type: Option<String>,
    pub reason_code: Option<u8>,
    pub reason_string: Option<String>,
    pub ack_state: Option<&'static str>,
    pub ack_reason: Option<u8>,
    pub ack_ns: Option<i64>,
    pub filters: Vec<MqttFilterRow>,
    pub props: Vec<(String, String)>,
    pub malformed: bool,
}

/// Messages of one topic in one direction of a connection (`topic` empty: other topics).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MqttTopicFlowRow {
    pub flow_id: i64,
    pub dir: &'static str,
    pub topic: String,
    pub messages: u64,
    pub payload_bytes: u64,
    pub first_ts: i64,
    pub last_ts: i64,
    pub qos: [u64; 3],
    pub retained: u64,
    pub max_payload: u64,
}

/// One subscribed filter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MqttSubscriptionRow {
    pub flow_id: i64,
    pub seq: u32,
    pub idx: u32,
    pub ts: i64,
    pub filter: String,
    pub qos: u8,
    pub options: u8,
    pub granted: Option<u8>,
    pub shared_group: Option<String>,
    pub wildcard: bool,
    pub unsubscribed_ts: Option<i64>,
}

/// A row of the MQTT tables.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MqttRow {
    Connection(Box<MqttConnectionRow>),
    Packet(Box<MqttPacketRow>),
    TopicFlow(MqttTopicFlowRow),
    Subscription(MqttSubscriptionRow),
    /// Connections a shard did not follow, added to [`META_UNFOLLOWED`].
    Unfollowed(u64),
}

fn json_pairs(pairs: &[(String, String)]) -> Result<String> {
    Ok(serde_json::to_string(pairs)?)
}

impl MqttRow {
    /// Name of the record type ([`crate::WriterStats::rows`]).
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Connection(_) => "mqtt_connections",
            Self::Packet(_) => "mqtt_packets",
            Self::TopicFlow(_) => "mqtt_topic_flows",
            Self::Subscription(_) => "mqtt_subscriptions",
            Self::Unfollowed(_) => "mqtt_unfollowed",
        }
    }

    /// Rough heap size, for the writer's batch accounting.
    pub fn approx_size(&self) -> usize {
        let opt = |v: &Option<String>| v.as_ref().map_or(0, String::len);
        let pairs =
            |p: &[(String, String)]| p.iter().map(|(k, v)| k.len() + v.len() + 48).sum::<usize>();
        match self {
            Self::Connection(c) => {
                512 + opt(&c.client_id)
                    + opt(&c.username)
                    + opt(&c.will_topic)
                    + c.will_payload.as_ref().map_or(0, Vec::len)
                    + pairs(&c.connect_props)
                    + pairs(&c.connack_props)
            }
            Self::Packet(p) => {
                256 + opt(&p.topic)
                    + p.payload.as_ref().map_or(0, Vec::len)
                    + p.filters.iter().map(|f| f.filter.len() + 32).sum::<usize>()
                    + pairs(&p.props)
            }
            Self::TopicFlow(t) => 128 + t.topic.len(),
            Self::Subscription(s) => 128 + s.filter.len(),
            Self::Unfollowed(_) => 64,
        }
    }

    pub(crate) fn insert(&self, conn: &Connection) -> Result<()> {
        match self {
            Self::Connection(c) => insert_connection(conn, c),
            Self::Packet(p) => insert_packet(conn, p),
            Self::TopicFlow(t) => {
                conn.prepare_cached(
                    "INSERT INTO mqtt_topic_flows (flow_id, dir, topic, messages, payload_bytes, \
                     first_ts, last_ts, qos0, qos1, qos2, retained, max_payload) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12) \
                     ON CONFLICT DO NOTHING",
                )?
                .execute(params![
                    t.flow_id,
                    t.dir,
                    t.topic,
                    sat(t.messages),
                    sat(t.payload_bytes),
                    t.first_ts,
                    t.last_ts,
                    sat(t.qos[0]),
                    sat(t.qos[1]),
                    sat(t.qos[2]),
                    sat(t.retained),
                    sat(t.max_payload),
                ])?;
                Ok(())
            }
            Self::Subscription(s) => {
                conn.prepare_cached(
                    "INSERT INTO mqtt_subscriptions (flow_id, seq, idx, ts, filter, qos, options, \
                     granted, shared_group, wildcard, unsubscribed_ts) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11) ON CONFLICT DO NOTHING",
                )?
                .execute(params![
                    s.flow_id,
                    s.seq,
                    s.idx,
                    s.ts,
                    s.filter,
                    s.qos,
                    s.options,
                    s.granted,
                    s.shared_group,
                    s.wildcard,
                    s.unsubscribed_ts,
                ])?;
                Ok(())
            }
            Self::Unfollowed(n) => {
                conn.prepare_cached(
                    "INSERT INTO meta (key, value) VALUES (?1, ?2) ON CONFLICT (key) DO UPDATE \
                     SET value = CAST(CAST(value AS INTEGER) + CAST(excluded.value AS INTEGER) \
                     AS TEXT)",
                )?
                .execute(params![META_UNFOLLOWED, n.to_string()])?;
                Ok(())
            }
        }
    }
}

fn insert_connection(conn: &Connection, c: &MqttConnectionRow) -> Result<()> {
    let inserted = conn
        .prepare_cached(
            "INSERT INTO mqtt_connections (flow_id, first_ts, last_ts, client_ip, client_port, \
             server_ip, server_port, transport, ws_path, ws_host, ws_subprotocol, ws_close_code, \
             ws_compressed, version, bridge, partial, protocol_name, client_id, \
             assigned_client_id, clean_start, keep_alive, server_keep_alive, session_expiry, \
             username, has_password, password_len, auth_method, auth, will_topic, will_qos, \
             will_retain, will_payload_len, will_payload, connect_props, connack_ts, \
             connack_code, session_present, connack_props, login, end_kind, disconnect_ts, \
             disconnect_by, disconnect_reason, broker_software, packets_c2s, packets_s2c, \
             publish_c2s, publish_s2c, payload_bytes_c2s, payload_bytes_s2c, subscribe_count, \
             pings, last_ping_ts, bytes_c2s, bytes_s2c, stored_packets, packets_truncated, \
             malformed, protocol_errors, gaps, state_dropped) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, \
             ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27, ?28, ?29, ?30, ?31, ?32, ?33, ?34, \
             ?35, ?36, ?37, ?38, ?39, ?40, ?41, ?42, ?43, ?44, ?45, ?46, ?47, ?48, ?49, ?50, ?51, \
             ?52, ?53, ?54, ?55, ?56, ?57, ?58, ?59, ?60, ?61) ON CONFLICT (flow_id) DO NOTHING",
        )?
        .execute(params![
            c.flow_id,
            c.first_ts,
            c.last_ts,
            c.client_ip.to_string(),
            c.client_port,
            c.server_ip.to_string(),
            c.server_port,
            c.transport,
            c.ws_path,
            c.ws_host,
            c.ws_subprotocol,
            c.ws_close_code,
            c.ws_compressed,
            c.version,
            c.bridge,
            c.partial,
            c.protocol_name,
            c.client_id,
            c.assigned_client_id,
            c.clean_start,
            c.keep_alive,
            c.server_keep_alive,
            c.session_expiry,
            c.username,
            c.password.is_some(),
            c.password_len,
            c.auth_method,
            c.auth,
            c.will_topic,
            c.will_qos,
            c.will_retain,
            c.will_payload_len.map(sat),
            c.will_payload,
            json_pairs(&c.connect_props)?,
            c.connack_ts,
            c.connack_code,
            c.session_present,
            json_pairs(&c.connack_props)?,
            c.login,
            c.end_kind,
            c.disconnect_ts,
            c.disconnect_by,
            c.disconnect_reason,
            c.broker_software,
            sat(c.packets_c2s),
            sat(c.packets_s2c),
            sat(c.publish_c2s),
            sat(c.publish_s2c),
            sat(c.payload_bytes_c2s),
            sat(c.payload_bytes_s2c),
            sat(c.subscribe_count),
            sat(c.pings),
            c.last_ping_ts,
            sat(c.bytes_c2s),
            sat(c.bytes_s2c),
            c.stored_packets,
            c.packets_truncated,
            c.malformed,
            c.protocol_errors,
            c.gaps,
            c.state_dropped,
        ])?;
    if inserted > 0
        && let Some(password) = &c.password
    {
        conn.prepare_cached(
            "INSERT INTO mqtt_connect_secrets (flow_id, password) VALUES (?1, ?2) \
             ON CONFLICT (flow_id) DO NOTHING",
        )?
        .execute(params![c.flow_id, password])?;
    }
    Ok(())
}

fn insert_packet(conn: &Connection, p: &MqttPacketRow) -> Result<()> {
    let filters: Vec<(&str, u8, Option<u8>)> = p
        .filters
        .iter()
        .map(|f| (f.filter.as_str(), f.options, f.granted))
        .collect();
    conn.prepare_cached(
        "INSERT INTO mqtt_packets (flow_id, seq, ts, dir, ptype, flags, packet_id, qos, retain, \
         dup, topic, topic_alias, topic_source, size, payload_len, payload, payload_format, \
         content_type, reason_code, reason_string, ack_state, ack_reason, ack_ns, filters, props, \
         malformed) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, \
         ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26) ON CONFLICT DO NOTHING",
    )?
    .execute(params![
        p.flow_id,
        p.seq,
        p.ts,
        p.dir,
        p.ptype,
        p.flags,
        p.packet_id,
        p.qos,
        p.retain,
        p.dup,
        p.topic,
        p.topic_alias,
        p.topic_source,
        sat(p.size),
        p.payload_len.map(sat),
        p.payload,
        p.payload_format,
        p.content_type,
        p.reason_code,
        p.reason_string,
        p.ack_state,
        p.ack_reason,
        p.ack_ns,
        serde_json::to_string(&filters)?,
        json_pairs(&p.props)?,
        p.malformed,
    ])?;
    Ok(())
}

// ---- topic tree (step `mqtt`) --------------------------------------------------------------

/// Levels of `topic`: split on `/`, at most [`MAX_DEPTH`] (the rest joined in the last one).
pub fn levels(topic: &str) -> Vec<&str> {
    let mut out: Vec<&str> = Vec::new();
    let mut rest = topic;
    loop {
        if out.len() + 1 >= MAX_DEPTH {
            out.push(rest);
            return out;
        }
        let Some((head, tail)) = rest.split_once('/') else {
            out.push(rest);
            return out;
        };
        out.push(head);
        rest = tail;
    }
}

/// Totals of a node of the tree being built.
#[derive(Debug, Clone, Default)]
struct NodeAgg {
    path: String,
    name: String,
    is_topic: bool,
    children: u64,
    topics: u64,
    messages_pub: u64,
    messages_del: u64,
    payload_bytes: u64,
    retained: u64,
    first_ts: i64,
    last_ts: i64,
    seen: bool,
}

impl NodeAgg {
    fn add(&mut self, other: &TopicTotals) {
        if !self.seen {
            self.first_ts = other.first_ts;
            self.last_ts = other.last_ts;
            self.seen = true;
        }
        self.first_ts = self.first_ts.min(other.first_ts);
        self.last_ts = self.last_ts.max(other.last_ts);
        self.messages_pub = self.messages_pub.saturating_add(other.messages_pub);
        self.messages_del = self.messages_del.saturating_add(other.messages_del);
        self.payload_bytes = self.payload_bytes.saturating_add(other.payload_bytes);
        self.retained = self.retained.saturating_add(other.retained);
        self.topics = self.topics.saturating_add(1);
    }
}

/// Totals of one topic over its connections.
#[derive(Debug, Clone, Default)]
struct TopicTotals {
    messages_pub: u64,
    messages_del: u64,
    payload_bytes: u64,
    retained: u64,
    first_ts: i64,
    last_ts: i64,
}

fn write_node(conn: &Connection, node: &NodeAgg, parent: Option<&str>, depth: usize) -> Result<()> {
    conn.prepare_cached(
        "INSERT INTO mqtt_topics (path, parent, name, depth, is_topic, children, topics, \
         messages_pub, messages_del, payload_bytes, retained, first_ts, last_ts) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13) \
         ON CONFLICT (path) DO NOTHING",
    )?
    .execute(params![
        node.path,
        parent,
        node.name,
        i64::try_from(depth).unwrap_or(i64::MAX),
        node.is_topic,
        sat(node.children),
        sat(node.topics),
        sat(node.messages_pub),
        sat(node.messages_del),
        sat(node.payload_bytes),
        sat(node.retained),
        node.first_ts,
        node.last_ts,
    ])?;
    Ok(())
}

/// Pops the nodes of `stack` deeper than `keep`, writing them (their parent is the node below).
fn pop_to(conn: &Connection, stack: &mut Vec<NodeAgg>, keep: usize) -> Result<()> {
    while stack.len() > keep {
        let Some(node) = stack.pop() else { break };
        let depth = stack.len() + 1;
        let parent = stack.last().map(|p| p.path.clone());
        if let Some(p) = stack.last_mut() {
            p.children = p.children.saturating_add(1);
        }
        write_node(conn, &node, parent.as_deref(), depth)?;
    }
    Ok(())
}

/// End-of-import step `mqtt`: the topic tree, in one pass over the topic aggregates in tree order
/// (`/` sorted before any other character, so that a subtree is contiguous): a stack of the
/// ancestors of the current topic, memory bounded by [`MAX_DEPTH`]. Idempotent.
pub(crate) fn finalize(conn: &Connection) -> Result<()> {
    build_tree(conn, MAX_TREE_TOPICS)
}

/// The tree of at most `max_topics` topics (the following ones counted in `meta`).
fn build_tree(conn: &Connection, max_topics: u64) -> Result<()> {
    conn.execute("DELETE FROM mqtt_topics", [])?;
    let mut stmt = conn.prepare(
        "SELECT topic, sum(CASE WHEN dir = 'c' THEN messages ELSE 0 END), \
         sum(CASE WHEN dir = 'b' THEN messages ELSE 0 END), sum(payload_bytes), sum(retained), \
         min(first_ts), max(last_ts) FROM mqtt_topic_flows WHERE topic != '' \
         GROUP BY topic ORDER BY replace(topic, '/', char(1)), topic",
    )?;
    let mut rows = stmt.query([])?;
    let mut stack: Vec<NodeAgg> = Vec::new();
    let mut topics: u64 = 0;
    let mut folded: u64 = 0;
    while let Some(row) = rows.next()? {
        topics = topics.saturating_add(1);
        if topics > max_topics {
            folded = folded.saturating_add(1);
            continue;
        }
        let topic: String = row.get(0)?;
        let unsigned = |i: usize| -> rusqlite::Result<u64> {
            Ok(u64::try_from(row.get::<_, i64>(i)?).unwrap_or(0))
        };
        let totals = TopicTotals {
            messages_pub: unsigned(1)?,
            messages_del: unsigned(2)?,
            payload_bytes: unsigned(3)?,
            retained: unsigned(4)?,
            first_ts: row.get(5)?,
            last_ts: row.get(6)?,
        };
        let parts = levels(&topic);
        // Longest common prefix with the stack (by level name).
        let common = stack
            .iter()
            .zip(&parts)
            .take_while(|(node, part)| node.name == **part)
            .count();
        pop_to(conn, &mut stack, common)?;
        for (i, part) in parts.iter().enumerate().skip(common) {
            let path = parts
                .get(..=i)
                .map_or_else(|| topic.clone(), |p| p.join("/"));
            stack.push(NodeAgg {
                path,
                name: (*part).to_owned(),
                ..NodeAgg::default()
            });
        }
        let depth = stack.len();
        for (i, node) in stack.iter_mut().enumerate() {
            node.add(&totals);
            if i + 1 == depth {
                node.is_topic = true;
            }
        }
    }
    pop_to(conn, &mut stack, 0)?;
    conn.execute(
        "INSERT INTO meta (key, value) VALUES (?1, ?2) \
         ON CONFLICT (key) DO UPDATE SET value = excluded.value",
        params![META_TOPICS_FOLDED, folded.to_string()],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests;
