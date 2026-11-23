//! The MQTT connection engine, independent of the transport: it receives the bytes of each
//! direction (reassembled TCP, or WebSocket payloads), frames the packets, follows the
//! connection state, and emits the records of `docs/specs/mqtt.md`.
//!
//! Bounds per connection: [`MAX_STORED`] packets stored, [`MAX_TOPICS`] topics per direction,
//! [`MAX_SUBSCRIPTIONS`] subscriptions, [`MAX_ALIASES`] topic aliases per direction,
//! [`MAX_PENDING`] packets waiting for their acknowledgement; per shard, [`Shared`] bounds the
//! bytes of those waiting packets.

use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;

use netsift_dissect::mqtt::{
    self as wire, FixedHeader, HeaderStatus, Packet, PacketType, Properties, Version,
};
use netsift_flow::{EndReason, Endpoint, FlowCtx, FlowId, TcpState};

use super::{
    AckState, AuthKind, Dir, EndKind, Login, MqttConnection, MqttFilter, MqttPacket, MqttRecord,
    MqttSubscription, MqttTopicStat, TopicSource, Transport, clean,
};
use crate::analyzer::RecordSink;
use crate::record::{Credential, Record, SecretState};

/// Packets stored per connection; beyond, only counters and aggregates.
pub const MAX_STORED: u32 = 10_000;
/// Topics aggregated per connection and direction; beyond, one "other topics" bucket.
pub const MAX_TOPICS: usize = 4096;
/// Subscriptions kept per connection.
pub const MAX_SUBSCRIPTIONS: usize = 1024;
/// Topic aliases kept per direction.
pub const MAX_ALIASES: usize = 1024;
/// Packets waiting for their acknowledgement per connection.
pub const MAX_PENDING: usize = 1024;
/// Segments tried to resynchronize a direction after a gap.
const MAX_RESYNC: u8 = 64;
/// Longest broker version kept (`$SYS/broker/version`), in bytes.
const MAX_SOFTWARE: usize = 128;
/// Topic of the broker version.
const SYS_VERSION: &str = "$SYS/broker/version";

/// State shared by the connections of one shard.
#[derive(Debug)]
pub(crate) struct Shared {
    /// Bytes still allowed for packets waiting for their acknowledgement.
    pending_budget: usize,
}

impl Shared {
    pub(crate) fn new(max_pending_bytes: usize) -> Self {
        Self {
            pending_budget: max_pending_bytes,
        }
    }
}

/// What the framer reports.
enum Event<'a> {
    Packet {
        header: FixedHeader,
        body: &'a [u8],
        ts: i64,
    },
    /// Bytes lost inside a packet whose end is known: the packet is dropped, alignment kept.
    Lost,
    /// Bytes lost elsewhere: resynchronizing.
    Gap,
    /// Invalid fixed header: the direction is abandoned.
    Invalid,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum FramerState {
    #[default]
    Normal,
    Resync(u8),
    Dead,
}

/// Packet framing of one direction. The buffer holds the fixed header and at most
/// [`wire::MAX_PACKET_PREFIX`] bytes of the body; the rest of a larger packet is skipped.
#[derive(Debug, Default)]
struct Framer {
    buf: Vec<u8>,
    header: Option<FixedHeader>,
    /// Time of the segment that started the packet.
    start_ts: i64,
    /// Bytes of the current (decoded) packet still to discard.
    skip: u64,
    state: FramerState,
}

/// True when `data` starts with packets of types allowed for `role` whose headers are valid up
/// to its end (the last one may continue past it).
fn starts_cleanly(data: &[u8], role: Dir) -> bool {
    let mut pos = 0usize;
    let mut packets = 0usize;
    while let Some(rest) = data.get(pos..) {
        if rest.is_empty() {
            break;
        }
        match wire::fixed_header(rest) {
            HeaderStatus::Invalid => return false,
            HeaderStatus::Incomplete => break,
            HeaderStatus::Valid(h) => {
                let allowed = match role {
                    Dir::Client => h.ptype.from_client(),
                    Dir::Broker => h.ptype.from_server(),
                };
                if !allowed || h.ptype == PacketType::Connect {
                    return false;
                }
                packets = packets.saturating_add(1);
                let size = usize::try_from(h.size()).unwrap_or(usize::MAX);
                pos = pos.saturating_add(size);
            }
        }
    }
    packets > 0
}

impl Framer {
    fn feed(
        &mut self,
        mut data: &[u8],
        ts: i64,
        gap: u64,
        role: Dir,
        on: &mut dyn FnMut(Event<'_>),
    ) {
        if self.state == FramerState::Dead {
            return;
        }
        if gap > 0 {
            self.gap(gap, on);
        }
        if let FramerState::Resync(tries) = self.state {
            if starts_cleanly(data, role) {
                self.state = FramerState::Normal;
            } else {
                let tries = tries.saturating_add(1);
                self.state = if tries >= MAX_RESYNC {
                    FramerState::Dead
                } else {
                    FramerState::Resync(tries)
                };
                return;
            }
        }
        while !data.is_empty() {
            if self.skip > 0 {
                let n = usize::try_from(self.skip)
                    .unwrap_or(usize::MAX)
                    .min(data.len());
                self.skip = self
                    .skip
                    .saturating_sub(u64::try_from(n).unwrap_or(u64::MAX));
                data = data.get(n..).unwrap_or_default();
                continue;
            }
            let Some(header) = self.header else {
                // One byte at a time: the header is 2 to 5 bytes long.
                if self.buf.is_empty() {
                    self.start_ts = ts;
                }
                let Some((&b, rest)) = data.split_first() else {
                    break;
                };
                data = rest;
                self.buf.push(b);
                match wire::fixed_header(&self.buf) {
                    HeaderStatus::Incomplete => {}
                    HeaderStatus::Invalid => {
                        self.state = FramerState::Dead;
                        self.buf.clear();
                        on(Event::Invalid);
                        return;
                    }
                    HeaderStatus::Valid(h) => {
                        self.header = Some(h);
                        if h.remaining == 0 {
                            self.emit(h, on);
                        }
                    }
                }
                continue;
            };
            let target = Self::target(header);
            let have = self
                .buf
                .len()
                .saturating_sub(usize::from(header.header_len));
            let n = target.saturating_sub(have).min(data.len());
            let (head, rest) = data.split_at(n);
            self.buf.extend_from_slice(head);
            data = rest;
            if have.saturating_add(n) >= target {
                self.emit(header, on);
            }
        }
    }

    /// Body bytes decoded for `header`.
    fn target(header: FixedHeader) -> usize {
        usize::try_from(header.remaining)
            .unwrap_or(usize::MAX)
            .min(wire::MAX_PACKET_PREFIX)
    }

    fn emit(&mut self, header: FixedHeader, on: &mut dyn FnMut(Event<'_>)) {
        let body = self
            .buf
            .get(usize::from(header.header_len)..)
            .unwrap_or_default();
        on(Event::Packet {
            header,
            body,
            ts: self.start_ts,
        });
        let decoded = u64::try_from(Self::target(header)).unwrap_or(u64::MAX);
        self.skip = u64::from(header.remaining).saturating_sub(decoded);
        self.buf.clear();
        self.header = None;
    }

    fn gap(&mut self, gap: u64, on: &mut dyn FnMut(Event<'_>)) {
        // Bytes of the current packet not received yet, when its end is known.
        let (left, dropped) = match self.header {
            Some(h) => {
                let have = u64::try_from(self.buf.len()).unwrap_or(u64::MAX);
                (Some(h.size().saturating_sub(have)), true)
            }
            None if self.buf.is_empty() && self.skip > 0 => (Some(self.skip), false),
            None => (None, false),
        };
        self.buf.clear();
        self.header = None;
        match left {
            Some(left) if gap <= left => {
                if dropped {
                    on(Event::Lost);
                }
                self.skip = left.saturating_sub(gap);
            }
            _ => {
                self.skip = 0;
                self.state = FramerState::Resync(0);
                on(Event::Gap);
            }
        }
    }
}

/// A packet waiting for its acknowledgement.
#[derive(Debug)]
enum Pending {
    Publish {
        row: Box<MqttPacket>,
        /// PUBREC received (`QoS` 2).
        received: bool,
        cost: usize,
    },
    Subscribe {
        row: Box<MqttPacket>,
        /// Indices in `subs` of its filters.
        subs: Vec<usize>,
        cost: usize,
    },
    Unsubscribe {
        row: Box<MqttPacket>,
        cost: usize,
    },
}

impl Pending {
    fn cost(&self) -> usize {
        match self {
            Self::Publish { cost, .. }
            | Self::Subscribe { cost, .. }
            | Self::Unsubscribe { cost, .. } => *cost,
        }
    }
}

/// Approximate memory of a stored packet row.
fn row_cost(row: &MqttPacket) -> usize {
    256 + row.topic.as_ref().map_or(0, String::len)
        + row.payload.as_ref().map_or(0, Vec::len)
        + row
            .filters
            .iter()
            .map(|f| f.filter.len() + 32)
            .sum::<usize>()
        + row
            .props
            .iter()
            .map(|(k, v)| k.len() + v.len() + 48)
            .sum::<usize>()
}

#[derive(Debug, Clone, Copy, Default)]
struct TopicAgg {
    messages: u64,
    payload_bytes: u64,
    first_ts: i64,
    last_ts: i64,
    qos: [u64; 3],
    retained: u64,
    max_payload: u64,
}

impl TopicAgg {
    fn add(&mut self, ts: i64, len: u64, qos: u8, retain: bool) {
        if self.messages == 0 {
            self.first_ts = ts;
            self.last_ts = ts;
        }
        self.first_ts = self.first_ts.min(ts);
        self.last_ts = self.last_ts.max(ts);
        self.messages = self.messages.saturating_add(1);
        self.payload_bytes = self.payload_bytes.saturating_add(len);
        if let Some(q) = self.qos.get_mut(usize::from(qos)) {
            *q = q.saturating_add(1);
        }
        if retain {
            self.retained = self.retained.saturating_add(1);
        }
        self.max_payload = self.max_payload.max(len);
    }
}

/// One MQTT connection being followed.
#[derive(Debug)]
pub(crate) struct Conn {
    row: Box<MqttConnection>,
    framers: [Framer; 2],
    /// Version used to decode (CONNECT, else guessed).
    version: Version,
    connect_seen: bool,
    next_seq: u32,
    pending: BTreeMap<(Dir, u16), Pending>,
    /// Credential of the CONNECT, waiting for the CONNACK.
    credential: Option<Credential>,
    aliases: [HashMap<u16, String>; 2],
    /// Topic Alias Maximum announced by the receiver of each direction.
    alias_max: [u16; 2],
    topics: [HashMap<String, TopicAgg>; 2],
    other: [TopicAgg; 2],
    subs: Vec<MqttSubscription>,
}

/// Password as stored: UTF-8 text without control characters, else `hex:` and hexadecimal.
pub(crate) fn render_secret(bytes: &[u8]) -> (String, &'static str) {
    match std::str::from_utf8(bytes) {
        Ok(s) if !s.chars().any(char::is_control) => (s.to_owned(), "utf8"),
        _ => {
            let mut out = String::with_capacity(4 + bytes.len() * 2);
            out.push_str("hex:");
            for b in bytes {
                let _ = write!(out, "{b:02x}");
            }
            (out, "hex")
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// 5.0 properties as ordered (name, value) pairs, without `skip` (kept in dedicated columns).
fn props_list(p: &Properties, skip_publish_columns: bool) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    let mut push = |k: &str, v: String| out.push((k.to_owned(), v));
    if !skip_publish_columns {
        if let Some(v) = p.payload_format {
            push("payload_format", v.to_string());
        }
        if let Some(v) = &p.content_type {
            push("content_type", clean(v));
        }
        if let Some(v) = p.topic_alias {
            push("topic_alias", v.to_string());
        }
        if let Some(v) = &p.reason_string {
            push("reason_string", clean(v));
        }
    }
    if let Some(v) = p.message_expiry {
        push("message_expiry", v.to_string());
    }
    if let Some(v) = &p.response_topic {
        push("response_topic", clean(v));
    }
    if let Some(v) = &p.correlation_data {
        push(
            "correlation_data",
            format!("{} ({} B)", hex(&v.bytes), v.len),
        );
    }
    for id in &p.subscription_ids {
        push("subscription_id", id.to_string());
    }
    if let Some(v) = p.session_expiry {
        push("session_expiry", v.to_string());
    }
    if let Some(v) = &p.assigned_client_id {
        push("assigned_client_id", clean(v));
    }
    if let Some(v) = p.server_keep_alive {
        push("server_keep_alive", v.to_string());
    }
    if let Some(v) = &p.auth_method {
        push("auth_method", clean(v));
    }
    if let Some(v) = p.auth_data_len {
        push("auth_data_len", v.to_string());
    }
    if let Some(v) = p.request_problem_info {
        push("request_problem_info", v.to_string());
    }
    if let Some(v) = p.will_delay {
        push("will_delay", v.to_string());
    }
    if let Some(v) = p.request_response_info {
        push("request_response_info", v.to_string());
    }
    if let Some(v) = &p.response_info {
        push("response_info", clean(v));
    }
    if let Some(v) = &p.server_reference {
        push("server_reference", clean(v));
    }
    if let Some(v) = p.receive_maximum {
        push("receive_maximum", v.to_string());
    }
    if let Some(v) = p.topic_alias_maximum {
        push("topic_alias_maximum", v.to_string());
    }
    if let Some(v) = p.maximum_qos {
        push("maximum_qos", v.to_string());
    }
    if let Some(v) = p.retain_available {
        push("retain_available", v.to_string());
    }
    if let Some(v) = p.maximum_packet_size {
        push("maximum_packet_size", v.to_string());
    }
    if let Some(v) = p.wildcard_available {
        push("wildcard_available", v.to_string());
    }
    if let Some(v) = p.sub_id_available {
        push("sub_id_available", v.to_string());
    }
    if let Some(v) = p.shared_available {
        push("shared_available", v.to_string());
    }
    for (k, v) in &p.user_properties {
        push("user_property", format!("{}: {}", clean(k), clean(v)));
    }
    if p.user_properties_dropped > 0 {
        push(
            "user_properties_dropped",
            p.user_properties_dropped.to_string(),
        );
    }
    if p.error {
        push("properties_error", "1".to_owned());
    }
    out
}

/// True for a filter that reads every topic (`#`, `+/#`, `$SYS/#`), shared or not.
fn reads_everything(filter: &str) -> bool {
    let inner = shared_parts(filter).map_or(filter, |(_, f)| f);
    matches!(inner, "#" | "+/#" | "$SYS/#")
}

/// `(group, filter)` of a shared subscription `$share/<group>/<filter>`.
fn shared_parts(filter: &str) -> Option<(&str, &str)> {
    let rest = filter.strip_prefix("$share/")?;
    let (group, f) = rest.split_once('/')?;
    Some((group, f))
}

impl Conn {
    pub(crate) fn new(
        flow_id: FlowId,
        client: Endpoint,
        server: Endpoint,
        transport: Transport,
        first_ts: i64,
    ) -> Self {
        Self {
            row: Box::new(MqttConnection {
                flow_id,
                client,
                server,
                first_ts,
                last_ts: first_ts,
                transport,
                ws_path: None,
                ws_host: None,
                ws_subprotocol: None,
                ws_close_code: None,
                ws_compressed: false,
                version: None,
                bridge: false,
                partial: false,
                protocol_name: None,
                client_id: None,
                assigned_client_id: None,
                clean_start: None,
                keep_alive: None,
                server_keep_alive: None,
                session_expiry: None,
                username: None,
                password: None,
                password_len: None,
                auth_method: None,
                auth: None,
                will_topic: None,
                will_qos: None,
                will_retain: None,
                will_payload_len: None,
                will_payload: None,
                connect_props: Vec::new(),
                connack_ts: None,
                connack_code: None,
                session_present: None,
                connack_props: Vec::new(),
                login: None,
                end_kind: EndKind::Capture,
                disconnect_ts: None,
                disconnect_by: None,
                disconnect_reason: None,
                broker_software: None,
                packets_c2s: 0,
                packets_s2c: 0,
                publish_c2s: 0,
                publish_s2c: 0,
                payload_bytes_c2s: 0,
                payload_bytes_s2c: 0,
                subscribe_count: 0,
                pings: 0,
                last_ping_ts: None,
                bytes_c2s: 0,
                bytes_s2c: 0,
                stored_packets: 0,
                packets_truncated: false,
                malformed: 0,
                protocol_errors: 0,
                gaps: 0,
            }),
            framers: [Framer::default(), Framer::default()],
            version: Version::V311,
            connect_seen: false,
            next_seq: 0,
            pending: BTreeMap::new(),
            credential: None,
            aliases: [HashMap::new(), HashMap::new()],
            alias_max: [0, 0],
            topics: [HashMap::new(), HashMap::new()],
            other: [TopicAgg::default(), TopicAgg::default()],
            subs: Vec::new(),
        }
    }

    /// A connection picked up in the middle, decoded with the guessed `version`.
    pub(crate) fn set_partial(&mut self, version: Version) {
        self.row.partial = true;
        self.row.version = Some(version);
        self.version = version;
    }

    /// Bytes of direction `dir`, in order; `gap`: bytes lost just before.
    pub(crate) fn feed(
        &mut self,
        dir: Dir,
        data: &[u8],
        ts: i64,
        gap: u64,
        shared: &mut Shared,
        out: &mut dyn RecordSink,
    ) {
        self.row.last_ts = self.row.last_ts.max(ts);
        let Some(slot) = self.framers.get_mut(dir.index()) else {
            return;
        };
        let mut framer = std::mem::take(slot);
        let mut kill = false;
        framer.feed(data, ts, gap, dir, &mut |event| match event {
            Event::Packet { header, body, ts } => {
                if !self.packet(dir, header, body, ts, shared, out) {
                    kill = true;
                }
            }
            Event::Lost | Event::Gap => self.row.gaps = self.row.gaps.saturating_add(1),
            Event::Invalid => self.row.malformed = self.row.malformed.saturating_add(1),
        });
        if kill {
            framer.state = FramerState::Dead;
        }
        if let Some(slot) = self.framers.get_mut(dir.index()) {
            *slot = framer;
        }
    }

    /// Takes a slot of the stored packets; false once [`MAX_STORED`] is reached.
    fn store_slot(&mut self) -> bool {
        if self.row.stored_packets < MAX_STORED {
            self.row.stored_packets = self.row.stored_packets.saturating_add(1);
            true
        } else {
            self.row.packets_truncated = true;
            false
        }
    }

    fn base_row(&self, seq: u32, ts: i64, dir: Dir, header: FixedHeader) -> MqttPacket {
        MqttPacket {
            flow_id: self.row.flow_id,
            seq,
            ts,
            dir,
            ptype: header.ptype,
            flags: header.flags,
            packet_id: None,
            qos: None,
            retain: false,
            dup: false,
            topic: None,
            topic_alias: None,
            topic_source: None,
            size: header.size(),
            payload_len: None,
            payload: None,
            payload_format: None,
            content_type: None,
            reason_code: None,
            reason_string: None,
            ack_state: None,
            ack_reason: None,
            ack_ns: None,
            filters: Vec::new(),
            props: Vec::new(),
            malformed: false,
        }
    }

    fn emit_row(out: &mut dyn RecordSink, row: Box<MqttPacket>) {
        out.emit(Record::Mqtt(MqttRecord::Packet(row)));
    }

    /// Handles one framed packet; false when the direction must be abandoned (malformed).
    fn packet(
        &mut self,
        dir: Dir,
        header: FixedHeader,
        body: &[u8],
        ts: i64,
        shared: &mut Shared,
        out: &mut dyn RecordSink,
    ) -> bool {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        match dir {
            Dir::Client => self.row.packets_c2s = self.row.packets_c2s.saturating_add(1),
            Dir::Broker => self.row.packets_s2c = self.row.packets_s2c.saturating_add(1),
        }
        let allowed = match dir {
            Dir::Client => header.ptype.from_client(),
            Dir::Broker => header.ptype.from_server(),
        };
        if !allowed {
            self.row.protocol_errors = self.row.protocol_errors.saturating_add(1);
        }
        let parsed = wire::parse_packet(header, body, self.version);
        let Ok(packet) = parsed else {
            self.row.malformed = self.row.malformed.saturating_add(1);
            if self.store_slot() {
                let mut row = self.base_row(seq, ts, dir, header);
                row.malformed = true;
                Self::emit_row(out, Box::new(row));
            }
            return false;
        };
        match packet {
            Packet::Connect(c) => self.connect(dir, header, &c, seq, ts, out),
            Packet::Connack(c) => self.connack(dir, header, &c, seq, ts, out),
            Packet::Publish(p) => self.publish(dir, header, *p, seq, ts, shared, out),
            Packet::Puback(a) | Packet::Pubcomp(a) => {
                self.ack(dir, header, &a, seq, ts, AckStep::Final, shared, out);
            }
            Packet::Pubrec(a) => self.ack(dir, header, &a, seq, ts, AckStep::Received, shared, out),
            Packet::Pubrel(a) => self.ack(dir, header, &a, seq, ts, AckStep::Release, shared, out),
            Packet::Subscribe(s) => self.subscribe(dir, header, &s, seq, ts, true, shared, out),
            Packet::Unsubscribe(s) => self.subscribe(dir, header, &s, seq, ts, false, shared, out),
            Packet::Suback(s) | Packet::Unsuback(s) => {
                self.suback(dir, header, &s, seq, ts, shared, out);
            }
            Packet::Pingreq => {
                self.row.pings = self.row.pings.saturating_add(1);
                self.row.last_ping_ts = Some(ts);
            }
            Packet::Pingresp => {}
            Packet::Disconnect(d) => {
                self.row.disconnect_ts = Some(ts);
                self.row.disconnect_by = Some(dir);
                self.row.disconnect_reason = d.reason;
                if self.store_slot() {
                    let mut row = self.base_row(seq, ts, dir, header);
                    row.reason_code = d.reason;
                    row.reason_string = d.properties.reason_string.as_deref().map(clean);
                    row.props = props_list(&d.properties, true);
                    Self::emit_row(out, Box::new(row));
                }
            }
            Packet::Auth(a) => {
                if self.store_slot() {
                    let mut row = self.base_row(seq, ts, dir, header);
                    row.reason_code = a.reason;
                    row.reason_string = a.properties.reason_string.as_deref().map(clean);
                    row.props = props_list(&a.properties, true);
                    Self::emit_row(out, Box::new(row));
                }
            }
        }
        true
    }

    fn connect(
        &mut self,
        dir: Dir,
        header: FixedHeader,
        c: &wire::Connect,
        seq: u32,
        ts: i64,
        out: &mut dyn RecordSink,
    ) {
        if self.connect_seen || dir != Dir::Client {
            self.row.protocol_errors = self.row.protocol_errors.saturating_add(1);
            if self.store_slot() {
                Self::emit_row(out, Box::new(self.base_row(seq, ts, dir, header)));
            }
            return;
        }
        self.connect_seen = true;
        if let Some(v) = c.version {
            self.version = v;
            self.row.version = Some(v);
        }
        if c.protocol_error {
            self.row.protocol_errors = self.row.protocol_errors.saturating_add(1);
        }
        let r = &mut self.row;
        r.partial = false;
        r.bridge = c.bridge;
        r.protocol_name = Some(clean(&c.protocol_name));
        r.client_id = Some(clean(&c.client_id.value));
        r.clean_start = Some(c.clean_start);
        r.keep_alive = Some(c.keep_alive);
        r.session_expiry = c.properties.session_expiry;
        r.auth_method = c.properties.auth_method.as_deref().map(clean);
        r.username = c.username.as_ref().map(|u| clean(&u.value));
        let rendered = c.password.as_deref().map(render_secret);
        r.password = rendered.as_ref().map(|(s, _)| s.clone());
        r.password_len = c.password.as_ref().map(|_| c.password_len);
        r.auth = Some(if r.auth_method.is_some() {
            AuthKind::Enhanced
        } else if c.password.is_some() {
            AuthKind::Password
        } else if c.username.is_some() {
            AuthKind::Username
        } else {
            AuthKind::None
        });
        if let Some(w) = &c.will {
            r.will_topic = Some(clean(&w.topic.value));
            r.will_qos = Some(w.qos);
            r.will_retain = Some(w.retain);
            r.will_payload_len = Some(w.payload.len);
            r.will_payload = Some(w.payload.bytes.clone());
        }
        r.connect_props = props_list(&c.properties, false);
        // Aliases sent by the broker are bounded by the client's maximum.
        if let Some(slot) = self.alias_max.get_mut(Dir::Broker.index()) {
            *slot = c.properties.topic_alias_maximum.unwrap_or(0);
        }
        if r.username.is_some() || r.password.is_some() || r.auth_method.is_some() {
            let mut details = vec![
                ("version".to_owned(), self.version.label().to_owned()),
                (
                    "client_id".to_owned(),
                    r.client_id.clone().unwrap_or_default(),
                ),
                ("transport".to_owned(), r.transport.as_str().to_owned()),
            ];
            if let Some((_, encoding)) = &rendered {
                details.push(("password_encoding".to_owned(), (*encoding).to_owned()));
            }
            if let Some(m) = &r.auth_method {
                details.push(("auth_method".to_owned(), m.clone()));
            }
            let plaintext = r.password.is_some();
            self.credential = Some(Credential {
                source_protocol: "mqtt",
                kind: "mqtt",
                flow_id: Some(r.flow_id),
                client: Some(r.client),
                server: Some(r.server),
                ts,
                username: r.username.clone(),
                domain: None,
                workstation: None,
                secret_state: if plaintext {
                    SecretState::Plaintext
                } else {
                    SecretState::MetadataOnly
                },
                secret: r.password.clone(),
                hashcat_mode: None,
                hashcat_line: None,
                details,
            });
        }
        if self.store_slot() {
            let mut row = self.base_row(seq, ts, dir, header);
            row.props.clone_from(&self.row.connect_props);
            Self::emit_row(out, Box::new(row));
        }
    }

    fn connack(
        &mut self,
        dir: Dir,
        header: FixedHeader,
        c: &wire::Connack,
        seq: u32,
        ts: i64,
        out: &mut dyn RecordSink,
    ) {
        if dir != Dir::Broker || self.row.connack_ts.is_some() {
            self.row.protocol_errors = self.row.protocol_errors.saturating_add(1);
        } else {
            let r = &mut self.row;
            r.connack_ts = Some(ts);
            r.connack_code = Some(c.code);
            r.session_present = Some(c.session_present);
            r.assigned_client_id = c.properties.assigned_client_id.as_deref().map(clean);
            r.server_keep_alive = c.properties.server_keep_alive;
            r.connack_props = props_list(&c.properties, false);
            let login = if c.code == 0 {
                Login::Accepted
            } else {
                Login::Rejected
            };
            r.login = Some(login);
            if let Some(slot) = self.alias_max.get_mut(Dir::Client.index()) {
                *slot = c.properties.topic_alias_maximum.unwrap_or(0);
            }
            if let Some(mut cred) = self.credential.take() {
                cred.details
                    .push(("result".to_owned(), login.as_str().to_owned()));
                cred.details
                    .push(("connack".to_owned(), format!("{:#04x}", c.code)));
                out.emit(Record::Credential(cred));
            }
        }
        if self.store_slot() {
            let mut row = self.base_row(seq, ts, dir, header);
            row.reason_code = Some(c.code);
            row.reason_string = c.properties.reason_string.as_deref().map(clean);
            row.props = props_list(&c.properties, true);
            Self::emit_row(out, Box::new(row));
        }
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)] // One packet: topic, aggregates, row.
    fn publish(
        &mut self,
        dir: Dir,
        header: FixedHeader,
        p: wire::Publish,
        seq: u32,
        ts: i64,
        shared: &mut Shared,
        out: &mut dyn RecordSink,
    ) {
        let d = dir.index();
        let alias = p.properties.topic_alias;
        let max = self.alias_max.get(d).copied().unwrap_or(0);
        if let Some(a) = alias
            && (a == 0 || a > max)
        {
            self.row.protocol_errors = self.row.protocol_errors.saturating_add(1);
        }
        let named = !p.topic.value.is_empty();
        let (topic, source) = if named {
            let topic = clean(&p.topic.value);
            if let (Some(a), Some(map)) = (alias, self.aliases.get_mut(d))
                && (map.len() < MAX_ALIASES || map.contains_key(&a))
            {
                map.insert(a, topic.clone());
            }
            (Some(topic), TopicSource::Name)
        } else {
            let resolved = alias.and_then(|a| self.aliases.get(d)?.get(&a).cloned());
            if resolved.is_none() && alias.is_none() {
                self.row.protocol_errors = self.row.protocol_errors.saturating_add(1);
            }
            let source = if resolved.is_some() {
                TopicSource::Alias
            } else {
                TopicSource::Unresolved
            };
            (resolved, source)
        };
        let len = p.payload.len;
        let qos = header.qos();
        match dir {
            Dir::Client => {
                self.row.publish_c2s = self.row.publish_c2s.saturating_add(1);
                self.row.payload_bytes_c2s = self.row.payload_bytes_c2s.saturating_add(len);
            }
            Dir::Broker => {
                self.row.publish_s2c = self.row.publish_s2c.saturating_add(1);
                self.row.payload_bytes_s2c = self.row.payload_bytes_s2c.saturating_add(len);
            }
        }
        // Topic aggregates: every PUBLISH, stored or not.
        let agg = match (&topic, self.topics.get_mut(d)) {
            (Some(t), Some(map)) if map.contains_key(t) || map.len() < MAX_TOPICS => {
                Some(map.entry(t.clone()).or_default())
            }
            _ => None,
        };
        match agg {
            Some(a) => a.add(ts, len, qos, header.retain()),
            None => {
                if let Some(o) = self.other.get_mut(d) {
                    o.add(ts, len, qos, header.retain());
                }
            }
        }
        if dir == Dir::Broker && topic.as_deref() == Some(SYS_VERSION) {
            let text = String::from_utf8_lossy(&p.payload.bytes);
            let mut software = clean(text.trim());
            if software.len() > MAX_SOFTWARE {
                let mut end = MAX_SOFTWARE;
                while !software.is_char_boundary(end) {
                    end = end.saturating_sub(1);
                }
                software.truncate(end);
            }
            if !software.is_empty() {
                self.row.broker_software = Some(software);
            }
        }
        if !self.store_slot() {
            return;
        }
        let mut row = self.base_row(seq, ts, dir, header);
        row.packet_id = p.packet_id;
        row.qos = Some(qos);
        row.retain = header.retain();
        row.dup = header.dup();
        row.topic = topic;
        row.topic_alias = alias;
        row.topic_source = Some(source);
        row.payload_len = Some(len);
        row.payload = Some(p.payload.bytes);
        row.payload_format = p.properties.payload_format;
        row.content_type = p.properties.content_type.as_deref().map(clean);
        row.props = props_list(&p.properties, true);
        let row = Box::new(row);
        match p.packet_id {
            Some(id) if qos > 0 => {
                let cost = row_cost(&row);
                let room = self.pending.len() < MAX_PENDING && shared.pending_budget >= cost;
                if room {
                    shared.pending_budget = shared.pending_budget.saturating_sub(cost);
                    // A packet id reused before its acknowledgement: the earlier one is done.
                    if let Some(old) = self.pending.remove(&(dir, id)) {
                        Self::flush(old, shared, out);
                    }
                    self.pending.insert(
                        (dir, id),
                        Pending::Publish {
                            row,
                            received: false,
                            cost,
                        },
                    );
                } else {
                    let mut row = row;
                    row.ack_state = Some(AckState::Missing);
                    Self::emit_row(out, row);
                }
            }
            _ => {
                let mut row = row;
                row.ack_state = Some(AckState::None);
                Self::emit_row(out, row);
            }
        }
    }

    /// Emits a packet still waiting at the end (no acknowledgement seen).
    fn flush(pending: Pending, shared: &mut Shared, out: &mut dyn RecordSink) {
        shared.pending_budget = shared.pending_budget.saturating_add(pending.cost());
        match pending {
            Pending::Publish {
                mut row, received, ..
            } => {
                row.ack_state = Some(if received {
                    AckState::Received
                } else {
                    AckState::Missing
                });
                Self::emit_row(out, row);
            }
            Pending::Subscribe { row, .. } | Pending::Unsubscribe { row, .. } => {
                Self::emit_row(out, row);
            }
        }
    }

    /// An acknowledgement without its packet: stored as a packet of its own.
    #[allow(clippy::too_many_arguments)]
    fn orphan(
        &mut self,
        dir: Dir,
        header: FixedHeader,
        packet_id: u16,
        reason: Option<u8>,
        seq: u32,
        ts: i64,
        out: &mut dyn RecordSink,
    ) {
        if self.store_slot() {
            let mut row = self.base_row(seq, ts, dir, header);
            row.packet_id = Some(packet_id);
            row.reason_code = reason;
            Self::emit_row(out, Box::new(row));
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn ack(
        &mut self,
        dir: Dir,
        header: FixedHeader,
        a: &wire::Ack,
        seq: u32,
        ts: i64,
        step: AckStep,
        shared: &mut Shared,
        out: &mut dyn RecordSink,
    ) {
        // PUBREL comes from the publisher; the others from the receiver.
        let publisher = if step == AckStep::Release {
            dir
        } else {
            dir.other()
        };
        let key = (publisher, a.packet_id);
        let failed = a.reason.is_some_and(|r| r >= 0x80);
        let action = match (step, self.pending.get(&key)) {
            (AckStep::Release, Some(Pending::Publish { .. })) => AckAction::Wait,
            (AckStep::Received, Some(Pending::Publish { .. })) if !failed => AckAction::Received,
            (AckStep::Final | AckStep::Received, Some(Pending::Publish { .. })) => AckAction::Done,
            _ => AckAction::Orphan,
        };
        match action {
            AckAction::Wait => {}
            AckAction::Received => {
                if let Some(Pending::Publish { row, received, .. }) = self.pending.get_mut(&key) {
                    *received = true;
                    row.ack_reason = a.reason;
                }
            }
            AckAction::Done => {
                if let Some(Pending::Publish { mut row, cost, .. }) = self.pending.remove(&key) {
                    shared.pending_budget = shared.pending_budget.saturating_add(cost);
                    row.ack_state = Some(if failed {
                        AckState::Error
                    } else {
                        AckState::Acked
                    });
                    row.ack_reason = a.reason;
                    row.ack_ns = Some(ts.saturating_sub(row.ts));
                    Self::emit_row(out, row);
                }
            }
            AckAction::Orphan => self.orphan(dir, header, a.packet_id, a.reason, seq, ts, out),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn subscribe(
        &mut self,
        dir: Dir,
        header: FixedHeader,
        s: &wire::Subscribe,
        seq: u32,
        ts: i64,
        subscribe: bool,
        shared: &mut Shared,
        out: &mut dyn RecordSink,
    ) {
        if s.protocol_error || dir != Dir::Client {
            self.row.protocol_errors = self.row.protocol_errors.saturating_add(1);
        }
        let mut indices = Vec::new();
        if subscribe {
            let added = u64::try_from(s.filters.len())
                .unwrap_or(u64::MAX)
                .saturating_add(u64::from(s.dropped));
            self.row.subscribe_count = self.row.subscribe_count.saturating_add(added);
            for (i, f) in s.filters.iter().enumerate() {
                if self.subs.len() >= MAX_SUBSCRIPTIONS {
                    break;
                }
                let filter = clean(&f.filter.value);
                indices.push(self.subs.len());
                self.subs.push(MqttSubscription {
                    flow_id: self.row.flow_id,
                    seq,
                    idx: u32::try_from(i).unwrap_or(u32::MAX),
                    ts,
                    shared_group: shared_parts(&filter).map(|(g, _)| g.to_owned()),
                    wildcard: reads_everything(&filter),
                    filter,
                    qos: f.qos(),
                    options: f.options,
                    granted: None,
                    unsubscribed_ts: None,
                });
            }
        } else {
            for f in &s.filters {
                let filter = clean(&f.filter.value);
                if let Some(sub) = self
                    .subs
                    .iter_mut()
                    .rev()
                    .find(|x| x.filter == filter && x.unsubscribed_ts.is_none())
                {
                    sub.unsubscribed_ts = Some(ts);
                }
            }
        }
        if !self.store_slot() {
            return;
        }
        let mut row = self.base_row(seq, ts, dir, header);
        row.packet_id = Some(s.packet_id);
        row.filters = s
            .filters
            .iter()
            .map(|f| MqttFilter {
                filter: clean(&f.filter.value),
                options: f.options,
                granted: None,
            })
            .collect();
        row.props = props_list(&s.properties, false);
        let row = Box::new(row);
        let cost = row_cost(&row);
        let key = (dir, s.packet_id);
        if self.pending.len() < MAX_PENDING
            && shared.pending_budget >= cost
            && !self.pending.contains_key(&key)
        {
            shared.pending_budget = shared.pending_budget.saturating_sub(cost);
            let pending = if subscribe {
                Pending::Subscribe {
                    row,
                    subs: indices,
                    cost,
                }
            } else {
                Pending::Unsubscribe { row, cost }
            };
            self.pending.insert(key, pending);
        } else {
            Self::emit_row(out, row);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn suback(
        &mut self,
        dir: Dir,
        header: FixedHeader,
        s: &wire::Suback,
        seq: u32,
        ts: i64,
        shared: &mut Shared,
        out: &mut dyn RecordSink,
    ) {
        let key = (dir.other(), s.packet_id);
        let matches = matches!(
            (header.ptype, self.pending.get(&key)),
            (PacketType::Suback, Some(Pending::Subscribe { .. }))
                | (PacketType::Unsuback, Some(Pending::Unsubscribe { .. }))
        );
        if !matches {
            if self.store_slot() {
                let mut row = self.base_row(seq, ts, dir, header);
                row.packet_id = Some(s.packet_id);
                row.reason_code = s.codes.first().copied();
                Self::emit_row(out, Box::new(row));
            }
            return;
        }
        let Some(pending) = self.pending.remove(&key) else {
            return;
        };
        shared.pending_budget = shared.pending_budget.saturating_add(pending.cost());
        match pending {
            Pending::Subscribe { mut row, subs, .. } => {
                for (i, f) in row.filters.iter_mut().enumerate() {
                    f.granted = s.codes.get(i).copied();
                }
                for (i, idx) in subs.iter().enumerate() {
                    if let Some(sub) = self.subs.get_mut(*idx) {
                        sub.granted = s.codes.get(i).copied();
                    }
                }
                row.ack_ns = Some(ts.saturating_sub(row.ts));
                Self::emit_row(out, row);
            }
            Pending::Unsubscribe { mut row, .. } => {
                for (i, f) in row.filters.iter_mut().enumerate() {
                    f.granted = s.codes.get(i).copied();
                }
                row.ack_ns = Some(ts.saturating_sub(row.ts));
                Self::emit_row(out, row);
            }
            Pending::Publish { .. } => {}
        }
    }

    /// Ends the connection: waiting packets, credential, aggregates, subscriptions, then the
    /// connection row. `ctx`: the flow summary and whether its key is swapped (TCP).
    pub(crate) fn finish(
        mut self,
        ctx: Option<(&FlowCtx, bool)>,
        shared: &mut Shared,
        out: &mut dyn RecordSink,
    ) {
        for (_, pending) in std::mem::take(&mut self.pending) {
            Self::flush(pending, shared, out);
        }
        if let Some(cred) = self.credential.take() {
            out.emit(Record::Credential(cred));
        }
        let flow_id = self.row.flow_id;
        let [client_topics, broker_topics] = std::mem::take(&mut self.topics);
        let [client_other, broker_other] = self.other;
        for (dir, map, other) in [
            (Dir::Client, client_topics, client_other),
            (Dir::Broker, broker_topics, broker_other),
        ] {
            let mut topics: Vec<(String, TopicAgg)> = map.into_iter().collect();
            topics.sort_unstable_by(|a, b| a.0.cmp(&b.0));
            let rows = topics
                .into_iter()
                .map(|(t, a)| (Some(t), a))
                .chain((other.messages > 0).then_some((None, other)));
            for (topic, a) in rows {
                out.emit(Record::Mqtt(MqttRecord::Topic(MqttTopicStat {
                    flow_id,
                    dir,
                    topic,
                    messages: a.messages,
                    payload_bytes: a.payload_bytes,
                    first_ts: a.first_ts,
                    last_ts: a.last_ts,
                    qos: a.qos,
                    retained: a.retained,
                    max_payload: a.max_payload,
                })));
            }
        }
        for sub in std::mem::take(&mut self.subs) {
            out.emit(Record::Mqtt(MqttRecord::Subscription(sub)));
        }
        let r = &mut self.row;
        if let Some((ctx, swapped)) = ctx {
            r.first_ts = r.first_ts.min(ctx.first_ts_ns);
            r.last_ts = r.last_ts.max(ctx.last_ts_ns);
            let (c2s, s2c) = if swapped {
                (ctx.to_client.bytes, ctx.to_server.bytes)
            } else {
                (ctx.to_server.bytes, ctx.to_client.bytes)
            };
            r.bytes_c2s = c2s;
            r.bytes_s2c = s2c;
        }
        r.end_kind = if r.disconnect_ts.is_some() {
            EndKind::Disconnect
        } else {
            match ctx.map(|(c, _)| (c.tcp_state, c.end)) {
                Some((Some(TcpState::Reset), _)) => EndKind::Reset,
                Some((_, EndReason::Timeout | EndReason::Evicted)) => EndKind::Timeout,
                Some((Some(TcpState::Closed | TcpState::Closing), _) | (_, EndReason::Closed)) => {
                    EndKind::Close
                }
                _ => EndKind::Capture,
            }
        };
        out.emit(Record::Mqtt(MqttRecord::Connection(self.row)));
    }
}

/// What an acknowledgement does to the waiting packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AckAction {
    /// PUBREL: the receiver's PUBCOMP is still expected.
    Wait,
    /// PUBREC: received, PUBCOMP expected.
    Received,
    /// PUBACK, PUBCOMP, or a failing PUBREC: the packet is emitted.
    Done,
    /// No waiting packet: stored on its own.
    Orphan,
}

/// Which acknowledgement of a PUBLISH.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AckStep {
    /// PUBACK or PUBCOMP.
    Final,
    /// PUBREC.
    Received,
    /// PUBREL (from the publisher).
    Release,
}
