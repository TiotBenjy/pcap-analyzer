//! Flow table: IP defragmentation, flow tracking, TCP reassembly, packet-time expiry.
//!
//! # Policies
//!
//! - **Orientation.** TCP: the client is the sender of a SYN (without ACK); if the first packet
//!   seen is a SYN-ACK, the client is its destination; otherwise the sender of the first
//!   packet, and the connection is `Midstream`. Other protocols: the sender of the first
//!   packet. Ports are 0 for protocols without ports (ICMP, ...).
//! - **Identity.** A flow is found by protocol + unordered endpoint pair; its id is
//!   [`FlowId::derive`] of the oriented key and the time of its first packet.
//! - **New flow on the same tuple.** A packet idle for longer than its timeout starts a new
//!   flow (the old one ends with `Timeout`). A SYN (without ACK) starts a new flow when the
//!   previous connection was closed or reset, when the flow was picked up midstream (no
//!   handshake seen: the SYN starts a new connection), or when it comes from the client with an
//!   initial sequence number different from the recorded one (port reuse); the old flow ends
//!   `Closed`.
//! - **Closing.** A TCP connection closed by FIN in both directions or by RST stays in the
//!   table for a short linger (`min(tcp_timeout, 10 s)` of packet time) so that the final ACK
//!   and retransmissions stay attached to it; it then ends with `Closed`. Once closed or reset,
//!   a connection always ends with `Closed`, whatever removes it (linger, eviction, end of
//!   capture). Its buffered out-of-order data is flushed as soon as it closes.
//! - **Expiry.** The decision is taken **at lookup**, from the flow alone: a packet arriving
//!   more than the timeout after the last packet of its flow ends that flow (`Timeout`, its
//!   `last_ts` being the time of its last packet) and opens a new one. A periodic sweep, run
//!   when packet time has advanced by one second in the table, only releases memory: it ends
//!   flows idle for longer than their timeout plus a grace of 5 s (`SWEEP_GRACE_NS`),
//!   producing exactly the [`FlowCtx`] the lookup would have produced. The sweep therefore
//!   never changes how traffic is split into flows, whatever else shares the table (number of
//!   shards, chunking), unless timestamps step backwards by more than the grace. Flows are kept
//!   in one LRU list per timeout class (open TCP, closed TCP, UDP, other), ordered by last
//!   activity, so a sweep only looks at the oldest entries. Pending IP fragments follow the
//!   same rule: fragment time against first fragment time at lookup, sweep with the grace.
//! - **End of capture.** [`FlowTable::finish_at`] ends the remaining flows: `Timeout` for
//!   those idle for longer than their timeout at the given end time, `EndOfCapture` for the
//!   others. With the global end time, a flow gets the same reason whether a sweep released it
//!   earlier or not.
//! - **Eviction.** Beyond `max_flows`, the least recently active flow ends with `Evicted`.
//!   This is the only behavior that depends on what else shares the table (hence on the number
//!   of shards): with the default bound it should not trigger on realistic captures.
//! - **Determinism.** Hash maps are used for lookups only. Every batch of flow ends (sweep,
//!   end of capture) is sorted (LRU order, creation order) before being reported. The set of
//!   `FlowCtx` and of reassembled streams does not depend on how flows are spread over tables
//!   (eviction aside); only the interleaving of `on_flow_end` calls with other events does.
//!
//! # Reported packets
//!
//! [`FlowSink::on_packet`] is called once per frame, except IP fragments: a fragment is
//! absorbed silently until its datagram is complete, which is then reported once, decoded
//! from the reassembled bytes, with the timestamp, chunk and frame index of the completing fragment and the
//! summed wire length of all its fragments. In that [`Decoded`], `network` comes from the last
//! fragment with `fragment = None`, `payload` and `ip_payload` borrow the reassembly buffer,
//! and `l4_offset` is `None` (offsets refer to the last fragment frame). Rejected fragments
//! (incoherent, oversized, truncated by the snaplen) are reported alone with `flow: None`;
//! incomplete datagrams that time out or are evicted are dropped without report. Packets
//! without IP or with a decoding error also get `flow: None`.
//!
//! Flow counters count reported packets (a reassembled datagram counts as one packet) and wire
//! bytes (every fragment included).
//!
//! A TCP segment truncated by the capture snaplen is reassembled with the payload length
//! announced by its IP header: the lost tail is reported as a gap right away (see `tcp`).

use std::collections::{BTreeMap, HashMap};

use netsift_dissect::{
    Decoded, IpVersion, Network, TcpInfo, Transport, decode, decode_transport, proto,
};

use crate::api::{
    DirStats, Direction, EndReason, Endpoint, FlowConfig, FlowCtx, FlowId, FlowKey, FlowSink,
    PacketCtx, PacketFlow, StreamCtx, TcpState,
};
use crate::defrag::{Defragmenter, Outcome, Piece};
use crate::tcp::{Segment, Stream};

const NS_PER_SEC: i64 = 1_000_000_000;
/// Packet time between two expiry sweeps.
const SWEEP_INTERVAL_NS: i64 = NS_PER_SEC;
/// Extra idle time before the sweep releases a flow or a pending datagram: the sweep runs on
/// the table's high-water time, which may be ahead of a late (slightly backward) packet of the
/// flow; the grace keeps the lookup the only place where expiry is decided.
pub(crate) const SWEEP_GRACE_NS: i64 = 5 * NS_PER_SEC;
/// How long a closed or reset TCP connection stays in the table (capped by the TCP timeout).
const CLOSED_LINGER_NS: i64 = 10 * NS_PER_SEC;

/// Lookup key: protocol and unordered endpoint pair (`a <= b`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct Canon {
    proto: u8,
    a: Endpoint,
    b: Endpoint,
}

impl Canon {
    fn new(proto: u8, x: Endpoint, y: Endpoint) -> Self {
        let (a, b) = if x <= y { (x, y) } else { (y, x) };
        Self { proto, a, b }
    }
}

/// Timeout class: one LRU list each.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    TcpOpen,
    TcpClosed,
    Udp,
    Other,
}

impl Class {
    const ALL: [Self; 4] = [Self::TcpOpen, Self::TcpClosed, Self::Udp, Self::Other];
}

/// LRU lists by class: tick of last activity -> flow.
#[derive(Debug, Default)]
struct Lru {
    tcp_open: BTreeMap<u64, Canon>,
    tcp_closed: BTreeMap<u64, Canon>,
    udp: BTreeMap<u64, Canon>,
    other: BTreeMap<u64, Canon>,
}

impl Lru {
    fn list(&self, class: Class) -> &BTreeMap<u64, Canon> {
        match class {
            Class::TcpOpen => &self.tcp_open,
            Class::TcpClosed => &self.tcp_closed,
            Class::Udp => &self.udp,
            Class::Other => &self.other,
        }
    }

    fn list_mut(&mut self, class: Class) -> &mut BTreeMap<u64, Canon> {
        match class {
            Class::TcpOpen => &mut self.tcp_open,
            Class::TcpClosed => &mut self.tcp_closed,
            Class::Udp => &mut self.udp,
            Class::Other => &mut self.other,
        }
    }

    /// Least recently active flow of all classes.
    fn oldest(&self) -> Option<Canon> {
        Class::ALL
            .iter()
            .filter_map(|&c| self.list(c).first_key_value())
            .min_by_key(|(tick, _)| **tick)
            .map(|(_, canon)| *canon)
    }
}

/// TCP connection state (both directions).
#[derive(Debug, Default)]
#[allow(clippy::struct_excessive_bools)] // one flag per observed event
struct TcpConn {
    syn: bool,
    syn_ack: bool,
    established: bool,
    midstream: bool,
    fin_client: bool,
    fin_server: bool,
    rst: bool,
    client_isn: Option<u32>,
    to_server: Stream,
    to_client: Stream,
}

impl TcpConn {
    /// Closed by FIN both ways, or reset: buffered holes will not be filled any more.
    fn finished(&self) -> bool {
        self.rst || (self.fin_client && self.fin_server)
    }

    fn state(&self) -> TcpState {
        if self.rst {
            TcpState::Reset
        } else if self.fin_client && self.fin_server {
            TcpState::Closed
        } else if self.fin_client || self.fin_server {
            TcpState::Closing
        } else if self.midstream {
            TcpState::Midstream
        } else if self.established {
            TcpState::Established
        } else if self.syn_ack {
            TcpState::SynReceived
        } else {
            TcpState::SynSent
        }
    }

    fn update(&mut self, t: &TcpInfo, dir: Direction) {
        let f = t.flags;
        if f.rst() {
            self.rst = true;
        }
        if f.syn() && !f.ack() && dir == Direction::ToServer {
            self.syn = true;
            self.client_isn.get_or_insert(t.seq);
        }
        if f.syn() && f.ack() && dir == Direction::ToClient {
            self.syn_ack = true;
        }
        if !f.syn() && f.ack() && (self.syn || self.syn_ack) {
            self.established = true;
        }
        if f.fin() {
            match dir {
                Direction::ToServer => self.fin_client = true,
                Direction::ToClient => self.fin_server = true,
            }
        }
    }

    fn stream_mut(&mut self, dir: Direction) -> &mut Stream {
        match dir {
            Direction::ToServer => &mut self.to_server,
            Direction::ToClient => &mut self.to_client,
        }
    }
}

#[derive(Debug)]
struct Flow {
    id: FlowId,
    key: FlowKey,
    /// Creation order (end-of-capture ordering).
    serial: u64,
    first_ts: i64,
    last_ts: i64,
    /// Chunk and frame of the packet that set `last_ts`.
    last_chunk: u32,
    last_frame: u64,
    to_server: DirStats,
    to_client: DirStats,
    /// Position in the LRU list of `class`.
    tick: u64,
    class: Class,
    tcp: Option<Box<TcpConn>>,
}

impl Flow {
    fn current_class(&self) -> Class {
        match self.tcp.as_deref() {
            Some(c) if c.finished() => Class::TcpClosed,
            Some(_) => Class::TcpOpen,
            None if self.key.proto == proto::UDP => Class::Udp,
            None => Class::Other,
        }
    }
}

/// Source of an event: packet time, chunk and global frame index.
#[derive(Debug, Clone, Copy)]
struct At {
    ts_ns: i64,
    chunk_id: u32,
    frame: u64,
}

/// Flushes the buffered data of both directions (holes reported as gaps).
fn flush_streams(conn: &mut TcpConn, at: At, id: FlowId, key: FlowKey, sink: &mut dyn FlowSink) {
    for dir in [Direction::ToServer, Direction::ToClient] {
        conn.stream_mut(dir).flush(&mut |gap, data| {
            let ctx = StreamCtx {
                ts_ns: at.ts_ns,
                chunk_id: at.chunk_id,
                frame: at.frame,
                id,
                key,
                gap_before: gap,
            };
            sink.on_stream(&ctx, dir, data);
        });
    }
}

/// The datagram rebuilt from fragments, decoded from `data` (see the module documentation).
fn reassembled<'b>(last: &Decoded<'b>, data: &'b [u8], next_header: u8) -> Decoded<'b> {
    let mut d = last.clone();
    d.ip_payload = data;
    d.payload = data;
    d.transport = None;
    d.l4_offset = None;
    d.error = None;
    let mut protocol = next_header;
    match decode_transport(next_header, data) {
        Ok(Some((t, payload))) => {
            protocol = match t {
                Transport::Tcp(_) => proto::TCP,
                Transport::Udp(_) => proto::UDP,
                Transport::Icmpv4(_) => proto::ICMP,
                Transport::Icmpv6(_) => proto::ICMPV6,
            };
            d.transport = Some(t);
            d.payload = payload;
        }
        Ok(None) => {}
        Err(e) => d.error = Some(e),
    }
    if let Some(Network::Ip(ip)) = d.network.as_mut() {
        ip.fragment = None;
        ip.protocol = protocol;
        ip.payload_len = data.len();
        ip.truncated = false;
    }
    d
}

/// One flow table per shard. Not `Sync`: owned by a single worker thread.
#[derive(Debug)]
pub struct FlowTable {
    config: FlowConfig,
    flows: HashMap<Canon, Flow>,
    lru: Lru,
    /// Last LRU tick handed out.
    tick: u64,
    /// Next creation serial.
    serial: u64,
    /// Highest packet time seen.
    now: i64,
    /// Packet time of the next expiry sweep.
    next_sweep: i64,
    defrag: Defragmenter,
}

impl FlowTable {
    pub fn new(config: FlowConfig) -> Self {
        Self {
            config,
            flows: HashMap::new(),
            lru: Lru::default(),
            tick: 0,
            serial: 0,
            now: i64::MIN,
            next_sweep: i64::MIN,
            defrag: Defragmenter::new(config.max_defrag_bytes, config.defrag_timeout_ns),
        }
    }

    pub fn config(&self) -> &FlowConfig {
        &self.config
    }

    /// Processes one captured frame. `frame` is its global index (see [`PacketCtx::frame`]),
    /// `wire_len` its original length on the wire. Frames must be passed in non-decreasing time order per shard (the engine guarantees it;
    /// small backward steps must be tolerated, never panic).
    // Frame metadata passed flat: called once per packet on the hot path (agreed signature).
    #[allow(clippy::too_many_arguments)]
    pub fn process(
        &mut self,
        ts_ns: i64,
        chunk_id: u32,
        frame: u64,
        linktype: u32,
        wire_len: u32,
        data: &[u8],
        sink: &mut dyn FlowSink,
    ) {
        let pkt = decode(linktype, data);
        let at = At {
            ts_ns,
            chunk_id,
            frame,
        };
        self.advance_clock(ts_ns, sink);
        let Some(ip) = pkt.ip() else {
            report_unflowed(at, wire_len, &pkt, sink);
            return;
        };
        let Some(fragment) = ip.fragment else {
            let announced = announced_tcp_len(&pkt, data);
            self.handle(at, wire_len, announced, &pkt, sink);
            return;
        };
        if ip.truncated {
            report_unflowed(at, wire_len, &pkt, sink);
            return;
        }
        let piece = Piece {
            ts_ns,
            version: ip.version,
            src: ip.src,
            dst: ip.dst,
            fragment,
            data: pkt.ip_payload,
            wire_len,
        };
        match self.defrag.push(&piece) {
            Outcome::Pending => {}
            Outcome::Rejected => report_unflowed(at, wire_len, &pkt, sink),
            Outcome::Complete(dg) => {
                let full = reassembled(&pkt, &dg.data, dg.next_header);
                let total = u32::try_from(dg.wire_len).unwrap_or(u32::MAX);
                self.handle(at, total, None, &full, sink);
            }
        }
    }

    /// Flushes every remaining flow with `EndReason::EndOfCapture`, then pending fragments.
    ///
    /// Same as [`FlowTable::finish_at`] with the latest packet time seen by this table: a
    /// flow already idle for longer than its timeout at that time ends with `Timeout`, as it
    /// would have if a later packet had come.
    pub fn finish(&mut self, sink: &mut dyn FlowSink) {
        self.finish_at(self.now, sink);
    }

    /// Flushes every remaining flow, in creation order, then drops pending fragments.
    ///
    /// `end_ts_ns` is the end of the capture (the latest packet time over **all** tables):
    /// flows idle for longer than their timeout at that time end with `Timeout`, the others
    /// with `EndOfCapture` (closed connections always end with `Closed`). Passing the global
    /// end makes the reasons independent of how flows are spread over tables: a flow released
    /// earlier by a sweep was idle for longer than its timeout before `end_ts_ns` too.
    pub fn finish_at(&mut self, end_ts_ns: i64, sink: &mut dyn FlowSink) {
        let mut all: Vec<(u64, Canon)> = self.flows.iter().map(|(c, f)| (f.serial, *c)).collect();
        all.sort_unstable_by_key(|&(serial, _)| serial);
        for (_, canon) in all {
            let idle = self
                .flows
                .get(&canon)
                .is_some_and(|f| end_ts_ns.saturating_sub(f.last_ts) > self.timeout(f.class));
            let reason = if idle {
                EndReason::Timeout
            } else {
                EndReason::EndOfCapture
            };
            self.end_flow(&canon, reason, sink);
        }
        self.lru = Lru::default();
        self.defrag.clear();
    }

    /// Number of flows currently tracked (for progress and memory reporting).
    pub fn active_flows(&self) -> usize {
        self.flows.len()
    }

    fn timeout(&self, class: Class) -> i64 {
        let c = &self.config;
        match class {
            Class::TcpOpen => c.tcp_timeout_ns,
            Class::TcpClosed => c.tcp_timeout_ns.min(CLOSED_LINGER_NS),
            Class::Udp => c.udp_timeout_ns,
            Class::Other => c.other_timeout_ns,
        }
    }

    fn advance_clock(&mut self, ts_ns: i64, sink: &mut dyn FlowSink) {
        self.now = self.now.max(ts_ns);
        if self.now >= self.next_sweep {
            self.sweep(self.now, sink);
            self.next_sweep = self.now.saturating_add(SWEEP_INTERVAL_NS);
        }
    }

    /// Releases the flows idle for longer than their timeout plus the grace at `now`, in LRU
    /// order, and the pending datagrams likewise.
    fn sweep(&mut self, now: i64, sink: &mut dyn FlowSink) {
        let mut expired: Vec<(u64, Class, Canon)> = Vec::new();
        for class in Class::ALL {
            let timeout = self.timeout(class).saturating_add(SWEEP_GRACE_NS);
            for (&tick, canon) in self.lru.list(class) {
                match self.flows.get(canon) {
                    Some(f) if now.saturating_sub(f.last_ts) <= timeout => break,
                    _ => expired.push((tick, class, *canon)),
                }
            }
        }
        expired.sort_unstable_by_key(|&(tick, _, _)| tick);
        for (tick, class, canon) in expired {
            if self.flows.get(&canon).is_some_and(|f| f.tick == tick) {
                self.end_flow(&canon, EndReason::Timeout, sink);
            } else {
                self.lru.list_mut(class).remove(&tick);
            }
        }
        self.defrag.expire(now.saturating_sub(SWEEP_GRACE_NS));
    }

    /// Removes a flow: flushes its streams, then reports its end.
    fn end_flow(&mut self, canon: &Canon, reason: EndReason, sink: &mut dyn FlowSink) {
        let Some(mut flow) = self.flows.remove(canon) else {
            return;
        };
        self.lru.list_mut(flow.class).remove(&flow.tick);
        let mut end = reason;
        let mut tcp_state = None;
        if let Some(conn) = flow.tcp.as_deref_mut() {
            let at = At {
                ts_ns: flow.last_ts,
                chunk_id: flow.last_chunk,
                frame: flow.last_frame,
            };
            flush_streams(conn, at, flow.id, flow.key, sink);
            if conn.finished() {
                end = EndReason::Closed;
            }
            tcp_state = Some(conn.state());
        }
        let ctx = FlowCtx {
            id: flow.id,
            key: flow.key,
            first_ts_ns: flow.first_ts,
            last_ts_ns: flow.last_ts,
            to_server: flow.to_server,
            to_client: flow.to_client,
            tcp_state,
            end,
        };
        sink.on_flow_end(&ctx);
    }

    /// Ends the existing flow of `canon` when this packet must start a new one.
    fn retire_stale(
        &mut self,
        canon: &Canon,
        ts_ns: i64,
        src: Endpoint,
        tcp: Option<&TcpInfo>,
        sink: &mut dyn FlowSink,
    ) {
        let Some(flow) = self.flows.get(canon) else {
            return;
        };
        let reason = if ts_ns.saturating_sub(flow.last_ts) > self.timeout(flow.class) {
            Some(EndReason::Timeout)
        } else {
            let fresh_syn = tcp.filter(|t| t.flags.syn() && !t.flags.ack());
            match (fresh_syn, flow.tcp.as_deref()) {
                (Some(t), Some(conn))
                    if conn.finished()
                        || conn.midstream
                        || (src == flow.key.client
                            && conn.client_isn.is_some_and(|isn| isn != t.seq)) =>
                {
                    Some(EndReason::Closed)
                }
                _ => None,
            }
        };
        if let Some(reason) = reason {
            self.end_flow(canon, reason, sink);
        }
    }

    /// Creates the flow of a first packet, evicting the least recently used flow if full.
    fn create(
        &mut self,
        canon: Canon,
        ts_ns: i64,
        src: Endpoint,
        dst: Endpoint,
        tcp: Option<&TcpInfo>,
        sink: &mut dyn FlowSink,
    ) {
        let cap = self.config.max_flows.max(1);
        while self.flows.len() >= cap {
            let Some(victim) = self.lru.oldest() else {
                break;
            };
            self.end_flow(&victim, EndReason::Evicted, sink);
        }
        let (client, server, conn) = match tcp {
            Some(t) if t.flags.syn() && t.flags.ack() => (dst, src, Some(TcpConn::default())),
            Some(t) if t.flags.syn() => (src, dst, Some(TcpConn::default())),
            Some(_) => (
                src,
                dst,
                Some(TcpConn {
                    midstream: true,
                    ..TcpConn::default()
                }),
            ),
            None => (src, dst, None),
        };
        let key = FlowKey {
            proto: canon.proto,
            client,
            server,
        };
        self.tick = self.tick.wrapping_add(1);
        let serial = self.serial;
        self.serial = self.serial.wrapping_add(1);
        let flow = Flow {
            id: FlowId::derive(&key, ts_ns),
            key,
            serial,
            first_ts: ts_ns,
            last_ts: ts_ns,
            last_chunk: 0,
            last_frame: 0,
            to_server: DirStats::default(),
            to_client: DirStats::default(),
            tick: self.tick,
            class: Class::Other,
            tcp: conn.map(Box::new),
        };
        let class = flow.current_class();
        let flow = Flow { class, ..flow };
        self.lru.list_mut(class).insert(self.tick, canon);
        self.flows.insert(canon, flow);
    }

    /// Tracks one decoded (possibly reassembled) packet and reports it.
    ///
    /// `announced_tcp`: TCP payload length announced by the IP header when the capture
    /// truncated the packet (see [`announced_tcp_len`]).
    fn handle(
        &mut self,
        at: At,
        wire_len: u32,
        announced_tcp: Option<u64>,
        pkt: &Decoded<'_>,
        sink: &mut dyn FlowSink,
    ) {
        let Some(ip) = pkt.ip().filter(|_| pkt.error.is_none()) else {
            report_unflowed(at, wire_len, pkt, sink);
            return;
        };
        let (sport, dport) = pkt.ports().unwrap_or((0, 0));
        let src = Endpoint {
            ip: ip.src,
            port: sport,
        };
        let dst = Endpoint {
            ip: ip.dst,
            port: dport,
        };
        let canon = Canon::new(ip.protocol, src, dst);
        let tcp = pkt.tcp().copied();
        let ts_ns = at.ts_ns;
        self.retire_stale(&canon, ts_ns, src, tcp.as_ref(), sink);
        if !self.flows.contains_key(&canon) {
            self.create(canon, ts_ns, src, dst, tcp.as_ref(), sink);
        }
        let Some(flow) = self.flows.get_mut(&canon) else {
            report_unflowed(at, wire_len, pkt, sink);
            return;
        };

        let dir = if src == flow.key.client {
            Direction::ToServer
        } else {
            Direction::ToClient
        };
        let stats = match dir {
            Direction::ToServer => &mut flow.to_server,
            Direction::ToClient => &mut flow.to_client,
        };
        stats.packets = stats.packets.saturating_add(1);
        stats.bytes = stats.bytes.saturating_add(u64::from(wire_len));
        if ts_ns >= flow.last_ts {
            flow.last_ts = ts_ns;
            flow.last_chunk = at.chunk_id;
            flow.last_frame = at.frame;
        }
        if let (Some(t), Some(conn)) = (tcp.as_ref(), flow.tcp.as_deref_mut()) {
            conn.update(t, dir);
        }
        let class = flow.current_class();
        if flow.tick != self.tick || flow.class != class {
            self.lru.list_mut(flow.class).remove(&flow.tick);
            self.tick = self.tick.wrapping_add(1);
            flow.tick = self.tick;
            flow.class = class;
            self.lru.list_mut(class).insert(self.tick, canon);
        }

        let (id, key) = (flow.id, flow.key);
        let ctx = PacketCtx {
            ts_ns,
            chunk_id: at.chunk_id,
            frame: at.frame,
            wire_len,
            flow: Some(PacketFlow { id, key, dir }),
        };
        sink.on_packet(&ctx, pkt);

        let (Some(t), Some(conn)) = (tcp, flow.tcp.as_deref_mut()) else {
            return;
        };
        if !t.flags.rst() {
            let seg = Segment {
                seq: t.seq,
                syn: t.flags.syn(),
                fin: t.flags.fin(),
                payload: pkt.payload,
                len: announced_tcp.unwrap_or(0),
            };
            conn.stream_mut(dir)
                .segment(&seg, self.config.max_stream_buffer, &mut |gap, data| {
                    let ctx = StreamCtx {
                        ts_ns,
                        chunk_id: at.chunk_id,
                        frame: at.frame,
                        id,
                        key,
                        gap_before: gap,
                    };
                    sink.on_stream(&ctx, dir, data);
                });
        }
        if conn.finished() {
            flush_streams(conn, at, id, key, sink);
        }
    }
}

/// TCP payload length announced by the IP header of a packet truncated by the capture snaplen
/// (`None` when not truncated, not TCP, or for an IPv6 jumbogram): IP total length minus the IP
/// and TCP headers, read from the frame.
fn announced_tcp_len(pkt: &Decoded<'_>, frame: &[u8]) -> Option<u64> {
    let ip = pkt.ip().filter(|ip| ip.truncated)?;
    let tcp = pkt.tcp()?;
    let l3 = frame.get(pkt.l3_offset?..)?;
    let be16 = |at: usize| -> Option<usize> {
        let b = l3.get(at..at.checked_add(2)?)?;
        Some(usize::from(u16::from_be_bytes(b.try_into().ok()?)))
    };
    let total = match ip.version {
        IpVersion::V4 => be16(2)?,
        IpVersion::V6 => match be16(4)? {
            0 => return None,
            n => n.checked_add(40)?,
        },
    };
    let tcp_len = total
        .checked_sub(ip.header_len)?
        .checked_sub(usize::from(tcp.header_len))?;
    u64::try_from(tcp_len).ok()
}

fn report_unflowed(at: At, wire_len: u32, pkt: &Decoded<'_>, sink: &mut dyn FlowSink) {
    let ctx = PacketCtx {
        ts_ns: at.ts_ns,
        chunk_id: at.chunk_id,
        frame: at.frame,
        wire_len,
        flow: None,
    };
    sink.on_packet(&ctx, pkt);
}
