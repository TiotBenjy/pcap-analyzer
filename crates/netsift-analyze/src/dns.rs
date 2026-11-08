//! The `dns` analyzer: DNS (UDP and TCP 53), mDNS (5353), LLMNR (5355) and the NetBIOS name
//! service (NBNS, UDP 137). One [`DnsTransaction`] per query/response pair.
//!
//! # Pairing
//!
//! A query sent to a unicast address waits for its response in memory, keyed by (transport,
//! protocol, client endpoint, transaction id), for at most [`DnsConfig::pair_window_ns`] of
//! packet time. A response pairs with the oldest waiting query of its key whose server is the
//! responder. Both directions of a unicast exchange reach the same shard, so this pairing is
//! complete and does not depend on the number of shards.
//!
//! A query sent to a group address (multicast or broadcast: NBNS broadcasts, LLMNR, mDNS) is
//! answered by whichever host owns the name, hence often in another shard, possibly by several
//! hosts. It is never paired here: it is emitted at once with [`DnsTransaction::pending`] set,
//! and its responses as response-only transactions. The store pairs them at the end of the
//! import, in an order that does not depend on the shards (see `netsift-store`, `dns.rs`).
//!
//! Memory is bounded per shard: [`DnsConfig::max_pending`] waiting queries and
//! [`DnsConfig::max_pending_bytes`] for them, [`DnsConfig::max_stream_bytes`] of partial
//! DNS-over-TCP messages.
//!
//! # Outcome
//!
//! - answered: `rcode` of the response (`NOERROR`, `NXDOMAIN`... `RCODE<n>` when unknown), with
//!   the latency;
//! - unanswered and a response was expected: `rcode` = [`TIMEOUT`] (for a group query, until
//!   the store finds its response);
//! - unanswered and no response is expected (mDNS queries, NBNS broadcast registrations,
//!   releases and refreshes): `rcode` = `None`;
//! - a response without query (query not captured, mDNS announcements, late responses): a
//!   transaction with only the response side, without latency.
//!
//! Names resolved by the responses feed `hosts.names` at the end of the import (store side),
//! for the hosts seen in the capture only.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};

use netsift_dissect::dns::{self, Flavor, Message, RData, Section};
use netsift_dissect::{Decoded, Network};
use netsift_flow::{Direction, Endpoint, FlowCtx, FlowId, PacketCtx, StreamCtx};

use crate::analyzer::{Analyzer, AnalyzerId, RecordSink};
use crate::record::Record;
use crate::registry::AnalyzerConfig;

/// Outcome of a query left without response although one was expected.
pub const TIMEOUT: &str = "timeout";
/// Answers kept per transaction.
pub const MAX_ANSWERS: usize = 32;
/// Largest DNS message accepted on a TCP stream (the length prefix is 16 bits).
const MAX_TCP_MESSAGE: usize = 65_535;

/// UDP ports.
const PORT_DNS: u16 = 53;
const PORT_NBNS: u16 = 137;
const PORT_MDNS: u16 = 5353;
const PORT_LLMNR: u16 = 5355;
const TCP: u8 = 6;
const UDP: u8 = 17;
/// NBNS opcode of a name query.
const NBNS_QUERY: u8 = 0;

/// Settings of the `dns` analyzer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsConfig {
    /// Longest wait for a response, in packet time (ns).
    pub pair_window_ns: i64,
    /// Queries waiting for a response per shard; beyond, the oldest is emitted unanswered.
    pub max_pending: usize,
    /// Approximate memory of the waiting queries per shard, in bytes (same eviction).
    pub max_pending_bytes: usize,
    /// Partial DNS-over-TCP messages buffered per shard, in bytes; beyond, the direction that
    /// would exceed it is given up until the end of its flow.
    pub max_stream_bytes: usize,
}

/// Default response window (5 s, `docs/specs/dns.md`).
pub const PAIR_WINDOW_NS: i64 = 5_000_000_000;

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            pair_window_ns: PAIR_WINDOW_NS,
            max_pending: 65_536,
            max_pending_bytes: 32 * 1024 * 1024,
            max_stream_bytes: 32 * 1024 * 1024,
        }
    }
}

/// Name service protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DnsProto {
    Dns,
    Mdns,
    Llmnr,
    Nbns,
}

impl DnsProto {
    /// Label stored in the database.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Dns => "dns",
            Self::Mdns => "mdns",
            Self::Llmnr => "llmnr",
            Self::Nbns => "nbns",
        }
    }

    fn flavor(self) -> Flavor {
        if self == Self::Nbns {
            Flavor::Nbns
        } else {
            Flavor::Dns
        }
    }

    /// Protocol of a UDP datagram, by port (NBNS first: its port is the most specific).
    fn of_udp(sport: u16, dport: u16) -> Option<Self> {
        let either = |p: u16| sport == p || dport == p;
        [
            (PORT_NBNS, Self::Nbns),
            (PORT_MDNS, Self::Mdns),
            (PORT_LLMNR, Self::Llmnr),
            (PORT_DNS, Self::Dns),
        ]
        .into_iter()
        .find_map(|(port, proto)| either(port).then_some(proto))
    }

    /// Protocol of a TCP connection, by server port (DNS and LLMNR define TCP transports).
    fn of_tcp(server_port: u16) -> Option<Self> {
        match server_port {
            PORT_DNS => Some(Self::Dns),
            PORT_LLMNR => Some(Self::Llmnr),
            PORT_MDNS => Some(Self::Mdns),
            _ => None,
        }
    }
}

/// One answer record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsAnswer {
    /// Owner name.
    pub name: String,
    /// Type mnemonic (`A`, `CNAME`, `NB`, `TYPE65534`...).
    pub rtype: String,
    /// Value in presentation form (address, name, text...), empty when not decoded.
    pub value: String,
    pub ttl: u32,
}

/// A query and its response (either side may be missing, see the module documentation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsTransaction {
    /// Time of the query, or of the response when there is no query.
    pub ts_ns: i64,
    /// Flow of the query (or of the response without query).
    pub flow: Option<FlowId>,
    /// IP protocol (6 TCP, 17 UDP).
    pub transport: u8,
    pub proto: DnsProto,
    /// Sender of the query (receiver of a response without query).
    pub client: Endpoint,
    /// Destination of the query (possibly a group address), or sender of a response without
    /// query.
    pub server: Endpoint,
    /// Sender of the response when it is not `server` (query sent to a group address).
    pub responder: Option<IpAddr>,
    pub id: u16,
    /// Opcode name (`QUERY`, `UPDATE`, `REGISTRATION`...).
    pub opcode: String,
    /// First question name; first answer owner when the message has no question.
    pub qname: String,
    /// Type of the first question (`A`, `NB`...), empty when unknown.
    pub qtype: String,
    /// NetBIOS suffix of the name (NBNS only).
    pub nb_suffix: Option<u8>,
    /// Flags of the response, or of the query when unanswered.
    pub flags: u16,
    /// Response code name, [`TIMEOUT`], or `None` (no response expected and none seen).
    pub rcode: Option<String>,
    /// Response time minus query time (ns), when both were seen.
    pub latency_ns: Option<i64>,
    /// Answer records of the response (for NBNS registrations, the registered addresses).
    pub answers: Vec<DnsAnswer>,
    pub has_query: bool,
    pub has_response: bool,
    /// Unanswered query sent to a group address, to be paired by the store at the end of the
    /// import with a response-only transaction of the same key.
    pub pending: bool,
}

/// Key of a waiting query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct PairKey {
    transport: u8,
    proto: DnsProto,
    client: Endpoint,
    id: u16,
}

/// A query waiting for its response.
#[derive(Debug)]
struct Waiting {
    key: PairKey,
    /// The query, completed when the response arrives.
    tx: DnsTransaction,
    expects_response: bool,
    /// Approximate memory of `tx`.
    bytes: usize,
}

/// Where a message comes from.
#[derive(Debug, Clone, Copy)]
struct Origin {
    ts_ns: i64,
    flow: Option<FlowId>,
    transport: u8,
    proto: DnsProto,
    src: Endpoint,
    dst: Endpoint,
    /// The destination is a multicast or broadcast address.
    to_group: bool,
}

/// See the module documentation.
#[derive(Debug)]
pub struct DnsAnalyzer {
    window_ns: i64,
    max_pending: usize,
    /// Waiting queries in arrival order.
    waiting: BTreeMap<u64, Waiting>,
    /// Arrival numbers of the waiting queries, per key, oldest first.
    by_key: HashMap<PairKey, Vec<u64>>,
    next_seq: u64,
    max_pending_bytes: usize,
    /// Approximate memory of the waiting queries.
    pending_bytes: usize,
    /// Partial DNS-over-TCP message, per flow direction.
    streams: HashMap<(FlowId, bool), Vec<u8>>,
    max_stream_bytes: usize,
    /// Bytes held in `streams`.
    stream_bytes: usize,
    /// Directions whose framing was lost (gap, invalid message, memory bound), until the end
    /// of their flow.
    desynced: HashSet<(FlowId, bool)>,
}

impl DnsAnalyzer {
    pub const ID: AnalyzerId = AnalyzerId("dns");

    pub fn new(config: &AnalyzerConfig) -> Self {
        Self {
            window_ns: config.dns.pair_window_ns.max(0),
            max_pending: config.dns.max_pending.max(1),
            waiting: BTreeMap::new(),
            by_key: HashMap::new(),
            next_seq: 0,
            max_pending_bytes: config.dns.max_pending_bytes.max(1),
            pending_bytes: 0,
            streams: HashMap::new(),
            max_stream_bytes: config.dns.max_stream_bytes,
            stream_bytes: 0,
            desynced: HashSet::new(),
        }
    }

    /// [`crate::registry::Factory`] of this analyzer.
    pub fn boxed(config: &AnalyzerConfig) -> Box<dyn Analyzer> {
        Box::new(Self::new(config))
    }

    /// Emits the queries whose window ended before `now`.
    fn expire(&mut self, now: i64, out: &mut dyn RecordSink) {
        while let Some(entry) = self.waiting.first_entry() {
            if now.saturating_sub(entry.get().tx.ts_ns) <= self.window_ns {
                break;
            }
            let (seq, w) = entry.remove_entry();
            self.forget(w.key, seq, w.bytes);
            emit_unanswered(w, out);
        }
    }

    /// Removes the index entry and the memory of a query that stopped waiting.
    fn forget(&mut self, key: PairKey, seq: u64, bytes: usize) {
        self.unindex(key, seq);
        self.pending_bytes = self.pending_bytes.saturating_sub(bytes);
    }

    fn unindex(&mut self, key: PairKey, seq: u64) {
        if let Some(seqs) = self.by_key.get_mut(&key) {
            seqs.retain(|s| *s != seq);
            if seqs.is_empty() {
                self.by_key.remove(&key);
            }
        }
    }

    /// Handles one message; false when it is not a DNS message at all.
    fn handle(&mut self, origin: &Origin, payload: &[u8], out: &mut dyn RecordSink) -> bool {
        let Ok(msg) = dns::parse(payload, origin.proto.flavor()) else {
            return false;
        };
        if msg.header.is_response() {
            self.on_response(origin, &msg, out);
        } else {
            self.on_query(origin, &msg, out);
        }
        true
    }

    fn on_query(&mut self, o: &Origin, msg: &Message, out: &mut dyn RecordSink) {
        let flavor = o.proto.flavor();
        let opcode = msg.header.opcode();
        let (qname, qtype, nb_suffix) = subject(msg, flavor);
        let expects_response = match o.proto {
            DnsProto::Mdns => false,
            DnsProto::Nbns => opcode == NBNS_QUERY || !o.to_group,
            DnsProto::Dns | DnsProto::Llmnr => true,
        };
        // NBNS registrations, releases and refreshes carry the address in the additional section.
        let answers = if o.proto == DnsProto::Nbns && opcode != NBNS_QUERY {
            answers_of(msg, flavor, Section::Additional)
        } else {
            Vec::new()
        };
        let tx = DnsTransaction {
            ts_ns: o.ts_ns,
            flow: o.flow,
            transport: o.transport,
            proto: o.proto,
            client: o.src,
            server: o.dst,
            responder: None,
            id: msg.header.id,
            opcode: dns::opcode_name(flavor, opcode),
            qname,
            qtype,
            nb_suffix,
            flags: msg.header.flags,
            rcode: None,
            latency_ns: None,
            answers,
            has_query: true,
            has_response: false,
            pending: false,
        };
        let key = PairKey {
            transport: o.transport,
            proto: o.proto,
            client: o.src,
            id: msg.header.id,
        };
        if o.to_group {
            // Paired by the store, whatever shard its responses reach.
            let mut tx = tx;
            tx.pending = true;
            tx.rcode = expects_response.then(|| TIMEOUT.to_owned());
            out.emit(Record::Dns(Box::new(tx)));
            return;
        }
        let bytes = approx_size(&tx);
        while self.waiting.len() >= self.max_pending
            || (!self.waiting.is_empty()
                && self.pending_bytes.saturating_add(bytes) > self.max_pending_bytes)
        {
            let Some((seq, w)) = self.waiting.pop_first() else {
                break;
            };
            self.forget(w.key, seq, w.bytes);
            emit_unanswered(w, out);
        }
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        self.waiting.insert(
            seq,
            Waiting {
                key,
                tx,
                expects_response,
                bytes,
            },
        );
        self.pending_bytes = self.pending_bytes.saturating_add(bytes);
        self.by_key.entry(key).or_default().push(seq);
    }

    fn on_response(&mut self, o: &Origin, msg: &Message, out: &mut dyn RecordSink) {
        let flavor = o.proto.flavor();
        let key = PairKey {
            transport: o.transport,
            proto: o.proto,
            client: o.dst,
            id: msg.header.id,
        };
        let matched = self.by_key.get(&key).and_then(|seqs| {
            seqs.iter().copied().find(|seq| {
                self.waiting.get(seq).is_some_and(|w| {
                    w.tx.server.ip == o.src.ip
                        && o.ts_ns.saturating_sub(w.tx.ts_ns) <= self.window_ns
                })
            })
        });
        let rcode = Some(dns::rcode_name(flavor, msg.header.rcode()));
        let answers = answers_of(msg, flavor, Section::Answer);
        if let Some(seq) = matched
            && let Some(w) = self.waiting.remove(&seq)
        {
            self.forget(key, seq, w.bytes);
            let mut tx = w.tx;
            if tx.server.ip != o.src.ip {
                tx.responder = Some(o.src.ip);
            }
            tx.flags = msg.header.flags;
            tx.rcode = rcode;
            tx.latency_ns = Some(o.ts_ns.saturating_sub(tx.ts_ns).max(0));
            if !answers.is_empty() || tx.answers.is_empty() {
                tx.answers = answers;
            }
            tx.has_response = true;
            out.emit(Record::Dns(Box::new(tx)));
            return;
        }
        let (qname, qtype, nb_suffix) = subject(msg, flavor);
        out.emit(Record::Dns(Box::new(DnsTransaction {
            ts_ns: o.ts_ns,
            flow: o.flow,
            transport: o.transport,
            proto: o.proto,
            client: o.dst,
            server: o.src,
            responder: None,
            id: msg.header.id,
            opcode: dns::opcode_name(flavor, msg.header.opcode()),
            qname,
            qtype,
            nb_suffix,
            flags: msg.header.flags,
            rcode,
            latency_ns: None,
            answers,
            has_query: false,
            has_response: true,
            pending: false,
        })));
    }

    fn on_tcp_data(
        &mut self,
        ctx: &StreamCtx,
        dir: Direction,
        proto: DnsProto,
        data: &[u8],
        out: &mut dyn RecordSink,
    ) {
        let to_server = dir == Direction::ToServer;
        let (src, dst) = if to_server {
            (ctx.key.client, ctx.key.server)
        } else {
            (ctx.key.server, ctx.key.client)
        };
        let origin = Origin {
            ts_ns: ctx.ts_ns,
            flow: Some(ctx.id),
            transport: TCP,
            proto,
            src,
            dst,
            to_group: false,
        };
        let slot = (ctx.id, to_server);
        if self.desynced.contains(&slot) {
            return;
        }
        let held = self.streams.remove(&slot).unwrap_or_default();
        self.stream_bytes = self.stream_bytes.saturating_sub(held.len());
        if ctx.gap_before > 0 {
            // Lost bytes: the framing is unknown for the rest of this direction.
            self.desynced.insert(slot);
            return;
        }
        // Without a partial message, the data is framed in place (no copy).
        let joined;
        let input: &[u8] = if held.is_empty() {
            data
        } else {
            let mut buf = held;
            buf.extend_from_slice(data);
            joined = buf;
            &joined
        };
        let mut pos = 0usize;
        while let Some(prefix) = input.get(pos..).and_then(<[u8]>::first_chunk::<2>) {
            let len = usize::from(u16::from_be_bytes(*prefix));
            let start = pos.saturating_add(2);
            let Some(message) = input.get(start..start.saturating_add(len)) else {
                break;
            };
            // Shorter than a header, or not DNS: the stream is not (or no longer) framed.
            if len < dns::HEADER_LEN || !self.handle(&origin, message, out) {
                self.desynced.insert(slot);
                return;
            }
            pos = start.saturating_add(len);
        }
        let rest = input.get(pos..).unwrap_or_default();
        if rest.is_empty() {
            return;
        }
        if rest.len() > MAX_TCP_MESSAGE.saturating_add(2)
            || self.stream_bytes.saturating_add(rest.len()) > self.max_stream_bytes
        {
            self.desynced.insert(slot);
            return;
        }
        self.stream_bytes = self.stream_bytes.saturating_add(rest.len());
        self.streams.insert(slot, rest.to_vec());
    }
}

/// Emits a query that got no response.
fn emit_unanswered(w: Waiting, out: &mut dyn RecordSink) {
    let mut tx = w.tx;
    if w.expects_response {
        tx.rcode = Some(TIMEOUT.to_owned());
    }
    out.emit(Record::Dns(Box::new(tx)));
}

/// Approximate heap and inline memory of a transaction.
fn approx_size(tx: &DnsTransaction) -> usize {
    let answers: usize = tx
        .answers
        .iter()
        .map(|a| std::mem::size_of::<DnsAnswer>() + a.name.len() + a.rtype.len() + a.value.len())
        .sum();
    std::mem::size_of::<DnsTransaction>()
        + tx.qname.len()
        + tx.qtype.len()
        + tx.opcode.len()
        + answers
}

/// Name, type and NetBIOS suffix that a message is about: its first question, else its first
/// answer.
fn subject(msg: &Message, flavor: Flavor) -> (String, String, Option<u8>) {
    if let Some(q) = msg.questions.first() {
        return (
            q.name.name.clone(),
            dns::type_name(flavor, q.qtype),
            q.name.suffix,
        );
    }
    msg.records
        .iter()
        .find(|r| r.rtype != dns::rtype::OPT)
        .map_or_else(
            || (String::new(), String::new(), None),
            |r| {
                (
                    r.name.name.clone(),
                    dns::type_name(flavor, r.rtype),
                    r.name.suffix,
                )
            },
        )
}

fn answers_of(msg: &Message, flavor: Flavor, section: Section) -> Vec<DnsAnswer> {
    msg.records
        .iter()
        .filter(|r| r.section == section && r.rtype != dns::rtype::OPT)
        .filter(|r| section == Section::Answer || matches!(r.data, RData::Nb(_)))
        .flat_map(|r| {
            let rtype = dns::type_name(flavor, r.rtype);
            // One answer per address of an NB record, so that each value is one address.
            let values = match &r.data {
                RData::Nb(addrs) if !addrs.is_empty() => {
                    addrs.iter().map(|a| a.addr.to_string()).collect()
                }
                data => vec![dns::rdata_text(data)],
            };
            values.into_iter().map(move |value| DnsAnswer {
                name: r.name.name.clone(),
                rtype: rtype.clone(),
                value,
                ttl: r.ttl,
            })
        })
        .take(MAX_ANSWERS)
        .collect()
}

/// Multicast destination, limited broadcast, or a frame sent to a group MAC address (subnet
/// broadcasts).
fn is_group(pkt: &Decoded<'_>, dst: IpAddr) -> bool {
    dst.is_multicast()
        || dst == IpAddr::V4(Ipv4Addr::BROADCAST)
        || pkt.link.dst_mac.is_some_and(|m| m.is_multicast())
}

impl Analyzer for DnsAnalyzer {
    fn id(&self) -> AnalyzerId {
        Self::ID
    }

    fn on_packet(&mut self, ctx: &PacketCtx, pkt: &Decoded<'_>, out: &mut dyn RecordSink) {
        self.expire(ctx.ts_ns, out);
        let (Some(udp), Some(Network::Ip(ip))) = (pkt.udp(), &pkt.network) else {
            return;
        };
        let Some(proto) = DnsProto::of_udp(udp.src_port, udp.dst_port) else {
            return;
        };
        let origin = Origin {
            ts_ns: ctx.ts_ns,
            flow: ctx.flow.map(|f| f.id),
            transport: UDP,
            proto,
            src: Endpoint {
                ip: ip.src,
                port: udp.src_port,
            },
            dst: Endpoint {
                ip: ip.dst,
                port: udp.dst_port,
            },
            to_group: is_group(pkt, ip.dst),
        };
        self.handle(&origin, pkt.payload, out);
    }

    fn on_stream(
        &mut self,
        ctx: &StreamCtx,
        dir: Direction,
        data: &[u8],
        out: &mut dyn RecordSink,
    ) {
        if ctx.key.proto != TCP {
            return;
        }
        let Some(proto) = DnsProto::of_tcp(ctx.key.server.port) else {
            return;
        };
        self.expire(ctx.ts_ns, out);
        self.on_tcp_data(ctx, dir, proto, data, out);
    }

    fn on_flow_end(&mut self, ctx: &FlowCtx, _out: &mut dyn RecordSink) {
        if ctx.key.proto == TCP {
            for dir in [true, false] {
                if let Some(buf) = self.streams.remove(&(ctx.id, dir)) {
                    self.stream_bytes = self.stream_bytes.saturating_sub(buf.len());
                }
                self.desynced.remove(&(ctx.id, dir));
            }
        }
    }

    fn finish(&mut self, out: &mut dyn RecordSink) {
        self.by_key.clear();
        for (_, w) in std::mem::take(&mut self.waiting) {
            emit_unanswered(w, out);
        }
        self.pending_bytes = 0;
        self.streams.clear();
        self.stream_bytes = 0;
        self.desynced.clear();
    }
}

#[cfg(test)]
mod tests;
