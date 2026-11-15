//! Interface between the flow layer (task P1.6) and the ingestion engine (task P1.7).
//! Frozen before both tasks start: change it only by agreement.
//!
//! Data path (docs/ARCHITECTURE.md, "Modèle d'exécution du pipeline"):
//! 1. the decoder thread decodes each frame and routes it with [`shard_hash`], so that both
//!    directions of a flow **and all IP fragments of a datagram** reach the same shard;
//! 2. each shard owns one [`crate::FlowTable`] and calls [`crate::FlowTable::process`] for every
//!    frame (the shard decodes again: `Decoded` borrows the frame and cannot cross threads);
//! 3. the table defragments, tracks flows, reassembles TCP, and reports to a [`FlowSink`]
//!    (the engine fans these events out to the analyzers).
//!
//! All time is **packet time** (`ts_ns`, nanoseconds since the Unix epoch, UTC), never wall clock.

use std::net::IpAddr;

use netsift_dissect::{Decoded, Network};

/// One side of a transport conversation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Endpoint {
    pub ip: IpAddr,
    /// 0 for protocols without ports (ICMP, other IP protocols).
    pub port: u16,
}

/// Oriented flow key: `client` is the initiator (sender of the SYN for TCP, otherwise the
/// sender of the first packet seen), `server` the other side.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FlowKey {
    /// IP protocol number (6 TCP, 17 UDP, 1 ICMP, 58 `ICMPv6`, ...).
    pub proto: u8,
    pub client: Endpoint,
    pub server: Endpoint,
}

/// Direction of a packet or of stream data within a flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    ToServer,
    ToClient,
}

/// Flow identifier: the global index ([`PacketCtx::frame`]) of the frame that created the flow,
/// that is its first packet (for a flow opened by a reassembled IP datagram, the fragment that
/// completed it).
///
/// Unique by construction, without hashing: the engine numbers frames once, in reading order,
/// before sharding, and a frame creates at most one flow. Two instances of the same 5-tuple
/// starting at the same timestamp (connection closed then reopened, LRU eviction, constant or
/// hostile timestamps) therefore get distinct ids, and no input can provoke a collision. The id
/// does not depend on the number of shards nor on the chunking of the input: a chunk set and a
/// single file deliver the same frames in the same order (docs/DECISIONS.md, ADR-022).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FlowId(pub i64);

impl FlowId {
    /// Id of the flow created by global frame `frame`. Non-negative (SQLite rowid); frames
    /// beyond `i64::MAX` (unreachable: 2^63 packets) are clamped.
    pub fn from_first_frame(frame: u64) -> Self {
        Self(i64::try_from(frame).unwrap_or(i64::MAX))
    }
}

/// Flow membership of a packet, when it belongs to a tracked flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketFlow {
    pub id: FlowId,
    pub key: FlowKey,
    pub dir: Direction,
}

/// Context of [`FlowSink::on_packet`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketCtx {
    pub ts_ns: i64,
    pub chunk_id: u32,
    /// Global frame index (0-based, in reading order over the whole chunk set), assigned by the
    /// engine; identifies the source packet for provenance and PCAP export.
    pub frame: u64,
    /// Original length on the wire of the frame (for byte counters), >= captured length.
    pub wire_len: u32,
    /// `None` for packets outside any flow (non-IP, undecodable, rejected IP fragments).
    /// Fragments of a datagram being reassembled are absorbed and not reported until the
    /// datagram is complete; an incomplete datagram is never reported.
    pub flow: Option<PacketFlow>,
}

/// Context of [`FlowSink::on_stream`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamCtx {
    /// Time of the packet that completed this in-order data.
    pub ts_ns: i64,
    pub chunk_id: u32,
    /// Global frame index (0-based, in reading order over the whole chunk set), assigned by the
    /// engine; identifies the source packet for provenance and PCAP export. Here, the frame
    /// that completed this data.
    pub frame: u64,
    pub id: FlowId,
    pub key: FlowKey,
    /// Bytes known to be missing just before this data (lost segments, buffer limit). Analyzers
    /// must resynchronize or give up on the current message when it is non-zero.
    pub gap_before: u64,
}

/// TCP connection state as observed (both directions).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TcpState {
    /// Only the SYN was seen.
    SynSent,
    /// SYN and SYN-ACK seen.
    SynReceived,
    Established,
    /// At least one FIN seen.
    Closing,
    /// FIN seen in both directions.
    Closed,
    Reset,
    /// The handshake was not captured (flow picked up in the middle).
    Midstream,
}

/// Why a flow ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EndReason {
    /// TCP closed (FIN both ways) or reset.
    Closed,
    /// Idle longer than the configured timeout (in packet time).
    Timeout,
    /// Evicted because the table reached `max_flows` (least recently used first).
    Evicted,
    /// End of the capture: every remaining flow is flushed by [`crate::FlowTable::finish_at`]
    /// (or [`crate::FlowTable::finish`]).
    EndOfCapture,
}

/// Per-direction counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DirStats {
    pub packets: u64,
    /// Wire bytes (frame `wire_len`), the unit used by the Overview and Connections views.
    pub bytes: u64,
}

/// Context of [`FlowSink::on_flow_end`]: the flow summary that becomes a row of `flows`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowCtx {
    pub id: FlowId,
    pub key: FlowKey,
    pub first_ts_ns: i64,
    pub last_ts_ns: i64,
    pub to_server: DirStats,
    pub to_client: DirStats,
    /// `None` for non-TCP flows.
    pub tcp_state: Option<TcpState>,
    pub end: EndReason,
}

/// Consumer of flow events. Implemented by the engine (P1.7), which fans out to analyzers.
pub trait FlowSink {
    /// Every decoded packet, after IP defragmentation: one event per frame, except IP fragments,
    /// which are absorbed; `on_packet` reports one event per reassembled datagram, with the
    /// timestamp, chunk and frame of its last fragment and the summed wire length of its
    /// fragments. An incomplete datagram (timed out, evicted, end of capture) is never reported.
    /// The engine counts global frames and bytes from raw frames before `process`.
    fn on_packet(&mut self, ctx: &PacketCtx, pkt: &Decoded<'_>);

    /// In-order reassembled TCP payload for one direction (retransmissions removed, overlaps
    /// resolved, bounded per flow by [`FlowConfig::max_stream_buffer`]).
    fn on_stream(&mut self, ctx: &StreamCtx, dir: Direction, data: &[u8]);

    /// A flow ended (closed, timed out, evicted, or end of capture). Called exactly once per flow.
    fn on_flow_end(&mut self, ctx: &FlowCtx);
}

/// Bounds and timeouts (docs/ARCHITECTURE.md, "Performance"). All durations in packet time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowConfig {
    pub tcp_timeout_ns: i64,
    pub udp_timeout_ns: i64,
    /// Other protocols (ICMP, ...).
    pub other_timeout_ns: i64,
    /// Maximum tracked flows **per table** (LRU eviction beyond); the engine divides its global
    /// bound by the number of shards.
    pub max_flows: usize,
    /// Maximum out-of-order bytes buffered per direction of a TCP flow, counting a fixed
    /// overhead per buffered piece.
    pub max_stream_buffer: usize,
    /// Fragments of an incomplete datagram are dropped after this delay.
    pub defrag_timeout_ns: i64,
    /// Total bytes held by pending fragments **per table** (plus fixed overheads); the engine
    /// divides its global bound by the number of shards.
    pub max_defrag_bytes: usize,
}

impl Default for FlowConfig {
    fn default() -> Self {
        const S: i64 = 1_000_000_000;
        Self {
            tcp_timeout_ns: 300 * S,
            udp_timeout_ns: 60 * S,
            other_timeout_ns: 60 * S,
            max_flows: 2_000_000,
            max_stream_buffer: 16 * 1024 * 1024,
            defrag_timeout_ns: 30 * S,
            max_defrag_bytes: 64 * 1024 * 1024,
        }
    }
}

/// Shard routing key: protocol + **unordered** IP pair, ports ignored, so that both directions
/// and every fragment of a datagram land on the same shard. Non-IP frames hash to 0.
pub fn shard_hash(pkt: &Decoded<'_>) -> u64 {
    let Some(Network::Ip(ip)) = &pkt.network else {
        return 0;
    };
    let (lo, hi) = if ip.src <= ip.dst {
        (ip.src, ip.dst)
    } else {
        (ip.dst, ip.src)
    };
    let mut h = Fnv::new();
    h.byte(ip.protocol);
    h.ip(&lo);
    h.ip(&hi);
    h.finish()
}

/// Small deterministic FNV-1a (no `std` hasher: its output is not guaranteed stable).
struct Fnv(u64);

impl Fnv {
    fn new() -> Self {
        Self(0xcbf2_9ce4_8422_2325)
    }
    fn byte(&mut self, b: u8) {
        self.0 ^= u64::from(b);
        self.0 = self.0.wrapping_mul(0x0000_0100_0000_01b3);
    }
    fn bytes(&mut self, bs: &[u8]) {
        for &b in bs {
            self.byte(b);
        }
    }
    fn ip(&mut self, ip: &IpAddr) {
        match ip {
            IpAddr::V4(v4) => {
                self.byte(4);
                self.bytes(&v4.octets());
            }
            IpAddr::V6(v6) => {
                self.byte(6);
                self.bytes(&v6.octets());
            }
        }
    }
    fn finish(&self) -> u64 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flow_id_is_the_first_frame_and_ignores_key_and_time() {
        assert_eq!(FlowId::from_first_frame(0), FlowId(0));
        assert_eq!(FlowId::from_first_frame(41), FlowId(41));
        assert_eq!(
            FlowId::from_first_frame(i64::MAX.unsigned_abs()),
            FlowId(i64::MAX)
        );
        // Unreachable in practice (2^63 frames): clamped, never negative.
        assert_eq!(FlowId::from_first_frame(u64::MAX), FlowId(i64::MAX));
        // Two flows can only share an id if they share their first frame, which a frame
        // never does (it creates at most one flow): distinct frames, distinct ids.
        let ids: std::collections::BTreeSet<FlowId> =
            (0..10_000u64).map(FlowId::from_first_frame).collect();
        assert_eq!(ids.len(), 10_000);
    }

    #[test]
    fn default_config_matches_architecture_bounds() {
        let c = FlowConfig::default();
        assert_eq!(c.tcp_timeout_ns, 300_000_000_000);
        assert_eq!(c.udp_timeout_ns, 60_000_000_000);
        assert_eq!(c.max_flows, 2_000_000);
        assert_eq!(c.max_stream_buffer, 16 * 1024 * 1024);
    }
}
