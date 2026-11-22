//! The `ethernet` analyzer: link-layer addresses, pairs, EtherTypes and VLANs for the Ethernet
//! view (`docs/specs/ethernet.md`).
//!
//! Every frame of an Ethernet or Linux cooked capture (802.11 frames belong to the WiFi view) is
//! folded, never stored one by one, into:
//! - its **source and destination MAC addresses**: frames and wire bytes sent and received,
//!   first and last frame times, VLAN stacks seen (at most [`MAX_VLANS`]), and, at flush time,
//!   the IEEE vendor ([`crate::oui`]);
//! - its **pair** (source -> destination, directional): frames, bytes, times, EtherTypes (at
//!   most [`MAX_ETHERTYPES`]) and VLAN stacks;
//! - its **EtherType** ([`EtherKey`]) and its **VLAN stack** (outermost tag first), when tagged.
//!
//! Like the `connections` analyzer, the maps are bounded per shard and flushed as additive
//! deltas when one is full, when packet time advances by `flush_interval_ns`, and at the end:
//! the store adds them up, so the result depends neither on the number of shards nor on flush
//! moments. A reassembled IP datagram reaches analyzers once, so it counts as one frame (with
//! the wire length of all its fragments), and the fragments of an incomplete datagram are not
//! counted, as in the `core` time series.

use std::collections::HashMap;
use std::fmt;

use netsift_dissect::{Decoded, LinkKind, MAX_VLAN_TAGS, Vlans};
use netsift_flow::PacketCtx;

use crate::analyzer::{Analyzer, AnalyzerId, RecordSink};
use crate::oui::{self, Registry};
use crate::record::Record;
use crate::registry::AnalyzerConfig;

/// VLAN stacks kept per address and per pair.
pub const MAX_VLANS: usize = 16;
/// EtherTypes kept per pair.
pub const MAX_ETHERTYPES: usize = 16;

/// Settings of the `ethernet` analyzer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthernetConfig {
    /// Maximum number of addresses (and of pairs) aggregated per shard before a flush.
    pub max_pending: usize,
    /// Pending deltas are flushed when packet time advances this much (ns).
    pub flush_interval_ns: i64,
}

impl Default for EthernetConfig {
    fn default() -> Self {
        Self {
            max_pending: 16_384,
            // Same choice as `connections`: memory is bounded by `max_pending`.
            flush_interval_ns: 3_600 * 1_000_000_000,
        }
    }
}

/// What the frame carries: an EtherType (`0x0600..=0xffff`), the DSAP of an 802.2 LLC header
/// without EtherType (`0..=0xff`, 802.3 framing: spanning tree, NetBIOS, IPX...), or
/// [`EtherKey::UNKNOWN`] when the link header is truncated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EtherKey(pub i32);

impl EtherKey {
    pub const UNKNOWN: Self = Self(-1);

    fn of(pkt: &Decoded<'_>) -> Self {
        match (pkt.link.ethertype, pkt.link.llc) {
            (Some(t), _) => Self(i32::from(t)),
            (None, Some(llc)) => Self(i32::from(llc.dsap)),
            (None, None) => Self::UNKNOWN,
        }
    }
}

/// VLAN identifiers of a frame, outermost first (empty: untagged). Its label joins them with a
/// dot (`100.20` for service tag 100, customer tag 20).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct VlanStack {
    len: u8,
    ids: [u16; MAX_VLAN_TAGS],
}

impl VlanStack {
    /// The identifiers of `vlans`.
    pub fn of(vlans: &Vlans) -> Self {
        let mut s = Self::default();
        for (slot, tag) in s.ids.iter_mut().zip(vlans.as_slice()) {
            *slot = tag.id;
            s.len = s.len.saturating_add(1);
        }
        s
    }

    /// Stack of the given identifiers (outermost first); extra ones are dropped.
    pub fn from_ids(ids: &[u16]) -> Self {
        let mut s = Self::default();
        for (slot, id) in s.ids.iter_mut().zip(ids) {
            *slot = *id & 0x0fff;
            s.len = s.len.saturating_add(1);
        }
        s
    }

    pub fn ids(&self) -> &[u16] {
        self.ids.get(..usize::from(self.len)).unwrap_or(&[])
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl fmt::Display for VlanStack {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, id) in self.ids().iter().enumerate() {
            if i > 0 {
                f.write_str(".")?;
            }
            write!(f, "{id}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for VlanStack {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// Traffic of one MAC address (additive delta).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacDelta {
    pub mac: [u8; 6],
    /// IEEE organization of the prefix (universally administered addresses only).
    pub vendor: Option<&'static str>,
    pub registry: Option<Registry>,
    pub frames_sent: u64,
    pub bytes_sent: u64,
    pub frames_received: u64,
    pub bytes_received: u64,
    pub first_ts: i64,
    pub last_ts: i64,
    /// VLAN stacks of its frames (sorted, at most [`MAX_VLANS`]).
    pub vlans: Vec<VlanStack>,
}

/// Frames from `src` to `dst` (additive delta).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairDelta {
    pub src: [u8; 6],
    pub dst: [u8; 6],
    pub frames: u64,
    pub bytes: u64,
    pub first_ts: i64,
    pub last_ts: i64,
    /// Sorted, at most [`MAX_ETHERTYPES`].
    pub ethertypes: Vec<EtherKey>,
    /// Sorted, at most [`MAX_VLANS`].
    pub vlans: Vec<VlanStack>,
}

/// Frames of one EtherType, or of one VLAN stack (additive delta).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Volume {
    pub frames: u64,
    pub bytes: u64,
    pub first_ts: i64,
    pub last_ts: i64,
}

/// Records of the `ethernet` analyzer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EthernetRecord {
    Mac(MacDelta),
    Pair(PairDelta),
    EtherType(EtherKey, Volume),
    /// A VLAN stack and the TPID of its outermost tag (`0x8100`, `0x88a8` or `0x9100`).
    Vlan(VlanStack, u16, Volume),
}

impl Volume {
    fn new(ts: i64) -> Self {
        Self {
            frames: 0,
            bytes: 0,
            first_ts: ts,
            last_ts: ts,
        }
    }

    fn add(&mut self, ts: i64, bytes: u32) {
        self.frames = self.frames.saturating_add(1);
        self.bytes = self.bytes.saturating_add(u64::from(bytes));
        self.first_ts = self.first_ts.min(ts);
        self.last_ts = self.last_ts.max(ts);
    }
}

#[derive(Debug, Clone)]
struct PendingMac {
    sent: Volume,
    received: Volume,
    first_ts: i64,
    last_ts: i64,
    vlans: Vec<VlanStack>,
}

#[derive(Debug, Clone)]
struct PendingPair {
    volume: Volume,
    ethertypes: Vec<EtherKey>,
    vlans: Vec<VlanStack>,
}

/// Inserts `v` into a small unsorted set bounded to `max` (sorted at flush).
fn add_bounded<T: PartialEq + Copy>(set: &mut Vec<T>, v: T, max: usize) {
    if set.len() < max && !set.contains(&v) {
        set.push(v);
    }
}

fn sorted<T: Ord>(mut v: Vec<T>) -> Vec<T> {
    v.sort_unstable();
    v
}

/// See the module documentation.
#[derive(Debug)]
pub struct EthernetAnalyzer {
    max_pending: usize,
    flush_interval_ns: i64,
    macs: HashMap<[u8; 6], PendingMac>,
    pairs: HashMap<([u8; 6], [u8; 6]), PendingPair>,
    ethertypes: HashMap<EtherKey, Volume>,
    /// Volume and outer TPID per stack.
    vlans: HashMap<VlanStack, (u16, Volume)>,
    /// Packet time of the last flush (or of the first frame).
    since: Option<i64>,
}

impl EthernetAnalyzer {
    pub const ID: AnalyzerId = AnalyzerId("ethernet");

    pub fn new(config: &AnalyzerConfig) -> Self {
        Self {
            max_pending: config.ethernet.max_pending.max(1),
            flush_interval_ns: config.ethernet.flush_interval_ns.max(0),
            macs: HashMap::new(),
            pairs: HashMap::new(),
            ethertypes: HashMap::new(),
            vlans: HashMap::new(),
            since: None,
        }
    }

    /// [`crate::registry::Factory`] of this analyzer.
    pub fn boxed(config: &AnalyzerConfig) -> Box<dyn Analyzer> {
        Box::new(Self::new(config))
    }

    fn mac(&mut self, mac: [u8; 6], ts: i64, bytes: u32, sent: bool, vlans: VlanStack) {
        let m = self.macs.entry(mac).or_insert_with(|| PendingMac {
            sent: Volume::new(ts),
            received: Volume::new(ts),
            first_ts: ts,
            last_ts: ts,
            vlans: Vec::new(),
        });
        if sent {
            m.sent.add(ts, bytes);
        } else {
            m.received.add(ts, bytes);
        }
        m.first_ts = m.first_ts.min(ts);
        m.last_ts = m.last_ts.max(ts);
        if !vlans.is_empty() {
            add_bounded(&mut m.vlans, vlans, MAX_VLANS);
        }
    }

    fn flush(&mut self, out: &mut dyn RecordSink) {
        let mut macs: Vec<_> = self.macs.drain().collect();
        // Deterministic emission order (the store merge does not need it; tests do).
        macs.sort_unstable_by_key(|(mac, _)| *mac);
        for (mac, m) in macs {
            let assignment = oui::vendor(mac);
            out.emit(Record::Ethernet(EthernetRecord::Mac(MacDelta {
                mac,
                vendor: assignment.map(|a| a.organization),
                registry: assignment.map(|a| a.registry),
                frames_sent: m.sent.frames,
                bytes_sent: m.sent.bytes,
                frames_received: m.received.frames,
                bytes_received: m.received.bytes,
                first_ts: m.first_ts,
                last_ts: m.last_ts,
                vlans: sorted(m.vlans),
            })));
        }
        let mut pairs: Vec<_> = self.pairs.drain().collect();
        pairs.sort_unstable_by_key(|(key, _)| *key);
        for ((src, dst), p) in pairs {
            out.emit(Record::Ethernet(EthernetRecord::Pair(PairDelta {
                src,
                dst,
                frames: p.volume.frames,
                bytes: p.volume.bytes,
                first_ts: p.volume.first_ts,
                last_ts: p.volume.last_ts,
                ethertypes: sorted(p.ethertypes),
                vlans: sorted(p.vlans),
            })));
        }
        let mut types: Vec<_> = self.ethertypes.drain().collect();
        types.sort_unstable_by_key(|(key, _)| *key);
        for (key, v) in types {
            out.emit(Record::Ethernet(EthernetRecord::EtherType(key, v)));
        }
        let mut vlans: Vec<_> = self.vlans.drain().collect();
        vlans.sort_unstable_by_key(|(key, _)| *key);
        for (stack, (tpid, v)) in vlans {
            out.emit(Record::Ethernet(EthernetRecord::Vlan(stack, tpid, v)));
        }
    }
}

impl Analyzer for EthernetAnalyzer {
    fn id(&self) -> AnalyzerId {
        Self::ID
    }

    fn on_packet(&mut self, ctx: &PacketCtx, pkt: &Decoded<'_>, out: &mut dyn RecordSink) {
        let link = &pkt.link;
        if !matches!(
            link.kind,
            LinkKind::Ethernet | LinkKind::LinuxSll | LinkKind::LinuxSll2
        ) {
            return;
        }
        let (src, dst) = (link.src_mac.map(|m| m.0), link.dst_mac.map(|m| m.0));
        if src.is_none() && dst.is_none() {
            return;
        }
        let ts = ctx.ts_ns;
        let since = *self.since.get_or_insert(ts);
        let full = self.macs.len().saturating_add(2) > self.max_pending
            || self.pairs.len() >= self.max_pending;
        if full || ts.saturating_sub(since) >= self.flush_interval_ns {
            self.flush(out);
            self.since = Some(ts);
        }

        let bytes = ctx.wire_len;
        let stack = VlanStack::of(&link.vlans);
        let key = EtherKey::of(pkt);
        if let Some(s) = src {
            self.mac(s, ts, bytes, true, stack);
        }
        if let Some(d) = dst {
            self.mac(d, ts, bytes, false, stack);
        }
        if let (Some(s), Some(d)) = (src, dst) {
            let p = self.pairs.entry((s, d)).or_insert_with(|| PendingPair {
                volume: Volume::new(ts),
                ethertypes: Vec::new(),
                vlans: Vec::new(),
            });
            p.volume.add(ts, bytes);
            add_bounded(&mut p.ethertypes, key, MAX_ETHERTYPES);
            if !stack.is_empty() {
                add_bounded(&mut p.vlans, stack, MAX_VLANS);
            }
        }
        self.ethertypes
            .entry(key)
            .or_insert_with(|| Volume::new(ts))
            .add(ts, bytes);
        if let Some(outer) = link.vlans.as_slice().first() {
            let (tpid, v) = self
                .vlans
                .entry(stack)
                .or_insert_with(|| (outer.tpid, Volume::new(ts)));
            *tpid = (*tpid).max(outer.tpid);
            v.add(ts, bytes);
        }
    }

    fn finish(&mut self, out: &mut dyn RecordSink) {
        self.flush(out);
        self.since = None;
    }
}

#[cfg(test)]
mod tests;
