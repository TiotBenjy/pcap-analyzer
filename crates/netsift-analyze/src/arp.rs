//! `arp` analyzer: one [`ArpMessage`] per ARP packet (RFC 826), typed (request, reply,
//! gratuitous, RFC 5227 probe), with the replies that no request preceded flagged
//! (`docs/specs/arp.md`).
//!
//! State: the time of the last request per (asker, asked address), bounded. Packets without an IP
//! layer all reach the same flow shard, in capture order (`netsift_flow::shard_hash` is 0 for
//! them): this analyzer sees every ARP packet of the capture. Were that to change, more replies
//! would be flagged, never fewer.

use std::collections::HashMap;
use std::net::IpAddr;

use netsift_dissect::{ArpInfo, Decoded, Network};
use netsift_flow::PacketCtx;

use crate::analyzer::{Analyzer, AnalyzerId, RecordSink};
use crate::record::Record;
use crate::registry::AnalyzerConfig;

/// A reply answers a request seen at most this long before it (ns).
pub const ANSWER_WINDOW_NS: i64 = 10_000_000_000;
/// Largest number of pending requests remembered.
pub const MAX_PENDING: usize = 16_384;

const OP_REQUEST: u16 = 1;
const OP_REPLY: u16 = 2;

/// Type of an ARP message (disjoint, see the spec).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ArpKind {
    Request,
    Reply,
    /// Sender address equals target address (announcement, request or reply form).
    Gratuitous,
    /// Request with sender address `0.0.0.0` (RFC 5227 address conflict detection).
    Probe,
    /// Other operation (RARP, `InARP`...) or protocol other than IPv4.
    Other,
}

impl ArpKind {
    /// Stored label (`arp_messages.kind`).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Reply => "reply",
            Self::Gratuitous => "gratuitous",
            Self::Probe => "probe",
            Self::Other => "other",
        }
    }

    /// Type of a decoded packet.
    pub fn of(arp: &ArpInfo) -> Self {
        let (Some(sender), Some(target)) = (arp.sender_ip, arp.target_ip) else {
            return Self::Other;
        };
        match arp.operation {
            OP_REQUEST if sender.is_unspecified() => Self::Probe,
            OP_REQUEST | OP_REPLY if sender == target => Self::Gratuitous,
            OP_REQUEST => Self::Request,
            OP_REPLY => Self::Reply,
            _ => Self::Other,
        }
    }
}

/// One ARP packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArpMessage {
    pub ts_ns: i64,
    /// Global frame index of the packet.
    pub frame: u64,
    pub operation: u16,
    pub kind: ArpKind,
    pub sender_mac: Option<[u8; 6]>,
    pub sender_ip: Option<IpAddr>,
    pub target_mac: Option<[u8; 6]>,
    pub target_ip: Option<IpAddr>,
    /// A reply that no request of its target for its sender address preceded within
    /// [`ANSWER_WINDOW_NS`] (never set during the first window of ARP traffic).
    pub unsolicited: bool,
    /// The message tells that `sender_ip` is at `sender_mac`: request, reply or gratuitous, with
    /// a non-zero sender address and a unicast, non-zero sender MAC.
    pub binds: bool,
}

/// See the module documentation.
#[derive(Debug, Default)]
pub struct ArpAnalyzer {
    /// (asker, asked address) -> time of the last request.
    pending: HashMap<(IpAddr, IpAddr), i64>,
    /// Time of the first ARP packet seen.
    first_ts: Option<i64>,
}

impl ArpAnalyzer {
    pub const ID: AnalyzerId = AnalyzerId("arp");

    pub fn new(_config: &AnalyzerConfig) -> Self {
        Self::default()
    }

    /// [`crate::registry::Factory`] of this analyzer.
    pub fn boxed(config: &AnalyzerConfig) -> Box<dyn Analyzer> {
        Box::new(Self::new(config))
    }

    fn remember(&mut self, ts: i64, asker: IpAddr, asked: IpAddr) {
        if self.pending.len() >= MAX_PENDING && !self.pending.contains_key(&(asker, asked)) {
            let horizon = ts.saturating_sub(ANSWER_WINDOW_NS);
            self.pending.retain(|_, t| *t >= horizon);
            if self.pending.len() > MAX_PENDING - MAX_PENDING / 4 {
                // A flood of distinct live requests: forget them (later replies may be flagged).
                // Below a quarter freed, the next requests would sweep the map at every packet.
                self.pending.clear();
            }
        }
        self.pending.insert((asker, asked), ts);
    }

    /// True when a reply from `sender` to `target` answers no recent request.
    fn unsolicited(&self, ts: i64, sender: IpAddr, target: IpAddr) -> bool {
        let warm = self
            .first_ts
            .is_some_and(|first| ts.saturating_sub(first) > ANSWER_WINDOW_NS);
        warm && self
            .pending
            .get(&(target, sender))
            .is_none_or(|asked| ts.saturating_sub(*asked) > ANSWER_WINDOW_NS)
    }

    fn message(&mut self, ctx: &PacketCtx, arp: &ArpInfo) -> ArpMessage {
        let ts = ctx.ts_ns;
        self.first_ts.get_or_insert(ts);
        let kind = ArpKind::of(arp);
        let mut unsolicited = false;
        if let (Some(sender), Some(target)) = (arp.sender_ip, arp.target_ip) {
            match kind {
                ArpKind::Request | ArpKind::Probe => self.remember(ts, sender, target),
                ArpKind::Reply => unsolicited = self.unsolicited(ts, sender, target),
                ArpKind::Gratuitous | ArpKind::Other => {}
            }
        }
        let sender_mac = arp.sender_mac.map(|m| m.0);
        let binds = matches!(
            kind,
            ArpKind::Request | ArpKind::Reply | ArpKind::Gratuitous
        ) && arp.sender_ip.is_some_and(|ip| !ip.is_unspecified())
            && arp
                .sender_mac
                .is_some_and(|m| !m.is_multicast() && m.0 != [0; 6]);
        ArpMessage {
            ts_ns: ts,
            frame: ctx.frame,
            operation: arp.operation,
            kind,
            sender_mac,
            sender_ip: arp.sender_ip,
            target_mac: arp.target_mac.map(|m| m.0),
            target_ip: arp.target_ip,
            unsolicited,
            binds,
        }
    }
}

impl Analyzer for ArpAnalyzer {
    fn id(&self) -> AnalyzerId {
        Self::ID
    }

    fn on_packet(&mut self, ctx: &PacketCtx, pkt: &Decoded<'_>, out: &mut dyn RecordSink) {
        if let Some(Network::Arp(arp)) = &pkt.network {
            let message = self.message(ctx, arp);
            out.emit(Record::Arp(message));
        }
    }
}

#[cfg(test)]
mod tests;
