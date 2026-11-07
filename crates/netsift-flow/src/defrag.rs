//! Bounded IPv4 / IPv6 defragmentation.
//!
//! Policy:
//! - datagrams are keyed by (source, destination, identification) plus the protocol for IPv4
//!   (RFC 791) and the address family; for IPv6 the next header of the offset-0 fragment is
//!   used (RFC 8200);
//! - fragments may arrive in any order; **the first arrival wins**: a later fragment only
//!   fills the holes left by earlier ones, so exact duplicates and retransmitted overlaps are
//!   ignored and a forged overlap cannot rewrite bytes already received;
//! - incoherent fragments are rejected together with their whole datagram (teardrop-style):
//!   two different end lengths, data beyond the known end, a non-last fragment whose length
//!   is not a multiple of 8, an empty non-last fragment, or a datagram larger than
//!   [`MAX_DATAGRAM`] bytes (IPv6 jumbograms cannot be fragmented, RFC 2675);
//! - a datagram whose first fragment is older than the timeout (packet time) is dropped;
//!   the bytes held (data plus a fixed per-piece overhead) are capped per table, the oldest
//!   datagrams being evicted first.
//!
//! Nothing is reported until a datagram is complete.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;

use netsift_dissect::{Fragment, IpVersion};

use crate::ranges::{holes, len64, sub};

/// Largest reassembled fragmentable part accepted, in bytes.
pub(crate) const MAX_DATAGRAM: u64 = 65_535;
/// Accounting overhead of one stored piece (map node and vector header).
const PIECE_OVERHEAD: usize = 64;
/// Accounting overhead of one pending datagram.
const DATAGRAM_OVERHEAD: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Key {
    src: IpAddr,
    dst: IpAddr,
    /// IPv4 protocol; 0 for IPv6 (not part of the RFC 8200 key).
    proto: u8,
    id: u32,
}

#[derive(Debug)]
struct Pending {
    serial: u64,
    first_ts: i64,
    /// Non-overlapping pieces by offset.
    pieces: BTreeMap<u64, Vec<u8>>,
    data_bytes: u64,
    cost: usize,
    /// Known once the last fragment (more-fragments clear) arrived.
    total: Option<u64>,
    /// Protocol of the fragmentable part, from the offset-0 fragment.
    next_header: Option<u8>,
    wire_len: u64,
}

impl Pending {
    /// End of the furthest piece.
    fn max_end(&self) -> u64 {
        self.pieces
            .last_key_value()
            .map_or(0, |(&off, d)| off.saturating_add(len64(d)))
    }
}

/// Fragment being added.
pub(crate) struct Piece<'a> {
    pub ts_ns: i64,
    pub version: IpVersion,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub fragment: Fragment,
    /// Fragmentable bytes ([`netsift_dissect::Decoded::ip_payload`]).
    pub data: &'a [u8],
    pub wire_len: u32,
}

/// A complete datagram.
#[derive(Debug)]
pub(crate) struct Datagram {
    pub next_header: u8,
    pub data: Vec<u8>,
    /// Sum of the wire lengths of every fragment frame absorbed (duplicates included).
    pub wire_len: u64,
}

#[derive(Debug)]
pub(crate) enum Outcome {
    /// Absorbed; nothing to report yet.
    Pending,
    /// Last missing piece received.
    Complete(Datagram),
    /// Incoherent or oversized fragment, or no room left: the datagram was dropped.
    Rejected,
}

/// Pending datagrams of one table.
#[derive(Debug)]
pub(crate) struct Defragmenter {
    pending: HashMap<Key, Pending>,
    /// Creation order, for timeouts and eviction (deterministic).
    by_age: BTreeMap<u64, Key>,
    next_serial: u64,
    cost: usize,
    max_cost: usize,
    timeout_ns: i64,
}

impl Defragmenter {
    pub(crate) fn new(max_bytes: usize, timeout_ns: i64) -> Self {
        Self {
            pending: HashMap::new(),
            by_age: BTreeMap::new(),
            next_serial: 0,
            cost: 0,
            max_cost: max_bytes,
            timeout_ns,
        }
    }

    /// Number of incomplete datagrams held.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.pending.len()
    }

    /// Bytes accounted for the pending datagrams.
    #[cfg(test)]
    pub(crate) fn cost(&self) -> usize {
        self.cost
    }

    fn remove(&mut self, key: &Key) {
        if let Some(p) = self.pending.remove(key) {
            self.by_age.remove(&p.serial);
            self.cost = self.cost.saturating_sub(p.cost);
        }
    }

    fn expired(&self, p: &Pending, now: i64) -> bool {
        now.saturating_sub(p.first_ts) > self.timeout_ns
    }

    /// Drops the datagrams whose first fragment is older than the timeout at `now`.
    pub(crate) fn expire(&mut self, now: i64) {
        while let Some((_, key)) = self.by_age.first_key_value() {
            let key = *key;
            match self.pending.get(&key) {
                Some(p) if !self.expired(p, now) => break,
                _ => self.remove(&key),
            }
        }
    }

    /// Drops everything (end of capture: incomplete datagrams are never reported).
    pub(crate) fn clear(&mut self) {
        self.pending.clear();
        self.by_age.clear();
        self.cost = 0;
    }

    /// Evicts the oldest datagrams other than `keep` until `extra` more bytes fit.
    fn make_room(&mut self, extra: usize, keep: &Key) -> bool {
        loop {
            if self.cost.saturating_add(extra) <= self.max_cost {
                return true;
            }
            let victim = self.by_age.values().find(|k| *k != keep).copied();
            match victim {
                Some(k) => self.remove(&k),
                None => return false,
            }
        }
    }

    /// Whether a fragment ending at `end` fits the datagram `key` (see the module policy).
    fn coherent(&self, key: &Key, frag: Fragment, end: u64) -> bool {
        let len = end.saturating_sub(u64::from(frag.offset));
        let malformed = end > MAX_DATAGRAM || (frag.more && (len == 0 || !len.is_multiple_of(8)));
        let incoherent = self.pending.get(key).is_some_and(|p| match p.total {
            Some(total) => end > total || (!frag.more && end != total),
            None => !frag.more && p.max_end() > end,
        });
        !malformed && !incoherent
    }

    /// Starts tracking datagram `key`; `false` when there is no room.
    fn open(&mut self, key: Key, ts_ns: i64) -> bool {
        if !self.make_room(DATAGRAM_OVERHEAD, &key) {
            return false;
        }
        let serial = self.next_serial;
        self.next_serial = self.next_serial.wrapping_add(1);
        self.by_age.insert(serial, key);
        self.pending.insert(
            key,
            Pending {
                serial,
                first_ts: ts_ns,
                pieces: BTreeMap::new(),
                data_bytes: 0,
                cost: DATAGRAM_OVERHEAD,
                total: None,
                next_header: None,
                wire_len: 0,
            },
        );
        self.cost = self.cost.saturating_add(DATAGRAM_OVERHEAD);
        true
    }

    pub(crate) fn push(&mut self, piece: &Piece<'_>) -> Outcome {
        let frag = piece.fragment;
        let key = Key {
            src: piece.src,
            dst: piece.dst,
            proto: match piece.version {
                IpVersion::V4 => frag.next_header,
                IpVersion::V6 => 0,
            },
            id: frag.id,
        };
        if self
            .pending
            .get(&key)
            .is_some_and(|p| self.expired(p, piece.ts_ns))
        {
            self.remove(&key);
        }

        let offset = u64::from(frag.offset);
        let end = offset.saturating_add(len64(piece.data));
        if !self.coherent(&key, frag, end) {
            self.remove(&key);
            return Outcome::Rejected;
        }
        if !self.pending.contains_key(&key) && !self.open(key, piece.ts_ns) {
            return Outcome::Rejected;
        }

        let holes = match self.pending.get(&key) {
            Some(p) => holes(&p.pieces, offset, end),
            None => return Outcome::Rejected,
        };
        let extra = holes
            .iter()
            .map(|(a, b)| {
                usize::try_from(b.saturating_sub(*a))
                    .unwrap_or(usize::MAX)
                    .saturating_add(PIECE_OVERHEAD)
            })
            .fold(0usize, usize::saturating_add);
        if !self.make_room(extra, &key) {
            self.remove(&key);
            return Outcome::Rejected;
        }
        let Some(p) = self.pending.get_mut(&key) else {
            return Outcome::Rejected;
        };
        for (a, b) in holes {
            if let Some(bytes) = sub(piece.data, offset, a, b) {
                p.pieces.insert(a, bytes.to_vec());
                p.data_bytes = p.data_bytes.saturating_add(len64(bytes));
            }
        }
        p.cost = p.cost.saturating_add(extra);
        self.cost = self.cost.saturating_add(extra);
        p.wire_len = p.wire_len.saturating_add(u64::from(piece.wire_len));
        if offset == 0 {
            p.next_header.get_or_insert(frag.next_header);
        }
        if !frag.more {
            p.total = Some(end);
        }

        let complete = p.total.is_some_and(|t| t == p.data_bytes) && p.next_header.is_some();
        if !complete {
            return Outcome::Pending;
        }
        let Some(p) = self.pending.remove(&key) else {
            return Outcome::Rejected;
        };
        self.by_age.remove(&p.serial);
        self.cost = self.cost.saturating_sub(p.cost);
        let mut data = Vec::with_capacity(usize::try_from(p.data_bytes).unwrap_or(0));
        for piece in p.pieces.into_values() {
            data.extend_from_slice(&piece);
        }
        Outcome::Complete(Datagram {
            next_header: p.next_header.unwrap_or_default(),
            data,
            wire_len: p.wire_len,
        })
    }
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    const S: i64 = 1_000_000_000;

    fn v4(id: u32, offset: u16, more: bool, data: &[u8], ts: i64) -> (Piece<'_>, IpVersion) {
        let p = Piece {
            ts_ns: ts,
            version: IpVersion::V4,
            src: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            fragment: Fragment {
                id,
                offset,
                more,
                next_header: 17,
            },
            data,
            wire_len: 100,
        };
        (p, IpVersion::V4)
    }

    fn push(
        d: &mut Defragmenter,
        id: u32,
        offset: u16,
        more: bool,
        data: &[u8],
        ts: i64,
    ) -> Outcome {
        d.push(&v4(id, offset, more, data, ts).0)
    }

    fn complete(o: Outcome) -> Vec<u8> {
        match o {
            Outcome::Complete(dg) => dg.data,
            other => panic!("expected a complete datagram, got {other:?}"),
        }
    }

    fn big() -> Defragmenter {
        Defragmenter::new(1 << 20, 30 * S)
    }

    #[test]
    fn out_of_order_with_duplicates() {
        let mut d = big();
        assert!(matches!(
            push(&mut d, 1, 16, false, b"cc", 0),
            Outcome::Pending
        ));
        assert!(matches!(
            push(&mut d, 1, 0, true, b"aaaaaaaa", 1),
            Outcome::Pending
        ));
        assert!(matches!(
            push(&mut d, 1, 0, true, b"aaaaaaaa", 2),
            Outcome::Pending
        ));
        let out = push(&mut d, 1, 8, true, b"bbbbbbbb", 3);
        let Outcome::Complete(dg) = out else {
            panic!("complete expected")
        };
        assert_eq!(dg.data, b"aaaaaaaabbbbbbbbcc");
        assert_eq!(dg.wire_len, 400, "every absorbed frame counts");
        assert_eq!(dg.next_header, 17);
        assert_eq!((d.len(), d.cost()), (0, 0));
    }

    #[test]
    fn overlap_first_arrival_wins() {
        let mut d = big();
        push(&mut d, 2, 0, true, b"AAAAAAAAAAAAAAAA", 0);
        push(&mut d, 2, 8, true, b"xxxxxxxxxxxxxxxx", 0);
        let data = complete(push(&mut d, 2, 24, false, b"z", 0));
        assert_eq!(data, b"AAAAAAAAAAAAAAAAxxxxxxxxz");
    }

    #[test]
    fn teardrop_and_malformed_fragments_drop_the_datagram() {
        let mut d = big();
        // Two different end lengths.
        push(&mut d, 3, 16, false, b"end", 0);
        assert!(matches!(
            push(&mut d, 3, 8, false, b"short", 0),
            Outcome::Rejected
        ));
        assert_eq!(d.len(), 0);
        // Data beyond the known end.
        push(&mut d, 4, 8, false, b"12", 0);
        assert!(matches!(
            push(&mut d, 4, 8, true, &[0; 16], 0),
            Outcome::Rejected
        ));
        // Last fragment shorter than data already received.
        push(&mut d, 5, 16, true, &[0; 8], 0);
        assert!(matches!(
            push(&mut d, 5, 0, false, &[0; 8], 0),
            Outcome::Rejected
        ));
        // Non-last fragment not a multiple of 8, empty non-last fragment.
        assert!(matches!(
            push(&mut d, 6, 0, true, &[0; 9], 0),
            Outcome::Rejected
        ));
        assert!(matches!(
            push(&mut d, 7, 0, true, &[], 0),
            Outcome::Rejected
        ));
        // Larger than 65 535 bytes.
        assert!(matches!(
            push(&mut d, 8, 65_528, false, &[0; 8], 0),
            Outcome::Rejected
        ));
        assert!(matches!(
            push(&mut d, 8, 65_528, false, &[0; 7], 0),
            Outcome::Pending
        ));
        assert_eq!(d.len(), 1);
    }

    #[test]
    fn timeout_in_packet_time() {
        let mut d = big();
        push(&mut d, 9, 0, true, &[1; 8], 0);
        push(&mut d, 10, 0, true, &[2; 8], 20 * S);
        d.expire(30 * S);
        assert_eq!(d.len(), 2, "exactly 30 s is not over the timeout");
        d.expire(30 * S + 1);
        assert_eq!(d.len(), 1);
        // A late fragment of the expired datagram starts a new one, which stays incomplete.
        assert!(matches!(
            push(&mut d, 9, 8, false, b"x", 31 * S),
            Outcome::Pending
        ));
        // Expiry is also checked on lookup.
        assert!(matches!(
            push(&mut d, 10, 8, false, b"y", 51 * S),
            Outcome::Pending
        ));
        assert_eq!(d.len(), 2);
    }

    #[test]
    fn memory_bound_evicts_the_oldest() {
        let budget = 3 * (DATAGRAM_OVERHEAD + PIECE_OVERHEAD + 8);
        let mut d = Defragmenter::new(budget, 30 * S);
        for id in 0..3 {
            push(&mut d, id, 0, true, &[0; 8], 0);
        }
        assert_eq!(d.len(), 3);
        assert!(d.cost() <= budget);
        push(&mut d, 3, 0, true, &[0; 8], 0);
        assert_eq!(d.len(), 3);
        assert!(d.cost() <= budget);
        // Datagram 0 was evicted: completing it now is impossible.
        assert!(matches!(
            push(&mut d, 0, 8, false, b"x", 0),
            Outcome::Pending
        ));
        // A fragment larger than the whole budget is rejected.
        assert!(matches!(
            push(&mut d, 99, 0, true, &vec![0; budget], 0),
            Outcome::Rejected
        ));
        assert!(d.cost() <= budget);
    }

    #[test]
    fn ipv6_key_ignores_the_next_header_of_later_fragments() {
        let mut d = big();
        let src = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let mk = |offset, more, next_header, data: &'static [u8]| Piece {
            ts_ns: 0,
            version: IpVersion::V6,
            src,
            dst: src,
            fragment: Fragment {
                id: 0xdead_beef,
                offset,
                more,
                next_header,
            },
            data,
            wire_len: 1,
        };
        assert!(matches!(
            d.push(&mk(8, false, 59, b"tail")),
            Outcome::Pending
        ));
        let Outcome::Complete(dg) = d.push(&mk(0, true, 17, b"headhead")) else {
            panic!("complete expected")
        };
        assert_eq!(dg.next_header, 17);
        assert_eq!(dg.data, b"headheadtail");
    }
}
