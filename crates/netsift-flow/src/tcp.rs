//! TCP reassembly of one direction of a connection.
//!
//! Sequence numbers are mapped to a 64-bit stream offset (offset 0 = first data byte, i.e.
//! the byte after the SYN, or the first sequence number seen when the SYN is missing). The
//! mapping is relative to the next expected sequence number, modulo 2^32, so it survives
//! wraparound as long as segments stay within +/- 2 GiB of it.
//!
//! Policy:
//! - in-order data is delivered at once; out-of-order segments are buffered, at most
//!   `max_buffer` bytes **including a fixed overhead of [`PIECE_OVERHEAD`] bytes per buffered
//!   piece** (so that tiny segments cannot multiply the real memory use); one extra segment may
//!   be held while the bound is enforced. A piece that extends the previous one is appended to
//!   it;
//! - a segment truncated by the capture snaplen covers its announced length: the captured
//!   prefix is delivered, and once it is in order the missing tail is skipped at once and
//!   reported as a gap before the next data (the bytes are lost for good);
//! - **the first arrival wins**: bytes already delivered or buffered are never replaced, so
//!   retransmissions are dropped and overlaps only fill holes;
//! - when a hole will not be filled (buffer full, connection closed or reset, flow end), the
//!   next buffered data is delivered with `gap` = number of missing bytes;
//! - SYN and FIN each consume one sequence number; data beyond the FIN is ignored; a FIN is
//!   only accepted within `[next expected byte, + MAX_AHEAD]`;
//! - segments more than [`MAX_AHEAD`] bytes ahead of the expected offset are ignored (another
//!   connection or garbage), which keeps reported gaps meaningful.

use std::collections::BTreeMap;

use crate::ranges::{holes, len64, sub};

/// Furthest a segment may start ahead of the next expected byte (1 GiB).
pub(crate) const MAX_AHEAD: u64 = 1 << 30;
/// Accounting overhead of one buffered piece (map node and vector header).
pub(crate) const PIECE_OVERHEAD: usize = 64;

/// Callback receiving in-order data: `(gap_before, bytes)`.
pub(crate) type Emit<'a> = dyn FnMut(u64, &[u8]) + 'a;

/// Header fields of a segment relevant to reassembly.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Segment<'a> {
    pub seq: u32,
    pub syn: bool,
    pub fin: bool,
    /// Captured payload.
    pub payload: &'a [u8],
    /// Payload length announced by the IP header (larger than `payload` when the capture
    /// truncated the packet).
    pub len: u64,
}

/// One direction of a TCP connection.
#[derive(Debug, Default)]
pub(crate) struct Stream {
    initialized: bool,
    /// The anchor comes from a SYN (as opposed to the first segment seen).
    from_syn: bool,
    /// Sequence number of the byte at `next_off`.
    next_seq: u32,
    /// Stream offset of the next byte to deliver.
    next_off: u64,
    /// Stream offset of the FIN, once seen.
    fin_off: Option<u64>,
    /// Out-of-order bytes, non-overlapping, all starting after `next_off`.
    pending: BTreeMap<u64, Vec<u8>>,
    /// Data bytes in `pending`.
    pending_bytes: usize,
    /// Missing bytes to report before the next delivered data.
    gap: u64,
}

impl Stream {
    fn anchor(&mut self, seq: u32, from_syn: bool) {
        self.initialized = true;
        self.from_syn = from_syn;
        self.next_seq = seq;
        self.next_off = 0;
    }

    /// Nothing delivered, buffered or skipped yet: the anchor may still move.
    fn untouched(&self) -> bool {
        self.next_off == 0 && self.pending.is_empty() && self.fin_off.is_none()
    }

    /// Advances the delivery point by `n` bytes (delivered or skipped).
    fn advance(&mut self, n: u64) {
        self.next_off = self.next_off.saturating_add(n);
        let low = u32::try_from(n & u64::from(u32::MAX)).unwrap_or(0);
        self.next_seq = self.next_seq.wrapping_add(low);
    }

    /// Stream offset of sequence number `seq` (may be negative: before the anchor).
    fn offset_of(&self, seq: u32) -> i128 {
        let delta = seq.wrapping_sub(self.next_seq).cast_signed();
        i128::from(self.next_off).saturating_add(i128::from(delta))
    }

    /// Bytes buffered out of order.
    #[cfg(test)]
    pub(crate) fn buffered(&self) -> usize {
        self.pending_bytes
    }

    /// Memory accounted for the buffered pieces (data plus per-piece overhead).
    pub(crate) fn cost(&self) -> usize {
        self.pending
            .len()
            .saturating_mul(PIECE_OVERHEAD)
            .saturating_add(self.pending_bytes)
    }

    /// Buffers `bytes` at offset `at` (a hole), appending to the previous piece when contiguous.
    fn store(&mut self, at: u64, bytes: &[u8]) {
        self.pending_bytes = self.pending_bytes.saturating_add(bytes.len());
        if let Some((&key, prev)) = self.pending.range_mut(..at).next_back()
            && key.saturating_add(len64(prev)) == at
        {
            prev.extend_from_slice(bytes);
            return;
        }
        self.pending.insert(at, bytes.to_vec());
    }

    /// Adds one segment (RST segments must not be passed: their payload is not data).
    pub(crate) fn segment(&mut self, seg: &Segment<'_>, max_buffer: usize, emit: &mut Emit<'_>) {
        // Data starts after the SYN, which consumes one sequence number.
        let data_seq = if seg.syn {
            seg.seq.wrapping_add(1)
        } else {
            seg.seq
        };
        if !self.initialized || (self.untouched() && !self.from_syn) {
            if seg.syn {
                self.anchor(data_seq, true);
            } else if !self.initialized || self.offset_of(data_seq) < 0 {
                // Pick-up without SYN: start at the first (or earliest untouched) sequence.
                self.anchor(data_seq, false);
            }
        }

        // Stream offset of payload[0] (negative when it starts before the anchor).
        let p0 = self.offset_of(data_seq);
        let captured = len64(seg.payload);
        let next = i128::from(self.next_off);
        let mut end = p0.saturating_add(i128::from(seg.len.max(captured)));
        if seg.fin && self.fin_off.is_none() {
            // The FIN consumes the sequence number after the data; ignored out of the window.
            let ahead = end.saturating_sub(next);
            if (0..=i128::from(MAX_AHEAD)).contains(&ahead) {
                self.fin_off = u64::try_from(end).ok();
            }
        }
        if let Some(fin) = self.fin_off {
            end = end.min(i128::from(fin));
        }
        if end <= next || p0.saturating_sub(next) > i128::from(MAX_AHEAD) {
            return;
        }
        // Trim what was already delivered (first arrival wins).
        let start = p0.max(next);
        let data_end = p0.saturating_add(i128::from(captured)).min(end).max(start);
        let (Ok(ra), Ok(rb), Ok(start), Ok(data_end), Ok(end)) = (
            usize::try_from(start.saturating_sub(p0)),
            usize::try_from(data_end.saturating_sub(p0)),
            u64::try_from(start),
            u64::try_from(data_end),
            u64::try_from(end),
        ) else {
            return;
        };
        let Some(data) = seg.payload.get(ra..rb) else {
            return;
        };

        if !data.is_empty() {
            if start == self.next_off && self.pending.is_empty() {
                let gap = std::mem::take(&mut self.gap);
                emit(gap, data);
                self.advance(len64(data));
            } else {
                for (a, b) in holes(&self.pending, start, data_end) {
                    if let Some(bytes) = sub(data, start, a, b) {
                        self.store(a, bytes);
                    }
                }
                self.drain(emit);
            }
        }
        // Truncated by the snaplen: once the captured prefix is in order, skip the lost tail
        // (up to buffered data, if any) instead of waiting for bytes that will never come.
        if end > data_end && self.next_off == data_end {
            let stop = self
                .pending
                .first_key_value()
                .map_or(end, |(&k, _)| k.min(end));
            let missing = stop.saturating_sub(self.next_off);
            self.gap = self.gap.saturating_add(missing);
            self.advance(missing);
            self.drain(emit);
        }
        while self.cost() > max_buffer {
            if !self.skip_hole(emit) {
                break;
            }
        }
    }

    /// Delivers the buffered data that is now in order.
    fn drain(&mut self, emit: &mut Emit<'_>) {
        while let Some(entry) = self.pending.first_entry() {
            if *entry.key() != self.next_off {
                break;
            }
            let data = entry.remove();
            self.pending_bytes = self.pending_bytes.saturating_sub(data.len());
            let gap = std::mem::take(&mut self.gap);
            emit(gap, &data);
            self.advance(len64(&data));
        }
    }

    /// Gives up on the hole before the first buffered segment: delivers it with the gap.
    /// Returns `false` when nothing is buffered.
    fn skip_hole(&mut self, emit: &mut Emit<'_>) -> bool {
        let Some((&start, _)) = self.pending.first_key_value() else {
            return false;
        };
        let missing = start.saturating_sub(self.next_off);
        self.gap = self.gap.saturating_add(missing);
        self.advance(missing);
        self.drain(emit);
        true
    }

    /// Delivers everything buffered, holes reported as gaps (the holes will not be filled).
    pub(crate) fn flush(&mut self, emit: &mut Emit<'_>) {
        while self.skip_hole(emit) {}
    }
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    const BIG: usize = 1 << 20;

    /// Collects `(gap, bytes)` deliveries.
    #[derive(Default)]
    struct Out(Vec<(u64, Vec<u8>)>);

    impl Out {
        fn concat(&self) -> Vec<u8> {
            self.0.iter().flat_map(|(_, d)| d.clone()).collect()
        }
        fn gaps(&self) -> Vec<u64> {
            self.0.iter().map(|(g, _)| *g).collect()
        }
    }

    fn push(
        s: &mut Stream,
        out: &mut Out,
        seq: u32,
        syn: bool,
        fin: bool,
        payload: &[u8],
        max: usize,
    ) {
        s.segment(
            &Segment {
                seq,
                syn,
                fin,
                payload,
                len: payload.len() as u64,
            },
            max,
            &mut |gap, data| out.0.push((gap, data.to_vec())),
        );
    }

    #[test]
    fn in_order_after_syn() {
        let (mut s, mut o) = (Stream::default(), Out::default());
        push(&mut s, &mut o, 99, true, false, b"", BIG);
        push(&mut s, &mut o, 100, false, false, b"abc", BIG);
        push(&mut s, &mut o, 103, false, false, b"def", BIG);
        assert_eq!(o.concat(), b"abcdef");
        assert_eq!(o.gaps(), vec![0, 0]);
    }

    #[test]
    fn out_of_order_and_overlaps_first_arrival_wins() {
        let (mut s, mut o) = (Stream::default(), Out::default());
        push(&mut s, &mut o, 0, true, false, b"", BIG);
        push(&mut s, &mut o, 5, false, false, b"FGH", BIG); // offsets 4..7
        push(&mut s, &mut o, 4, false, false, b"xyzw", BIG); // overlaps: only 3 is new
        push(&mut s, &mut o, 1, false, false, b"abc", BIG);
        push(&mut s, &mut o, 1, false, false, b"ABCDEFGH", BIG); // retransmission
        assert_eq!(
            o.concat(),
            b"abcxFGHH",
            "only the last byte of the retransmission is new"
        );
        assert_eq!(s.buffered(), 0);
    }

    #[test]
    fn wraparound() {
        let (mut s, mut o) = (Stream::default(), Out::default());
        push(&mut s, &mut o, u32::MAX - 2, true, false, b"", BIG);
        push(&mut s, &mut o, 0, false, false, b"cd", BIG); // offset 2
        push(&mut s, &mut o, u32::MAX - 1, false, false, b"ab", BIG);
        push(&mut s, &mut o, 2, false, true, b"e", BIG);
        assert_eq!(o.concat(), b"abcde");
        assert_eq!(s.fin_off, Some(5));
    }

    #[test]
    fn buffer_limit_skips_the_hole() {
        let (mut s, mut o) = (Stream::default(), Out::default());
        let max = PIECE_OVERHEAD + 4;
        push(&mut s, &mut o, 0, true, false, b"", max);
        push(&mut s, &mut o, 11, false, false, b"klm", max); // offset 10, hole 0..10
        assert_eq!(o.0.len(), 0);
        push(&mut s, &mut o, 14, false, false, b"no", max); // appended: 5 bytes + overhead
        assert_eq!(o.0, vec![(10, b"klmno".to_vec())]);
        push(&mut s, &mut o, 1, false, false, b"late", max); // dropped
        assert_eq!(o.concat(), b"klmno");
    }

    #[test]
    fn one_byte_segments_pay_their_overhead() {
        let (mut s, mut o) = (Stream::default(), Out::default());
        let max = 1000;
        push(&mut s, &mut o, 0, true, false, b"", max);
        let mut pushed = 0;
        // Non-contiguous 1-byte segments (offsets 2, 4, 6, ...): one piece each.
        for i in 1..=10_000u32 {
            push(&mut s, &mut o, 1 + 2 * i, false, false, b"x", max);
            pushed += 1;
            assert!(s.cost() <= max, "cost {} after {pushed} segments", s.cost());
            if !o.0.is_empty() {
                break;
            }
        }
        // 1000 / (1 + 64) = 15 pieces fit: the 16th forces the first hole to be skipped.
        assert_eq!(pushed, 16);
        assert_eq!(o.0[0].0, 2);
        assert!(s.buffered() <= 15);
    }

    #[test]
    fn contiguous_pieces_are_merged() {
        let (mut s, mut o) = (Stream::default(), Out::default());
        push(&mut s, &mut o, 0, true, false, b"", 1 << 20);
        for i in 0..100u32 {
            push(&mut s, &mut o, 11 + i, false, false, b"y", 1 << 20);
        }
        assert_eq!((s.pending.len(), s.buffered()), (1, 100));
        assert_eq!(s.cost(), 100 + PIECE_OVERHEAD);
    }

    #[test]
    fn truncated_segment_skips_its_lost_tail_at_once() {
        let (mut s, mut o) = (Stream::default(), Out::default());
        push(&mut s, &mut o, 0, true, false, b"", 1 << 20);
        let seg = |seq, payload: &'static [u8], len| Segment {
            seq,
            syn: false,
            fin: false,
            payload,
            len,
        };
        let mut emit = |gap: u64, data: &[u8]| o.0.push((gap, data.to_vec()));
        s.segment(&seg(1, b"abc", 10), 1 << 20, &mut emit);
        assert_eq!(s.next_off, 10, "the lost tail is skipped without waiting");
        s.segment(&seg(11, b"", 10), 1 << 20, &mut emit); // nothing captured at all
        s.segment(&seg(21, b"xyz", 3), 1 << 20, &mut emit);
        assert_eq!(o.0, vec![(0, b"abc".to_vec()), (17, b"xyz".to_vec())]);
        assert_eq!(s.buffered(), 0);
    }

    #[test]
    fn fin_outside_the_window_is_ignored() {
        let (mut s, mut o) = (Stream::default(), Out::default());
        push(&mut s, &mut o, 0, true, false, b"", BIG);
        push(&mut s, &mut o, 1, false, false, b"0123456789", BIG);
        push(&mut s, &mut o, 3, false, true, b"", BIG); // stale FIN behind the data
        push(&mut s, &mut o, 1 + (1 << 31), false, true, b"", BIG); // far ahead
        push(&mut s, &mut o, 11, false, false, b"more", BIG);
        assert_eq!(o.concat(), b"0123456789more");
        assert_eq!(s.fin_off, None);
    }

    #[test]
    fn flush_reports_each_gap() {
        let (mut s, mut o) = (Stream::default(), Out::default());
        push(&mut s, &mut o, 0, true, false, b"", BIG);
        push(&mut s, &mut o, 1, false, false, b"a", BIG);
        push(&mut s, &mut o, 4, false, false, b"d", BIG);
        push(&mut s, &mut o, 8, false, false, b"h", BIG);
        s.flush(&mut |gap, data| o.0.push((gap, data.to_vec())));
        assert_eq!(
            o.0,
            vec![(0, b"a".to_vec()), (2, b"d".to_vec()), (3, b"h".to_vec())]
        );
    }

    #[test]
    fn midstream_starts_at_first_seq_and_reanchors_before_data() {
        let (mut s, mut o) = (Stream::default(), Out::default());
        push(&mut s, &mut o, 500, false, false, b"", BIG); // pure ACK
        push(&mut s, &mut o, 490, false, false, b"0123456789", BIG);
        push(&mut s, &mut o, 500, false, false, b"tail", BIG);
        assert_eq!(o.concat(), b"0123456789tail");
    }

    #[test]
    fn data_after_fin_and_far_segments_are_ignored() {
        let (mut s, mut o) = (Stream::default(), Out::default());
        push(&mut s, &mut o, 0, true, false, b"", BIG);
        push(&mut s, &mut o, 1, false, true, b"ab", BIG);
        push(&mut s, &mut o, 3, false, false, b"zz", BIG);
        push(&mut s, &mut o, 1 + (1 << 31) - 5, false, false, b"far", BIG);
        assert_eq!(o.concat(), b"ab");
        assert_eq!(s.buffered(), 0);
    }

    #[test]
    fn zero_buffer_delivers_out_of_order_data_at_once() {
        let (mut s, mut o) = (Stream::default(), Out::default());
        push(&mut s, &mut o, 0, true, false, b"", 0);
        push(&mut s, &mut o, 3, false, false, b"cd", 0);
        assert_eq!(o.0, vec![(2, b"cd".to_vec())]);
    }
}
