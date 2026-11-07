//! TCP reassembly of one direction of a connection.
//!
//! Sequence numbers are mapped to a 64-bit stream offset (offset 0 = first data byte, i.e.
//! the byte after the SYN, or the first sequence number seen when the SYN is missing). The
//! mapping is relative to the next expected sequence number, modulo 2^32, so it survives
//! wraparound as long as segments stay within +/- 2 GiB of it.
//!
//! Policy:
//! - in-order data is delivered at once; out-of-order segments are buffered (at most
//!   `max_buffer` bytes; one extra segment may be held while the bound is enforced);
//! - **the first arrival wins**: bytes already delivered or buffered are never replaced, so
//!   retransmissions are dropped and overlaps only fill holes;
//! - when a hole will not be filled (buffer full, connection closed or reset, flow end), the
//!   next buffered data is delivered with `gap` = number of missing bytes;
//! - SYN and FIN each consume one sequence number; data beyond the FIN is ignored;
//! - segments more than [`MAX_AHEAD`] bytes ahead of the expected offset are ignored (another
//!   connection or garbage), which keeps reported gaps meaningful.

use std::collections::BTreeMap;

use crate::ranges::{holes, len64, sub};

/// Furthest a segment may start ahead of the next expected byte (1 GiB).
pub(crate) const MAX_AHEAD: u64 = 1 << 30;

/// Callback receiving in-order data: `(gap_before, bytes)`.
pub(crate) type Emit<'a> = dyn FnMut(u64, &[u8]) + 'a;

/// Header fields of a segment relevant to reassembly.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Segment<'a> {
    pub seq: u32,
    pub syn: bool,
    pub fin: bool,
    pub payload: &'a [u8],
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
        let mut end = p0.saturating_add(i128::from(len64(seg.payload)));
        if seg.fin && self.fin_off.is_none() {
            // The FIN consumes the sequence number after the data.
            let fin = u64::try_from(end.max(0)).unwrap_or(u64::MAX);
            self.fin_off = Some(fin.max(self.next_off));
        }
        if let Some(fin) = self.fin_off {
            end = end.min(i128::from(fin));
        }
        let next = i128::from(self.next_off);
        if end <= next || p0.saturating_sub(next) > i128::from(MAX_AHEAD) {
            return;
        }
        // Trim what was already delivered (first arrival wins).
        let start = p0.max(next);
        let (Ok(ra), Ok(rb), Ok(start), Ok(end)) = (
            usize::try_from(start.saturating_sub(p0)),
            usize::try_from(end.saturating_sub(p0)),
            u64::try_from(start),
            u64::try_from(end),
        ) else {
            return;
        };
        let Some(data) = seg.payload.get(ra..rb) else {
            return;
        };

        if start == self.next_off && self.pending.is_empty() {
            let gap = std::mem::take(&mut self.gap);
            emit(gap, data);
            self.advance(len64(data));
            return;
        }
        for (a, b) in holes(&self.pending, start, end) {
            if let Some(bytes) = sub(data, start, a, b) {
                self.pending_bytes = self.pending_bytes.saturating_add(bytes.len());
                self.pending.insert(a, bytes.to_vec());
            }
        }
        self.drain(emit);
        while self.pending_bytes > max_buffer {
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
            },
            max,
            &mut |gap, data| out.0.push((gap, data.to_vec())),
        );
    }

    #[test]
    fn in_order_after_syn() {
        let (mut s, mut o) = (Stream::default(), Out::default());
        push(&mut s, &mut o, 99, true, false, b"", 100);
        push(&mut s, &mut o, 100, false, false, b"abc", 100);
        push(&mut s, &mut o, 103, false, false, b"def", 100);
        assert_eq!(o.concat(), b"abcdef");
        assert_eq!(o.gaps(), vec![0, 0]);
    }

    #[test]
    fn out_of_order_and_overlaps_first_arrival_wins() {
        let (mut s, mut o) = (Stream::default(), Out::default());
        push(&mut s, &mut o, 0, true, false, b"", 100);
        push(&mut s, &mut o, 5, false, false, b"FGH", 100); // offsets 4..7
        push(&mut s, &mut o, 4, false, false, b"xyzw", 100); // overlaps: only 3 is new
        push(&mut s, &mut o, 1, false, false, b"abc", 100);
        push(&mut s, &mut o, 1, false, false, b"ABCDEFGH", 100); // retransmission
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
        push(&mut s, &mut o, u32::MAX - 2, true, false, b"", 100);
        push(&mut s, &mut o, 0, false, false, b"cd", 100); // offset 2
        push(&mut s, &mut o, u32::MAX - 1, false, false, b"ab", 100);
        push(&mut s, &mut o, 2, false, true, b"e", 100);
        assert_eq!(o.concat(), b"abcde");
        assert_eq!(s.fin_off, Some(5));
    }

    #[test]
    fn buffer_limit_skips_the_hole() {
        let (mut s, mut o) = (Stream::default(), Out::default());
        push(&mut s, &mut o, 0, true, false, b"", 4);
        push(&mut s, &mut o, 11, false, false, b"klm", 4); // offset 10, hole 0..10
        assert_eq!(o.0.len(), 0);
        push(&mut s, &mut o, 14, false, false, b"no", 4); // 5 bytes > 4
        assert_eq!(o.0, vec![(10, b"klm".to_vec()), (0, b"no".to_vec())]);
        push(&mut s, &mut o, 1, false, false, b"late", 4); // dropped
        assert_eq!(o.concat(), b"klmno");
    }

    #[test]
    fn flush_reports_each_gap() {
        let (mut s, mut o) = (Stream::default(), Out::default());
        push(&mut s, &mut o, 0, true, false, b"", 100);
        push(&mut s, &mut o, 1, false, false, b"a", 100);
        push(&mut s, &mut o, 4, false, false, b"d", 100);
        push(&mut s, &mut o, 8, false, false, b"h", 100);
        s.flush(&mut |gap, data| o.0.push((gap, data.to_vec())));
        assert_eq!(
            o.0,
            vec![(0, b"a".to_vec()), (2, b"d".to_vec()), (3, b"h".to_vec())]
        );
    }

    #[test]
    fn midstream_starts_at_first_seq_and_reanchors_before_data() {
        let (mut s, mut o) = (Stream::default(), Out::default());
        push(&mut s, &mut o, 500, false, false, b"", 100); // pure ACK
        push(&mut s, &mut o, 490, false, false, b"0123456789", 100);
        push(&mut s, &mut o, 500, false, false, b"tail", 100);
        assert_eq!(o.concat(), b"0123456789tail");
    }

    #[test]
    fn data_after_fin_and_far_segments_are_ignored() {
        let (mut s, mut o) = (Stream::default(), Out::default());
        push(&mut s, &mut o, 0, true, false, b"", 100);
        push(&mut s, &mut o, 1, false, true, b"ab", 100);
        push(&mut s, &mut o, 3, false, false, b"zz", 100);
        push(&mut s, &mut o, 1 + (1 << 31) - 5, false, false, b"far", 100);
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
