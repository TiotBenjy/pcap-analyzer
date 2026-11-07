//! Byte-range helpers shared by IP defragmentation and TCP reassembly.

use std::collections::BTreeMap;

/// Sub-ranges of `[start, end)` not covered by `pieces`, in order.
///
/// `pieces` maps an offset to the bytes stored there and must be non-overlapping. Inserting
/// only the returned ranges implements the "first arrival wins" overlap policy.
pub(crate) fn holes(pieces: &BTreeMap<u64, Vec<u8>>, start: u64, end: u64) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    let mut cur = start;
    if let Some((&s, d)) = pieces.range(..start).next_back() {
        cur = cur.max(s.saturating_add(len64(d)));
    }
    for (&s, d) in pieces.range(start..end) {
        if cur >= end {
            break;
        }
        if s > cur {
            out.push((cur, s));
        }
        cur = cur.max(s.saturating_add(len64(d)));
    }
    if cur < end {
        out.push((cur, end));
    }
    out
}

/// Length of a slice as `u64` (lossless on every supported target).
pub(crate) fn len64(data: &[u8]) -> u64 {
    u64::try_from(data.len()).unwrap_or(u64::MAX)
}

/// `data[a - base .. b - base]`, or `None` when out of range.
pub(crate) fn sub(data: &[u8], base: u64, a: u64, b: u64) -> Option<&[u8]> {
    let ra = usize::try_from(a.checked_sub(base)?).ok()?;
    let rb = usize::try_from(b.checked_sub(base)?).ok()?;
    data.get(ra..rb)
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    fn map(entries: &[(u64, usize)]) -> BTreeMap<u64, Vec<u8>> {
        entries.iter().map(|&(o, l)| (o, vec![0; l])).collect()
    }

    #[test]
    fn holes_skip_covered_bytes() {
        let m = map(&[(10, 5), (20, 5)]);
        assert_eq!(holes(&m, 0, 30), vec![(0, 10), (15, 20), (25, 30)]);
        assert_eq!(holes(&m, 12, 22), vec![(15, 20)]);
        assert_eq!(holes(&m, 10, 15), vec![]);
        assert_eq!(holes(&m, 11, 13), vec![]);
        assert_eq!(holes(&BTreeMap::new(), 3, 7), vec![(3, 7)]);
        assert_eq!(holes(&m, 5, 5), vec![]);
    }

    #[test]
    fn sub_is_bounds_checked() {
        let d = [1, 2, 3, 4];
        assert_eq!(sub(&d, 10, 11, 13), Some(&d[1..3]));
        assert_eq!(sub(&d, 10, 9, 13), None);
        assert_eq!(sub(&d, 10, 11, 15), None);
    }
}
