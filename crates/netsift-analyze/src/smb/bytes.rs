//! Bounds-checked little/big-endian readers used by the SMB and NTLMSSP parsers.
//!
//! Captures are hostile input: every accessor returns `Option`/falls back, never panics, and
//! no allocation is ever sized from an unchecked length field.

/// Byte at `off`.
pub(super) fn u8_at(data: &[u8], off: usize) -> Option<u8> {
    data.get(off).copied()
}

/// Fixed-size array at `off`.
pub(super) fn array<const N: usize>(data: &[u8], off: usize) -> Option<[u8; N]> {
    data.get(off..off.checked_add(N)?)?.try_into().ok()
}

pub(super) fn le16(data: &[u8], off: usize) -> Option<u16> {
    array(data, off).map(u16::from_le_bytes)
}

pub(super) fn le32(data: &[u8], off: usize) -> Option<u32> {
    array(data, off).map(u32::from_le_bytes)
}

pub(super) fn le64(data: &[u8], off: usize) -> Option<u64> {
    array(data, off).map(u64::from_le_bytes)
}

/// 24-bit big-endian integer at `off` (NetBIOS session service message length).
pub(super) fn be24(data: &[u8], off: usize) -> Option<u32> {
    let b: [u8; 3] = array(data, off)?;
    Some(u32::from_be_bytes([0, b[0], b[1], b[2]]))
}

/// Slice `data[off..off+len]`, or `None` when it would run past the end.
pub(super) fn slice(data: &[u8], off: usize, len: usize) -> Option<&[u8]> {
    data.get(off..off.checked_add(len)?)
}

/// First index of `needle` in `haystack`, searching at most `limit` starting positions.
pub(super) fn find(haystack: &[u8], needle: &[u8], limit: usize) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    let last = haystack.len() - needle.len();
    for start in 0..=last.min(limit) {
        if haystack.get(start..start.checked_add(needle.len())?) == Some(needle) {
            return Some(start);
        }
    }
    None
}

/// Decodes a NTLMSSP string field: UTF-16LE when `unicode`, otherwise OEM/ASCII. Bounded by
/// the slice length; invalid sequences are replaced, never rejected.
pub(super) fn decode_string(data: &[u8], unicode: bool) -> String {
    if unicode {
        let (pairs, _) = data.as_chunks::<2>();
        let units: Vec<u16> = pairs.iter().copied().map(u16::from_le_bytes).collect();
        String::from_utf16_lossy(&units)
    } else {
        data.iter().map(|&b| char::from(b)).collect()
    }
}

/// Lower-case hexadecimal of `data`.
pub(super) fn to_hex(data: &[u8]) -> String {
    use std::fmt::Write as _;
    data.iter()
        .fold(String::with_capacity(data.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}
