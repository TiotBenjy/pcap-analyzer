//! Bounds-checked byte readers (never panic).

use crate::error::{DecodeError, Layer};

/// Splits `n` bytes off the front, or reports a truncation at `layer`.
pub(crate) fn split(data: &[u8], n: usize, layer: Layer) -> Result<(&[u8], &[u8]), DecodeError> {
    data.split_at_checked(n)
        .ok_or(DecodeError::truncated(layer, n, data.len()))
}

/// Fixed-size array at `off`.
pub(crate) fn array<const N: usize>(data: &[u8], off: usize) -> Option<[u8; N]> {
    data.get(off..off.checked_add(N)?)?.try_into().ok()
}

pub(crate) fn u8_at(data: &[u8], off: usize) -> Option<u8> {
    data.get(off).copied()
}

pub(crate) fn be16(data: &[u8], off: usize) -> Option<u16> {
    array(data, off).map(u16::from_be_bytes)
}

pub(crate) fn le16(data: &[u8], off: usize) -> Option<u16> {
    array(data, off).map(u16::from_le_bytes)
}

pub(crate) fn be32(data: &[u8], off: usize) -> Option<u32> {
    array(data, off).map(u32::from_be_bytes)
}

pub(crate) fn le32(data: &[u8], off: usize) -> Option<u32> {
    array(data, off).map(u32::from_le_bytes)
}
