//! Bounded walk over IP extension headers (IPv6 extensions, IPv4/IPv6 AH).
//!
//! Hand-written rather than `etherparse`'s lax extension slicing: that code keeps parsing
//! after a non-first fragment header (reading fragment data as headers) and its iterator
//! reads past the validated bytes after a truncated header.

use crate::bytes::{be16, be32, u8_at};
use crate::decoded::{Fragment, IpExtensions};
use crate::error::{DecodeError, Layer};

/// IP protocol numbers of the extension headers walked here.
pub(crate) const PROTO_HOP_BY_HOP: u8 = 0;
pub(crate) const PROTO_ROUTING: u8 = 43;
pub(crate) const PROTO_FRAGMENT: u8 = 44;
pub(crate) const PROTO_AUTH: u8 = 51;
pub(crate) const PROTO_DEST_OPTIONS: u8 = 60;

/// Result of an extension header walk.
pub(crate) struct ExtWalk<'a> {
    /// Protocol number of `rest` (upper layer, or the fragment's next header).
    pub protocol: u8,
    /// Bytes after the last header walked.
    pub rest: &'a [u8],
    /// Bytes consumed by the walked headers.
    pub consumed: usize,
    /// Fragment header that fragments the payload, with the fragmentable part after it.
    pub fragment: Option<(Fragment, &'a [u8])>,
    /// Identification of a fragment header (even an atomic one).
    pub ident: Option<u32>,
    /// Protocol numbers of the walked headers.
    pub extensions: IpExtensions,
    /// Truncated or malformed header that stopped the walk.
    pub error: Option<DecodeError>,
}

/// Length of the extension header `next` at the start of `rest`.
fn header_len(next: u8, rest: &[u8], layer: Layer) -> Result<usize, DecodeError> {
    if next == PROTO_FRAGMENT {
        return Ok(8);
    }
    let len_field = u8_at(rest, 1)
        .map(usize::from)
        .ok_or(DecodeError::truncated(layer, 2, rest.len()))?;
    if next == PROTO_AUTH {
        // RFC 4302: length in 4-byte units, minus 2. Zero cannot hold the fixed fields.
        if len_field == 0 {
            return Err(DecodeError::malformed(
                layer,
                "invalid authentication header",
            ));
        }
        return Ok(len_field.saturating_add(2).saturating_mul(4));
    }
    // RFC 8200: length in 8-byte units, not counting the first 8 bytes.
    Ok(len_field.saturating_add(1).saturating_mul(8))
}

/// Walks the extension headers starting with protocol `first` at the start of `data`.
///
/// With `ipv6 = false` only AH is recognized (IPv4). The walk stops on the first
/// upper-layer protocol, on a fragment header with a non-zero offset (what follows is
/// fragment data), or on an error. Each step consumes at least 8 bytes.
pub(crate) fn walk(first: u8, data: &[u8], ipv6: bool, layer: Layer) -> ExtWalk<'_> {
    let mut w = ExtWalk {
        protocol: first,
        rest: data,
        consumed: 0,
        fragment: None,
        ident: None,
        extensions: IpExtensions::default(),
        error: None,
    };
    loop {
        let next = w.protocol;
        let known = match next {
            PROTO_AUTH => true,
            PROTO_HOP_BY_HOP | PROTO_ROUTING | PROTO_FRAGMENT | PROTO_DEST_OPTIONS => ipv6,
            _ => false,
        };
        if !known {
            return w;
        }
        if next == PROTO_HOP_BY_HOP && !w.extensions.is_empty() {
            w.error = Some(DecodeError::malformed(
                layer,
                "hop-by-hop header is not first",
            ));
            return w;
        }
        let len = match header_len(next, w.rest, layer) {
            Ok(len) => len,
            Err(e) => {
                w.error = Some(e);
                return w;
            }
        };
        let Some((hdr, after)) = w.rest.split_at_checked(len) else {
            w.error = Some(DecodeError::truncated(layer, len, w.rest.len()));
            return w;
        };
        // Headers beyond MAX_IPV6_EXTENSIONS are not listed; the walk continues.
        w.extensions.push(next);
        w.consumed = w.consumed.saturating_add(len);
        w.rest = after;
        w.protocol = u8_at(hdr, 0).unwrap_or_default();
        if next == PROTO_FRAGMENT {
            let off_flags = be16(hdr, 2).unwrap_or_default();
            let id = be32(hdr, 4).unwrap_or_default();
            // 13-bit offset in 8-byte units in the high bits: masking gives bytes.
            let offset = off_flags & 0xfff8;
            let more = off_flags & 0x0001 != 0;
            w.ident = Some(id);
            if offset != 0 || more {
                let frag = Fragment {
                    id,
                    offset,
                    more,
                    next_header: w.protocol,
                };
                w.fragment = Some((frag, after));
            }
            if offset != 0 {
                return w;
            }
        }
    }
}
