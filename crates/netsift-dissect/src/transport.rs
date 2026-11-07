//! Transport layer: TCP, UDP, ICMP, `ICMPv6` (via `etherparse` header slices).

use etherparse::err::tcp::{HeaderError as TcpHeaderError, HeaderSliceError as TcpSliceError};
use etherparse::{Icmpv4Slice, Icmpv6Slice, TcpHeaderSlice, UdpHeaderSlice};

use crate::bytes::{be16, be32, tail, u8_at};
use crate::decoded::{IcmpInfo, TcpFlags, TcpInfo, TcpOptions, Transport, UdpInfo};
use crate::error::{DecodeError, Layer};
use crate::ipext;

/// IP protocol numbers.
pub mod proto {
    /// ICMP.
    pub const ICMP: u8 = 1;
    /// TCP.
    pub const TCP: u8 = 6;
    /// UDP.
    pub const UDP: u8 = 17;
    /// `ICMPv6`.
    pub const ICMPV6: u8 = 58;
}

/// UDP header length.
const UDP_HEADER_LEN: usize = 8;

/// Decodes the transport header carried by an IP payload.
///
/// Leading extension headers (IPv6 hop-by-hop, routing, destination options, AH) are
/// skipped first, so this also accepts a reassembled fragmentable part: concatenate the
/// [`crate::Decoded::ip_payload`] of the fragments in offset order and call it with
/// [`crate::Fragment::next_header`].
///
/// Returns `Ok(None)` for protocols other than TCP, UDP, ICMP and `ICMPv6`, and
/// `Ok(Some((header, payload)))` otherwise, where `payload` borrows `data`.
pub fn decode_transport(
    protocol: u8,
    data: &[u8],
) -> Result<Option<(Transport, &[u8])>, DecodeError> {
    Ok(decode_at(protocol, data)?.map(|(t, _, payload)| (t, payload)))
}

/// Transport header, slice starting at that header, and payload.
pub(crate) type Located<'a> = (Transport, &'a [u8], &'a [u8]);

/// Like [`decode_transport`], also returning the slice starting at the transport header.
pub(crate) fn decode_at(protocol: u8, data: &[u8]) -> Result<Option<Located<'_>>, DecodeError> {
    let w = ipext::walk(protocol, data, true, Layer::Ipv6);
    if let Some(e) = w.error {
        return Err(e);
    }
    // A nested non-first fragment header: what follows is fragment data.
    if w.fragment.is_some_and(|(f, _)| !f.is_first()) {
        return Ok(None);
    }
    let header = w.rest;
    let decoded = match w.protocol {
        proto::TCP => tcp(header)?,
        proto::UDP => udp(header)?,
        proto::ICMP => {
            let icmp = Icmpv4Slice::from_slice(header)
                .map_err(|e| DecodeError::truncated(Layer::Icmpv4, e.required_len, e.len))?;
            let echo = matches!(icmp.type_u8(), 0 | 8);
            let info = icmp_info(icmp.type_u8(), icmp.code_u8(), echo, icmp.bytes5to8());
            (Transport::Icmpv4(info), icmp.payload())
        }
        proto::ICMPV6 => {
            let icmp = Icmpv6Slice::from_slice(header)
                .map_err(|e| DecodeError::truncated(Layer::Icmpv6, e.required_len, e.len))?;
            let echo = matches!(icmp.type_u8(), 128 | 129);
            let info = icmp_info(icmp.type_u8(), icmp.code_u8(), echo, icmp.bytes5to8());
            (Transport::Icmpv6(info), icmp.payload())
        }
        _ => return Ok(None),
    };
    Ok(Some((decoded.0, header, decoded.1)))
}

fn icmp_info(icmp_type: u8, code: u8, echo: bool, rest_of_header: [u8; 4]) -> IcmpInfo {
    let [i0, i1, s0, s1] = rest_of_header;
    IcmpInfo {
        icmp_type,
        code,
        id: echo.then(|| u16::from_be_bytes([i0, i1])),
        sequence: echo.then(|| u16::from_be_bytes([s0, s1])),
    }
}

fn tcp(data: &[u8]) -> Result<(Transport, &[u8]), DecodeError> {
    let h = TcpHeaderSlice::from_slice(data).map_err(|e| match e {
        TcpSliceError::Len(l) => DecodeError::truncated(Layer::Tcp, l.required_len, l.len),
        TcpSliceError::Content(TcpHeaderError::DataOffsetTooSmall { .. }) => {
            DecodeError::malformed(Layer::Tcp, "data offset below 5")
        }
    })?;
    let header_len = h.slice().len();
    let payload = tail(data, header_len);
    let info = TcpInfo {
        src_port: h.source_port(),
        dst_port: h.destination_port(),
        seq: h.sequence_number(),
        ack: h.acknowledgment_number(),
        flags: TcpFlags(be16(h.slice(), 12).unwrap_or_default() & 0x01ff),
        window: h.window_size(),
        header_len: u8::try_from(header_len).unwrap_or(u8::MAX),
        options: tcp_options(h.options()),
        payload_len: payload.len(),
    };
    Ok((Transport::Tcp(info), payload))
}

/// Parses the TCP options used by analyzers (RFC 9293, 7323, 2018). Bounded by the
/// option area (at most 40 bytes); stops silently on a malformed option.
fn tcp_options(mut rest: &[u8]) -> TcpOptions {
    let mut o = TcpOptions::default();
    while let Some(&kind) = rest.first() {
        match kind {
            0 => break,
            1 => {
                rest = tail(rest, 1);
                continue;
            }
            _ => {}
        }
        let Some(len) = u8_at(rest, 1).map(usize::from) else {
            break;
        };
        if len < 2 {
            break;
        }
        let Some((opt, after)) = rest.split_at_checked(len) else {
            break;
        };
        match (kind, len) {
            (2, 4) => o.mss = be16(opt, 2),
            (3, 3) => o.window_scale = u8_at(opt, 2),
            (4, 2) => o.sack_permitted = true,
            (8, 10) => o.timestamps = be32(opt, 2).zip(be32(opt, 6)),
            _ => {}
        }
        rest = after;
    }
    o
}

fn udp(data: &[u8]) -> Result<(Transport, &[u8]), DecodeError> {
    let h = UdpHeaderSlice::from_slice(data)
        .map_err(|e| DecodeError::truncated(Layer::Udp, e.required_len, e.len))?;
    let length = h.length();
    let end = usize::from(length);
    // Trim trailing bytes (link padding) when the length field is consistent; otherwise
    // (truncated capture, jumbogram with length 0) keep everything captured.
    let rest = tail(data, UDP_HEADER_LEN);
    let payload = if (UDP_HEADER_LEN..=data.len()).contains(&end) {
        data.get(UDP_HEADER_LEN..end).unwrap_or(rest)
    } else {
        rest
    };
    let info = UdpInfo {
        src_port: h.source_port(),
        dst_port: h.destination_port(),
        length,
        payload_len: payload.len(),
    };
    Ok((Transport::Udp(info), payload))
}
