//! Transport layer: TCP, UDP, ICMP, `ICMPv6` (via `etherparse` header slices).

use etherparse::err::tcp::{HeaderError as TcpHeaderError, HeaderSliceError as TcpSliceError};
use etherparse::{Icmpv4Slice, Icmpv6Slice, TcpHeaderSlice, UdpHeaderSlice};

use crate::bytes::be16;
use crate::decoded::{IcmpInfo, TcpFlags, TcpInfo, Transport, UdpInfo};
use crate::error::{DecodeError, Layer};

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
/// Returns `Ok(None)` for protocols other than TCP, UDP, ICMP and `ICMPv6`, and
/// `Ok(Some((header, payload)))` otherwise, where `payload` borrows `data`. Used by
/// [`crate::decode`] and by IP reassembly (`netsift-flow`) on reassembled datagrams.
pub fn decode_transport(
    protocol: u8,
    data: &[u8],
) -> Result<Option<(Transport, &[u8])>, DecodeError> {
    match protocol {
        proto::TCP => tcp(data).map(Some),
        proto::UDP => udp(data).map(Some),
        proto::ICMP => {
            let icmp = Icmpv4Slice::from_slice(data)
                .map_err(|e| DecodeError::truncated(Layer::Icmpv4, e.required_len, e.len))?;
            let info = IcmpInfo {
                icmp_type: icmp.type_u8(),
                code: icmp.code_u8(),
            };
            Ok(Some((Transport::Icmpv4(info), icmp.payload())))
        }
        proto::ICMPV6 => {
            let icmp = Icmpv6Slice::from_slice(data)
                .map_err(|e| DecodeError::truncated(Layer::Icmpv6, e.required_len, e.len))?;
            let info = IcmpInfo {
                icmp_type: icmp.type_u8(),
                code: icmp.code_u8(),
            };
            Ok(Some((Transport::Icmpv6(info), icmp.payload())))
        }
        _ => Ok(None),
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
    let payload = data.get(header_len..).unwrap_or_default();
    let info = TcpInfo {
        src_port: h.source_port(),
        dst_port: h.destination_port(),
        seq: h.sequence_number(),
        ack: h.acknowledgment_number(),
        flags: TcpFlags(be16(h.slice(), 12).unwrap_or_default() & 0x01ff),
        window: h.window_size(),
        header_len: u8::try_from(header_len).unwrap_or(u8::MAX),
        payload_len: payload.len(),
    };
    Ok((Transport::Tcp(info), payload))
}

fn udp(data: &[u8]) -> Result<(Transport, &[u8]), DecodeError> {
    let h = UdpHeaderSlice::from_slice(data)
        .map_err(|e| DecodeError::truncated(Layer::Udp, e.required_len, e.len))?;
    let length = h.length();
    let end = usize::from(length);
    // Trim trailing bytes (link padding) when the length field is consistent; otherwise
    // (truncated capture, jumbogram with length 0) keep everything captured.
    let payload = if (UDP_HEADER_LEN..=data.len()).contains(&end) {
        data.get(UDP_HEADER_LEN..end)
    } else {
        data.get(UDP_HEADER_LEN..)
    }
    .unwrap_or_default();
    let info = UdpInfo {
        src_port: h.source_port(),
        dst_port: h.destination_port(),
        length,
        payload_len: payload.len(),
    };
    Ok((Transport::Udp(info), payload))
}
