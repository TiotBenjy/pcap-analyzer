//! Network layer: IPv4 / IPv6 (header slices from `etherparse`, extension headers walked
//! by hand, see `ipext`) and ARP.

use std::net::{IpAddr, Ipv4Addr};

use etherparse::err::{ipv4, ipv6};
use etherparse::{Ipv4HeaderSlice, Ipv6HeaderSlice};

use crate::bytes::{array, be16, split, tail, u8_at};
use crate::decoded::{
    ArpInfo, Decoded, Fragment, IpExtensions, IpInfo, IpVersion, MacAddr, Network,
};
use crate::error::{DecodeError, Layer};
use crate::{ethertype, ipext, transport};

/// Dispatches on an Ethertype: IP, ARP, or nothing (payload stays the link payload).
pub(crate) fn decode_ethertype<'a>(
    d: &mut Decoded<'a>,
    ty: u16,
    data: &'a [u8],
) -> Result<(), DecodeError> {
    d.payload = data;
    match ty {
        ethertype::IPV4 => decode_ip(d, data, Some(IpVersion::V4)),
        ethertype::IPV6 => decode_ip(d, data, Some(IpVersion::V6)),
        ethertype::ARP | ethertype::RARP => decode_arp(d, data),
        _ => Ok(()),
    }
}

const fn ip_layer(v: IpVersion) -> Layer {
    match v {
        IpVersion::V4 => Layer::Ipv4,
        IpVersion::V6 => Layer::Ipv6,
    }
}

/// IPv4 / IPv6 header (+ extensions), then the transport layer.
///
/// `expected`: version implied by the link layer; a mismatch is reported as malformed.
pub(crate) fn decode_ip<'a>(
    d: &mut Decoded<'a>,
    data: &'a [u8],
    expected: Option<IpVersion>,
) -> Result<(), DecodeError> {
    d.payload = data;
    let Some(first) = u8_at(data, 0) else {
        let layer = expected.map_or(Layer::Ip, ip_layer);
        return Err(DecodeError::truncated(layer, 1, 0));
    };
    let version = match first >> 4 {
        4 => IpVersion::V4,
        6 => IpVersion::V6,
        _ => return Err(DecodeError::malformed(Layer::Ip, "unknown IP version")),
    };
    if expected.is_some_and(|e| e != version) {
        return Err(DecodeError::malformed(
            ip_layer(version),
            "IP version does not match the link protocol",
        ));
    }
    match version {
        IpVersion::V4 => decode_ipv4(d, data),
        IpVersion::V6 => decode_ipv6(d, data),
    }
}

/// Bytes announced by the IP length field after a `header_len`-byte header, without
/// link padding. Falls back to everything captured when the field is inconsistent;
/// the flag is set when the field announces more than captured.
fn ip_body(data: &[u8], header_len: usize, announced_end: Option<usize>) -> (&[u8], bool) {
    let rest = tail(data, header_len);
    match announced_end {
        Some(end) if end > data.len() => (rest, true),
        Some(end) if end >= header_len => (data.get(header_len..end).unwrap_or(rest), false),
        _ => (rest, false),
    }
}

fn decode_ipv4<'a>(d: &mut Decoded<'a>, data: &'a [u8]) -> Result<(), DecodeError> {
    use ipv4::{HeaderError as E, HeaderSliceError as S};
    let h = Ipv4HeaderSlice::from_slice(data).map_err(|e| match e {
        S::Len(l) => DecodeError::truncated(Layer::Ipv4, l.required_len, l.len),
        S::Content(E::UnexpectedVersion { .. }) => {
            DecodeError::malformed(Layer::Ipv4, "unexpected IP version")
        }
        S::Content(E::HeaderLengthSmallerThanHeader { .. }) => {
            DecodeError::malformed(Layer::Ipv4, "header length below 20 bytes")
        }
    })?;
    let header_len = h.slice().len();
    let (body, truncated) = ip_body(data, header_len, Some(usize::from(h.total_len())));
    let protocol = h.protocol().0;
    let offset = h.fragments_offset().byte_offset();
    let more = h.more_fragments();
    let fragment = (offset != 0 || more).then(|| Fragment {
        id: u32::from(h.identification()),
        offset,
        more,
        next_header: protocol,
    });
    let mut info = IpInfo {
        version: IpVersion::V4,
        src: IpAddr::V4(h.source_addr()),
        dst: IpAddr::V4(h.destination_addr()),
        protocol,
        ttl: h.ttl(),
        header_len,
        payload_len: body.len(),
        truncated,
        ident: Some(u32::from(h.identification())),
        dont_fragment: h.dont_fragment(),
        fragment,
        extensions: IpExtensions::default(),
    };
    d.l3_offset = d.offset_of(data);
    d.ip_payload = body;
    d.payload = body;
    if offset != 0 {
        // Fragment data only: no AH, no transport header to look for.
        d.network = Some(Network::Ip(info));
        return Ok(());
    }
    let w = ipext::walk(protocol, body, false, Layer::Ipv4);
    info.protocol = w.protocol;
    info.header_len = header_len.saturating_add(w.consumed);
    info.payload_len = w.rest.len();
    info.extensions = w.extensions;
    finish_ip(d, info, w.rest, w.error)
}

fn decode_ipv6<'a>(d: &mut Decoded<'a>, data: &'a [u8]) -> Result<(), DecodeError> {
    use ipv6::{HeaderError as E, HeaderSliceError as S};
    let h = Ipv6HeaderSlice::from_slice(data).map_err(|e| match e {
        S::Len(l) => DecodeError::truncated(Layer::Ipv6, l.required_len, l.len),
        S::Content(E::UnexpectedVersion { .. }) => {
            DecodeError::malformed(Layer::Ipv6, "unexpected IP version")
        }
    })?;
    let header_len = h.slice().len();
    // Payload length 0 means a jumbogram (RFC 2675) or an unset field: use the capture.
    let announced = match h.payload_length() {
        0 => None,
        n => header_len.checked_add(usize::from(n)),
    };
    let (body, truncated) = ip_body(data, header_len, announced);
    let w = ipext::walk(h.next_header().0, body, true, Layer::Ipv6);
    let info = IpInfo {
        version: IpVersion::V6,
        src: IpAddr::V6(h.source_addr()),
        dst: IpAddr::V6(h.destination_addr()),
        protocol: w.protocol,
        ttl: h.hop_limit(),
        header_len: header_len.saturating_add(w.consumed),
        payload_len: w.rest.len(),
        truncated,
        ident: w.ident,
        dont_fragment: false,
        fragment: w.fragment.map(|(f, _)| f),
        extensions: w.extensions,
    };
    d.l3_offset = d.offset_of(data);
    d.ip_payload = w.fragment.map_or(w.rest, |(_, fragmentable)| fragmentable);
    finish_ip(d, info, w.rest, w.error)
}

/// Stores the IP layer, then decodes the transport header unless the packet is a
/// non-first fragment or an extension header failed.
fn finish_ip<'a>(
    d: &mut Decoded<'a>,
    info: IpInfo,
    upper: &'a [u8],
    error: Option<DecodeError>,
) -> Result<(), DecodeError> {
    let protocol = info.protocol;
    let fragment = info.fragment;
    if fragment.is_none() {
        d.ip_payload = upper;
    }
    d.network = Some(Network::Ip(info));
    d.payload = upper;
    if let Some(e) = error {
        return Err(e);
    }
    if fragment.is_some_and(|f| !f.is_first()) {
        return Ok(());
    }
    if let Some((t, header, payload)) = transport::decode_at(protocol, upper)? {
        d.transport = Some(t);
        d.l4_offset = d.offset_of(header);
        d.payload = payload;
    }
    Ok(())
}

/// ARP / RARP (RFC 826): fixed part, then addresses of the announced lengths.
fn decode_arp<'a>(d: &mut Decoded<'a>, data: &'a [u8]) -> Result<(), DecodeError> {
    let (fixed, addrs) = split(data, 8, Layer::Arp)?;
    let hardware_type = be16(fixed, 0).unwrap_or_default();
    let protocol_type = be16(fixed, 2).unwrap_or_default();
    let hlen = usize::from(u8_at(fixed, 4).unwrap_or_default());
    let plen = usize::from(u8_at(fixed, 5).unwrap_or_default());
    let operation = be16(fixed, 6).unwrap_or_default();
    // Both values are < 256: no overflow possible, saturating keeps the lint quiet.
    let pair = hlen.saturating_add(plen);
    let needed = pair.saturating_mul(2);
    let (addrs, rest) = split(addrs, needed, Layer::Arp)
        .map_err(|_| DecodeError::truncated(Layer::Arp, needed.saturating_add(8), data.len()))?;
    let mac = |off: usize| {
        if hlen == 6 {
            addrs.get(off..).and_then(MacAddr::from_slice)
        } else {
            None
        }
    };
    let ip = |off: usize| {
        if protocol_type == ethertype::IPV4 && plen == 4 {
            array::<4>(addrs, off).map(|b| IpAddr::V4(Ipv4Addr::from(b)))
        } else {
            None
        }
    };
    d.l3_offset = d.offset_of(data);
    d.network = Some(Network::Arp(ArpInfo {
        hardware_type,
        protocol_type,
        operation,
        sender_mac: mac(0),
        sender_ip: ip(hlen),
        target_mac: mac(pair),
        target_ip: ip(pair.saturating_add(hlen)),
    }));
    d.payload = rest;
    Ok(())
}
