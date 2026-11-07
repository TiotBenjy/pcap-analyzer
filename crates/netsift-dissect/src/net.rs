//! Network layer: IPv4 / IPv6 (via `etherparse` lax slicing) and ARP.

use std::net::{IpAddr, Ipv4Addr};

use etherparse::err::ip::{HeaderError as IpHeaderError, LaxHeaderSliceError};
use etherparse::err::ipv6_exts::{
    HeaderError as ExtHeaderError, HeaderSliceError as ExtSliceError,
};
use etherparse::{LaxIpSlice, LaxIpv4Slice, LaxIpv6Slice};

use crate::bytes::{array, be16, be32, split, u8_at};
use crate::decoded::{
    ArpInfo, Decoded, Fragment, IpExtensions, IpInfo, IpVersion, MacAddr, Network,
};
use crate::error::{DecodeError, Layer};
use crate::{ethertype, transport};

/// IP protocol numbers of the extension headers recognized by `etherparse`.
const PROTO_HOP_BY_HOP: u8 = 0;
const PROTO_ROUTING: u8 = 43;
const PROTO_FRAGMENT: u8 = 44;
const PROTO_AUTH: u8 = 51;
const PROTO_DEST_OPTIONS: u8 = 60;

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
    let layer = ip_layer(version);
    if expected.is_some_and(|e| e != version) {
        return Err(DecodeError::malformed(
            layer,
            "IP version does not match the link protocol",
        ));
    }
    let (ip, ext_err) = LaxIpSlice::from_slice(data).map_err(|e| match e {
        LaxHeaderSliceError::Len(l) => DecodeError::truncated(layer, l.required_len, l.len),
        LaxHeaderSliceError::Content(IpHeaderError::UnsupportedIpVersion { .. }) => {
            DecodeError::malformed(Layer::Ip, "unknown IP version")
        }
        LaxHeaderSliceError::Content(IpHeaderError::Ipv4HeaderLengthSmallerThanHeader {
            ..
        }) => DecodeError::malformed(Layer::Ipv4, "header length below 20 bytes"),
    })?;

    let payload = ip.payload();
    let mut info = IpInfo {
        version,
        src: ip.source_addr(),
        dst: ip.destination_addr(),
        protocol: payload.ip_number.0,
        ttl: 0,
        header_len: 0,
        payload_len: payload.payload.len(),
        truncated: payload.incomplete,
        ident: None,
        dont_fragment: false,
        fragment: None,
        extensions: IpExtensions::default(),
    };
    match &ip {
        LaxIpSlice::Ipv4(v4) => fill_ipv4(&mut info, v4),
        LaxIpSlice::Ipv6(v6) => fill_ipv6(&mut info, v6),
    }
    let protocol = info.protocol;
    let fragment = info.fragment;
    d.network = Some(Network::Ip(info));
    d.payload = payload.payload;

    if let Some((e, _)) = ext_err {
        return Err(ext_error(&e, layer));
    }
    // Non-first fragments carry no transport header.
    if fragment.is_some_and(|f| !f.is_first()) {
        return Ok(());
    }
    if let Some((t, rest)) = transport::decode_transport(protocol, payload.payload)? {
        d.transport = Some(t);
        d.payload = rest;
    }
    Ok(())
}

fn fill_ipv4(info: &mut IpInfo, v4: &LaxIpv4Slice<'_>) {
    let h = v4.header();
    info.ttl = h.ttl();
    info.ident = Some(u32::from(h.identification()));
    info.dont_fragment = h.dont_fragment();
    let offset = h.fragments_offset();
    if h.more_fragments() || offset.value() != 0 {
        info.fragment = Some(Fragment {
            id: u32::from(h.identification()),
            offset: offset.byte_offset(),
            more: h.more_fragments(),
        });
    }
    let mut header_len = h.slice().len();
    if let Some(auth) = &v4.extensions().auth {
        info.extensions.push(PROTO_AUTH);
        header_len = header_len.saturating_add(auth.slice().len());
    }
    info.header_len = header_len;
}

fn fill_ipv6(info: &mut IpInfo, v6: &LaxIpv6Slice<'_>) {
    let h = v6.header();
    info.ttl = h.hop_limit();
    let exts = v6.extensions();
    info.header_len = h.slice().len().saturating_add(exts.slice().len());
    walk_ipv6_extensions(info, h.next_header().0, exts.slice());
}

/// Walks the IPv6 extension headers already validated by `etherparse` (`validated` only
/// holds complete headers).
///
/// `Ipv6ExtensionsSlice::into_iter` is deliberately not used: when a lax parse stopped on
/// a truncated header, that iterator builds the next header with an unchecked constructor
/// and reads past the validated bytes (debug assertion, undefined behaviour in release).
fn walk_ipv6_extensions(info: &mut IpInfo, first: u8, validated: &[u8]) {
    let mut next = first;
    let mut rest = validated;
    while !rest.is_empty() {
        let Some(len_field) = u8_at(rest, 1).map(usize::from) else {
            return;
        };
        let len = match next {
            PROTO_FRAGMENT => Some(8),
            // RFC 4302: length in 4-byte units, minus 2.
            PROTO_AUTH => len_field.checked_add(2).and_then(|n| n.checked_mul(4)),
            // RFC 8200: length in 8-byte units, not counting the first 8 bytes.
            PROTO_HOP_BY_HOP | PROTO_ROUTING | PROTO_DEST_OPTIONS => {
                len_field.checked_add(1).and_then(|n| n.checked_mul(8))
            }
            _ => None,
        };
        let Some((hdr, after)) = len.and_then(|n| rest.split_at_checked(n)) else {
            return;
        };
        if next == PROTO_FRAGMENT {
            let off_flags = be16(hdr, 2).unwrap_or_default();
            let id = be32(hdr, 4).unwrap_or_default();
            let offset = off_flags & 0xfff8; // 13-bit offset in 8-byte units, i.e. bytes
            let more = off_flags & 0x0001 != 0;
            info.ident = Some(id);
            if offset != 0 || more {
                info.fragment = Some(Fragment { id, offset, more });
            }
        }
        // Headers beyond MAX_IPV6_EXTENSIONS are not listed; decoding continues.
        info.extensions.push(next);
        next = u8_at(hdr, 0).unwrap_or_default();
        rest = after;
    }
}

fn ext_error(e: &ExtSliceError, layer: Layer) -> DecodeError {
    match e {
        ExtSliceError::Len(l) => DecodeError::truncated(layer, l.required_len, l.len),
        ExtSliceError::Content(ExtHeaderError::HopByHopNotAtStart) => {
            DecodeError::malformed(layer, "hop-by-hop header is not first")
        }
        ExtSliceError::Content(ExtHeaderError::IpAuth(_)) => {
            DecodeError::malformed(layer, "invalid authentication header")
        }
    }
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
