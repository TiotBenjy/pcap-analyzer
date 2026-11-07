//! Link layer: Ethernet / 802.3, VLAN tags, LLC/SNAP, Linux SLL/SLL2, loopback, raw IP.

use crate::bytes::{be16, be32, le32, split, u8_at};
use crate::decoded::{Decoded, IpVersion, LinkKind, Llc, MacAddr, SllInfo, VlanTag};
use crate::error::{DecodeError, ErrorKind, Layer};
use crate::{ethertype, linktype, net, wifi};

/// Highest value of the Ethernet type field interpreted as an 802.3 length.
const MAX_8023_LEN: u16 = 1500;

/// `ARPHRD_*` device types that change how a Linux cooked header is followed.
const ARPHRD_IEEE80211: u16 = 801;
const ARPHRD_IEEE80211_RADIOTAP: u16 = 803;
const ARPHRD_NETLINK: u16 = 824;

/// Linux pseudo-protocol: 802.2 LLC frame follows (`ETH_P_802_2`).
const SLL_PROTO_802_2: u16 = 0x0004;

/// Entry point of the link layer; fills `d` and returns the first error, if any.
pub(crate) fn decode<'a>(d: &mut Decoded<'a>, lt: u32, data: &'a [u8]) -> Result<(), DecodeError> {
    match lt {
        linktype::ETHERNET => {
            d.link.kind = LinkKind::Ethernet;
            ethernet(d, data)
        }
        linktype::LINUX_SLL => {
            d.link.kind = LinkKind::LinuxSll;
            sll(d, data)
        }
        linktype::LINUX_SLL2 => {
            d.link.kind = LinkKind::LinuxSll2;
            sll2(d, data)
        }
        linktype::RAW | linktype::IPV4 | linktype::IPV6 => {
            d.link.kind = LinkKind::RawIp;
            raw(d, lt, data)
        }
        linktype::NULL | linktype::LOOP => {
            d.link.kind = LinkKind::Loopback;
            loopback(d, lt == linktype::LOOP, data)
        }
        linktype::IEEE802_11 => {
            d.link.kind = LinkKind::Ieee80211;
            wifi::ieee80211(d, data, false)
        }
        linktype::IEEE802_11_RADIOTAP => {
            d.link.kind = LinkKind::Ieee80211Radiotap;
            wifi::radiotap(d, data)
        }
        other => Err(DecodeError {
            layer: Layer::Link,
            kind: ErrorKind::UnsupportedLinktype(other),
        }),
    }
}

fn ethernet<'a>(d: &mut Decoded<'a>, data: &'a [u8]) -> Result<(), DecodeError> {
    let (hdr, rest) = split(data, 14, Layer::Ethernet)?;
    d.link.dst_mac = MacAddr::from_slice(hdr);
    d.link.src_mac = hdr.get(6..).and_then(MacAddr::from_slice);
    let ty = be16(hdr, 12).ok_or(DecodeError::truncated(Layer::Ethernet, 14, data.len()))?;
    d.payload = rest;
    ether_payload(d, ty, rest, true)
}

const fn is_vlan_tpid(ty: u16) -> bool {
    matches!(ty, ethertype::VLAN | ethertype::QINQ | ethertype::QINQ_OLD)
}

/// Follows an Ethertype: VLAN tags (bounded), 802.3 length + LLC when `allow_len`,
/// then the network layer.
///
/// `allow_len` is `false` after SNAP and for Linux cooked captures, where values below
/// `0x0600` are not 802.3 lengths. This also keeps the call graph acyclic (no recursion).
pub(crate) fn ether_payload<'a>(
    d: &mut Decoded<'a>,
    mut ty: u16,
    mut data: &'a [u8],
    allow_len: bool,
) -> Result<(), DecodeError> {
    while is_vlan_tpid(ty) {
        let (tag, rest) = split(data, 4, Layer::Vlan)?;
        let tci = be16(tag, 0).unwrap_or_default();
        let vlan = VlanTag {
            tpid: ty,
            pcp: u8::try_from(tci >> 13).unwrap_or_default(),
            dei: tci & 0x1000 != 0,
            id: tci & 0x0fff,
        };
        if !d.link.vlans.push(vlan) {
            return Err(DecodeError::malformed(
                Layer::Vlan,
                "too many stacked VLAN tags",
            ));
        }
        ty = be16(tag, 2).unwrap_or_default();
        data = rest;
        d.payload = rest;
    }
    if ty < ethertype::MIN_ETHERTYPE {
        if !allow_len {
            return Ok(());
        }
        if ty > MAX_8023_LEN {
            return Err(DecodeError::malformed(
                Layer::Ethernet,
                "invalid type/length field",
            ));
        }
        // 802.3 length: drop Ethernet padding when the length is consistent.
        let frame = data.get(..usize::from(ty)).unwrap_or(data);
        d.payload = frame;
        return llc(d, frame);
    }
    d.link.ethertype = Some(ty);
    net::decode_ethertype(d, ty, data)
}

/// IEEE 802.2 LLC header, followed by SNAP when DSAP = SSAP = `0xaa`.
pub(crate) fn llc<'a>(d: &mut Decoded<'a>, data: &'a [u8]) -> Result<(), DecodeError> {
    let (Some(dsap), Some(ssap), Some(ctrl)) = (u8_at(data, 0), u8_at(data, 1), u8_at(data, 2))
    else {
        return Err(DecodeError::truncated(Layer::Llc, 3, data.len()));
    };
    // U-frames have a 1-byte control field, I/S-frames a 2-byte one.
    let (control, hdr_len) = if ctrl & 0x03 == 0x03 {
        (u16::from(ctrl), 3)
    } else {
        let c = be16(data, 2).ok_or(DecodeError::truncated(Layer::Llc, 4, data.len()))?;
        (c, 4)
    };
    let (_, rest) = split(data, hdr_len, Layer::Llc)?;
    let mut info = Llc {
        dsap,
        ssap,
        control,
        snap_oui: None,
    };
    if dsap == 0xaa && ssap == 0xaa && hdr_len == 3 {
        let Ok((snap, after)) = split(rest, 5, Layer::Llc) else {
            d.link.llc = Some(info);
            d.payload = rest;
            return Err(DecodeError::truncated(Layer::Llc, 8, data.len()));
        };
        let oui = crate::bytes::array::<3>(snap, 0).unwrap_or_default();
        let pid = be16(snap, 3).unwrap_or_default();
        info.snap_oui = Some(oui);
        d.link.llc = Some(info);
        d.payload = after;
        // RFC 1042 (00-00-00) and 802.1H bridge tunnel (00-00-f8) carry an EtherType.
        if oui == [0, 0, 0] || oui == [0, 0, 0xf8] {
            return ether_payload(d, pid, after, false);
        }
        return Ok(());
    }
    d.link.llc = Some(info);
    d.payload = rest;
    Ok(())
}

/// Linux cooked capture v1 (16-byte header).
fn sll<'a>(d: &mut Decoded<'a>, data: &'a [u8]) -> Result<(), DecodeError> {
    let (hdr, rest) = split(data, 16, Layer::LinuxSll)?;
    let packet_type = be16(hdr, 0).unwrap_or_default();
    let arphrd_type = be16(hdr, 2).unwrap_or_default();
    let addr_len = be16(hdr, 4).unwrap_or_default();
    let protocol = be16(hdr, 14).unwrap_or_default();
    if addr_len == 6 {
        d.link.src_mac = hdr.get(6..).and_then(MacAddr::from_slice);
    }
    d.link.sll = Some(SllInfo {
        packet_type,
        arphrd_type,
        protocol,
        if_index: None,
    });
    d.payload = rest;
    sll_payload(d, arphrd_type, protocol, rest)
}

/// Linux cooked capture v2 (20-byte header).
fn sll2<'a>(d: &mut Decoded<'a>, data: &'a [u8]) -> Result<(), DecodeError> {
    let (hdr, rest) = split(data, 20, Layer::LinuxSll)?;
    let protocol = be16(hdr, 0).unwrap_or_default();
    let if_index = be32(hdr, 4);
    let arphrd_type = be16(hdr, 8).unwrap_or_default();
    let packet_type = u8_at(hdr, 10).unwrap_or_default();
    let addr_len = u8_at(hdr, 11).unwrap_or_default();
    if addr_len == 6 {
        d.link.src_mac = hdr.get(12..).and_then(MacAddr::from_slice);
    }
    d.link.sll = Some(SllInfo {
        packet_type: u16::from(packet_type),
        arphrd_type,
        protocol,
        if_index,
    });
    d.payload = rest;
    sll_payload(d, arphrd_type, protocol, rest)
}

fn sll_payload<'a>(
    d: &mut Decoded<'a>,
    arphrd_type: u16,
    protocol: u16,
    data: &'a [u8],
) -> Result<(), DecodeError> {
    match arphrd_type {
        ARPHRD_IEEE80211_RADIOTAP => wifi::radiotap(d, data),
        ARPHRD_IEEE80211 => wifi::ieee80211(d, data, false),
        // Netlink: the protocol field is a netlink family, not an EtherType.
        ARPHRD_NETLINK => Ok(()),
        _ if protocol == SLL_PROTO_802_2 => llc(d, data),
        _ => ether_payload(d, protocol, data, false),
    }
}

/// Raw IP: version from the first nibble (`RAW`) or from the linktype (`IPV4`/`IPV6`).
fn raw<'a>(d: &mut Decoded<'a>, lt: u32, data: &'a [u8]) -> Result<(), DecodeError> {
    let version = match lt {
        linktype::IPV4 => IpVersion::V4,
        linktype::IPV6 => IpVersion::V6,
        _ => match u8_at(data, 0).map(|b| b >> 4) {
            Some(4) => IpVersion::V4,
            Some(6) => IpVersion::V6,
            Some(_) => return Err(DecodeError::malformed(Layer::Ip, "unknown IP version")),
            None => return Err(DecodeError::truncated(Layer::Ip, 1, 0)),
        },
    };
    d.link.ethertype = Some(match version {
        IpVersion::V4 => ethertype::IPV4,
        IpVersion::V6 => ethertype::IPV6,
    });
    net::decode_ip(d, data, Some(version))
}

/// Maps a BSD address family to an Ethertype (`AF_INET6` differs between BSDs).
const fn af_to_ethertype(af: u32) -> Option<u16> {
    match af {
        2 => Some(ethertype::IPV4),
        24 | 28 | 30 => Some(ethertype::IPV6),
        _ => None,
    }
}

/// `DLT_NULL` (host byte order, accepted either way) and `DLT_LOOP` (network order).
fn loopback<'a>(
    d: &mut Decoded<'a>,
    network_order: bool,
    data: &'a [u8],
) -> Result<(), DecodeError> {
    let (hdr, rest) = split(data, 4, Layer::Loopback)?;
    let be = be32(hdr, 0).and_then(af_to_ethertype);
    let le = le32(hdr, 0).and_then(af_to_ethertype);
    let ty = if network_order { be.or(le) } else { le.or(be) };
    d.payload = rest;
    let ty = ty.ok_or(DecodeError::malformed(
        Layer::Loopback,
        "unknown address family",
    ))?;
    d.link.ethertype = Some(ty);
    net::decode_ethertype(d, ty, rest)
}
