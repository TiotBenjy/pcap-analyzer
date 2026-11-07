//! Hand-crafted frames for the flow layer: TCP segments with arbitrary sequence numbers and
//! flags, UDP and ICMP echo datagrams, and IP fragments (IPv4 and IPv6) with arbitrary offsets,
//! overlaps and duplicates.
//!
//! Unlike [`crate::scenario`], nothing here keeps a clock or a coherent conversation: callers
//! choose every field, which is what out-of-order, retransmission, loss and wraparound tests
//! need. [`TcpConv`] adds a thin layer that maps stream offsets to sequence numbers.
//!
//! ```
//! use netsift_fixtures::craft::{FragSpec, fragment_frames, ip_payload, udp_frame};
//! use netsift_fixtures::scenarios::hosts;
//!
//! let frame = udp_frame(&hosts::workstation(), &hosts::router(), 5000, 53, &[7u8; 100]);
//! let payload = ip_payload(&frame).unwrap().to_vec(); // UDP header + data, 108 bytes
//! let frags = fragment_frames(&frame, 42, &FragSpec::even(&payload, 64));
//! assert_eq!(frags.len(), 2);
//! ```

use std::net::IpAddr;

use etherparse::PacketBuilder;

use crate::packet::{Host, LINKTYPE_ETHERNET, Packet};

/// Hop limit / TTL of crafted frames.
pub const TTL: u8 = 64;
/// Receive window of crafted TCP segments.
pub const WINDOW: u16 = 64_240;

const ETH_LEN: usize = 14;
const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86dd;
const IPV6_HEADER_LEN: usize = 40;
const IPV6_FRAGMENT_HEADER: u8 = 44;

/// TCP header fields of a crafted segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[allow(clippy::struct_excessive_bools)] // mirrors the TCP flag bits
pub struct TcpSeg {
    pub seq: u32,
    /// Acknowledgment number; `Some` sets the ACK flag.
    pub ack: Option<u32>,
    pub syn: bool,
    pub fin: bool,
    pub rst: bool,
    pub psh: bool,
}

impl TcpSeg {
    /// Segment without any flag.
    pub fn new(seq: u32) -> Self {
        Self {
            seq,
            ..Self::default()
        }
    }

    /// Sets the ACK flag and number.
    #[must_use]
    pub fn ack(mut self, ack: u32) -> Self {
        self.ack = Some(ack);
        self
    }

    #[must_use]
    pub fn syn(mut self) -> Self {
        self.syn = true;
        self
    }

    #[must_use]
    pub fn fin(mut self) -> Self {
        self.fin = true;
        self
    }

    #[must_use]
    pub fn rst(mut self) -> Self {
        self.rst = true;
        self
    }

    #[must_use]
    pub fn psh(mut self) -> Self {
        self.psh = true;
        self
    }
}

fn ip_builder(src: &Host, dst: &Host) -> etherparse::PacketBuilderStep<etherparse::IpHeaders> {
    let eth = PacketBuilder::ethernet2(src.mac, dst.mac);
    match (src.ip, dst.ip) {
        (IpAddr::V4(s), IpAddr::V4(d)) => eth.ipv4(s.octets(), d.octets(), TTL),
        (IpAddr::V6(s), IpAddr::V6(d)) => eth.ipv6(s.octets(), d.octets(), TTL),
        _ => panic!("source and destination must use the same IP version"),
    }
}

/// Ethernet + IP + TCP frame with valid checksums.
pub fn tcp_frame(
    src: &Host,
    dst: &Host,
    sport: u16,
    dport: u16,
    seg: &TcpSeg,
    payload: &[u8],
) -> Vec<u8> {
    let mut b = ip_builder(src, dst).tcp(sport, dport, seg.seq, WINDOW);
    if seg.syn {
        b = b.syn();
    }
    if let Some(ack) = seg.ack {
        b = b.ack(ack);
    }
    if seg.psh {
        b = b.psh();
    }
    if seg.fin {
        b = b.fin();
    }
    if seg.rst {
        b = b.rst();
    }
    let mut out = Vec::with_capacity(b.size(payload.len()));
    b.write(&mut out, payload).expect("valid TCP frame");
    out
}

/// Ethernet + IP + UDP frame with valid checksums.
pub fn udp_frame(src: &Host, dst: &Host, sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let b = ip_builder(src, dst).udp(sport, dport);
    let mut out = Vec::with_capacity(b.size(payload.len()));
    b.write(&mut out, payload).expect("valid UDP frame");
    out
}

/// Ethernet + IP + ICMP (IPv4) or `ICMPv6` (IPv6) echo request or reply.
pub fn icmp_echo_frame(
    src: &Host,
    dst: &Host,
    id: u16,
    seq: u16,
    reply: bool,
    payload: &[u8],
) -> Vec<u8> {
    let ip = ip_builder(src, dst);
    let mut out = Vec::new();
    match (src.ip, reply) {
        (IpAddr::V4(_), false) => ip.icmpv4_echo_request(id, seq).write(&mut out, payload),
        (IpAddr::V4(_), true) => ip.icmpv4_echo_reply(id, seq).write(&mut out, payload),
        (IpAddr::V6(_), false) => ip.icmpv6_echo_request(id, seq).write(&mut out, payload),
        (IpAddr::V6(_), true) => ip.icmpv6_echo_reply(id, seq).write(&mut out, payload),
    }
    .expect("valid ICMP frame");
    out
}

/// Ethernet frame on interface 0 at `ts_ns`.
pub fn packet(ts_ns: i64, data: Vec<u8>) -> Packet {
    Packet {
        ts_ns,
        linktype: LINKTYPE_ETHERNET,
        interface: 0,
        data,
    }
}

/// Internet checksum (RFC 1071) of `data`, as stored in a header.
pub fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for pair in data.chunks(2) {
        let word = match *pair {
            [hi, lo] => u16::from_be_bytes([hi, lo]),
            [hi] => u16::from_be_bytes([hi, 0]),
            _ => 0,
        };
        sum += u32::from(word);
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !u16::try_from(sum).unwrap_or(u16::MAX)
}

fn ethertype(frame: &[u8]) -> Option<u16> {
    Some(u16::from_be_bytes(frame.get(12..14)?.try_into().ok()?))
}

fn ipv4_header_len(frame: &[u8]) -> Option<usize> {
    if ethertype(frame)? != ETHERTYPE_IPV4 {
        return None;
    }
    Some(usize::from(frame.get(ETH_LEN)? & 0x0f) * 4)
}

/// Sets the identification field of an Ethernet + IPv4 frame and fixes the header checksum.
/// Returns `false` (frame untouched) for any other frame.
pub fn set_ipv4_ident(frame: &mut [u8], ident: u16) -> bool {
    let Some(ihl) = ipv4_header_len(frame) else {
        return false;
    };
    let Some(header) = frame.get_mut(ETH_LEN..ETH_LEN + ihl) else {
        return false;
    };
    header[4..6].copy_from_slice(&ident.to_be_bytes());
    header[10..12].fill(0);
    let sum = internet_checksum(header);
    header[10..12].copy_from_slice(&sum.to_be_bytes());
    true
}

/// IP payload of an Ethernet + IPv4 / IPv6 frame built by this crate (no IPv6 extension
/// header): the bytes after the IPv4 header or the IPv6 fixed header, i.e. the transport
/// header and its data. This is what [`fragment_frames`] cuts into fragments.
pub fn ip_payload(frame: &[u8]) -> Option<&[u8]> {
    match ethertype(frame)? {
        ETHERTYPE_IPV4 => {
            let ihl = ipv4_header_len(frame)?;
            let total = usize::from(u16::from_be_bytes(
                frame.get(ETH_LEN + 2..ETH_LEN + 4)?.try_into().ok()?,
            ));
            frame.get(ETH_LEN + ihl..ETH_LEN + total)
        }
        ETHERTYPE_IPV6 => {
            let len = usize::from(u16::from_be_bytes(
                frame.get(ETH_LEN + 4..ETH_LEN + 6)?.try_into().ok()?,
            ));
            let start = ETH_LEN + IPV6_HEADER_LEN;
            frame.get(start..start + len)
        }
        _ => None,
    }
}

/// One fragment to build: `data` placed at byte `offset` of the fragmentable part.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FragSpec {
    /// Offset in bytes; must be a multiple of 8 (the header field counts 8-byte units).
    pub offset: u16,
    /// More-fragments flag.
    pub more: bool,
    pub data: Vec<u8>,
}

impl FragSpec {
    pub fn new(offset: u16, more: bool, data: impl Into<Vec<u8>>) -> Self {
        Self {
            offset,
            more,
            data: data.into(),
        }
    }

    /// Fragment carrying `payload[range]` (offset = range start); `more` is set unless the
    /// range reaches the end of `payload`.
    pub fn slice(payload: &[u8], range: std::ops::Range<usize>) -> Self {
        let more = range.end < payload.len();
        let offset = u16::try_from(range.start).expect("offset fits in 16 bits");
        Self::new(offset, more, &payload[range])
    }

    /// Consecutive fragments of `size` bytes (rounded down to a multiple of 8, at least 8),
    /// in order, the last one shorter and without the more-fragments flag.
    pub fn even(payload: &[u8], size: usize) -> Vec<Self> {
        let size = (size / 8 * 8).max(8);
        (0..payload.len())
            .step_by(size)
            .map(|start| Self::slice(payload, start..(start + size).min(payload.len())))
            .collect()
    }
}

/// Builds one Ethernet frame per spec from an unfragmented Ethernet + IPv4 / IPv6 `frame`
/// (as built by this crate): same link and IP header, with the fragment fields set
/// (IPv4: flags, offset, identification = low 16 bits of `ident`, total length, checksum;
/// IPv6: a Fragment header inserted after the fixed header). Specs may overlap, repeat or
/// leave holes: nothing is checked, which is the point.
pub fn fragment_frames(frame: &[u8], ident: u32, specs: &[FragSpec]) -> Vec<Vec<u8>> {
    specs
        .iter()
        .map(|spec| fragment_frame(frame, ident, spec))
        .collect()
}

fn fragment_frame(frame: &[u8], ident: u32, spec: &FragSpec) -> Vec<u8> {
    assert!(
        spec.offset.is_multiple_of(8),
        "fragment offsets are counted in 8-byte units"
    );
    match ethertype(frame) {
        Some(ETHERTYPE_IPV4) => {
            let ihl = ipv4_header_len(frame).expect("IPv4 header");
            let mut out = frame[..ETH_LEN + ihl].to_vec();
            let total = u16::try_from(ihl + spec.data.len()).expect("fragment fits in 64 KiB");
            let flags_offset = (spec.offset / 8) | if spec.more { 0x2000 } else { 0 };
            let header = &mut out[ETH_LEN..];
            header[2..4].copy_from_slice(&total.to_be_bytes());
            header[6..8].copy_from_slice(&flags_offset.to_be_bytes());
            out.extend_from_slice(&spec.data);
            let ident = u16::try_from(ident & 0xffff).unwrap_or_default();
            assert!(set_ipv4_ident(&mut out, ident));
            out
        }
        Some(ETHERTYPE_IPV6) => {
            let mut out = frame[..ETH_LEN + IPV6_HEADER_LEN].to_vec();
            let next_header = out[ETH_LEN + 6];
            let len = u16::try_from(8 + spec.data.len()).expect("fragment fits in 64 KiB");
            out[ETH_LEN + 4..ETH_LEN + 6].copy_from_slice(&len.to_be_bytes());
            out[ETH_LEN + 6] = IPV6_FRAGMENT_HEADER;
            let offset_flags = spec.offset | u16::from(spec.more);
            out.extend_from_slice(&[next_header, 0]);
            out.extend_from_slice(&offset_flags.to_be_bytes());
            out.extend_from_slice(&ident.to_be_bytes());
            out.extend_from_slice(&spec.data);
            out
        }
        _ => panic!("fragment_frames needs an Ethernet + IPv4 / IPv6 frame"),
    }
}

/// Which side sends a [`TcpConv`] segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Client,
    Server,
}

/// TCP conversation helper: maps stream offsets to sequence numbers so that tests can emit
/// any segment (out of order, overlapping, retransmitted, lost) of a connection.
///
/// Stream offset 0 is the first data byte of a side, i.e. sequence number `isn + 1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpConv {
    pub client: Host,
    pub server: Host,
    pub cport: u16,
    pub sport: u16,
    pub client_isn: u32,
    pub server_isn: u32,
}

impl TcpConv {
    pub fn new(client: Host, server: Host, cport: u16, sport: u16) -> Self {
        Self {
            client,
            server,
            cport,
            sport,
            client_isn: 1_000,
            server_isn: 5_000_000,
        }
    }

    /// Sets both initial sequence numbers (to test wraparound, pick values near `u32::MAX`).
    #[must_use]
    pub fn with_isns(mut self, client_isn: u32, server_isn: u32) -> Self {
        self.client_isn = client_isn;
        self.server_isn = server_isn;
        self
    }

    fn isn(&self, side: Side) -> u32 {
        match side {
            Side::Client => self.client_isn,
            Side::Server => self.server_isn,
        }
    }

    /// Sequence number of stream byte `offset` sent by `side`.
    pub fn seq(&self, side: Side, offset: u64) -> u32 {
        let low = u32::try_from(offset & 0xffff_ffff).unwrap_or_default();
        self.isn(side).wrapping_add(1).wrapping_add(low)
    }

    /// Frame sent by `side` with the given header (addresses and ports filled in).
    pub fn frame(&self, side: Side, seg: &TcpSeg, payload: &[u8]) -> Vec<u8> {
        match side {
            Side::Client => tcp_frame(
                &self.client,
                &self.server,
                self.cport,
                self.sport,
                seg,
                payload,
            ),
            Side::Server => tcp_frame(
                &self.server,
                &self.client,
                self.sport,
                self.cport,
                seg,
                payload,
            ),
        }
    }

    /// Client SYN.
    pub fn syn(&self) -> Vec<u8> {
        self.frame(Side::Client, &TcpSeg::new(self.client_isn).syn(), &[])
    }

    /// Server SYN-ACK.
    pub fn syn_ack(&self) -> Vec<u8> {
        let seg = TcpSeg::new(self.server_isn)
            .syn()
            .ack(self.seq(Side::Client, 0));
        self.frame(Side::Server, &seg, &[])
    }

    /// Data from `side` at stream `offset`, acknowledging `peer_offset` bytes of the peer.
    pub fn data(&self, side: Side, offset: u64, peer_offset: u64, payload: &[u8]) -> Vec<u8> {
        let peer = match side {
            Side::Client => Side::Server,
            Side::Server => Side::Client,
        };
        let seg = TcpSeg::new(self.seq(side, offset))
            .ack(self.seq(peer, peer_offset))
            .psh();
        self.frame(side, &seg, payload)
    }

    /// Pure ACK from `side` at stream `offset`, acknowledging `peer_offset`.
    pub fn ack(&self, side: Side, offset: u64, peer_offset: u64) -> Vec<u8> {
        let peer = match side {
            Side::Client => Side::Server,
            Side::Server => Side::Client,
        };
        let seg = TcpSeg::new(self.seq(side, offset)).ack(self.seq(peer, peer_offset));
        self.frame(side, &seg, &[])
    }

    /// FIN (with ACK) from `side` after `offset` data bytes.
    pub fn fin(&self, side: Side, offset: u64, peer_offset: u64) -> Vec<u8> {
        let peer = match side {
            Side::Client => Side::Server,
            Side::Server => Side::Client,
        };
        let seg = TcpSeg::new(self.seq(side, offset))
            .ack(self.seq(peer, peer_offset))
            .fin();
        self.frame(side, &seg, &[])
    }

    /// RST from `side` at stream `offset`.
    pub fn rst(&self, side: Side, offset: u64) -> Vec<u8> {
        self.frame(side, &TcpSeg::new(self.seq(side, offset)).rst(), &[])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scenarios::hosts;

    #[test]
    fn checksum_of_reference_header() {
        // RFC 1071 example words 0x0001 0xf203 0xf4f5 0xf6f7: sum 0xddf2, checksum 0x220d.
        assert_eq!(
            internet_checksum(&[0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7]),
            0x220d
        );
    }

    #[test]
    fn ipv4_fragments_carry_offsets_and_flags() {
        let payload: Vec<u8> = (0..100u8).collect();
        let frame = udp_frame(&hosts::workstation(), &hosts::router(), 1, 2, &payload);
        let body = ip_payload(&frame).unwrap().to_vec();
        assert_eq!(body.len(), 108);
        let frags = fragment_frames(&frame, 0x1234, &FragSpec::even(&body, 48));
        assert_eq!(frags.len(), 3);
        let mut rebuilt = Vec::new();
        for (i, f) in frags.iter().enumerate() {
            let ip = &f[14..34];
            assert_eq!(&ip[4..6], &[0x12, 0x34]);
            let flags_offset = u16::from_be_bytes([ip[6], ip[7]]);
            assert_eq!(usize::from(flags_offset & 0x1fff) * 8, i * 48);
            assert_eq!(flags_offset & 0x2000 != 0, i < 2);
            assert_eq!(internet_checksum(ip), 0);
            rebuilt.extend_from_slice(ip_payload(f).unwrap());
        }
        assert_eq!(rebuilt, body);
    }

    #[test]
    fn ipv6_fragments_insert_a_fragment_header() {
        let frame = udp_frame(
            &hosts::workstation_v6(),
            &hosts::router_v6(),
            1,
            2,
            &[9u8; 60],
        );
        let body = ip_payload(&frame).unwrap().to_vec();
        let frags = fragment_frames(&frame, 0xdead_beef, &FragSpec::even(&body, 40));
        assert_eq!(frags.len(), 2);
        let f = &frags[1];
        assert_eq!(f[14 + 6], 44);
        let ext = &f[54..62];
        assert_eq!(ext[0], 17);
        assert_eq!(u16::from_be_bytes([ext[2], ext[3]]), 40);
        assert_eq!(&ext[4..8], &0xdead_beef_u32.to_be_bytes());
        assert_eq!(&f[62..], &body[40..]);
    }

    #[test]
    fn conv_sequence_numbers_wrap() {
        let c = TcpConv::new(hosts::workstation(), hosts::web_server(), 40_000, 80)
            .with_isns(u32::MAX - 1, 7);
        assert_eq!(c.seq(Side::Client, 0), u32::MAX);
        assert_eq!(c.seq(Side::Client, 1), 0);
        assert_eq!(c.seq(Side::Server, 0), 8);
    }
}
