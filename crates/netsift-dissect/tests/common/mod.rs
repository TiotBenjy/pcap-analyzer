//! Hand-made frame builders shared by the integration tests (synthetic data only).
#![allow(dead_code)]

use etherparse::PacketBuilder;

pub const MAC_A: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x0a];
pub const MAC_B: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x0b];
pub const MAC_C: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x0c];
pub const MAC_D: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x0d];
pub const IP4_A: [u8; 4] = [192, 168, 1, 10];
pub const IP4_B: [u8; 4] = [198, 51, 100, 7];
pub const IP6_A: [u8; 16] = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
pub const IP6_B: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

pub const DNS_QUERY: &[u8] = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00";

/// IPv4 + UDP 5353 -> 53 carrying `payload` (no link header).
pub fn udp4(payload: &[u8]) -> Vec<u8> {
    let b = PacketBuilder::ipv4(IP4_A, IP4_B, 64).udp(5353, 53);
    let mut v = Vec::new();
    b.write(&mut v, payload).unwrap();
    v
}

/// IPv4 + TCP SYN 40000 -> 80 carrying `payload`.
pub fn tcp4(payload: &[u8]) -> Vec<u8> {
    let b = PacketBuilder::ipv4(IP4_A, IP4_B, 64)
        .tcp(40000, 80, 1000, 64240)
        .syn();
    let mut v = Vec::new();
    b.write(&mut v, payload).unwrap();
    v
}

/// IPv6 + TCP PSH|ACK 443 -> 51000 carrying `payload`.
pub fn tcp6(payload: &[u8]) -> Vec<u8> {
    let b = PacketBuilder::ipv6(IP6_B, IP6_A, 57)
        .tcp(443, 51000, 7, 501)
        .psh()
        .ack(99);
    let mut v = Vec::new();
    b.write(&mut v, payload).unwrap();
    v
}

/// IPv6 + UDP 546 -> 547 carrying `payload`.
pub fn udp6(payload: &[u8]) -> Vec<u8> {
    let b = PacketBuilder::ipv6(IP6_A, IP6_B, 1).udp(546, 547);
    let mut v = Vec::new();
    b.write(&mut v, payload).unwrap();
    v
}

/// Ethernet II header + body.
pub fn eth(dst: [u8; 6], src: [u8; 6], ty: u16, body: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&dst);
    v.extend_from_slice(&src);
    v.extend_from_slice(&ty.to_be_bytes());
    v.extend_from_slice(body);
    v
}

/// One VLAN tag body (TCI + next type) to append after a TPID.
pub fn vlan(pcp: u8, id: u16, next: u16) -> Vec<u8> {
    let tci = (u16::from(pcp) << 13) | (id & 0x0fff);
    let mut v = tci.to_be_bytes().to_vec();
    v.extend_from_slice(&next.to_be_bytes());
    v
}

/// LLC/SNAP (RFC 1042) header carrying `ethertype`, followed by `body`.
pub fn snap(ethertype: u16, body: &[u8]) -> Vec<u8> {
    let mut v = vec![0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00];
    v.extend_from_slice(&ethertype.to_be_bytes());
    v.extend_from_slice(body);
    v
}

/// Linux cooked v1 header + body.
pub fn sll(packet_type: u16, arphrd: u16, addr: &[u8], protocol: u16, body: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&packet_type.to_be_bytes());
    v.extend_from_slice(&arphrd.to_be_bytes());
    v.extend_from_slice(&u16::try_from(addr.len()).unwrap().to_be_bytes());
    let mut a = [0u8; 8];
    a[..addr.len()].copy_from_slice(addr);
    v.extend_from_slice(&a);
    v.extend_from_slice(&protocol.to_be_bytes());
    v.extend_from_slice(body);
    v
}

/// Linux cooked v2 header + body.
pub fn sll2(
    protocol: u16,
    if_index: u32,
    arphrd: u16,
    packet_type: u8,
    addr: &[u8],
    body: &[u8],
) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&protocol.to_be_bytes());
    v.extend_from_slice(&[0, 0]);
    v.extend_from_slice(&if_index.to_be_bytes());
    v.extend_from_slice(&arphrd.to_be_bytes());
    v.push(packet_type);
    v.push(u8::try_from(addr.len()).unwrap());
    let mut a = [0u8; 8];
    a[..addr.len()].copy_from_slice(addr);
    v.extend_from_slice(&a);
    v.extend_from_slice(body);
    v
}

/// Radiotap header: version 0, `present` bitmap word(s) and pre-aligned `fields`.
pub fn radiotap(present: &[u32], fields: &[u8], frame: &[u8]) -> Vec<u8> {
    let len = 4 + 4 * present.len() + fields.len();
    let mut v = vec![0u8, 0u8];
    v.extend_from_slice(&u16::try_from(len).unwrap().to_le_bytes());
    for p in present {
        v.extend_from_slice(&p.to_le_bytes());
    }
    v.extend_from_slice(fields);
    v.extend_from_slice(frame);
    v
}

/// 802.11 frame control bytes.
pub fn fc(frame_type: u8, subtype: u8, flags: u8) -> [u8; 2] {
    [(subtype << 4) | (frame_type << 2), flags]
}

/// 802.11 management/data header (24 bytes, or 30 with `addr4`), optional `QoS` field,
/// followed by `body`.
pub fn wifi(
    fc: [u8; 2],
    addrs: [[u8; 6]; 3],
    addr4: Option<[u8; 6]>,
    seq: u16,
    qos: Option<u16>,
    body: &[u8],
) -> Vec<u8> {
    let mut v = fc.to_vec();
    v.extend_from_slice(&[0x2c, 0x00]); // duration
    for a in addrs {
        v.extend_from_slice(&a);
    }
    v.extend_from_slice(&(seq << 4).to_le_bytes());
    if let Some(a) = addr4 {
        v.extend_from_slice(&a);
    }
    if let Some(q) = qos {
        v.extend_from_slice(&q.to_le_bytes());
    }
    v.extend_from_slice(body);
    v
}

/// Manual IPv4 header (checksum left at 0: the decoder does not verify it).
pub fn ipv4_hdr(proto: u8, total_len: u16, id: u16, flags_frag: u16, body: &[u8]) -> Vec<u8> {
    let mut v = vec![0x45, 0x00];
    v.extend_from_slice(&total_len.to_be_bytes());
    v.extend_from_slice(&id.to_be_bytes());
    v.extend_from_slice(&flags_frag.to_be_bytes());
    v.extend_from_slice(&[64, proto, 0, 0]);
    v.extend_from_slice(&IP4_A);
    v.extend_from_slice(&IP4_B);
    v.extend_from_slice(body);
    v
}

/// Manual IPv6 header followed by `body` (payload length computed).
pub fn ipv6_hdr(next: u8, body: &[u8]) -> Vec<u8> {
    let mut v = vec![0x60, 0, 0, 0];
    v.extend_from_slice(&u16::try_from(body.len()).unwrap().to_be_bytes());
    v.extend_from_slice(&[next, 64]);
    v.extend_from_slice(&IP6_A);
    v.extend_from_slice(&IP6_B);
    v.extend_from_slice(body);
    v
}

/// Generic 8-byte IPv6 extension header (hop-by-hop, routing, destination options).
pub fn ext8(next: u8) -> Vec<u8> {
    vec![next, 0, 0, 0, 0, 0, 0, 0]
}

/// IPv6 fragment header.
pub fn frag6(next: u8, offset_bytes: u16, more: bool, id: u32) -> Vec<u8> {
    let mut v = vec![next, 0];
    v.extend_from_slice(&((offset_bytes / 8) << 3 | u16::from(more)).to_be_bytes());
    v.extend_from_slice(&id.to_be_bytes());
    v
}

/// Manual UDP header + payload (checksum 0).
pub fn udp_hdr(sp: u16, dp: u16, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&sp.to_be_bytes());
    v.extend_from_slice(&dp.to_be_bytes());
    v.extend_from_slice(&u16::try_from(payload.len() + 8).unwrap().to_be_bytes());
    v.extend_from_slice(&[0, 0]);
    v.extend_from_slice(payload);
    v
}

/// `true` if `inner` lies within `outer` (zero-copy check).
pub fn is_subslice(outer: &[u8], inner: &[u8]) -> bool {
    let o = outer.as_ptr_range();
    let i = inner.as_ptr_range();
    inner.is_empty() || (o.start <= i.start && i.end <= o.end)
}
