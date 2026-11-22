//! Link-layer showcase for the Ethernet view: addresses of known vendors (MA-L, MA-M, MA-S),
//! locally administered addresses, broadcast and multicast destinations, 802.1Q and Q-in-Q tags,
//! and several EtherTypes, including 802.3 frames with an LLC header (spanning tree).
//!
//! Frames are built by hand (the scenario builder only writes untagged Ethernet II), with an IPv4
//! or IPv6 UDP payload from `etherparse` when the EtherType is IP.

use std::net::Ipv6Addr;

use etherparse::PacketBuilder;

use crate::scenario::Scenario;

/// Addresses of the showcase (prefixes of real IEEE assignments, made-up device parts).
pub mod macs {
    /// MA-L `08:00:27` (PCS Systemtechnik GmbH, VirtualBox).
    pub const VBOX_A: [u8; 6] = [0x08, 0x00, 0x27, 0x09, 0xd9, 0xcb];
    /// MA-L `08:00:27`, a second VirtualBox guest.
    pub const VBOX_B: [u8; 6] = [0x08, 0x00, 0x27, 0x80, 0xf2, 0x01];
    /// MA-L `00:00:0c` (Cisco Systems): the switch that sends spanning tree and LLDP frames.
    pub const SWITCH: [u8; 6] = [0x00, 0x00, 0x0c, 0x9f, 0xf0, 0x01];
    /// MA-L `00:1b:21` (Intel Corporate).
    pub const INTEL: [u8; 6] = [0x00, 0x1b, 0x21, 0x3a, 0x4b, 0x5c];
    /// MA-L `b8:27:eb` (Raspberry Pi Foundation).
    pub const RASPBERRY: [u8; 6] = [0xb8, 0x27, 0xeb, 0x12, 0x34, 0x56];
    /// MA-M `1c:87:74:0` (Philips Personal Health Solutions).
    pub const MA_M: [u8; 6] = [0x1c, 0x87, 0x74, 0x01, 0x02, 0x03];
    /// MA-S `70:b3:d5:00:1` (SOREDI touch systems GmbH).
    pub const MA_S: [u8; 6] = [0x70, 0xb3, 0xd5, 0x00, 0x1a, 0xbc];
    /// Locally administered: QEMU user-mode networking gateway.
    pub const QEMU: [u8; 6] = [0x52, 0x55, 0x0a, 0x00, 0x02, 0x01];
    /// Locally administered and random-looking: a phone with a private address.
    pub const RANDOM: [u8; 6] = [0xda, 0xa1, 0x19, 0x3c, 0x4e, 0x7f];
    /// Broadcast.
    pub const BROADCAST: [u8; 6] = [0xff; 6];
    /// IPv4 multicast of 224.0.0.251 (mDNS).
    pub const IPV4_MDNS: [u8; 6] = [0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb];
    /// IPv6 multicast of ff02::1 (all nodes).
    pub const IPV6_ALL_NODES: [u8; 6] = [0x33, 0x33, 0x00, 0x00, 0x00, 0x01];
    /// IEEE 802.1D spanning tree (bridge group address).
    pub const STP: [u8; 6] = [0x01, 0x80, 0xc2, 0x00, 0x00, 0x00];
    /// LLDP nearest bridge.
    pub const LLDP: [u8; 6] = [0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e];
}

/// IEEE 802.1Q customer tag.
pub const TPID_8021Q: u16 = 0x8100;
/// IEEE 802.1ad service tag (outer tag of Q-in-Q).
pub const TPID_8021AD: u16 = 0x88a8;
/// LLDP EtherType.
pub const ETHERTYPE_LLDP: u16 = 0x88cc;
/// IEEE local experimental EtherType 1 (no registered protocol name).
pub const ETHERTYPE_EXPERIMENTAL: u16 = 0x88b5;

/// Ethernet frame: destination, source, VLAN tags `(tpid, vlan id)` outermost first, then the
/// EtherType (or the 802.3 length when below 0x0600) and the payload.
pub fn frame(dst: [u8; 6], src: [u8; 6], tags: &[(u16, u16)], ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(14 + 4 * tags.len() + payload.len());
    out.extend_from_slice(&dst);
    out.extend_from_slice(&src);
    for (tpid, vid) in tags {
        out.extend_from_slice(&tpid.to_be_bytes());
        out.extend_from_slice(&(vid & 0x0fff).to_be_bytes());
    }
    out.extend_from_slice(&ethertype.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// IPv4 + UDP packet (no link header).
pub fn ipv4_udp(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let b = PacketBuilder::ipv4(src, dst, 64).udp(sport, dport);
    let mut out = Vec::with_capacity(b.size(payload.len()));
    b.write(&mut out, payload).expect("valid IPv4 UDP packet");
    out
}

/// IPv6 + UDP packet (no link header).
pub fn ipv6_udp(src: Ipv6Addr, dst: Ipv6Addr, sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let b = PacketBuilder::ipv6(src.octets(), dst.octets(), 64).udp(sport, dport);
    let mut out = Vec::with_capacity(b.size(payload.len()));
    b.write(&mut out, payload).expect("valid IPv6 UDP packet");
    out
}

/// 802.3 frame with an LLC header carrying a configuration BPDU (spanning tree, DSAP 0x42).
pub fn stp_bpdu(src: [u8; 6]) -> Vec<u8> {
    let mut llc = vec![0x42, 0x42, 0x03];
    // Protocol 0, version 0, configuration BPDU, flags, root id, path cost, bridge id, port id,
    // message age, max age, hello time, forward delay (IEEE 802.1D, 9.3.1).
    llc.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00]);
    llc.extend_from_slice(&[0x80, 0x00]);
    llc.extend_from_slice(&src);
    llc.extend_from_slice(&[0, 0, 0, 0]);
    llc.extend_from_slice(&[0x80, 0x00]);
    llc.extend_from_slice(&src);
    llc.extend_from_slice(&[0x80, 0x01, 0, 0, 0x14, 0, 0x02, 0, 0x0f, 0]);
    let len = u16::try_from(llc.len()).expect("short BPDU");
    frame(macs::STP, src, &[], len, &llc)
}

/// LLDP frame: chassis id (MAC), port id, TTL and end TLVs.
pub fn lldp(src: [u8; 6]) -> Vec<u8> {
    let mut tlvs = vec![0x02, 0x07, 0x04];
    tlvs.extend_from_slice(&src);
    tlvs.extend_from_slice(&[0x04, 0x05, 0x05, b'G', b'i', b'0', b'1']);
    tlvs.extend_from_slice(&[0x06, 0x02, 0x00, 0x78]);
    tlvs.extend_from_slice(&[0x00, 0x00]);
    frame(macs::LLDP, src, &[], ETHERTYPE_LLDP, &tlvs)
}

/// One round of the showcase (14 frames): call it several times to spread it over a capture.
pub fn ethernet_showcase(sc: &mut Scenario) {
    use macs::{
        BROADCAST, INTEL, IPV4_MDNS, IPV6_ALL_NODES, MA_M, MA_S, QEMU, RANDOM, RASPBERRY, SWITCH,
        VBOX_A, VBOX_B,
    };
    let v4 = |src: [u8; 4], dst: [u8; 4], port: u16| ipv4_udp(src, dst, 40_000, port, b"netsift");
    let lan = |host: u8| [192, 168, 56, host];

    // The switch: spanning tree and LLDP.
    sc.push_frame(stp_bpdu(SWITCH));
    sc.push_frame(lldp(SWITCH));
    // Two VirtualBox guests and the QEMU gateway, untagged.
    sc.push_frame(frame(QEMU, VBOX_A, &[], 0x0800, &v4(lan(11), lan(1), 9)));
    sc.push_frame(frame(VBOX_A, QEMU, &[], 0x0800, &v4(lan(1), lan(11), 9)));
    sc.push_frame(frame(VBOX_B, VBOX_A, &[], 0x0800, &v4(lan(11), lan(12), 9)));
    sc.push_frame(frame(BROADCAST, VBOX_B, &[], 0x0800, &v4(lan(12), [255, 255, 255, 255], 9)));
    let ll = |last: u16| Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, last);
    let all_nodes = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
    sc.push_frame(frame(IPV6_ALL_NODES, VBOX_A, &[], 0x86dd, &ipv6_udp(ll(11), all_nodes, 40_000, 9, b"netsift")));
    // 802.1Q VLAN 10: an Intel host and a Raspberry Pi; mDNS to the IPv4 multicast group.
    let vlan10 = [(TPID_8021Q, 10)];
    sc.push_frame(frame(RASPBERRY, INTEL, &vlan10, 0x0800, &v4([10, 0, 10, 5], [10, 0, 10, 6], 9)));
    sc.push_frame(frame(INTEL, RASPBERRY, &vlan10, 0x0800, &v4([10, 0, 10, 6], [10, 0, 10, 5], 9)));
    sc.push_frame(frame(IPV4_MDNS, RASPBERRY, &vlan10, 0x0800, &v4([10, 0, 10, 6], [224, 0, 0, 251], 5353)));
    // Q-in-Q: service tag 100, customer tag 20, between the MA-M and MA-S devices.
    let qinq = [(TPID_8021AD, 100), (TPID_8021Q, 20)];
    sc.push_frame(frame(MA_S, MA_M, &qinq, 0x0800, &v4([10, 20, 0, 2], [10, 20, 0, 3], 9)));
    sc.push_frame(frame(MA_M, MA_S, &qinq, 0x0800, &v4([10, 20, 0, 3], [10, 20, 0, 2], 9)));
    // A phone with a random address, and a frame of an experimental EtherType.
    sc.push_frame(frame(QEMU, RANDOM, &[], 0x0800, &v4(lan(40), lan(1), 9)));
    sc.push_frame(frame(BROADCAST, INTEL, &vlan10, ETHERTYPE_EXPERIMENTAL, b"netsift experimental"));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn showcase_is_deterministic_and_tagged() {
        let mut a = Scenario::starting_at(0);
        ethernet_showcase(&mut a);
        let mut b = Scenario::starting_at(0);
        ethernet_showcase(&mut b);
        assert_eq!(a.packets(), b.packets());
        assert_eq!(a.len(), 14);
        // Q-in-Q frames carry the service tag first, then the customer tag.
        let qinq = a
            .packets()
            .iter()
            .find(|p| p.data.get(12..14) == Some(&TPID_8021AD.to_be_bytes()[..]))
            .unwrap();
        assert_eq!(&qinq.data[14..18], &[0x00, 100, 0x81, 0x00]);
        assert_eq!(&qinq.data[18..20], &[0x00, 20]);
    }

    #[test]
    fn bpdu_uses_an_8023_length() {
        let f = stp_bpdu(macs::SWITCH);
        let len = u16::from_be_bytes([f[12], f[13]]);
        assert_eq!(usize::from(len), f.len() - 14);
        assert_eq!(&f[14..17], &[0x42, 0x42, 0x03]);
    }
}
