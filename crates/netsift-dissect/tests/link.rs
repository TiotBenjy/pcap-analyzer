//! Link-layer decoding: one test group per supported linktype.

mod common;

use std::net::{IpAddr, Ipv4Addr};

use common::*;
use etherparse::{PacketBuilder, VlanId};
use netsift_dissect::{
    DecodeError, ErrorKind, Layer, LinkKind, MacAddr, Network, Transport, WifiFrameType, decode,
    ethertype, linktype,
};

const B4: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));

// ---------------------------------------------------------------- Ethernet

#[test]
fn ethernet_ipv4_udp() {
    let b = PacketBuilder::ethernet2(MAC_A, MAC_B)
        .ipv4(IP4_A, IP4_B, 64)
        .udp(5353, 53);
    let mut f = Vec::new();
    b.write(&mut f, DNS_QUERY).unwrap();
    let d = decode(linktype::ETHERNET, &f);
    assert_eq!(d.error, None);
    assert_eq!(d.link.kind, LinkKind::Ethernet);
    assert_eq!(d.link.src_mac, Some(MacAddr(MAC_A)));
    assert_eq!(d.link.dst_mac, Some(MacAddr(MAC_B)));
    assert_eq!(d.ports(), Some((5353, 53)));
    assert_eq!(d.payload, DNS_QUERY);
    assert!(is_subslice(&f, d.payload));
    insta::assert_debug_snapshot!("ethernet_ipv4_udp", d);
}

#[test]
fn ethernet_tcp_syn() {
    let f = eth(MAC_B, MAC_A, ethertype::IPV4, &tcp4(&[]));
    let d = decode(linktype::ETHERNET, &f);
    let tcp = d.tcp().unwrap();
    assert!(tcp.flags.syn() && !tcp.flags.ack());
    assert_eq!((tcp.seq, tcp.window, tcp.header_len), (1000, 64240, 20));
    assert_eq!(d.ip().unwrap().dst, B4);
    insta::assert_debug_snapshot!("ethernet_tcp_syn", d);
}

#[test]
fn ethernet_padding_is_trimmed() {
    // 20 (IP) + 8 (UDP) + 2 bytes payload = 30 < 46: the frame is padded to 60 bytes.
    let mut f = eth(MAC_B, MAC_A, ethertype::IPV4, &udp4(b"hi"));
    f.resize(60, 0);
    let d = decode(linktype::ETHERNET, &f);
    assert_eq!(d.error, None);
    assert_eq!(d.payload, b"hi");
    assert!(!d.ip().unwrap().truncated);
}

#[test]
fn ethernet_unknown_ethertype_keeps_link_payload() {
    let f = eth(MAC_B, MAC_A, 0x88cc, b"lldp-tlvs"); // LLDP
    let d = decode(linktype::ETHERNET, &f);
    assert_eq!(d.error, None);
    assert_eq!(d.link.ethertype, Some(0x88cc));
    assert!(d.network.is_none());
    assert_eq!(d.payload, b"lldp-tlvs");
}

#[test]
fn ethernet_single_vlan() {
    let b = PacketBuilder::ethernet2(MAC_A, MAC_B)
        .single_vlan(VlanId::try_new(42).unwrap())
        .ipv4(IP4_A, IP4_B, 64)
        .udp(5353, 53);
    let mut f = Vec::new();
    b.write(&mut f, DNS_QUERY).unwrap();
    let d = decode(linktype::ETHERNET, &f);
    assert_eq!(d.error, None);
    let tags = d.link.vlans.as_slice();
    assert_eq!(tags.len(), 1);
    assert_eq!((tags[0].tpid, tags[0].id), (ethertype::VLAN, 42));
    assert_eq!(d.link.ethertype, Some(ethertype::IPV4));
    assert_eq!(d.payload, DNS_QUERY);
}

#[test]
fn ethernet_double_vlan_builder() {
    let b = PacketBuilder::ethernet2(MAC_A, MAC_B)
        .double_vlan(VlanId::try_new(100).unwrap(), VlanId::try_new(200).unwrap())
        .ipv6(IP6_A, IP6_B, 64)
        .udp(546, 547);
    let mut f = Vec::new();
    b.write(&mut f, b"dhcp6").unwrap();
    let d = decode(linktype::ETHERNET, &f);
    assert_eq!(d.error, None);
    let ids: Vec<u16> = d.link.vlans.as_slice().iter().map(|t| t.id).collect();
    assert_eq!(ids, [100, 200]);
    assert_eq!(d.link.vlans.inner_id(), Some(200));
    assert_eq!(d.payload, b"dhcp6");
}

#[test]
fn ethernet_qinq_three_tags() {
    // 802.1ad outer, pre-standard 0x9100 middle, 802.1Q inner.
    let mut body = vlan(5, 10, 0x9100);
    body.extend(vlan(0, 20, ethertype::VLAN));
    body.extend(vlan(3, 30, ethertype::IPV4));
    body.extend(udp4(DNS_QUERY));
    let f = eth(MAC_B, MAC_A, ethertype::QINQ, &body);
    let d = decode(linktype::ETHERNET, &f);
    assert_eq!(d.error, None);
    assert_eq!(d.link.vlans.len(), 3);
    assert_eq!(d.payload, DNS_QUERY);
    insta::assert_debug_snapshot!("ethernet_qinq_three_tags", d.link.vlans);
}

#[test]
fn ethernet_too_many_vlan_tags() {
    let mut body = Vec::new();
    for id in 1..=5 {
        body.extend(vlan(0, id, ethertype::VLAN));
    }
    body.extend(vlan(0, 6, ethertype::IPV4));
    body.extend(udp4(b""));
    let f = eth(MAC_B, MAC_A, ethertype::VLAN, &body);
    let d = decode(linktype::ETHERNET, &f);
    assert_eq!(d.link.vlans.len(), netsift_dissect::MAX_VLAN_TAGS);
    assert_eq!(d.error.unwrap().layer, Layer::Vlan);
    assert!(d.network.is_none());
}

#[test]
fn ethernet_8023_llc_stp() {
    // 802.3 length 7 + STP-like LLC (DSAP/SSAP 0x42, UI) + 4 bytes, padded to 60.
    let body = [0x42, 0x42, 0x03, 0x00, 0x00, 0x00, 0x00];
    let mut f = eth(MAC_B, MAC_A, 7, &body);
    f.resize(60, 0);
    let d = decode(linktype::ETHERNET, &f);
    assert_eq!(d.error, None);
    let llc = d.link.llc.unwrap();
    assert_eq!(
        (llc.dsap, llc.ssap, llc.control, llc.snap_oui),
        (0x42, 0x42, 0x03, None)
    );
    assert_eq!(d.link.ethertype, None);
    assert_eq!(d.payload, &[0, 0, 0, 0]);
}

#[test]
fn ethernet_8023_snap_ipv4() {
    let body = snap(ethertype::IPV4, &udp4(DNS_QUERY));
    let f = eth(MAC_B, MAC_A, u16::try_from(body.len()).unwrap(), &body);
    let d = decode(linktype::ETHERNET, &f);
    assert_eq!(d.error, None);
    assert_eq!(d.link.llc.unwrap().snap_oui, Some([0, 0, 0]));
    assert_eq!(d.link.ethertype, Some(ethertype::IPV4));
    assert_eq!(d.payload, DNS_QUERY);
}

#[test]
fn ethernet_invalid_type_length() {
    let f = eth(MAC_B, MAC_A, 0x05ff, &[0; 10]);
    let d = decode(linktype::ETHERNET, &f);
    assert_eq!(d.error.unwrap().layer, Layer::Ethernet);
    assert_eq!(d.link.src_mac, Some(MacAddr(MAC_A)));
}

#[test]
fn ethernet_arp_request() {
    let arp = etherparse::ArpPacket::new(
        etherparse::ArpHardwareId::ETHERNET,
        etherparse::EtherType::IPV4,
        etherparse::ArpOperation::REQUEST,
        &MAC_A,
        &IP4_A,
        &[0; 6],
        &IP4_B,
    )
    .unwrap();
    let b = PacketBuilder::ethernet2(MAC_A, [0xff; 6]).arp(arp);
    let mut f = Vec::new();
    b.write(&mut f).unwrap();
    f.resize(60, 0);
    let d = decode(linktype::ETHERNET, &f);
    assert_eq!(d.error, None);
    assert_eq!(d.link.dst_mac, Some(MacAddr::BROADCAST));
    let Some(Network::Arp(arp)) = d.network else {
        panic!("no ARP")
    };
    assert_eq!(arp.operation, 1);
    assert_eq!(arp.target_ip, Some(B4));
    insta::assert_debug_snapshot!("ethernet_arp_request", d);
}

// ---------------------------------------------------------------- Linux SLL / SLL2

#[test]
fn sll_ipv4_udp() {
    let f = sll(4, 1, &MAC_A, ethertype::IPV4, &udp4(DNS_QUERY));
    let d = decode(linktype::LINUX_SLL, &f);
    assert_eq!(d.error, None);
    assert_eq!(d.link.kind, LinkKind::LinuxSll);
    assert_eq!(d.link.src_mac, Some(MacAddr(MAC_A)));
    assert_eq!(d.link.dst_mac, None);
    assert_eq!(d.payload, DNS_QUERY);
    insta::assert_debug_snapshot!("sll_ipv4_udp", d);
}

#[test]
fn sll_with_vlan() {
    let mut body = vlan(0, 7, ethertype::IPV4);
    body.extend(udp4(DNS_QUERY));
    let f = sll(0, 1, &MAC_A, ethertype::VLAN, &body);
    let d = decode(linktype::LINUX_SLL, &f);
    assert_eq!(d.error, None);
    assert_eq!(d.link.vlans.inner_id(), Some(7));
    assert_eq!(d.payload, DNS_QUERY);
}

#[test]
fn sll_llc_pseudo_protocol() {
    let f = sll(0, 1, &MAC_A, 0x0004, &snap(ethertype::IPV4, &udp4(b"x")));
    let d = decode(linktype::LINUX_SLL, &f);
    assert_eq!(d.error, None);
    assert!(d.link.llc.is_some());
    assert_eq!(d.payload, b"x");
}

#[test]
fn sll_netlink_is_not_ip() {
    let f = sll(4, 824, &[], 0x0000, &[1, 2, 3, 4]);
    let d = decode(linktype::LINUX_SLL, &f);
    assert_eq!(d.error, None);
    assert!(d.network.is_none());
    assert_eq!(d.payload, &[1, 2, 3, 4]);
}

#[test]
fn sll_radiotap_device() {
    let frame = wifi(
        fc(2, 0, 0x02),
        [MAC_A, MAC_B, MAC_C],
        None,
        1,
        None,
        &snap(ethertype::IPV4, &udp4(b"r")),
    );
    let f = sll(0, 803, &[], 0x0019, &radiotap(&[0], &[], &frame));
    let d = decode(linktype::LINUX_SLL, &f);
    assert_eq!(d.error, None);
    assert!(d.link.radiotap.is_some());
    assert_eq!(d.link.wifi.unwrap().bssid, Some(MacAddr(MAC_B)));
    assert_eq!(d.payload, b"r");
}

#[test]
fn sll2_ipv6_tcp() {
    let f = sll2(ethertype::IPV6, 3, 1, 4, &MAC_B, &tcp6(b"\x17\x03\x03"));
    let d = decode(linktype::LINUX_SLL2, &f);
    assert_eq!(d.error, None);
    assert_eq!(d.link.kind, LinkKind::LinuxSll2);
    let sll = d.link.sll.unwrap();
    assert_eq!(
        (sll.if_index, sll.packet_type, sll.arphrd_type),
        (Some(3), 4, 1)
    );
    let tcp = d.tcp().unwrap();
    assert!(tcp.flags.ack() && tcp.flags.contains(netsift_dissect::TcpFlags::PSH));
    assert_eq!(d.payload, b"\x17\x03\x03");
    insta::assert_debug_snapshot!("sll2_ipv6_tcp", d);
}

// ---------------------------------------------------------------- Raw IP

#[test]
fn raw_ip_detects_version() {
    let v4 = udp4(DNS_QUERY);
    let v6 = udp6(b"six");
    for (lt, f) in [(linktype::RAW, &v4), (linktype::IPV4, &v4)] {
        let d = decode(lt, f);
        assert_eq!(d.error, None, "linktype {lt}");
        assert_eq!(d.link.kind, LinkKind::RawIp);
        assert_eq!(d.link.ethertype, Some(ethertype::IPV4));
        assert_eq!(d.payload, DNS_QUERY);
    }
    for (lt, f) in [(linktype::RAW, &v6), (linktype::IPV6, &v6)] {
        let d = decode(lt, f);
        assert_eq!(d.error, None, "linktype {lt}");
        assert_eq!(d.link.ethertype, Some(ethertype::IPV6));
        assert_eq!(d.payload, b"six");
    }
}

#[test]
fn raw_ip_version_mismatch_and_garbage() {
    let buf = udp4(b"");
    let d = decode(linktype::IPV6, &buf);
    assert_eq!(
        d.error,
        Some(DecodeError {
            layer: Layer::Ipv4,
            kind: ErrorKind::Malformed("IP version does not match the link protocol"),
        })
    );
    let d = decode(linktype::RAW, &[0x55; 30]);
    assert_eq!(d.error.unwrap().layer, Layer::Ip);
    assert_eq!(d.payload.len(), 30);
}

// ---------------------------------------------------------------- Loopback

fn null_frame(af: [u8; 4], ip: &[u8]) -> Vec<u8> {
    let mut v = af.to_vec();
    v.extend_from_slice(ip);
    v
}

#[test]
fn null_little_endian_ipv4() {
    let f = null_frame(2u32.to_le_bytes(), &udp4(DNS_QUERY));
    let d = decode(linktype::NULL, &f);
    assert_eq!(d.error, None);
    assert_eq!(d.link.kind, LinkKind::Loopback);
    assert_eq!(d.payload, DNS_QUERY);
    insta::assert_debug_snapshot!("null_little_endian_ipv4", d);
}

#[test]
fn null_big_endian_ipv4() {
    let f = null_frame(2u32.to_be_bytes(), &udp4(DNS_QUERY));
    let d = decode(linktype::NULL, &f);
    assert_eq!(d.error, None);
    assert_eq!(d.payload, DNS_QUERY);
}

#[test]
fn null_ipv6_family_values() {
    for af in [24u32, 28, 30] {
        for bytes in [af.to_le_bytes(), af.to_be_bytes()] {
            let buf = null_frame(bytes, &udp6(b"v6"));
            let d = decode(linktype::NULL, &buf);
            assert_eq!(d.error, None, "AF {af}");
            assert_eq!(d.link.ethertype, Some(ethertype::IPV6));
            assert_eq!(d.payload, b"v6");
        }
    }
}

#[test]
fn loop_network_order() {
    let buf = null_frame(30u32.to_be_bytes(), &udp6(b"lo"));
    let d = decode(linktype::LOOP, &buf);
    assert_eq!(d.error, None);
    assert_eq!(d.payload, b"lo");
    let buf = null_frame(2u32.to_be_bytes(), &udp4(b"lo"));
    let d = decode(linktype::LOOP, &buf);
    assert_eq!(d.error, None);
}

#[test]
fn null_unknown_family() {
    let buf = null_frame(7u32.to_le_bytes(), &udp4(b""));
    let d = decode(linktype::NULL, &buf);
    assert_eq!(d.error.unwrap().layer, Layer::Loopback);
    assert_eq!(d.payload.len(), 28);
}

// ---------------------------------------------------------------- Radiotap + 802.11

/// TSFT + Flags + Channel + antenna signal, properly aligned (24 bytes total).
fn rt_fields(flags: u8) -> (Vec<u32>, Vec<u8>) {
    let mut fields = vec![0u8; 8]; // TSFT at offset 8
    fields.push(flags); // Flags at 16
    fields.push(0); // pad to 18 (channel is 2-aligned)
    fields.extend_from_slice(&2437u16.to_le_bytes()); // channel 6
    fields.extend_from_slice(&0x00a0u16.to_le_bytes()); // channel flags
    fields.push((-42i8).to_le_bytes()[0]); // antenna signal at 22
    fields.push(0); // trailing pad
    (vec![0x0000_002b], fields)
}

#[test]
fn radiotap_qos_data_with_fcs() {
    let (present, fields) = rt_fields(0x10);
    let body = snap(ethertype::IPV4, &udp4(DNS_QUERY));
    // To DS: addr1 = BSSID, addr2 = SA, addr3 = DA. QoS TID 5.
    let mut frame = wifi(
        fc(2, 8, 0x01),
        [MAC_C, MAC_A, MAC_B],
        None,
        100,
        Some(5),
        &body,
    );
    frame.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]); // FCS
    let f = radiotap(&present, &fields, &frame);
    let d = decode(linktype::IEEE802_11_RADIOTAP, &f);
    assert_eq!(d.error, None);
    let rt = d.link.radiotap.unwrap();
    assert!(rt.fcs_present);
    assert_eq!(
        (rt.header_len, rt.channel_mhz, rt.signal_dbm),
        (24, Some(2437), Some(-42))
    );
    let w = d.link.wifi.unwrap();
    assert_eq!(w.frame_type, WifiFrameType::Data);
    assert_eq!((w.subtype, w.qos_tid, w.sequence), (8, Some(5), Some(100)));
    assert_eq!(w.bssid, Some(MacAddr(MAC_C)));
    assert_eq!(d.link.src_mac, Some(MacAddr(MAC_A)));
    assert_eq!(d.link.dst_mac, Some(MacAddr(MAC_B)));
    assert_eq!(d.payload, DNS_QUERY, "FCS must be stripped");
    insta::assert_debug_snapshot!("radiotap_qos_data_with_fcs", d);
}

#[test]
fn radiotap_without_fcs_keeps_trailing_bytes() {
    let (present, fields) = rt_fields(0x00);
    let frame = wifi(
        fc(2, 0, 0x02),
        [MAC_A, MAC_B, MAC_C],
        None,
        1,
        None,
        &snap(ethertype::IPV4, &udp4(b"ok")),
    );
    let buf = radiotap(&present, &fields, &frame);
    let d = decode(linktype::IEEE802_11_RADIOTAP, &buf);
    assert_eq!(d.error, None);
    assert!(!d.link.radiotap.unwrap().fcs_present);
    // From DS: addr1 = DA, addr2 = BSSID, addr3 = SA.
    assert_eq!(d.link.wifi.unwrap().bssid, Some(MacAddr(MAC_B)));
    assert_eq!(d.link.src_mac, Some(MacAddr(MAC_C)));
    assert_eq!(d.payload, b"ok");
}

#[test]
fn radiotap_extended_bitmap_and_data_pad() {
    // Two presence words (ext bit set on the first), Flags = FCS | data pad at offset 12.
    let present = [0x8000_0002, 0x0000_0000];
    let fields = [0x30u8];
    let mut frame = wifi(fc(2, 8, 0x01), [MAC_C, MAC_A, MAC_B], None, 9, Some(0), &[]);
    frame.extend_from_slice(&[0, 0]); // 26-byte header padded to 28
    frame.extend(snap(ethertype::IPV4, &udp4(b"pad")));
    frame.extend_from_slice(&[1, 2, 3, 4]); // FCS
    let buf = radiotap(&present, &fields, &frame);
    let d = decode(linktype::IEEE802_11_RADIOTAP, &buf);
    assert_eq!(d.error, None);
    assert_eq!(d.link.radiotap.unwrap().header_len, 13);
    assert_eq!(d.payload, b"pad");
}

#[test]
fn ieee80211_four_address() {
    let body = snap(ethertype::IPV4, &udp4(b"wds"));
    let f = wifi(
        fc(2, 0, 0x03),
        [MAC_A, MAC_B, MAC_C],
        Some(MAC_D),
        7,
        None,
        &body,
    );
    let d = decode(linktype::IEEE802_11, &f);
    assert_eq!(d.error, None);
    assert_eq!(d.link.kind, LinkKind::Ieee80211);
    let w = d.link.wifi.unwrap();
    assert_eq!((w.addr4, w.bssid), (Some(MacAddr(MAC_D)), None));
    assert_eq!(d.link.dst_mac, Some(MacAddr(MAC_C)));
    assert_eq!(d.link.src_mac, Some(MacAddr(MAC_D)));
    assert_eq!(d.payload, b"wds");
    insta::assert_debug_snapshot!("ieee80211_four_address", d);
}

#[test]
fn ieee80211_qos_four_address() {
    let body = snap(ethertype::IPV6, &udp6(b"mesh"));
    let f = wifi(
        fc(2, 8, 0x03),
        [MAC_A, MAC_B, MAC_C],
        Some(MAC_D),
        7,
        Some(0x0006),
        &body,
    );
    let d = decode(linktype::IEEE802_11, &f);
    assert_eq!(d.error, None);
    assert_eq!(d.link.wifi.unwrap().qos_tid, Some(6));
    assert_eq!(d.payload, b"mesh");
}

#[test]
fn ieee80211_beacon() {
    let mut body = vec![0u8; 8]; // timestamp
    body.extend_from_slice(&100u16.to_le_bytes()); // beacon interval
    body.extend_from_slice(&0x0411u16.to_le_bytes()); // capabilities
    body.extend_from_slice(&[0, 4]);
    body.extend_from_slice(b"test"); // SSID element
    let f = wifi(
        fc(0, 8, 0),
        [[0xff; 6], MAC_C, MAC_C],
        None,
        2049,
        None,
        &body,
    );
    let d = decode(linktype::IEEE802_11, &f);
    assert_eq!(d.error, None);
    let w = d.link.wifi.unwrap();
    assert_eq!((w.frame_type, w.subtype), (WifiFrameType::Management, 8));
    assert_eq!(w.bssid, Some(MacAddr(MAC_C)));
    assert_eq!(w.sequence, Some(2049));
    assert!(d.network.is_none());
    assert_eq!(d.payload, &body[..]);
    insta::assert_debug_snapshot!("ieee80211_beacon", d.link.wifi);
}

#[test]
fn ieee80211_control_frames() {
    // ACK: frame control, duration, RA.
    let mut ack = fc(1, 13, 0).to_vec();
    ack.extend_from_slice(&[0, 0]);
    ack.extend_from_slice(&MAC_A);
    let d = decode(linktype::IEEE802_11, &ack);
    assert_eq!(d.error, None);
    let w = d.link.wifi.unwrap();
    assert_eq!(
        (w.frame_type, w.subtype, w.addr1, w.addr2),
        (WifiFrameType::Control, 13, Some(MacAddr(MAC_A)), None)
    );
    // RTS: RA + TA.
    let mut rts = fc(1, 11, 0).to_vec();
    rts.extend_from_slice(&[0, 0]);
    rts.extend_from_slice(&MAC_A);
    rts.extend_from_slice(&MAC_B);
    let d = decode(linktype::IEEE802_11, &rts);
    assert_eq!(d.error, None);
    assert_eq!(d.link.src_mac, Some(MacAddr(MAC_B)));
    // RTS missing its TA.
    let d = decode(linktype::IEEE802_11, &rts[..12]);
    assert_eq!(d.error.unwrap().layer, Layer::Ieee80211);
    assert_eq!(d.link.wifi.unwrap().subtype, 11);
}

#[test]
fn ieee80211_protected_and_null_data() {
    let f = wifi(
        fc(2, 0, 0x41),
        [MAC_C, MAC_A, MAC_B],
        None,
        3,
        None,
        &[0x11; 24],
    );
    let d = decode(linktype::IEEE802_11, &f);
    assert_eq!(d.error, None);
    assert!(d.link.wifi.unwrap().protected);
    assert!(d.network.is_none() && d.link.llc.is_none());
    assert_eq!(d.payload, &[0x11; 24]);

    let f = wifi(fc(2, 4, 0x01), [MAC_C, MAC_A, MAC_C], None, 4, None, &[]);
    let d = decode(linktype::IEEE802_11, &f);
    assert_eq!(d.error, None);
    assert_eq!(d.payload, &[] as &[u8]);
}

#[test]
fn ieee80211_amsdu_not_decoded() {
    let f = wifi(
        fc(2, 8, 0x01),
        [MAC_C, MAC_A, MAC_B],
        None,
        5,
        Some(0x0080),
        &[0x22; 30],
    );
    let d = decode(linktype::IEEE802_11, &f);
    assert_eq!(d.error, None);
    assert!(d.link.wifi.unwrap().amsdu);
    assert!(d.network.is_none());
}

#[test]
fn ieee80211_bad_version() {
    let d = decode(linktype::IEEE802_11, &[0x01, 0x00, 0, 0, 1, 2, 3, 4, 5, 6]);
    assert_eq!(d.error.unwrap().layer, Layer::Ieee80211);
    assert!(d.link.wifi.is_none());
}

// ---------------------------------------------------------------- Misc

#[test]
fn unsupported_linktype() {
    let d = decode(9999, &[1, 2, 3]);
    assert_eq!(d.link.kind, LinkKind::Unknown);
    assert_eq!(
        d.error,
        Some(DecodeError {
            layer: Layer::Link,
            kind: ErrorKind::UnsupportedLinktype(9999)
        })
    );
    assert_eq!(d.payload, &[1, 2, 3]);
    assert!(!linktype::is_supported(9999));
    assert!(
        linktype::SUPPORTED
            .iter()
            .all(|&lt| linktype::is_supported(lt))
    );
}

#[test]
fn error_display() {
    let e = DecodeError {
        layer: Layer::Tcp,
        kind: ErrorKind::Truncated {
            needed: 20,
            available: 3,
        },
    };
    assert_eq!(e.to_string(), "tcp: truncated (3 of 20 bytes)");
    assert_eq!(MacAddr(MAC_A).to_string(), "02:00:00:00:00:0a");
}

#[test]
fn transport_accessors() {
    let buf = udp4(b"z");
    let d = decode(linktype::RAW, &buf);
    assert!(matches!(d.transport, Some(Transport::Udp(_))));
    assert!(d.tcp().is_none());
    assert_eq!(d.udp().unwrap().length, 9);
}
