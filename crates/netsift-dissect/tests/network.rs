//! Network and transport layers: IPv6 extensions, fragments, ICMP, truncation per layer.

mod common;

use common::*;
use etherparse::PacketBuilder;
use netsift_dissect::{
    ErrorKind, Fragment, IpVersion, Layer, Transport, decode, decode_transport, ethertype,
    linktype, proto,
};

fn on_eth(ty: u16, ip: &[u8]) -> Vec<u8> {
    eth(MAC_B, MAC_A, ty, ip)
}

#[test]
fn ipv6_extension_chain_with_first_fragment() {
    // HBH -> Routing -> Fragment (offset 0, MF) -> Destination options -> UDP.
    let mut exts = ext8(43);
    exts.extend(ext8(44));
    exts.extend(frag6(60, 0, true, 0xdead_beef));
    exts.extend(ext8(17));
    exts.extend(udp_hdr(1234, 53, DNS_QUERY));
    let f = on_eth(ethertype::IPV6, &ipv6_hdr(0, &exts));
    let d = decode(linktype::ETHERNET, &f);
    assert_eq!(d.error, None);
    let ip = d.ip().unwrap();
    assert_eq!(ip.version, IpVersion::V6);
    assert_eq!(ip.extensions.as_slice(), &[0, 43, 44, 60]);
    assert_eq!(ip.header_len, 40 + 32);
    assert_eq!(ip.protocol, proto::UDP);
    assert_eq!(
        ip.fragment,
        Some(Fragment {
            id: 0xdead_beef,
            offset: 0,
            more: true
        })
    );
    assert_eq!(d.ports(), Some((1234, 53)));
    assert_eq!(d.payload, DNS_QUERY);
    insta::assert_debug_snapshot!("ipv6_extension_chain_with_first_fragment", d);
}

#[test]
fn ipv6_non_first_fragment_has_no_transport() {
    let mut exts = frag6(17, 1448, false, 7);
    exts.extend_from_slice(b"fragment data");
    let buf = ipv6_hdr(44, &exts);
    let d = decode(linktype::RAW, &buf);
    assert_eq!(d.error, None);
    let ip = d.ip().unwrap();
    assert_eq!(
        ip.fragment,
        Some(Fragment {
            id: 7,
            offset: 1448,
            more: false
        })
    );
    assert!(d.transport.is_none());
    assert_eq!(d.payload, b"fragment data");
}

#[test]
fn ipv6_atomic_fragment_is_not_a_fragment() {
    let mut exts = frag6(17, 0, false, 9);
    exts.extend(udp_hdr(1, 2, b"a"));
    let buf = ipv6_hdr(44, &exts);
    let d = decode(linktype::RAW, &buf);
    let ip = d.ip().unwrap();
    assert_eq!((ip.fragment, ip.ident), (None, Some(9)));
    assert_eq!(d.payload, b"a");
}

#[test]
fn ipv6_truncated_extension_keeps_ip() {
    let mut ip = ipv6_hdr(0, &[17, 0, 0, 0, 0, 0, 0, 0]);
    // Announce a hop-by-hop header but cut it.
    ip.truncate(40 + 4);
    let d = decode(linktype::RAW, &ip);
    let e = d.error.unwrap();
    assert_eq!(e.layer, Layer::Ipv6);
    assert!(matches!(e.kind, ErrorKind::Truncated { .. }));
    assert!(d.ip().is_some(), "IPv6 header must be kept");
    assert!(d.transport.is_none());
}

#[test]
fn ipv4_first_fragment_decodes_tcp_header() {
    let mut tcp = vec![0u8; 20];
    tcp[0..2].copy_from_slice(&40000u16.to_be_bytes());
    tcp[2..4].copy_from_slice(&80u16.to_be_bytes());
    tcp[12] = 5 << 4;
    tcp[13] = 0x18; // PSH|ACK
    tcp.extend_from_slice(&[0x41; 12]);
    let f = on_eth(ethertype::IPV4, &ipv4_hdr(6, 52, 0x1234, 0x2000, &tcp));
    let d = decode(linktype::ETHERNET, &f);
    assert_eq!(d.error, None);
    let ip = d.ip().unwrap();
    assert_eq!(
        ip.fragment,
        Some(Fragment {
            id: 0x1234,
            offset: 0,
            more: true
        })
    );
    assert_eq!(d.tcp().unwrap().payload_len, 12);
}

#[test]
fn ipv4_second_fragment() {
    let data = [0x42u8; 16];
    let f = on_eth(ethertype::IPV4, &ipv4_hdr(6, 36, 0x1234, 185, &data));
    let d = decode(linktype::ETHERNET, &f);
    assert_eq!(d.error, None);
    assert!(d.transport.is_none());
    assert_eq!(d.payload, &data);
    insta::assert_debug_snapshot!("ipv4_second_fragment", d.network);
}

#[test]
fn ipv4_dont_fragment_is_not_a_fragment() {
    let buf = ipv4_hdr(17, 28 + 1, 1, 0x4000, &udp_hdr(1, 2, b"x"));
    let d = decode(linktype::RAW, &buf);
    let ip = d.ip().unwrap();
    assert!(ip.dont_fragment);
    assert_eq!(ip.fragment, None);
    assert_eq!(d.payload, b"x");
}

#[test]
fn ipv4_snaplen_truncation_is_flagged() {
    let mut ip = udp4(&[0x33; 100]);
    ip.truncate(20 + 8 + 10);
    let d = decode(linktype::RAW, &ip);
    assert_eq!(d.error, None);
    assert!(d.ip().unwrap().truncated);
    assert_eq!(d.udp().unwrap().length, 108);
    assert_eq!(d.payload, &[0x33; 10]);
}

#[test]
fn ipv4_other_protocol_keeps_ip_payload() {
    let buf = ipv4_hdr(47, 24, 1, 0, &[0, 0, 0x08, 0x00]); // GRE
    let d = decode(linktype::RAW, &buf);
    assert_eq!(d.error, None);
    assert_eq!(d.ip().unwrap().protocol, 47);
    assert!(d.transport.is_none());
    assert_eq!(d.payload, &[0, 0, 0x08, 0x00]);
}

#[test]
fn icmpv4_and_icmpv6_echo() {
    let mut f = Vec::new();
    PacketBuilder::ipv4(IP4_A, IP4_B, 64)
        .icmpv4_echo_request(1, 2)
        .write(&mut f, b"ping")
        .unwrap();
    let d = decode(linktype::RAW, &f);
    let Some(Transport::Icmpv4(i)) = d.transport else {
        panic!("no ICMP")
    };
    assert_eq!((i.icmp_type, i.code), (8, 0));
    assert_eq!(d.payload, b"ping");

    let mut f = Vec::new();
    PacketBuilder::ipv6(IP6_A, IP6_B, 64)
        .icmpv6_echo_reply(1, 2)
        .write(&mut f, b"pong")
        .unwrap();
    let d = decode(linktype::RAW, &f);
    let Some(Transport::Icmpv6(i)) = d.transport else {
        panic!("no ICMPv6")
    };
    assert_eq!((i.icmp_type, i.code), (129, 0));
    assert_eq!(d.payload, b"pong");
}

#[test]
fn udp_bogus_length_keeps_captured_bytes() {
    let mut u = udp_hdr(1, 2, b"abcd");
    u[4..6].copy_from_slice(&3u16.to_be_bytes()); // below the header size
    let buf = ipv4_hdr(17, 32, 1, 0, &u);
    let d = decode(linktype::RAW, &buf);
    assert_eq!(d.payload, b"abcd");
}

#[test]
fn tcp_bad_data_offset() {
    let mut tcp = vec![0u8; 20];
    tcp[12] = 4 << 4;
    let buf = ipv4_hdr(6, 40, 1, 0, &tcp);
    let d = decode(linktype::RAW, &buf);
    assert_eq!(d.error.unwrap().layer, Layer::Tcp);
    assert!(matches!(d.error.unwrap().kind, ErrorKind::Malformed(_)));
    assert!(d.ip().is_some());
}

#[test]
fn ipv4_bad_ihl() {
    let mut ip = udp4(b"");
    ip[0] = 0x44;
    let d = decode(linktype::RAW, &ip);
    assert_eq!(d.error.unwrap().layer, Layer::Ipv4);
    assert!(d.network.is_none());
}

#[test]
fn decode_transport_on_reassembled_payload() {
    let u = udp_hdr(5353, 5353, b"mdns");
    let (t, payload) = decode_transport(proto::UDP, &u).unwrap().unwrap();
    assert!(matches!(t, Transport::Udp(_)));
    assert_eq!(payload, b"mdns");
    assert_eq!(decode_transport(47, &u).unwrap(), None);
    assert_eq!(
        decode_transport(proto::TCP, &u[..4]).unwrap_err().layer,
        Layer::Tcp
    );
}

/// Cuts a valid frame at every length and checks that the error points at the right
/// layer and that all layers before it are kept.
#[test]
fn truncation_at_every_layer() {
    // Ethernet (14) + VLAN (4) + IPv4 (20) + TCP (20) + 4 bytes payload.
    let mut body = vlan(0, 5, ethertype::IPV4);
    body.extend(tcp4(b"data"));
    let f = eth(MAC_B, MAC_A, ethertype::VLAN, &body);
    for cut in 0..f.len() {
        let d = decode(linktype::ETHERNET, &f[..cut]);
        let expected = match cut {
            0..14 => Some(Layer::Ethernet),
            14..18 => Some(Layer::Vlan),
            18..38 => Some(Layer::Ipv4),
            38..58 => Some(Layer::Tcp),
            _ => None,
        };
        assert_eq!(d.error.map(|e| e.layer), expected, "cut at {cut}");
        assert_eq!(d.link.src_mac.is_some(), cut >= 14, "cut at {cut}");
        assert_eq!(d.link.vlans.len(), usize::from(cut >= 18), "cut at {cut}");
        assert_eq!(d.network.is_some(), cut >= 38, "cut at {cut}");
        assert_eq!(d.transport.is_some(), cut >= 58, "cut at {cut}");
        assert!(is_subslice(&f, d.payload));
    }
}

#[test]
fn truncation_per_linktype_header() {
    let cases: [(u32, Vec<u8>, usize, Layer); 7] = [
        (
            linktype::LINUX_SLL,
            sll(0, 1, &MAC_A, ethertype::IPV4, &udp4(b"")),
            16,
            Layer::LinuxSll,
        ),
        (
            linktype::LINUX_SLL2,
            sll2(ethertype::IPV4, 1, 1, 0, &MAC_A, &udp4(b"")),
            20,
            Layer::LinuxSll,
        ),
        (
            linktype::NULL,
            [2u8, 0, 0, 0].into_iter().chain(udp4(b"")).collect(),
            4,
            Layer::Loopback,
        ),
        (
            linktype::IEEE802_11_RADIOTAP,
            radiotap(&[0], &[], &[0; 30]),
            8,
            Layer::Radiotap,
        ),
        (
            linktype::IEEE802_11,
            wifi(
                fc(2, 8, 1),
                [MAC_A, MAC_B, MAC_C],
                None,
                1,
                Some(0),
                &snap(ethertype::IPV4, &udp4(b"")),
            ),
            26,
            Layer::Ieee80211,
        ),
        (linktype::IPV6, udp6(b""), 40, Layer::Ipv6),
        (linktype::IPV4, udp4(b""), 20, Layer::Ipv4),
    ];
    for (lt, frame, header, layer) in cases {
        for cut in 0..header {
            let d = decode(lt, &frame[..cut]);
            let e = d
                .error
                .unwrap_or_else(|| panic!("linktype {lt} cut {cut}: no error"));
            assert_eq!(e.layer, layer, "linktype {lt} cut {cut}");
            assert!(d.network.is_none());
        }
        let d = decode(lt, &frame);
        assert_eq!(d.error, None, "linktype {lt} full frame");
    }
}

#[test]
fn truncation_llc_snap_and_arp() {
    let llc = snap(ethertype::IPV4, &udp4(b""));
    let wifi_frame = wifi(fc(2, 0, 1), [MAC_A, MAC_B, MAC_C], None, 1, None, &llc);
    for cut in 24..32 {
        let d = decode(linktype::IEEE802_11, &wifi_frame[..cut]);
        assert_eq!(d.error.unwrap().layer, Layer::Llc, "cut {cut}");
        assert!(d.link.wifi.is_some());
    }
    let arp = [0u8, 1, 8, 0, 6, 4, 0, 1, 1, 2, 3, 4, 5, 6, 10, 0, 0, 1];
    let buf = on_eth(ethertype::ARP, &arp);
    let d = decode(linktype::ETHERNET, &buf);
    assert_eq!(d.error.unwrap().layer, Layer::Arp);
    assert!(d.network.is_none());
}

#[test]
fn radiotap_length_beyond_frame() {
    let mut f = radiotap(&[0], &[], &[]);
    f[2] = 200; // it_len = 200 > 8 captured bytes
    let d = decode(linktype::IEEE802_11_RADIOTAP, &f);
    assert_eq!(d.error.unwrap().layer, Layer::Radiotap);
    f[2] = 4; // it_len below the fixed header
    let d = decode(linktype::IEEE802_11_RADIOTAP, &f);
    assert_eq!(
        d.error.unwrap().kind,
        ErrorKind::Malformed("header length below 8")
    );
}

/// Regression: a hop-by-hop header announcing a fragment header that is cut must not
/// make the decoder read past the frame (etherparse's extension iterator does).
#[test]
fn ipv6_truncated_fragment_header_after_hop_by_hop() {
    let mut body = ext8(44);
    body.extend(frag6(17, 0, true, 1));
    let full = ipv6_hdr(0, &body);
    for cut in 40..full.len() {
        let d = decode(linktype::IPV6, &full[..cut]);
        assert!(d.ip().is_some(), "cut {cut}");
        if cut >= 48 {
            assert_eq!(d.ip().unwrap().extensions.as_slice(), &[0], "cut {cut}");
            assert_eq!(d.error.unwrap().layer, Layer::Ipv6, "cut {cut}");
        }
    }
}
