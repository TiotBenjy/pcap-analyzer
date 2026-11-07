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
            more: true,
            next_header: 60,
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
            more: false,
            next_header: 17,
        })
    );
    assert!(d.transport.is_none());
    assert_eq!(d.payload, b"fragment data");
    assert_eq!(d.ip_payload, b"fragment data");
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
            more: true,
            next_header: 6,
        })
    );
    assert_eq!(d.tcp().unwrap().payload_len, 12);
    assert_eq!(d.ip_payload, &tcp[..]);
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
    assert_eq!(
        (i.icmp_type, i.code, i.id, i.sequence),
        (8, 0, Some(1), Some(2))
    );
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
    assert_eq!(
        (i.icmp_type, i.code, i.id, i.sequence),
        (129, 0, Some(1), Some(2))
    );
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

/// Non-first IPv6 fragments whose Fragment header announces an extension header: the
/// fragment data must not be parsed as headers.
#[test]
fn ipv6_non_first_fragment_announcing_extensions() {
    for next in [60u8, 51] {
        // Looks like a header with length 0xff (or an AH with length 0).
        let data = [
            17u8,
            if next == 51 { 0 } else { 0xff },
            1,
            2,
            3,
            4,
            5,
            6,
            7,
            8,
        ];
        let mut body = frag6(next, 2048, true, 42);
        body.extend_from_slice(&data);
        let buf = ipv6_hdr(44, &body);
        let d = decode(linktype::IPV6, &buf);
        assert_eq!(d.error, None, "next header {next}");
        let ip = d.ip().unwrap();
        assert_eq!(ip.protocol, next);
        assert_eq!(ip.extensions.as_slice(), &[44]);
        assert_eq!(ip.header_len, 48);
        let frag = ip.fragment.unwrap();
        assert_eq!(
            (frag.offset, frag.more, frag.next_header),
            (2048, true, next)
        );
        assert!(d.transport.is_none());
        assert_eq!(d.payload, &data);
        assert_eq!(d.ip_payload, &data);
    }
}

/// Non-first IPv4 fragment with protocol AH: the data is not an AH header.
#[test]
fn ipv4_non_first_fragment_with_auth_protocol() {
    let data = [6u8, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    let buf = ipv4_hdr(51, 36, 0x99, 185, &data);
    let d = decode(linktype::IPV4, &buf);
    assert_eq!(d.error, None);
    let ip = d.ip().unwrap();
    assert_eq!((ip.protocol, ip.header_len), (51, 20));
    assert!(ip.extensions.is_empty());
    assert_eq!(ip.fragment.unwrap().next_header, 51);
    assert!(d.transport.is_none());
    assert_eq!(d.payload, &data);
    assert_eq!(d.ip_payload, &data);
}

#[test]
fn ipv6_first_fragment_with_destination_options_after_fragment() {
    let mut fragmentable = ext8(17);
    fragmentable.extend(udp_hdr(4000, 5000, b"first"));
    let mut body = frag6(60, 0, true, 5);
    body.extend_from_slice(&fragmentable);
    let buf = ipv6_hdr(44, &body);
    let d = decode(linktype::IPV6, &buf);
    assert_eq!(d.error, None);
    let ip = d.ip().unwrap();
    assert_eq!(ip.extensions.as_slice(), &[44, 60]);
    assert_eq!(ip.protocol, proto::UDP);
    assert_eq!(ip.fragment.unwrap().next_header, 60);
    assert_eq!(d.ports(), Some((4000, 5000)));
    assert_eq!(
        d.ip_payload,
        &fragmentable[..],
        "fragmentable part starts after the Fragment header"
    );
    assert_eq!(d.payload, b"first");
}

/// Reassembles fragments by hand from `ip_payload` and decodes the transport header,
/// as `netsift-flow` will.
fn reassemble(frames: &[Vec<u8>], lt: u32) -> (u8, Vec<u8>) {
    let mut parts: Vec<(u16, u8, Vec<u8>)> = frames
        .iter()
        .map(|f| {
            let d = decode(lt, f);
            let frag = d.ip().unwrap().fragment.unwrap();
            (frag.offset, frag.next_header, d.ip_payload.to_vec())
        })
        .collect();
    parts.sort_by_key(|p| p.0);
    let next_header = parts[0].1;
    let mut data = Vec::new();
    for (offset, _, part) in parts {
        assert_eq!(usize::from(offset), data.len(), "contiguous fragments");
        data.extend(part);
    }
    (next_header, data)
}

#[test]
fn reassembled_ipv6_fragments_decode_transport() {
    let payload = [0x5au8; 40];
    let mut fragmentable = ext8(17);
    fragmentable.extend(udp_hdr(4000, 5000, &payload));
    let (a, b) = fragmentable.split_at(24);
    let mut f1 = frag6(60, 0, true, 9);
    f1.extend_from_slice(a);
    let mut f2 = frag6(60, 24, false, 9);
    f2.extend_from_slice(b);
    // Second fragment first: order comes from the offsets.
    let frames = [ipv6_hdr(44, &f2), ipv6_hdr(44, &f1)];
    let (next_header, data) = reassemble(&frames, linktype::IPV6);
    assert_eq!(data, fragmentable);
    let (t, rest) = decode_transport(next_header, &data).unwrap().unwrap();
    let Transport::Udp(u) = t else {
        panic!("not UDP")
    };
    assert_eq!((u.src_port, u.dst_port), (4000, 5000));
    assert_eq!(rest, &payload);
}

#[test]
fn reassembled_ipv4_fragments_decode_transport() {
    let datagram = udp_hdr(1111, 2222, &[0x77; 30]);
    let (a, b) = datagram.split_at(16);
    let f1 = ipv4_hdr(17, 36, 0x4242, 0x2000, a);
    let f2 = ipv4_hdr(17, 20 + 22, 0x4242, 2, b);
    let (next_header, data) = reassemble(&[f1, f2], linktype::IPV4);
    assert_eq!(data, datagram);
    let (t, rest) = decode_transport(next_header, &data).unwrap().unwrap();
    let Transport::Udp(u) = t else {
        panic!("not UDP")
    };
    assert_eq!((u.src_port, u.dst_port, u.length), (1111, 2222, 38));
    assert_eq!(rest, &[0x77; 30]);
}

fn tcp_with_options(options: &[u8]) -> Vec<u8> {
    let mut tcp = vec![0u8; 20];
    tcp[0..2].copy_from_slice(&443u16.to_be_bytes());
    tcp[2..4].copy_from_slice(&50000u16.to_be_bytes());
    tcp[12] = u8::try_from((20 + options.len()) / 4).unwrap() << 4;
    tcp[13] = 0x12; // SYN|ACK
    tcp.extend_from_slice(options);
    let total = u16::try_from(20 + tcp.len()).unwrap();
    ipv4_hdr(6, total, 1, 0x4000, &tcp)
}

#[test]
fn tcp_options_are_parsed() {
    let mut opts = vec![2, 4, 0x05, 0xb4, 1, 3, 3, 7, 4, 2, 8, 10];
    opts.extend_from_slice(&1u32.to_be_bytes());
    opts.extend_from_slice(&2u32.to_be_bytes());
    let buf = tcp_with_options(&opts);
    let d = decode(linktype::IPV4, &buf);
    assert_eq!(d.error, None);
    let tcp = d.tcp().unwrap();
    assert_eq!(tcp.header_len, 40);
    let o = tcp.options;
    assert_eq!(
        (o.mss, o.window_scale, o.sack_permitted, o.timestamps),
        (Some(1460), Some(7), true, Some((1, 2)))
    );
    insta::assert_debug_snapshot!("tcp_options_are_parsed", tcp);
}

#[test]
fn tcp_malformed_options_stop_quietly() {
    // MSS with a zero length, then a valid window scale that must not be reached.
    let buf = tcp_with_options(&[2, 0, 0, 0, 3, 3, 7, 0]);
    let d = decode(linktype::IPV4, &buf);
    assert_eq!(d.error, None);
    assert_eq!(
        d.tcp().unwrap().options,
        netsift_dissect::TcpOptions::default()
    );
    // Option longer than the option area.
    let buf = tcp_with_options(&[8, 10, 0, 0]);
    let d = decode(linktype::IPV4, &buf);
    assert_eq!(d.tcp().unwrap().options.timestamps, None);
}

#[test]
fn layer_offsets() {
    let mut body = vlan(0, 5, ethertype::IPV4);
    body.extend(tcp4(b"data"));
    let f = eth(MAC_B, MAC_A, ethertype::VLAN, &body);
    let d = decode(linktype::ETHERNET, &f);
    assert_eq!(
        (d.l3_offset, d.l4_offset, d.payload_offset),
        (Some(18), Some(38), 58)
    );
    assert_eq!(&f[d.payload_offset..], b"data");

    let arp = [
        0u8, 1, 8, 0, 6, 4, 0, 1, 1, 2, 3, 4, 5, 6, 10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 10, 0, 0, 2,
    ];
    let buf = on_eth(ethertype::ARP, &arp);
    let d = decode(linktype::ETHERNET, &buf);
    assert_eq!(
        (d.l3_offset, d.l4_offset, d.payload_offset),
        (Some(14), None, 42)
    );

    let d = decode(9999, &[1, 2, 3]);
    assert_eq!(
        (d.l3_offset, d.l4_offset, d.payload_offset),
        (None, None, 0)
    );
}
