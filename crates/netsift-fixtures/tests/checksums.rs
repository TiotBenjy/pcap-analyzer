//! Generated frames carry valid IPv4 header, TCP and UDP checksums (checked by an independent
//! implementation), IPv4 identifications vary when enabled, and the fragmentation scenario
//! rebuilds its datagrams.

use std::collections::BTreeSet;

use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use netsift_fixtures::Packet;
use netsift_fixtures::craft::{TcpConv, ip_payload, udp_frame};
use netsift_fixtures::scenario::{Scenario, TcpOptions};
use netsift_fixtures::scenarios::{self, Kind, hosts};

/// One's complement sum folded to 16 bits (RFC 1071), not yet complemented.
fn ones_sum(chunks: &[&[u8]]) -> u32 {
    let mut sum: u64 = 0;
    for data in chunks {
        let mut i = 0;
        while i + 1 < data.len() {
            sum += u64::from(u16::from_be_bytes([data[i], data[i + 1]]));
            i += 2;
        }
        if i < data.len() {
            sum += u64::from(data[i]) << 8;
        }
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    u32::try_from(sum).unwrap()
}

/// Verifies the IP header checksum (IPv4) and the TCP / UDP checksum of one frame.
/// Returns `(ip_version, transport)` for statistics.
fn verify(frame: &[u8]) -> (u8, &'static str) {
    let sliced = SlicedPacket::from_ethernet(frame).expect("decodable frame");
    let (version, pseudo_addrs, proto): (u8, Vec<u8>, u8) = match &sliced.net {
        Some(NetSlice::Ipv4(v4)) => {
            let header = v4.header().slice();
            assert_eq!(ones_sum(&[header]), 0xffff, "IPv4 header checksum");
            let mut addrs = v4.header().source().to_vec();
            addrs.extend_from_slice(&v4.header().destination());
            (4, addrs, v4.header().protocol().0)
        }
        Some(NetSlice::Ipv6(v6)) => {
            let mut addrs = v6.header().source().to_vec();
            addrs.extend_from_slice(&v6.header().destination());
            (6, addrs, v6.header().next_header().0)
        }
        other => panic!("unexpected network layer {other:?}"),
    };
    let segment = ip_payload(frame).expect("IP payload");
    let len = u32::try_from(segment.len()).unwrap();
    let pseudo_tail: Vec<u8> = if version == 4 {
        let mut t = vec![0, proto];
        t.extend_from_slice(&u16::try_from(len).unwrap().to_be_bytes());
        t
    } else {
        let mut t = len.to_be_bytes().to_vec();
        t.extend_from_slice(&[0, 0, 0, proto]);
        t
    };
    let kind = match sliced.transport {
        Some(TransportSlice::Tcp(_)) => "tcp",
        Some(TransportSlice::Udp(_)) => "udp",
        _ => return (version, "other"),
    };
    assert_eq!(
        ones_sum(&[&pseudo_addrs, &pseudo_tail, segment]),
        0xffff,
        "{kind} checksum over IPv{version}"
    );
    (version, kind)
}

fn verify_all(packets: &[Packet]) -> BTreeSet<(u8, &'static str)> {
    packets.iter().map(|p| verify(&p.data)).collect()
}

#[test]
fn every_scenario_has_valid_checksums() {
    let mut seen = BTreeSet::new();
    seen.extend(verify_all(scenarios::demo().packets()));
    for kind in Kind::ALL {
        seen.extend(verify_all(&scenarios::generate(kind, 2, 3)));
    }
    for want in [(4, "tcp"), (4, "udp"), (6, "udp")] {
        assert!(seen.contains(&want), "{want:?} covered");
    }
}

#[test]
fn crafted_frames_have_valid_checksums() {
    let conv = TcpConv::new(hosts::workstation_v6(), hosts::router_v6(), 40_000, 80)
        .with_isns(u32::MAX - 3, 17);
    assert_eq!(verify(&conv.syn()), (6, "tcp"));
    assert_eq!(
        verify(&conv.data(netsift_fixtures::craft::Side::Client, 0, 0, b"odd")),
        (6, "tcp")
    );
    let v4 = TcpConv::new(hosts::workstation(), hosts::web_server(), 40_000, 80);
    assert_eq!(verify(&v4.syn_ack()), (4, "tcp"));
    let udp = udp_frame(&hosts::workstation(), &hosts::router(), 1, 2, b"x");
    assert_eq!(verify(&udp), (4, "udp"));
}

#[test]
fn ip_ids_vary_only_when_enabled() {
    let ids = |sc: &Scenario| -> Vec<u16> {
        sc.packets()
            .iter()
            .filter_map(|p| match SlicedPacket::from_ethernet(&p.data).ok()?.net {
                Some(NetSlice::Ipv4(v4)) => Some(v4.header().identification()),
                _ => None,
            })
            .collect()
    };
    let default = scenarios::demo();
    assert!(ids(&default).iter().all(|&id| id == 0));

    let mut sc = Scenario::new().with_ip_ids(0xfffe);
    sc.udp(hosts::workstation(), hosts::router(), 1, 2, b"a");
    sc.udp(hosts::workstation_v6(), hosts::router_v6(), 1, 2, b"b");
    sc.udp(hosts::workstation(), hosts::router(), 1, 2, b"c");
    sc.udp(hosts::workstation(), hosts::router(), 1, 2, b"d");
    sc.tcp_open(
        hosts::workstation(),
        hosts::web_server(),
        &TcpOptions::new(80),
    );
    assert_eq!(ids(&sc), vec![0xfffe, 0xffff, 0, 1, 2, 3]);
    verify_all(sc.packets());
}

#[test]
fn fragmentation_scenario_rebuilds_each_datagram() {
    let (sc, expected) = scenarios::fragmentation();
    assert_eq!(expected.len(), 4);
    assert_eq!(
        sc.len(),
        expected.iter().map(|d| d.frames).sum::<usize>(),
        "only fragment frames"
    );
    let mut idx = 0;
    for dg in &expected {
        let frames = &sc.packets()[idx..idx + dg.frames];
        idx += dg.frames;
        // Naive "first arrival wins" rebuild of the fragmentable part.
        let mut buf: Vec<Option<u8>> = Vec::new();
        for p in frames {
            let sliced = SlicedPacket::from_ethernet(&p.data).unwrap();
            let (offset, data) = match &sliced.net {
                Some(NetSlice::Ipv4(v4)) => {
                    assert!(v4.is_payload_fragmented());
                    let off = usize::from(v4.header().fragments_offset().byte_offset());
                    (off, v4.payload().payload)
                }
                Some(NetSlice::Ipv6(v6)) => {
                    let raw = ip_payload(&p.data).unwrap();
                    assert_eq!(v6.header().next_header().0, 44);
                    let off = usize::from(u16::from_be_bytes([raw[2], raw[3]]) & 0xfff8);
                    (off, &raw[8..])
                }
                _ => panic!("IP fragment expected"),
            };
            if buf.len() < offset + data.len() {
                buf.resize(offset + data.len(), None);
            }
            for (slot, &b) in buf[offset..].iter_mut().zip(data) {
                slot.get_or_insert(b);
            }
        }
        let rebuilt: Vec<u8> = buf.into_iter().map(Option::unwrap).collect();
        assert_eq!(&rebuilt[8..], dg.payload.as_slice(), "UDP payload");
        assert_eq!(
            u16::from_be_bytes([rebuilt[0], rebuilt[1]]),
            dg.sport,
            "UDP source port"
        );
    }
}
