//! Property tests: `decode` never panics and always returns a payload borrowed from the
//! input, whatever the bytes and the linktype.

mod common;

use common::*;
use netsift_dissect::{decode, ethertype, linktype};
use proptest::prelude::*;

fn check(lt: u32, data: &[u8]) {
    let d = decode(lt, data);
    assert!(
        is_subslice(data, d.payload),
        "payload must borrow the frame"
    );
    assert!(d.payload.len() <= data.len());
    assert_eq!(d.link.linktype, lt);
    assert!(
        is_subslice(data, d.ip_payload),
        "ip_payload must borrow the frame"
    );
    let end = d.payload_offset + d.payload.len();
    assert_eq!(&data[d.payload_offset..end], d.payload, "payload_offset");
    if let Some(l4) = d.l4_offset {
        assert!(l4 <= d.payload_offset);
        assert!(d.l3_offset.is_some_and(|l3| l3 <= l4));
    }
    if let Some(l3) = d.l3_offset {
        assert!(l3 <= d.payload_offset);
    }
    // Formatting must not panic either (used in logs and snapshots).
    let _ = format!("{d:?}");
    if let Some(e) = d.error {
        let _ = e.to_string();
    }
}

/// Valid frames per linktype, used as seeds for mutation.
fn seeds() -> Vec<(u32, Vec<u8>)> {
    let mut qinq = vlan(1, 10, ethertype::VLAN);
    qinq.extend(vlan(2, 20, ethertype::IPV4));
    qinq.extend(tcp4(b"GET / HTTP/1.1\r\n"));
    let mut v6 = ext8(44);
    v6.extend(frag6(17, 0, true, 1));
    v6.extend(udp_hdr(1, 2, DNS_QUERY));
    let wifi_frame = wifi(
        fc(2, 8, 0x01),
        [MAC_C, MAC_A, MAC_B],
        None,
        1,
        Some(3),
        &snap(ethertype::IPV4, &udp4(DNS_QUERY)),
    );
    let rt_fields = [0u8; 8]
        .into_iter()
        .chain([0x10, 0, 0x85, 0x09, 0, 0, 0xd6, 0])
        .collect::<Vec<_>>();
    let mut rt_frame = wifi_frame.clone();
    rt_frame.extend_from_slice(&[0; 4]);
    vec![
        (
            linktype::ETHERNET,
            eth(MAC_B, MAC_A, ethertype::QINQ, &qinq),
        ),
        (
            linktype::ETHERNET,
            eth(MAC_B, MAC_A, ethertype::IPV6, &ipv6_hdr(0, &v6)),
        ),
        (
            linktype::LINUX_SLL,
            sll(0, 1, &MAC_A, ethertype::IPV4, &udp4(DNS_QUERY)),
        ),
        (
            linktype::LINUX_SLL2,
            sll2(ethertype::IPV6, 2, 1, 4, &MAC_A, &tcp6(b"x")),
        ),
        (linktype::RAW, udp4(DNS_QUERY)),
        (linktype::IPV4, tcp4(b"abc")),
        (linktype::IPV6, udp6(b"abc")),
        (
            linktype::NULL,
            [2u8, 0, 0, 0].into_iter().chain(udp4(b"q")).collect(),
        ),
        (
            linktype::LOOP,
            [0u8, 0, 0, 30].into_iter().chain(udp6(b"q")).collect(),
        ),
        (linktype::IEEE802_11, wifi_frame),
        (
            linktype::IEEE802_11_RADIOTAP,
            radiotap(&[0x0000_002b], &rt_fields, &rt_frame),
        ),
    ]
}

proptest! {
    // 512 cases by default; `PROPTEST_CASES` raises it for longer local runs.
    #![proptest_config(ProptestConfig {
        cases: std::env::var("PROPTEST_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(512),
        ..ProptestConfig::default()
    })]

    #[test]
    fn arbitrary_bytes_every_supported_linktype(data in proptest::collection::vec(any::<u8>(), 0..512)) {
        for lt in linktype::SUPPORTED {
            check(lt, &data);
        }
    }

    #[test]
    fn arbitrary_linktype(lt in any::<u32>(), data in proptest::collection::vec(any::<u8>(), 0..64)) {
        check(lt, &data);
    }

    #[test]
    fn mutated_valid_frames(
        seed in 0usize..11,
        flips in proptest::collection::vec((any::<usize>(), any::<u8>()), 0..8),
        cut in any::<usize>(),
    ) {
        let seeds = seeds();
        let (lt, mut frame) = seeds[seed % seeds.len()].clone();
        for (pos, val) in flips {
            let len = frame.len();
            frame[pos % len] = val;
        }
        let cut = cut % (frame.len() + 1);
        check(lt, &frame[..cut]);
        check(lt, &frame);
    }
}

#[test]
fn seeds_decode_fully() {
    for (lt, frame) in seeds() {
        let d = decode(lt, &frame);
        assert_eq!(d.error, None, "linktype {lt}");
        assert!(d.transport.is_some(), "linktype {lt}");
    }
}
