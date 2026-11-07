//! Files written by the crate, read back with the independent `pcap-file` reader.

mod common;

use common::{ReadPacket, expected, raw_bytes, read_bytes, read_file};
use netsift_fixtures::anomaly::{merge_interfaces, two_interface_traffic};
use netsift_fixtures::scenario::Scenario;
use netsift_fixtures::scenarios;
use netsift_fixtures::writer::{
    Encoding, Endian, FileFormat, Interface, PcapNgOptions, PcapOptions, PcapPrecision,
    TsResolution, encode, write_file,
};
use netsift_fixtures::{LINKTYPE_ETHERNET, LINKTYPE_RAW, Packet};

/// Demo traffic with sub-microsecond timestamps, so that precision loss is observable.
fn odd_timestamps() -> Vec<Packet> {
    let mut packets = scenarios::demo().into_packets();
    for (i, p) in packets.iter_mut().enumerate() {
        p.ts_ns += (i64::try_from(i).unwrap() * 7_919) % 1_000; // nanosecond noise
    }
    packets
}

#[test]
fn pcap_microseconds_little_endian() {
    let packets = odd_timestamps();
    let bytes = encode(&packets, &Encoding::pcap()).unwrap();
    assert_eq!(&bytes[..4], &[0xd4, 0xc3, 0xb2, 0xa1]);
    let read = read_bytes(&bytes);
    assert_eq!(read.len(), packets.len());
    assert_eq!(read, expected(&packets, 1_000));
    assert!(read.iter().all(|p| p.linktype == LINKTYPE_ETHERNET));
}

#[test]
fn pcap_nanoseconds_big_endian() {
    let packets = odd_timestamps();
    let enc = Encoding::from(FileFormat::Pcap(PcapOptions {
        precision: PcapPrecision::Nano,
        endian: Endian::Big,
        ..PcapOptions::default()
    }));
    let bytes = encode(&packets, &enc).unwrap();
    assert_eq!(&bytes[..4], &[0xa1, 0xb2, 0x3c, 0x4d]);
    assert_eq!(read_bytes(&bytes), expected(&packets, 1));
}

#[test]
fn pcap_raw_ip_linktype() {
    let packets: Vec<Packet> = odd_timestamps()
        .into_iter()
        .map(|mut p| {
            p.data.drain(..14);
            p.linktype = LINKTYPE_RAW;
            p
        })
        .collect();
    let read = read_bytes(&encode(&packets, &Encoding::pcap_ns()).unwrap());
    assert!(read.iter().all(|p| p.linktype == LINKTYPE_RAW));
    assert_eq!(read, expected(&packets, 1));
}

#[test]
fn pcapng_default_microsecond_interface() {
    let packets = odd_timestamps();
    let bytes = encode(&packets, &Encoding::pcapng()).unwrap();
    assert_eq!(&bytes[..4], &[0x0a, 0x0d, 0x0d, 0x0a]);
    assert_eq!(read_bytes(&bytes), expected(&packets, 1_000));
}

#[test]
fn pcapng_multiple_interfaces_with_custom_resolutions() {
    let (a, b) = two_interface_traffic(20);
    let mut packets = merge_interfaces(&a, &b);
    // A third interface carrying raw IP with a base-2 resolution.
    let mut c = Scenario::starting_at(packets[3].ts_ns + 333);
    c.set_interface(2);
    c.dns(
        scenarios::hosts::workstation(),
        scenarios::hosts::router(),
        &netsift_fixtures::scenario::DnsExchange::a("raw.example.test", [192, 0, 2, 9]),
    );
    for mut p in c.into_packets() {
        p.data.drain(..14);
        p.linktype = LINKTYPE_RAW;
        packets.push(p);
    }
    packets.sort_by_key(|p| p.ts_ns);
    for (i, p) in packets.iter_mut().enumerate() {
        p.ts_ns += (i64::try_from(i).unwrap() * 7_919) % 1_000;
    }

    let interfaces = vec![
        Interface::ethernet().with_name("eth0"),
        Interface::ethernet()
            .with_name("eth1")
            .with_tsresol(TsResolution::NANO),
        Interface {
            linktype: LINKTYPE_RAW,
            ..Interface::ethernet().with_tsresol(TsResolution::Pow2(30))
        },
    ];
    for endian in [Endian::Little, Endian::Big] {
        let enc = Encoding::from(FileFormat::PcapNg(PcapNgOptions {
            endian,
            interfaces: interfaces.clone(),
        }));
        let read = read_bytes(&encode(&packets, &enc).unwrap());
        assert_eq!(read.len(), packets.len());
        let mut per_iface = [0usize; 3];
        for (r, p) in read.iter().zip(&packets) {
            per_iface[r.interface as usize] += 1;
            assert_eq!(r.interface, p.interface);
            assert_eq!(r.linktype, p.linktype);
            assert_eq!(r.data, p.data);
            match p.interface {
                0 => assert_eq!(r.ts_ns, p.ts_ns - p.ts_ns % 1_000),
                1 => assert_eq!(r.ts_ns, p.ts_ns),
                _ => assert!((p.ts_ns - r.ts_ns).abs() <= 2, "2^-30 s resolution"),
            }
        }
        assert!(per_iface.iter().all(|n| *n > 0), "{per_iface:?}");
    }
}

#[test]
fn pcapng_derives_one_interface_per_id() {
    let (a, b) = two_interface_traffic(5);
    let packets = merge_interfaces(&a, &b);
    let read = read_bytes(&encode(&packets, &Encoding::pcapng()).unwrap());
    let expected: Vec<ReadPacket> = packets.iter().map(ReadPacket::from).collect();
    assert_eq!(read, expected);
}

#[test]
fn gzip_variants_round_trip() {
    let packets = odd_timestamps();
    let dir = tempfile::tempdir().unwrap();
    for (enc, unit) in [
        (Encoding::pcap().gz(), 1_000),
        (Encoding::pcap_ns().gz(), 1),
        (Encoding::pcapng().gz(), 1_000),
    ] {
        let path = dir.path().join(format!("capture.{}", enc.extension()));
        write_file(&path, &packets, &enc).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(&bytes[..2], &[0x1f, 0x8b], "gzip magic");
        let plain = Encoding {
            gzip: false,
            ..enc.clone()
        };
        assert_eq!(raw_bytes(&bytes), encode(&packets, &plain).unwrap());
        assert_eq!(read_file(&path), expected(&packets, unit));
    }
}
