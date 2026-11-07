//! Chunk splitter: names, bounds, lossless concatenation; anomaly helpers.
#![allow(clippy::case_sensitive_file_extension_comparisons)] // names are generated here

mod common;

use std::path::PathBuf;

use common::{ReadPacket, read_bytes, read_file, tcp_segment, udp_payload};
use netsift_fixtures::anomaly::{
    create_empty_file, dns_across_chunks, duplicate_chunk, http_request_across_chunks,
    merge_interfaces, mixed_encodings, remove_chunk, truncate_last_packet, two_interface_traffic,
    write_overlapping_sets, write_two_prefixes,
};
use netsift_fixtures::scenarios::{self, Kind};
use netsift_fixtures::split::{ChunkSink, Naming, SplitBy, SplitOptions, split, split_to_dir};
use netsift_fixtures::time::NS_PER_SEC;
use netsift_fixtures::writer::{Encoding, Interface, header_size, record_size};
use netsift_fixtures::{Packet, time};

/// Traffic spanning about a minute: a demo round every 2.5 s.
fn traffic() -> Vec<Packet> {
    let mut sc = netsift_fixtures::Scenario::new();
    for _ in 0..24 {
        Kind::Demo.append_to(&mut sc);
        sc.advance(2 * NS_PER_SEC);
    }
    sc.into_packets()
}

fn as_read(packets: &[Packet]) -> Vec<ReadPacket> {
    packets.iter().map(ReadPacket::from).collect()
}

fn concat_files(paths: &[PathBuf]) -> Vec<ReadPacket> {
    paths.iter().flat_map(|p| read_file(p)).collect()
}

fn names(paths: &[PathBuf]) -> Vec<String> {
    paths
        .iter()
        .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
        .collect()
}

#[test]
fn dumpcap_default_naming() {
    let packets = traffic();
    let chunks = split(
        &packets,
        &SplitOptions::new(SplitBy::Duration(10 * NS_PER_SEC), Naming::Dumpcap),
    );
    assert!(chunks.len() >= 5);
    assert_eq!(chunks[0].file_name, "capture_00001_20231114221320.pcapng");
    for c in &chunks {
        let ts = time::compact_timestamp(c.first_ts().unwrap());
        assert_eq!(
            c.file_name,
            format!("capture_{:05}_{ts}.pcapng", c.index + 1)
        );
    }
}

#[test]
fn dumpcap_nametimenum_and_editcap_naming() {
    let packets = traffic();
    let by = SplitBy::Packets(100);
    let ntn = split(
        &packets,
        &SplitOptions::new(by.clone(), Naming::DumpcapNameTimeNum).with_prefix("ring"),
    );
    assert_eq!(ntn[0].file_name, "ring_20231114221320_00001.pcapng");
    assert_eq!(ntn[1].number, 2);

    let editcap = split(
        &packets,
        &SplitOptions::new(by, Naming::Editcap)
            .with_encoding(Encoding::pcap())
            .with_prefix("out"),
    );
    assert_eq!(editcap[0].file_name, "out_00000_20231114221320.pcap");
    assert!(editcap[1].file_name.starts_with("out_00001_2023111422"));
    assert!(editcap.iter().all(|c| c.packets.len() <= 100));
    assert!(
        editcap[..editcap.len() - 1]
            .iter()
            .all(|c| c.packets.len() == 100)
    );
}

#[test]
fn tcpdump_c_naming() {
    let packets = traffic();
    let opts = SplitOptions::new(SplitBy::Size(40_000), Naming::TcpdumpC)
        .with_prefix("trace")
        .with_encoding(Encoding::pcap());
    let chunks = split(&packets, &opts);
    let names: Vec<&str> = chunks.iter().map(|c| c.file_name.as_str()).collect();
    assert_eq!(&names[..3], &["trace.pcap", "trace.pcap1", "trace.pcap2"]);

    let bare = split(
        &packets,
        &opts
            .clone()
            .with_extension("")
            .with_encoding(Encoding::pcap().gz()),
    );
    assert_eq!(bare[0].file_name, "trace.gz");
    assert_eq!(bare[1].file_name, "trace1.gz");
}

#[test]
fn high_start_numbers_grow_past_five_digits() {
    let packets = traffic();
    let opts = SplitOptions::new(SplitBy::Packets(150), Naming::Dumpcap).with_start_number(99_998);
    let chunks = split(&packets, &opts);
    assert!(chunks.len() >= 4);
    let numbers: Vec<&str> = chunks.iter().map(|c| &c.file_name[8..14]).collect();
    assert_eq!(&numbers[..4], &["99998_", "99999_", "100000", "100001"]);
    // Lexicographic order differs from numeric order: readers must sort numerically.
    let mut lexical: Vec<&String> = chunks.iter().map(|c| &c.file_name).collect();
    lexical.sort();
    assert_ne!(lexical[0], &chunks[0].file_name);
}

#[test]
fn size_bound_is_respected_and_maximal() {
    let packets = traffic();
    for enc in [Encoding::pcap(), Encoding::pcapng()] {
        let limit = 20_000;
        let opts =
            SplitOptions::new(SplitBy::Size(limit), Naming::Dumpcap).with_encoding(enc.clone());
        let dir = tempfile::tempdir().unwrap();
        let (chunks, paths) = split_to_dir(dir.path(), &packets, &opts).unwrap();
        assert!(chunks.len() > 3);
        for (i, (c, path)) in chunks.iter().zip(&paths).enumerate() {
            let size = std::fs::metadata(path).unwrap().len();
            assert_eq!(size, c.raw_size());
            assert!(
                size <= limit || c.packets.len() == 1,
                "chunk {i}: {size} > {limit}"
            );
            if let Some(next) = chunks.get(i + 1) {
                let would_be = size + record_size(&enc.format, &next.packets[0]);
                assert!(would_be > limit, "chunk {i} rotated too early");
            }
        }
        assert_eq!(concat_files(&paths), as_read(&packets));
        assert!(header_size(&enc.format, &chunks[0].interfaces) > 0);
    }
}

#[test]
fn oversized_packet_gets_its_own_chunk() {
    let packets = traffic();
    let chunks = split(
        &packets,
        &SplitOptions::new(SplitBy::Size(100), Naming::Dumpcap),
    );
    assert_eq!(chunks.len(), packets.len());
}

#[test]
fn duration_bound_is_respected() {
    let packets = traffic();
    let d = 7 * NS_PER_SEC;
    let opts = SplitOptions::new(SplitBy::Duration(d), Naming::DumpcapNameTimeNum)
        .with_encoding(Encoding::pcap_ns());
    let dir = tempfile::tempdir().unwrap();
    let (chunks, paths) = split_to_dir(dir.path(), &packets, &opts).unwrap();
    assert!(chunks.len() >= 8);
    for (i, c) in chunks.iter().enumerate() {
        let (first, last) = (c.first_ts().unwrap(), c.last_ts().unwrap());
        assert!(last - first < d, "chunk {i} lasts too long");
        if let Some(next) = chunks.get(i + 1) {
            assert!(
                next.first_ts().unwrap() - first >= d,
                "chunk {i} rotated too early"
            );
        }
    }
    assert_eq!(concat_files(&paths), as_read(&packets));
}

#[test]
fn mixed_formats_in_one_set_concatenate_losslessly() {
    let packets = traffic();
    let opts =
        SplitOptions::new(SplitBy::Packets(60), Naming::Dumpcap).with_encodings(mixed_encodings());
    let dir = tempfile::tempdir().unwrap();
    let (_, paths) = split_to_dir(dir.path(), &packets, &opts).unwrap();
    let names = names(&paths);
    assert!(names[0].ends_with(".pcapng"));
    assert!(names[1].ends_with(".pcap"));
    assert!(names[2].ends_with(".pcapng.gz"));
    assert!(names[3].ends_with(".pcap.gz"));
    assert_eq!(concat_files(&paths), as_read(&packets));
}

#[test]
fn streaming_sink_matches_in_memory_split() {
    let packets = traffic();
    for (by, encs) in [
        (SplitBy::Size(30_000), vec![Encoding::pcapng()]),
        (SplitBy::Duration(5 * NS_PER_SEC), mixed_encodings()),
        (SplitBy::Packets(77), vec![Encoding::pcap().gz()]),
    ] {
        let opts = SplitOptions::new(by, Naming::Dumpcap).with_encodings(encs);
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let (_, expected) = split_to_dir(a.path(), &packets, &opts).unwrap();
        let mut sink = ChunkSink::new(b.path(), &opts, &[Interface::ethernet()]).unwrap();
        for p in &packets {
            sink.push(p).unwrap();
        }
        let streamed = sink.finish().unwrap();
        assert_eq!(names(&streamed), names(&expected));
        for (x, y) in expected.iter().zip(&streamed) {
            assert_eq!(std::fs::read(x).unwrap(), std::fs::read(y).unwrap());
        }
    }
}

#[test]
fn missing_duplicate_truncated_and_empty_chunks() {
    let packets = traffic();
    let dir = tempfile::tempdir().unwrap();
    let opts = SplitOptions::new(SplitBy::Packets(100), Naming::Dumpcap).with_encodings(vec![
        Encoding::pcap(),
        Encoding::pcapng(),
        Encoding::pcap_ns().gz(),
    ]);
    let (chunks, paths) = split_to_dir(dir.path(), &packets, &opts).unwrap();

    remove_chunk(&paths[1]).unwrap();
    assert!(!paths[1].exists());

    let dup = duplicate_chunk(&paths[0], "copy_of_first.pcap").unwrap();
    assert_eq!(
        std::fs::read(&dup).unwrap(),
        std::fs::read(&paths[0]).unwrap()
    );

    for idx in [0, 2, 3, 4] {
        let before = read_file(&paths[idx]).len();
        let new_len = truncate_last_packet(&paths[idx]).unwrap();
        let raw = common::raw_bytes(&std::fs::read(&paths[idx]).unwrap());
        assert_eq!(raw.len() as u64, new_len);
        // pcap-file stops with an error on the incomplete record: count complete ones.
        assert_eq!(count_complete(&raw), before - 1, "chunk {idx}");
        assert_eq!(chunks[idx].packets.len(), before);
    }

    let empty = create_empty_file(dir.path(), "capture_00099_20231114230000.pcapng").unwrap();
    assert_eq!(std::fs::metadata(empty).unwrap().len(), 0);
}

fn count_complete(raw: &[u8]) -> usize {
    use pcap_file::pcapng::{Block, PcapNgReader};
    if raw.starts_with(&[0x0a, 0x0d, 0x0d, 0x0a]) {
        let mut r = PcapNgReader::new(raw).unwrap();
        let mut n = 0;
        while let Some(Ok(block)) = r.next_block() {
            n += usize::from(matches!(block, Block::EnhancedPacket(_)));
        }
        n
    } else {
        let mut r = pcap_file::pcap::PcapReader::new(raw).unwrap();
        let mut n = 0;
        while let Some(Ok(_)) = r.next_packet() {
            n += 1;
        }
        n
    }
}

#[test]
fn two_prefixes_in_one_directory() {
    let a = scenarios::generate(Kind::Dns, 30, 1);
    let b = scenarios::generate(Kind::Http, 10, 2);
    let dir = tempfile::tempdir().unwrap();
    let opts = SplitOptions::new(SplitBy::Packets(25), Naming::Dumpcap);
    let (pa, pb) = write_two_prefixes(dir.path(), ("siteA", &a), ("siteB", &b), &opts).unwrap();
    assert!(names(&pa).iter().all(|n| n.starts_with("siteA_")));
    assert!(names(&pb).iter().all(|n| n.starts_with("siteB_")));
    assert_eq!(
        std::fs::read_dir(dir.path()).unwrap().count(),
        pa.len() + pb.len()
    );
    assert_eq!(concat_files(&pa), as_read(&a));
    assert_eq!(concat_files(&pb), as_read(&b));
}

#[test]
fn overlapping_interface_sets_merge_into_increasing_order() {
    let dir = tempfile::tempdir().unwrap();
    let opts = SplitOptions::new(SplitBy::Packets(10), Naming::Dumpcap);
    let (eth0, eth1) = write_overlapping_sets(dir.path(), 20, &opts).unwrap();
    let a = concat_files(&eth0);
    let b = concat_files(&eth1);
    let (a_first, a_last) = (a[0].ts_ns, a.last().unwrap().ts_ns);
    let (b_first, b_last) = (b[0].ts_ns, b.last().unwrap().ts_ns);
    assert!(a_first < b_last && b_first < a_last, "time ranges overlap");

    let (ra, rb) = two_interface_traffic(20);
    let merged = merge_interfaces(&ra, &rb);
    assert_eq!(merged.len(), ra.len() + rb.len());
    assert!(merged.windows(2).all(|w| w[0].ts_ns < w[1].ts_ns));
    assert!(merged.iter().any(|p| p.interface == 1));
    let single = read_bytes(&netsift_fixtures::encode(&merged, &Encoding::pcapng()).unwrap());
    assert_eq!(single, as_read(&merged));
}

#[test]
fn dns_query_and_response_in_consecutive_chunks() {
    let case = dns_across_chunks();
    let opts = SplitOptions::new(case.split_by(), Naming::Dumpcap);
    let chunks = split(&case.packets, &opts);
    assert_eq!(chunks.len(), 2);
    let last_of_first = chunks[0].packets.last().unwrap();
    let first_of_second = &chunks[1].packets[0];
    let (_, dport, q) = udp_payload(&last_of_first.data).unwrap();
    let (sport, _, r) = udp_payload(&first_of_second.data).unwrap();
    assert_eq!((dport, sport), (53, 53));
    let q = simple_dns::Packet::parse(&q).unwrap();
    let r = simple_dns::Packet::parse(&r).unwrap();
    assert_eq!((q.id(), r.id()), (0x5151, 0x5151));
    assert!(q.answers.is_empty() && !r.answers.is_empty());
}

#[test]
fn http_request_cut_between_two_chunks() {
    let case = http_request_across_chunks();
    let dir = tempfile::tempdir().unwrap();
    let opts = SplitOptions::new(case.split_by(), Naming::TcpdumpC).with_encoding(Encoding::pcap());
    let (chunks, paths) = split_to_dir(dir.path(), &case.packets, &opts).unwrap();
    assert_eq!(names(&paths), ["capture.pcap", "capture.pcap1"]);
    let tail = tcp_segment(&chunks[0].packets.last().unwrap().data).unwrap();
    let head = tcp_segment(&chunks[1].packets[0].data).unwrap();
    assert!(tail.payload.starts_with(b"GET /images/logo.png"));
    assert!(!head.payload.is_empty() && head.src_port == tail.src_port);
    assert_eq!(
        head.seq,
        tail.seq
            .wrapping_add(u32::try_from(tail.payload.len()).unwrap())
    );
    let request: Vec<u8> = chunks
        .iter()
        .flat_map(|c| &c.packets)
        .filter_map(|p| tcp_segment(&p.data))
        .filter(|s| s.dst_port == 80)
        .flat_map(|s| s.payload)
        .collect();
    assert!(request.ends_with(b"\r\n\r\n"));
    assert_eq!(concat_files(&paths), as_read(&case.packets));
}
