//! Integration tests of chunk sets on synthetic captures written by `netsift-fixtures`
//! (see the "Tests obligatoires" list of `docs/CHUNKED_CAPTURES.md`).

use std::fs;
use std::path::Path;

use netsift_capture::chunkset::{
    self, Anomaly, AnomalyKind, ChunkGroup, ChunkSetSource, ContinuityConfig, EntryKind, GroupKind,
    Grouping, InventoryOptions, MemberStatus, ReadOptions,
};
use netsift_capture::{PacketSource, ReadWarning, reader};
use netsift_fixtures::anomaly::{
    create_empty_file, duplicate_chunk, mixed_encodings, remove_chunk, truncate_last_packet,
    two_interface_traffic, write_overlapping_sets, write_two_prefixes,
};
use netsift_fixtures::scenarios::{Kind, generate};
use netsift_fixtures::writer::PcapOptions;
use netsift_fixtures::{
    Encoding, FileFormat, LINKTYPE_RAW, Naming, Packet, SplitBy, SplitOptions, split_to_dir,
    write_file,
};
use tempfile::TempDir;

const SEC: i64 = 1_000_000_000;

/// (timestamp, linktype, bytes) of a packet, the identity compared across readings.
type Seen = (i64, u32, Vec<u8>);

fn traffic() -> Vec<Packet> {
    generate(Kind::Demo, 6, 7)
}

fn expected(packets: &[Packet]) -> Vec<Seen> {
    packets
        .iter()
        .map(|p| (p.ts_ns, p.linktype, p.data.clone()))
        .collect()
}

fn drain(source: &mut dyn PacketSource) -> Vec<Seen> {
    let mut out = Vec::new();
    while let Some(p) = source.next_packet().unwrap() {
        out.push((p.ts_ns, p.linktype, p.data.to_vec()));
    }
    out
}

fn grouping(dir: &Path, recursive: bool) -> Grouping {
    let options = InventoryOptions {
        recursive,
        ..InventoryOptions::default()
    };
    chunkset::group(&chunkset::inventory(dir, &options).unwrap())
}

/// The only group of `dir`.
fn only_group(dir: &Path) -> ChunkGroup {
    let mut grouping = grouping(dir, false);
    assert_eq!(grouping.groups.len(), 1, "{:#?}", grouping.groups);
    grouping.groups.remove(0)
}

/// Reads a whole group; returns the packets, the source (anomalies, stats) after the end.
fn read(group: &ChunkGroup) -> (Vec<Seen>, ChunkSetSource) {
    let mut source = ChunkSetSource::new(group, ReadOptions::default());
    let packets = drain(&mut source);
    assert!(source.is_finished());
    assert_eq!(source.bytes_read(), source.total_bytes());
    (packets, source)
}

fn codes(anomalies: &[Anomaly]) -> Vec<(Option<u32>, &'static str)> {
    anomalies.iter().map(|a| (a.chunk, a.kind.code())).collect()
}

fn names(group: &ChunkGroup) -> Vec<&str> {
    group
        .members
        .iter()
        .map(|m| m.entry.name.as_str())
        .collect()
}

fn split(dir: &Path, packets: &[Packet], opts: &SplitOptions) -> Vec<std::path::PathBuf> {
    split_to_dir(dir, packets, opts).unwrap().1
}

#[test]
fn split_set_reads_like_the_single_file() {
    let packets = traffic();
    let tmp = TempDir::new().unwrap();
    let single = tmp.path().join("single.pcapng");
    write_file(&single, &packets, &Encoding::pcapng()).unwrap();
    let reference = drain(reader::open(&single).unwrap().as_mut());
    assert_eq!(reference, expected(&packets));

    let cases = [
        (SplitBy::Size(4096), Naming::Dumpcap),
        (SplitBy::Duration(SEC), Naming::DumpcapNameTimeNum),
        (SplitBy::Packets(7), Naming::Editcap),
        (SplitBy::Size(3000), Naming::TcpdumpC),
    ];
    for (i, (by, naming)) in cases.into_iter().enumerate() {
        let dir = tmp.path().join(format!("case{i}"));
        let paths = split(&dir, &packets, &SplitOptions::new(by.clone(), naming));
        assert!(paths.len() > 3, "{by:?} gives several chunks");
        let group = only_group(&dir);
        let kind = match naming {
            Naming::Dumpcap | Naming::Editcap => GroupKind::Dumpcap,
            Naming::DumpcapNameTimeNum => GroupKind::DumpcapNameTimeNum,
            Naming::TcpdumpC => GroupKind::TcpdumpRotation,
        };
        assert_eq!(group.kind, kind);
        assert_eq!(group.members.len(), paths.len());
        let (seen, source) = read(&group);
        assert_eq!(seen, reference, "{by:?} {naming:?}");
        assert_eq!(source.anomalies(), &[], "{by:?} {naming:?}");
        let sizes: u64 = paths.iter().map(|p| fs::metadata(p).unwrap().len()).sum();
        assert_eq!(source.total_bytes(), sizes);
        // Chunk ids follow the file order and every chunk has its packets.
        let counts: Vec<u64> = source.chunk_stats().map(|s| s.packets).collect();
        assert!(counts.iter().all(|&n| n > 0));
        assert_eq!(counts.iter().sum::<u64>(), packets.len() as u64);
    }
}

#[test]
fn chunk_ids_follow_group_order() {
    let packets = traffic();
    let tmp = TempDir::new().unwrap();
    let opts = SplitOptions::new(SplitBy::At(vec![10, 20]), Naming::Dumpcap);
    split(tmp.path(), &packets, &opts);
    let group = only_group(tmp.path());
    let mut source = ChunkSetSource::new(&group, ReadOptions::default());
    let mut ids = Vec::new();
    while let Some(p) = source.next_packet().unwrap() {
        ids.push(p.chunk_id);
    }
    assert_eq!(ids.iter().filter(|&&c| c == 0).count(), 10);
    assert_eq!(ids.iter().filter(|&&c| c == 1).count(), 10);
    assert_eq!(ids.iter().filter(|&&c| c == 2).count(), packets.len() - 20);
    assert!(ids.is_sorted());
}

#[test]
fn numbering_beyond_99999_is_sorted_numerically() {
    let packets = traffic();
    let tmp = TempDir::new().unwrap();
    let opts = SplitOptions::new(SplitBy::Packets(8), Naming::Dumpcap).with_start_number(99_997);
    let paths = split(tmp.path(), &packets, &opts);
    assert!(paths.len() >= 5);
    // On disk (lexicographic) the 6-digit names sort first: the files are "out of order".
    let mut on_disk: Vec<_> = fs::read_dir(tmp.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    on_disk.sort();
    assert!(on_disk[0].starts_with("capture_100000_"));

    let group = only_group(tmp.path());
    let seqs: Vec<_> = group.members.iter().map(|m| m.seq.unwrap()).collect();
    let wanted: Vec<u64> = (99_997..99_997 + paths.len() as u64).collect();
    assert_eq!(seqs, wanted);
    let (seen, source) = read(&group);
    assert_eq!(seen, expected(&packets));
    assert_eq!(source.anomalies(), &[]);
}

#[test]
fn missing_chunk_is_reported_and_the_rest_is_read() {
    let packets = traffic();
    let tmp = TempDir::new().unwrap();
    let opts = SplitOptions::new(SplitBy::At(vec![10, 20, 30]), Naming::Dumpcap);
    let paths = split(tmp.path(), &packets, &opts);
    remove_chunk(&paths[2]).unwrap();

    let group = only_group(tmp.path());
    let (seen, source) = read(&group);
    let mut kept = packets[..20].to_vec();
    kept.extend_from_slice(&packets[30..]);
    assert_eq!(seen, expected(&kept));
    assert_eq!(
        source.anomalies()[0],
        Anomaly {
            chunk: Some(2),
            kind: AnomalyKind::MissingSequence { first: 3, last: 3 },
        }
    );
}

#[test]
fn time_gap_is_reported() {
    let mut packets = traffic();
    for p in &mut packets[25..] {
        p.ts_ns += 60 * SEC;
    }
    let tmp = TempDir::new().unwrap();
    let opts = SplitOptions::new(SplitBy::At(vec![25]), Naming::Dumpcap);
    split(tmp.path(), &packets, &opts);
    let group = only_group(tmp.path());
    let (seen, source) = read(&group);
    assert_eq!(seen, expected(&packets));
    let gap = packets[25].ts_ns - packets[24].ts_ns;
    assert_eq!(
        source.anomalies(),
        &[Anomaly {
            chunk: Some(1),
            kind: AnomalyKind::TimeGap {
                previous: 0,
                gap_ns: gap,
                threshold_ns: 5 * SEC,
            },
        }]
    );
    // A larger fixed threshold silences it.
    let options = ReadOptions {
        continuity: ContinuityConfig {
            gap: chunkset::GapThreshold::Fixed { ns: 120 * SEC },
        },
        ..ReadOptions::default()
    };
    let mut source = ChunkSetSource::new(&group, options);
    drain(&mut source);
    assert_eq!(source.anomalies(), &[]);
}

#[test]
fn duplicate_chunks_are_ignored() {
    let packets = traffic();
    let tmp = TempDir::new().unwrap();
    let opts = SplitOptions::new(SplitBy::At(vec![10, 20]), Naming::Dumpcap);
    let paths = split(tmp.path(), &packets, &opts);
    // Same name in a sub-directory (recursive import of a folder holding a copy).
    let sub = tmp.path().join("copy");
    fs::create_dir(&sub).unwrap();
    fs::copy(&paths[1], sub.join(paths[1].file_name().unwrap())).unwrap();

    let mut grouping = grouping(tmp.path(), true);
    assert_eq!(grouping.groups.len(), 1);
    let group = grouping.groups.remove(0);
    assert_eq!(group.members.len(), 4);
    let (seen, source) = read(&group);
    assert_eq!(seen, expected(&packets));
    assert_eq!(codes(source.anomalies()), vec![(Some(2), "duplicate")]);
    assert_eq!(group.members[2].status, MemberStatus::Duplicate { of: 1 });

    // Copy under another name in a plain folder of unrelated names.
    let flat = TempDir::new().unwrap();
    let single = flat.path().join("trace.pcapng");
    write_file(&single, &packets, &Encoding::pcapng()).unwrap();
    duplicate_chunk(&single, "trace (copy).pcapng").unwrap();
    let group = only_group(flat.path());
    let (seen, source) = read(&group);
    assert_eq!(seen, expected(&packets));
    assert_eq!(codes(source.anomalies()), vec![(Some(1), "duplicate")]);
}

#[test]
fn truncated_last_packet_is_dropped_cleanly() {
    let packets = traffic();
    for encoding in [
        Encoding::pcap(),
        Encoding::pcapng(),
        Encoding::pcapng().gz(),
    ] {
        let tmp = TempDir::new().unwrap();
        let opts = SplitOptions::new(SplitBy::At(vec![15]), Naming::Dumpcap)
            .with_encoding(encoding.clone());
        let paths = split(tmp.path(), &packets, &opts);
        truncate_last_packet(paths.last().unwrap()).unwrap();
        let group = only_group(tmp.path());
        let (seen, source) = read(&group);
        assert_eq!(
            seen,
            expected(&packets[..packets.len() - 1]),
            "{encoding:?}"
        );
        assert_eq!(
            codes(source.anomalies()),
            vec![(Some(1), "truncated_tail")],
            "{encoding:?}"
        );
        assert!(matches!(
            source.warnings(),
            [ReadWarning::TruncatedTail { .. }]
        ));
    }
}

#[test]
fn empty_and_short_files_never_fail_the_set() {
    let packets = traffic();
    let tmp = TempDir::new().unwrap();
    let opts = SplitOptions::new(SplitBy::At(vec![15]), Naming::Dumpcap);
    let paths = split(tmp.path(), &packets, &opts);
    // The file being written when the folder was copied, and a stray short file.
    create_empty_file(tmp.path(), "capture_00003_20991231235959.pcapng").unwrap();
    fs::write(tmp.path().join("notes.txt"), b"hi").unwrap();
    // A header-only capture (dumpcap just rotated).
    let header_only = tmp.path().join("capture_00004_20991231235959.pcapng");
    write_file(&header_only, &[], &Encoding::pcapng()).unwrap();

    let inventory = chunkset::inventory(tmp.path(), &InventoryOptions::default()).unwrap();
    let kinds: Vec<_> = inventory
        .entries
        .iter()
        .map(|e| match &e.kind {
            EntryKind::Capture(m) => format!("capture first_ts={}", m.first_ts.is_some()),
            other => format!("{other:?}"),
        })
        .collect();
    assert_eq!(
        kinds,
        vec![
            "capture first_ts=true",
            "capture first_ts=true",
            "Empty",
            "capture first_ts=false",
            "TooShort",
        ]
    );
    assert_eq!(inventory.rejected().count(), 2);

    let grouping = chunkset::group(&inventory);
    assert_eq!(grouping.groups.len(), 1);
    assert_eq!(grouping.ungrouped.len(), 1);
    let group = &grouping.groups[0];
    assert_eq!(names(group).len(), 4);
    assert_eq!(group.members[2].status, MemberStatus::Skipped);
    let (seen, source) = read(group);
    assert_eq!(seen, expected(&packets));
    assert_eq!(
        source.anomalies(),
        &[Anomaly {
            chunk: Some(2),
            kind: AnomalyKind::EmptyChunk { last: false },
        }]
    );
    let sizes: u64 = paths
        .iter()
        .chain([&header_only])
        .map(|p| fs::metadata(p).unwrap().len())
        .sum();
    assert_eq!(source.total_bytes(), sizes);
}

#[test]
fn empty_last_file_is_flagged_as_last() {
    let packets = traffic();
    let tmp = TempDir::new().unwrap();
    let opts = SplitOptions::new(SplitBy::At(vec![15]), Naming::TcpdumpC);
    split(tmp.path(), &packets, &opts);
    create_empty_file(tmp.path(), "capture.pcapng2").unwrap();
    let group = only_group(tmp.path());
    assert_eq!(group.kind, GroupKind::TcpdumpRotation);
    let (seen, source) = read(&group);
    assert_eq!(seen, expected(&packets));
    assert_eq!(
        source.anomalies(),
        &[Anomaly {
            chunk: Some(2),
            kind: AnomalyKind::EmptyChunk { last: true },
        }]
    );
}

#[test]
fn mixed_pcap_pcapng_and_gzip_in_one_set() {
    let packets = traffic();
    let tmp = TempDir::new().unwrap();
    let opts =
        SplitOptions::new(SplitBy::Packets(6), Naming::Dumpcap).with_encodings(mixed_encodings());
    let paths = split(tmp.path(), &packets, &opts);
    assert!(paths.len() >= 5);
    let group = only_group(tmp.path());
    let formats: Vec<_> = group
        .members
        .iter()
        .map(|m| {
            let info = &m.entry.capture().unwrap().info;
            (info.format, info.compressed)
        })
        .collect();
    assert!(formats.contains(&(netsift_capture::CaptureFormat::Pcap, true)));
    assert!(formats.contains(&(netsift_capture::CaptureFormat::PcapNg, true)));
    assert!(formats.contains(&(netsift_capture::CaptureFormat::Pcap, false)));
    let (seen, source) = read(&group);
    assert_eq!(seen, expected(&packets));
    assert!(source.info().compressed);
    // Same link type and snaplen everywhere: no change reported.
    assert_eq!(source.anomalies(), &[]);
}

#[test]
fn two_prefixes_give_two_groups() {
    let a = generate(Kind::Dns, 4, 1);
    let b = generate(Kind::Http, 4, 2);
    let tmp = TempDir::new().unwrap();
    let opts = SplitOptions::new(SplitBy::Packets(5), Naming::Dumpcap);
    write_two_prefixes(tmp.path(), ("site-a", &a), ("site-b", &b), &opts).unwrap();
    let grouping = grouping(tmp.path(), false);
    let labels: Vec<_> = grouping
        .groups
        .iter()
        .map(|g| (g.kind, g.label.as_str()))
        .collect();
    assert_eq!(
        labels,
        vec![
            (GroupKind::Dumpcap, "site-a"),
            (GroupKind::Dumpcap, "site-b")
        ]
    );
    let (seen_a, _) = read(&grouping.groups[0]);
    let (seen_b, _) = read(&grouping.groups[1]);
    assert_eq!(seen_a, expected(&a));
    assert_eq!(seen_b, expected(&b));
}

#[test]
fn overlapping_sets_are_merged_in_timestamp_order() {
    let tmp = TempDir::new().unwrap();
    let opts = SplitOptions::new(SplitBy::Packets(9), Naming::Dumpcap);
    write_overlapping_sets(tmp.path(), 12, &opts).unwrap();
    let grouping = grouping(tmp.path(), false);
    assert_eq!(grouping.groups.len(), 2);
    let merged = ChunkGroup::merge(grouping.groups);
    assert_eq!(merged.kind, GroupKind::Merged);

    let (a, b) = two_interface_traffic(12);
    let mut all: Vec<Packet> = a.iter().chain(&b).cloned().collect();
    all.sort_by_key(|p| p.ts_ns);
    let (seen, source) = read(&merged);
    assert_eq!(seen.len(), a.len() + b.len());
    assert!(seen.windows(2).all(|w| w[0].0 <= w[1].0));
    assert_eq!(seen, expected(&all));
    assert!(
        source
            .anomalies()
            .iter()
            .all(|x| matches!(x.kind, AnomalyKind::Overlap { .. }))
    );
    assert_ne!(source.anomalies().len(), 0);
}

#[test]
fn overlapping_chunks_of_one_set_are_merged() {
    // Two interfaces captured into consecutive files of the same set.
    let (a, b) = two_interface_traffic(10);
    let packets: Vec<Packet> = a.iter().chain(&b).cloned().collect();
    let tmp = TempDir::new().unwrap();
    let opts = SplitOptions::new(SplitBy::At(vec![a.len()]), Naming::Dumpcap);
    split(tmp.path(), &packets, &opts);
    let group = only_group(tmp.path());
    let (seen, source) = read(&group);
    let mut sorted = packets.clone();
    sorted.sort_by_key(|p| p.ts_ns);
    assert_eq!(seen, expected(&sorted));
    assert_eq!(codes(source.anomalies()), vec![(Some(1), "overlap")]);
}

#[test]
fn timestamps_going_backwards_are_kept_and_reported() {
    let mut packets = traffic();
    packets[5].ts_ns = packets[3].ts_ns - 1000;
    let tmp = TempDir::new().unwrap();
    let opts = SplitOptions::new(SplitBy::At(vec![20]), Naming::Dumpcap)
        .with_encoding(Encoding::pcap_ns());
    split(tmp.path(), &packets, &opts);
    let group = only_group(tmp.path());
    let (seen, source) = read(&group);
    assert_eq!(seen, expected(&packets));
    assert_eq!(
        codes(source.anomalies()),
        vec![(Some(0), "timestamp_backwards")]
    );
}

#[test]
fn linktype_and_snaplen_changes_are_accepted() {
    let mut packets = traffic();
    for p in &mut packets[20..] {
        p.linktype = LINKTYPE_RAW;
    }
    let small_snaplen = Encoding::from(FileFormat::Pcap(PcapOptions {
        snaplen: 65_535,
        ..PcapOptions::default()
    }));
    let tmp = TempDir::new().unwrap();
    let opts = SplitOptions::new(SplitBy::At(vec![10, 20]), Naming::Dumpcap).with_encodings(vec![
        Encoding::pcap(),
        small_snaplen,
        Encoding::pcap(),
    ]);
    split(tmp.path(), &packets, &opts);
    let group = only_group(tmp.path());
    let (seen, source) = read(&group);
    assert_eq!(seen, expected(&packets));
    assert_eq!(
        codes(source.anomalies()),
        vec![
            (Some(1), "snaplen_change"),
            (Some(2), "linktype_change"),
            (Some(2), "snaplen_change"),
        ]
    );
    assert_eq!(source.info().linktypes, vec![1, LINKTYPE_RAW]);
}

#[test]
fn inventory_options_and_rejected_files() {
    let packets = traffic();
    let tmp = TempDir::new().unwrap();
    let top = tmp.path().join("top.pcap");
    write_file(&top, &packets, &Encoding::pcap()).unwrap();
    fs::write(tmp.path().join("README.md"), b"not a capture at all").unwrap();
    // pcap magic but truncated global header: unreadable, not fatal.
    fs::write(
        tmp.path().join("cut.pcap"),
        [0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0],
    )
    .unwrap();
    let sub = tmp.path().join("nested");
    fs::create_dir(&sub).unwrap();
    write_file(&sub.join("deep.pcapng"), &packets, &Encoding::pcapng()).unwrap();

    let flat = chunkset::inventory(tmp.path(), &InventoryOptions::default()).unwrap();
    let found: Vec<_> = flat.entries.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(found, vec!["README.md", "cut.pcap", "top.pcap"]);
    assert!(matches!(flat.entries[0].kind, EntryKind::Unrecognized));
    assert!(matches!(flat.entries[1].kind, EntryKind::Unreadable { .. }));
    let top_entry = &flat.entries[2];
    assert_eq!(top_entry.size, fs::metadata(&top).unwrap().len());
    assert!(top_entry.mtime_ns.is_some());
    assert_eq!(top_entry.first_ts(), Some(packets[0].ts_ns));
    let meta = top_entry.capture().unwrap();
    assert_eq!(meta.info.linktypes, vec![1]);
    assert_eq!(meta.info.snaplen, Some(262_144));
    assert_eq!(meta.scan, None);
    assert_eq!(top_entry.fingerprint.unwrap().to_hex().len(), 64);

    let deep = chunkset::inventory(
        tmp.path(),
        &InventoryOptions {
            recursive: true,
            full_scan: true,
        },
    )
    .unwrap();
    assert_eq!(deep.entries.len(), 4);
    let scanned = deep
        .entries
        .iter()
        .find(|e| e.name == "deep.pcapng")
        .unwrap();
    let scan = scanned.capture().unwrap().scan.as_ref().unwrap();
    assert_eq!(scan.packets, packets.len() as u64);
    assert_eq!(scan.last_ts, Some(packets.last().unwrap().ts_ns));
    // Fallback groups are per directory.
    let grouping = chunkset::group(&deep);
    assert_eq!(grouping.groups.len(), 2);
    assert_eq!(grouping.ungrouped.len(), 2);

    // A file path inventories that file only.
    let one = chunkset::inventory(&top, &InventoryOptions::default()).unwrap();
    assert_eq!(one.entries.len(), 1);
    assert!(
        chunkset::inventory(&tmp.path().join("missing"), &InventoryOptions::default()).is_err()
    );
}

#[test]
fn full_scan_previews_timing_anomalies() {
    let mut packets = traffic();
    for p in &mut packets[25..] {
        p.ts_ns += 60 * SEC;
    }
    let tmp = TempDir::new().unwrap();
    let opts = SplitOptions::new(SplitBy::At(vec![25]), Naming::Dumpcap);
    let paths = split(tmp.path(), &packets, &opts);
    truncate_last_packet(&paths[1]).unwrap();
    let options = InventoryOptions {
        full_scan: true,
        ..InventoryOptions::default()
    };
    let inventory = chunkset::inventory(tmp.path(), &options).unwrap();
    let group = chunkset::group(&inventory).groups.remove(0);
    let preview = group.anomalies(&ContinuityConfig::default());
    assert_eq!(
        codes(&preview),
        vec![(Some(1), "truncated_tail"), (Some(1), "time_gap")]
    );
    // The import finds the same anomalies.
    let (_, source) = read(&group);
    assert_eq!(codes(source.anomalies()), codes(&preview));
}
