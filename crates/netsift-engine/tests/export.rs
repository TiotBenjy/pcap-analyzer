//! "Save PCAP" export: round trip through the capture reader, single file versus chunks, flow
//! and range selections, mixed link types, source checks and cleanup of the partial file.

use std::fs;
use std::path::{Path, PathBuf};

use netsift_capture::{RawPacket, ReadWarning, reader};
use netsift_engine::{
    CancelToken, ExportError, ExportSelection, IngestOptions, IngestReport, ingest, plan_export,
};
use netsift_fixtures::craft::{self, FragSpec, Side, TcpConv};
use netsift_fixtures::scenarios::hosts;
use netsift_fixtures::{
    Encoding, Host, LINKTYPE_RAW, Naming, Packet, SplitBy, SplitOptions, split_to_dir, write_file,
};
use netsift_store::{Catalog, OpenMode, Session, SessionState};
use tempfile::TempDir;

const T0: i64 = 1_700_000_000_000_000_000;
const MS: i64 = 1_000_000;

fn server() -> Host {
    hosts::web_server()
}

/// Frames of each test flow, to compare with the exports.
struct Traffic {
    packets: Vec<Packet>,
    /// Flow A: TCP 40000 -> 80, both directions.
    flow_a: Vec<Vec<u8>>,
    /// Fragmented UDP datagram 6000 -> 7000 (one flow), fragments included.
    flow_frag: Vec<Vec<u8>>,
}

fn traffic() -> Traffic {
    let ws = hosts::workstation();
    let a = TcpConv::new(ws, server(), 40_000, 80);
    // Same hosts, same server port: must never leak into flow A.
    let b = TcpConv::new(ws, server(), 40_001, 80);
    let mut frames: Vec<(char, Vec<u8>)> = vec![
        ('a', a.syn()),
        ('a', a.syn_ack()),
        ('b', b.syn()),
        ('b', b.syn_ack()),
    ];
    let body = [b'x'; 200];
    for i in 0..60u64 {
        frames.push(('a', a.data(Side::Client, i * 200, 0, &body)));
        frames.push(('b', b.data(Side::Client, i * 200, 0, &body)));
        frames.push(('a', a.ack(Side::Server, 0, (i + 1) * 200)));
        frames.push((
            'c',
            craft::udp_frame(&ws, &server(), 5353, 53, &[u8::try_from(i).unwrap(); 40]),
        ));
        if i == 30 {
            let datagram = craft::udp_frame(&ws, &server(), 6000, 7000, &[7u8; 300]);
            let payload = craft::ip_payload(&datagram).unwrap().to_vec();
            for f in craft::fragment_frames(&datagram, 0x4242, &FragSpec::even(&payload, 128)) {
                frames.push(('f', f));
            }
        }
    }
    frames.push(('a', a.fin(Side::Client, 60 * 200, 0)));
    frames.push(('a', a.fin(Side::Server, 0, 60 * 200 + 1)));
    let mut packets = Vec::new();
    let (mut flow_a, mut flow_frag) = (Vec::new(), Vec::new());
    for (i, (kind, data)) in frames.into_iter().enumerate() {
        match kind {
            'a' => flow_a.push(data.clone()),
            'f' => flow_frag.push(data.clone()),
            _ => {}
        }
        packets.push(craft::packet(T0 + i64::try_from(i).unwrap() * MS, data));
    }
    Traffic {
        packets,
        flow_a,
        flow_frag,
    }
}

fn import(catalog: &Catalog, input: &Path) -> IngestReport {
    let options = IngestOptions {
        shards: Some(2),
        ..IngestOptions::default()
    };
    let report = ingest(catalog, input, &options, &CancelToken::new(), &mut |_| {}).unwrap();
    assert_eq!(report.state, SessionState::Ready);
    report
}

fn session(catalog: &Catalog, report: &IngestReport) -> Session {
    catalog
        .open_session(&report.session, OpenMode::ReadOnly)
        .unwrap()
}

fn export(session: &Session, selection: ExportSelection, dest: &Path) -> Vec<RawPacket> {
    let plan = plan_export(session, &selection).unwrap();
    let mut calls = 0;
    let report = plan
        .run(dest, &CancelToken::new(), &mut |_| calls += 1)
        .unwrap();
    assert!(calls >= 1, "final progress");
    let packets = read(dest);
    assert_eq!(report.packets, u64::try_from(packets.len()).unwrap());
    assert_eq!(report.bytes_written, fs::metadata(dest).unwrap().len());
    assert!(!netsift_engine::export::part_path(dest).exists());
    packets
}

fn read(path: &Path) -> Vec<RawPacket> {
    let mut source = reader::open(path).unwrap();
    let mut out = Vec::new();
    while let Some(p) = source.next_packet().unwrap() {
        out.push(p);
    }
    // The export keeps the read order: a source whose timestamps go backwards gives a file
    // whose timestamps go backwards the same way. Nothing else is tolerated.
    let other: Vec<_> = source
        .warnings()
        .iter()
        .filter(|w| !matches!(w, ReadWarning::TimestampBackwards { .. }))
        .collect();
    assert!(other.is_empty(), "{other:?}");
    out
}

fn flow_id(session: &Session, sport: u16, dport: u16, transport: u8) -> u64 {
    session
        .conn()
        .query_row(
            "SELECT id FROM flows WHERE src_port = ?1 AND dst_port = ?2 AND transport = ?3",
            (sport, dport, transport),
            |r| r.get(0),
        )
        .unwrap()
}

fn chunks_dir(tmp: &TempDir, packets: &[Packet]) -> (PathBuf, Vec<PathBuf>) {
    let dir = tmp.path().join("chunks");
    let opts = SplitOptions::new(SplitBy::Size(8 * 1024), Naming::Dumpcap).with_encodings(vec![
        Encoding::pcapng(),
        Encoding::pcap_ns(),
        Encoding::pcapng().gz(),
        Encoding::pcap().zst(),
        Encoding::pcapng().lz4(),
    ]);
    let files = split_to_dir(&dir, packets, &opts).unwrap().1;
    assert!(files.len() >= 5, "{} chunks", files.len());
    (dir, files)
}

fn summary(packets: &[RawPacket]) -> Vec<(i64, u32, Vec<u8>)> {
    packets
        .iter()
        .map(|p| (p.ts_ns, p.linktype, p.data.to_vec()))
        .collect()
}

#[test]
fn session_export_round_trips_and_matches_for_a_file_and_its_chunks() {
    let tmp = TempDir::new().unwrap();
    let catalog = Catalog::open(tmp.path().join("data")).unwrap();
    let t = traffic();
    let single = tmp.path().join("single.pcap");
    write_file(&single, &t.packets, &Encoding::pcap_ns()).unwrap();
    let (dir, _) = chunks_dir(&tmp, &t.packets);

    let out = tmp.path().join("out");
    fs::create_dir(&out).unwrap();
    let from_file = export(
        &session(&catalog, &import(&catalog, &single)),
        ExportSelection::Session,
        &out.join("file.pcapng"),
    );
    let from_chunks = export(
        &session(&catalog, &import(&catalog, &dir)),
        ExportSelection::Session,
        &out.join("chunks.pcapng"),
    );
    let expected: Vec<_> = t
        .packets
        .iter()
        .map(|p| (p.ts_ns, p.linktype, p.data.clone()))
        .collect();
    assert_eq!(summary(&from_file), expected);
    assert_eq!(summary(&from_chunks), expected);
    for p in &from_file {
        assert_eq!(p.orig_len, u32::try_from(p.data.len()).unwrap());
    }
}

#[test]
fn flow_export_keeps_both_directions_and_nothing_else() {
    let tmp = TempDir::new().unwrap();
    let catalog = Catalog::open(tmp.path().join("data")).unwrap();
    let t = traffic();
    let (dir, _) = chunks_dir(&tmp, &t.packets);
    let session = session(&catalog, &import(&catalog, &dir));

    let a = flow_id(&session, 40_000, 80, 6);
    let got = export(
        &session,
        ExportSelection::Flow { id: a },
        &tmp.path().join("a.pcapng"),
    );
    let data: Vec<Vec<u8>> = got.iter().map(|p| p.data.to_vec()).collect();
    assert_eq!(data, t.flow_a);
    assert!(got.windows(2).all(|w| w[0].ts_ns <= w[1].ts_ns));

    // The fragments of a datagram follow their first fragment.
    let frag = flow_id(&session, 6000, 7000, 17);
    let got = export(
        &session,
        ExportSelection::Flow { id: frag },
        &tmp.path().join("f.pcapng"),
    );
    let data: Vec<Vec<u8>> = got.iter().map(|p| p.data.to_vec()).collect();
    assert_eq!(data, t.flow_frag);
    assert!(data.len() >= 3);

    // No session reaches i64::MAX flows or frames: never an existing id.
    let missing = u64::try_from(i64::MAX).unwrap();
    let err = plan_export(&session, &ExportSelection::Flow { id: missing }).unwrap_err();
    assert!(
        matches!(err, ExportError::FlowNotFound(id) if id == missing),
        "{err}"
    );
}

#[test]
fn range_export_is_inclusive_at_both_bounds() {
    let tmp = TempDir::new().unwrap();
    let catalog = Catalog::open(tmp.path().join("data")).unwrap();
    let t = traffic();
    let (dir, _) = chunks_dir(&tmp, &t.packets);
    let session = session(&catalog, &import(&catalog, &dir));

    let (from_ns, to_ns) = (T0 + 37 * MS, T0 + 180 * MS);
    let got = export(
        &session,
        ExportSelection::Range { from_ns, to_ns },
        &tmp.path().join("r.pcapng"),
    );
    let expected: Vec<i64> = t
        .packets
        .iter()
        .map(|p| p.ts_ns)
        .filter(|ts| (from_ns..=to_ns).contains(ts))
        .collect();
    let ts: Vec<i64> = got.iter().map(|p| p.ts_ns).collect();
    assert_eq!(ts, expected);
    assert_eq!(ts.first(), Some(&from_ns));
    assert_eq!(ts.last(), Some(&to_ns));

    // One nanosecond inside each bound drops both edge packets.
    let got = export(
        &session,
        ExportSelection::Range {
            from_ns: from_ns + 1,
            to_ns: to_ns - 1,
        },
        &tmp.path().join("r2.pcapng"),
    );
    assert_eq!(got.len(), expected.len() - 2);

    // Before the capture: a valid, empty file.
    let got = export(
        &session,
        ExportSelection::Range {
            from_ns: 0,
            to_ns: 1,
        },
        &tmp.path().join("r3.pcapng"),
    );
    assert_eq!(got.len(), 0);

    let err = plan_export(
        &session,
        &ExportSelection::Range {
            from_ns: 2,
            to_ns: 1,
        },
    )
    .unwrap_err();
    assert!(matches!(err, ExportError::InvalidRange));
}

#[test]
fn chunks_with_different_link_types_give_one_valid_file() {
    let tmp = TempDir::new().unwrap();
    let catalog = Catalog::open(tmp.path().join("data")).unwrap();
    let t = traffic();
    let (eth, raw) = t.packets.split_at(t.packets.len() / 2);
    // Second half as raw IP (link type 101): Ethernet header removed.
    let raw: Vec<Packet> = raw
        .iter()
        .map(|p| Packet {
            linktype: LINKTYPE_RAW,
            data: p.data[14..].to_vec(),
            ..p.clone()
        })
        .collect();
    let dir = tmp.path().join("mixed");
    fs::create_dir(&dir).unwrap();
    write_file(
        &dir.join("cap_00001_20231114221320.pcap"),
        eth,
        &Encoding::pcap(),
    )
    .unwrap();
    write_file(
        &dir.join("cap_00002_20231114221321.pcapng"),
        &raw,
        &Encoding::pcapng(),
    )
    .unwrap();
    let session = session(&catalog, &import(&catalog, &dir));
    let dest = tmp.path().join("mixed.pcapng");
    let got = export(&session, ExportSelection::Session, &dest);
    assert_eq!(got.len(), t.packets.len());
    let mut source = reader::open(&dest).unwrap();
    while source.next_packet().unwrap().is_some() {}
    assert_eq!(source.info().linktypes, vec![1, LINKTYPE_RAW]);
    assert!(got[..eth.len()].iter().all(|p| p.linktype == 1));
    assert!(got[eth.len()..].iter().all(|p| p.linktype == LINKTYPE_RAW));
    // Microseconds in the pcap source, nanoseconds kept as such.
    assert_eq!(got[eth.len()].ts_ns, raw[0].ts_ns);
}

fn only_files(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

#[test]
fn missing_or_modified_sources_are_refused_without_leaving_a_file() {
    let tmp = TempDir::new().unwrap();
    let catalog = Catalog::open(tmp.path().join("data")).unwrap();
    let t = traffic();
    let (dir, files) = chunks_dir(&tmp, &t.packets);
    let session = session(&catalog, &import(&catalog, &dir));
    let out = tmp.path().join("out");
    fs::create_dir(&out).unwrap();
    let dest = out.join("x.pcapng");

    // A range inside the first chunk does not need the last one.
    let last = files.last().unwrap();
    let saved = fs::read(last).unwrap();
    fs::remove_file(last).unwrap();
    let first_range = ExportSelection::Range {
        from_ns: T0,
        to_ns: T0 + 2 * MS,
    };
    assert_eq!(export(&session, first_range, &dest).len(), 3);
    fs::remove_file(&dest).unwrap();
    let err = plan_export(&session, &ExportSelection::Session).unwrap_err();
    assert!(
        matches!(&err, ExportError::SourceMissing { name, .. } if Path::new(last).ends_with(name)),
        "{err}"
    );

    // Same size, other content.
    let mut changed = saved.clone();
    let n = changed.len();
    changed[n - 10] ^= 0xff;
    fs::write(last, &changed).unwrap();
    let err = plan_export(&session, &ExportSelection::Session).unwrap_err();
    assert!(matches!(err, ExportError::SourceModified { .. }), "{err}");

    // Original bytes back, but the modification time changed with the rewrite: still refused.
    fs::write(last, &saved).unwrap();
    let err = plan_export(&session, &ExportSelection::Session).unwrap_err();
    assert!(
        matches!(err, ExportError::SourceModified { what, .. } if what == "modification time"),
        "{err}"
    );
    assert_eq!(only_files(&out), Vec::<String>::new());
}

#[test]
fn a_source_changed_during_the_export_or_a_cancellation_leaves_nothing() {
    let tmp = TempDir::new().unwrap();
    let catalog = Catalog::open(tmp.path().join("data")).unwrap();
    let t = traffic();
    let (dir, files) = chunks_dir(&tmp, &t.packets);
    let session = session(&catalog, &import(&catalog, &dir));
    let out = tmp.path().join("out");
    fs::create_dir(&out).unwrap();
    let dest = out.join("x.pcapng");

    let plan = plan_export(&session, &ExportSelection::Session).unwrap();
    assert_eq!(plan.chunks(), files.len());
    assert!(plan.total_bytes() > 0);
    let mut bytes = fs::read(&files[0]).unwrap();
    bytes.extend_from_slice(&[0; 4]);
    fs::write(&files[0], &bytes).unwrap();
    let err = plan
        .run(&dest, &CancelToken::new(), &mut |_| {})
        .unwrap_err();
    assert!(matches!(err, ExportError::SourceModified { .. }), "{err}");
    assert_eq!(only_files(&out), Vec::<String>::new());

    let again = tmp.path().join("again");
    let opts = SplitOptions::new(SplitBy::Size(8 * 1024), Naming::Dumpcap);
    split_to_dir(&again, &t.packets, &opts).unwrap();
    let session2 = self::session(&catalog, &import(&catalog, &again));
    let plan = plan_export(&session2, &ExportSelection::Session).unwrap();
    let cancel = CancelToken::new();
    cancel.cancel();
    let err = plan.run(&dest, &cancel, &mut |_| {}).unwrap_err();
    assert!(matches!(err, ExportError::Cancelled));
    assert_eq!(only_files(&out), Vec::<String>::new());

    // An existing destination is never overwritten.
    fs::write(&dest, b"keep").unwrap();
    let plan = plan_export(&session2, &ExportSelection::Session).unwrap();
    let err = plan
        .run(&dest, &CancelToken::new(), &mut |_| {})
        .unwrap_err();
    assert!(matches!(err, ExportError::DestinationExists(_)));
    assert_eq!(fs::read(&dest).unwrap(), b"keep");
    assert_eq!(only_files(&out), ["x.pcapng"]);
}

fn flow_packets(session: &Session, id: u64) -> u64 {
    session
        .conn()
        .query_row(
            "SELECT packets_fwd + packets_rev FROM flows WHERE id = ?1",
            [i64::try_from(id).unwrap()],
            |r| r.get(0),
        )
        .unwrap()
}

#[test]
fn timestamps_going_backwards_lose_no_packet() {
    let tmp = TempDir::new().unwrap();
    let catalog = Catalog::open(tmp.path().join("data")).unwrap();
    let ws = hosts::workstation();
    let a = TcpConv::new(ws, server(), 40_000, 80);
    let noise = |i: u8| craft::udp_frame(&ws, &server(), 5353, 53, &[i; 20]);
    // File order with timestamps (ms after T0) going backwards twice: the SYN-ACK of flow A is
    // older than its SYN, and a data segment comes after a later UDP packet.
    let frames: Vec<(i64, Vec<u8>)> = vec![
        (100, a.syn()),
        (110, noise(1)),
        (90, a.syn_ack()),
        (300, noise(2)),
        (150, a.data(Side::Client, 0, 0, b"hello")),
        (310, a.ack(Side::Server, 0, 5)),
        (320, noise(3)),
    ];
    let packets: Vec<Packet> = frames
        .iter()
        .map(|(ms, data)| craft::packet(T0 + ms * MS, data.clone()))
        .collect();
    let input = tmp.path().join("backwards.pcap");
    write_file(&input, &packets, &Encoding::pcap_ns()).unwrap();
    let session = session(&catalog, &import(&catalog, &input));

    let id = flow_id(&session, 40_000, 80, 6);
    let got = export(
        &session,
        ExportSelection::Flow { id },
        &tmp.path().join("a.pcapng"),
    );
    assert_eq!(
        u64::try_from(got.len()).unwrap(),
        flow_packets(&session, id)
    );
    let data: Vec<Vec<u8>> = got.iter().map(|p| p.data.to_vec()).collect();
    let expected: Vec<Vec<u8>> = [0, 2, 4, 5].iter().map(|&i| frames[i].1.clone()).collect();
    assert_eq!(data, expected);

    // The packet at 150 ms comes after one at 300 ms: the read must not stop there.
    let got = export(
        &session,
        ExportSelection::Range {
            from_ns: T0,
            to_ns: T0 + 200 * MS,
        },
        &tmp.path().join("r.pcapng"),
    );
    let ts: Vec<i64> = got.iter().map(|p| (p.ts_ns - T0) / MS).collect();
    assert_eq!(ts, [100, 110, 90, 150]);
}

#[test]
fn overlapping_and_duplicated_chunks_export_like_the_single_file() {
    let tmp = TempDir::new().unwrap();
    let catalog = Catalog::open(tmp.path().join("data")).unwrap();
    let t = traffic();
    // Two "interfaces" captured over the same period (k-way merge), plus a copy of the first.
    let even: Vec<Packet> = t.packets.iter().step_by(2).cloned().collect();
    let odd: Vec<Packet> = t.packets.iter().skip(1).step_by(2).cloned().collect();
    let dir = tmp.path().join("overlap");
    fs::create_dir(&dir).unwrap();
    let first = dir.join("cap_00001_20231114221320.pcapng");
    write_file(&first, &even, &Encoding::pcapng()).unwrap();
    write_file(
        &dir.join("cap_00002_20231114221320.pcap"),
        &odd,
        &Encoding::pcap_ns(),
    )
    .unwrap();
    fs::copy(&first, dir.join("cap_00003_20231114221320.pcapng")).unwrap();
    let session = session(&catalog, &import(&catalog, &dir));
    let kinds: Vec<String> = {
        let mut stmt = session
            .conn()
            .prepare("SELECT kind FROM anomalies")
            .unwrap();
        stmt.query_map([], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    };
    assert!(kinds.iter().any(|k| k == "overlap"), "{kinds:?}");
    assert!(kinds.iter().any(|k| k == "duplicate"), "{kinds:?}");

    let got = export(
        &session,
        ExportSelection::Session,
        &tmp.path().join("s.pcapng"),
    );
    let expected: Vec<_> = t
        .packets
        .iter()
        .map(|p| (p.ts_ns, p.linktype, p.data.clone()))
        .collect();
    assert_eq!(summary(&got), expected);

    let a = flow_id(&session, 40_000, 80, 6);
    let got = export(
        &session,
        ExportSelection::Flow { id: a },
        &tmp.path().join("a.pcapng"),
    );
    let data: Vec<Vec<u8>> = got.iter().map(|p| p.data.to_vec()).collect();
    assert_eq!(data, t.flow_a);
}

#[test]
fn read_errors_in_an_unchanged_source_are_reported() {
    let tmp = TempDir::new().unwrap();
    let catalog = Catalog::open(tmp.path().join("data")).unwrap();
    let ws = hosts::workstation();
    let packets: Vec<Packet> = (0..300)
        .map(|i| {
            let frame = craft::udp_frame(&ws, &server(), 5353, 53, &[7; 500]);
            craft::packet(T0 + i * MS, frame)
        })
        .collect();
    let input = tmp.path().join("big.pcap");
    write_file(&input, &packets, &Encoding::pcap()).unwrap();
    let session = session(&catalog, &import(&catalog, &input));

    // Corrupt the length of a record beyond the fingerprinted 64 KiB, size and date kept.
    let mtime = fs::metadata(&input).unwrap().modified().unwrap();
    let mut bytes = fs::read(&input).unwrap();
    let mut offset = 24;
    let mut index = 0;
    while offset < 70_000 {
        offset += 16 + packets[index].data.len();
        index += 1;
    }
    bytes[offset + 8..offset + 12].copy_from_slice(&u32::MAX.to_le_bytes());
    fs::write(&input, &bytes).unwrap();
    fs::File::options()
        .write(true)
        .open(&input)
        .unwrap()
        .set_modified(mtime)
        .unwrap();

    let dest = tmp.path().join("x.pcapng");
    let report = plan_export(&session, &ExportSelection::Session)
        .unwrap()
        .run(&dest, &CancelToken::new(), &mut |_| {})
        .unwrap();
    assert_eq!(report.read_errors, 1);
    assert_eq!(report.packets, u64::try_from(index).unwrap());
    assert_eq!(read(&dest).len(), index);
}
