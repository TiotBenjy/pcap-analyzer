//! End-to-end imports of synthetic captures (`netsift-fixtures`), including the acceptance
//! test of `docs/CHUNKED_CAPTURES.md`: a single file and the same traffic split into chunks
//! produce identical `timeseries`, `hosts` and `flows` tables.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use netsift_analyze::dissect::Decoded;
use netsift_analyze::flow::PacketCtx;
use netsift_analyze::{Analyzer, AnalyzerId, RecordSink, Registry};
use netsift_capture::chunkset::Opener;
use netsift_capture::{CaptureError, CaptureInfo, PacketSource, RawPacket, ReadWarning, reader};
use netsift_engine::{
    ANALYZER_PANICKED, CancelToken, EngineError, GroupSelection, INTERRUPTED_DETAIL, IngestOptions,
    IngestReport, Phase, Progress, ingest, recover_interrupted,
};
use netsift_fixtures::anomaly::{
    CrossChunkCase, dns_across_chunks, http_request_across_chunks, mixed_encodings, remove_chunk,
    write_two_prefixes,
};
use netsift_fixtures::scenarios::hosts;
use netsift_fixtures::scenarios::{Kind, generate};
use netsift_fixtures::{
    Encoding, Naming, Packet, Scenario, SplitBy, SplitOptions, split_to_dir, write_file,
};
use netsift_store::query::get_meta;
use netsift_store::{Catalog, OpenMode, Session, SessionState};
use tempfile::TempDir;

/// Mixed traffic (NBNS, DNS v4/v6, HTTP with an image, TLS, SMB browser, SNMP, FTP), 8 rounds
/// one second apart.
fn traffic() -> Vec<Packet> {
    generate(Kind::Demo, 8, 7)
}

/// Comparable content of the tables produced by the analyzers, one line per row.
#[derive(Debug, PartialEq, Eq)]
struct Tables {
    timeseries: Vec<String>,
    hosts: Vec<String>,
    flows: Vec<String>,
}

impl Tables {
    fn render(&self) -> String {
        let mut s = String::new();
        for (name, rows) in [
            ("timeseries", &self.timeseries),
            ("hosts", &self.hosts),
            ("flows", &self.flows),
        ] {
            writeln!(s, "# {name} ({} rows)", rows.len()).unwrap();
            for r in rows {
                s.push_str(r);
                s.push('\n');
            }
        }
        s
    }
}

fn rows(session: &Session, sql: &str) -> Vec<String> {
    let mut stmt = session.conn().prepare(sql).unwrap();
    stmt.query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

fn tables(catalog: &Catalog, report: &IngestReport) -> Tables {
    let session = catalog
        .open_session(&report.session, OpenMode::ReadOnly)
        .unwrap();
    let conn = &session;
    Tables {
        timeseries: rows(
            conn,
            "SELECT bucket_s || ' ' || proto || ' bytes=' || bytes || ' packets=' || packets \
             FROM timeseries ORDER BY bucket_s, proto",
        ),
        hosts: rows(
            conn,
            "SELECT ip || ' macs=' || macs || ' names=' || names || ' country=' || \
             coalesce(country, '-') || ' category=' || coalesce(category, '-') || ' ' || \
             first_ts || '..' || last_ts FROM hosts ORDER BY ip",
        ),
        flows: rows(
            conn,
            "SELECT id || ' ' || transport || ' ' || src_ip || ':' || src_port || ' -> ' || \
             dst_ip || ':' || dst_port || ' ' || first_ts || '..' || last_ts || \
             ' fwd=' || packets_fwd || '/' || bytes_fwd || ' rev=' || packets_rev || '/' || \
             bytes_rev || ' app=' || coalesce(app_proto, '-') || ' tcp=' || \
             coalesce(tcp_state, '-') FROM flows ORDER BY id",
        ),
    }
}

fn scalar(catalog: &Catalog, report: &IngestReport, sql: &str) -> i64 {
    let session = catalog
        .open_session(&report.session, OpenMode::ReadOnly)
        .unwrap();
    session.conn().query_row(sql, [], |r| r.get(0)).unwrap()
}

fn n(v: usize) -> i64 {
    i64::try_from(v).unwrap()
}

fn options(shards: usize) -> IngestOptions {
    IngestOptions {
        shards: Some(shards),
        ..IngestOptions::default()
    }
}

fn run(catalog: &Catalog, input: &Path, options: &IngestOptions) -> IngestReport {
    ingest(catalog, input, options, &CancelToken::new(), &mut |_| {}).unwrap()
}

fn state(catalog: &Catalog, report: &IngestReport) -> SessionState {
    catalog.get(&report.session).unwrap().unwrap().state
}

/// Writes `packets` as chunks of at most 16 KiB.
fn split(dir: &Path, packets: &[Packet], naming: Naming, encodings: Vec<Encoding>) -> Vec<PathBuf> {
    let opts = SplitOptions::new(SplitBy::Size(16 * 1024), naming).with_encodings(encodings);
    split_to_dir(dir, packets, &opts).unwrap().1
}

#[test]
fn single_file_and_chunks_give_identical_tables() {
    let tmp = TempDir::new().unwrap();
    let catalog = Catalog::open(tmp.path().join("data")).unwrap();
    let packets = traffic();

    let single = tmp.path().join("single.pcapng");
    write_file(&single, &packets, &Encoding::pcapng()).unwrap();
    let reference = run(&catalog, &single, &options(3));
    assert_eq!(reference.state, SessionState::Ready);
    assert_eq!(reference.chunks, 1);
    assert_eq!(reference.packets, packets.len() as u64);
    let expected = tables(&catalog, &reference);
    assert_ne!(expected.timeseries.len(), 0);
    assert_ne!(expected.hosts.len(), 0);
    assert_ne!(expected.flows.len(), 0);
    for shards in [1, 4, 7] {
        let again = run(&catalog, &single, &options(shards));
        assert_eq!(
            tables(&catalog, &again),
            expected,
            "single file, {shards} shards"
        );
    }
    insta::assert_snapshot!("reference_tables", expected.render());

    let sets = [
        ("dumpcap", Naming::Dumpcap, vec![Encoding::pcapng()]),
        ("tcpdump", Naming::TcpdumpC, vec![Encoding::pcap()]),
        ("nametimenum", Naming::DumpcapNameTimeNum, mixed_encodings()),
    ];
    for ((name, naming, encodings), shards) in sets.into_iter().zip([1, 4, 7]) {
        let dir = tmp.path().join(name);
        let files = split(&dir, &packets, naming, encodings);
        assert!(files.len() > 3, "{name}: {} chunks", files.len());
        let report = run(&catalog, &dir, &options(shards));
        assert_eq!(report.state, SessionState::Ready, "{name}");
        assert_eq!(report.chunks_read, files.len(), "{name}");
        assert_eq!(report.packets, packets.len() as u64, "{name}");
        assert_eq!(tables(&catalog, &report), expected, "{name}");
        // Chunks and anomalies differ naturally; the chunk rows must describe every file.
        let chunk_rows = scalar(&catalog, &report, "SELECT count(*) FROM chunks");
        assert_eq!(chunk_rows, n(files.len()), "{name}");
        let chunk_packets = scalar(&catalog, &report, "SELECT sum(packets) FROM chunks");
        assert_eq!(chunk_packets, n(packets.len()), "{name}");
    }
}

#[test]
fn tables_do_not_depend_on_shard_count_nor_on_the_run() {
    let tmp = TempDir::new().unwrap();
    let catalog = Catalog::open(tmp.path().join("data")).unwrap();
    let dir = tmp.path().join("chunks");
    split(&dir, &traffic(), Naming::Dumpcap, vec![Encoding::pcapng()]);

    let one = run(&catalog, &dir, &options(1));
    let again = run(&catalog, &dir, &options(1));
    let four = run(&catalog, &dir, &options(4));
    let small_batches = run(
        &catalog,
        &dir,
        &IngestOptions {
            shards: Some(7),
            batch_packets: 3,
            channel_batches: 1,
            record_batch: 1,
            ..IngestOptions::default()
        },
    );
    assert_eq!(one.shards, 1);
    assert_eq!(four.shards, 4);
    let reference = tables(&catalog, &one);
    for report in [&again, &four, &small_batches] {
        assert_eq!(tables(&catalog, report), reference);
    }
}

#[test]
fn single_file_input() {
    let tmp = TempDir::new().unwrap();
    let catalog = Catalog::open(tmp.path().join("data")).unwrap();
    let packets = traffic();
    let file = tmp.path().join("capture.pcap.gz");
    write_file(&file, &packets, &Encoding::pcap().gz()).unwrap();

    let report = run(&catalog, &file, &IngestOptions::default());
    assert_eq!(report.state, SessionState::Ready);
    assert_eq!(state(&catalog, &report), SessionState::Ready);
    assert_eq!((report.chunks, report.chunks_read), (1, 1));
    assert_eq!(report.packets, packets.len() as u64);
    assert_eq!(report.anomalies, 0);
    assert!(report.hosts > 0);
    assert_eq!(report.name, "capture");

    let ts_packets = scalar(&catalog, &report, "SELECT sum(packets) FROM timeseries");
    assert_eq!(ts_packets, n(packets.len()));
    let ts_bytes = scalar(&catalog, &report, "SELECT sum(bytes) FROM timeseries");
    assert_eq!(
        ts_bytes,
        packets.iter().map(|p| n(p.data.len())).sum::<i64>()
    );
    let status_ok = scalar(
        &catalog,
        &report,
        "SELECT count(*) FROM chunks WHERE status = 'ok' AND format = 'pcap' AND compressed = 1",
    );
    assert_eq!(status_ok, 1);

    let session = catalog
        .open_session(&report.session, OpenMode::ReadOnly)
        .unwrap();
    let meta = |k: &str| get_meta(session.conn(), k).unwrap();
    assert_eq!(meta("import.state").as_deref(), Some("ready"));
    assert_eq!(meta("stats.packets"), Some(packets.len().to_string()));
    // Every built-in analyzer, `core` first.
    let analyzers = meta("import.analyzers").unwrap_or_default();
    assert_eq!(analyzers.split(',').next(), Some("core"), "{analyzers}");
    let info = catalog.get(&report.session).unwrap().unwrap();
    assert_eq!(info.sources, vec![std::fs::canonicalize(&file).unwrap()]);
    assert!(info.session_bytes > 0);
}

#[test]
fn folder_with_several_groups_requires_a_choice() {
    let tmp = TempDir::new().unwrap();
    let catalog = Catalog::open(tmp.path().join("data")).unwrap();
    let dir = tmp.path().join("two");
    let a = generate(Kind::Dns, 6, 1);
    let b = generate(Kind::Http, 3, 2);
    let opts = SplitOptions::new(SplitBy::Packets(10), Naming::Dumpcap);
    write_two_prefixes(&dir, ("left", &a), ("right", &b), &opts).unwrap();

    let err = ingest(
        &catalog,
        &dir,
        &IngestOptions::default(),
        &CancelToken::new(),
        &mut |_| {},
    )
    .unwrap_err();
    let EngineError::MultipleGroups { groups, .. } = &err else {
        panic!("unexpected error: {err}");
    };
    assert_eq!(groups.len(), 2);
    let labels: Vec<_> = groups.iter().map(|g| g.label.as_str()).collect();
    assert_eq!(labels, ["left", "right"]);
    let message = err.to_string();
    assert!(
        message.contains("[0] left") && message.contains("[1] right"),
        "{message}"
    );
    assert_eq!(
        catalog.list().unwrap().len(),
        0,
        "no session for input errors"
    );

    let out_of_range = ingest(
        &catalog,
        &dir,
        &IngestOptions {
            selection: GroupSelection::Index(2),
            ..IngestOptions::default()
        },
        &CancelToken::new(),
        &mut |_| {},
    )
    .unwrap_err();
    assert!(matches!(
        out_of_range,
        EngineError::GroupOutOfRange { index: 2, .. }
    ));

    let right = run(
        &catalog,
        &dir,
        &IngestOptions {
            selection: GroupSelection::Index(1),
            ..IngestOptions::default()
        },
    );
    assert_eq!(right.packets, b.len() as u64);
    assert_eq!(right.group, "right");

    let all = run(
        &catalog,
        &dir,
        &IngestOptions {
            selection: GroupSelection::MergeAll,
            ..IngestOptions::default()
        },
    );
    assert_eq!(all.packets, (a.len() + b.len()) as u64);
    assert_eq!(catalog.list().unwrap().len(), 2);
}

#[test]
fn input_errors_create_no_session() {
    let tmp = TempDir::new().unwrap();
    let catalog = Catalog::open(tmp.path().join("data")).unwrap();
    let missing = ingest(
        &catalog,
        &tmp.path().join("nope"),
        &IngestOptions::default(),
        &CancelToken::new(),
        &mut |_| {},
    )
    .unwrap_err();
    assert!(matches!(missing, EngineError::Input { .. }), "{missing}");

    let junk = tmp.path().join("junk");
    std::fs::create_dir_all(&junk).unwrap();
    std::fs::write(junk.join("notes.txt"), b"not a capture at all").unwrap();
    let empty = ingest(
        &catalog,
        &junk,
        &IngestOptions::default(),
        &CancelToken::new(),
        &mut |_| {},
    )
    .unwrap_err();
    assert!(
        matches!(empty, EngineError::NoCapture { rejected: 1, .. }),
        "{empty}"
    );
    assert_eq!(catalog.list().unwrap().len(), 0);
}

#[test]
fn cancelled_before_start_gives_an_empty_incomplete_session() {
    let tmp = TempDir::new().unwrap();
    let catalog = Catalog::open(tmp.path().join("data")).unwrap();
    let dir = tmp.path().join("chunks");
    let files = split(&dir, &traffic(), Naming::Dumpcap, vec![Encoding::pcapng()]);
    let cancel = CancelToken::new();
    cancel.cancel();

    let report = ingest(
        &catalog,
        &dir,
        &IngestOptions::default(),
        &cancel,
        &mut |_| {},
    )
    .unwrap();
    assert_eq!(report.state, SessionState::Incomplete);
    assert_eq!(state(&catalog, &report), SessionState::Incomplete);
    assert_eq!(report.packets, 0);
    // Still browsable: every chunk is listed.
    assert_eq!(
        scalar(&catalog, &report, "SELECT count(*) FROM chunks"),
        n(files.len())
    );
    assert_eq!(
        scalar(&catalog, &report, "SELECT count(*) FROM timeseries"),
        0
    );
}

/// Source wrapper that cancels the import once `limit` packets have been read.
struct CancelAfter {
    inner: Box<dyn PacketSource>,
    read: Arc<AtomicU64>,
    limit: u64,
    cancel: CancelToken,
}

impl PacketSource for CancelAfter {
    fn info(&self) -> &CaptureInfo {
        self.inner.info()
    }

    fn next_packet(&mut self) -> Result<Option<RawPacket>, CaptureError> {
        let packet = self.inner.next_packet()?;
        if packet.is_some() && self.read.fetch_add(1, Ordering::SeqCst) + 1 >= self.limit {
            self.cancel.cancel();
        }
        Ok(packet)
    }

    fn bytes_read(&self) -> u64 {
        self.inner.bytes_read()
    }

    fn warnings(&self) -> &[ReadWarning] {
        self.inner.warnings()
    }
}

#[test]
fn cancelled_midway_keeps_what_was_read() {
    const LIMIT: u64 = 100;
    let tmp = TempDir::new().unwrap();
    let catalog = Catalog::open(tmp.path().join("data")).unwrap();
    let dir = tmp.path().join("chunks");
    let packets = traffic();
    split(&dir, &packets, Naming::Dumpcap, vec![Encoding::pcapng()]);

    let cancel = CancelToken::new();
    let read = Arc::new(AtomicU64::new(0));
    let opener: Arc<Opener> = {
        let cancel = cancel.clone();
        let read = read.clone();
        Arc::new(move |path: &Path| {
            let inner = reader::open(path)?;
            Ok(Box::new(CancelAfter {
                inner,
                read: read.clone(),
                limit: LIMIT,
                cancel: cancel.clone(),
            }) as Box<dyn PacketSource>)
        })
    };
    let options = IngestOptions {
        opener: Some(opener),
        ..options(2)
    };
    let mut phases = Vec::new();
    let report = ingest(&catalog, &dir, &options, &cancel, &mut |p: &Progress| {
        phases.push(p.phase);
    })
    .unwrap();
    assert!(LIMIT < packets.len() as u64);
    assert_eq!(report.state, SessionState::Incomplete);
    assert_eq!(state(&catalog, &report), SessionState::Incomplete);
    // The chunk-set reader looks one packet ahead: at most one packet read by the file
    // reader is not delivered.
    assert!(
        (LIMIT - 1..=LIMIT).contains(&report.packets),
        "{}",
        report.packets
    );
    assert_eq!(
        scalar(&catalog, &report, "SELECT sum(packets) FROM timeseries"),
        i64::try_from(report.packets).unwrap()
    );
    assert_eq!(phases.last(), Some(&Phase::Done));
    let session = catalog
        .open_session(&report.session, OpenMode::ReadOnly)
        .unwrap();
    assert_eq!(
        get_meta(session.conn(), "import.state").unwrap().as_deref(),
        Some("incomplete")
    );
}

#[test]
fn progress_reports_reading_then_finishing_then_done() {
    let tmp = TempDir::new().unwrap();
    let catalog = Catalog::open(tmp.path().join("data")).unwrap();
    let dir = tmp.path().join("chunks");
    let packets = traffic();
    let files = split(&dir, &packets, Naming::Dumpcap, vec![Encoding::pcapng()]);
    let mut seen: Vec<Progress> = Vec::new();
    let report = ingest(
        &catalog,
        &dir,
        &IngestOptions::default(),
        &CancelToken::new(),
        &mut |p: &Progress| seen.push(p.clone()),
    )
    .unwrap();
    let phases: Vec<Phase> = seen.iter().map(|p| p.phase).collect();
    assert_eq!(phases.first(), Some(&Phase::Reading));
    assert!(phases.contains(&Phase::Finishing));
    let done = seen.last().unwrap();
    assert_eq!(done.phase, Phase::Done);
    assert_eq!(done.packets, packets.len() as u64);
    assert_eq!(done.bytes_read, done.bytes_total);
    assert!((done.fraction() - 1.0).abs() < f64::EPSILON);
    assert_eq!(done.chunks_total, files.len());
    let finishing = seen.iter().find(|p| p.phase == Phase::Finishing).unwrap();
    assert_eq!(finishing.packets, report.packets);
    // Monotonic counters.
    for w in seen.windows(2) {
        assert!(w[0].bytes_read <= w[1].bytes_read);
        assert!(w[0].packets <= w[1].packets);
    }
}

#[test]
fn continuity_anomalies_are_recorded() {
    let tmp = TempDir::new().unwrap();
    let catalog = Catalog::open(tmp.path().join("data")).unwrap();
    let dir = tmp.path().join("chunks");
    let files = split(&dir, &traffic(), Naming::Dumpcap, vec![Encoding::pcapng()]);
    remove_chunk(&files[1]).unwrap();

    let report = run(&catalog, &dir, &IngestOptions::default());
    assert_eq!(report.state, SessionState::Ready);
    assert_eq!(report.anomaly_kinds.get("missing_sequence"), Some(&1));
    assert_eq!(
        scalar(
            &catalog,
            &report,
            "SELECT count(*) FROM anomalies WHERE kind = 'missing_sequence' \
             AND json_extract(detail, '$.first') = 2"
        ),
        1
    );
}

#[test]
fn progress_carries_the_session_and_anomalies_as_they_are_found() {
    let tmp = TempDir::new().unwrap();
    let catalog = Catalog::open(tmp.path().join("data")).unwrap();
    let dir = tmp.path().join("chunks");
    // A ten-minute pause in the middle (time gap, found at the end of reading) and a missing
    // file (known from the inventory, before the first packet).
    let mut packets = traffic();
    let middle = packets[packets.len() / 2].ts_ns;
    for p in &mut packets {
        if p.ts_ns >= middle {
            p.ts_ns += 600_000_000_000;
        }
    }
    // Several packets stamped before their predecessor: one `out_of_order` anomaly whose
    // counters grow while reading.
    for i in [5, 9, 13, 17] {
        packets[i].ts_ns = packets[i - 1].ts_ns - 1_000;
    }
    let opts = SplitOptions::new(SplitBy::Duration(1_000_000_000), Naming::Dumpcap);
    let files = split_to_dir(&dir, &packets, &opts).unwrap().1;
    remove_chunk(&files[1]).unwrap();

    let mut seen: Vec<Progress> = Vec::new();
    let report = ingest(
        &catalog,
        &dir,
        &IngestOptions::default(),
        &CancelToken::new(),
        &mut |p: &Progress| seen.push(p.clone()),
    )
    .unwrap();
    assert!(seen.iter().all(|p| p.session == report.session));
    let first = seen.first().unwrap();
    assert_eq!(first.phase, Phase::Reading);
    assert!(
        first
            .new_anomalies
            .iter()
            .any(|a| a.kind == "missing_sequence"),
        "{:?}",
        first.new_anomalies
    );
    let finishing = seen.iter().find(|p| p.phase == Phase::Finishing).unwrap();
    assert!(
        finishing.new_anomalies.iter().any(|a| a.kind == "time_gap"),
        "{:?}",
        finishing.new_anomalies
    );
    // Each anomaly is delivered once, with the stored details (`out_of_order` counters
    // included: published once final). Analyzer failures (`analyzer_panicked`) are written by
    // the shards and never published live; none occurs here.
    let mut live: Vec<String> = seen
        .iter()
        .flat_map(|p| {
            p.new_anomalies
                .iter()
                .map(|a| format!("{} {}", a.kind, serde_json::to_string(&a.detail).unwrap()))
        })
        .collect();
    live.sort();
    let session = catalog
        .open_session(&report.session, OpenMode::ReadOnly)
        .unwrap();
    let mut stored = rows(&session, "SELECT kind || ' ' || detail FROM anomalies");
    stored.sort();
    assert_eq!(live, stored);
    assert_eq!(live.len(), report.anomalies);
    let out_of_order = live
        .iter()
        .find(|a| a.starts_with("out_of_order "))
        .unwrap_or_else(|| panic!("{live:?}"));
    assert!(out_of_order.contains("\"packets\":4"), "{out_of_order}");
    assert!(
        finishing
            .new_anomalies
            .iter()
            .any(|a| a.kind == "out_of_order"),
        "published before the end of reading"
    );
}

#[test]
fn large_packets_stay_within_the_byte_budget() {
    let tmp = TempDir::new().unwrap();
    let catalog = Catalog::open(tmp.path().join("data")).unwrap();
    // 400 UDP datagrams of 60 000 bytes (TSO-like frames), about 24 MB in total.
    let mut sc = Scenario::new();
    let payload = vec![0x5a_u8; 60_000];
    for i in 0..400u16 {
        sc.udp(
            hosts::workstation(),
            hosts::file_server(),
            40_000 + i % 50,
            9_000,
            &payload,
        );
    }
    let packets = sc.into_packets();
    let dir = tmp.path().join("big");
    split(&dir, &packets, Naming::Dumpcap, vec![Encoding::pcapng()]);
    let options = IngestOptions {
        shards: Some(3),
        batch_bytes: 256 * 1024,
        channel_batches: 2,
        // Far below the input size: the reader has to wait for the shards.
        max_in_flight_bytes: 1 << 20,
        ..IngestOptions::default()
    };
    let report = run(&catalog, &dir, &options);
    assert_eq!(report.state, SessionState::Ready);
    assert_eq!(report.packets, packets.len() as u64);
    assert_eq!(
        scalar(&catalog, &report, "SELECT sum(bytes) FROM timeseries"),
        packets.iter().map(|p| n(p.data.len())).sum::<i64>()
    );
}

/// Analyzer that panics on its third packet.
struct Panicker {
    seen: u32,
}

impl Analyzer for Panicker {
    fn id(&self) -> AnalyzerId {
        AnalyzerId("panicker")
    }

    fn on_packet(&mut self, _ctx: &PacketCtx, _pkt: &Decoded<'_>, _out: &mut dyn RecordSink) {
        self.seen += 1;
        assert!(self.seen < 3, "synthetic analyzer failure");
    }
}

#[test]
fn a_panicking_analyzer_is_disabled_and_the_import_goes_on() {
    let tmp = TempDir::new().unwrap();
    let catalog = Catalog::open(tmp.path().join("data")).unwrap();
    let dir = tmp.path().join("chunks");
    let packets = traffic();
    split(&dir, &packets, Naming::Dumpcap, vec![Encoding::pcapng()]);
    let registry = Registry::default().with(AnalyzerId("panicker"), |_| {
        Box::new(Panicker { seen: 0 }) as Box<dyn Analyzer>
    });
    let options = IngestOptions {
        analyzers: registry,
        ..options(2)
    };
    let report = run(&catalog, &dir, &options);
    assert_eq!(report.state, SessionState::Ready);
    assert_eq!(state(&catalog, &report), SessionState::Ready);
    let panics = scalar(
        &catalog,
        &report,
        "SELECT count(*) FROM anomalies WHERE kind = 'analyzer_panicked' \
         AND json_extract(detail, '$.analyzer') = 'panicker' \
         AND json_extract(detail, '$.message') = 'synthetic analyzer failure'",
    );
    assert!((1..=2).contains(&panics), "{panics}");
    assert_eq!(
        report.anomaly_kinds.get(ANALYZER_PANICKED).copied(),
        Some(usize::try_from(panics).unwrap())
    );
    // The other analyzers saw every packet.
    assert_eq!(
        scalar(&catalog, &report, "SELECT sum(packets) FROM timeseries"),
        n(packets.len())
    );
}

#[test]
fn a_writer_failure_fails_the_session_without_deadlock() {
    let tmp = TempDir::new().unwrap();
    let catalog = Catalog::open(tmp.path().join("data")).unwrap();
    let dir = tmp.path().join("chunks");
    let packets = generate(Kind::Demo, 40, 7);
    split(&dir, &packets, Naming::Dumpcap, vec![Encoding::pcapng()]);
    let options = IngestOptions {
        shards: Some(3),
        batch_packets: 4,
        channel_batches: 1,
        record_batch: 1,
        max_in_flight_bytes: 64 * 1024,
        fail_writer_after_records: Some(20),
        ..IngestOptions::default()
    };
    let err = ingest(&catalog, &dir, &options, &CancelToken::new(), &mut |_| {}).unwrap_err();
    let EngineError::ImportFailed { session, reason } = err else {
        panic!("unexpected error: {err}");
    };
    assert!(reason.contains("writer"), "{reason}");
    let info = catalog.get(&session).unwrap().unwrap();
    assert_eq!(info.state, SessionState::Failed);
    assert_eq!(info.state_detail.as_deref(), Some(reason.as_str()));
    // What was written stays readable.
    let readable = catalog.open_session(&session, OpenMode::ReadOnly).unwrap();
    let chunks: i64 = readable
        .conn()
        .query_row("SELECT count(*) FROM chunks", [], |r| r.get(0))
        .unwrap();
    assert!(chunks > 0);
}

#[test]
fn interrupted_imports_are_recovered_as_incomplete() {
    let tmp = TempDir::new().unwrap();
    let catalog = Catalog::open(tmp.path().join("data")).unwrap();
    // A session left `importing` by a crash, next to a finished one.
    let crashed = catalog.create("crashed", &[], 0).unwrap();
    let file = tmp.path().join("one.pcapng");
    write_file(&file, &traffic(), &Encoding::pcapng()).unwrap();
    let done = run(&catalog, &file, &IngestOptions::default());

    let recovered = recover_interrupted(&catalog).unwrap();
    assert_eq!(recovered, vec![crashed.id.clone()]);
    let info = catalog.get(&crashed.id).unwrap().unwrap();
    assert_eq!(info.state, SessionState::Incomplete);
    assert_eq!(info.state_detail.as_deref(), Some(INTERRUPTED_DETAIL));
    assert_eq!(state(&catalog, &done), SessionState::Ready);
}

/// Ingests `case` as one file and as two chunks cut at `case.cut`; returns both reports.
fn ingest_cross_chunk(
    tmp: &TempDir,
    catalog: &Catalog,
    name: &str,
    case: &CrossChunkCase,
) -> (IngestReport, IngestReport) {
    let single = tmp.path().join(format!("{name}.pcapng"));
    write_file(&single, &case.packets, &Encoding::pcapng()).unwrap();
    let dir = tmp.path().join(name);
    let opts = SplitOptions::new(case.split_by(), Naming::Dumpcap);
    let (chunks, _) = split_to_dir(&dir, &case.packets, &opts).unwrap();
    assert_eq!(chunks.len(), 2);
    let whole = run(catalog, &single, &options(2));
    let cut = run(catalog, &dir, &options(2));
    assert_eq!(cut.chunks_read, 2);
    assert_eq!(tables(catalog, &cut), tables(catalog, &whole), "{name}");
    (whole, cut)
}

#[test]
fn a_tcp_flow_cut_between_two_chunks_is_one_flow() {
    let tmp = TempDir::new().unwrap();
    let catalog = Catalog::open(tmp.path().join("data")).unwrap();
    let case = http_request_across_chunks();
    let (_, cut) = ingest_cross_chunk(&tmp, &catalog, "http", &case);
    let flows = tables(&catalog, &cut).flows;
    assert_eq!(flows.len(), 1, "{flows:#?}");
    let check = |sql: &str| scalar(&catalog, &cut, sql);
    assert_eq!(
        check("SELECT packets_fwd + packets_rev FROM flows"),
        n(case.packets.len())
    );
    assert_eq!(
        check("SELECT bytes_fwd + bytes_rev FROM flows"),
        case.packets.iter().map(|p| n(p.data.len())).sum::<i64>()
    );
    assert_eq!(
        check(
            "SELECT count(*) FROM flows WHERE packets_fwd > 0 AND packets_rev > 0 \
             AND app_proto = 'http' AND dst_port = 80 AND tcp_state = 'closed'"
        ),
        1
    );
}

#[test]
fn a_dns_transaction_cut_between_two_chunks_stays_paired() {
    let tmp = TempDir::new().unwrap();
    let catalog = Catalog::open(tmp.path().join("data")).unwrap();
    let case = dns_across_chunks();
    let (_, cut) = ingest_cross_chunk(&tmp, &catalog, "dns", &case);
    let check = |sql: &str| scalar(&catalog, &cut, sql);
    assert!(check("SELECT count(*) FROM flows") >= 1);
    // Every query is in the same flow as its response, whatever chunk each is in.
    assert_eq!(
        check("SELECT count(*) FROM flows WHERE packets_rev = 0 OR packets_fwd = 0"),
        0
    );
    assert_eq!(
        check("SELECT sum(packets_fwd + packets_rev) FROM flows"),
        n(case.packets.len())
    );
    assert_eq!(
        check("SELECT count(*) FROM flows WHERE app_proto IS NOT 'dns'"),
        0
    );
}
