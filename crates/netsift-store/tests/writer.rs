//! Batched writer: batching, delayed flush, upserts, concurrent reads, error reporting.

mod common;

use std::path::Path;
use std::time::{Duration, Instant};

use common::{flow, host, ts};
use netsift_store::query::{anomalies_page, chunks_page, count_flows, get_meta};
use netsift_store::{
    AnomalyRow, ChunkFormat, ChunkRow, ChunkStatus, MetaRow, OpenMode, PageRequest, Session,
    StoreError, StoreRecord, StoreWriter, WriterConfig,
};
use rusqlite::Connection;

fn writer(dir: &Path, batch_rows: usize, flush_interval: Duration) -> StoreWriter {
    let session = Session::open(dir, OpenMode::Import).unwrap();
    StoreWriter::spawn(
        session,
        WriterConfig {
            batch_rows,
            flush_interval,
            channel_capacity: 64,
        },
    )
    .unwrap()
}

fn read_only(dir: &Path) -> Session {
    Session::open(dir, OpenMode::ReadOnly).unwrap()
}

fn count(conn: &Connection, table: &str) -> i64 {
    conn.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
        .unwrap()
}

const LONG: Duration = Duration::from_secs(3600);

#[test]
fn commits_by_batch_size() {
    let tmp = tempfile::tempdir().unwrap();
    let w = writer(tmp.path(), 100, LONG);
    for i in 0..250 {
        w.send(StoreRecord::Flow(flow(i, 0, 1))).unwrap();
    }
    let stats = w.finish().unwrap();
    assert_eq!(stats.batches, 3, "100 + 100 + 50");
    assert_eq!(stats.rows_of("flows"), 250);
    assert_eq!(stats.total_rows(), 250);
    assert_eq!(count_flows(read_only(tmp.path()).conn()).unwrap(), 250);
}

#[test]
fn batch_messages_are_split_by_size_too() {
    let tmp = tempfile::tempdir().unwrap();
    let w = writer(tmp.path(), 10, LONG);
    w.send_batch((0..35).map(|i| StoreRecord::Flow(flow(i, 0, 1))).collect())
        .unwrap();
    w.send_batch(Vec::new()).unwrap();
    let stats = w.finish().unwrap();
    assert_eq!(stats.batches, 4);
    assert_eq!(stats.rows_of("flows"), 35);
}

#[test]
fn flushes_after_the_interval_without_reaching_the_size() {
    let tmp = tempfile::tempdir().unwrap();
    let w = writer(tmp.path(), 1_000_000, Duration::from_millis(50));
    // One message: the timer cannot split it, whatever the load of the machine.
    w.send_batch((0..10).map(|i| StoreRecord::Flow(flow(i, 0, 1))).collect())
        .unwrap();
    let reader = read_only(tmp.path());
    let start = Instant::now();
    while count_flows(reader.conn()).unwrap() < 10 {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "rows not committed by the timer"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let stats = w.finish().unwrap();
    assert_eq!(stats.batches, 1);
    assert_eq!(stats.rows_of("flows"), 10);
}

#[test]
fn finish_writes_every_record_type() {
    let tmp = tempfile::tempdir().unwrap();
    let w = writer(tmp.path(), 50_000, LONG);
    let chunk = ChunkRow {
        id: 0,
        seq: Some(100_000),
        path: "/captures/cap_100000_20260101000000.pcapng.gz".into(),
        format: Some(ChunkFormat::PcapNg),
        compressed: true,
        linktypes: vec![1, 113],
        snaplen: Some(262_144),
        first_ts: Some(1_000),
        last_ts: Some(2_000),
        packets: 2,
        bytes: 120,
        file_size: 4096,
        mtime_ns: Some(42),
        head_hash: Some("ab".repeat(32)),
        status: ChunkStatus::Truncated,
    };
    let anomaly = AnomalyRow {
        kind: "time_gap".into(),
        chunk_id: Some(0),
        ts: Some(2_000),
        detail: serde_json::json!({ "gap_ns": 43_000_000_000_i64 }),
    };
    let sender = w.sender();
    sender
        .send(StoreRecord::Meta(MetaRow {
            key: "tool".into(),
            value: "old".into(),
        }))
        .unwrap();
    sender
        .send(StoreRecord::Meta(MetaRow {
            key: "tool".into(),
            value: "netsift".into(),
        }))
        .unwrap();
    sender.send(StoreRecord::Chunk(chunk.clone())).unwrap();
    sender.send(StoreRecord::Anomaly(anomaly.clone())).unwrap();
    sender
        .send(StoreRecord::Timeseries(ts(1, "dns", 10, 1)))
        .unwrap();
    sender
        .send(StoreRecord::Host(host("192.168.1.10", 5, 6)))
        .unwrap();
    sender.send(StoreRecord::Flow(flow(7, 0, 99))).unwrap();
    // A producer still holding a sender must not block finish().
    let stats = w.finish().unwrap();
    assert!(sender.send(StoreRecord::Flow(flow(8, 0, 1))).is_err());

    assert_eq!(stats.batches, 1);
    assert_eq!(stats.total_rows(), 7);
    for (kind, n) in [
        ("meta", 2),
        ("chunks", 1),
        ("anomalies", 1),
        ("timeseries", 1),
        ("hosts", 1),
        ("flows", 1),
    ] {
        assert_eq!(stats.rows_of(kind), n, "{kind}");
    }

    let ro = read_only(tmp.path());
    let conn = ro.conn();
    assert_eq!(get_meta(conn, "tool").unwrap().as_deref(), Some("netsift"));
    assert_eq!(get_meta(conn, "absent").unwrap(), None);
    let chunks = chunks_page(conn, &PageRequest::first(10)).unwrap();
    assert_eq!(chunks.items, vec![chunk]);
    assert_eq!(chunks.next_cursor, None);
    let anomalies = anomalies_page(conn, &PageRequest::first(10)).unwrap().items;
    assert_eq!(anomalies.len(), 1);
    assert_eq!(anomalies[0].kind, anomaly.kind);
    assert_eq!(anomalies[0].chunk_id, anomaly.chunk_id);
    assert_eq!(anomalies[0].ts, anomaly.ts);
    assert_eq!(anomalies[0].detail, anomaly.detail);
    assert_eq!(count_flows(conn).unwrap(), 1);
    let (src, dst): (String, String) = conn
        .query_row("SELECT src_ip, dst_ip FROM flows", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    assert_eq!((src.as_str(), dst.as_str()), ("10.0.0.1", "2001:db8::1"));
}

#[test]
fn timeseries_upsert_is_additive() {
    let tmp = tempfile::tempdir().unwrap();
    let w = writer(tmp.path(), 3, LONG); // spans several transactions
    for _ in 0..5 {
        w.send(StoreRecord::Timeseries(ts(100, "http", 1500, 1)))
            .unwrap();
    }
    w.send(StoreRecord::Timeseries(ts(100, "dns", 80, 1)))
        .unwrap();
    w.send(StoreRecord::Timeseries(ts(101, "http", 60, 2)))
        .unwrap();
    w.finish().unwrap();

    let ro = read_only(tmp.path());
    let mut stmt = ro
        .conn()
        .prepare("SELECT bucket_s, proto, bytes, packets FROM timeseries ORDER BY bucket_s, proto")
        .unwrap();
    let rows: Vec<(i64, String, i64, i64)> = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(
        rows,
        vec![
            (100, "dns".into(), 80, 1),
            (100, "http".into(), 7500, 5),
            (101, "http".into(), 60, 2),
        ]
    );
}

#[test]
fn host_upsert_merges() {
    let tmp = tempfile::tempdir().unwrap();
    let w = writer(tmp.path(), 2, LONG);
    let mut first = host("fe80::1", 500, 600);
    first.names = vec!["b.local".into(), "a.local".into(), "a.local".into()];
    first.macs = vec![[0x00, 0x1b, 0x21, 0xAA, 0xBB, 0x0C], [0xff; 6]];
    w.send(StoreRecord::Host(first)).unwrap();

    let mut second = host("fe80:0:0::1", 100, 550); // same address, other spelling
    second.names = vec!["c.local".into(), "a.local".into(), String::new()];
    second.macs = vec![[0xff; 6], [0x02, 0, 0, 0, 0, 1]];
    second.country = Some("FR".into());
    second.category = Some("link-local".into());
    w.send(StoreRecord::Host(second)).unwrap();

    let mut third = host("fe80::1", 700, 900);
    third.category = None; // unknown values do not erase known ones
    third.country = Some("US".into()); // between two known values, the smallest wins
    w.send(StoreRecord::Host(third)).unwrap();

    let mut many = host("10.0.0.2", 1, 1);
    many.names = (0..100).map(|i| format!("n{i:03}")).collect();
    w.send(StoreRecord::Host(many)).unwrap();
    let mut more = host("10.0.0.2", 1, 1);
    more.names = vec!["zzz".into()];
    w.send(StoreRecord::Host(more)).unwrap();
    w.finish().unwrap();

    let ro = read_only(tmp.path());
    let row = |ip: &str| -> (String, String, Option<String>, Option<String>, i64, i64) {
        ro.conn()
            .query_row(
                "SELECT macs, names, country, category, first_ts, last_ts FROM hosts WHERE ip = ?1",
                [ip],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                    ))
                },
            )
            .unwrap()
    };
    assert_eq!(count(ro.conn(), "hosts"), 2);
    let (macs, names, country, category, first, last) = row("fe80::1");
    let macs: Vec<String> = serde_json::from_str(&macs).unwrap();
    assert_eq!(
        macs,
        [
            "00:1b:21:aa:bb:0c",
            "02:00:00:00:00:01",
            "ff:ff:ff:ff:ff:ff"
        ]
    );
    let names: Vec<String> = serde_json::from_str(&names).unwrap();
    assert_eq!(names, ["a.local", "b.local", "c.local"]);
    assert_eq!(country.as_deref(), Some("FR"));
    assert_eq!(category.as_deref(), Some("link-local"));
    assert_eq!((first, last), (100, 900));

    let names: Vec<String> = serde_json::from_str(&row("10.0.0.2").1).unwrap();
    assert_eq!(names.len(), netsift_store::records::MAX_HOST_NAMES);
    assert_eq!(names[0], "n000");
}

#[test]
fn flow_upsert_keeps_the_maxima() {
    let tmp = tempfile::tempdir().unwrap();
    let w = writer(tmp.path(), 50_000, LONG);
    w.send(StoreRecord::Flow(flow(1, 1_000, 10))).unwrap();
    let mut later = flow(1, 5_000, 30);
    later.last_ts = 9_000;
    later.app_proto = None;
    later.tcp_state = Some("closed".into());
    w.send(StoreRecord::Flow(later)).unwrap();
    w.finish().unwrap();

    let ro = read_only(tmp.path());
    let got: (i64, i64, i64, i64, Option<String>, String) = ro
        .conn()
        .query_row(
            "SELECT first_ts, last_ts, bytes_fwd, bytes_total, app_proto, tcp_state FROM flows",
            [],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(
        got,
        (1_000, 9_000, 30, 30, Some("tls".into()), "closed".into())
    );
}

#[test]
fn readers_see_committed_batches_during_the_import() {
    let tmp = tempfile::tempdir().unwrap();
    // No timer flush: every commit is a whole batch of 200 rows.
    let w = writer(tmp.path(), 200, LONG);
    let dir = tmp.path().to_path_buf();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let reader = {
        let stop = stop.clone();
        std::thread::spawn(move || {
            let ro = read_only(&dir);
            let mut last = 0;
            let mut reads = 0u32;
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                let n = count_flows(ro.conn()).expect("read must not fail during writes");
                assert!(n >= last, "counts never go backwards");
                assert_eq!(n % 200, 0, "only whole batches are visible: {n}");
                last = n;
                reads += 1;
            }
            (last, reads)
        })
    };
    for i in 0..20_000 {
        w.send(StoreRecord::Flow(flow(i, 0, 1))).unwrap();
    }
    std::thread::sleep(Duration::from_millis(50));
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let (_, reads) = reader.join().unwrap();
    assert!(reads > 0);
    let stats = w.finish().unwrap();
    assert_eq!(stats.rows_of("flows"), 20_000);
    assert_eq!(count_flows(read_only(tmp.path()).conn()).unwrap(), 20_000);
}

#[test]
fn invalid_records_are_rejected_one_by_one() {
    let tmp = tempfile::tempdir().unwrap();
    let w = writer(tmp.path(), 10, LONG);
    for i in 0..15 {
        w.send(StoreRecord::Flow(flow(i, 0, 1))).unwrap();
    }
    // An identifier above i64::MAX cannot be stored: only this record is dropped.
    w.send(StoreRecord::Flow(flow(u64::MAX, 0, 1))).unwrap();
    // Counters above i64::MAX are saturated, not rejected.
    w.send(StoreRecord::Flow(flow(20, 0, u64::MAX))).unwrap();
    w.send(StoreRecord::Timeseries(ts(1, "x", u64::MAX, 1)))
        .unwrap();
    w.send(StoreRecord::Timeseries(ts(1, "x", u64::MAX, 1)))
        .unwrap();
    for i in 21..25 {
        w.send(StoreRecord::Flow(flow(i, 0, 1))).unwrap();
    }
    let stats = w.finish().unwrap();
    assert_eq!(stats.rejected.get("flows"), Some(&1));
    assert_eq!(stats.total_rejected(), 1);
    assert_eq!(stats.rows_of("flows"), 20);

    let ro = read_only(tmp.path());
    assert_eq!(count_flows(ro.conn()).unwrap(), 20);
    let (bytes, total): (i64, i64) = ro
        .conn()
        .query_row(
            "SELECT bytes_fwd, bytes_total FROM flows WHERE id = 20",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!((bytes, total), (i64::MAX, i64::MAX));
    let ts_bytes: i64 = ro
        .conn()
        .query_row("SELECT bytes FROM timeseries", [], |r| r.get(0))
        .unwrap();
    assert_eq!(ts_bytes, i64::MAX, "additive upsert saturates");
}

#[test]
fn fatal_errors_stop_the_writer_and_are_reported_by_finish() {
    let tmp = tempfile::tempdir().unwrap();
    let session = Session::open(tmp.path(), OpenMode::Import).unwrap();
    // A database that cannot grow: inserts fail with SQLITE_FULL, which is not row-level.
    let pages: i64 = session
        .conn()
        .query_row("PRAGMA page_count", [], |r| r.get(0))
        .unwrap();
    session
        .conn()
        .pragma_update(None, "max_page_count", pages + 1)
        .unwrap();
    let w = StoreWriter::spawn(
        session,
        WriterConfig {
            batch_rows: 100,
            flush_interval: LONG,
            channel_capacity: 64,
        },
    )
    .unwrap();
    let mut closed = false;
    for i in 0..1_000_000 {
        if w.send(StoreRecord::Flow(flow(i, 0, 1))).is_err() {
            closed = true;
            break;
        }
    }
    assert!(closed, "senders fail once the writer stopped");
    let err = w.finish().unwrap_err();
    assert!(matches!(err, StoreError::Sqlite(_)), "{err}");
    // Committed batches stay, the failing one is rolled back: whole batches only.
    let n = count_flows(read_only(tmp.path()).conn()).unwrap();
    assert_eq!(n % 100, 0, "{n}");
}
