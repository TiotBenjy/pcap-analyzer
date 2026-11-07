//! Records fed by flow shards arrive in a non-deterministic order: the same records written
//! in different orders (and with different batch borders) must give identical tables.

mod common;

use std::path::Path;
use std::time::Duration;

use common::{flow, host, ts};
use netsift_store::{AnomalyRow, OpenMode, Session, StoreRecord, StoreWriter, WriterConfig};

fn records() -> Vec<StoreRecord> {
    let mut out = Vec::new();
    for i in 0..40u8 {
        let mut h = host(&format!("10.0.0.{}", i % 7), i64::from(i), i64::from(i) + 5);
        h.macs = vec![[0, 0, 0, 0, 0, i % 5], [2, 0, 0, 0, 0, i % 3]];
        h.names = vec![format!("h{}.lan", i % 11), format!("alias{}", i % 4)];
        h.country = match i % 4 {
            0 => None,
            1 => Some("FR".into()),
            2 => Some("DE".into()),
            _ => Some("US".into()),
        };
        h.category = (i % 3 == 0).then(|| format!("cat{}", i % 2));
        out.push(StoreRecord::Host(h));

        // Several snapshots of the same flows, some with smaller counters.
        let mut f = flow(u64::from(i % 6), i64::from(i % 9), u64::from(i) * 10);
        f.last_ts = i64::from(i) * 100;
        f.packets_rev = u64::from(40 - i);
        f.app_proto = (i % 2 == 0).then(|| ["dns", "http", "tls"][usize::from(i % 3)].into());
        f.tcp_state = (i % 5 != 0).then(|| ["established", "closed"][usize::from(i % 2)].into());
        out.push(StoreRecord::Flow(f));

        out.push(StoreRecord::Timeseries(ts(
            i64::from(i % 4),
            ["dns", "tls"][usize::from(i % 2)],
            u64::from(i),
            1,
        )));
        if i % 10 == 0 {
            out.push(StoreRecord::Anomaly(AnomalyRow {
                kind: "time_gap".into(),
                chunk_id: Some(u32::from(i)),
                ts: Some(i64::from(i)),
                detail: serde_json::json!({ "i": i }),
            }));
        }
    }
    out
}

/// Deterministic permutation (linear congruential shuffle).
fn shuffled(mut v: Vec<StoreRecord>, mut seed: u64) -> Vec<StoreRecord> {
    for i in (1..v.len()).rev() {
        seed = seed
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let j = usize::try_from(seed >> 33).unwrap() % (i + 1);
        v.swap(i, j);
    }
    v
}

fn write(dir: &Path, records: Vec<StoreRecord>, batch_rows: usize) {
    let w = StoreWriter::spawn(
        Session::open(dir, OpenMode::Import).unwrap(),
        WriterConfig {
            batch_rows,
            flush_interval: Duration::from_secs(3600),
            channel_capacity: 16,
        },
    )
    .unwrap();
    for r in records {
        w.send(r).unwrap();
    }
    let stats = w.finish().unwrap();
    assert_eq!(stats.total_rejected(), 0);
}

/// Every row of the order-sensitive tables, as text, in a canonical order.
fn dump(dir: &Path) -> String {
    let session = Session::open(dir, OpenMode::ReadOnly).unwrap();
    let mut out = String::new();
    for sql in [
        "SELECT quote(ip), macs, names, quote(country), quote(category), first_ts, last_ts \
         FROM hosts ORDER BY ip",
        "SELECT id, transport, src_ip, src_port, dst_ip, dst_port, first_ts, last_ts, \
         bytes_fwd, bytes_rev, packets_fwd, packets_rev, quote(app_proto), quote(tcp_state) \
         FROM flows ORDER BY id",
        "SELECT bucket_s, proto, bytes, packets FROM timeseries ORDER BY bucket_s, proto",
        "SELECT kind, chunk_id, ts, detail FROM anomalies ORDER BY kind, chunk_id, ts, detail",
    ] {
        let mut stmt = session.conn().prepare(sql).unwrap();
        let n = stmt.column_count();
        let mut rows = stmt.query([]).unwrap();
        while let Some(row) = rows.next().unwrap() {
            let cols: Vec<String> = (0..n)
                .map(|i| match row.get_ref(i).unwrap() {
                    rusqlite::types::ValueRef::Integer(v) => v.to_string(),
                    rusqlite::types::ValueRef::Text(t) => String::from_utf8_lossy(t).into_owned(),
                    other => format!("{other:?}"),
                })
                .collect();
            out.push_str(&cols.join(" | "));
            out.push('\n');
        }
        out.push_str("--\n");
    }
    out
}

#[test]
fn merges_do_not_depend_on_arrival_order() {
    let tmp = tempfile::tempdir().unwrap();
    let base = records();
    let reversed: Vec<StoreRecord> = base.iter().rev().cloned().collect();
    let variants = [
        (base.clone(), 7),
        (reversed, 3),
        (shuffled(base.clone(), 1), 1000),
        (shuffled(base, 42), 1),
    ];
    let dumps: Vec<String> = variants
        .into_iter()
        .enumerate()
        .map(|(i, (records, batch))| {
            let dir = tmp.path().join(format!("s{i}"));
            write(&dir, records, batch);
            dump(&dir)
        })
        .collect();
    for d in &dumps[1..] {
        assert_eq!(&dumps[0], d);
    }

    // Spot-check the documented rules on the merged result.
    let session = Session::open(tmp.path().join("s0"), OpenMode::ReadOnly).unwrap();
    let (country, macs): (String, String) = session
        .conn()
        .query_row(
            "SELECT country, macs FROM hosts WHERE ip = '10.0.0.1'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(country, "DE", "smallest non-NULL value");
    assert!(macs.starts_with("[\"00:00:00:00:00:00\""), "{macs}");
    insta::assert_snapshot!(dumps[0]);
}
