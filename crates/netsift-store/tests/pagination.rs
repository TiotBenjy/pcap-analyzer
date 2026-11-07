//! Keyset pagination: complete, without duplicates, stable under concurrent inserts.

mod common;

use std::collections::HashSet;

use common::flow;
use netsift_store::query::{FlowSort, flows_page};
use netsift_store::{
    Keyset, OpenMode, PageRequest, Session, StoreError, StoreRecord, StoreWriter, WriterConfig,
    keyset_page,
};

/// 500 flows with heavily repeated sort keys (bytes in 0..7, `first_ts` in 0..13).
fn seeded() -> (tempfile::TempDir, Session) {
    let tmp = tempfile::tempdir().unwrap();
    let w = StoreWriter::spawn(
        Session::open(tmp.path(), OpenMode::Import).unwrap(),
        WriterConfig::default(),
    )
    .unwrap();
    for i in 0..500u64 {
        let first_ts = i64::try_from(i % 13).unwrap();
        w.send(StoreRecord::Flow(flow(i, first_ts, i % 7))).unwrap();
    }
    w.finish().unwrap();
    let session = Session::open(tmp.path(), OpenMode::ReadWrite).unwrap();
    (tmp, session)
}

fn walk(session: &Session, sort: FlowSort, descending: bool, limit: u32) -> Vec<(u64, u64, i64)> {
    let mut out = Vec::new();
    let mut request = PageRequest::first(limit);
    loop {
        let page = flows_page(session.conn(), sort, descending, &request).unwrap();
        assert!(page.items.len() <= usize::try_from(limit).unwrap());
        out.extend(page.items.iter().map(|f| (f.id, f.bytes_fwd, f.first_ts)));
        match page.next_cursor {
            Some(c) => request.cursor = Some(c),
            None => break,
        }
    }
    out
}

#[test]
fn pages_cover_every_row_once_in_order() {
    let (_tmp, session) = seeded();
    for (sort, descending) in [
        (FlowSort::Bytes, false),
        (FlowSort::Bytes, true),
        (FlowSort::FirstTs, false),
        (FlowSort::FirstTs, true),
    ] {
        for limit in [1, 37, 100, 500, 1000] {
            let rows = walk(&session, sort, descending, limit);
            assert_eq!(rows.len(), 500, "{sort:?} {descending} {limit}");
            let ids: HashSet<u64> = rows.iter().map(|r| r.0).collect();
            assert_eq!(ids.len(), 500, "no duplicates");
            let keys: Vec<(i64, u64)> = rows
                .iter()
                .map(|&(id, bytes, first)| {
                    let k = if sort == FlowSort::Bytes {
                        i64::try_from(bytes).unwrap()
                    } else {
                        first
                    };
                    (k, id)
                })
                .collect();
            let mut sorted = keys.clone();
            sorted.sort_unstable();
            if descending {
                sorted.reverse();
            }
            assert_eq!(keys, sorted, "{sort:?} {descending} {limit}");
        }
    }
}

#[test]
fn exact_multiple_has_no_empty_trailing_page() {
    let (_tmp, session) = seeded();
    let page = flows_page(
        session.conn(),
        FlowSort::LastTs,
        false,
        &PageRequest::first(500),
    )
    .unwrap();
    assert_eq!(page.items.len(), 500);
    assert_eq!(page.next_cursor, None);
}

#[test]
fn pagination_is_stable_when_rows_are_added() {
    let (_tmp, session) = seeded();
    let first = flows_page(
        session.conn(),
        FlowSort::Bytes,
        false,
        &PageRequest::first(100),
    )
    .unwrap();
    let last_seen = first.items.last().unwrap().clone();
    // A row sorting before the cursor must not shift the next page; one after it appears.
    session
        .conn()
        .execute_batch(
            "INSERT INTO flows (id, transport, src_ip, dst_ip, first_ts, last_ts, bytes_fwd) \
             VALUES (10000, 6, '10.0.0.9', '10.0.0.8', 0, 0, 0), \
                    (10001, 6, '10.0.0.9', '10.0.0.8', 0, 0, 6)",
        )
        .unwrap();
    let mut seen: Vec<u64> = first.items.iter().map(|f| f.id).collect();
    let mut request = PageRequest {
        limit: 50,
        cursor: first.next_cursor,
    };
    loop {
        let page = flows_page(session.conn(), FlowSort::Bytes, false, &request).unwrap();
        for f in &page.items {
            assert!(
                (f.bytes_fwd, f.id) > (last_seen.bytes_fwd, last_seen.id),
                "page went backwards"
            );
        }
        seen.extend(page.items.iter().map(|f| f.id));
        match page.next_cursor {
            Some(c) => request.cursor = Some(c),
            None => break,
        }
    }
    assert!(!seen.contains(&10000));
    assert!(seen.contains(&10001));
    assert_eq!(
        seen.len(),
        501,
        "500 seeded + the row inserted after the cursor"
    );
    assert_eq!(seen.iter().collect::<HashSet<_>>().len(), 501);
}

#[test]
fn generic_helper_with_filter_and_params() {
    let (_tmp, session) = seeded();
    let query = Keyset {
        from: "flows",
        select: "id",
        sort: "bytes_total",
        tiebreak: "id",
        descending: true,
        filter: Some("bytes_fwd >= ? AND first_ts < ?"),
    };
    let mut request = PageRequest::first(7);
    let mut ids = Vec::new();
    loop {
        let page = keyset_page(session.conn(), &query, &[&5_i64, &3_i64], &request, |r| {
            r.get::<_, u64>(0)
        })
        .unwrap();
        ids.extend(page.items);
        match page.next_cursor {
            Some(c) => request.cursor = Some(c),
            None => break,
        }
    }
    let expected: Vec<u64> = {
        let mut v: Vec<u64> = (0..500u64).filter(|i| i % 7 >= 5 && i % 13 < 3).collect();
        v.sort_unstable_by_key(|i| std::cmp::Reverse((i % 7, *i)));
        v
    };
    assert_eq!(ids, expected);
}

#[test]
fn limits_are_clamped_and_bad_cursors_rejected() {
    let (_tmp, session) = seeded();
    let page = flows_page(
        session.conn(),
        FlowSort::Bytes,
        false,
        &PageRequest::first(0),
    )
    .unwrap();
    assert_eq!(page.items.len(), 100, "0 means the default size");

    let bad = PageRequest {
        limit: 10,
        cursor: Some("not-a-cursor".into()),
    };
    assert!(matches!(
        flows_page(session.conn(), FlowSort::Bytes, false, &bad).unwrap_err(),
        StoreError::InvalidCursor
    ));
}

#[test]
fn chunks_and_anomalies_are_paginated() {
    use netsift_store::query::{anomalies_page, chunks_page};
    use netsift_store::{AnomalyRow, ChunkRow, ChunkStatus};

    let tmp = tempfile::tempdir().unwrap();
    let w = StoreWriter::spawn(
        Session::open(tmp.path(), OpenMode::Import).unwrap(),
        WriterConfig::default(),
    )
    .unwrap();
    for id in (0..25u32).rev() {
        w.send(StoreRecord::Chunk(ChunkRow {
            id,
            seq: Some(i64::from(id) + 1),
            path: format!("/c/cap{id}.pcap"),
            format: None,
            compressed: false,
            linktypes: vec![1],
            snaplen: None,
            first_ts: None,
            last_ts: None,
            packets: 0,
            bytes: 0,
            file_size: 0,
            mtime_ns: None,
            head_hash: None,
            status: ChunkStatus::Ok,
        }))
        .unwrap();
    }
    for i in 0..20i64 {
        w.send(StoreRecord::Anomaly(AnomalyRow {
            kind: "k".into(),
            chunk_id: None,
            ts: (i % 3 != 0).then_some(100 - i % 5),
            detail: serde_json::json!({ "i": i }),
        }))
        .unwrap();
    }
    w.finish().unwrap();
    let ro = Session::open(tmp.path(), OpenMode::ReadOnly).unwrap();

    let mut ids = Vec::new();
    let mut request = PageRequest::first(4);
    loop {
        let page = chunks_page(ro.conn(), &request).unwrap();
        ids.extend(page.items.iter().map(|c| c.id));
        match page.next_cursor {
            Some(c) => request.cursor = Some(c),
            None => break,
        }
    }
    assert_eq!(ids, (0..25).collect::<Vec<u32>>());

    let mut keys = Vec::new();
    let mut request = PageRequest::first(3);
    loop {
        let page = anomalies_page(ro.conn(), &request).unwrap();
        keys.extend(page.items.iter().map(|a| (a.ts.unwrap_or(i64::MAX), a.id)));
        match page.next_cursor {
            Some(c) => request.cursor = Some(c),
            None => break,
        }
    }
    assert_eq!(keys.len(), 20);
    let mut sorted = keys.clone();
    sorted.sort_unstable();
    assert_eq!(keys, sorted, "by timestamp, timestamp-less last, then id");
}
