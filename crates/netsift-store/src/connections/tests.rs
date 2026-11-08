use rusqlite::Connection;

use super::*;
use crate::migrate::migrate;
use crate::records::{HostRow, StoreRecord};
use crate::schema::SESSION_SCHEMA;

pub(crate) fn db() -> Connection {
    let mut conn = Connection::open_in_memory().unwrap();
    migrate(&mut conn, &SESSION_SCHEMA).unwrap();
    conn
}

pub(crate) fn conv(
    src: &str,
    dst: &str,
    fwd: u64,
    rev: u64,
    protocols: &[&str],
) -> ConversationRow {
    ConversationRow {
        src_ip: src.parse().unwrap(),
        dst_ip: dst.parse().unwrap(),
        first_ts: 1_000,
        last_ts: 2_000,
        bytes_fwd: fwd,
        bytes_rev: rev,
        packets_fwd: 1,
        packets_rev: 1,
        flows: 1,
        dns_bytes_fwd: 0,
        dns_bytes_rev: 0,
        dns_flows: 0,
        protocols: protocols.iter().map(|p| (*p).to_owned()).collect(),
    }
}

pub(crate) fn host(ip: &str, category: &str, country: Option<&str>, names: &[&str]) -> HostRow {
    HostRow {
        ip: ip.parse().unwrap(),
        macs: Vec::new(),
        names: names.iter().map(|n| (*n).to_owned()).collect(),
        country: country.map(str::to_owned),
        category: Some(category.to_owned()),
        first_ts: 0,
        last_ts: 0,
    }
}

#[allow(clippy::needless_pass_by_value)] // Called with record literals.
fn insert(conn: &Connection, record: StoreRecord) {
    record.insert(conn).unwrap();
}

fn all(conn: &Connection, filter: &ConversationFilter, limit: u32) -> Vec<ConversationEntry> {
    let mut out = Vec::new();
    let mut request = PageRequest::first(limit);
    loop {
        let page =
            conversations_page(conn, filter, ConversationSort::Bytes, true, &request).unwrap();
        out.extend(page.items);
        match page.next_cursor {
            Some(c) => request.cursor = Some(c),
            None => return out,
        }
    }
}

#[test]
fn upserts_add_counters_and_unite_protocols() {
    let conn = db();
    let mut a = conv("10.0.0.1", "10.0.0.2", 100, 10, &["tls"]);
    a.first_ts = 500;
    let mut b = conv("10.0.0.1", "10.0.0.2", 50, 5, &["dns", "tls"]);
    b.last_ts = 9_000;
    b.dns_bytes_fwd = 40;
    b.dns_bytes_rev = 5;
    b.dns_flows = 1;
    // The opposite orientation is another conversation.
    let c = conv("10.0.0.2", "10.0.0.1", 7, 7, &["ssh"]);
    for r in [a, b, c] {
        insert(&conn, StoreRecord::Conversation(r));
    }
    let rows = all(&conn, &ConversationFilter::default(), 10);
    assert_eq!(rows.len(), 2);
    let r = &rows[0].row;
    assert_eq!((r.bytes_fwd, r.bytes_rev, r.flows), (150, 15, 2));
    assert_eq!((r.dns_bytes_fwd, r.dns_bytes_rev, r.dns_flows), (40, 5, 1));
    assert_eq!((r.first_ts, r.last_ts), (500, 9_000));
    assert_eq!(r.protocols, ["dns", "tls"]);
    assert_eq!(rows[1].row.src_ip.to_string(), "10.0.0.2");

    // Saturation instead of overflow.
    insert(
        &conn,
        StoreRecord::Conversation(conv("10.0.0.2", "10.0.0.1", u64::MAX, 0, &[])),
    );
    let rows = all(&conn, &ConversationFilter::default(), 10);
    assert_eq!(rows[0].row.bytes_fwd, i64::MAX as u64);
    assert_eq!(rows[0].row.protocols, ["ssh"]);
}

/// 30 endpoints talking to one server, with distinct volumes.
fn thirty(conn: &Connection) {
    for i in 1..=30_u64 {
        let src = format!("10.0.1.{i}");
        let protocols: &[&str] = if i % 3 == 0 { &["dns"] } else { &["http"] };
        let mut row = conv(&src, "192.168.1.1", i * 1_000, i * 10, protocols);
        if i % 3 == 0 {
            row.dns_bytes_fwd = row.bytes_fwd;
            row.dns_bytes_rev = row.bytes_rev;
            row.dns_flows = 1;
        }
        insert(conn, StoreRecord::Conversation(row));
        let category = if i % 2 == 0 { "private" } else { "public" };
        let name = format!("host{i}.example.test");
        insert(
            conn,
            StoreRecord::Host(host(&src, category, None, &[name.as_str()])),
        );
    }
    insert(
        conn,
        StoreRecord::Host(host("192.168.1.1", "private", None, &[])),
    );
}

#[test]
fn keyset_pages_follow_the_sort_and_cover_every_row() {
    let conn = db();
    thirty(&conn);
    let rows = all(&conn, &ConversationFilter::default(), 7);
    assert_eq!(rows.len(), 30);
    let bytes: Vec<u64> = rows.iter().map(|r| r.row.bytes_fwd).collect();
    let mut sorted = bytes.clone();
    sorted.sort_unstable_by(|a, b| b.cmp(a));
    assert_eq!(bytes, sorted);
    assert_eq!(rows[0].src.names, ["host30.example.test"]);
    assert_eq!(rows[0].dst.category.as_deref(), Some("private"));
    assert_eq!(
        count_conversations(&conn, &ConversationFilter::default()).unwrap(),
        30
    );

    for sort in [
        ConversationSort::Packets,
        ConversationSort::Flows,
        ConversationSort::FirstTs,
        ConversationSort::LastTs,
    ] {
        let page = conversations_page(
            &conn,
            &ConversationFilter::default(),
            sort,
            false,
            &PageRequest::first(100),
        )
        .unwrap();
        assert_eq!(page.items.len(), 30, "{sort:?}");
    }
}

#[test]
fn filters_combine() {
    let conn = db();
    thirty(&conn);
    let ips = |f: ConversationFilter| -> Vec<String> {
        all(&conn, &f, 100)
            .into_iter()
            .map(|e| e.row.src_ip.to_string())
            .collect()
    };
    // IP substring or name substring, case-insensitive.
    assert_eq!(
        ips(ConversationFilter {
            from: Some("10.0.1.2".into()),
            ..ConversationFilter::default()
        }),
        [
            "10.0.1.29",
            "10.0.1.28",
            "10.0.1.27",
            "10.0.1.26",
            "10.0.1.25",
            "10.0.1.24",
            "10.0.1.23",
            "10.0.1.22",
            "10.0.1.21",
            "10.0.1.20",
            "10.0.1.2"
        ]
    );
    assert_eq!(
        ips(ConversationFilter {
            from: Some(" HOST7.example".into()),
            ..ConversationFilter::default()
        }),
        ["10.0.1.7"]
    );
    assert_eq!(
        ips(ConversationFilter {
            to: Some("10.0.1".into()),
            ..ConversationFilter::default()
        })
        .len(),
        0
    );
    let dns = ips(ConversationFilter {
        protocol: Some("dns".into()),
        ..ConversationFilter::default()
    });
    assert_eq!(dns.len(), 10);
    // Both ends count: the server is private, so every conversation matches "private".
    let f = ConversationFilter {
        categories: Some(vec!["private".into()]),
        ..ConversationFilter::default()
    };
    assert_eq!(ips(f.clone()).len(), 30);
    assert_eq!(count_conversations(&conn, &f).unwrap(), 30);
    let public_dns = ConversationFilter {
        protocol: Some("dns".into()),
        categories: Some(vec!["public".into()]),
        ..ConversationFilter::default()
    };
    assert_eq!(
        ips(public_dns),
        [
            "10.0.1.27",
            "10.0.1.21",
            "10.0.1.15",
            "10.0.1.9",
            "10.0.1.3"
        ]
    );
}

#[test]
fn top_n_matches_the_sql_sort_with_and_without_dns() {
    let conn = db();
    thirty(&conn);
    let top: Vec<String> = top_conversations(&conn, 10, false)
        .unwrap()
        .into_iter()
        .map(|e| e.row.src_ip.to_string())
        .collect();
    let expected: Vec<String> = (21..=30).rev().map(|i| format!("10.0.1.{i}")).collect();
    assert_eq!(top, expected);

    let top = top_conversations(&conn, 10, true).unwrap();
    assert_eq!(top.len(), 10);
    assert!(
        top.iter()
            .all(|e| !e.row.protocols.contains(&"dns".to_owned()))
    );
    assert_eq!(top[0].row.src_ip.to_string(), "10.0.1.29");
    // Only DNS conversations left: none of them (they would be empty).
    assert_eq!(top_conversations(&conn, 1_000, true).unwrap().len(), 20);
    assert_eq!(top_conversations(&conn, 1_000, false).unwrap().len(), 30);
}

#[test]
fn sort_and_top_queries_use_indexes() {
    let conn = db();
    thirty(&conn);
    let plan = |sql: &str| -> String {
        let mut stmt = conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap();
        let rows = stmt.query_map([], |r| r.get::<_, String>(3)).unwrap();
        rows.map(Result::unwrap).collect::<Vec<_>>().join("\n")
    };
    let p =
        plan("SELECT c.id FROM conversations c ORDER BY c.bytes_total DESC, c.id DESC LIMIT 10");
    assert!(p.contains("conversations_bytes"), "{p}");
    assert!(!p.contains("TEMP B-TREE"), "{p}");
    let p = plan(
        "SELECT c.id FROM conversations c WHERE (c.bytes_fwd + c.bytes_rev - c.dns_bytes_fwd - c.dns_bytes_rev) > 0 \
         ORDER BY (c.bytes_fwd + c.bytes_rev - c.dns_bytes_fwd - c.dns_bytes_rev) DESC, c.id DESC LIMIT 10",
    );
    assert!(p.contains("conversations_bytes_no_dns"), "{p}");
    assert!(!p.contains("TEMP B-TREE"), "{p}");
}

#[test]
fn countries_group_hosts_with_and_without_country() {
    let conn = db();
    let traffic = |ip: &str, sent: u64, received: u64| {
        StoreRecord::HostTraffic(HostTrafficRow {
            ip: ip.parse().unwrap(),
            bytes_sent: sent,
            bytes_received: received,
            packets_sent: 1,
            packets_received: 1,
        })
    };
    for r in [
        traffic("81.0.0.1", 1_000, 10),
        traffic("81.0.0.2", 500, 0),
        traffic("81.0.0.2", 500, 20),
        traffic("5.0.0.1", 300, 5),
        traffic("9.9.9.9", 50, 0),
        traffic("192.168.1.10", 30, 2_000),
        StoreRecord::Host(host("81.0.0.1", "public", Some("FR"), &[])),
        StoreRecord::Host(host("81.0.0.2", "public", Some("FR"), &[])),
        StoreRecord::Host(host("5.0.0.1", "public", Some("DE"), &[])),
        StoreRecord::Host(host("9.9.9.9", "public", None, &[])),
        StoreRecord::Host(host("192.168.1.10", "private", None, &[])),
    ] {
        insert(&conn, r);
    }
    let sent = country_traffic(&conn, TrafficSide::Sent).unwrap();
    let summary: Vec<_> = sent
        .iter()
        .map(|c| (c.country.as_deref(), c.public, c.bytes, c.hosts))
        .collect();
    assert_eq!(
        summary,
        vec![
            (Some("FR"), true, 2_000, 2),
            (Some("DE"), true, 300, 1),
            (None, true, 50, 1),
            (None, false, 30, 1),
        ]
    );
    let received = country_traffic(&conn, TrafficSide::Received).unwrap();
    assert_eq!(received[0].country, None);
    assert!(!received[0].public);
    assert_eq!(
        received.len(),
        3,
        "hosts that received nothing are left out: {received:?}"
    );
}
