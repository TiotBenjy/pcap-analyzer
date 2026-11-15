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

/// The filter before P4.2 (`?n IS NULL OR`, conditions on the joined hosts): the reference of
/// [`active_filters_match_the_former_filter`].
const FORMER_FILTER: &str = "\
    (?1 IS NULL OR instr(c.src_ip, ?1) > 0 OR instr(lower(coalesce(hs.names, '')), ?1) > 0) \
    AND (?2 IS NULL OR instr(c.dst_ip, ?2) > 0 OR instr(lower(coalesce(hd.names, '')), ?2) > 0) \
    AND (?3 IS NULL OR EXISTS (SELECT 1 FROM json_each(c.protocols) WHERE value = ?3)) \
    AND (?4 IS NULL OR hs.category IN (SELECT value FROM json_each(?4)) \
         OR hd.category IN (SELECT value FROM json_each(?4)))";

#[test]
#[allow(clippy::too_many_lines)] // Data, then every combination of filters.
fn active_filters_match_the_former_filter() {
    let conn = db();
    // 40 addresses, a quarter of them unknown to `hosts`, names on some, two categories.
    let ip = |i: u64| {
        if i.is_multiple_of(5) {
            format!("2001:db8::{i:x}")
        } else {
            format!("10.{}.0.{}", i % 3, i)
        }
    };
    for i in 0..40_u64 {
        if i % 4 == 3 {
            continue;
        }
        let names: Vec<String> = if i % 2 == 0 {
            vec![format!("Srv{i}.Example.test")]
        } else {
            Vec::new()
        };
        let names: Vec<&str> = names.iter().map(String::as_str).collect();
        let category = if i % 3 == 0 { "public" } else { "private" };
        insert(
            &conn,
            StoreRecord::Host(host(&ip(i), category, None, &names)),
        );
    }
    let labels = ["dns", "http", "tls", "udp"];
    let mut seed = 7_u64;
    for n in 0..300_u64 {
        seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        let (a, b) = ((seed >> 33) % 40, (seed >> 13) % 40);
        if a == b {
            continue;
        }
        let protocols: Vec<&str> = labels
            .iter()
            .enumerate()
            .filter(|(k, _)| (seed >> (k + 3)) & 1 == 1)
            .map(|(_, l)| *l)
            .collect();
        insert(
            &conn,
            StoreRecord::Conversation(conv(&ip(a), &ip(b), n * 7 % 1000, n, &protocols)),
        );
    }
    let texts = [
        None,
        Some("10.1"),
        Some("srv1"),
        Some("EXAMPLE"),
        Some("::"),
        Some("zz"),
    ];
    let protocols = [None, Some("dns"), Some("udp"), Some("nope")];
    let categories = [
        None,
        Some(vec!["public".to_owned()]),
        Some(vec!["private".to_owned()]),
    ];
    let mut checked = 0;
    for from in texts {
        for to in [None, Some("10.2"), Some("srv")] {
            for protocol in protocols {
                for cats in &categories {
                    let filter = ConversationFilter {
                        from: from.map(str::to_owned),
                        to: to.map(str::to_owned),
                        protocol: protocol.map(str::to_owned),
                        categories: cats.clone(),
                    };
                    let mut got: Vec<i64> = all(&conn, &filter, 7).iter().map(|e| e.id).collect();
                    got.sort_unstable();
                    let params = (
                        text_filter(filter.from.as_ref()),
                        text_filter(filter.to.as_ref()),
                        filter.protocol.clone(),
                        json_list(filter.categories.as_deref()).unwrap(),
                    );
                    let mut want: Vec<i64> = conn
                        .prepare(&format!(
                            "SELECT c.id FROM {CONVERSATION_FROM} WHERE {FORMER_FILTER} ORDER BY c.id"
                        ))
                        .unwrap()
                        .query_map(
                            params![params.0, params.1, params.2, params.3],
                            |r| r.get(0),
                        )
                        .unwrap()
                        .map(Result::unwrap)
                        .collect();
                    want.sort_unstable();
                    assert_eq!(got, want, "{filter:?}");
                    assert_eq!(
                        count_conversations(&conn, &filter).unwrap(),
                        u64::try_from(want.len()).unwrap(),
                        "{filter:?}"
                    );
                    checked += usize::from(!want.is_empty());
                }
            }
        }
    }
    assert!(checked > 50, "too few non-empty cases: {checked}");
}

#[test]
fn filtered_count_needs_no_join() {
    let conn = db();
    thirty(&conn);
    let filter = ConversationFilter {
        from: Some("host".into()),
        categories: Some(vec!["public".into()]),
        ..ConversationFilter::default()
    };
    let c = conditions(&filter).unwrap();
    let sql = format!(
        "SELECT count(*) FROM conversations c WHERE {}",
        c.sql().unwrap()
    );
    let plan: Vec<String> = conn
        .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
        .unwrap()
        .query_map(c.params().as_slice(), |r| r.get::<_, String>(3))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    // Hosts are read by the sub-queries only (one pass each), never joined per conversation.
    assert!(
        plan.iter().all(|l| !l.contains("hs") && !l.contains("hd")),
        "{plan:?}"
    );
    assert_eq!(count_conversations(&conn, &filter).unwrap(), 15);
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

#[test]
fn country_sums_saturate_instead_of_failing() {
    let conn = db();
    for ip in ["81.0.0.1", "81.0.0.2"] {
        insert(
            &conn,
            StoreRecord::HostTraffic(HostTrafficRow {
                ip: ip.parse().unwrap(),
                bytes_sent: u64::MAX,
                bytes_received: 0,
                packets_sent: 1,
                packets_received: 0,
            }),
        );
        insert(
            &conn,
            StoreRecord::Host(host(ip, "public", Some("FR"), &[])),
        );
    }
    let sent = country_traffic(&conn, TrafficSide::Sent).unwrap();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].bytes, i64::MAX as u64);
    assert_eq!(sent[0].hosts, 2);
}

fn flow(id: u64, src: &str, dst: &str, first_ts: i64) -> StoreRecord {
    StoreRecord::Flow(crate::records::FlowRow {
        id,
        transport: 6,
        src_ip: src.parse().unwrap(),
        src_port: 40_000,
        dst_ip: dst.parse().unwrap(),
        dst_port: 443,
        first_ts,
        last_ts: first_ts + 10,
        bytes_fwd: 1,
        bytes_rev: 1,
        packets_fwd: 1,
        packets_rev: 1,
        app_proto: None,
        tcp_state: None,
    })
}

#[test]
fn conversation_ends_and_flows_are_paged_by_first_seen() {
    use crate::query::conversation_flows_page;

    let conn = db();
    insert(
        &conn,
        StoreRecord::Conversation(conv("10.0.0.1", "10.0.0.2", 1, 1, &["tls"])),
    );
    let id: i64 = conn
        .query_row("SELECT id FROM conversations", [], |r| r.get(0))
        .unwrap();
    let (src, dst) = conversation_ends(&conn, id).unwrap().unwrap();
    assert_eq!(
        (src.to_string(), dst.to_string()),
        ("10.0.0.1".into(), "10.0.0.2".into())
    );
    assert_eq!(conversation_ends(&conn, id + 1).unwrap(), None);

    // Seven flows of the conversation (two with the same first_ts, ordered by id), plus flows
    // of the reverse orientation and of another pair, which never show up.
    for (i, ts) in [50, 10, 30, 30, 70, 20, 60].into_iter().enumerate() {
        insert(&conn, flow(100 + i as u64, "10.0.0.1", "10.0.0.2", ts));
    }
    insert(&conn, flow(1, "10.0.0.2", "10.0.0.1", 5));
    insert(&conn, flow(2, "10.0.0.1", "10.0.0.3", 5));
    let mut seen = Vec::new();
    let mut request = PageRequest::first(3);
    loop {
        let page = conversation_flows_page(&conn, src, dst, &request).unwrap();
        assert!(page.items.len() <= 3);
        seen.extend(page.items.iter().map(|f| (f.first_ts, f.id)));
        match page.next_cursor {
            Some(c) => request.cursor = Some(c),
            None => break,
        }
    }
    assert_eq!(
        seen,
        [
            (10, 101),
            (20, 105),
            (30, 102),
            (30, 103),
            (50, 100),
            (60, 106),
            (70, 104)
        ]
    );
}

#[test]
fn conversation_flows_query_uses_its_index() {
    let conn = db();
    let mut stmt = conn
        .prepare(
            "EXPLAIN QUERY PLAN SELECT id FROM flows WHERE (src_ip = ? AND dst_ip = ?) \
             AND (first_ts, id) > (?, ?) ORDER BY first_ts ASC, id ASC LIMIT 51",
        )
        .unwrap();
    let plan = stmt
        .query_map((("10.0.0.1"), ("10.0.0.2"), 5, 1), |r| {
            r.get::<_, String>(3)
        })
        .unwrap()
        .map(Result::unwrap)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(plan.contains("flows_conversation"), "{plan}");
    assert!(!plan.contains("TEMP B-TREE"), "{plan}");
    assert!(!plan.contains("SCAN"), "{plan}");
}

/// 600 conversations between private, public and multicast hosts and hosts absent from `hosts`,
/// with many equal sort keys (deterministic pseudo-random).
fn mixed_categories(conn: &Connection) {
    let mut seed: u64 = 0x2545_F491;
    let mut next = move |n: u64| {
        seed = seed
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (seed >> 33) % n
    };
    let end = |kind: u64, i: u64| match kind {
        0 => format!("10.0.{}.{}", i / 200, i % 200),
        1 => format!("81.0.{}.{}", i / 200, i % 200),
        2 => format!("224.0.0.{}", i % 20),
        _ => format!("100.64.0.{}", i % 50),
    };
    for _ in 0..600 {
        // Mostly private clients, mostly public servers; a few multicast and unknown ends.
        let src = end(
            [0, 0, 0, 0, 0, 0, 1, 3][usize::try_from(next(8)).unwrap()],
            next(120),
        );
        let dst = end(
            [1, 1, 1, 1, 0, 2, 3, 1][usize::try_from(next(8)).unwrap()],
            next(400),
        );
        let mut row = conv(
            &src,
            &dst,
            next(5) * 100,
            next(3),
            &[["dns", "tls", "http"][usize::try_from(next(3)).unwrap()]],
        );
        row.first_ts = i64::try_from(next(10)).unwrap();
        row.last_ts = 100 + i64::try_from(next(10)).unwrap();
        row.flows = next(4);
        insert(conn, StoreRecord::Conversation(row));
    }
    for i in 0..400 {
        for (kind, category) in [(0, "private"), (1, "public"), (2, "multicast")] {
            insert(
                conn,
                StoreRecord::Host(host(&end(kind, i), category, None, &[])),
            );
        }
    }
}

fn every_page(
    conn: &Connection,
    filter: &ConversationFilter,
    sort: ConversationSort,
    descending: bool,
    plan: CategoryPlan,
) -> Vec<i64> {
    let mut out = Vec::new();
    let mut request = PageRequest::first(7);
    loop {
        let page = page_with(conn, filter, sort, descending, &request, plan).unwrap();
        out.extend(page.items.iter().map(|e| e.id));
        match page.next_cursor {
            Some(c) => request.cursor = Some(c),
            None => return out,
        }
    }
}

#[test]
fn stored_category_counts_and_plans_read_the_same_conversations() {
    let conn = db();
    mixed_categories(&conn);
    finalize(&conn).unwrap();
    conn.execute(
        "INSERT INTO meta (key, value) VALUES ('finalizers', 'connections:1')",
        [],
    )
    .unwrap();
    let sets: [&[&str]; 7] = [
        &[],
        &["private"],
        &["public"],
        &["multicast"],
        &["loopback"],
        &["private", "multicast"],
        &["public", "private", "multicast", "cgnat"],
    ];
    let sorts = [
        ConversationSort::Bytes,
        ConversationSort::Packets,
        ConversationSort::Flows,
        ConversationSort::FirstTs,
        ConversationSort::LastTs,
    ];
    for set in sets {
        let categories = Some(set.iter().map(|c| (*c).to_owned()).collect::<Vec<_>>());
        let only = ConversationFilter {
            categories: categories.clone(),
            ..ConversationFilter::default()
        };
        let with_protocol = ConversationFilter {
            protocol: Some("tls".to_owned()),
            ..only.clone()
        };
        let want = count_at_read_time(&conn, &only).unwrap();
        assert_eq!(count_conversations(&conn, &only).unwrap(), want, "{set:?}");
        assert_eq!(
            count_conversations(&conn, &with_protocol).unwrap(),
            count_at_read_time(&conn, &with_protocol).unwrap()
        );
        for filter in [&only, &with_protocol] {
            for sort in sorts {
                for descending in [true, false] {
                    let want = every_page(&conn, filter, sort, descending, CategoryPlan::Lists);
                    assert_eq!(
                        usize::try_from(count_at_read_time(&conn, filter).unwrap()).unwrap(),
                        want.len()
                    );
                    for plan in [CategoryPlan::Probe, CategoryPlan::Lookup] {
                        let got = every_page(&conn, filter, sort, descending, plan);
                        assert_eq!(got, want, "{set:?} {sort:?} {descending} {plan:?}");
                    }
                }
            }
        }
    }
    // The plan follows the share of matching conversations.
    let plan = |set: &[&str], limit| {
        let filter = ConversationFilter {
            categories: Some(set.iter().map(|c| (*c).to_owned()).collect()),
            ..ConversationFilter::default()
        };
        category_plan(&conn, &filter, limit).unwrap()
    };
    assert_eq!(plan(&["public"], 50), CategoryPlan::Probe);
    assert_eq!(plan(&["multicast"], 50), CategoryPlan::Lookup);
    assert_eq!(plan(&["loopback"], 50), CategoryPlan::Lookup);
    // Before the step: the lists, and the count at read time.
    conn.execute("DELETE FROM meta WHERE key = 'finalizers'", [])
        .unwrap();
    conn.execute("DELETE FROM conversation_categories", [])
        .unwrap();
    assert_eq!(plan(&["public"], 50), CategoryPlan::Lists);
    let public = ConversationFilter {
        categories: Some(vec!["public".to_owned()]),
        ..ConversationFilter::default()
    };
    assert!(count_conversations(&conn, &public).unwrap() > 300);
}

#[test]
fn category_plans_use_their_indexes() {
    let conn = db();
    mixed_categories(&conn);
    let plan = |plan: CategoryPlan| -> String {
        let filter = ConversationFilter {
            categories: Some(vec!["public".to_owned()]),
            ..ConversationFilter::default()
        };
        let c = conditions_with(&filter, plan).unwrap();
        let sql = format!(
            "EXPLAIN QUERY PLAN SELECT c.id FROM {CONVERSATION_FROM} WHERE {} \
             ORDER BY c.bytes_total DESC, c.id DESC LIMIT 51",
            c.sql().unwrap()
        );
        let mut stmt = conn.prepare(&sql).unwrap();
        stmt.query_map(c.params().as_slice(), |r| r.get::<_, String>(3))
            .unwrap()
            .map(Result::unwrap)
            .collect::<Vec<_>>()
            .join("\n")
    };
    // Probe: the sort index, one primary key search per end, no list of hosts.
    let p = plan(CategoryPlan::Probe);
    assert!(p.contains("SCAN c USING INDEX conversations_bytes"), "{p}");
    assert!(
        p.contains("SEARCH h USING INDEX sqlite_autoindex_hosts_1 (ip=?)"),
        "{p}"
    );
    assert!(
        !p.contains("hosts_category") && !p.contains("TEMP B-TREE"),
        "{p}"
    );
    // Lookup: the conversations of the hosts of the category, by index, then sorted.
    let p = plan(CategoryPlan::Lookup);
    assert!(p.contains("MULTI-INDEX OR"), "{p}");
    assert!(p.contains("conversations_dst_ip"), "{p}");
    assert!(p.contains("hosts_category"), "{p}");
    assert!(!p.contains("SCAN c"), "{p}");
    // The stored counts: a few dozen rows at most, never `conversations`.
    let mut stmt = conn
        .prepare(
            "EXPLAIN QUERY PLAN SELECT coalesce(sum(conversations) FILTER (WHERE src_category IN \
             (SELECT value FROM json_each(?1)) OR dst_category IN (SELECT value FROM json_each(?1))), 0), \
             coalesce(sum(conversations), 0) FROM conversation_categories",
        )
        .unwrap();
    let p = stmt
        .query_map(["[\"public\"]"], |r| r.get::<_, String>(3))
        .unwrap()
        .map(Result::unwrap)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !p.contains("conversations ") && !p.contains("TEMP B-TREE"),
        "{p}"
    );
}

#[test]
fn both_sides_in_one_pass_match_each_side() {
    let conn = db();
    mixed_categories(&conn);
    let traffic = |ip: &str, sent: u64, received: u64| {
        StoreRecord::HostTraffic(HostTrafficRow {
            ip: ip.parse().unwrap(),
            bytes_sent: sent,
            bytes_received: received,
            packets_sent: 1,
            packets_received: 1,
        })
    };
    for (i, (ip, country)) in [
        ("81.0.0.1", Some("FR")),
        ("81.0.0.2", Some("FR")),
        ("81.0.0.3", Some("DE")),
        ("81.0.0.4", None),
        ("10.0.0.1", None),
        ("10.0.0.2", None),
        ("100.64.0.1", None),
    ]
    .into_iter()
    .enumerate()
    {
        let i = u64::try_from(i).unwrap();
        // Some hosts only send, some only receive, some neither.
        insert(&conn, traffic(ip, (i % 3) * 100, (i % 2) * 50 + i));
        if let Some(c) = country {
            insert(&conn, StoreRecord::Host(host(ip, "public", Some(c), &[])));
        }
    }
    insert(&conn, traffic("10.9.9.9", 0, 0));
    let (sent, received) = country_traffic_both(&conn).unwrap();
    assert_eq!(sent, country_traffic(&conn, TrafficSide::Sent).unwrap());
    assert_eq!(
        received,
        country_traffic(&conn, TrafficSide::Received).unwrap()
    );
    assert!(sent.len() >= 3 && received.len() >= 3);
}
