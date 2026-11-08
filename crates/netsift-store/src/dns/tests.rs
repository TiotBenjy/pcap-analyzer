use std::path::Path;

use super::*;
use crate::records::{HostRow, StoreRecord};
use crate::session::{OpenMode, Session};
use crate::writer::{StoreWriter, WriterConfig};

const MS: i64 = 1_000_000;
const T0: i64 = 1_700_000_000_000_000_000;

fn row(ts: i64, proto: &str, client: &str, server: &str, qname: &str) -> DnsRow {
    DnsRow {
        ts,
        flow_id: Some(1),
        transport: 17,
        proto: proto.to_owned(),
        client_ip: client.parse().unwrap(),
        client_port: 50_000,
        server_ip: server.parse().unwrap(),
        server_port: 53,
        responder_ip: None,
        txid: 1,
        opcode: "QUERY".to_owned(),
        qname: qname.to_owned(),
        qtype: "A".to_owned(),
        nb_suffix: None,
        flags: 0x8180,
        rcode: Some("NOERROR".to_owned()),
        latency_ns: Some(2 * MS),
        answers: Vec::new(),
        has_query: true,
        has_response: true,
        pending: false,
    }
}

fn answer(name: &str, rtype: &str, value: &str) -> DnsAnswerRow {
    DnsAnswerRow {
        name: name.to_owned(),
        rtype: rtype.to_owned(),
        value: value.to_owned(),
        ttl: 60,
    }
}

fn host(ip: &str, country: Option<&str>) -> StoreRecord {
    StoreRecord::Host(HostRow {
        ip: ip.parse().unwrap(),
        macs: Vec::new(),
        names: Vec::new(),
        country: country.map(str::to_owned),
        category: Some("private".to_owned()),
        first_ts: T0,
        last_ts: T0,
    })
}

/// A broadcast NBNS query, its unicast answer (as a separate response-only row), a second
/// responder, and an unanswered LLMNR multicast query.
fn group_rows() -> Vec<StoreRecord> {
    let mut query = row(T0, "nbns", "192.168.1.10", "192.168.1.255", "WPAD");
    query.server_port = 137;
    query.client_port = 137;
    query.qtype = "NB".to_owned();
    query.nb_suffix = Some(0);
    query.rcode = Some("timeout".to_owned());
    query.latency_ns = None;
    query.has_response = false;
    query.pending = true;
    query.flags = 0x0110;
    let mut response = row(T0 + 3 * MS, "nbns", "192.168.1.10", "192.168.1.20", "WPAD");
    response.server_port = 137;
    response.client_port = 137;
    response.qtype = "NB".to_owned();
    response.has_query = false;
    response.latency_ns = None;
    response.answers = vec![answer("WPAD", "NB", "192.168.1.20")];
    let mut second = response.clone();
    second.ts = T0 + 4 * MS;
    second.server_ip = "192.168.1.30".parse().unwrap();
    second.answers = vec![answer("WPAD", "NB", "192.168.1.30")];
    let mut llmnr = row(
        T0 + 10 * MS,
        "llmnr",
        "192.168.1.10",
        "224.0.0.252",
        "printer",
    );
    llmnr.rcode = Some("timeout".to_owned());
    llmnr.latency_ns = None;
    llmnr.has_response = false;
    llmnr.pending = true;
    vec![
        StoreRecord::Dns(Box::new(query)),
        StoreRecord::Dns(Box::new(response)),
        StoreRecord::Dns(Box::new(second)),
        StoreRecord::Dns(Box::new(llmnr)),
    ]
}

/// Plain DNS traffic: two answered names, a NXDOMAIN, a timeout.
fn dns_rows() -> Vec<StoreRecord> {
    let mut a = row(
        T0 + 20 * MS,
        "dns",
        "192.168.1.10",
        "192.168.1.1",
        "www.example.test",
    );
    a.answers = vec![answer("www.example.test", "A", "203.0.113.80")];
    let mut b = row(
        T0 + 21 * MS,
        "dns",
        "192.168.1.10",
        "192.168.1.1",
        "www.example.test",
    );
    b.latency_ns = Some(4 * MS);
    let mut cname = row(
        T0 + 22 * MS,
        "dns",
        "192.168.1.10",
        "8.8.8.8",
        "secure.example.test",
    );
    cname.answers = vec![
        answer("secure.example.test", "CNAME", "edge.cdn.example.net"),
        answer("edge.cdn.example.net", "A", "198.51.100.43"),
    ];
    let mut nx = row(
        T0 + 23 * MS,
        "dns",
        "192.168.1.10",
        "192.168.1.1",
        "missing.example.test",
    );
    nx.rcode = Some("NXDOMAIN".to_owned());
    let mut lost = row(
        T0 + 24 * MS,
        "dns",
        "192.168.1.11",
        "192.168.1.1",
        "lost.example.test",
    );
    lost.qtype = "AAAA".to_owned();
    lost.rcode = Some("timeout".to_owned());
    lost.latency_ns = None;
    lost.has_response = false;
    vec![
        StoreRecord::Dns(Box::new(a)),
        StoreRecord::Dns(Box::new(b)),
        StoreRecord::Dns(Box::new(cname)),
        StoreRecord::Dns(Box::new(nx)),
        StoreRecord::Dns(Box::new(lost)),
    ]
}

fn hosts() -> Vec<StoreRecord> {
    vec![
        host("192.168.1.10", None),
        host("192.168.1.1", None),
        host("192.168.1.20", None),
        host("203.0.113.80", None),
        host("8.8.8.8", Some("US")),
    ]
}

fn import(dir: &Path, records: Vec<StoreRecord>) -> Session {
    let session = Session::open(dir, OpenMode::Import).unwrap();
    let writer = StoreWriter::spawn(session, WriterConfig::default()).unwrap();
    writer.send_batch(records).unwrap();
    writer.finish().unwrap();
    Session::open(dir, OpenMode::ReadOnly).unwrap()
}

fn all_records() -> Vec<StoreRecord> {
    let mut v = hosts();
    v.extend(group_rows());
    v.extend(dns_rows());
    v
}

/// Content of the DNS tables and host names, without the arrival-order row ids.
fn dump(conn: &Connection) -> String {
    let mut out = String::new();
    let mut stmt = conn
        .prepare(
            "SELECT ts, proto, client_ip, server_ip, responder_ip, qname, rcode, latency_ns, \
             answers, has_query, has_response, pending, pair_id FROM dns_messages \
             ORDER BY ts, server_ip, qname",
        )
        .unwrap();
    let rows = stmt
        .query_map([], |r| {
            Ok(format!(
                "msg {} {} {} -> {} responder={:?} {} rcode={:?} latency={:?} {} q={} r={} \
                 pending={} pair={:?}",
                r.get::<_, i64>(0)? - T0,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, Option<String>>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, Option<String>>(6)?,
                r.get::<_, Option<i64>>(7)?,
                r.get::<_, String>(8)?,
                r.get::<_, i64>(9)?,
                r.get::<_, i64>(10)?,
                r.get::<_, i64>(11)?,
                r.get::<_, Option<i64>>(12)?,
            ))
        })
        .unwrap();
    for r in rows {
        out.push_str(&r.unwrap());
        out.push('\n');
    }
    let mut stmt = conn
        .prepare(
            "SELECT id, proto, client_ip, server_ip, messages, errors, names, top_names \
             FROM dns_pairs ORDER BY id",
        )
        .unwrap();
    let rows = stmt
        .query_map([], |r| {
            Ok(format!(
                "pair {} {} {} -> {} messages={} errors={} names={} top={}",
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, i64>(5)?,
                r.get::<_, i64>(6)?,
                r.get::<_, String>(7)?,
            ))
        })
        .unwrap();
    for r in rows {
        out.push_str(&r.unwrap());
        out.push('\n');
    }
    let mut stmt = conn
        .prepare("SELECT ip, names FROM hosts ORDER BY ip")
        .unwrap();
    let rows = stmt
        .query_map([], |r| {
            Ok(format!(
                "host {} {}",
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?
            ))
        })
        .unwrap();
    for r in rows {
        out.push_str(&r.unwrap());
        out.push('\n');
    }
    out
}

#[test]
fn end_of_import_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let session = import(dir.path(), all_records());
    insta::assert_snapshot!(dump(session.conn()));
}

#[test]
fn the_import_records_its_end_of_import_step() {
    let dir = tempfile::tempdir().unwrap();
    let session = import(dir.path(), all_records());
    assert_eq!(
        crate::query::get_meta(session.conn(), crate::finalize::MARKER_KEY)
            .unwrap()
            .as_deref(),
        Some("dns:1")
    );
}

#[test]
fn result_does_not_depend_on_arrival_order() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let mut reversed = all_records();
    reversed.reverse();
    let first = dump(import(a.path(), all_records()).conn());
    let second = dump(import(b.path(), reversed).conn());
    assert_eq!(first, second);
}

#[test]
fn group_query_pairs_with_the_earliest_response() {
    let dir = tempfile::tempdir().unwrap();
    let session = import(dir.path(), all_records());
    let conn = session.conn();
    let (responder, rcode, latency, pending): (Option<String>, String, i64, i64) = conn
        .query_row(
            "SELECT responder_ip, rcode, latency_ns, pending FROM dns_messages \
             WHERE proto = 'nbns' AND has_query = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .unwrap();
    assert_eq!(responder.as_deref(), Some("192.168.1.20"));
    assert_eq!(rcode, "NOERROR");
    assert_eq!(latency, 3 * MS);
    assert_eq!(pending, 0);
    // The second responder stays as a response-only transaction.
    let alone: i64 = conn
        .query_row(
            "SELECT count(*) FROM dns_messages WHERE proto = 'nbns' AND has_query = 0",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(alone, 1);
    // The LLMNR query had no answer: a timeout.
    let llmnr: (String, i64) = conn
        .query_row(
            "SELECT rcode, pending FROM dns_messages WHERE proto = 'llmnr'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(llmnr, ("timeout".to_owned(), 0));
}

#[test]
fn responses_outside_the_window_are_not_paired() {
    let dir = tempfile::tempdir().unwrap();
    let mut rows = group_rows();
    rows.truncate(2);
    if let StoreRecord::Dns(r) = &mut rows[1] {
        r.ts = T0 + PAIR_WINDOW_NS + 1;
    }
    let session = import(dir.path(), rows);
    let n: i64 = session
        .conn()
        .query_row("SELECT count(*) FROM dns_messages", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 2);
}

#[test]
fn resolved_names_feed_known_hosts_only() {
    let dir = tempfile::tempdir().unwrap();
    let session = import(dir.path(), all_records());
    let conn = session.conn();
    let names = |ip: &str| -> Option<String> {
        conn.query_row("SELECT names FROM hosts WHERE ip = ?1", [ip], |r| r.get(0))
            .ok()
    };
    assert_eq!(
        names("203.0.113.80").as_deref(),
        Some(r#"["www.example.test"]"#)
    );
    assert_eq!(names("192.168.1.20").as_deref(), Some(r#"["WPAD"]"#));
    // 198.51.100.43 was resolved but never seen in the traffic: no host row.
    assert_eq!(names("198.51.100.43"), None);
}

#[test]
fn stats_count_every_category() {
    let dir = tempfile::tempdir().unwrap();
    let session = import(dir.path(), all_records());
    let s = stats(session.conn()).unwrap();
    assert_eq!(s.total, 8);
    // NXDOMAIN, two timeouts.
    assert_eq!(s.errors, 3);
    let get = |v: &[Bucket], k: &str| {
        v.iter()
            .find(|b| b.key.as_deref() == Some(k))
            .map_or(0, |b| b.count)
    };
    assert_eq!(get(&s.protocols, "dns"), 5);
    assert_eq!(get(&s.protocols, "nbns"), 2);
    assert_eq!(get(&s.protocols, "llmnr"), 1);
    assert_eq!(get(&s.rcodes, "timeout"), 2);
    assert_eq!(get(&s.rcodes, "NXDOMAIN"), 1);
    assert_eq!(get(&s.qtypes, "A"), 5);
    assert_eq!(get(&s.qtypes, "AAAA"), 1);
    assert_eq!(
        s.countries,
        vec![CountryBucket {
            country: Some("US".to_owned()),
            servers: 1,
            messages: 1
        }]
    );
    assert_eq!(s.country_unknown.messages, 7);
    assert_eq!(s.latency_p50_ns, Some(2 * MS));
    assert_eq!(s.latency_p95_ns, Some(3 * MS));
}

#[test]
fn pairs_filters_search_and_pagination() {
    let dir = tempfile::tempdir().unwrap();
    let session = import(dir.path(), all_records());
    let conn = session.conn();
    let all = DnsFilter::default();
    let (page, total) = pairs_page(conn, &all, &PageRequest::first(100)).unwrap();
    assert_eq!(total, 6);
    assert_eq!(page.items.len(), 6);
    assert_eq!(page.items[0].messages, 3);
    assert_eq!(
        page.items[0].top_names,
        ["www.example.test", "missing.example.test"]
    );

    // Keyset pagination returns every pair once.
    let mut seen = Vec::new();
    let mut request = PageRequest::first(2);
    loop {
        let (page, _) = pairs_page(conn, &all, &request).unwrap();
        seen.extend(page.items.iter().map(|p| p.id));
        match page.next_cursor {
            Some(c) => request.cursor = Some(c),
            None => break,
        }
    }
    seen.sort_unstable();
    assert_eq!(seen, vec![1, 2, 3, 4, 5, 6]);

    let only = |protocols: &[&str], errors_only: bool, search: Option<&str>| {
        let filter = DnsFilter {
            protocols: protocols.iter().map(|p| (*p).to_owned()).collect(),
            errors_only,
            search: search.map(str::to_owned),
        };
        pairs_page(conn, &filter, &PageRequest::first(100))
            .unwrap()
            .1
    };
    assert_eq!(only(&["nbns"], false, None), 2);
    assert_eq!(only(&["dns", "llmnr"], true, None), 3);
    assert_eq!(only(&[], false, None), 0);
    assert_eq!(only(&["bogus"], false, None), 0);
    // Search: case-insensitive substring of names, addresses and answers.
    assert_eq!(
        only(&["dns", "mdns", "llmnr", "nbns"], false, Some("wpad")),
        2
    );
    assert_eq!(
        only(
            &["dns", "mdns", "llmnr", "nbns"],
            false,
            Some("cdn.example")
        ),
        1
    );
    assert_eq!(
        only(&["dns", "mdns", "llmnr", "nbns"], false, Some("8.8.8")),
        1
    );
    assert_eq!(
        only(&["dns", "mdns", "llmnr", "nbns"], false, Some("mi")),
        1
    );
    assert_eq!(
        only(&["dns", "mdns", "llmnr", "nbns"], false, Some("\"%_")),
        0
    );
    assert_eq!(only(&["dns", "mdns", "llmnr", "nbns"], false, Some("%")), 0);
    // Answers are searched by value, never through their JSON keys.
    assert_eq!(
        only(&["dns", "mdns", "llmnr", "nbns"], false, Some("ttl")),
        0
    );
    assert_eq!(
        only(&["dns", "mdns", "llmnr", "nbns"], false, Some("tt")),
        0
    );
    assert_eq!(
        only(&["dns", "mdns", "llmnr", "nbns"], false, Some("198.51.100")),
        1
    );
}

#[test]
fn messages_of_a_pair_in_time_order() {
    let dir = tempfile::tempdir().unwrap();
    let session = import(dir.path(), all_records());
    let conn = session.conn();
    let (pairs, _) = pairs_page(conn, &DnsFilter::default(), &PageRequest::first(1)).unwrap();
    let pair = pairs.items[0].id;
    let (page, total) = messages_page(
        conn,
        Some(pair),
        &DnsFilter::default(),
        &PageRequest::first(2),
    )
    .unwrap();
    assert_eq!(total, 3);
    assert_eq!(page.items.len(), 2);
    assert!(page.items[0].ts <= page.items[1].ts);
    assert_eq!(page.items[0].answers[0].value, "203.0.113.80");
    let (rest, _) = messages_page(
        conn,
        Some(pair),
        &DnsFilter::default(),
        &PageRequest {
            limit: 2,
            cursor: page.next_cursor,
        },
    )
    .unwrap();
    assert_eq!(rest.items.len(), 1);
    assert_eq!(rest.items[0].rcode.as_deref(), Some("NXDOMAIN"));
    assert_eq!(rest.next_cursor, None);

    let errors = DnsFilter {
        errors_only: true,
        ..DnsFilter::default()
    };
    let (_, n) = messages_page(conn, None, &errors, &PageRequest::first(10)).unwrap();
    assert_eq!(n, 3);
    let search = DnsFilter {
        search: Some("WPAD".to_owned()),
        ..DnsFilter::default()
    };
    let (found, n) = messages_page(conn, None, &search, &PageRequest::first(10)).unwrap();
    assert_eq!(n, 2);
    assert!(found.items.iter().all(|m| m.proto == "nbns"));
}

#[test]
fn servers_with_geolocation() {
    let dir = tempfile::tempdir().unwrap();
    let session = import(dir.path(), all_records());
    let (page, total) = servers_page(session.conn(), &PageRequest::first(100)).unwrap();
    assert_eq!(total, 5);
    let first = &page.items[0];
    assert_eq!(first.ip.to_string(), "192.168.1.1");
    assert_eq!(first.messages, 4);
    assert_eq!(first.clients, 2);
    assert_eq!(first.protocols, ["dns"]);
    let google = page
        .items
        .iter()
        .find(|s| s.ip.to_string() == "8.8.8.8")
        .unwrap();
    assert_eq!(google.host.country.as_deref(), Some("US"));
}

#[test]
fn finalize_is_idempotent_and_handles_empty_sessions() {
    let dir = tempfile::tempdir().unwrap();
    let session = import(dir.path(), Vec::new());
    assert_eq!(stats(session.conn()).unwrap(), DnsStats::default());
    drop(session);
    let dir = tempfile::tempdir().unwrap();
    let session = import(dir.path(), all_records());
    let before = dump(session.conn());
    drop(session);
    let rw = Session::open(dir.path(), OpenMode::ReadWrite).unwrap();
    finalize(rw.conn()).unwrap();
    assert_eq!(dump(rw.conn()), before);
}

/// A session whose rows were written but whose end-of-import step never ran (interrupted
/// import, recovered as `incomplete`).
fn unfinalized(dir: &Path) {
    let session = Session::open(dir, OpenMode::ReadWrite).unwrap();
    for record in all_records() {
        match record {
            StoreRecord::Dns(r) => r.insert(session.conn()).unwrap(),
            StoreRecord::Host(h) => StoreRecord::Host(h).insert(session.conn()).unwrap(),
            _ => unreachable!(),
        }
    }
}

fn pair_count(session: &Session) -> i64 {
    session
        .conn()
        .query_row("SELECT count(*) FROM dns_pairs", [], |r| r.get(0))
        .unwrap()
}

#[test]
fn an_unfinalized_session_is_finalized_at_opening() {
    use crate::session::Upgrade;
    let dir = tempfile::tempdir().unwrap();
    unfinalized(dir.path());

    // A read-only server never writes: readable, steps still pending, no error.
    let session = Session::open_finished(dir.path(), Upgrade::Refuse).unwrap();
    assert_eq!(pair_count(&session), 0);
    assert!(!crate::finalize::finalizers_complete(session.conn()).unwrap());
    drop(session);

    let session = Session::open_finished(dir.path(), Upgrade::Apply).unwrap();
    assert_eq!(session.mode(), OpenMode::ReadOnly);
    assert!(crate::finalize::finalizers_complete(session.conn()).unwrap());
    assert_eq!(pair_count(&session), 6);
    let search = DnsFilter {
        search: Some("wpad".to_owned()),
        ..DnsFilter::default()
    };
    let (_, n) = messages_page(session.conn(), None, &search, &PageRequest::first(10)).unwrap();
    assert_eq!(n, 2, "search index rebuilt");
    let before = dump(session.conn());
    drop(session);

    // Idempotent: the next opening finds nothing to do and changes nothing.
    let session = Session::open_finished(dir.path(), Upgrade::Apply).unwrap();
    assert_eq!(dump(session.conn()), before);
}

#[test]
fn filled_tables_leave_the_list_of_tables_added_after_the_import() {
    use crate::session::{TABLES_ADDED_AFTER_IMPORT, Upgrade, tables_added_after_import};
    let set = |value: &str| {
        let s = Session::open(tempfile::tempdir().unwrap().keep(), OpenMode::ReadWrite).unwrap();
        s.conn()
            .execute(
                "INSERT INTO meta (key, value) VALUES (?1, ?2)",
                [TABLES_ADDED_AFTER_IMPORT, value],
            )
            .unwrap();
        s.dir().to_path_buf()
    };
    // The DNS analyzer never ran: nothing derived, everything stays listed.
    let old = set("dns_fts,dns_messages,dns_pairs");
    let session = Session::open_finished(&old, Upgrade::Apply).unwrap();
    assert_eq!(tables_added_after_import(session.conn()).unwrap().len(), 3);
    // Its data is there (only the derived tables were added): they are filled now.
    let derived = set("dns_fts,dns_pairs,later_items");
    let session = Session::open_finished(&derived, Upgrade::Apply).unwrap();
    assert_eq!(
        tables_added_after_import(session.conn())
            .unwrap()
            .into_iter()
            .collect::<Vec<_>>(),
        ["later_items"]
    );
    for dir in [old, derived] {
        let _ = std::fs::remove_dir_all(dir);
    }
}
