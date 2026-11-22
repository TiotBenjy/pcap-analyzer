use std::net::{IpAddr, Ipv4Addr};

use rusqlite::Connection;

use super::*;
use crate::migrate::migrate;
use crate::schema::SESSION_SCHEMA;

fn db() -> Connection {
    let mut conn = Connection::open_in_memory().unwrap();
    migrate(&mut conn, &SESSION_SCHEMA).unwrap();
    conn
}

fn v4(last: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(192, 168, 1, last))
}

const GROUP: IpAddr = IpAddr::V4(Ipv4Addr::new(239, 255, 255, 250));

fn notify(ts: i64, last: u8, uuid: &str, target: &str, nts: &str) -> SsdpRow {
    SsdpRow {
        ts,
        src_ip: v4(last),
        src_port: 1900,
        dst_ip: GROUP,
        dst_port: 1900,
        multicast: true,
        kind: "notify".to_owned(),
        nts: Some(nts.to_owned()),
        status: None,
        target: Some(target.to_owned()),
        usn: Some(format!("uuid:{uuid}::{target}")),
        uuid: Some(uuid.to_owned()),
        server: (nts != "byebye").then(|| format!("Server/{ts}")),
        user_agent: None,
        location: (nts != "byebye").then(|| format!("http://192.168.1.{last}/d{ts}.xml")),
        max_age: Some(1800),
        mx: None,
        size: 300,
        raw: format!("NOTIFY * HTTP/1.1\nNT: {target}\n"),
        raw_truncated: false,
        device_type: target.contains(":device:").then(|| target.to_owned()),
    }
}

fn search(ts: i64, last: u8, target: &str) -> SsdpRow {
    SsdpRow {
        kind: "search".to_owned(),
        nts: None,
        usn: None,
        uuid: None,
        server: None,
        user_agent: Some("Agent/1".to_owned()),
        location: None,
        mx: Some(2),
        src_port: 50_000,
        device_type: None,
        target: Some(target.to_owned()),
        ..notify(ts, last, "x", target, "alive")
    }
}

fn response(ts: i64, last: u8, uuid: &str, target: &str) -> SsdpRow {
    SsdpRow {
        kind: "response".to_owned(),
        nts: None,
        status: Some(200),
        dst_ip: v4(10),
        dst_port: 50_000,
        multicast: false,
        ..notify(ts, last, uuid, target, "alive")
    }
}

const IGD: &str = "urn:schemas-upnp-org:device:InternetGatewayDevice:1";

fn fill(conn: &Connection) {
    // The gateway (.1) announces three targets, answers a search, then says byebye; the TV
    // (.40) announces once; the workstation (.10) searches twice.
    for r in [
        notify(10, 1, "gw", "upnp:rootdevice", "alive"),
        notify(11, 1, "gw", IGD, "alive"),
        notify(12, 1, "gw", "uuid:gw", "alive"),
        search(20, 10, "ssdp:all"),
        response(21, 1, "gw", IGD),
        notify(
            30,
            40,
            "tv",
            "urn:schemas-upnp-org:device:MediaRenderer:1",
            "alive",
        ),
        search(40, 10, "upnp:rootdevice"),
        notify(50, 1, "gw", "upnp:rootdevice", "byebye"),
    ] {
        r.insert(conn).unwrap();
    }
}

#[test]
fn devices_fold_per_uuid_and_address() {
    let conn = db();
    fill(&conn);
    let page = devices_page(&conn, None, None, &PageRequest::first(10)).unwrap();
    assert_eq!(page.items.len(), 2);
    let gw = &page.items[0];
    assert_eq!((gw.uuid.as_str(), gw.ip), ("gw", v4(1)));
    assert_eq!(gw.message_count, 5);
    assert_eq!(
        (gw.alive_count, gw.byebye_count, gw.response_count),
        (3, 1, 1)
    );
    assert_eq!((gw.first_ts, gw.last_ts), (10, 50));
    assert_eq!(gw.device_type, IGD);
    // The byebye at 50 carries no SERVER / LOCATION: the latest non-empty values stay.
    assert_eq!(gw.server, "Server/21");
    assert_eq!(gw.location, "http://192.168.1.1/d21.xml");
    assert_eq!(page.items[1].uuid, "tv");
    assert_eq!(
        device_targets(&conn, "gw", v4(1), 16).unwrap(),
        vec![
            "upnp:rootdevice".to_owned(),
            IGD.to_owned(),
            "uuid:gw".to_owned()
        ]
    );
    assert_eq!(device_targets(&conn, "gw", v4(1), 1).unwrap().len(), 1);
}

#[test]
fn searches_never_create_devices() {
    let conn = db();
    // A search carrying an identifier (USN or a `uuid:` target) names what it looks for.
    SsdpRow {
        uuid: Some("tv".to_owned()),
        target: Some("uuid:tv".to_owned()),
        ..search(10, 10, "uuid:tv")
    }
    .insert(&conn)
    .unwrap();
    assert_eq!(count_devices(&conn, None, None).unwrap(), 0);
    assert_eq!(
        count_messages(&conn, &SsdpMessageFilter::default()).unwrap(),
        1
    );
}

#[test]
fn an_empty_value_never_beats_a_later_arrival() {
    // Negative times (before 1970) are valid packet times: the empty value of the first message
    // must not win over them because of its placeholder timestamp.
    let rows = [
        SsdpRow {
            server: None,
            location: None,
            ..notify(10, 1, "gw", IGD, "alive")
        },
        notify(-5, 1, "gw", "upnp:rootdevice", "alive"),
    ];
    for order in [[0, 1], [1, 0]] {
        let conn = db();
        for i in order {
            rows[i].insert(&conn).unwrap();
        }
        let d = devices_page(&conn, None, None, &PageRequest::first(10))
            .unwrap()
            .items;
        assert_eq!(d[0].server, "Server/-5", "{order:?}");
        assert_eq!(d[0].location, "http://192.168.1.1/d-5.xml", "{order:?}");
        assert_eq!(d[0].device_type, IGD, "{order:?}");
    }
}

#[test]
fn device_fold_is_order_independent() {
    let rows = [
        notify(10, 1, "gw", IGD, "alive"),
        notify(30, 1, "gw", "upnp:rootdevice", "byebye"),
        response(20, 1, "gw", IGD),
        SsdpRow {
            server: Some("Other/1".to_owned()),
            ..notify(20, 1, "gw", "uuid:gw", "alive")
        },
    ];
    let mut seen = None;
    for perm in [[0, 1, 2, 3], [3, 2, 1, 0], [1, 3, 0, 2], [2, 0, 3, 1]] {
        let conn = db();
        for i in perm {
            rows[i].insert(&conn).unwrap();
        }
        let d = devices_page(&conn, None, None, &PageRequest::first(10))
            .unwrap()
            .items;
        if let Some(prev) = &seen {
            assert_eq!(prev, &d, "{perm:?}");
        }
        seen = Some(d);
    }
    let d = seen.unwrap();
    // Same timestamp (20): the greater value wins.
    assert_eq!(d[0].server, "Server/20");
}

#[test]
fn messages_filter_and_count() {
    let conn = db();
    fill(&conn);
    let all = SsdpMessageFilter::default();
    assert_eq!(count_messages(&conn, &all).unwrap(), 8);
    let f = |filter: SsdpMessageFilter| {
        let page = messages_page(&conn, &filter, &PageRequest::first(100)).unwrap();
        assert_eq!(
            page.items.len() as u64,
            count_messages(&conn, &filter).unwrap()
        );
        page.items.iter().map(|m| m.ts).collect::<Vec<_>>()
    };
    assert_eq!(
        f(SsdpMessageFilter {
            kind: Some("search".to_owned()),
            ..all.clone()
        }),
        vec![20, 40]
    );
    assert_eq!(
        f(SsdpMessageFilter {
            kind: Some("notify".to_owned()),
            nts: Some("byebye".to_owned()),
            ..all.clone()
        }),
        vec![50]
    );
    assert_eq!(
        f(SsdpMessageFilter {
            uuid: Some("gw".to_owned()),
            src: Some(v4(1)),
            ..all.clone()
        }),
        vec![10, 11, 12, 21, 50]
    );
    assert_eq!(
        f(SsdpMessageFilter {
            target: Some(IGD.to_owned()),
            ..all.clone()
        }),
        vec![11, 21]
    );
    // Search in the location, LIKE wildcards taken literally.
    assert_eq!(
        f(SsdpMessageFilter {
            q: Some("d30.xml".to_owned()),
            ..all.clone()
        }),
        vec![30]
    );
    assert_eq!(
        f(SsdpMessageFilter {
            q: Some("%".to_owned()),
            ..all.clone()
        }),
        Vec::<i64>::new()
    );
    // Point range, half-open.
    assert_eq!(
        f(SsdpMessageFilter {
            range: TimeRange::new(20, 40),
            ..all
        }),
        vec![20, 21, 30]
    );
}

#[test]
fn message_pages_follow_the_keyset() {
    let conn = db();
    // Identical timestamps: the id breaks the tie.
    for i in 0..25 {
        search(100 + i / 3, 10, "ssdp:all").insert(&conn).unwrap();
    }
    let mut ids = Vec::new();
    let mut cursor = None;
    loop {
        let page = messages_page(
            &conn,
            &SsdpMessageFilter::default(),
            &PageRequest { limit: 7, cursor },
        )
        .unwrap();
        ids.extend(page.items.iter().map(|m| m.id));
        cursor = page.next_cursor;
        if cursor.is_none() {
            break;
        }
    }
    assert_eq!(ids, (1..=25).collect::<Vec<i64>>());
}

#[test]
fn device_ranges_and_pages() {
    let conn = db();
    fill(&conn);
    // The TV (30..30) overlaps [25, 35); the gateway (10..50) too.
    let r = TimeRange::new(25, 35);
    assert_eq!(count_devices(&conn, None, r).unwrap(), 2);
    assert_eq!(
        count_devices(&conn, None, TimeRange::new(51, 60)).unwrap(),
        0
    );
    assert_eq!(
        count_devices(&conn, Some("mediarenderer"), None).unwrap(),
        1
    );
    let first = devices_page(&conn, None, None, &PageRequest::first(1)).unwrap();
    assert_eq!(first.items[0].uuid, "gw");
    let second = devices_page(
        &conn,
        None,
        None,
        &PageRequest {
            limit: 1,
            cursor: first.next_cursor,
        },
    )
    .unwrap();
    assert_eq!(second.items[0].uuid, "tv");
    assert!(second.next_cursor.is_none());
}

#[test]
fn stats_count_kinds_and_rank() {
    let conn = db();
    fill(&conn);
    let s = stats(&conn, 10, None).unwrap();
    assert_eq!(
        (
            s.messages, s.notify, s.alive, s.byebye, s.search, s.response, s.invalid
        ),
        (8, 5, 4, 1, 2, 1, 0)
    );
    assert_eq!((s.devices, s.senders), (2, 3));
    assert_eq!(s.targets[0], ("upnp:rootdevice".to_owned(), 3));
    assert_eq!(s.senders_top[0].0, v4(1));
    assert_eq!(s.senders_top[0].1, 5);
    assert!(s.software.iter().any(|(n, c)| n == "Agent/1" && *c == 2));

    let r = stats(&conn, 10, TimeRange::new(20, 41)).unwrap();
    assert_eq!((r.messages, r.search, r.response, r.notify), (4, 2, 1, 1));
    assert_eq!(r.devices, 2);
    assert_eq!(r.senders, 3);
    assert_eq!(
        r.messages,
        crate::range::ModuleRows::Ssdp
            .count(&conn, TimeRange::new(20, 41).unwrap())
            .unwrap()
    );
}

#[test]
fn stats_queries_read_indexes_only() {
    let conn = db();
    fill(&conn);
    let plan = |sql: &str| -> String {
        let mut stmt = conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap();
        let rows = stmt.query_map([], |r| r.get::<_, String>(3)).unwrap();
        rows.map(Result::unwrap).collect::<Vec<_>>().join("\n")
    };
    for sql in [
        "SELECT kind, nts, count(*) FROM ssdp_messages WHERE +ts >= 1 AND +ts < 2 GROUP BY kind, nts",
        "SELECT count(DISTINCT src_ip) FROM ssdp_messages WHERE +ts >= 1 AND +ts < 2",
        "SELECT target, count(*) AS n FROM ssdp_messages WHERE target IS NOT NULL \
         AND +ts >= 1 AND +ts < 2 GROUP BY target ORDER BY n DESC, target LIMIT 10",
        "SELECT software, count(*) AS n FROM ssdp_messages WHERE software IS NOT NULL \
         AND +ts >= 1 AND +ts < 2 GROUP BY software ORDER BY n DESC, software LIMIT 10",
    ] {
        let p = plan(sql);
        for line in p.lines().filter(|l| l.contains("ssdp_messages")) {
            assert!(line.contains("COVERING INDEX"), "{sql}\n{p}");
        }
    }
}

#[test]
fn fifty_thousand_messages_answer_quickly() {
    // Order of magnitude of a busy LAN; the 300 ms target is for 10 M packets in release mode,
    // this debug-mode check only guards against a full scan per page or aggregate.
    let conn = db();
    conn.execute_batch("BEGIN").unwrap();
    for i in 0..50_000_i64 {
        let last = u8::try_from(i % 200).unwrap();
        let row = if i % 5 == 0 {
            search(i, last, "ssdp:all")
        } else {
            notify(i, last, &format!("dev{last}"), "upnp:rootdevice", "alive")
        };
        row.insert(&conn).unwrap();
    }
    conn.execute_batch("COMMIT").unwrap();
    let range = TimeRange::new(10_000, 40_000);
    let start = std::time::Instant::now();
    let s = stats(&conn, 10, range).unwrap();
    assert_eq!(s.messages, 30_000);
    let page = messages_page(
        &conn,
        &SsdpMessageFilter {
            range,
            ..SsdpMessageFilter::default()
        },
        &PageRequest::first(200),
    )
    .unwrap();
    assert_eq!(page.items.len(), 200);
    let devices = devices_page(&conn, None, range, &PageRequest::first(100)).unwrap();
    assert_eq!(devices.items.len(), 100);
    let elapsed = start.elapsed();
    println!("stats + message page + device page under a range: {elapsed:?}");
    assert!(elapsed.as_secs() < 5, "{elapsed:?}");
}

/// Order of magnitude of the queries on 500 000 messages from 2 000 devices (a very busy LAN
/// over days). Run on demand in release mode:
/// `./x.sh cargo test --release -p netsift-store ssdp::tests::timings -- --ignored --nocapture`.
#[test]
#[ignore = "measurement, run on demand in release mode"]
fn timings() {
    let conn = db();
    conn.execute_batch("BEGIN").unwrap();
    for i in 0..500_000_i64 {
        let dev = i % 2000;
        let last = u8::try_from(dev % 250).unwrap();
        let ts = i * 1_000_000_000;
        let row = if i % 7 == 0 {
            search(ts, last, "ssdp:all")
        } else {
            let target =
                ["upnp:rootdevice", IGD, "urn:x:service:Y:1"][usize::try_from(i % 3).unwrap()];
            // One SERVER and one LOCATION per device, as real devices send.
            SsdpRow {
                server: Some(format!("Linux/5.10 UPnP/1.0 Product{}/1.0", dev % 40)),
                location: Some(format!("http://192.168.1.{last}:5000/{dev}.xml")),
                ..notify(ts, last, &format!("dev{dev}"), target, "alive")
            }
        };
        row.insert(&conn).unwrap();
    }
    conn.execute_batch("COMMIT; ANALYZE").unwrap();
    let total = 500_000 * 1_000_000_000_i64;
    for sql in [
        "SELECT kind, nts, count(*) FROM ssdp_messages GROUP BY kind, nts",
        "SELECT count(DISTINCT src_ip) FROM ssdp_messages",
        "SELECT target, count(*) AS n FROM ssdp_messages WHERE target IS NOT NULL \
         GROUP BY target ORDER BY n DESC, target LIMIT 10",
        "SELECT software, count(*) AS n FROM ssdp_messages WHERE software IS NOT NULL \
         GROUP BY software ORDER BY n DESC, software LIMIT 10",
        "SELECT src_ip AS ip, count(*) AS n FROM ssdp_messages GROUP BY src_ip \
         ORDER BY n DESC, src_ip LIMIT 10",
        "SELECT count(*) FROM ssdp_devices",
    ] {
        let t = std::time::Instant::now();
        let mut stmt = conn.prepare(sql).unwrap();
        let n = stmt.query_map([], |_| Ok(())).unwrap().count();
        let plan: Vec<String> = conn
            .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
            .unwrap()
            .query_map([], |r| r.get(3))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        println!("{:?} {n} rows {sql}\n  {}", t.elapsed(), plan.join(" | "));
    }
    for (name, range) in [
        ("whole", None),
        (
            "1 h",
            TimeRange::new(total / 2, total / 2 + 3_600 * 1_000_000_000),
        ),
        ("half", TimeRange::new(total / 4, total * 3 / 4)),
    ] {
        let t = std::time::Instant::now();
        stats(&conn, 10, range).unwrap();
        let stats_time = t.elapsed();
        let t = std::time::Instant::now();
        let filter = SsdpMessageFilter {
            range,
            ..SsdpMessageFilter::default()
        };
        messages_page(&conn, &filter, &PageRequest::first(200)).unwrap();
        count_messages(&conn, &filter).unwrap();
        let messages_time = t.elapsed();
        let t = std::time::Instant::now();
        let kind = SsdpMessageFilter {
            kind: Some("search".to_owned()),
            q: Some("all".to_owned()),
            range,
            ..SsdpMessageFilter::default()
        };
        messages_page(&conn, &kind, &PageRequest::first(200)).unwrap();
        count_messages(&conn, &kind).unwrap();
        let search_time = t.elapsed();
        let t = std::time::Instant::now();
        let page = devices_page(&conn, None, range, &PageRequest::first(200)).unwrap();
        for d in &page.items {
            device_targets(&conn, &d.uuid, d.ip, 16).unwrap();
        }
        count_devices(&conn, None, range).unwrap();
        let devices_time = t.elapsed();
        println!(
            "{name}: stats {stats_time:?}, messages {messages_time:?}, search+q {search_time:?}, \
             devices {devices_time:?}"
        );
    }
}
