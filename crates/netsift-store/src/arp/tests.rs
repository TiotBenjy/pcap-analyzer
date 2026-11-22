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

fn mac(last: u8) -> [u8; 6] {
    [2, 0, 0, 0, 0, last]
}

/// `sender` (IP and MAC suffix) tells `target`.
fn row(ts: i64, kind: &'static str, sender: (u8, u8), target: u8, unsolicited: bool) -> ArpRow {
    ArpRow {
        ts,
        frame: u64::try_from(ts).unwrap(),
        operation: if kind == "reply" { 2 } else { 1 },
        kind,
        sender_mac: Some(mac(sender.1)),
        sender_ip: Some(if kind == "probe" {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        } else {
            v4(sender.0)
        }),
        target_mac: None,
        target_ip: Some(v4(target)),
        unsolicited,
        binds: kind != "probe",
    }
}

/// .1 at :01 (router) answers .10 at :10; :66 claims .1 at t=50..70 with unsolicited replies.
fn fill(conn: &Connection) {
    let rows = [
        row(10, "request", (10, 10), 1, false),
        row(11, "reply", (1, 1), 10, false),
        row(20, "probe", (30, 30), 30, false),
        row(30, "gratuitous", (30, 30), 30, false),
        row(50, "reply", (1, 66), 10, true),
        row(60, "reply", (1, 66), 10, true),
        row(70, "reply", (66, 66), 10, false),
        row(80, "reply", (1, 1), 10, false),
    ];
    for r in rows {
        r.insert(conn).unwrap();
    }
}

#[test]
fn messages_fold_into_bindings() {
    let conn = db();
    fill(&conn);
    let counts = kind_counts(&conn, None).unwrap();
    assert_eq!(
        (
            counts.get("request"),
            counts.get("reply"),
            counts.get("gratuitous"),
            counts.get("probe"),
            counts.unsolicited,
            counts.total()
        ),
        (1, 5, 1, 1, 2, 8)
    );
    let page = bindings_page(
        &conn,
        &BindingFilters::default(),
        &PageRequest::first(10),
        None,
    )
    .unwrap();
    let rows: Vec<_> = page
        .items
        .iter()
        .map(|b| {
            (
                b.ip.to_string(),
                b.mac.clone(),
                b.first_ts,
                b.last_ts,
                b.messages,
                b.conflict,
            )
        })
        .collect();
    assert_eq!(
        rows,
        vec![
            (
                "192.168.1.10".into(),
                "02:00:00:00:00:0a".into(),
                10,
                10,
                1,
                false
            ),
            (
                "192.168.1.1".into(),
                "02:00:00:00:00:01".into(),
                11,
                80,
                2,
                true
            ),
            (
                "192.168.1.30".into(),
                "02:00:00:00:00:1e".into(),
                30,
                30,
                1,
                false
            ),
            (
                "192.168.1.1".into(),
                "02:00:00:00:00:42".into(),
                50,
                60,
                2,
                true
            ),
            (
                "192.168.1.66".into(),
                "02:00:00:00:00:42".into(),
                70,
                70,
                1,
                false
            ),
        ]
    );
    let f = binding_figures(&conn, None).unwrap();
    assert_eq!((f.bindings, f.addresses, f.conflicts), (5, 4, 1));
    let top = top_senders(&conn, 2, None).unwrap();
    assert_eq!(top[0].messages, 2);
    assert_eq!(top.len(), 2);
}

#[test]
fn message_filters_and_pages() {
    let conn = db();
    fill(&conn);
    let kinds = MessageFilters {
        kinds: vec!["reply".into(), "probe".into()],
        ..MessageFilters::default()
    };
    assert_eq!(count_messages(&conn, &kinds, None).unwrap(), 6);
    let by_ip = MessageFilters {
        ip: Some(v4(30)),
        ..MessageFilters::default()
    };
    assert_eq!(count_messages(&conn, &by_ip, None).unwrap(), 2);
    let by_mac = MessageFilters {
        mac: Some("02:00:00:00:00:42".into()),
        unsolicited: true,
        ..MessageFilters::default()
    };
    assert_eq!(count_messages(&conn, &by_mac, None).unwrap(), 2);
    // Pages of 3 cover every message once, in time order.
    let mut seen = Vec::new();
    let mut request = PageRequest::first(3);
    loop {
        let page = messages_page(&conn, &MessageFilters::default(), &request, None).unwrap();
        seen.extend(page.items.iter().map(|m| m.ts));
        match page.next_cursor {
            Some(c) => request.cursor = Some(c),
            None => break,
        }
    }
    assert_eq!(seen, vec![10, 11, 20, 30, 50, 60, 70, 80]);
    assert_eq!(period(&conn, None).unwrap(), Some((10, 80)));
}

#[test]
fn conflicts_and_their_signs() {
    let conn = db();
    fill(&conn);
    let (items, total) = conflicts(&conn, 10, 16, None).unwrap();
    assert_eq!(total, 1);
    let c = &items[0];
    assert_eq!(c.ip, v4(1));
    assert_eq!(c.mac_count, 2);
    assert_eq!(
        c.sides
            .iter()
            .map(|s| (s.mac.as_str(), s.other_ips, s.unsolicited))
            .collect::<Vec<_>>(),
        vec![("02:00:00:00:00:01", 0, 0), ("02:00:00:00:00:42", 1, 2)]
    );
    assert_eq!(c.signs, vec!["simultaneous", "unsolicited", "multiple_ips"]);
    let only = BindingFilters {
        conflicts: true,
        q: None,
    };
    assert_eq!(count_bindings(&conn, &only, None).unwrap(), 2);
    let search = BindingFilters {
        q: Some("00:1E".into()),
        conflicts: false,
    };
    assert_eq!(count_bindings(&conn, &search, None).unwrap(), 1);
    // A literal `%` matches nothing.
    let wild = BindingFilters {
        q: Some("%".into()),
        conflicts: false,
    };
    assert_eq!(count_bindings(&conn, &wild, None).unwrap(), 0);
}

#[test]
fn successive_owners_are_told_apart() {
    let side = |first, last| ConflictSide {
        mac: String::new(),
        first_ts: first,
        last_ts: last,
        messages: 1,
        gratuitous: 0,
        unsolicited: 0,
        other_ips: 0,
    };
    assert_eq!(signs(&[side(0, 10), side(11, 20)]), vec!["successive"]);
    assert_eq!(signs(&[side(11, 20), side(0, 11)]), vec!["simultaneous"]);
}

#[test]
fn a_range_keeps_the_messages_and_overlapping_bindings() {
    let conn = db();
    fill(&conn);
    // [45, 65): the two spoofed replies.
    let r = TimeRange::new(45, 65).unwrap();
    let counts = kind_counts(&conn, Some(r)).unwrap();
    assert_eq!((counts.total(), counts.unsolicited), (2, 2));
    assert_eq!(
        count_messages(&conn, &MessageFilters::default(), Some(r)).unwrap(),
        2
    );
    assert_eq!(period(&conn, Some(r)).unwrap(), Some((50, 60)));
    // Bindings active then: the router (11..80) and the intruder for .1 (50..60).
    let f = binding_figures(&conn, Some(r)).unwrap();
    assert_eq!((f.bindings, f.addresses, f.conflicts), (2, 1, 1));
    let (items, _) = conflicts(&conn, 10, 16, Some(r)).unwrap();
    // The intruder's own address (70) is outside the range.
    assert_eq!(items[0].sides[1].other_ips, 0);
    let top = top_senders(&conn, 10, Some(r)).unwrap();
    assert_eq!(top.len(), 1);
    assert_eq!(
        (top[0].mac.as_str(), top[0].messages),
        ("02:00:00:00:00:42", 2)
    );
    let page = bindings_page(
        &conn,
        &BindingFilters::default(),
        &PageRequest::first(10),
        Some(r),
    )
    .unwrap();
    assert_eq!(page.items.len(), 2);
    assert!(page.items.iter().all(|b| b.conflict));
    // Outside of every message.
    let empty = TimeRange::new(1000, 2000).unwrap();
    assert_eq!(kind_counts(&conn, Some(empty)).unwrap().total(), 0);
    assert_eq!(period(&conn, Some(empty)).unwrap(), None);
}
