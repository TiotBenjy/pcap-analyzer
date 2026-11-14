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

/// Public id of the entry folded under `fp`.
fn id_of(conn: &Connection, fp: &str) -> String {
    conn.query_row(
        "SELECT id FROM credentials WHERE fingerprint = ?1",
        [fp],
        |r| r.get(0),
    )
    .unwrap()
}

/// Fingerprint of a public id (tests only: the queries never read it back).
fn fp_of(conn: &Connection, id: &str) -> String {
    conn.query_row(
        "SELECT fingerprint FROM credentials WHERE id = ?1",
        [id],
        |r| r.get(0),
    )
    .unwrap()
}

fn ip(last: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(192, 168, 1, last))
}

fn row(fp: &str, protocol: &str, state: &str, ts: i64, flow: u64) -> CredentialRow {
    CredentialRow {
        fingerprint: fp.to_owned(),
        protocol: protocol.to_owned(),
        kind: protocol.to_owned(),
        secret_state: state.to_owned(),
        flow_id: Some(flow),
        client_ip: Some(ip(10)),
        client_port: Some(u16::try_from(40_000 + flow).unwrap()),
        server_ip: Some(ip(1)),
        server_port: Some(161),
        username: None,
        domain: None,
        workstation: None,
        secret: (state == "plaintext").then(|| format!("secret-{fp}")),
        hashcat_mode: (state == "recoverable").then_some(5600),
        hashcat_line: (state == "recoverable").then(|| format!("line-{fp}")),
        details: vec![("flow".to_owned(), flow.to_string())],
        ts,
    }
}

#[test]
fn identical_credentials_fold_whatever_the_order() {
    let observations = [
        row("a", "snmp", "plaintext", 30, 3),
        row("a", "snmp", "plaintext", 10, 1),
        row("a", "snmp", "plaintext", 20, 2),
        row("a", "snmp", "plaintext", 10, 0),
    ];
    let mut results = Vec::new();
    for order in [[0, 1, 2, 3], [3, 2, 1, 0], [1, 3, 0, 2]] {
        let conn = db();
        for i in order {
            observations[i].insert(&conn).unwrap();
        }
        let page = page(&conn, &CredentialFilter::default(), &PageRequest::first(10)).unwrap();
        assert_eq!(page.items.len(), 1);
        let mut e = page.items[0].clone();
        let id = std::mem::take(&mut e.id);
        // Random public id: 16 bytes in hex, never the fingerprint.
        assert_eq!(id.len(), 32);
        assert!(
            id.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
        results.push(e);
    }
    assert!(results.windows(2).all(|w| w[0] == w[1]), "{results:?}");
    let e = &results[0];
    assert_eq!(e.seen_count, 4);
    assert_eq!((e.first_ts, e.last_ts), (10, 30));
    // Earliest observation, lowest flow id on a tie.
    assert_eq!(e.flow_id, Some(0));
    assert_eq!(e.client.as_ref().unwrap().port, Some(40_000));
    assert_eq!(e.details, vec![("flow".to_owned(), "0".to_owned())]);
    assert!(e.has_secret);
}

#[test]
fn lists_never_carry_secrets_but_detail_and_export_do() {
    let conn = db();
    row("p", "ftp", "plaintext", 1, 1).insert(&conn).unwrap();
    row("r", "smb", "recoverable", 2, 2).insert(&conn).unwrap();
    row("m", "smb", "metadata-only", 3, 3)
        .insert(&conn)
        .unwrap();

    let (p, r) = (id_of(&conn, "p"), id_of(&conn, "r"));
    let d = detail(&conn, &p).unwrap().unwrap();
    assert_eq!(d.secret.as_deref(), Some("secret-p"));
    let debug = format!("{d:?}");
    assert!(!debug.contains("secret-p"), "{debug}");
    assert!(detail(&conn, "nope").unwrap().is_none());

    let all = export(&conn, &CredentialFilter::default(), &[]).unwrap();
    assert_eq!(all.len(), 3);
    let only = export(
        &conn,
        &CredentialFilter::default(),
        &[r.clone(), p.clone(), r.clone(), "x".to_owned()],
    )
    .unwrap();
    let ids: Vec<_> = only.iter().map(|c| c.entry.id.clone()).collect();
    assert_eq!(ids, vec![p, r]);
    assert_eq!(only[1].hashcat_line.as_deref(), Some("line-r"));

    let mode = CredentialFilter {
        hashcat_mode: Some(5600),
        ..CredentialFilter::default()
    };
    assert_eq!(export(&conn, &mode, &[]).unwrap().len(), 1);
    let row_debug = format!("{:?}", row("p", "ftp", "plaintext", 1, 1));
    assert!(!row_debug.contains("secret-p"), "{row_debug}");
}

#[test]
fn filters_stats_and_paging() {
    let conn = db();
    for i in 0..5u8 {
        row(
            &format!("s{i}"),
            "snmp",
            "plaintext",
            i64::from(i),
            u64::from(i),
        )
        .insert(&conn)
        .unwrap();
    }
    row("f", "ftp", "plaintext", 10, 10).insert(&conn).unwrap();
    row("n", "smb", "recoverable", 11, 11)
        .insert(&conn)
        .unwrap();
    row("m", "smb", "metadata-only", 12, 12)
        .insert(&conn)
        .unwrap();

    let s = stats(&conn).unwrap();
    assert_eq!(
        (s.total, s.plaintext, s.recoverable, s.metadata_only),
        (8, 6, 1, 1)
    );
    assert_eq!(s.hashcat_modes, vec![(5600, 1)]);
    assert_eq!(s.protocols[0], ("snmp".to_owned(), 5));

    let smb = CredentialFilter {
        protocol: Some("smb".to_owned()),
        ..CredentialFilter::default()
    };
    assert_eq!(count(&conn, &smb).unwrap(), 2);
    let plain_smb = CredentialFilter {
        secret_state: Some("plaintext".to_owned()),
        ..smb.clone()
    };
    assert_eq!(count(&conn, &plain_smb).unwrap(), 0);

    // Keyset paging over every entry, in first-seen order.
    let mut seen = Vec::new();
    let mut req = PageRequest::first(3);
    loop {
        let p = page(&conn, &CredentialFilter::default(), &req).unwrap();
        seen.extend(p.items.into_iter().map(|e| fp_of(&conn, &e.id)));
        match p.next_cursor {
            Some(c) => req.cursor = Some(c),
            None => break,
        }
    }
    assert_eq!(seen, vec!["s0", "s1", "s2", "s3", "s4", "f", "n", "m"]);

    let (top, others) = paths(&conn, 2).unwrap();
    assert_eq!(top.len(), 2);
    assert_eq!(top[0].protocol, "snmp");
    assert_eq!((top[0].entries, top[0].seen, top[0].plaintext), (5, 5, 5));
    assert_eq!(others, 1);
}
