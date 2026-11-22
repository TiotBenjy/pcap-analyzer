use std::net::{IpAddr, Ipv4Addr};

use rusqlite::Connection;

use super::*;
use crate::migrate::migrate;
use crate::range::ModuleRows;
use crate::schema::SESSION_SCHEMA;

fn db() -> Connection {
    let mut conn = Connection::open_in_memory().unwrap();
    migrate(&mut conn, &SESSION_SCHEMA).unwrap();
    conn
}

fn v4(last: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(192, 168, 1, last))
}

fn run(speaker: Speaker, text: &str) -> TelnetRun {
    TelnetRun {
        speaker,
        text: text.to_owned(),
    }
}

/// A session of `flow_id` between `first` and `last` (seconds).
fn row(flow_id: i64, first: i64, last: i64, login: Option<&str>, attempts: u32) -> TelnetRow {
    TelnetRow {
        flow_id,
        first_ts: first * 1_000_000_000,
        last_ts: last * 1_000_000_000,
        client_ip: v4(10),
        client_port: 49_152,
        server_ip: v4(u8::try_from(20 + flow_id % 3).unwrap()),
        server_port: 23,
        client_bytes: 100,
        server_bytes: 2000,
        username: Some(format!("user{flow_id}")),
        env_user: None,
        login: login.map(str::to_owned),
        login_attempts: attempts,
        terminal: Some("XTERM".to_owned()),
        window: Some((80, 24)),
        options: vec!["ECHO".to_owned(), "NAWS".to_owned()],
        transcript: vec![
            run(Speaker::Server, "login: "),
            run(Speaker::Client, "jdoe\n"),
            run(Speaker::Server, "Password:"),
            run(Speaker::Secret, "hunter2-fixture"),
            run(Speaker::Client, "\n"),
            run(Speaker::Server, "$ "),
            run(Speaker::Client, "uname -a\n"),
        ],
        transcript_bytes: 50,
        transcript_lines: 4,
        truncated: false,
    }
}

#[test]
fn secrets_are_stored_apart_and_joined_by_the_detail_only() {
    let conn = db();
    row(7, 10, 20, Some("accepted"), 1).insert(&conn).unwrap();
    // A flow is inserted once.
    row(7, 10, 99, None, 0).insert(&conn).unwrap();
    let (transcript, secrets): (String, String) = conn
        .query_row(
            "SELECT transcript, secrets FROM telnet_sessions WHERE flow_id = 7",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert!(!transcript.contains("hunter2"), "{transcript}");
    assert!(transcript.contains(r#"["p",""]"#), "{transcript}");
    assert_eq!(secrets, r#"["hunter2-fixture"]"#);

    let detail = session_detail(&conn, 7).unwrap().unwrap();
    assert_eq!(detail.transcript, row(7, 0, 0, None, 0).transcript);
    assert_eq!(detail.entry.last_ts, 20_000_000_000);
    assert_eq!(detail.entry.window, Some((80, 24)));
    assert_eq!(detail.entry.options, vec!["ECHO", "NAWS"]);
    assert_eq!(detail.entry.login.as_deref(), Some("accepted"));
    assert!(session_detail(&conn, 8).unwrap().is_none());
    // Debug never shows the secret.
    assert!(!format!("{detail:?} {:?}", row(7, 0, 0, None, 0)).contains("hunter2"));
}

#[test]
fn search_never_matches_a_secret() {
    let conn = db();
    row(1, 10, 20, Some("accepted"), 1).insert(&conn).unwrap();
    let count = |q: &str| {
        count_sessions(
            &conn,
            &TelnetFilter {
                q: Some(q.to_owned()),
                ..TelnetFilter::default()
            },
        )
        .unwrap()
    };
    assert_eq!(count("uname"), 1);
    assert_eq!(count("XTERM"), 1);
    assert_eq!(count("192.168.1.21"), 1);
    assert_eq!(count("hunter2"), 0);
    assert_eq!(count("100%"), 0);
}

#[test]
fn filters_pages_range_and_stats() {
    let conn = db();
    let rows = [
        row(1, 10, 20, Some("accepted"), 1),
        row(2, 30, 40, Some("rejected"), 3),
        row(3, 50, 60, None, 1),
        row(4, 70, 80, None, 0),
        TelnetRow {
            truncated: true,
            ..row(5, 90, 300, Some("accepted"), 2)
        },
    ];
    for r in &rows {
        r.insert(&conn).unwrap();
    }
    let ids = |filter: &TelnetFilter| -> Vec<i64> {
        let mut out = Vec::new();
        let mut request = PageRequest::first(2);
        loop {
            let page = sessions_page(&conn, filter, &request).unwrap();
            out.extend(page.items.iter().map(|e| e.flow_id));
            match page.next_cursor {
                Some(c) => request.cursor = Some(c),
                None => break,
            }
        }
        assert_eq!(count_sessions(&conn, filter).unwrap(), out.len() as u64);
        out
    };
    assert_eq!(ids(&TelnetFilter::default()), vec![1, 2, 3, 4, 5]);
    let login = |l| TelnetFilter {
        login: Some(l),
        ..TelnetFilter::default()
    };
    assert_eq!(ids(&login(LoginFilter::Accepted)), vec![1, 5]);
    assert_eq!(ids(&login(LoginFilter::Rejected)), vec![2]);
    assert_eq!(ids(&login(LoginFilter::Unknown)), vec![3]);
    assert_eq!(ids(&login(LoginFilter::None)), vec![4]);

    // Overlap: [35 s, 95 s) keeps 2 (ends at 40), 3, 4 and 5 (starts at 90).
    let range = TimeRange::new(35_000_000_000, 95_000_000_000).unwrap();
    let ranged = TelnetFilter {
        range: Some(range),
        ..TelnetFilter::default()
    };
    assert_eq!(ids(&ranged), vec![2, 3, 4, 5]);
    assert_eq!(ModuleRows::Telnet.count(&conn, range).unwrap(), 4);

    let all = stats(&conn, None).unwrap();
    assert_eq!(
        all,
        TelnetStatsRow {
            sessions: 5,
            clients: 1,
            servers: 3,
            logins: 4,
            accepted: 2,
            rejected: 1,
            truncated: 1,
        }
    );
    let some = stats(&conn, Some(range)).unwrap();
    assert_eq!((some.sessions, some.accepted, some.logins), (4, 1, 3));
    let none = stats(&conn, TimeRange::new(1_000_000_000_000, 2_000_000_000_000)).unwrap();
    assert_eq!(none, TelnetStatsRow::default());
}
