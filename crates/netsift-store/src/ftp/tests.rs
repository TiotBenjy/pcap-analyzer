use std::net::{IpAddr, Ipv4Addr};

use rusqlite::Connection;

use super::*;
use crate::migrate::migrate;
use crate::objects::{ObjectFilter, ObjectSort, objects_page};
use crate::schema::SESSION_SCHEMA;

fn db() -> Connection {
    let mut conn = Connection::open_in_memory().unwrap();
    migrate(&mut conn, &SESSION_SCHEMA).unwrap();
    conn
}

fn v4(last: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(192, 168, 1, last))
}

const S: i64 = 1_000_000_000;

fn session_row(
    flow_id: i64,
    first: i64,
    last: i64,
    user: &str,
    login: Option<&str>,
) -> FtpSessionRow {
    FtpSessionRow {
        flow_id,
        client_ip: v4(10),
        client_port: 50_000,
        server_ip: v4(21),
        server_port: 21,
        first_ts: first,
        last_ts: last,
        banner: Some("(vsFTPd 3.0.5)".to_owned()),
        username: Some(user.to_owned()),
        login: login.map(str::to_owned),
        tls: false,
        commands: 5,
        replies: 6,
        files: 1,
        listings: 0,
        bytes: 100,
        lines: 2,
        transcript_truncated: false,
        gaps: 0,
    }
}

fn transfer_row(flow_id: i64, seq: u32, ts: i64, direction: &'static str) -> FtpTransferRow {
    FtpTransferRow {
        flow_id,
        seq,
        ts,
        end_ts: Some(ts + S),
        command: if direction == "upload" {
            "STOR"
        } else {
            "RETR"
        }
        .to_owned(),
        path: Some(format!("dir/file{flow_id}-{seq}.bin")),
        direction,
        mode: Some("passive"),
        mode_command: Some("PASV"),
        data_flow_id: Some(flow_id + 1),
        status: Some(226),
        status_text: Some("Transfer complete.".to_owned()),
        bytes: 100,
        restart_offset: None,
        truncated: false,
        sha256: None,
        mime: None,
        listing: None,
    }
}

fn line_row(flow_id: i64, seq: u32, dir: &'static str, head: &str, text: &str) -> FtpLineRow {
    FtpLineRow {
        flow_id,
        seq,
        ts: i64::from(seq),
        dir,
        head: Some(head.to_owned()),
        text: text.to_owned(),
        secret: head == "PASS",
        truncated: false,
    }
}

/// Three sessions: 10 s - 20 s (alice, accepted), 30 s - 40 s (bob, rejected), 50 s - 60 s
/// (no login); transfers at 12 s (download), 15 s (upload) and 55 s (listing).
fn fill(conn: &Connection) {
    for r in [
        FtpRow::Session(session_row(1, 10 * S, 20 * S, "alice", Some("accepted"))),
        FtpRow::Session(session_row(2, 30 * S, 40 * S, "bob", Some("rejected"))),
        FtpRow::Session(FtpSessionRow {
            server_ip: v4(22),
            username: None,
            ..session_row(3, 50 * S, 60 * S, "-", None)
        }),
        FtpRow::Transfer(transfer_row(1, 0, 12 * S, "download")),
        FtpRow::Transfer(transfer_row(1, 1, 15 * S, "upload")),
        FtpRow::Transfer(FtpTransferRow {
            status: Some(426),
            listing: Some("a\nb\n".to_owned()),
            ..transfer_row(3, 0, 55 * S, "listing")
        }),
        FtpRow::Line(line_row(1, 1, "c", "PASS", "s3cret")),
        FtpRow::Line(line_row(1, 0, "c", "USER", "alice")),
    ] {
        r.insert(conn).unwrap();
    }
}

#[test]
fn rows_are_written_once() {
    let conn = db();
    fill(&conn);
    fill(&conn);
    let n: i64 = conn
        .query_row(
            "SELECT (SELECT count(*) FROM ftp_sessions) * 100 \
                  + (SELECT count(*) FROM ftp_transfers) * 10 + (SELECT count(*) FROM ftp_lines)",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(n, 332);
}

#[test]
fn line_rows_never_show_the_secret() {
    let row = line_row(1, 1, "c", "PASS", "s3cret");
    assert!(!format!("{row:?}").contains("s3cret"));
    let conn = db();
    fill(&conn);
    let got = lines(&conn, 1, 100).unwrap();
    assert_eq!(got.len(), 2);
    assert_eq!(got[0].head.as_deref(), Some("USER"));
    assert!(got[1].secret);
    assert_eq!(got[1].text, "s3cret");
    assert!(!format!("{got:?}").contains("s3cret"));
}

#[test]
fn sessions_filter_page_and_overlap() {
    let conn = db();
    fill(&conn);
    let all = FtpSessionFilter::default();
    let page = sessions_page(&conn, &all, &PageRequest::first(2)).unwrap();
    assert_eq!(
        page.items.iter().map(|e| e.row.flow_id).collect::<Vec<_>>(),
        vec![1, 2]
    );
    let next = sessions_page(
        &conn,
        &all,
        &PageRequest {
            limit: 2,
            cursor: page.next_cursor,
        },
    )
    .unwrap();
    assert_eq!(next.items.len(), 1);
    assert_eq!(next.next_cursor, None);
    let count = |f: FtpSessionFilter| count_sessions(&conn, &f).unwrap();
    assert_eq!(count(all.clone()), 3);
    for (login, n) in [
        (LoginFilter::Accepted, 1),
        (LoginFilter::Rejected, 1),
        (LoginFilter::None, 1),
    ] {
        assert_eq!(
            count(FtpSessionFilter {
                login: Some(login),
                ..FtpSessionFilter::default()
            }),
            n
        );
    }
    assert_eq!(
        count(FtpSessionFilter {
            q: Some("ali".to_owned()),
            ..FtpSessionFilter::default()
        }),
        1
    );
    assert_eq!(
        count(FtpSessionFilter {
            q: Some("192.168.1.22".to_owned()),
            ..FtpSessionFilter::default()
        }),
        1
    );
    // 19 s - 31 s overlaps the first two sessions.
    let range = TimeRange::new(19 * S, 31 * S);
    assert_eq!(
        count(FtpSessionFilter {
            range,
            ..FtpSessionFilter::default()
        }),
        2
    );
    assert_eq!(
        session(&conn, 2).unwrap().unwrap().row.username.as_deref(),
        Some("bob")
    );
    assert!(session(&conn, 9).unwrap().is_none());
}

#[test]
fn transfers_filter_and_point_range() {
    let conn = db();
    fill(&conn);
    let count = |f: FtpTransferFilter| count_transfers(&conn, &f).unwrap();
    assert_eq!(count(FtpTransferFilter::default()), 3);
    assert_eq!(
        count(FtpTransferFilter {
            direction: Some("upload"),
            ..FtpTransferFilter::default()
        }),
        1
    );
    assert_eq!(
        count(FtpTransferFilter {
            session: Some(1),
            ..FtpTransferFilter::default()
        }),
        2
    );
    assert_eq!(
        count(FtpTransferFilter {
            q: Some("file3".to_owned()),
            ..FtpTransferFilter::default()
        }),
        1
    );
    let range = TimeRange::new(12 * S, 15 * S);
    let f = FtpTransferFilter {
        range,
        ..FtpTransferFilter::default()
    };
    let page = transfers_page(&conn, &f, &PageRequest::first(10)).unwrap();
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].username.as_deref(), Some("alice"));
    assert_eq!(page.items[0].server_ip, v4(21));
    let mine = session_transfers(&conn, 1, 100).unwrap();
    assert_eq!(mine.iter().map(|t| t.seq).collect::<Vec<_>>(), vec![0, 1]);
}

#[test]
fn stats_follow_the_range() {
    let conn = db();
    fill(&conn);
    let s = stats(&conn, None).unwrap();
    assert_eq!((s.sessions, s.servers, s.clients, s.users), (3, 2, 1, 2));
    assert_eq!(
        (s.logins_accepted, s.logins_rejected, s.tls_sessions),
        (1, 1, 0)
    );
    assert_eq!(
        (
            s.transfers,
            s.downloads,
            s.uploads,
            s.listings,
            s.failed,
            s.bytes
        ),
        (3, 1, 1, 1, 1, 300)
    );
    let s = stats(&conn, TimeRange::new(11 * S, 13 * S)).unwrap();
    assert_eq!(
        (s.sessions, s.transfers, s.downloads, s.bytes),
        (1, 1, 1, 100)
    );
    let s = stats(&conn, TimeRange::new(100 * S, 200 * S)).unwrap();
    assert_eq!(s, FtpStatsRows::default());
}

#[test]
fn stored_files_become_objects() {
    let conn = db();
    fill(&conn);
    let sha = "ab".repeat(32);
    FtpRow::Transfer(FtpTransferRow {
        sha256: Some(sha.clone()),
        mime: Some("image/png".to_owned()),
        bytes: 1234,
        path: Some("photos/a.png".to_owned()),
        ..transfer_row(2, 0, 35 * S, "download")
    })
    .insert(&conn)
    .unwrap();
    // The same content uploaded later in another session: one object, two occurrences.
    FtpRow::Transfer(FtpTransferRow {
        sha256: Some(sha.clone()),
        mime: Some("image/png".to_owned()),
        bytes: 1234,
        ..transfer_row(3, 1, 58 * S, "upload")
    })
    .insert(&conn)
    .unwrap();
    crate::objects::finalize(&conn).unwrap();
    let page = objects_page(
        &conn,
        &ObjectFilter {
            images_only: true,
            ..ObjectFilter::default()
        },
        ObjectSort::Time,
        false,
        &PageRequest::first(10),
    )
    .unwrap();
    assert_eq!(page.items.len(), 1);
    let o = &page.items[0];
    assert_eq!(o.source, "ftp");
    assert_eq!(o.uri.as_deref(), Some("photos/a.png"));
    assert_eq!((o.flow_id, o.seq, o.occurrences), (2, 0, 2));
    assert_eq!((o.first_ts, o.last_ts), (35 * S, 58 * S));
    assert_eq!(o.server_port, 21);
    assert_eq!(o.host, None);
    // Under a range: the transfers of the range only.
    let ranged = ObjectFilter {
        images_only: true,
        range: TimeRange::new(50 * S, 60 * S),
        ..ObjectFilter::default()
    };
    let page = objects_page(
        &conn,
        &ranged,
        ObjectSort::Time,
        false,
        &PageRequest::first(10),
    )
    .unwrap();
    assert_eq!(page.items[0].occurrences, 1);
    assert_eq!(page.items[0].first_ts, 58 * S);
    assert_eq!(crate::objects::count_objects(&conn, &ranged).unwrap(), 1);
    let s = crate::objects::stats(&conn, true, 10, TimeRange::new(50 * S, 60 * S)).unwrap();
    assert_eq!((s.count, s.occurrences), (1, 1));
    let none = ObjectFilter {
        range: TimeRange::new(0, S),
        ..ranged
    };
    assert_eq!(crate::objects::count_objects(&conn, &none).unwrap(), 0);
    assert_eq!(
        crate::range::ModuleRows::Pictures
            .count(&conn, TimeRange::new(50 * S, 60 * S).unwrap())
            .unwrap(),
        1
    );
    assert_eq!(
        crate::range::ModuleRows::FtpSessions
            .count(&conn, TimeRange::new(19 * S, 31 * S).unwrap())
            .unwrap(),
        2
    );
}

#[test]
fn stats_read_a_covering_index() {
    let conn = db();
    fill(&conn);
    let sql = "SELECT count(*), coalesce(sum(direction = 'download'), 0), \
               coalesce(sum(status IS NULL OR status < 200 OR status >= 300), 0), \
               coalesce(sum(bytes), 0), coalesce(sum(sha256 IS NOT NULL), 0) \
               FROM ftp_transfers WHERE +ts >= 1 AND +ts < 2";
    let mut stmt = conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap();
    let plan: Vec<String> = stmt
        .query_map([], |r| r.get(3))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert!(
        plan.iter().any(|l| l.contains("COVERING INDEX")),
        "{plan:?}"
    );
}

/// Order of magnitude on 100 000 sessions and 400 000 transfers. Run on demand in release mode:
/// `./x.sh cargo test --release -p netsift-store ftp::tests::timings -- --ignored --nocapture`.
#[test]
#[ignore = "measurement, run on demand in release mode"]
fn timings() {
    let conn = db();
    conn.execute_batch("BEGIN").unwrap();
    for i in 0..100_000_i64 {
        let first = i * 10 * S;
        let login = ["accepted", "rejected"][usize::try_from(i % 2).unwrap()];
        FtpRow::Session(FtpSessionRow {
            client_ip: v4(u8::try_from(i % 200).unwrap()),
            ..session_row(
                i * 100,
                first,
                first + 8 * S,
                &format!("user{}", i % 500),
                Some(login),
            )
        })
        .insert(&conn)
        .unwrap();
        for seq in 0..4_u32 {
            let direction = ["download", "upload", "listing", "download"][seq as usize];
            FtpRow::Transfer(FtpTransferRow {
                sha256: (seq == 0).then(|| format!("{i:064x}")),
                ..transfer_row(i * 100, seq, first + i64::from(seq) * S, direction)
            })
            .insert(&conn)
            .unwrap();
        }
        for seq in 0..20_u32 {
            FtpRow::Line(line_row(i * 100, seq, "s", "200", "Command okay."))
                .insert(&conn)
                .unwrap();
        }
    }
    conn.execute_batch("COMMIT; ANALYZE").unwrap();
    let total = 100_000 * 10 * S;
    for (name, range) in [
        ("whole", None),
        ("1 h", TimeRange::new(total / 2, total / 2 + 3_600 * S)),
        ("half", TimeRange::new(total / 4, total * 3 / 4)),
    ] {
        let t = std::time::Instant::now();
        stats(&conn, range).unwrap();
        let stats_time = t.elapsed();
        let t = std::time::Instant::now();
        let f = FtpSessionFilter {
            range,
            ..FtpSessionFilter::default()
        };
        sessions_page(&conn, &f, &PageRequest::first(100)).unwrap();
        count_sessions(&conn, &f).unwrap();
        let sessions_time = t.elapsed();
        let t = std::time::Instant::now();
        let f = FtpSessionFilter {
            q: Some("user42".to_owned()),
            login: Some(LoginFilter::Accepted),
            range,
        };
        sessions_page(&conn, &f, &PageRequest::first(100)).unwrap();
        count_sessions(&conn, &f).unwrap();
        let search_time = t.elapsed();
        let t = std::time::Instant::now();
        let f = FtpTransferFilter {
            direction: Some("upload"),
            range,
            ..FtpTransferFilter::default()
        };
        transfers_page(&conn, &f, &PageRequest::first(100)).unwrap();
        count_transfers(&conn, &f).unwrap();
        let transfers_time = t.elapsed();
        let t = std::time::Instant::now();
        let id = 50_000 * 100;
        session(&conn, id).unwrap();
        lines(&conn, id, 2000).unwrap();
        session_transfers(&conn, id, 1000).unwrap();
        let detail_time = t.elapsed();
        println!(
            "{name}: stats {stats_time:?}, sessions {sessions_time:?}, search {search_time:?}, \
             transfers {transfers_time:?}, detail {detail_time:?}"
        );
    }
}

/// Cost of the second `EXISTS` (FTP transfers) of the objects filtered by a time range, on
/// 200 000 HTTP images and 50 000 FTP files. Run on demand in release mode:
/// `./x.sh cargo test --release -p netsift-store --lib ftp::tests::objects_timings -- --ignored --nocapture`.
#[test]
#[ignore = "measurement, run on demand in release mode"]
fn objects_timings() {
    let conn = db();
    conn.execute_batch("BEGIN").unwrap();
    for i in 0..200_000_i64 {
        conn.execute(
            "INSERT INTO http_transactions (flow_id, seq, client_ip, client_port, server_ip, \
             server_port, ts, end_ts, method, method_group, uri, host, status, status_key, \
             status_class, content_type, resp_ts, resp_body_len, resp_body_state, \
             resp_mime_magic, resp_sha256) \
             VALUES (?1, 0, '10.0.0.1', 40000, '10.0.0.2', 80, ?2, ?2, 'GET', 'GET', ?3, \
             'cdn.test', 200, 200, '2xx', 'image/png', ?2, 1000, 'complete', 'image/png', ?4)",
            rusqlite::params![i, i * S, format!("/img/{i}.png"), format!("h{i:063x}")],
        )
        .unwrap();
    }
    for i in 0..50_000_i64 {
        FtpRow::Session(session_row(
            1_000_000 + i,
            i * S,
            i * S + S,
            "u",
            Some("accepted"),
        ))
        .insert(&conn)
        .unwrap();
        FtpRow::Transfer(FtpTransferRow {
            sha256: Some(format!("f{i:063x}")),
            mime: Some("image/png".to_owned()),
            ..transfer_row(1_000_000 + i, 0, i * S, "download")
        })
        .insert(&conn)
        .unwrap();
    }
    crate::objects::finalize(&conn).unwrap();
    conn.execute_batch("COMMIT; ANALYZE").unwrap();
    let total = 200_000 * S;
    for (name, range) in [
        ("whole", None),
        ("1 h", TimeRange::new(total / 2, total / 2 + 3_600 * S)),
        ("half", TimeRange::new(total / 4, total * 3 / 4)),
    ] {
        let filter = ObjectFilter {
            images_only: true,
            range,
            ..ObjectFilter::default()
        };
        let t = std::time::Instant::now();
        objects_page(
            &conn,
            &filter,
            ObjectSort::Time,
            true,
            &PageRequest::first(100),
        )
        .unwrap();
        crate::objects::count_objects(&conn, &filter).unwrap();
        let page = t.elapsed();
        let t = std::time::Instant::now();
        crate::objects::stats(&conn, true, 50, range).unwrap();
        let stats_time = t.elapsed();
        println!("{name}: objects page + count {page:?}, stats {stats_time:?}");
    }
}
