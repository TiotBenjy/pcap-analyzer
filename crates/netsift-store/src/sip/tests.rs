use std::net::{IpAddr, Ipv4Addr};

use rusqlite::Connection;

use super::*;
use crate::migrate::migrate;
use crate::schema::SESSION_SCHEMA;

const S: i64 = 1_000_000_000;

fn db() -> Connection {
    let mut conn = Connection::open_in_memory().unwrap();
    migrate(&mut conn, &SESSION_SCHEMA).unwrap();
    conn
}

fn v4(last: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 20, 0, last))
}

fn request(ts: i64, src: u8, dst: u8, method: &str, call_id: &str) -> SipRow {
    SipRow {
        ts,
        src_ip: v4(src),
        src_port: 5060,
        dst_ip: v4(dst),
        dst_port: 5060,
        transport: "udp".to_owned(),
        flow_id: Some(1),
        kind: "request".to_owned(),
        method: Some(method.to_owned()),
        status: None,
        reason: None,
        request_uri: Some(format!("sip:{dst}@10.20.0.{dst}")),
        call_id: Some(call_id.to_owned()),
        from_name: Some(format!("User {src}")),
        from_uri: Some(format!("sip:{src}@10.20.0.{src}")),
        from_tag: Some("f".to_owned()),
        to_name: None,
        to_uri: Some(format!("sip:{dst}@10.20.0.{dst}")),
        to_tag: None,
        cseq: Some(1),
        user_agent: Some(format!("Phone {src}")),
        server: None,
        scanner: None,
        contact: None,
        via: None,
        expires: None,
        content_type: None,
        auth_user: None,
        auth_realm: None,
        challenge_realm: None,
        media: Vec::new(),
        size: 300,
        raw: format!("{method} sip:x SIP/2.0\n"),
        raw_truncated: false,
    }
}

fn response(ts: i64, src: u8, dst: u8, status: u16, method: &str, call_id: &str) -> SipRow {
    SipRow {
        kind: "response".to_owned(),
        status: Some(status),
        reason: Some(format!("Reason {status}")),
        request_uri: None,
        user_agent: None,
        server: Some(format!("Server {src}")),
        raw: format!("SIP/2.0 {status} R\n"),
        ..request(ts, src, dst, method, call_id)
    }
}

fn audio(last: u8, port: u16) -> Vec<SipMediaDesc> {
    vec![SipMediaDesc {
        media: "audio".to_owned(),
        ip: Some(v4(last)),
        port,
        proto: "RTP/AVP".to_owned(),
        codecs: vec!["PCMU".to_owned(), "PCMA".to_owned()],
        direction: Some("sendrecv".to_owned()),
    }]
}

/// Every case of the view, by Call-ID: a completed call with RTP, a rejected call, a cancelled
/// call, an authenticated registration, an unanswered scanner OPTIONS.
fn rows() -> Vec<SipRow> {
    let mut v = vec![
        // Completed: 21 calls 22, answered at 13 s, BYE at 20 s.
        SipRow {
            media: audio(21, 40_000),
            ..request(10 * S, 21, 22, "INVITE", "call-a")
        },
        response(10 * S + 1, 22, 21, 100, "INVITE", "call-a"),
        response(11 * S, 22, 21, 180, "INVITE", "call-a"),
        SipRow {
            media: audio(22, 42_000),
            ..response(13 * S, 22, 21, 200, "INVITE", "call-a")
        },
        request(13 * S + 1, 21, 22, "ACK", "call-a"),
        request(20 * S, 22, 21, "BYE", "call-a"),
        response(20 * S + 1, 21, 22, 200, "BYE", "call-a"),
        // Rejected.
        request(30 * S, 21, 2, "INVITE", "call-b"),
        response(30 * S + 5, 2, 21, 486, "INVITE", "call-b"),
        request(30 * S + 6, 21, 2, "ACK", "call-b"),
        // Cancelled.
        request(40 * S, 22, 21, "INVITE", "call-c"),
        response(40 * S + 1, 21, 22, 180, "INVITE", "call-c"),
        request(44 * S, 22, 21, "CANCEL", "call-c"),
        response(44 * S + 1, 21, 22, 200, "CANCEL", "call-c"),
        response(44 * S + 2, 21, 22, 487, "INVITE", "call-c"),
        // Registration: challenged, then accepted.
        request(5 * S, 21, 2, "REGISTER", "reg-a"),
        SipRow {
            challenge_realm: Some("pbx".to_owned()),
            ..response(5 * S + 1, 2, 21, 401, "REGISTER", "reg-a")
        },
        SipRow {
            auth_user: Some("201".to_owned()),
            auth_realm: Some("pbx".to_owned()),
            cseq: Some(2),
            ..request(5 * S + 2, 21, 2, "REGISTER", "reg-a")
        },
        response(5 * S + 3, 2, 21, 200, "REGISTER", "reg-a"),
        // Scanner, never answered.
        SipRow {
            src_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 66)),
            src_port: 5070,
            user_agent: Some("friendly-scanner".to_owned()),
            scanner: Some("SIPVicious".to_owned()),
            ..request(50 * S, 66, 2, "OPTIONS", "scan-1")
        },
    ];
    // A response seen without its request (picked up mid-dialog) still makes a dialog.
    v.push(response(60 * S, 2, 22, 200, "OPTIONS", "orphan"));
    v
}

/// UDP flows: the two RTP directions of the completed call, and an unrelated one on the same
/// port much later (not joined).
fn flows(conn: &Connection) {
    conn.execute_batch(
        "INSERT INTO flows (id, transport, src_ip, src_port, dst_ip, dst_port, first_ts, last_ts, \
                            bytes_fwd, bytes_rev, packets_fwd, packets_rev) VALUES \
         (100, 17, '10.20.0.21', 40000, '10.20.0.22', 42000, 13500000000, 19900000000, 17200, 17200, 100, 100), \
         (101, 17, '10.20.0.9', 5000, '10.20.0.22', 42000, 900000000000, 900000000001, 10, 0, 1, 0), \
         (102, 6, '10.20.0.21', 40000, '10.20.0.22', 42000, 13500000000, 19900000000, 1, 1, 1, 1);",
    )
    .unwrap();
}

fn build(rows: &[SipRow]) -> Connection {
    let conn = db();
    for r in rows {
        r.insert(&conn).unwrap();
    }
    flows(&conn);
    finalize(&conn).unwrap();
    conn
}

fn dump(conn: &Connection) -> String {
    let mut out = String::new();
    let mut stmt = conn
        .prepare(
            "SELECT id || ' ' || call_id || ' ' || method || ' ' || state || ' ' || \
             coalesce(final_status, '-') || ' ' || coalesce(duration_ns, '-') || ' ' || \
             client_ip || '>' || server_ip || ' r=' || requests || '/' || responses || ' ua=' || \
             coalesce(user_agent, '-') || ' sa=' || coalesce(server_agent, '-') || ' auth=' || \
             coalesce(auth_user, '-') || ' ch=' || challenged || ' sc=' || coalesce(scanner, '-') \
             || ' m=' || media_count FROM sip_dialogs ORDER BY id",
        )
        .unwrap();
    for r in stmt.query_map([], |r| r.get::<_, String>(0)).unwrap() {
        out.push_str(&r.unwrap());
        out.push('\n');
    }
    let mut stmt = conn
        .prepare(
            "SELECT dialog_id || ' ' || media || ' ' || ip || ':' || port || ' ' || codecs || \
             ' by=' || offered_by || ' flows=' || flow_count || ' p=' || packets || ' b=' || \
             bytes || ' first=' || coalesce(first_flow_id, '-') FROM sip_media ORDER BY id",
        )
        .unwrap();
    for r in stmt.query_map([], |r| r.get::<_, String>(0)).unwrap() {
        out.push_str(&r.unwrap());
        out.push('\n');
    }
    out
}

#[test]
fn dialogs_get_their_state_duration_and_media() {
    let conn = build(&rows());
    let d = dialogs_page(&conn, &SipDialogFilter::default(), &PageRequest::first(50)).unwrap();
    let by = |call: &str| d.items.iter().find(|x| x.call_id == call).unwrap();
    let a = by("call-a");
    assert_eq!(
        (a.method.as_str(), a.state.as_str()),
        ("INVITE", "completed")
    );
    assert_eq!(a.final_status, Some(200));
    assert_eq!(a.duration_ns, Some(7 * S));
    assert_eq!(a.ringing_ts, Some(11 * S));
    assert_eq!((a.requests, a.responses), (3, 4));
    assert_eq!(a.user_agent.as_deref(), Some("Phone 21"));
    assert_eq!(a.server_agent.as_deref(), Some("Server 22"));
    assert_eq!(a.media.len(), 2);
    let callee = a.media.iter().find(|m| m.port == 42_000).unwrap();
    // Joined to the UDP RTP flow only (not the late one, not the TCP one).
    assert_eq!((callee.flow_count, callee.packets), (1, 200));
    assert_eq!(callee.first_flow_id, Some(100));
    assert_eq!(callee.offered_by, v4(22));
    assert_eq!(by("call-b").state, "rejected");
    assert_eq!(by("call-b").final_status, Some(486));
    assert_eq!(by("call-c").state, "cancelled");
    assert_eq!(by("call-c").final_status, Some(487));
    let reg = by("reg-a");
    assert_eq!(
        (reg.method.as_str(), reg.state.as_str()),
        ("REGISTER", "ok")
    );
    assert!(reg.challenged);
    assert_eq!(reg.auth_user.as_deref(), Some("201"));
    let scan = by("scan-1");
    assert_eq!(
        (scan.state.as_str(), scan.scanner.as_deref()),
        ("no-answer", Some("SIPVicious"))
    );
    let orphan = by("orphan");
    assert_eq!(
        (orphan.method.as_str(), orphan.state.as_str()),
        ("UNKNOWN", "ok")
    );
    assert_eq!(orphan.client_ip, v4(2));
    insta::assert_snapshot!(dump(&conn));
}

#[test]
fn dialogs_do_not_depend_on_arrival_order_and_replay() {
    let mut forward = rows();
    let reference = dump(&build(&forward));
    forward.reverse();
    let conn = build(&forward);
    assert_eq!(dump(&conn), reference);
    // Running the step again gives the same tables.
    finalize(&conn).unwrap();
    assert_eq!(dump(&conn), reference);
}

#[test]
fn stats_and_filters() {
    let conn = build(&rows());
    let s = stats(&conn, 10, None).unwrap();
    assert_eq!(s.messages, 21);
    assert_eq!((s.requests, s.responses), (10, 11));
    assert_eq!(s.dialogs, 6);
    assert_eq!((s.calls, s.registrations), (3, 1));
    assert_eq!(s.call_duration_ns, 7 * S);
    assert_eq!(s.scanner_messages, 1);
    assert_eq!(s.methods[0], ("INVITE".to_owned(), 3));
    assert_eq!(
        s.call_states,
        [
            ("cancelled".to_owned(), 1),
            ("completed".to_owned(), 1),
            ("rejected".to_owned(), 1)
        ]
    );
    assert_eq!(s.statuses[0].0, 200);
    assert!(
        s.top_agents
            .iter()
            .any(|(a, t, _)| a == "friendly-scanner" && t.as_deref() == Some("SIPVicious"))
    );

    let calls = SipDialogFilter {
        kind: Some(DialogType::Call),
        ..SipDialogFilter::default()
    };
    assert_eq!(count_dialogs(&conn, &calls).unwrap(), 3);
    let other = SipDialogFilter {
        kind: Some(DialogType::Other),
        ..SipDialogFilter::default()
    };
    assert_eq!(count_dialogs(&conn, &other).unwrap(), 2);
    let q = SipDialogFilter {
        q: Some("call-%".to_owned()),
        ..SipDialogFilter::default()
    };
    assert_eq!(
        count_dialogs(&conn, &q).unwrap(),
        0,
        "wildcards are escaped"
    );

    let by_call = SipMessageFilter {
        call_id: Some("call-a".to_owned()),
        ..SipMessageFilter::default()
    };
    assert_eq!(count_messages(&conn, &by_call).unwrap(), 7);
    let scan = SipMessageFilter {
        scanner: true,
        ..SipMessageFilter::default()
    };
    let page = messages_page(&conn, &scan, &PageRequest::first(10)).unwrap();
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].software.as_deref(), Some("friendly-scanner"));
    let found = scanners(&conn, 50, None).unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!((found[0].messages, found[0].targets), (1, 1));
    assert_eq!(found[0].methods, ["OPTIONS"]);
}

#[test]
fn ranges_are_points_for_messages_and_overlaps_for_dialogs() {
    let conn = build(&rows());
    // 15 s to 35 s: the end of call-a and all of call-b.
    let range = TimeRange::new(15 * S, 35 * S);
    let s = stats(&conn, 10, range).unwrap();
    assert_eq!(s.messages, 2 + 3);
    assert_eq!(s.calls, 2);
    let d = dialogs_page(
        &conn,
        &SipDialogFilter {
            range,
            ..SipDialogFilter::default()
        },
        &PageRequest::first(50),
    )
    .unwrap();
    let ids: Vec<&str> = d.items.iter().map(|x| x.call_id.as_str()).collect();
    assert_eq!(ids, ["call-a", "call-b"]);
    // Folded counters stay those of the session.
    assert_eq!(d.items[0].requests, 3);
    assert_eq!(scanners(&conn, 50, range).unwrap().len(), 0);
}

#[test]
fn pages_of_dialogs_and_messages_have_no_gap() {
    let conn = build(&rows());
    let mut seen = Vec::new();
    let mut request = PageRequest::first(2);
    loop {
        let page = dialogs_page(&conn, &SipDialogFilter::default(), &request).unwrap();
        seen.extend(page.items.iter().map(|d| (d.first_ts, d.id, d.media.len())));
        match page.next_cursor {
            Some(c) => request.cursor = Some(c),
            None => break,
        }
    }
    assert_eq!(seen.len(), 6);
    assert!(seen.windows(2).all(|w| w[0].0 <= w[1].0));
    // Media are attached across pages too.
    assert_eq!(seen.iter().map(|s| s.2).sum::<usize>(), 2);
}

/// A session of `calls` calls of 8 messages (1 M messages for 125 000 calls), one in 250 through
/// a media gateway, with their RTP flows and 200 000 flows of that gateway (measurement only).
fn volume(calls: i64) -> Connection {
    let conn = db();
    conn.execute_batch("BEGIN").unwrap();
    // 1 M messages: 125 000 calls of 8 messages, one call every 4 s, 500 phones.
    for c in 0..calls {
        let base = c * 4 * S;
        let a = u8::try_from(c % 250).unwrap();
        let b = u8::try_from((c + 7) % 250).unwrap();
        let id = format!("call-{c}");
        // One call in 250 goes through the media gateway (.2, a port per call).
        let offer = if c % 250 == 0 {
            audio(2, 10_000 + u16::try_from(c / 250 % 5_000).unwrap())
        } else {
            audio(a, 40_000)
        };
        let mut v = vec![
            SipRow {
                media: offer,
                ..request(base, a, b, "INVITE", &id)
            },
            response(base + 1, b, a, 100, "INVITE", &id),
            response(base + 2, b, a, 180, "INVITE", &id),
            SipRow {
                media: audio(b, 42_000),
                ..response(base + S, b, a, 200, "INVITE", &id)
            },
            request(base + S + 1, a, b, "ACK", &id),
            request(base + 3 * S, a, b, "BYE", &id),
            response(base + 3 * S + 1, b, a, 200, "BYE", &id),
        ];
        if c % 50 == 0 {
            v.push(SipRow {
                scanner: Some("SIPVicious".to_owned()),
                user_agent: Some("friendly-scanner".to_owned()),
                ..request(base + 2 * S, 66, b, "OPTIONS", &format!("scan-{c}"))
            });
        } else {
            v.push(request(
                base + 2 * S,
                a,
                2,
                "REGISTER",
                &format!("reg-{}", c % 500),
            ));
        }
        for r in v {
            r.insert(&conn).unwrap();
        }
    }
    // UDP flows: the RTP of every call, and 200 000 flows sent by the media gateway from its
    // ports (the case of a loaded SBC: one address in every media join).
    {
        let mut insert = conn
            .prepare(
                "INSERT INTO flows (id, transport, src_ip, src_port, dst_ip, dst_port, first_ts, \
                 last_ts, bytes_fwd, bytes_rev, packets_fwd, packets_rev) \
                 VALUES (?1, 17, ?2, ?3, ?4, ?5, ?6, ?7, 17200, 17200, 100, 100)",
            )
            .unwrap();
        for c in 0..calls {
            let base = c * 4 * S;
            let a = u8::try_from(c % 250).unwrap();
            let b = u8::try_from((c + 7) % 250).unwrap();
            insert
                .execute(rusqlite::params![
                    c,
                    v4(a).to_string(),
                    40_000,
                    v4(b).to_string(),
                    42_000,
                    base + S,
                    base + 3 * S
                ])
                .unwrap();
        }
        for i in 0..200_000_i64 {
            let ts = i * calls * 4 * S / 200_000;
            insert
                .execute(rusqlite::params![
                    calls + i,
                    v4(2).to_string(),
                    10_000 + i % 50_000,
                    format!("10.30.{}.{}", i % 250, i / 250 % 250),
                    20_000 + i % 1_000,
                    ts,
                    ts + 2 * S
                ])
                .unwrap();
        }
    }
    conn.execute_batch("COMMIT; ANALYZE").unwrap();
    conn
}

/// Time and query plan of each aggregate of `/sip/stats` without range (measurement only).
#[allow(clippy::print_stdout)]
fn print_plans(conn: &Connection) {
    for sql in [
        "SELECT kind, method, count(*) FROM sip_messages GROUP BY kind, method",
        "SELECT status, reason, count(*) FROM sip_messages WHERE status IS NOT NULL \
         GROUP BY status, reason",
        "SELECT status, min(reason), count(*) AS n FROM sip_messages WHERE status IS NOT NULL \
         GROUP BY status ORDER BY n DESC, status LIMIT 10",
        "SELECT software, scanner, n, count(*) OVER () FROM (SELECT software, scanner, \
         count(*) AS n FROM sip_messages WHERE software IS NOT NULL GROUP BY software, scanner) \
         ORDER BY n DESC, software, scanner LIMIT 10",
        "SELECT count(*) FROM sip_messages WHERE scanner IS NOT NULL",
        "SELECT count(DISTINCT src_ip) FROM sip_messages",
        "SELECT software, scanner, count(*) AS n FROM sip_messages WHERE software IS NOT NULL \
         GROUP BY software, scanner",
        "SELECT method, state, count(*), coalesce(sum(duration_ns), 0) FROM sip_dialogs \
         GROUP BY method, state",
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
}

/// `cargo test -p netsift-store --release sip::tests::timings -- --ignored --nocapture`.
#[test]
#[ignore = "measurement"]
#[allow(clippy::print_stdout)]
fn timings() {
    let calls = 125_000_i64;
    let conn = volume(calls);
    let t = std::time::Instant::now();
    conn.execute_batch("BEGIN").unwrap();
    finalize(&conn).unwrap();
    conn.execute_batch("COMMIT; ANALYZE").unwrap();
    println!("finalize {:?}", t.elapsed());
    let t = std::time::Instant::now();
    conn.execute_batch("BEGIN").unwrap();
    join_media_flows(&conn).unwrap();
    conn.execute_batch("COMMIT").unwrap();
    println!("media join alone {:?}", t.elapsed());
    let joined: i64 = conn
        .query_row("SELECT sum(flow_count) FROM sip_media", [], |r| r.get(0))
        .unwrap();
    println!("media joined to {joined} flows");
    print_plans(&conn);
    let total = calls * 4 * S;
    for (name, range) in [
        ("whole", None),
        ("1 h", TimeRange::new(total / 2, total / 2 + 3_600 * S)),
        ("half", TimeRange::new(total / 4, total * 3 / 4)),
    ] {
        let t = std::time::Instant::now();
        stats(&conn, 10, range).unwrap();
        let stats_time = t.elapsed();
        let t = std::time::Instant::now();
        let filter = SipMessageFilter {
            range,
            ..SipMessageFilter::default()
        };
        messages_page(&conn, &filter, &PageRequest::first(200)).unwrap();
        count_messages(&conn, &filter).unwrap();
        let messages_time = t.elapsed();
        let t = std::time::Instant::now();
        let dialogs = SipDialogFilter {
            kind: Some(DialogType::Call),
            range,
            ..SipDialogFilter::default()
        };
        dialogs_page(&conn, &dialogs, &PageRequest::first(200)).unwrap();
        count_dialogs(&conn, &dialogs).unwrap();
        let dialogs_time = t.elapsed();
        let t = std::time::Instant::now();
        let registers = SipDialogFilter {
            kind: Some(DialogType::Register),
            q: Some("reg-4".to_owned()),
            range,
            ..SipDialogFilter::default()
        };
        dialogs_page(&conn, &registers, &PageRequest::first(200)).unwrap();
        count_dialogs(&conn, &registers).unwrap();
        let search_time = t.elapsed();
        let t = std::time::Instant::now();
        scanners(&conn, 50, range).unwrap();
        let scanners_time = t.elapsed();
        println!(
            "{name}: stats {stats_time:?}, messages {messages_time:?}, calls {dialogs_time:?}, \
             register search {search_time:?}, scanners {scanners_time:?}"
        );
    }
}
