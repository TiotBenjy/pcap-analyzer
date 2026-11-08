use super::*;
use crate::migrate::migrate;
use crate::schema::SESSION_SCHEMA;

fn db() -> Connection {
    let mut conn = Connection::open_in_memory().unwrap();
    migrate(&mut conn, &SESSION_SCHEMA).unwrap();
    conn
}

fn message(ts: i64, headers: &[(&str, &str)], body_len: u64) -> HttpMessageRow {
    HttpMessageRow {
        ts,
        frame: 1,
        head_len: 100,
        body_wire: body_len,
        body_len,
        body_state: if body_len == 0 { "none" } else { "complete" }.to_owned(),
        chunked: false,
        encoding: None,
        mime_magic: None,
        sha256: None,
        preview: None,
        headers: headers
            .iter()
            .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
            .collect(),
    }
}

#[allow(clippy::too_many_arguments)]
fn row(
    seq: u32,
    ts: i64,
    method: Option<&str>,
    host: &str,
    path: &str,
    status: Option<u16>,
    ctype: Option<&str>,
    size: u64,
    headers: &[(&str, &str)],
) -> HttpRow {
    HttpRow {
        flow_id: 42,
        seq,
        client_ip: "192.168.1.10".parse().unwrap(),
        client_port: 50_000,
        server_ip: "203.0.113.80".parse().unwrap(),
        server_port: 80,
        ts,
        end_ts: ts + 10,
        method: method.map(ToOwned::to_owned),
        uri: Some(path.to_owned()),
        host: Some(host.to_owned()),
        path: Some(path.to_owned()),
        query: None,
        version: Some("HTTP/1.1".to_owned()),
        status,
        reason: status.map(|_| "R".to_owned()),
        content_type: ctype.map(ToOwned::to_owned),
        user_agent: Some("curl/8.0".to_owned()),
        referer: None,
        req_content_type: None,
        request: method.map(|_| message(ts, headers, 0)),
        response: status.map(|_| message(ts + 5, &[("Server", "nginx")], size)),
    }
}

fn fill(conn: &Connection) {
    let rows = [
        row(
            0,
            10,
            Some("GET"),
            "a.test",
            "/index.html",
            Some(200),
            Some("text/html"),
            500,
            &[("Host", "a.test"), ("Cookie", "session=s3cr3tvalue42")],
        ),
        row(
            1,
            20,
            Some("POST"),
            "a.test",
            "/login",
            Some(302),
            None,
            0,
            &[("Host", "a.test"), ("Authorization", "Basic dXNlcjpwYXNz")],
        ),
        row(
            2,
            30,
            Some("GET"),
            "b.test",
            "/missing",
            Some(404),
            Some("text/html"),
            50,
            &[("Host", "b.test")],
        ),
        row(
            3,
            40,
            Some("PROPFIND"),
            "b.test",
            "/dav",
            None,
            None,
            0,
            &[("Host", "b.test"), ("X-Rare", "1")],
        ),
        row(
            4,
            50,
            None,
            "",
            "",
            Some(500),
            Some("application/json"),
            7000,
            &[],
        ),
    ];
    for r in &rows {
        r.insert(conn).unwrap();
    }
}

fn paths(page: &Page<HttpEntry>) -> Vec<String> {
    page.items
        .iter()
        .map(|e| e.path.clone().unwrap_or_default())
        .collect()
}

fn list(conn: &Connection, filter: &HttpFilter) -> Vec<String> {
    paths(
        &transactions_page(
            conn,
            filter,
            HttpSort::Time,
            false,
            &PageRequest::first(100),
        )
        .unwrap(),
    )
}

#[test]
fn insert_writes_headers_and_derived_columns() {
    let conn = db();
    fill(&conn);
    let (group, class): (String, String) = conn
        .query_row(
            "SELECT method_group, status_class FROM http_transactions WHERE seq = 3",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!((group.as_str(), class.as_str()), ("other", "none"));
    assert_eq!(header_count(&conn).unwrap(), 11);
    // Duplicate (flow, seq): rejected as a whole, headers included.
    let err = row(0, 10, Some("GET"), "a", "/", None, None, 0, &[("A", "b")]).insert(&conn);
    assert!(err.is_err());
    assert_eq!(header_count(&conn).unwrap(), 11);
}

#[test]
fn filters_combine() {
    let conn = db();
    fill(&conn);
    let all = HttpFilter::default();
    assert_eq!(list(&conn, &all).len(), 5);
    let get = HttpFilter {
        methods: Some(vec!["GET".into()]),
        ..HttpFilter::default()
    };
    assert_eq!(list(&conn, &get), vec!["/index.html", "/missing"]);
    let other = HttpFilter {
        methods: Some(vec!["other".into()]),
        ..HttpFilter::default()
    };
    assert_eq!(list(&conn, &other), vec!["/dav", ""]);
    let none = HttpFilter {
        methods: Some(vec![]),
        ..HttpFilter::default()
    };
    assert_eq!(list(&conn, &none), Vec::<String>::new());
    let errors = HttpFilter {
        statuses: Some(vec!["4xx".into(), "500".into()]),
        ..HttpFilter::default()
    };
    assert_eq!(list(&conn, &errors), vec!["/missing", ""]);
    let unanswered = HttpFilter {
        statuses: Some(vec!["none".into()]),
        host: Some("b.test".into()),
        ..HttpFilter::default()
    };
    assert_eq!(list(&conn, &unanswered), vec!["/dav"]);
    assert_eq!(count_transactions(&conn, &unanswered).unwrap(), 1);
}

#[test]
fn text_search_uses_trigrams_or_like() {
    let conn = db();
    fill(&conn);
    let q = |q: &str| {
        list(
            &conn,
            &HttpFilter {
                q: Some(q.into()),
                ..HttpFilter::default()
            },
        )
    };
    assert_eq!(q("issin"), vec!["/missing"]);
    assert_eq!(q("b.t"), vec!["/missing", "/dav"]);
    assert_eq!(q("/l"), vec!["/login"]);
    assert_eq!(q("%"), Vec::<String>::new());
    assert_eq!(q("\"quoted"), Vec::<String>::new());
    assert!(
        transactions_page(
            &conn,
            &HttpFilter {
                q: Some("x".repeat(MAX_QUERY_CHARS + 1)),
                ..HttpFilter::default()
            },
            HttpSort::Time,
            false,
            &PageRequest::first(10),
        )
        .is_err()
    );
}

#[test]
fn header_search_finds_cookie_values() {
    let conn = db();
    fill(&conn);
    let find = |name: Option<&str>, q: Option<&str>| {
        list(
            &conn,
            &HttpFilter {
                header_name: name.map(Into::into),
                header_q: q.map(Into::into),
                ..HttpFilter::default()
            },
        )
    };
    assert_eq!(find(None, Some("3cr3tval")), vec!["/index.html"]);
    assert_eq!(find(Some("AUTHORIZATION"), None), vec!["/login"]);
    assert_eq!(find(Some("host"), Some("b.test")), vec!["/missing", "/dav"]);
    assert_eq!(find(Some("cookie"), Some("b.test")), Vec::<String>::new());
    assert_eq!(
        find(None, Some("ng")),
        vec!["/index.html", "/login", "/missing", ""]
    );
}

#[test]
fn keyset_pages_follow_each_sort() {
    let conn = db();
    fill(&conn);
    for (sort, desc, expected) in [
        (
            HttpSort::Time,
            true,
            vec!["", "/dav", "/missing", "/login", "/index.html"],
        ),
        (
            HttpSort::Size,
            true,
            vec!["", "/index.html", "/missing", "/dav", "/login"],
        ),
        (
            HttpSort::Status,
            false,
            vec!["/dav", "/index.html", "/login", "/missing", ""],
        ),
    ] {
        let mut seen = Vec::new();
        let mut request = PageRequest::first(2);
        loop {
            let page =
                transactions_page(&conn, &HttpFilter::default(), sort, desc, &request).unwrap();
            seen.extend(paths(&page));
            match page.next_cursor {
                Some(c) => request.cursor = Some(c),
                None => break,
            }
        }
        // Size ties (0) are broken by id, descending.
        assert_eq!(seen, expected, "{sort:?}");
    }
}

#[test]
fn detail_has_both_messages_and_headers_in_order() {
    let conn = db();
    fill(&conn);
    let id: i64 = conn
        .query_row("SELECT id FROM http_transactions WHERE seq = 0", [], |r| {
            r.get(0)
        })
        .unwrap();
    let d = transaction(&conn, id).unwrap().unwrap();
    assert_eq!(d.entry.path.as_deref(), Some("/index.html"));
    let req = d.request.unwrap();
    assert_eq!(
        req.headers,
        vec![
            ("Host".to_owned(), "a.test".to_owned()),
            ("Cookie".to_owned(), "session=s3cr3tvalue42".to_owned())
        ]
    );
    let resp = d.response.unwrap();
    assert_eq!(resp.body_len, 500);
    assert_eq!(resp.content_type.as_deref(), Some("text/html"));
    assert_eq!(d.flow_first_ts, None);
    assert!(transaction(&conn, 999).unwrap().is_none());
}

#[test]
fn stats_are_ordered_and_bounded() {
    let conn = db();
    fill(&conn);
    let s = stats(&conn).unwrap();
    assert_eq!(s.transactions, 5);
    let keys = |v: &[Count]| {
        v.iter()
            .map(|c| (c.key.clone(), c.count))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        keys(&s.methods),
        vec![("GET".into(), 2), ("POST".into(), 1), ("other".into(), 2)]
    );
    assert_eq!(
        keys(&s.status_classes),
        vec![
            ("2xx".into(), 1),
            ("3xx".into(), 1),
            ("4xx".into(), 1),
            ("5xx".into(), 1),
            ("none".into(), 1)
        ]
    );
    assert_eq!(s.statuses.len(), 4);
    assert_eq!(keys(&s.content_types)[0], ("text/html".into(), 2));
    assert_eq!(s.content_types_other, 0);
    assert_eq!(keys(&s.hosts)[0], ("a.test".into(), 2));
    assert_eq!(s.host_count, 3);
    assert_eq!(keys(&s.rare_headers)[0], ("authorization".into(), 1));
    assert_eq!(s.header_count, 11);
    assert_eq!(
        keys(&header_names(&conn, 1).unwrap()),
        vec![("host".into(), 4)]
    );
}

#[test]
fn classes_and_groups() {
    assert_eq!(method_group(Some("GET")), "GET");
    assert_eq!(method_group(Some("get")), "other");
    assert_eq!(method_group(None), "other");
    assert_eq!(status_class(Some(101)), "1xx");
    assert_eq!(status_class(Some(999)), "other");
    assert_eq!(status_class(None), "none");
}

#[test]
fn sort_queries_use_indexes() {
    let conn = db();
    fill(&conn);
    let plan = |sql: &str| -> String {
        let mut stmt = conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap();
        let nulls = vec![rusqlite::types::Null; stmt.parameter_count()];
        let rows = stmt
            .query_map(rusqlite::params_from_iter(nulls), |r| r.get::<_, String>(3))
            .unwrap();
        rows.map(Result::unwrap).collect::<Vec<_>>().join("\n")
    };
    for (sort, index) in [
        ("t.ts", "http_transactions_ts"),
        ("t.resp_body_len", "http_transactions_size"),
        ("t.status_key", "http_transactions_status"),
    ] {
        for cursor in ["", &format!(" AND ({sort}, t.id) < (?, ?)")] {
            let p = plan(&format!(
                "SELECT t.id FROM http_transactions t WHERE ({FILTER}){cursor} \
                 ORDER BY {sort} DESC, t.id DESC LIMIT 10"
            ));
            assert!(p.contains(index), "{sort}: {p}");
            assert!(!p.contains("TEMP B-TREE"), "{sort}: {p}");
        }
    }
}
