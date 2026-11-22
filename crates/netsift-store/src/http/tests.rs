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
    // The search indexes are built at the end of the import (step `http`, recorded in `meta`).
    assert!(crate::finalize::run_finalizers(conn).unwrap().is_complete());
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
    assert_eq!(header_count(&conn, None).unwrap(), 11);
    // Duplicate (flow, seq): rejected as a whole, headers included.
    let err = row(0, 10, Some("GET"), "a", "/", None, None, 0, &[("A", "b")]).insert(&conn);
    assert!(err.is_err());
    assert_eq!(header_count(&conn, None).unwrap(), 11);
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
fn search_indexes_are_built_by_the_finalizer_only() {
    let conn = db();
    fill(&conn);
    // No trigger: a row inserted afterwards waits for the next rebuild.
    row(
        9,
        1,
        Some("GET"),
        "late.test",
        "/late",
        Some(200),
        None,
        0,
        &[],
    )
    .insert(&conn)
    .unwrap();
    let q = HttpFilter {
        q: Some("late".into()),
        ..HttpFilter::default()
    };
    assert_eq!(list(&conn, &q), Vec::<String>::new());
    finalize(&conn).unwrap();
    finalize(&conn).unwrap();
    assert_eq!(list(&conn, &q), vec!["/late"]);
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
    assert_eq!(d.entry.server, EndpointInfo::default());
    conn.execute_batch(
        "INSERT INTO hosts (ip, names, country, category, first_ts, last_ts) \
         VALUES ('203.0.113.80', '[\"web.example.test\"]', 'FR', 'public', 0, 1)",
    )
    .unwrap();
    let d = transaction(&conn, id).unwrap().unwrap();
    assert_eq!(d.entry.server.names, vec!["web.example.test".to_owned()]);
    assert_eq!(d.entry.server.country.as_deref(), Some("FR"));
    assert_eq!(d.entry.client.category, None);
    let page = transactions_page(
        &conn,
        &HttpFilter::default(),
        HttpSort::Time,
        false,
        &PageRequest::first(1),
    )
    .unwrap();
    assert_eq!(page.items[0].server.category.as_deref(), Some("public"));
    assert!(transaction(&conn, 999).unwrap().is_none());
}

#[test]
fn stats_are_ordered_and_bounded() {
    let conn = db();
    fill(&conn);
    let s = stats(&conn, None).unwrap();
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
        keys(&header_names(&conn, 1, None).unwrap()),
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
                "SELECT t.id FROM {ENTRY_FROM} WHERE 1{cursor} \
                 ORDER BY {sort} DESC, t.id DESC LIMIT 10"
            ));
            assert!(p.contains(index), "{sort}: {p}");
            assert!(!p.contains("TEMP B-TREE"), "{sort}: {p}");
        }
    }
    // Without filter, the query has no condition at all (P4.2): the count no longer builds the
    // set of transactions of the header filter (a scan of `http_headers`).
    assert!(conditions(&HttpFilter::default(), true).unwrap().is_empty());
    // An active filter uses its index.
    let host = HttpFilter {
        host: Some("www.example.test".into()),
        ..HttpFilter::default()
    };
    let c = conditions(&host, true).unwrap();
    let p = plan(&format!(
        "SELECT count(*) FROM http_transactions t WHERE {}",
        c.sql().unwrap()
    ));
    assert!(p.contains("http_transactions_host"), "{p}");
}

/// The filter before P4.2 (`?n IS NULL OR`), reference of [`active_filters_match_the_former_filter`].
const FORMER_FILTER: &str = "(?1 IS NULL OR t.method_group IN (SELECT value FROM json_each(?1))) \
    AND (?2 IS NULL OR t.status_class IN (SELECT value FROM json_each(?2)) \
         OR CAST(t.status AS TEXT) IN (SELECT value FROM json_each(?2))) \
    AND (?3 IS NULL OR t.host = ?3) \
    AND (?4 IS NULL OR t.id IN (SELECT rowid FROM http_transactions_fts \
         WHERE http_transactions_fts MATCH ?4)) \
    AND (?5 IS NULL OR t.host LIKE ?5 ESCAPE '\\' OR t.uri LIKE ?5 ESCAPE '\\' \
         OR t.user_agent LIKE ?5 ESCAPE '\\') \
    AND ((?6 IS NULL AND ?7 IS NULL AND ?8 IS NULL) OR t.id IN ( \
         SELECT h.transaction_id FROM http_headers h \
         WHERE (?6 IS NULL OR h.name_lc = ?6) \
           AND (?7 IS NULL OR h.id IN (SELECT rowid FROM http_headers_fts \
                WHERE http_headers_fts MATCH ?7)) \
           AND (?8 IS NULL OR h.name LIKE ?8 ESCAPE '\\' OR h.value LIKE ?8 ESCAPE '\\')))";

#[test]
fn active_filters_match_the_former_filter() {
    let conn = db();
    fill(&conn);
    let lists = |v: &[&str]| Some(v.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>());
    let methods = [None, lists(&["GET"]), lists(&["POST", "other"])];
    let statuses = [
        None,
        lists(&["2xx"]),
        lists(&["404", "none"]),
        lists(&["0404", "5xx", "abc"]),
    ];
    let hosts = [None, Some("a.test")];
    let texts = [None, Some("issin"), Some("/l"), Some("curl")];
    let names = [None, Some("host"), Some("AUTHORIZATION")];
    let header_texts = [None, Some("3cr3t"), Some("b.")];
    // The expected rows use the search index; the second pass forgets the step `http`, so that
    // every search falls back to `LIKE` (ADR-023): same rows.
    let fts_ready = true;
    let mut checked = 0;
    for pass in 0..2 {
        if pass == 1 {
            conn.execute("DELETE FROM meta WHERE key = 'finalizers'", [])
                .unwrap();
        }
        for m in &methods {
            for st in &statuses {
                for host in hosts {
                    for q in texts {
                        for name in names {
                            for hq in header_texts {
                                let filter = HttpFilter {
                                    methods: m.clone(),
                                    statuses: st.clone(),
                                    host: host.map(str::to_owned),
                                    q: q.map(str::to_owned),
                                    header_name: name.map(str::to_owned),
                                    header_q: hq.map(str::to_owned),
                                    range: None,
                                };
                                let (fts, like) = search(filter.q.as_deref(), fts_ready).unwrap();
                                let (hfts, hlike) =
                                    search(filter.header_q.as_deref(), fts_ready).unwrap();
                                let p: [Option<String>; 8] = [
                                    json_list(filter.methods.as_ref()).unwrap(),
                                    json_list(filter.statuses.as_ref()).unwrap(),
                                    filter.host.clone(),
                                    fts,
                                    like,
                                    filter
                                        .header_name
                                        .as_deref()
                                        .map(|n| n.trim().to_ascii_lowercase()),
                                    hfts,
                                    hlike,
                                ];
                                let want: Vec<String> = conn
                                .prepare(&format!(
                                    "SELECT t.path FROM http_transactions t WHERE {FORMER_FILTER} \
                                     ORDER BY t.ts, t.id"
                                ))
                                .unwrap()
                                .query_map(rusqlite::params_from_iter(p.iter()), |r| r.get(0))
                                .unwrap()
                                .map(Result::unwrap)
                                .collect();
                                assert_eq!(list(&conn, &filter), want, "{filter:?}");
                                assert_eq!(
                                    count_transactions(&conn, &filter).unwrap(),
                                    u64::try_from(want.len()).unwrap(),
                                    "{filter:?}"
                                );
                                checked += usize::from(!want.is_empty());
                            }
                        }
                    }
                }
            }
        }
    }
    assert!(checked > 60, "too few non-empty cases: {checked}");
}

#[test]
fn pages_read_their_hosts_after_the_sort_with_the_same_rows() {
    let conn = db();
    fill(&conn);
    // Hosts known for one end only, and a second client.
    conn.execute_batch(
        "INSERT INTO hosts (ip, names, category, country, first_ts, last_ts) VALUES
             ('192.168.1.10', '[\"pc.lan\"]', 'private', NULL, 0, 1);
         UPDATE http_transactions SET client_ip = '192.168.1.11' WHERE seq IN (1, 3);",
    )
    .unwrap();
    let filters = [
        HttpFilter::default(),
        HttpFilter {
            q: Some("test".to_owned()),
            ..HttpFilter::default()
        },
        HttpFilter {
            header_name: Some("host".to_owned()),
            ..HttpFilter::default()
        },
    ];
    for filter in &filters {
        for (sort, expr) in [
            (HttpSort::Time, "t.ts"),
            (HttpSort::Size, "t.resp_body_len"),
            (HttpSort::Status, "t.status_key"),
        ] {
            for descending in [false, true] {
                let c = conditions(filter, true).unwrap();
                let where_sql = c.sql();
                // The former query: hosts joined before the sort.
                let former = Keyset {
                    from: ENTRY_FROM,
                    select: ENTRY_COLUMNS,
                    sort: expr,
                    tiebreak: "t.id",
                    descending,
                    filter: where_sql.as_deref(),
                };
                let mut want = Vec::new();
                let mut got = Vec::new();
                let mut request = PageRequest::first(2);
                loop {
                    let page =
                        keyset_page(&conn, &former, &c.params(), &request, HttpEntry::from_row)
                            .unwrap();
                    want.extend(page.items);
                    match page.next_cursor {
                        Some(cursor) => request.cursor = Some(cursor),
                        None => break,
                    }
                }
                let mut request = PageRequest::first(2);
                loop {
                    let page =
                        transactions_page(&conn, filter, sort, descending, &request).unwrap();
                    got.extend(page.items);
                    match page.next_cursor {
                        Some(cursor) => request.cursor = Some(cursor),
                        None => break,
                    }
                }
                assert_ne!(want.len(), 0);
                assert_eq!(got, want, "{filter:?} {sort:?} {descending}");
            }
        }
    }
    // The rows of a page: one search per id, in `http_transactions` then `hosts`.
    let mut stmt = conn
        .prepare(&format!(
            "EXPLAIN QUERY PLAN SELECT {ENTRY_COLUMNS} FROM json_each(?1) p \
             JOIN http_transactions t ON t.id = p.value \
             LEFT JOIN hosts hc ON hc.ip = t.client_ip LEFT JOIN hosts hs ON hs.ip = t.server_ip"
        ))
        .unwrap();
    let plan = stmt
        .query_map(["[3,1,2]"], |r| r.get::<_, String>(3))
        .unwrap()
        .map(Result::unwrap)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        plan.contains("SEARCH t USING INTEGER PRIMARY KEY (rowid=?)"),
        "{plan}"
    );
    assert!(
        plan.lines()
            .filter(|l| l.contains("SCAN"))
            .all(|l| l.starts_with("SCAN p VIRTUAL TABLE")),
        "{plan}"
    );
    assert!(!plan.contains("TEMP B-TREE"), "{plan}");
}
