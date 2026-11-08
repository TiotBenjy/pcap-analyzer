use super::*;
use crate::session::{OpenMode, Session};

fn session() -> (tempfile::TempDir, Session) {
    let dir = tempfile::tempdir().unwrap();
    let session = Session::open(dir.path(), OpenMode::ReadWrite).unwrap();
    (dir, session)
}

/// `(flow_id, seq, response time, sha, mime, size, host, uri)`.
type Tx = (
    i64,
    i64,
    i64,
    Option<&'static str>,
    Option<&'static str>,
    i64,
    &'static str,
    &'static str,
);

const SHA_A: &str = "aa00000000000000000000000000000000000000000000000000000000000000";
const SHA_B: &str = "bb00000000000000000000000000000000000000000000000000000000000000";
const SHA_S: &str = "cc00000000000000000000000000000000000000000000000000000000000000";

fn transactions() -> Vec<Tx> {
    vec![
        (
            7,
            0,
            300,
            Some(SHA_A),
            Some("image/png"),
            1000,
            "cdn.test",
            "/a.png",
        ),
        (
            3,
            1,
            100,
            Some(SHA_A),
            Some("image/png"),
            1000,
            "www.test",
            "/logo.png",
        ),
        (
            3,
            0,
            100,
            Some(SHA_B),
            Some("image/jpeg"),
            5000,
            "www.test",
            "/photo.jpg",
        ),
        (
            9,
            0,
            50,
            Some(SHA_S),
            Some("image/svg+xml"),
            400,
            "www.test",
            "/icon.svg",
        ),
        (9, 1, 60, None, Some("text/html"), 20, "www.test", "/"),
        (
            5,
            0,
            100,
            Some(SHA_A),
            Some("image/png"),
            1000,
            "cdn.test",
            "/a.png?v=2",
        ),
    ]
}

fn insert(conn: &Connection, txs: &[Tx]) {
    for (flow, seq, ts, sha, mime, size, host, uri) in txs {
        conn.execute(
            "INSERT INTO http_transactions (flow_id, seq, client_ip, client_port, server_ip, \
             server_port, ts, end_ts, method, method_group, uri, host, status, status_key, \
             status_class, content_type, resp_ts, resp_body_len, resp_body_state, \
             resp_mime_magic, resp_sha256) \
             VALUES (?1, ?2, '10.0.0.1', 40000, '10.0.0.2', 80, ?3 - 1, ?3, 'GET', 'GET', ?4, \
             ?5, 200, 200, '2xx', 'image/x-test', ?3, ?6, 'complete', ?7, ?8)",
            params![flow, seq, ts, uri, host, size, mime, sha],
        )
        .unwrap();
    }
}

fn dump(conn: &Connection) -> Vec<String> {
    let mut stmt = conn
        .prepare(
            "SELECT id || ' ' || sha256 || ' ' || mime || ' ' || size || ' x' || occurrences || \
             ' ' || first_ts || '-' || last_ts || ' ' || flow_id || '/' || seq || ' ' || host || \
             uri || ' ' || thumb FROM objects ORDER BY id",
        )
        .unwrap();
    stmt.query_map([], |r| r.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}

#[test]
fn one_row_per_digest_whatever_the_arrival_order() {
    let (_d1, s1) = session();
    insert(s1.conn(), &transactions());
    finalize(s1.conn()).unwrap();
    let expected = dump(s1.conn());
    assert_eq!(
        expected,
        vec![
            format!("1 {SHA_S} image/svg+xml 400 x1 50-50 9/0 www.test/icon.svg none"),
            format!("2 {SHA_B} image/jpeg 5000 x1 100-100 3/0 www.test/photo.jpg pending"),
            // First appearance: smallest (time, flow, seq) among three occurrences.
            format!("3 {SHA_A} image/png 1000 x3 100-300 3/1 www.test/logo.png pending"),
        ]
    );
    let (_d2, s2) = session();
    let mut reversed = transactions();
    reversed.reverse();
    insert(s2.conn(), &reversed);
    finalize(s2.conn()).unwrap();
    assert_eq!(dump(s2.conn()), expected);
}

#[test]
fn a_replay_keeps_the_thumbnails() {
    let (_d, mut s) = session();
    insert(s.conn(), &transactions());
    finalize(s.conn()).unwrap();
    let pending = pending_thumbs(s.conn(), 0, 10).unwrap();
    assert_eq!(
        pending
            .iter()
            .map(|p| p.sha256.as_str())
            .collect::<Vec<_>>(),
        vec![SHA_B, SHA_A]
    );
    assert_eq!(count_pending_thumbs(s.conn()).unwrap(), 2);
    // Batches by keyset.
    let first = pending_thumbs(s.conn(), 0, 1).unwrap();
    assert_eq!(first.len(), 1);
    let next = pending_thumbs(s.conn(), first[0].id, 1).unwrap();
    assert_eq!(next[0].sha256, SHA_A);
    set_thumbs(
        s.conn_mut(),
        &[ThumbUpdate {
            sha256: SHA_A.to_owned(),
            state: thumb::READY,
            width: Some(16),
            height: Some(8),
        }],
    )
    .unwrap();
    finalize(s.conn()).unwrap();
    let a = object(s.conn(), SHA_A).unwrap().unwrap();
    assert_eq!(
        (a.thumb.as_str(), a.width, a.height),
        ("ready", Some(16), Some(8))
    );
    assert_eq!(a.occurrences, 3);
    assert_eq!(pending_thumbs(s.conn(), 0, 10).unwrap().len(), 1);
    assert!(object(s.conn(), "missing").unwrap().is_none());
}

#[test]
fn pages_filters_and_stats() {
    let (_d, s) = session();
    let conn = s.conn();
    insert(conn, &transactions());
    finalize(conn).unwrap();
    let all = ObjectFilter::default();
    let page = objects_page(conn, &all, ObjectSort::Size, true, &PageRequest::first(2)).unwrap();
    assert_eq!(
        page.items.iter().map(|o| o.size).collect::<Vec<_>>(),
        vec![5000, 1000]
    );
    let next = PageRequest {
        limit: 2,
        cursor: page.next_cursor.clone(),
    };
    let rest = objects_page(conn, &all, ObjectSort::Size, true, &next).unwrap();
    assert_eq!(rest.items.len(), 1);
    assert!(rest.next_cursor.is_none());
    let time = objects_page(conn, &all, ObjectSort::Time, false, &PageRequest::first(10)).unwrap();
    assert_eq!(time.items[0].mime, "image/svg+xml");

    let count = |f: ObjectFilter| count_objects(conn, &f).unwrap();
    assert_eq!(count(all.clone()), 3);
    let png = ObjectFilter {
        mime: Some("image/png".to_owned()),
        ..ObjectFilter::default()
    };
    assert_eq!(count(png), 1);
    let host = ObjectFilter {
        host: Some("www.test".to_owned()),
        ..ObjectFilter::default()
    };
    assert_eq!(count(host), 3);
    let q = ObjectFilter {
        q: Some("PHOTO".to_owned()),
        ..ObjectFilter::default()
    };
    assert_eq!(count(q), 1, "case-insensitive");
    let wildcard = ObjectFilter {
        q: Some("%".to_owned()),
        ..ObjectFilter::default()
    };
    assert_eq!(count(wildcard), 0, "LIKE wildcards are literal");
    let sizes = ObjectFilter {
        min_size: Some(500),
        max_size: Some(1000),
        ..ObjectFilter::default()
    };
    assert_eq!(count(sizes), 1);

    let st = stats(conn, true, 10).unwrap();
    assert_eq!((st.count, st.bytes, st.occurrences), (3, 6400, 5));
    assert_eq!(st.types.len(), 3);
    assert_eq!(st.hosts, vec![("www.test".to_owned(), 3)]);
    // The view counted by the overview.
    let pictures: i64 = conn
        .query_row("SELECT count(*) FROM pictures", [], |r| r.get(0))
        .unwrap();
    assert_eq!(pictures, 3);
}
