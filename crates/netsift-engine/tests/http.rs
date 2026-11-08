//! End-to-end imports through the `http` analyzer: the HTTP tables do not depend on the
//! chunking of the capture, a response cut between two chunk files included.

use std::path::Path;

use netsift_engine::{CancelToken, IngestOptions, IngestReport, ingest};
use netsift_fixtures::scenario::TcpOptions;
use netsift_fixtures::scenarios::hosts;
use netsift_fixtures::{
    Encoding, Naming, Packet, Scenario, SplitBy, SplitOptions, split_to_dir, write_file,
};
use netsift_store::{Catalog, OpenMode, SessionState};
use tempfile::TempDir;

fn run(catalog: &Catalog, input: &Path, shards: usize) -> IngestReport {
    let options = IngestOptions {
        shards: Some(shards),
        ..IngestOptions::default()
    };
    ingest(catalog, input, &options, &CancelToken::new(), &mut |_| {}).unwrap()
}

/// Files under the `blobs/` directory of a session.
fn blob_files(catalog: &Catalog, report: &IngestReport) -> Vec<std::path::PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for e in entries.flatten() {
            let path = e.path();
            if path.is_dir() {
                walk(&path, out);
            } else {
                out.push(path);
            }
        }
    }
    let mut out = Vec::new();
    walk(
        &catalog.session_dir(&report.session).join("blobs"),
        &mut out,
    );
    out
}

/// Comparable content of the HTTP tables (ids depend on arrival order: left out).
fn http_rows(catalog: &Catalog, report: &IngestReport) -> Vec<String> {
    let session = catalog
        .open_session(&report.session, OpenMode::ReadOnly)
        .unwrap();
    let mut stmt = session
        .conn()
        .prepare(
            "SELECT t.flow_id || '/' || t.seq || ' ' || coalesce(t.method, '-') || ' ' || \
             coalesce(t.host, '-') || coalesce(t.path, '') || ' ' || coalesce(t.status, '-') || \
             ' ' || coalesce(t.content_type, '-') || ' resp=' || t.resp_body_len || '/' || \
             coalesce(t.resp_body_wire, '-') || ' ' || coalesce(t.resp_body_state, '-') || \
             ' headers=' || (SELECT count(*) FROM http_headers h WHERE h.transaction_id = t.id) \
             FROM http_transactions t ORDER BY t.flow_id, t.seq",
        )
        .unwrap();
    stmt.query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

/// Keep-alive connection with three transactions (the second response is large, chunked),
/// a request without response and the demo image download.
fn traffic() -> (Vec<Packet>, usize) {
    let mut sc = Scenario::new();
    let mut s = sc.tcp_open(
        hosts::workstation(),
        hosts::web_server(),
        &TcpOptions::new(80),
    );
    s.client_send(b"GET / HTTP/1.1\r\nHost: www.example.test\r\n\r\n");
    s.server_send(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 5\r\n\r\nhello");
    s.client_send(b"GET /data.json HTTP/1.1\r\nHost: www.example.test\r\n\r\n");
    let mut body = Vec::new();
    for i in 0..40 {
        let piece = format!("{{\"row\":{i},\"pad\":\"{}\"}}\n", "x".repeat(200));
        body.extend_from_slice(format!("{:x}\r\n", piece.len()).as_bytes());
        body.extend_from_slice(piece.as_bytes());
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(b"0\r\n\r\n");
    let mut resp =
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n"
            .to_vec();
    resp.extend_from_slice(&body);
    let cut = s.server_send(&resp);
    s.client_send(b"POST /form HTTP/1.1\r\nHost: www.example.test\r\nContent-Length: 3\r\n\r\na=1");
    s.server_send(b"HTTP/1.1 204 No Content\r\n\r\n");
    s.close();
    sc.advance(10_000_000);
    let mut s = sc.tcp_open(
        hosts::workstation(),
        hosts::web_server(),
        &TcpOptions::new(8080),
    );
    s.client_send(b"GET /never HTTP/1.1\r\nHost: slow.example.test\r\n\r\n");
    s.close();
    sc.advance(10_000_000);
    sc.http_get(
        hosts::workstation(),
        hosts::web_server(),
        &netsift_fixtures::scenario::HttpGet::default(),
    );
    // Split in the middle of the large response.
    let middle = usize::midpoint(cut.start, cut.end);
    (sc.into_packets(), middle)
}

#[test]
fn http_tables_do_not_depend_on_chunking_nor_shards() {
    let tmp = TempDir::new().unwrap();
    let catalog = Catalog::open(tmp.path().join("data")).unwrap();
    let (packets, middle) = traffic();

    let single = tmp.path().join("single.pcap");
    write_file(&single, &packets, &Encoding::pcap()).unwrap();
    let reference = run(&catalog, &single, 1);
    assert_eq!(reference.state, SessionState::Ready);
    let expected = http_rows(&catalog, &reference);
    insta::assert_snapshot!(expected.join("\n"));
    assert_eq!(expected.len(), 5);

    let dir = tmp.path().join("chunks");
    let opts = SplitOptions::new(SplitBy::At(vec![middle, middle + 3]), Naming::Dumpcap)
        .with_encoding(Encoding::pcapng());
    let files = split_to_dir(&dir, &packets, &opts).unwrap().1;
    assert_eq!(files.len(), 3);
    for shards in [1, 4] {
        let report = run(&catalog, &dir, shards);
        assert_eq!(report.chunks_read, 3);
        assert_eq!(http_rows(&catalog, &report), expected, "{shards} shards");
    }
}

#[test]
fn header_search_finds_a_cookie() {
    let tmp = TempDir::new().unwrap();
    let catalog = Catalog::open(tmp.path().join("data")).unwrap();
    let mut sc = Scenario::new();
    let mut s = sc.tcp_open(
        hosts::workstation(),
        hosts::web_server(),
        &TcpOptions::new(80),
    );
    s.client_send(b"GET /a HTTP/1.1\r\nHost: x.test\r\nCookie: sid=AbCdEf123456\r\n\r\n");
    s.server_send(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    s.client_send(b"GET /b HTTP/1.1\r\nHost: x.test\r\nCookie: sid=zzz\r\n\r\n");
    s.server_send(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    s.close();
    let file = tmp.path().join("cookie.pcap");
    write_file(&file, sc.packets(), &Encoding::pcap()).unwrap();
    let report = run(&catalog, &file, 2);
    let session = catalog
        .open_session(&report.session, OpenMode::ReadOnly)
        .unwrap();
    let filter = netsift_store::http::HttpFilter {
        header_q: Some("cdef12".to_owned()),
        ..Default::default()
    };
    let page = netsift_store::http::transactions_page(
        session.conn(),
        &filter,
        netsift_store::http::HttpSort::Time,
        false,
        &netsift_store::PageRequest::first(10),
    )
    .unwrap();
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].path.as_deref(), Some("/a"));
}

#[test]
fn only_images_reach_the_disk() {
    let tmp = TempDir::new().unwrap();
    let catalog = Catalog::open(tmp.path().join("data")).unwrap();
    let (packets, _) = traffic();
    let file = tmp.path().join("http.pcap");
    write_file(&file, &packets, &Encoding::pcap()).unwrap();

    // Default (P3.6): the image is stored; the page, the JSON document and the POST body not.
    let report = run(&catalog, &file, 2);
    let blobs = blob_files(&catalog, &report);
    assert_eq!(blobs.len(), 1, "{blobs:?}");
    assert!(std::fs::read(&blobs[0]).unwrap().starts_with(b"\x89PNG"));
    let session = catalog
        .open_session(&report.session, OpenMode::ReadOnly)
        .unwrap();
    let count = |sql: &str| -> i64 { session.conn().query_row(sql, [], |r| r.get(0)).unwrap() };
    assert_eq!(
        count("SELECT count(*) FROM http_transactions WHERE req_sha256 IS NOT NULL"),
        0
    );
    assert_eq!(
        count("SELECT count(*) FROM http_transactions WHERE resp_sha256 IS NOT NULL"),
        1
    );
    assert_eq!(count("SELECT count(*) FROM objects"), 1);
    let sha: String = session
        .conn()
        .query_row("SELECT sha256 FROM objects", [], |r| r.get(0))
        .unwrap();
    assert!(session.blob_path(&sha).unwrap().is_file());

    // Switched off: nothing reaches the disk.
    let mut options = IngestOptions {
        shards: Some(2),
        ..IngestOptions::default()
    };
    options.analyzers.config_mut().http.store_bodies = false;
    let report = ingest(&catalog, &file, &options, &CancelToken::new(), &mut |_| {}).unwrap();
    assert_eq!(
        blob_files(&catalog, &report),
        Vec::<std::path::PathBuf>::new()
    );
}
