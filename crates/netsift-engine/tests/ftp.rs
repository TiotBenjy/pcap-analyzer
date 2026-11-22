//! FTP end to end (ADR-032): a control connection and its data connections reach the same shard,
//! so the sessions, transcripts, transfers and stored files are the same for a single file and
//! for chunks, with 1, 4 or 7 shards.

use std::fmt::Write as _;
use std::path::Path;

use netsift_engine::{CancelToken, IngestOptions, IngestReport, ingest};
use netsift_fixtures::ftp::ftp_showcase;
use netsift_fixtures::scenarios::{Kind, generate};
use netsift_fixtures::{
    Encoding, Naming, Packet, Scenario, SplitBy, SplitOptions, split_to_dir, write_file,
};
use netsift_store::{Catalog, OpenMode, SessionState};
use tempfile::TempDir;

fn options(shards: usize) -> IngestOptions {
    IngestOptions {
        shards: Some(shards),
        ..IngestOptions::default()
    }
}

fn run(catalog: &Catalog, input: &Path, shards: usize) -> IngestReport {
    let report = ingest(
        catalog,
        input,
        &options(shards),
        &CancelToken::new(),
        &mut |_| {},
    )
    .unwrap();
    assert_eq!(report.state, SessionState::Ready);
    report
}

/// The FTP tables and the FTP objects, one line per row (row ids left out: arrival order).
fn ftp_tables(catalog: &Catalog, report: &IngestReport) -> String {
    let session = catalog
        .open_session(&report.session, OpenMode::ReadOnly)
        .unwrap();
    let mut s = String::new();
    for (name, sql) in [
        (
            "session",
            "SELECT flow_id || ' ' || client_ip || ':' || client_port || ' -> ' || server_ip || \
             ':' || server_port || ' ' || first_ts || '..' || last_ts || ' ' || \
             coalesce(username, '-') || ' ' || coalesce(login, '-') || ' tls=' || tls || \
             ' c=' || commands || ' r=' || replies || ' f=' || files || ' l=' || listings || \
             ' b=' || bytes || ' lines=' || lines FROM ftp_sessions ORDER BY flow_id",
        ),
        (
            "line",
            "SELECT flow_id || ' #' || seq || ' ' || ts || ' ' || dir || ' ' || \
             coalesce(head, '-') || ' ' || text FROM ftp_lines ORDER BY flow_id, seq",
        ),
        (
            "transfer",
            "SELECT flow_id || ' #' || seq || ' ' || command || ' ' || coalesce(path, '-') || ' ' || \
             direction || ' ' || coalesce(mode, '-') || ' data=' || coalesce(data_flow_id, '-') || \
             ' ' || coalesce(status, '-') || ' b=' || bytes || ' t=' || truncated || ' ' || \
             coalesce(sha256, '-') || ' ' || coalesce(mime, '-') FROM ftp_transfers \
             ORDER BY flow_id, seq",
        ),
        (
            "object",
            "SELECT sha256 || ' ' || size || ' ' || mime || ' ' || occurrences || ' ' || \
             flow_id || '/' || seq || ' ' || coalesce(uri, '-') FROM objects \
             WHERE source = 'ftp' ORDER BY sha256",
        ),
    ] {
        let mut stmt = session.conn().prepare(sql).unwrap();
        for row in stmt.query_map([], |r| r.get::<_, String>(0)).unwrap() {
            writeln!(s, "{name} {}", row.unwrap()).unwrap();
        }
    }
    s
}

/// The FTP showcase interleaved with the mixed demo traffic (spread over the shards).
fn traffic() -> Vec<Packet> {
    let mut sc = Scenario::new();
    ftp_showcase(&mut sc);
    let mut packets = generate(Kind::Demo, 8, 7);
    packets.extend(sc.into_packets());
    packets.sort_by_key(|p| p.ts_ns);
    packets
}

#[test]
fn ftp_tables_do_not_depend_on_shards_nor_chunks() {
    let tmp = TempDir::new().unwrap();
    let catalog = Catalog::open(tmp.path().join("data")).unwrap();
    let packets = traffic();
    let single = tmp.path().join("ftp.pcapng");
    write_file(&single, &packets, &Encoding::pcapng()).unwrap();
    let reference = run(&catalog, &single, 1);
    let want = ftp_tables(&catalog, &reference);
    // The 6 sessions of the showcase plus the FTP logins of the demo traffic.
    assert!(
        want.lines().filter(|l| l.starts_with("session ")).count() > 6,
        "{want}"
    );
    assert_eq!(
        want.lines().filter(|l| l.starts_with("object ")).count(),
        3,
        "{want}"
    );
    assert!(
        !want.contains("data=- "),
        "every showcase transfer has its data: {want}"
    );
    for shards in [1, 4, 7] {
        let again = run(&catalog, &single, shards);
        assert_eq!(
            ftp_tables(&catalog, &again),
            want,
            "single file, {shards} shards"
        );
        // Small chunks: control lines, data connections and files cut across chunk borders.
        let dir = tmp.path().join(format!("chunks-{shards}"));
        let opts = SplitOptions::new(SplitBy::Size(4 * 1024), Naming::Dumpcap)
            .with_encoding(Encoding::pcapng());
        let files = split_to_dir(&dir, &packets, &opts).unwrap().1;
        assert!(files.len() > 5);
        let chunked = run(&catalog, &dir, shards);
        assert_eq!(
            ftp_tables(&catalog, &chunked),
            want,
            "chunks, {shards} shards"
        );
    }
}
