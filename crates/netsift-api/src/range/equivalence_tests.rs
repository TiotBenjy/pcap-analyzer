//! The build of a range database derives again, from the records, what the analyzers and the
//! end-of-import steps derive for the whole session (`netsift_store::ranges`: copies of the
//! `server_evidence_source` view, of the `connections` analyzer and of the category counts). Over a
//! range covering imported sessions, every table must equal that of the session.

use std::path::Path;

use netsift_engine::{CancelToken, IngestOptions, ingest};
use netsift_fixtures::packet::Packet;
use netsift_fixtures::scenarios::{Kind, generate};
use netsift_fixtures::{Encoding, encode};
use netsift_store::ranges::{ATTACHED, CancelFlag, RANGE_TABLES, RangeCache};
use netsift_store::{Catalog, Connection, Session, TimeRange};

/// Imports `packets` into a new data directory under `tmp` and opens the session.
fn import(tmp: &Path, packets: &[Packet]) -> Session {
    let capture = tmp.join("capture.pcap");
    std::fs::write(&capture, encode(packets, &Encoding::pcap()).unwrap()).unwrap();
    let catalog = Catalog::open(tmp.join("data")).unwrap();
    let report = ingest(
        &catalog,
        &capture,
        &IngestOptions::default(),
        &CancelToken::new(),
        &mut |_| {},
    )
    .unwrap();
    Session::open_upgrading(catalog.session_dir(&report.session)).unwrap()
}

/// Rows of `table` in `schema`, every column, as sorted JSON arrays (the session `meta` keeps its
/// own step markers, the only expected difference).
fn rows(conn: &Connection, schema: &str, table: &str) -> Vec<String> {
    let columns: Vec<String> = conn
        .prepare(&format!(
            "SELECT name FROM pragma_table_xinfo('{table}', '{schema}')"
        ))
        .unwrap()
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert!(!columns.is_empty(), "{schema}.{table}");
    let filter = if table == "meta" {
        " WHERE key <> 'finalizers'"
    } else {
        ""
    };
    let sql = format!(
        "SELECT json_array({}) FROM {schema}.{table}{filter} ORDER BY 1",
        columns.join(", ")
    );
    conn.prepare(&sql)
        .unwrap()
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

/// Builds the range database of a range covering the session (bounded to its period, so it is
/// built rather than dropped as the API would) and compares every table with the session.
fn assert_rebuilds_the_session(packets: &[Packet]) {
    let tmp = tempfile::tempdir().unwrap();
    let session = import(tmp.path(), packets);
    let dir = tmp.path().join("ranges");
    let view = RangeCache::new()
        .open(
            &session,
            &dir,
            TimeRange::new(i64::MIN / 2, i64::MAX / 2).unwrap(),
            &CancelFlag::new(),
        )
        .unwrap();
    let conn = view.conn();
    let mut compared = 0;
    for table in RANGE_TABLES {
        let (built, imported) = (rows(conn, "main", table), rows(conn, ATTACHED, table));
        assert_eq!(built, imported, "{table}");
        compared += usize::from(!imported.is_empty());
    }
    // The fixtures fill most tables (the scratch table `network_ends` stays empty).
    assert!(compared >= 12, "{compared} tables with rows");
}

/// The demo traffic and the servers showcase (every server role, a relayed DHCP exchange).
#[test]
fn a_covering_range_rebuilds_the_demo_and_servers_sessions() {
    let mut packets = generate(Kind::Demo, 3, 1);
    let start = packets.last().map_or(0, |p| p.ts_ns) + 1_000_000_000;
    let mut sc = netsift_fixtures::Scenario::starting_at(start);
    netsift_fixtures::servers::servers_showcase(&mut sc);
    packets.extend(sc.into_packets());
    assert_rebuilds_the_session(&packets);
}

/// The spread capture: bursts and a connection longer than an hour.
#[test]
fn a_covering_range_rebuilds_the_spread_session() {
    assert_rebuilds_the_session(&netsift_fixtures::spread::spread().packets);
}
