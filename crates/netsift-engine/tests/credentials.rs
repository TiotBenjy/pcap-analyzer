//! End-to-end imports of the credential emitters (`smb`, `http`, `credentials` analyzers): the
//! `credentials` table is identical for a single file and for the same traffic split into chunks,
//! whatever the number of shards, and repeated observations fold into one row per credential.

use std::fmt::Write as _;
use std::path::Path;

use netsift_engine::{CancelToken, IngestOptions, IngestReport, ingest};
use netsift_fixtures::credentials::credentials_showcase;
use netsift_fixtures::scenarios::{Kind, generate};
use netsift_fixtures::{Encoding, Naming, Packet, Scenario, SplitBy, SplitOptions};
use netsift_fixtures::{split_to_dir, write_file};
use netsift_store::{Catalog, OpenMode, SessionState};
use tempfile::TempDir;

/// Demo rounds (FTP, SNMP each round) and the credentials showcase, twice.
fn traffic() -> Vec<Packet> {
    let mut packets = generate(Kind::Demo, 3, 9);
    for round in 0..2 {
        let start = packets.last().map_or(0, |p| p.ts_ns) + 1_000_000;
        let mut sc = Scenario::starting_at(start).with_seed(round);
        credentials_showcase(&mut sc);
        packets.extend(sc.into_packets());
    }
    packets
}

fn run(catalog: &Catalog, input: &Path, shards: usize) -> IngestReport {
    let options = IngestOptions {
        shards: Some(shards),
        ..IngestOptions::default()
    };
    let report = ingest(catalog, input, &options, &CancelToken::new(), &mut |_| {}).unwrap();
    assert_eq!(report.state, SessionState::Ready);
    report
}

fn table(catalog: &Catalog, report: &IngestReport) -> String {
    let session = catalog
        .open_session(&report.session, OpenMode::ReadOnly)
        .unwrap();
    let mut stmt = session
        .conn()
        .prepare(
            "SELECT protocol || '/' || kind || ' ' || coalesce(client_ip, '-') || ' -> ' || \
             coalesce(server_ip, '-') || ':' || coalesce(server_port, '-') || ' user=' || \
             coalesce(username, '-') || ' domain=' || coalesce(domain, '-') || ' ' || \
             secret_state || ' secret=' || coalesce(secret, '-') || ' mode=' || \
             coalesce(hashcat_mode, '-') || ' n=' || seen_count || ' ' || details \
             FROM credentials ORDER BY first_ts, fingerprint",
        )
        .unwrap();
    let rows: Vec<String> = stmt
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    let mut out = String::new();
    writeln!(out, "# credentials ({} rows)", rows.len()).unwrap();
    for r in rows {
        writeln!(out, "{r}").unwrap();
    }
    out
}

#[test]
fn credentials_do_not_depend_on_chunking_nor_shards() {
    let tmp = TempDir::new().unwrap();
    let catalog = Catalog::open(tmp.path().join("data")).unwrap();
    let packets = traffic();
    let single = tmp.path().join("single.pcapng");
    write_file(&single, &packets, &Encoding::pcapng()).unwrap();
    let expected = table(&catalog, &run(&catalog, &single, 1));
    insta::assert_snapshot!(expected);
    assert_eq!(
        table(&catalog, &run(&catalog, &single, 4)),
        expected,
        "single file, 4 shards"
    );
    let dir = tmp.path().join("chunks");
    let opts = SplitOptions::new(SplitBy::Size(8 * 1024), Naming::Dumpcap)
        .with_encodings(vec![Encoding::pcapng()]);
    let files = split_to_dir(&dir, &packets, &opts).unwrap().1;
    assert!(files.len() > 3);
    for shards in [1, 4] {
        assert_eq!(
            table(&catalog, &run(&catalog, &dir, shards)),
            expected,
            "chunks, {shards} shards"
        );
    }
}

#[test]
fn ftp_http_basic_and_snmp_give_three_entries() {
    // Acceptance fixture of the spec: one FTP USER/PASS, one HTTP Basic, one SNMP community.
    let mut sc = Scenario::new();
    let ws = netsift_fixtures::scenarios::hosts::workstation();
    sc.ftp_login(
        ws,
        netsift_fixtures::scenarios::hosts::ftp_server(),
        &netsift_fixtures::scenario::FtpLogin::default(),
    );
    netsift_fixtures::credentials::http_basic(
        &mut sc,
        ws,
        netsift_fixtures::credentials::credential_hosts::intranet(),
        "admin",
        "basic-fixture",
        false,
    );
    sc.snmp_get(
        ws,
        netsift_fixtures::scenarios::hosts::router(),
        &netsift_fixtures::scenario::SnmpGet::default(),
    );
    let tmp = TempDir::new().unwrap();
    let catalog = Catalog::open(tmp.path().join("data")).unwrap();
    let file = tmp.path().join("three.pcap");
    write_file(&file, sc.packets(), &Encoding::pcap()).unwrap();
    let report = run(&catalog, &file, 2);
    let session = catalog
        .open_session(&report.session, OpenMode::ReadOnly)
        .unwrap();
    let mut stmt = session
        .conn()
        .prepare("SELECT protocol, secret, seen_count FROM credentials ORDER BY first_ts")
        .unwrap();
    let rows: Vec<(String, String, i64)> = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(
        rows,
        vec![
            ("ftp".to_owned(), "s3cret-fixture".to_owned(), 1),
            ("http".to_owned(), "basic-fixture".to_owned(), 1),
            // The request and the response carry the same community: one entry, seen twice.
            ("snmp".to_owned(), "public".to_owned(), 2),
        ]
    );
}
