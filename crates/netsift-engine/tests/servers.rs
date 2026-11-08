//! End-to-end imports for the `servers` analyzer and the derived roles: DHCP, NTP and Kerberos
//! tables, DHCP host names in `hosts` and the `server_evidence` view are identical for a single
//! file and for the same traffic split into chunks, whatever the number of shards.

use std::fmt::Write as _;
use std::path::Path;

use netsift_engine::{CancelToken, IngestOptions, IngestReport, ingest};
use netsift_fixtures::scenarios::{Kind, generate};
use netsift_fixtures::servers::servers_showcase;
use netsift_fixtures::{Encoding, Naming, Packet, Scenario, SplitBy, SplitOptions};
use netsift_fixtures::{split_to_dir, write_file};
use netsift_store::{Catalog, OpenMode, SessionState};
use tempfile::TempDir;

/// Demo traffic (DNS, SMB, HTTP...) with the infrastructure exchanges in the middle, twice.
fn traffic() -> Vec<Packet> {
    let mut packets = generate(Kind::Demo, 4, 5);
    for round in 0..2 {
        let start = packets.last().map_or(0, |p| p.ts_ns) + 1_000_000;
        let mut sc = Scenario::starting_at(start).with_seed(round);
        servers_showcase(&mut sc);
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

fn tables(catalog: &Catalog, report: &IngestReport) -> String {
    let session = catalog
        .open_session(&report.session, OpenMode::ReadOnly)
        .unwrap();
    let mut out = String::new();
    for (name, sql) in [
        (
            "dhcp_messages",
            "SELECT ts || ' ' || src_ip || ' -> ' || dst_ip || ' op=' || op || ' ' || \
             coalesce(msg_type, '-') || ' xid=' || xid || ' mac=' || coalesce(client_mac, '-') || \
             ' yiaddr=' || coalesce(yiaddr, '-') || ' server=' || server_ip || ' requested=' || \
             coalesce(requested_ip, '-') || ' mask=' || coalesce(subnet_mask, '-') || ' routers=' \
             || routers || ' dns=' || dns_servers || ' lease=' || coalesce(lease_s, '-') || \
             ' hostname=' || coalesce(hostname, '-') FROM dhcp_messages ORDER BY ts, src_ip",
        ),
        (
            "ntp_responses",
            "SELECT server_ip || ' -> ' || client_ip || ' n=' || responses || ' v' || version || \
             ' stratum=' || stratum || ' ref=' || reference || ' ' || first_ts || '..' || last_ts \
             FROM ntp_responses ORDER BY server_ip, client_ip",
        ),
        (
            "kerberos_replies",
            "SELECT server_ip || ' -> ' || client_ip || ' ' || kind || ' n=' || replies || \
             ' realm=' || coalesce(realm, '-') || ' error=' || coalesce(error_code, '-') || ' ' || \
             first_ts || '..' || last_ts FROM kerberos_replies ORDER BY server_ip, client_ip, kind",
        ),
        (
            "hosts with names",
            "SELECT ip || ' ' || names FROM hosts WHERE names <> '[]' ORDER BY ip",
        ),
        (
            "server_evidence",
            "SELECT role || ' ' || ip || ' ' || kind || ' n=' || count || ' clients=' || \
             coalesce(clients, '-') || ' ' || first_ts || '..' || last_ts || ' ' || \
             coalesce(example, '-') FROM server_evidence ORDER BY role, ip, kind",
        ),
    ] {
        let mut stmt = session.conn().prepare(sql).unwrap();
        let rows: Vec<String> = stmt
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        writeln!(out, "# {name} ({} rows)", rows.len()).unwrap();
        for r in rows {
            writeln!(out, "{r}").unwrap();
        }
    }
    out
}

#[test]
fn servers_tables_do_not_depend_on_chunking_nor_shards() {
    let tmp = TempDir::new().unwrap();
    let catalog = Catalog::open(tmp.path().join("data")).unwrap();
    let packets = traffic();
    let single = tmp.path().join("single.pcapng");
    write_file(&single, &packets, &Encoding::pcapng()).unwrap();
    let expected = tables(&catalog, &run(&catalog, &single, 1));
    insta::assert_snapshot!(expected);
    assert_eq!(
        tables(&catalog, &run(&catalog, &single, 4)),
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
            tables(&catalog, &run(&catalog, &dir, shards)),
            expected,
            "chunks, {shards} shards"
        );
    }
}
