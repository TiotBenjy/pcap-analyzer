//! End-to-end imports for the `connections` and `ports` analyzers: their tables
//! (`conversations`, `host_traffic`, `open_ports`) are identical for a single file and for the
//! same traffic split into chunks, whatever the number of shards.

use std::fmt::Write as _;
use std::path::Path;

use netsift_engine::{CancelToken, IngestOptions, IngestReport, ingest};
use netsift_fixtures::craft::{Side, TcpConv, TcpSeg};
use netsift_fixtures::scenarios::{Kind, generate, hosts};
use netsift_fixtures::{Encoding, Host, Naming, Packet, Scenario, SplitBy, SplitOptions};
use netsift_fixtures::{split_to_dir, write_file};
use netsift_store::{Catalog, OpenMode, SessionState};
use tempfile::TempDir;

/// Demo traffic plus a SYN scan of one host (80 and 443 open, 22 and 8080 closed).
fn traffic() -> Vec<Packet> {
    let mut packets = generate(Kind::Demo, 6, 3);
    let start = packets.last().map_or(0, |p| p.ts_ns) + 1_000_000;
    let mut sc = Scenario::starting_at(start);
    let target = Host::v4([0x02, 0, 0x5e, 0x10, 0, 0x50], [192, 168, 1, 50]);
    for (i, port) in [80_u16, 443, 22, 8080].into_iter().enumerate() {
        let conv = TcpConv::new(
            hosts::workstation(),
            target,
            41_000 + u16::try_from(i).unwrap(),
            port,
        );
        sc.push_frame(conv.syn());
        if port == 80 || port == 443 {
            sc.push_frame(conv.syn_ack());
            sc.push_frame(conv.rst(Side::Client, 0));
        } else {
            let rst = TcpSeg::new(0).rst().ack(conv.seq(Side::Client, 0));
            sc.push_frame(conv.frame(Side::Server, &rst, &[]));
        }
    }
    packets.extend(sc.into_packets());
    packets
}

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

fn tables(catalog: &Catalog, report: &IngestReport) -> String {
    let session = catalog
        .open_session(&report.session, OpenMode::ReadOnly)
        .unwrap();
    let mut out = String::new();
    for (name, sql) in [
        (
            "conversations",
            "SELECT src_ip || ' -> ' || dst_ip || ' ' || first_ts || '..' || last_ts || \
             ' bytes=' || bytes_fwd || '/' || bytes_rev || ' packets=' || packets_fwd || '/' || \
             packets_rev || ' flows=' || flows || ' dns=' || dns_bytes_fwd || '/' || \
             dns_bytes_rev || '/' || dns_flows || ' ' || protocols \
             FROM conversations ORDER BY src_ip, dst_ip",
        ),
        (
            "host_traffic",
            "SELECT ip || ' sent=' || bytes_sent || '/' || packets_sent || ' received=' || \
             bytes_received || '/' || packets_received FROM host_traffic ORDER BY ip",
        ),
        (
            "open_ports",
            "SELECT ip || ' ' || transport || '/' || port || ' ' || evidence || ' service=' || \
             coalesce(service, '-') || ' detected=' || coalesce(detected, '-') || ' banner=' || \
             coalesce(banner, '-') || ' ' || first_ts || '..' || last_ts \
             FROM open_ports ORDER BY ip, transport, port",
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
fn tables_are_the_same_for_a_file_and_its_chunks_whatever_the_shards() {
    let tmp = TempDir::new().unwrap();
    let catalog = Catalog::open(tmp.path().join("data")).unwrap();
    let packets = traffic();
    let single = tmp.path().join("single.pcapng");
    write_file(&single, &packets, &Encoding::pcapng()).unwrap();
    let expected = tables(&catalog, &run(&catalog, &single, 3));
    insta::assert_snapshot!(expected);

    for shards in [1, 4, 7] {
        assert_eq!(
            tables(&catalog, &run(&catalog, &single, shards)),
            expected,
            "single file, {shards} shards"
        );
    }
    let dir = tmp.path().join("chunks");
    let opts = SplitOptions::new(SplitBy::Size(16 * 1024), Naming::Dumpcap)
        .with_encodings(vec![Encoding::pcapng()]);
    let files = split_to_dir(&dir, &packets, &opts).unwrap().1;
    assert!(files.len() > 3);
    for shards in [1, 5] {
        assert_eq!(
            tables(&catalog, &run(&catalog, &dir, shards)),
            expected,
            "chunks, {shards} shards"
        );
    }
}
