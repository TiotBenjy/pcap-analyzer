//! End-to-end imports for the `ethernet` analyzer: its tables (`eth_macs`, `eth_pairs`,
//! `eth_types`, `eth_vlans`) are identical for a single file and for the same traffic split into
//! chunks, whatever the number of shards and the batch sizes, including the bounded sets of an
//! address on a trunk of more VLANs than a set keeps.

use std::fmt::Write as _;
use std::path::Path;

use netsift_engine::{CancelToken, IngestOptions, IngestReport, ingest};
use netsift_fixtures::ethernet::{self as fx, ethernet_showcase, macs};
use netsift_fixtures::scenarios::{Kind, generate};
use netsift_fixtures::{Encoding, Naming, Packet, Scenario, SplitBy, SplitOptions};
use netsift_fixtures::{split_to_dir, write_file};
use netsift_store::{Catalog, OpenMode, SessionState};
use tempfile::TempDir;

/// VLANs of the trunk: more than the 16 kept per address and per pair.
const TRUNK_VLANS: u16 = 40;

/// Demo traffic, three rounds of the link-layer showcase, and a router on a trunk of 40 VLANs
/// in a mixed order (one UDP flow per VLAN, so that the frames reach different shards).
fn traffic() -> Vec<Packet> {
    let mut packets = generate(Kind::Demo, 4, 5);
    let start = packets.last().map_or(0, |p| p.ts_ns) + 1_000_000;
    let mut sc = Scenario::starting_at(start);
    for _ in 0..3 {
        ethernet_showcase(&mut sc);
        sc.advance(2_000_000_000);
    }
    for round in 0..2u16 {
        for i in 0..TRUNK_VLANS {
            let vid = (i * 37 + round * 11) % 400 + 1;
            let udp = fx::ipv4_udp([10, 9, 0, 1], [10, 9, 0, 2], 41_000 + i, 9, b"trunk");
            sc.push_frame(fx::frame(
                macs::RASPBERRY,
                macs::SWITCH,
                &[(fx::TPID_8021Q, vid)],
                0x0800,
                &udp,
            ));
        }
    }
    packets.extend(sc.into_packets());
    packets
}

fn run(catalog: &Catalog, input: &Path, options: &IngestOptions) -> IngestReport {
    let report = ingest(catalog, input, options, &CancelToken::new(), &mut |_| {}).unwrap();
    assert_eq!(report.state, SessionState::Ready);
    report
}

fn shards(n: usize) -> IngestOptions {
    IngestOptions {
        shards: Some(n),
        ..IngestOptions::default()
    }
}

fn tables(catalog: &Catalog, report: &IngestReport) -> String {
    let session = catalog
        .open_session(&report.session, OpenMode::ReadOnly)
        .unwrap();
    let mut out = String::new();
    for (name, sql) in [
        (
            "eth_macs",
            "SELECT mac || ' ' || coalesce(vendor, '-') || ' ' || coalesce(registry, '-') || ' ' || \
             kind || ' local=' || local || ' ' || coalesce(grp, '-') || ' sent=' || frames_sent || \
             '/' || bytes_sent || ' received=' || frames_received || '/' || bytes_received || ' ' || \
             first_ts || '..' || last_ts || ' ' || vlans FROM eth_macs ORDER BY mac",
        ),
        (
            "eth_pairs",
            "SELECT src_mac || ' -> ' || dst_mac || ' ' || frames || '/' || bytes || ' ' || \
             first_ts || '..' || last_ts || ' ' || ethertypes || ' ' || vlans \
             FROM eth_pairs ORDER BY src_mac, dst_mac",
        ),
        (
            "eth_types",
            "SELECT ethertype || ' ' || frames || '/' || bytes || ' ' || first_ts || '..' || last_ts \
             FROM eth_types ORDER BY ethertype",
        ),
        (
            "eth_vlans",
            "SELECT stack || ' ' || outer_id || ' ' || inner_id || ' ' || depth || ' ' || \
             outer_tpid || ' ' || frames || '/' || bytes || ' ' || first_ts || '..' || last_ts \
             FROM eth_vlans ORDER BY stack",
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
    let expected = tables(&catalog, &run(&catalog, &single, &shards(3)));
    // The trunk address keeps 16 VLAN stacks, the smallest in text order.
    let mut labels: Vec<String> = (0..2u16)
        .flat_map(|round| {
            (0..TRUNK_VLANS).map(move |i| ((i * 37 + round * 11) % 400 + 1).to_string())
        })
        .collect();
    labels.sort();
    labels.dedup();
    assert!(labels.len() > 16);
    labels.truncate(16);
    let kept = format!("[\"{}\"]", labels.join("\",\""));
    let switch = expected
        .lines()
        .find(|l| l.starts_with("00:00:0c:9f:f0:01"))
        .unwrap();
    assert!(switch.ends_with(&kept), "{switch}");
    insta::assert_snapshot!(expected);

    for n in [1, 4, 7] {
        assert_eq!(
            tables(&catalog, &run(&catalog, &single, &shards(n))),
            expected,
            "single file, {n} shards"
        );
    }
    let small_batches = IngestOptions {
        shards: Some(7),
        batch_packets: 3,
        channel_batches: 1,
        record_batch: 1,
        ..IngestOptions::default()
    };
    assert_eq!(
        tables(&catalog, &run(&catalog, &single, &small_batches)),
        expected,
        "small batches"
    );
    let dir = tmp.path().join("chunks");
    let opts = SplitOptions::new(SplitBy::Size(16 * 1024), Naming::Dumpcap)
        .with_encodings(vec![Encoding::pcapng()]);
    let files = split_to_dir(&dir, &packets, &opts).unwrap().1;
    assert!(files.len() > 3);
    for n in [1, 5] {
        assert_eq!(
            tables(&catalog, &run(&catalog, &dir, &shards(n))),
            expected,
            "chunks, {n} shards"
        );
    }
}
