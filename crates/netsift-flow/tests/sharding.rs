//! The split of traffic into flows does not depend on how flows are spread over tables
//! (number of shards): same multiset of `FlowCtx`, same reassembled streams, same packet
//! attribution. Periodic sweeps run at different moments in each table, which must not matter.

mod common;

use std::collections::BTreeMap;

use common::{Event, Recorder, S};
use netsift_dissect::decode;
use netsift_fixtures::Packet;
use netsift_fixtures::scenario::{Scenario, TcpOptions};
use netsift_fixtures::scenarios::{self, Kind, hosts};
use netsift_flow::{Direction, FlowConfig, FlowTable, shard_hash};

/// Short timeouts so that flows time out and reopen during the capture.
fn config() -> FlowConfig {
    FlowConfig {
        tcp_timeout_ns: 4 * S,
        udp_timeout_ns: 2 * S,
        other_timeout_ns: S,
        defrag_timeout_ns: S,
        ..FlowConfig::default()
    }
}

/// Mixed traffic with idle periods shorter and longer than the timeouts, recurring tuples
/// (a UDP keepalive, a TCP client port reused with new ISNs) and IP fragments.
fn traffic() -> Vec<Packet> {
    let idles_ms = [
        300, 2_500, 800, 6_000, 1_900, 4_500, 100, 9_000, 2_100, 700, 3_000, 5_200,
    ];
    let mut sc = Scenario::new().with_seed(42);
    for (round, idle) in idles_ms.iter().enumerate() {
        let kind = Kind::ALL[round % Kind::ALL.len()];
        kind.append_to(&mut sc);
        sc.udp(
            hosts::workstation(),
            hosts::router(),
            5555,
            7777,
            b"keepalive",
        );
        let opts = TcpOptions {
            client_port: Some(41_000),
            ..TcpOptions::new(8080)
        };
        let mut s = sc.tcp_open(hosts::workstation(), hosts::web_server(), &opts);
        s.client_send(format!("round {round}").as_bytes());
        if round % 3 == 0 {
            s.close();
        }
        sc.advance(idle * 1_000_000);
    }
    let mut packets = sc.into_packets();
    // Small backward steps (well below the sweep grace), as in real captures.
    for (i, p) in packets.iter_mut().enumerate() {
        if i % 7 == 3 {
            p.ts_ns -= 3_000_000;
        }
    }
    let frag = scenarios::fragmentation().0.into_packets();
    let shift = packets.last().map_or(0, |p| p.ts_ns) + 1_500_000_000 - frag[0].ts_ns;
    packets.extend(frag.into_iter().map(|mut p| {
        p.ts_ns += shift;
        p
    }));
    packets
}

/// Comparable view of a run: sorted flow summaries, streams by flow and direction, and the
/// sorted packet attributions.
type Streams = BTreeMap<(i64, bool), Vec<(u64, Vec<u8>)>>;
type View = (Vec<String>, Streams, Vec<String>);

fn view(rec: &Recorder) -> View {
    let mut ends: Vec<String> = rec.ends().iter().map(|c| format!("{c:?}")).collect();
    ends.sort();
    let mut streams = Streams::new();
    let mut packets = Vec::new();
    for e in &rec.events {
        match e {
            Event::Stream { ctx, dir, data } => streams
                .entry((ctx.id.0, *dir == Direction::ToServer))
                .or_default()
                .push((ctx.gap_before, data.clone())),
            Event::Packet { ctx, summary, .. } => packets.push(format!("{ctx:?} {summary}")),
            Event::End(_) => {}
        }
    }
    packets.sort();
    (ends, streams, packets)
}

/// Runs `packets` over `n` tables, routing each frame with `route(shard_hash) % n`.
fn run_sharded(packets: &[Packet], n: u64, route: impl Fn(u64) -> u64) -> Recorder {
    let mut tables: Vec<FlowTable> = (0..n).map(|_| FlowTable::new(config())).collect();
    let mut rec = Recorder::default();
    for (frame, p) in (0u64..).zip(packets) {
        let shard = route(shard_hash(&decode(p.linktype, &p.data))) % n;
        let len = u32::try_from(p.data.len()).unwrap();
        tables[usize::try_from(shard).unwrap()]
            .process(p.ts_ns, 0, frame, p.linktype, len, &p.data, &mut rec);
    }
    let end = packets.iter().map(|p| p.ts_ns).max().unwrap_or(0);
    for t in &mut tables {
        t.finish_at(end, &mut rec);
    }
    rec.assert_ends_once();
    rec
}

#[test]
fn flows_do_not_depend_on_the_number_of_tables() {
    let packets = traffic();
    let single = run_sharded(&packets, 1, |h| h);
    let reference = view(&single);
    // Sanity: the traffic exercises timeouts, port reuse and reassembled datagrams.
    let ends = single.ends();
    assert!(
        ends.iter()
            .any(|c| c.end == netsift_flow::EndReason::Timeout)
    );
    assert!(
        ends.iter()
            .any(|c| c.end == netsift_flow::EndReason::Closed)
    );
    assert!(ends.len() > 30, "{} flows", ends.len());
    for n in [2, 4, 7] {
        let rec = run_sharded(&packets, n, |h| h);
        assert_eq!(view(&rec), reference, "{n} tables");
    }
    // Another spread: odd / even hashes.
    let rec = run_sharded(&packets, 2, |h| h.count_ones().into());
    assert_eq!(view(&rec), reference, "parity split");
}
