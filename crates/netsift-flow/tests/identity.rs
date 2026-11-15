//! Flow identity: every flow instance gets its own id, the global index of the frame that
//! created it, even when several instances share the 5-tuple and the first timestamp
//! (docs/DECISIONS.md, ADR-022).

mod common;

use std::collections::{BTreeMap, BTreeSet};

use common::{Event, MS, Recorder, feed, run, timed};
use netsift_dissect::decode;
use netsift_fixtures::Packet;
use netsift_fixtures::craft::{Side, TcpConv, packet, udp_frame};
use netsift_fixtures::scenarios::hosts;
use netsift_flow::{
    Direction, EndReason, FlowConfig, FlowCtx, FlowId, FlowTable, TcpState, shard_hash,
};
use proptest::collection::vec;
use proptest::prelude::*;

/// Constant timestamp of the hostile captures below.
const T: i64 = 1_700_000_000_000_000_000;

fn conv(cport: u16) -> TcpConv {
    TcpConv::new(hosts::workstation(), hosts::web_server(), cport, 80)
}

/// Full connection: handshake, one request, one response, FIN both ways, last ACK.
fn connection(c: &TcpConv, request: &[u8], response: &[u8]) -> Vec<Vec<u8>> {
    let (q, r) = (request.len() as u64, response.len() as u64);
    vec![
        c.syn(),
        c.syn_ack(),
        c.ack(Side::Client, 0, 0),
        c.data(Side::Client, 0, 0, request),
        c.data(Side::Server, 0, q, response),
        c.fin(Side::Client, q, r),
        c.fin(Side::Server, r, q + 1),
        c.ack(Side::Client, q + 1, r + 1),
    ]
}

/// Checks the identity invariants: ids are unique among ended flows, every flow seen in
/// packets ended, and each id is the frame of the first packet of its flow.
fn assert_ids_are_first_frames(rec: &Recorder) {
    rec.assert_ends_once();
    let mut first: BTreeMap<FlowId, u64> = BTreeMap::new();
    for e in &rec.events {
        if let Event::Packet { ctx, .. } = e
            && let Some(f) = ctx.flow
        {
            first.entry(f.id).or_insert(ctx.frame);
        }
    }
    for (id, frame) in &first {
        assert_eq!(
            *id,
            FlowId::from_first_frame(*frame),
            "first frame of {id:?}"
        );
    }
    let ended: BTreeSet<FlowId> = rec.ends().iter().map(|c| c.id).collect();
    assert_eq!(ended.len(), rec.ends().len(), "duplicate flow ids");
    assert_eq!(ended, first.keys().copied().collect::<BTreeSet<_>>());
}

fn wire(frames: &[Vec<u8>]) -> u64 {
    frames.iter().map(|f| f.len() as u64).sum()
}

#[test]
fn a_reopened_connection_at_the_same_time_gets_its_own_id_and_counters() {
    let c = conv(40_000);
    let first = connection(&c, b"GET /one HTTP/1.1\r\n\r\n", b"HTTP/1.1 204 A\r\n\r\n");
    // Same 5-tuple, same ISNs, same timestamp: only the frame index tells them apart.
    let second = connection(&c, b"GET /two HTTP/1.1\r\n\r\n", b"HTTP/1.1 204 BB\r\n\r\n");
    let mut frames = first.clone();
    frames.extend(second.iter().cloned());
    let rec = run(&timed(frames, T, 0), FlowConfig::default());
    assert_ids_are_first_frames(&rec);

    let ends = rec.ends();
    assert_eq!(ends.len(), 2);
    let (a, b) = (ends[0], ends[1]);
    assert_eq!(a.key, b.key);
    assert_eq!((a.first_ts_ns, b.first_ts_ns), (T, T));
    assert_eq!(a.id, FlowId(0));
    assert_eq!(b.id, FlowId::from_first_frame(first.len() as u64));
    assert_eq!(a.end, EndReason::Closed);
    assert_eq!(b.tcp_state, Some(TcpState::Closed));
    for (ctx, frames) in [(a, &first), (b, &second)] {
        // 5 client frames, 3 server frames, wire bytes split accordingly.
        let to_server: Vec<_> = [0, 2, 3, 5, 7].map(|i| frames[i].clone()).into();
        let to_client: Vec<_> = [1, 4, 6].map(|i| frames[i].clone()).into();
        assert_eq!(ctx.to_server.packets, 5);
        assert_eq!(ctx.to_client.packets, 3);
        assert_eq!(ctx.to_server.bytes, wire(&to_server));
        assert_eq!(ctx.to_client.bytes, wire(&to_client));
    }
    assert_eq!(
        rec.stream(a.id, Direction::ToServer).0,
        b"GET /one HTTP/1.1\r\n\r\n"
    );
    assert_eq!(
        rec.stream(b.id, Direction::ToServer).0,
        b"GET /two HTTP/1.1\r\n\r\n"
    );
}

#[test]
fn an_evicted_flow_resumed_at_the_same_time_gets_a_new_id() {
    let config = FlowConfig {
        max_flows: 1,
        ..FlowConfig::default()
    };
    let x = conv(40_000);
    let y = conv(40_001);
    let frames = vec![
        x.syn(),
        x.syn_ack(),
        x.ack(Side::Client, 0, 0),
        x.data(Side::Client, 0, 0, b"first"),
        // Another connection between the same hosts evicts x...
        y.syn(),
        // ... which resumes from its client: a midstream flow with the same oriented key.
        x.data(Side::Client, 5, 0, b"second"),
    ];
    let rec = run(&timed(frames, T, 0), config);
    assert_ids_are_first_frames(&rec);
    let ends = rec.ends();
    assert_eq!(
        ends.iter().map(|e| (e.id, e.end)).collect::<Vec<_>>(),
        vec![
            (FlowId(0), EndReason::Evicted),
            (FlowId(4), EndReason::Evicted),
            (FlowId(5), EndReason::EndOfCapture),
        ]
    );
    let (before, after) = (ends[0], ends[2]);
    assert_eq!(before.key, after.key);
    assert_eq!(before.first_ts_ns, after.first_ts_ns);
    assert_eq!(after.tcp_state, Some(TcpState::Midstream));
    assert_eq!((before.to_server.packets, after.to_server.packets), (3, 1));
    assert_eq!(rec.stream(after.id, Direction::ToServer).0, b"second");
}

/// Reopened connections and DNS exchanges between several host pairs, interleaved, at one
/// timestamp.
fn mixed_constant_time_traffic() -> Vec<Packet> {
    let mut frames = Vec::new();
    for round in 0..3u8 {
        for (i, client) in [hosts::workstation(), hosts::file_server()]
            .iter()
            .enumerate()
        {
            let c = TcpConv::new(*client, hosts::web_server(), 40_000, 80);
            frames.extend(connection(&c, &[b'q'; 7], &vec![round; 30 + i]));
            let (dns, dport) = (hosts::router(), 53);
            frames.push(udp_frame(client, &dns, 5353, dport, b"query"));
            frames.push(udp_frame(&dns, client, dport, 5353, b"answer"));
        }
    }
    timed(frames, T, 0)
}

fn run_on_tables(packets: &[Packet], n: u64) -> Vec<FlowCtx> {
    let mut tables: Vec<FlowTable> = (0..n)
        .map(|_| FlowTable::new(FlowConfig::default()))
        .collect();
    let mut rec = Recorder::default();
    for (frame, p) in (0u64..).zip(packets) {
        let shard = shard_hash(&decode(p.linktype, &p.data)) % n;
        let len = u32::try_from(p.data.len()).unwrap();
        tables[usize::try_from(shard).unwrap()]
            .process(p.ts_ns, 0, frame, p.linktype, len, &p.data, &mut rec);
    }
    for t in &mut tables {
        t.finish_at(T, &mut rec);
    }
    assert_ids_are_first_frames(&rec);
    let mut ends = rec.ends();
    ends.sort_by_key(|c| c.id);
    ends
}

#[test]
fn ids_do_not_depend_on_the_number_of_tables() {
    let packets = mixed_constant_time_traffic();
    let reference = run_on_tables(&packets, 1);
    // 2 clients x 3 reopened TCP connections, plus one DNS flow per client (UDP flows only
    // end on timeout, which constant time never reaches).
    assert_eq!(reference.len(), 8);
    for n in [2, 3, 4, 7] {
        assert_eq!(run_on_tables(&packets, n), reference, "{n} tables");
    }
}

/// Hostile TCP frame on one of three tuples between two hosts: (tuple, kind, ISN seed).
fn hostile_frame() -> impl Strategy<Value = (u16, u8, u32)> {
    (0u16..3, 0u8..7, any::<u32>())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn constant_time_hostile_traffic_never_reuses_an_id(
        frames in vec(hostile_frame(), 0..80),
        max_flows in 1usize..4,
        step_back in prop::bool::ANY,
    ) {
        let config = FlowConfig { max_flows, ..FlowConfig::default() };
        let mut table = FlowTable::new(config);
        let mut rec = Recorder::default();
        let packets: Vec<Packet> = frames
            .iter()
            .enumerate()
            .map(|(i, &(tuple, kind, isn))| {
                let c = conv(40_000 + tuple).with_isns(isn, isn.rotate_left(7));
                let data = match kind {
                    0 => c.syn(),
                    1 => c.syn_ack(),
                    2 => c.data(Side::Client, 0, 0, b"x"),
                    3 => c.data(Side::Server, 0, 0, b"y"),
                    4 => c.fin(Side::Client, 0, 0),
                    5 => c.rst(Side::Server, 0),
                    _ => c.ack(Side::Client, 0, 0),
                };
                // Constant time, optionally with small backward steps.
                let ts = if step_back && i % 3 == 1 { T - MS } else { T };
                packet(ts, data)
            })
            .collect();
        feed(&mut table, &packets, &mut rec);
        table.finish(&mut rec);
        prop_assert_eq!(table.active_flows(), 0);
        assert_ids_are_first_frames(&rec);
    }
}
