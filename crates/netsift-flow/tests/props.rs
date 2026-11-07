//! Property tests: reassembly is order-independent within the buffer, hostile frames never
//! panic, and the sink sees the same calls for the same input.

mod common;

use common::{MS, Recorder, run, timed};
use netsift_fixtures::Packet;
use netsift_fixtures::craft::{Side, TcpConv, packet};
use netsift_fixtures::scenarios::{self, Kind, hosts};
use netsift_flow::{Direction, FlowConfig, FlowTable};
use proptest::collection::vec;
use proptest::prelude::*;

/// Data, its segmentation (start, end), and a delivery order of the segments (with extra
/// overlapping segments and duplicates).
fn segmented() -> impl Strategy<Value = (Vec<u8>, u32, Vec<(usize, usize)>)> {
    (
        vec(any::<u8>(), 1..3000),
        vec(1usize..400, 1..40),
        vec((any::<prop::sample::Index>(), 1usize..500), 0..10),
        // Half of the cases start right before the sequence number wraps to zero.
        prop_oneof![any::<u32>(), (u32::MAX - 4000)..=u32::MAX],
    )
        .prop_flat_map(|(data, cuts, extra, isn)| {
            let mut segs = Vec::new();
            let mut start = 0;
            let mut cut = cuts.iter().cycle();
            while start < data.len() {
                let end = (start + cut.next().copied().unwrap_or(1)).min(data.len());
                segs.push((start, end));
                start = end;
            }
            for (at, len) in extra {
                let s = at.index(data.len());
                segs.push((s, (s + len).min(data.len())));
            }
            (Just(data), Just(isn), Just(segs).prop_shuffle())
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn any_order_within_the_buffer_gives_the_same_stream((data, isn, segs) in segmented()) {
        let c = TcpConv::new(hosts::workstation(), hosts::web_server(), 40_000, 80)
            .with_isns(isn, isn.wrapping_mul(7));
        let mut frames = vec![c.syn(), c.syn_ack(), c.ack(Side::Client, 0, 0)];
        for &(s, e) in &segs {
            frames.push(c.data(Side::Client, s as u64, 0, &data[s..e]));
        }
        let rec = run(&timed(frames, 0, MS), FlowConfig::default());
        let (stream, gaps) = rec.stream(rec.single_flow().id, Direction::ToServer);
        prop_assert!(gaps.is_empty());
        prop_assert_eq!(stream, data);
    }

    #[test]
    fn small_buffer_delivers_each_byte_at_most_once_in_order(
        (data, isn, segs) in segmented(),
        drops in vec(any::<prop::sample::Index>(), 0..6),
        max_stream_buffer in 0usize..2000,
    ) {
        let c = TcpConv::new(hosts::workstation(), hosts::web_server(), 40_000, 80)
            .with_isns(isn, 1);
        let dropped: Vec<usize> = drops.iter().map(|d| d.index(segs.len())).collect();
        let mut frames = vec![c.syn(), c.syn_ack(), c.ack(Side::Client, 0, 0)];
        for (i, &(s, e)) in segs.iter().enumerate() {
            // Lose some segments, never one that carries the last byte.
            if e < data.len() && dropped.contains(&i) {
                continue;
            }
            frames.push(c.data(Side::Client, s as u64, 0, &data[s..e]));
        }
        let config = FlowConfig { max_stream_buffer, ..FlowConfig::default() };
        let rec = run(&timed(frames, 0, MS), config);
        let id = rec.single_flow().id;
        let mut off = 0usize;
        for e in &rec.events {
            if let common::Event::Stream { ctx, dir, data: bytes } = e {
                prop_assert_eq!(ctx.id, id);
                prop_assert_eq!(*dir, Direction::ToServer);
                off += usize::try_from(ctx.gap_before).unwrap();
                prop_assert!(!bytes.is_empty());
                prop_assert_eq!(&data[off..off + bytes.len()], bytes.as_slice());
                off += bytes.len();
            }
        }
        // Delivered bytes plus gaps cover the whole stream.
        prop_assert_eq!(off, data.len());
    }

    #[test]
    fn arbitrary_frames_never_panic(
        frames in vec(
            (
                prop::sample::select(vec![0u32, 1, 101, 105, 113, 127, 228, 229, 276, 999]),
                vec(any::<u8>(), 0..200),
                -2_000_000_000i64..2_000_000_000,
            ),
            0..60,
        ),
    ) {
        let config = tiny_config();
        let mut table = FlowTable::new(config);
        let mut rec = Recorder::default();
        let mut ts = 1_700_000_000_000_000_000i64;
        for (i, (linktype, data, step)) in frames.iter().enumerate() {
            ts = ts.saturating_add(*step);
            table.process(ts, 0, i as u64, *linktype, u32::try_from(data.len()).unwrap(), data, &mut rec);
        }
        table.finish(&mut rec);
        prop_assert_eq!(table.active_flows(), 0);
        rec.assert_ends_once();
    }

    #[test]
    fn mutated_traffic_never_panics_and_is_deterministic(
        flips in vec((any::<prop::sample::Index>(), any::<prop::sample::Index>(), any::<u8>()), 0..200),
        drops in vec(any::<prop::sample::Index>(), 0..20),
        jitter in vec(-3_000_000_000i64..3_000_000_000, 0..20),
    ) {
        let mut packets = base_traffic();
        for (p, b, v) in flips {
            let pkt = p.get_mut(&mut packets);
            if !pkt.data.is_empty() {
                *b.get_mut(&mut pkt.data) ^= v;
            }
        }
        for (i, j) in jitter.into_iter().enumerate() {
            let n = packets.len();
            packets[(i * 37) % n].ts_ns += j;
        }
        for d in drops {
            if !packets.is_empty() {
                let i = d.index(packets.len());
                packets.remove(i);
            }
        }
        let a = run(&packets, tiny_config());
        let b = run(&packets, tiny_config());
        prop_assert_eq!(a, b);
    }
}

fn tiny_config() -> FlowConfig {
    FlowConfig {
        tcp_timeout_ns: 2_000_000_000,
        udp_timeout_ns: 1_000_000_000,
        other_timeout_ns: 500_000_000,
        max_flows: 8,
        max_stream_buffer: 512,
        defrag_timeout_ns: 1_000_000_000,
        max_defrag_bytes: 4096,
    }
}

/// Mixed traffic: every scenario kind plus the fragmentation scenario.
fn base_traffic() -> Vec<Packet> {
    let mut packets = scenarios::generate(Kind::Demo, 1, 5);
    let frag = scenarios::fragmentation().0.into_packets();
    let shift = packets.last().map_or(0, |p| p.ts_ns) + MS - frag[0].ts_ns;
    packets.extend(frag.into_iter().map(|mut p| {
        p.ts_ns += shift;
        p
    }));
    packets
}

#[test]
fn same_input_same_calls_whatever_the_hash_seed() {
    let mut packets = Vec::new();
    for kind in Kind::ALL {
        packets.extend(scenarios::generate(kind, 3, 11));
    }
    packets.sort_by_key(|p| p.ts_ns);
    // Many flows ending at the same time (sweep and end of capture batches).
    for port in 0..50u16 {
        let c = TcpConv::new(hosts::workstation(), hosts::web_server(), 30_000 + port, 80);
        packets.push(packet(1_800_000_000_000_000_000, c.syn()));
    }
    let a = run(&packets, FlowConfig::default());
    for _ in 0..3 {
        // Each table gets a fresh hash seed: the output must not depend on it.
        assert_eq!(run(&packets, FlowConfig::default()), a);
    }
    let small = FlowConfig {
        max_flows: 4,
        ..FlowConfig::default()
    };
    assert_eq!(run(&packets, small), run(&packets, small));
}
