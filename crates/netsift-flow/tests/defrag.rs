//! IP defragmentation through the flow table.

mod common;

use common::{MS, S, run, timed};
use netsift_fixtures::craft::{
    FragSpec, Side, TcpConv, fragment_frames, ip_payload, packet, udp_frame,
};
use netsift_fixtures::scenarios::{self, hosts};
use netsift_flow::{Direction, FlowConfig};

#[test]
fn fragmentation_scenario_reports_each_datagram_once() {
    let (sc, expected) = scenarios::fragmentation();
    let rec = run(sc.packets(), FlowConfig::default());
    let packets = rec.packets();
    assert_eq!(
        packets.len(),
        expected.len(),
        "fragments are not reported one by one"
    );
    let mut idx = 0;
    for ((ctx, summary, payload), dg) in packets.iter().zip(&expected) {
        let frames = &sc.packets()[idx..idx + dg.frames];
        idx += dg.frames;
        assert_eq!(payload, &dg.payload, "{summary}");
        assert_eq!(
            ctx.frame,
            u64::try_from(idx - 1).unwrap(),
            "frame of the last fragment"
        );
        assert_eq!(
            ctx.ts_ns,
            frames.last().unwrap().ts_ns,
            "time of the last fragment"
        );
        let wire: usize = frames.iter().map(|p| p.data.len()).sum();
        assert_eq!(ctx.wire_len as usize, wire, "every fragment counted");
        let flow = ctx.flow.expect("reassembled datagrams belong to a flow");
        assert_eq!(flow.key.proto, 17);
        assert_eq!(flow.key.client.port, dg.sport);
        assert_eq!(flow.key.server.port, dg.dport);
        assert_eq!(flow.dir, Direction::ToServer);
    }
    assert_eq!(rec.ends().len(), 4);
    insta::assert_snapshot!(rec.render());
}

#[test]
fn fragmented_tcp_segment_feeds_the_stream() {
    let c = TcpConv::new(hosts::workstation_v6(), hosts::router_v6(), 40_000, 80);
    let data: Vec<u8> = (0..3000u32).map(|i| (i % 253) as u8).collect();
    let seg = c.data(Side::Client, 0, 0, &data);
    let body = ip_payload(&seg).unwrap().to_vec();
    let mut specs = FragSpec::even(&body, 1280);
    specs.reverse();
    let mut frames = vec![c.syn(), c.syn_ack(), c.ack(Side::Client, 0, 0)];
    frames.extend(fragment_frames(&seg, 7, &specs));
    frames.push(c.data(Side::Client, 3000, 0, b"after"));
    let rec = run(&timed(frames, 0, MS), FlowConfig::default());
    let flow = rec.single_flow();
    assert_eq!(
        flow.to_server.packets, 4,
        "SYN, ACK, reassembled segment, data"
    );
    let mut want = data.clone();
    want.extend_from_slice(b"after");
    assert_eq!(rec.stream(flow.id, Direction::ToServer).0, want);
}

fn three_fragments(ident: u32) -> Vec<Vec<u8>> {
    let frame = udp_frame(
        &hosts::workstation(),
        &hosts::router(),
        7000,
        9,
        &[5u8; 200],
    );
    let body = ip_payload(&frame).unwrap().to_vec();
    fragment_frames(&frame, ident, &FragSpec::even(&body, 80))
}

#[test]
fn incomplete_datagrams_expire_in_packet_time_and_are_never_reported() {
    let f = three_fragments(1);
    let packets = vec![
        packet(0, f[0].clone()),
        packet(MS, f[1].clone()),
        // 31 s later: the first two fragments are gone (30 s timeout).
        packet(31 * S, f[2].clone()),
        // A new copy: its first two fragments complete the datagram with the fresh last
        // fragment received at 31 s; its own last fragment then starts an orphan datagram.
        packet(32 * S, f[0].clone()),
        packet(32 * S + 1, f[1].clone()),
        packet(32 * S + 2, f[2].clone()),
        // Left incomplete at the end of the capture: dropped silently.
        packet(33 * S, three_fragments(2)[0].clone()),
    ];
    let rec = run(&packets, FlowConfig::default());
    let reported = rec.packets();
    assert_eq!(reported.len(), 1);
    assert_eq!(reported[0].0.ts_ns, 32 * S + 1);
    assert_eq!(reported[0].2, vec![5u8; 200]);
}

#[test]
fn defrag_memory_bound_rejects_what_does_not_fit() {
    let config = FlowConfig {
        max_defrag_bytes: 300,
        ..FlowConfig::default()
    };
    let rec = run(&timed(three_fragments(3), 0, MS), config);
    // Each fragment costs its data plus fixed overheads: nothing fits in 300 bytes, every
    // fragment is reported alone without a flow.
    let reported = rec.packets();
    assert_eq!(reported.len(), 3);
    assert!(reported.iter().all(|(c, _, _)| c.flow.is_none()));
}

#[test]
fn teardrop_fragment_is_reported_without_flow() {
    let frame = udp_frame(&hosts::workstation(), &hosts::router(), 7000, 9, &[1u8; 40]);
    let body = ip_payload(&frame).unwrap().to_vec();
    let specs = [
        FragSpec::slice(&body, 0..16),
        FragSpec::new(16, false, body[16..].to_vec()),
        // Another "last" fragment that ends before the first one did.
        FragSpec::new(8, false, vec![0u8; 4]),
    ];
    let mut frames = vec![fragment_frames(&frame, 9, &specs[1..2])[0].clone()];
    frames.extend(fragment_frames(&frame, 9, &specs[2..]));
    frames.extend(fragment_frames(&frame, 9, &specs[..1]));
    let rec = run(&timed(frames, 0, MS), FlowConfig::default());
    let reported = rec.packets();
    // The teardrop fragment is rejected (with the pending datagram); the first fragment then
    // starts a new datagram that never completes.
    assert_eq!(reported.len(), 1);
    assert!(reported[0].0.flow.is_none());
    assert_eq!(reported[0].0.ts_ns, MS);
}

#[test]
fn snaplen_truncated_fragment_is_not_reassembled() {
    let mut f = three_fragments(4);
    let cut = f[2].len() - 4;
    f[2].truncate(cut);
    let rec = run(&timed(f, 0, MS), FlowConfig::default());
    let reported = rec.packets();
    assert_eq!(reported.len(), 1);
    assert!(reported[0].0.flow.is_none());
}
