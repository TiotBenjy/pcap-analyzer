//! Packet-time expiry, LRU eviction, end of capture, non-TCP flows.

mod common;

use common::{MS, Recorder, S, ends_with, feed, run, timed};
use netsift_fixtures::craft::{icmp_echo_frame, packet, udp_frame};
use netsift_fixtures::scenarios::hosts;
use netsift_fixtures::{LINKTYPE_ETHERNET, Packet};
use netsift_flow::{Direction, EndReason, FlowConfig, FlowTable};

fn udp(sport: u16, reply: bool) -> Vec<u8> {
    let (a, b) = (hosts::workstation(), hosts::router());
    if reply {
        udp_frame(&b, &a, 53, sport, b"answer")
    } else {
        udp_frame(&a, &b, sport, 53, b"query")
    }
}

#[test]
fn udp_flow_times_out_then_reopens_with_a_new_id() {
    let packets = vec![
        packet(0, udp(5000, false)),
        packet(MS, udp(5000, true)),
        // 61 s of silence > 60 s UDP timeout: the next packet opens a new flow.
        packet(61 * S + MS + 1, udp(5000, true)),
    ];
    let rec = run(&packets, FlowConfig::default());
    let ends = rec.ends();
    assert_eq!(ends.len(), 2);
    assert_eq!(ends[0].end, EndReason::Timeout);
    assert_eq!(ends[0].key.client.port, 5000);
    assert_eq!(
        (ends[0].to_server.packets, ends[0].to_client.packets),
        (1, 1)
    );
    // The reply after the timeout starts a flow oriented from the resolver.
    assert_eq!(ends[1].key.client.port, 53);
    assert_eq!(ends[1].first_ts_ns, 61 * S + MS + 1);
    assert_eq!(ends[1].end, EndReason::EndOfCapture);
    assert_ne!(ends[0].id, ends[1].id);
    // The timeout is reported before the packet that reopened the tuple.
    let pos_end = rec
        .events
        .iter()
        .position(|e| matches!(e, common::Event::End(_)))
        .unwrap();
    assert_eq!(pos_end, 2);
}

#[test]
fn exactly_the_timeout_is_not_idle_enough() {
    let packets = vec![packet(0, udp(5000, false)), packet(60 * S, udp(5000, true))];
    let rec = run(&packets, FlowConfig::default());
    assert_eq!(rec.single_flow().to_client.packets, 1);
}

#[test]
fn sweep_expires_idle_flows_while_others_are_active() {
    let config = FlowConfig {
        udp_timeout_ns: 5 * S,
        ..FlowConfig::default()
    };
    let mut table = FlowTable::new(config);
    let mut rec = Recorder::default();
    let mut packets = vec![packet(0, udp(1, false)), packet(MS, udp(2, false))];
    // Flow 3 keeps talking every 500 ms for 10 s.
    for i in 0..20 {
        packets.push(packet(2 * MS + i * 500 * MS, udp(3, false)));
    }
    feed(&mut table, &packets, &mut rec);
    assert_eq!(
        table.active_flows(),
        1,
        "flows 1 and 2 expired during the capture"
    );
    assert_eq!(ends_with(&rec, EndReason::Timeout), 2);
    let ends = rec.ends();
    assert_eq!(
        ends.iter().map(|e| e.key.client.port).collect::<Vec<_>>(),
        vec![1, 2],
        "expired in LRU order"
    );
    table.finish(&mut rec);
    assert_eq!(table.active_flows(), 0);
    assert_eq!(ends_with(&rec, EndReason::EndOfCapture), 1);
    rec.assert_ends_once();
}

#[test]
fn lru_eviction_beyond_max_flows() {
    let config = FlowConfig {
        max_flows: 3,
        ..FlowConfig::default()
    };
    let packets = vec![
        packet(0, udp(1, false)),
        packet(MS, udp(2, false)),
        packet(2 * MS, udp(3, false)),
        packet(3 * MS, udp(1, true)),  // flow 1 becomes the most recent
        packet(4 * MS, udp(4, false)), // evicts flow 2
        packet(5 * MS, udp(5, false)), // evicts flow 3
    ];
    let mut table = FlowTable::new(config);
    let mut rec = Recorder::default();
    feed(&mut table, &packets, &mut rec);
    assert_eq!(table.active_flows(), 3);
    let evicted: Vec<u16> = rec.ends().iter().map(|e| e.key.client.port).collect();
    assert_eq!(evicted, vec![2, 3]);
    assert_eq!(ends_with(&rec, EndReason::Evicted), 2);
    table.finish(&mut rec);
    // End of capture in creation order: 1, 4, 5.
    let rest: Vec<u16> = rec.ends()[2..].iter().map(|e| e.key.client.port).collect();
    assert_eq!(rest, vec![1, 4, 5]);
    rec.assert_ends_once();
}

#[test]
fn max_flows_zero_still_tracks_one_flow() {
    let config = FlowConfig {
        max_flows: 0,
        ..FlowConfig::default()
    };
    let packets = vec![packet(0, udp(1, false)), packet(MS, udp(2, false))];
    let rec = run(&packets, config);
    assert_eq!(rec.ends().len(), 2);
    assert_eq!(rec.ends()[0].end, EndReason::Evicted);
}

#[test]
fn small_clock_steps_backwards_are_tolerated() {
    let packets = vec![
        packet(10 * S, udp(1, false)),
        packet(10 * S - 3 * MS, udp(1, true)),
        packet(9 * S, udp(1, false)),
        packet(10 * S + MS, udp(1, true)),
    ];
    let rec = run(&packets, FlowConfig::default());
    let flow = rec.single_flow();
    assert_eq!(flow.first_ts_ns, 10 * S);
    assert_eq!(flow.last_ts_ns, 10 * S + MS);
    assert_eq!(flow.to_server.packets + flow.to_client.packets, 4);
}

#[test]
fn tcp_uses_its_own_timeout() {
    let c = netsift_fixtures::craft::TcpConv::new(hosts::workstation(), hosts::web_server(), 4, 80);
    let mut packets = timed(vec![c.syn(), c.syn_ack()], 0, MS);
    packets.push(packet(100 * S, udp(9, false)));
    packets.push(packet(301 * S, udp(9, false)));
    let rec = run(&packets, FlowConfig::default());
    let ends = rec.ends();
    // At 301 s one sweep expires the TCP flow (idle 300.999 s > 300 s) and the UDP flow
    // (idle 201 s > 60 s), in LRU order; the last packet then opens a new UDP flow.
    assert_eq!(ends.len(), 3);
    assert_eq!(ends[0].key.proto, 6);
    assert_eq!(ends[0].end, EndReason::Timeout);
    assert_eq!(ends[1].key.proto, 17);
    assert_eq!(ends[1].end, EndReason::Timeout);
}

#[test]
fn icmp_flows_have_zero_ports() {
    let (a, b) = (hosts::workstation(), hosts::router());
    let packets = timed(
        vec![
            icmp_echo_frame(&a, &b, 7, 1, false, b"ping"),
            icmp_echo_frame(&b, &a, 7, 1, true, b"ping"),
            icmp_echo_frame(&a, &b, 7, 2, false, b"ping"),
        ],
        0,
        MS,
    );
    let rec = run(&packets, FlowConfig::default());
    let flow = rec.single_flow();
    assert_eq!(flow.key.proto, 1);
    assert_eq!((flow.key.client.port, flow.key.server.port), (0, 0));
    assert_eq!((flow.to_server.packets, flow.to_client.packets), (2, 1));
    assert_eq!(flow.tcp_state, None);
    let dirs: Vec<_> = rec
        .packets()
        .iter()
        .map(|(c, _, _)| c.flow.unwrap().dir)
        .collect();
    assert_eq!(
        dirs,
        vec![
            Direction::ToServer,
            Direction::ToClient,
            Direction::ToServer
        ]
    );
}

#[test]
fn non_ip_and_undecodable_frames_have_no_flow() {
    let mut arp = vec![0xff; 6];
    arp.extend_from_slice(&hosts::workstation().mac);
    arp.extend_from_slice(&[0x08, 0x06]);
    arp.extend_from_slice(&[0, 1, 8, 0, 6, 4, 0, 1]);
    arp.extend_from_slice(&[0; 20]);
    let mut truncated_tcp =
        netsift_fixtures::craft::TcpConv::new(hosts::workstation(), hosts::web_server(), 1, 2)
            .syn();
    truncated_tcp.truncate(14 + 20 + 10); // TCP header cut
    let packets = vec![
        packet(0, arp),
        packet(1, truncated_tcp),
        Packet {
            ts_ns: 2,
            linktype: 999,
            interface: 0,
            data: vec![1, 2, 3],
        },
    ];
    let rec = run(&packets, FlowConfig::default());
    assert_eq!(rec.packets().len(), 3);
    assert!(rec.packets().iter().all(|(c, _, _)| c.flow.is_none()));
    assert_eq!(rec.ends().len(), 0);
}

#[test]
fn chunk_and_wire_length_are_passed_through() {
    let mut table = FlowTable::new(FlowConfig::default());
    let mut rec = Recorder::default();
    let frame = udp(1, false);
    table.process(5, 42, LINKTYPE_ETHERNET, 1500, &frame, &mut rec);
    table.finish(&mut rec);
    let (ctx, _, _) = rec.packets()[0].clone();
    assert_eq!((ctx.ts_ns, ctx.chunk_id, ctx.wire_len), (5, 42, 1500));
    assert_eq!(rec.single_flow().to_server.bytes, 1500);
}
