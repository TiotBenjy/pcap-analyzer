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
    // Flow 3 keeps talking every 500 ms for 15 s: the sweep releases idle flows once they
    // are idle for the timeout plus the 5 s grace.
    for i in 0..30 {
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
fn tcp_uses_its_own_timeout_and_the_sweep_waits_for_the_grace() {
    let c = netsift_fixtures::craft::TcpConv::new(hosts::workstation(), hosts::web_server(), 4, 80);
    let mut packets = timed(vec![c.syn(), c.syn_ack()], 0, MS);
    packets.push(packet(100 * S, udp(9, false)));
    // Lookup: UDP flow 9 idle 201 s > 60 s ends at once and reopens.
    packets.push(packet(301 * S, udp(9, false)));
    // TCP idle 301 s > 300 s, but the sweep waits for the 5 s grace.
    packets.push(packet(305 * S, udp(7, false)));
    packets.push(packet(306 * S + 2 * MS, udp(7, false)));
    let mut table = FlowTable::new(FlowConfig::default());
    let mut rec = Recorder::default();
    feed(&mut table, &packets[..5], &mut rec);
    assert_eq!(rec.ends().len(), 1);
    assert_eq!(rec.ends()[0].key.proto, 17);
    assert_eq!(rec.ends()[0].last_ts_ns, 100 * S);
    feed(&mut table, &packets[5..], &mut rec);
    let ends = rec.ends();
    assert_eq!(ends.len(), 2);
    assert_eq!((ends[1].key.proto, ends[1].end), (6, EndReason::Timeout));
    assert_eq!(
        ends[1].last_ts_ns, MS,
        "time of the last packet, not of the sweep"
    );
    table.finish(&mut rec);
    rec.assert_ends_once();
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
    table.process(
        5,
        42,
        9_000_000_000,
        LINKTYPE_ETHERNET,
        1500,
        &frame,
        &mut rec,
    );
    table.finish(&mut rec);
    let (ctx, _, _) = rec.packets()[0].clone();
    assert_eq!(
        (ctx.ts_ns, ctx.chunk_id, ctx.frame, ctx.wire_len),
        (5, 42, 9_000_000_000, 1500)
    );
    assert_eq!(rec.single_flow().to_server.bytes, 1500);
}

#[test]
fn end_of_capture_reason_depends_on_the_end_time_only() {
    let packets = vec![packet(0, udp(1, false)), packet(62 * S, udp(2, false))];
    // Idle 62 s > 60 s at the table's last packet, but within the sweep grace: not released
    // by a sweep, yet reported as a timeout at the end, like a swept flow.
    let rec = run(&packets, FlowConfig::default());
    let reasons: Vec<_> = rec
        .ends()
        .iter()
        .map(|e| (e.key.client.port, e.end))
        .collect();
    assert_eq!(
        reasons,
        vec![(1, EndReason::Timeout), (2, EndReason::EndOfCapture)]
    );
    // With an explicit (global) end time, flow 2 alone in its table gets the same reasons as
    // in a table that saw later traffic.
    let mut table = FlowTable::new(FlowConfig::default());
    let mut rec = Recorder::default();
    feed(&mut table, &packets[1..], &mut rec);
    table.finish_at(200 * S, &mut rec);
    assert_eq!(rec.single_flow().end, EndReason::Timeout);
    assert_eq!(rec.single_flow().last_ts_ns, 62 * S);
}
