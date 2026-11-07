//! TCP tracking and reassembly on synthetic traffic.

mod common;

use common::{MS, Recorder, run, timed};
use netsift_fixtures::craft::{Side, TcpConv, TcpSeg};
use netsift_fixtures::scenario::{HttpGet, Scenario};
use netsift_fixtures::scenarios::hosts;
use netsift_flow::{Direction, EndReason, FlowConfig, FlowId, TcpState};

fn conv() -> TcpConv {
    TcpConv::new(hosts::workstation(), hosts::web_server(), 40_000, 80)
}

fn handshake(c: &TcpConv) -> Vec<Vec<u8>> {
    vec![c.syn(), c.syn_ack(), c.ack(Side::Client, 0, 0)]
}

fn id_of(rec: &Recorder) -> FlowId {
    rec.single_flow().id
}

#[test]
fn http_session_streams_equal_the_bytes_sent() {
    let get = HttpGet::default();
    let mut sc = Scenario::new();
    let ex = sc.http_get(hosts::workstation(), hosts::web_server(), &get);
    let rec = run(sc.packets(), FlowConfig::default());

    let flow = rec.single_flow();
    assert_eq!(flow.key.proto, 6);
    assert_eq!(flow.key.client.ip, hosts::workstation().ip);
    assert_eq!(flow.key.client.port, ex.client_port);
    assert_eq!(flow.key.server.port, 80);
    assert_eq!(flow.tcp_state, Some(TcpState::Closed));
    assert_eq!(flow.end, EndReason::Closed);
    let total = flow.to_server.packets + flow.to_client.packets;
    assert_eq!(total, u64::try_from(sc.len()).unwrap());
    let bytes: usize = sc.packets().iter().map(|p| p.data.len()).sum();
    assert_eq!(
        flow.to_server.bytes + flow.to_client.bytes,
        u64::try_from(bytes).unwrap()
    );
    assert_eq!(flow.first_ts_ns, sc.packets()[0].ts_ns);
    assert_eq!(flow.last_ts_ns, sc.packets().last().unwrap().ts_ns);

    let (req, gaps) = rec.stream(flow.id, Direction::ToServer);
    assert_eq!(req, get.request_bytes());
    assert_eq!(gaps, Vec::<u64>::new());
    let (resp, gaps) = rec.stream(flow.id, Direction::ToClient);
    assert_eq!(resp, get.response_bytes());
    assert_eq!(gaps, Vec::<u64>::new());

    // Every packet carries the flow, with the right direction.
    for (ctx, _, _) in rec.packets() {
        let f = ctx.flow.expect("TCP packets belong to the flow");
        assert_eq!(f.id, flow.id);
        assert_eq!(f.key, flow.key);
    }
}

#[test]
fn small_http_session_event_sequence() {
    let c = conv();
    let mut frames = handshake(&c);
    frames.push(c.data(Side::Client, 0, 0, b"GET / HTTP/1.1\r\n\r\n"));
    frames.push(c.data(Side::Server, 0, 18, b"HTTP/1.1 204 No Content\r\n\r\n"));
    frames.push(c.fin(Side::Client, 18, 27));
    frames.push(c.fin(Side::Server, 27, 19));
    frames.push(c.ack(Side::Client, 19, 28));
    let rec = run(
        &timed(frames, 1_700_000_000 * common::S, MS),
        FlowConfig::default(),
    );
    insta::assert_snapshot!(rec.render());
}

#[test]
fn out_of_order_retransmissions_and_overlaps() {
    let c = conv();
    let msg = b"0123456789abcdefghijklmnopqrstuvwxyz";
    let d = |from: usize, to: usize| c.data(Side::Client, from as u64, 0, &msg[from..to]);
    let mut frames = handshake(&c);
    frames.extend([
        d(10, 20),
        d(30, 36),
        d(0, 10),
        d(0, 10), // retransmission
        d(5, 15), // overlap with delivered data
        // Overlap with buffered data, different bytes: first arrival wins.
        c.data(Side::Client, 25, 0, b"XXXXXXXXXX"),
        d(20, 25),
        d(20, 36), // late retransmission covering everything
    ]);
    let rec = run(&timed(frames, 0, MS), FlowConfig::default());
    let (data, gaps) = rec.stream(id_of(&rec), Direction::ToServer);
    assert_eq!(data, b"0123456789abcdefghijklmnoXXXXXuvwxyz");
    assert_eq!(gaps, Vec::<u64>::new());
}

#[test]
fn loss_is_reported_as_a_gap() {
    let c = conv();
    let mut frames = handshake(&c);
    frames.push(c.data(Side::Client, 0, 0, b"aaaa"));
    frames.push(c.data(Side::Client, 10, 0, b"cccc")); // 6 bytes lost
    frames.push(c.data(Side::Client, 14, 0, b"dd"));
    let rec = run(&timed(frames, 0, MS), FlowConfig::default());
    let id = id_of(&rec);
    let (data, gaps) = rec.stream(id, Direction::ToServer);
    assert_eq!(data, b"aaaaccccdd");
    assert_eq!(gaps, vec![6]);
    // The hole is given up at the end of the capture, with the last packet time.
    assert_eq!(rec.single_flow().end, EndReason::EndOfCapture);
}

#[test]
fn buffer_limit_gives_up_on_a_hole() {
    let c = conv();
    let config = FlowConfig {
        max_stream_buffer: 8,
        ..FlowConfig::default()
    };
    let mut frames = handshake(&c);
    frames.push(c.data(Side::Client, 4, 0, b"efgh"));
    frames.push(c.data(Side::Client, 8, 0, b"ijkl")); // 8 bytes buffered: still fits
    frames.push(c.data(Side::Client, 12, 0, b"m")); // 9 > 8: give up on 0..4
    frames.push(c.data(Side::Client, 0, 0, b"abcd")); // too late
    let rec = run(&timed(frames, 0, MS), config);
    let streams: Vec<_> = rec
        .events
        .iter()
        .filter_map(|e| match e {
            common::Event::Stream { ctx, data, .. } => Some((ctx.gap_before, data.clone())),
            _ => None,
        })
        .collect();
    assert_eq!(
        streams,
        vec![
            (4, b"efgh".to_vec()),
            (0, b"ijkl".to_vec()),
            (0, b"m".to_vec())
        ]
    );
}

#[test]
fn sequence_numbers_wrap_around() {
    let c = conv().with_isns(u32::MAX - 5, u32::MAX);
    let mut frames = handshake(&c);
    frames.push(c.data(Side::Client, 8, 0, b"89abcdef"));
    frames.push(c.data(Side::Client, 0, 0, b"01234567"));
    frames.push(c.data(Side::Server, 0, 16, b"wrapped server data"));
    frames.push(c.fin(Side::Client, 16, 19));
    frames.push(c.fin(Side::Server, 19, 17));
    let rec = run(&timed(frames, 0, MS), FlowConfig::default());
    let id = id_of(&rec);
    assert_eq!(rec.stream(id, Direction::ToServer).0, b"0123456789abcdef");
    assert_eq!(
        rec.stream(id, Direction::ToClient).0,
        b"wrapped server data"
    );
    assert_eq!(rec.single_flow().tcp_state, Some(TcpState::Closed));
}

#[test]
fn midstream_pickup_starts_at_the_first_sequence() {
    let c = conv();
    // Server speaks first in the capture: it becomes the "client" of the flow key.
    let frames = vec![
        c.data(Side::Server, 1000, 50, b"world"),
        c.data(Side::Client, 50, 1005, b"hello"),
        c.data(Side::Server, 1005, 55, b"!"),
    ];
    let rec = run(&timed(frames, 0, MS), FlowConfig::default());
    let flow = rec.single_flow();
    assert_eq!(flow.tcp_state, Some(TcpState::Midstream));
    assert_eq!(flow.key.client.port, 80);
    assert_eq!(rec.stream(flow.id, Direction::ToServer).0, b"world!");
    assert_eq!(rec.stream(flow.id, Direction::ToClient).0, b"hello");
}

#[test]
fn syn_ack_without_syn_orients_toward_its_destination() {
    let c = conv();
    let frames = vec![
        c.syn_ack(),
        c.ack(Side::Client, 0, 0),
        c.data(Side::Client, 0, 0, b"req"),
    ];
    let rec = run(&timed(frames, 0, MS), FlowConfig::default());
    let flow = rec.single_flow();
    assert_eq!(flow.key.client.port, 40_000);
    assert_eq!(flow.tcp_state, Some(TcpState::Established));
    assert_eq!(rec.stream(flow.id, Direction::ToServer).0, b"req");
}

#[test]
fn handshake_states() {
    let c = conv();
    let syn_only = run(&timed(vec![c.syn(), c.syn()], 0, MS), FlowConfig::default());
    assert_eq!(syn_only.single_flow().tcp_state, Some(TcpState::SynSent));
    assert_eq!(syn_only.single_flow().to_server.packets, 2);
    let half = run(
        &timed(vec![c.syn(), c.syn_ack()], 0, MS),
        FlowConfig::default(),
    );
    assert_eq!(half.single_flow().tcp_state, Some(TcpState::SynReceived));
    let full = run(&timed(handshake(&c), 0, MS), FlowConfig::default());
    assert_eq!(full.single_flow().tcp_state, Some(TcpState::Established));
    assert_eq!(full.single_flow().end, EndReason::EndOfCapture);
}

#[test]
fn reset_flushes_and_closes() {
    let c = conv();
    let mut frames = handshake(&c);
    frames.push(c.data(Side::Client, 0, 0, b"ab"));
    frames.push(c.data(Side::Client, 5, 0, b"fg")); // hole 2..5
    frames.push(c.rst(Side::Server, 0));
    frames.push(c.ack(Side::Client, 7, 0)); // still the same flow (linger)
    let rec = run(&timed(frames, 0, MS), FlowConfig::default());
    let flow = rec.single_flow();
    assert_eq!(flow.tcp_state, Some(TcpState::Reset));
    assert_eq!(flow.end, EndReason::Closed);
    assert_eq!(flow.to_server.packets, 5);
    let (data, gaps) = rec.stream(flow.id, Direction::ToServer);
    assert_eq!((data.as_slice(), gaps), (&b"abfg"[..], vec![3]));
    // The gap is flushed when the RST arrives, not at the end of the capture.
    let flush_pos = rec
        .events
        .iter()
        .position(|e| matches!(e, common::Event::Stream { ctx, .. } if ctx.gap_before == 3))
        .unwrap();
    let last_pkt = rec
        .events
        .iter()
        .rposition(|e| matches!(e, common::Event::Packet { .. }))
        .unwrap();
    assert!(flush_pos < last_pkt);
}

#[test]
fn fin_both_sides_then_linger_then_end() {
    let c = conv();
    let mut frames = handshake(&c);
    frames.push(c.data(Side::Client, 0, 0, b"q"));
    frames.push(c.fin(Side::Server, 0, 1));
    frames.push(c.data(Side::Client, 1, 1, b"half-closed"));
    frames.push(c.fin(Side::Client, 12, 1));
    frames.push(c.ack(Side::Server, 1, 13));
    let mut packets = timed(frames, 0, MS);
    // A stray ACK 20 s later: the closed flow lingered 10 s, so this opens a new flow.
    packets.push(netsift_fixtures::craft::packet(
        20 * common::S,
        c.ack(Side::Server, 1, 13),
    ));
    let rec = run(&packets, FlowConfig::default());
    let ends = rec.ends();
    assert_eq!(ends.len(), 2);
    assert_eq!(ends[0].tcp_state, Some(TcpState::Closed));
    assert_eq!(ends[0].end, EndReason::Closed);
    assert_eq!(ends[0].to_client.packets, 3);
    assert_eq!(
        rec.stream(ends[0].id, Direction::ToServer).0,
        b"qhalf-closed"
    );
    assert_eq!(ends[1].tcp_state, Some(TcpState::Midstream));
    assert_eq!(ends[1].end, EndReason::EndOfCapture);
    assert_ne!(ends[0].id, ends[1].id);
}

#[test]
fn syn_after_close_or_with_a_new_isn_opens_a_new_flow() {
    let c = conv();
    let mut frames = handshake(&c);
    frames.push(c.rst(Side::Client, 0));
    // Port reuse right after the reset.
    let c2 = c.with_isns(77_777, 88_888);
    frames.extend(handshake(&c2));
    frames.push(c2.data(Side::Client, 0, 0, b"second"));
    // Port reuse without any close seen: a SYN with another ISN.
    let c3 = c.with_isns(123, 456);
    frames.push(c3.syn());
    let rec = run(&timed(frames, 0, MS), FlowConfig::default());
    let ends = rec.ends();
    assert_eq!(ends.len(), 3);
    assert_eq!(
        ends.iter().map(|e| e.end).collect::<Vec<_>>(),
        vec![
            EndReason::Closed,
            EndReason::Closed,
            EndReason::EndOfCapture
        ]
    );
    assert_eq!(ends[0].tcp_state, Some(TcpState::Reset));
    assert_eq!(ends[1].tcp_state, Some(TcpState::Established));
    assert_eq!(rec.stream(ends[1].id, Direction::ToServer).0, b"second");
    assert_eq!(ends[2].tcp_state, Some(TcpState::SynSent));
}

#[test]
fn syn_payload_and_fin_consume_sequence_numbers() {
    let c = conv();
    let syn_data = c.frame(Side::Client, &TcpSeg::new(c.client_isn).syn(), b"tfo");
    let frames = vec![
        syn_data,
        c.syn_ack(),
        c.data(Side::Client, 3, 0, b"rest"),
        c.fin(Side::Client, 7, 0),
        // Data "after" the FIN is ignored.
        c.data(Side::Client, 8, 0, b"junk"),
    ];
    let rec = run(&timed(frames, 0, MS), FlowConfig::default());
    assert_eq!(rec.stream(id_of(&rec), Direction::ToServer).0, b"tforest");
}
