use std::fmt::Write as _;
use std::net::Ipv4Addr;

use netsift_dissect::decode;
use netsift_fixtures::proto::dns::{
    DnsAnswer as FxAnswer, DnsData, DnsType, encode_query, encode_response,
};
use netsift_fixtures::proto::netbios::NetbiosName;
use netsift_fixtures::scenario::DnsExchange;
use netsift_fixtures::scenarios::{Kind, generate, hosts};
use netsift_fixtures::{Host, Packet, Scenario};
use netsift_flow::FlowKey;

use super::*;

const S: i64 = 1_000_000_000;

fn analyzer() -> DnsAnalyzer {
    DnsAnalyzer::new(&AnalyzerConfig::default())
}

fn feed(dns: &mut DnsAnalyzer, packets: &[Packet], out: &mut Vec<Record>) {
    for p in packets {
        let pkt = decode(p.linktype, &p.data);
        let ctx = PacketCtx {
            ts_ns: p.ts_ns,
            chunk_id: 0,
            frame: 0,
            wire_len: u32::try_from(p.data.len()).unwrap(),
            flow: None,
        };
        dns.on_packet(&ctx, &pkt, out);
    }
}

fn run(packets: &[Packet]) -> Vec<DnsTransaction> {
    let mut dns = analyzer();
    let mut out = Vec::new();
    feed(&mut dns, packets, &mut out);
    dns.finish(&mut out);
    transactions(out)
}

fn transactions(records: Vec<Record>) -> Vec<DnsTransaction> {
    records
        .into_iter()
        .map(|r| match r {
            Record::Dns(t) => *t,
            other => panic!("unexpected record {other:?}"),
        })
        .collect()
}

fn render(txs: &[DnsTransaction]) -> String {
    let mut s = String::new();
    for t in txs {
        let answers: Vec<String> = t
            .answers
            .iter()
            .map(|a| format!("{} {} {} ttl={}", a.name, a.rtype, a.value, a.ttl))
            .collect();
        writeln!(
            s,
            "{} {} {}:{} -> {}:{} responder={:?} id={:#06x} {} {:?} {} suffix={:?} rcode={:?} \
             latency={:?} q={} r={} pending={} answers={answers:?}",
            t.proto.as_str(),
            t.transport,
            t.client.ip,
            t.client.port,
            t.server.ip,
            t.server.port,
            t.responder,
            t.id,
            t.opcode,
            t.qname,
            t.qtype,
            t.nb_suffix,
            t.rcode,
            t.latency_ns,
            u8::from(t.has_query),
            u8::from(t.has_response),
            u8::from(t.pending),
        )
        .unwrap();
    }
    s
}

#[test]
fn dns_and_nbns_rounds_snapshot() {
    let mut packets = generate(Kind::Dns, 1, 3);
    packets.extend(generate(Kind::Nbns, 1, 3));
    insta::assert_snapshot!(render(&run(&packets)));
}

#[test]
fn dns_round_is_fully_paired() {
    let txs = run(&generate(Kind::Dns, 2, 1));
    assert_eq!(txs.len(), 8);
    assert!(
        txs.iter()
            .all(|t| t.has_query && t.has_response && !t.pending)
    );
    assert!(txs.iter().all(|t| t.latency_ns.is_some()));
    let nx = txs
        .iter()
        .filter(|t| t.rcode.as_deref() == Some("NXDOMAIN"))
        .count();
    assert_eq!(nx, 2);
}

#[test]
fn unanswered_unicast_query_times_out_after_the_window() {
    let mut sc = Scenario::new();
    sc.dns(
        hosts::workstation(),
        hosts::router(),
        &DnsExchange::new("lost.example.test", DnsType::A).unanswered(),
    );
    sc.advance(6 * S);
    sc.dns(
        hosts::workstation(),
        hosts::router(),
        &DnsExchange::a("next.example.test", [203, 0, 113, 9]),
    );
    let mut dns = analyzer();
    let mut out = Vec::new();
    feed(&mut dns, sc.packets(), &mut out);
    // The timeout is emitted by packet time, before the end of the capture.
    let early = transactions(out.clone());
    assert_eq!(early.len(), 2);
    assert_eq!(early[0].qname, "lost.example.test");
    assert_eq!(early[0].rcode.as_deref(), Some(TIMEOUT));
    assert!(!early[0].pending);
    assert_eq!(early[1].rcode.as_deref(), Some("NOERROR"));
    dns.finish(&mut out);
    assert_eq!(out.len(), 2);
}

#[test]
fn late_response_is_kept_alone() {
    let mut sc = Scenario::new();
    let ex = DnsExchange::a("slow.example.test", [203, 0, 113, 7])
        .with_id(0x4242)
        .unanswered();
    let idx = sc.dns(hosts::workstation(), hosts::router(), &ex);
    sc.advance(6 * S);
    let payload = encode_response(0x4242, &ex.name, DnsType::A, 0, &ex.answers);
    sc.udp(
        hosts::router(),
        hosts::workstation(),
        53,
        idx.client_port,
        &payload,
    );
    let txs = run(sc.packets());
    assert_eq!(txs.len(), 2);
    assert_eq!(txs[0].rcode.as_deref(), Some(TIMEOUT));
    assert!(!txs[1].has_query && txs[1].has_response);
    assert_eq!(txs[1].client.ip, hosts::workstation().ip);
    assert_eq!(txs[1].answers[0].value, "203.0.113.7");
    assert_eq!(txs[1].latency_ns, None);
}

fn llmnr_group() -> Host {
    Host::v4([0x01, 0x00, 0x5e, 0x00, 0x00, 0xfc], [224, 0, 0, 252])
}

fn mdns_group() -> Host {
    Host::v4([0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb], [224, 0, 0, 251])
}

#[test]
fn group_queries_are_left_to_the_store() {
    let mut sc = Scenario::new();
    let ws = hosts::workstation();
    // LLMNR: multicast query answered by the owner of the name.
    sc.udp(
        ws,
        llmnr_group(),
        50_001,
        5355,
        &encode_query(7, "filesrv01", DnsType::A),
    );
    let answer = FxAnswer::new("filesrv01", 30, DnsData::A(Ipv4Addr::new(192, 168, 1, 20)));
    sc.udp(
        hosts::file_server(),
        ws,
        5355,
        50_001,
        &encode_response(7, "filesrv01", DnsType::A, 0, &[answer]),
    );
    // LLMNR without answer: pending (the answer may be in another shard).
    sc.udp(
        ws,
        llmnr_group(),
        50_002,
        5355,
        &encode_query(8, "wpad", DnsType::A),
    );
    // mDNS query: no response expected.
    sc.udp(
        ws,
        mdns_group(),
        5353,
        5353,
        &encode_query(0, "_ipp._tcp.local", DnsType::Ptr),
    );
    // NBNS broadcast query without answer.
    sc.nbns_query(ws, hosts::broadcast(), 0x99, &NetbiosName::new("WPAD", 0));
    let txs = run(sc.packets());
    // The answered LLMNR query is not paired here: query and response come out apart.
    assert_eq!(txs.len(), 5);
    let by_name = |n: &str| txs.iter().find(|t| t.qname == n && t.has_query).unwrap();

    let llmnr = by_name("filesrv01");
    assert_eq!(llmnr.proto, DnsProto::Llmnr);
    assert_eq!(llmnr.server.ip, llmnr_group().ip);
    assert!(llmnr.pending);
    assert_eq!(llmnr.rcode.as_deref(), Some(TIMEOUT));
    let response = txs.iter().find(|t| !t.has_query).unwrap();
    assert_eq!(response.server.ip, hosts::file_server().ip);
    assert_eq!(response.client.port, 50_001);
    assert_eq!(response.rcode.as_deref(), Some("NOERROR"));

    let wpad = by_name("wpad");
    assert_eq!(wpad.rcode.as_deref(), Some(TIMEOUT));
    assert!(wpad.pending);

    let mdns = by_name("_ipp._tcp.local");
    assert_eq!(mdns.proto, DnsProto::Mdns);
    assert_eq!(mdns.rcode, None);
    assert!(mdns.pending);

    let nbns = by_name("WPAD");
    assert_eq!(nbns.proto, DnsProto::Nbns);
    assert_eq!(nbns.nb_suffix, Some(0));
    assert_eq!(nbns.rcode.as_deref(), Some(TIMEOUT));
    assert!(nbns.pending);
}

#[test]
fn responses_from_another_host_do_not_pair_with_a_unicast_query() {
    let mut sc = Scenario::new();
    let ws = hosts::workstation();
    let q = sc.dns(
        ws,
        hosts::router(),
        &DnsExchange::new("spoof.example.test", DnsType::A)
            .with_id(5)
            .unanswered(),
    );
    sc.udp(
        hosts::web_server(),
        ws,
        53,
        q.client_port,
        &encode_response(5, "spoof.example.test", DnsType::A, 0, &[]),
    );
    let txs = run(sc.packets());
    assert_eq!(txs.len(), 2);
    assert!(txs.iter().all(|t| !(t.has_query && t.has_response)));
}

#[test]
fn pending_queries_are_bounded() {
    let config = AnalyzerConfig {
        dns: DnsConfig {
            max_pending: 2,
            ..DnsConfig::default()
        },
        ..AnalyzerConfig::default()
    };
    let mut sc = Scenario::new();
    for i in 0..5u16 {
        sc.dns(
            hosts::workstation(),
            hosts::router(),
            &DnsExchange::new(format!("n{i}.test"), DnsType::A)
                .with_id(i)
                .unanswered(),
        );
    }
    let mut dns = DnsAnalyzer::new(&config);
    let mut out = Vec::new();
    feed(&mut dns, sc.packets(), &mut out);
    assert_eq!(
        out.len(),
        3,
        "the oldest queries are emitted when the table is full"
    );
    assert!(dns.waiting.len() <= 2);
    dns.finish(&mut out);
    assert_eq!(out.len(), 5);
}

#[test]
fn hostile_payloads_on_dns_ports_are_ignored() {
    let mut sc = Scenario::new();
    for (i, len) in [0usize, 3, 11, 12, 40, 300].into_iter().enumerate() {
        let payload: Vec<u8> = (0..len)
            .map(|b| u8::try_from((b * 31 + i * 7) % 256).unwrap())
            .collect();
        sc.udp(hosts::workstation(), hosts::router(), 40_000, 53, &payload);
        sc.udp(hosts::workstation(), hosts::broadcast(), 137, 137, &payload);
    }
    // Must not panic; whatever is plausible enough is recorded.
    let _ = run(sc.packets());
}

fn stream_ctx(ts_ns: i64, gap_before: u64) -> StreamCtx {
    let key = FlowKey {
        proto: TCP,
        client: Endpoint {
            ip: hosts::workstation().ip,
            port: 41_000,
        },
        server: Endpoint {
            ip: hosts::router().ip,
            port: 53,
        },
    };
    StreamCtx {
        ts_ns,
        chunk_id: 0,
        frame: 0,
        id: FlowId::derive(&key, 0),
        key,
        gap_before,
    }
}

fn framed(msg: &[u8]) -> Vec<u8> {
    let mut out = u16::try_from(msg.len()).unwrap().to_be_bytes().to_vec();
    out.extend_from_slice(msg);
    out
}

#[test]
fn dns_over_tcp_is_reassembled_and_paired() {
    let mut dns = analyzer();
    let mut out = Vec::new();
    let query = framed(&encode_query(
        0x77,
        "axfr.example.test",
        DnsType::Other(252),
    ));
    let answer = FxAnswer::new(
        "axfr.example.test",
        60,
        DnsData::A(Ipv4Addr::new(10, 0, 0, 1)),
    );
    let response = framed(&encode_response(
        0x77,
        "axfr.example.test",
        DnsType::Other(252),
        0,
        &[answer],
    ));
    // The query arrives in two pieces, the response with garbage of a next message.
    let (a, b) = query.split_at(5);
    dns.on_stream(&stream_ctx(S, 0), Direction::ToServer, a, &mut out);
    dns.on_stream(&stream_ctx(S, 0), Direction::ToServer, b, &mut out);
    let mut tail = response.clone();
    tail.extend_from_slice(&[0x00]);
    dns.on_stream(
        &stream_ctx(S + 1_000, 0),
        Direction::ToClient,
        &tail,
        &mut out,
    );
    let txs = transactions(out);
    assert_eq!(txs.len(), 1);
    let t = &txs[0];
    assert_eq!(t.transport, TCP);
    assert_eq!(t.qtype, "AXFR");
    assert_eq!(t.latency_ns, Some(1_000));
    assert_eq!(t.answers.len(), 1);

    // A gap drops the partial message.
    let mut out = Vec::new();
    dns.on_stream(&stream_ctx(2 * S, 0), Direction::ToServer, a, &mut out);
    dns.on_stream(&stream_ctx(2 * S, 4), Direction::ToServer, b, &mut out);
    dns.finish(&mut out);
    assert_eq!(out.len(), 0);
}

#[test]
fn many_tcp_messages_in_one_segment_are_framed_linearly() {
    let mut dns = analyzer();
    let mut out = Vec::new();
    let mut data = Vec::new();
    for i in 0..3_000u16 {
        data.extend_from_slice(&framed(&encode_query(i, "bulk.example.test", DnsType::A)));
    }
    let started = std::time::Instant::now();
    dns.on_stream(&stream_ctx(S, 0), Direction::ToServer, &data, &mut out);
    assert!(started.elapsed() < std::time::Duration::from_secs(2));
    dns.finish(&mut out);
    assert_eq!(out.len(), 3_000);
}

#[test]
fn a_tcp_direction_stays_desynchronized_after_a_gap_or_garbage() {
    let mut dns = analyzer();
    let mut out = Vec::new();
    let query = framed(&encode_query(1, "a.example.test", DnsType::A));
    // A gap: everything after it in this direction is ignored, even well framed.
    dns.on_stream(&stream_ctx(S, 10), Direction::ToServer, &query, &mut out);
    dns.on_stream(&stream_ctx(S, 0), Direction::ToServer, &query, &mut out);
    dns.finish(&mut out);
    assert_eq!(out.len(), 0);

    // A frame shorter than a header: the stream is not DNS.
    let mut dns = analyzer();
    let mut garbage = vec![0, 4, 1, 2, 3, 4];
    garbage.extend_from_slice(&query);
    dns.on_stream(&stream_ctx(S, 0), Direction::ToServer, &garbage, &mut out);
    dns.on_stream(&stream_ctx(S, 0), Direction::ToServer, &query, &mut out);
    // The other direction is not affected.
    let response = framed(&encode_response(1, "a.example.test", DnsType::A, 0, &[]));
    dns.on_stream(&stream_ctx(S, 0), Direction::ToClient, &response, &mut out);
    dns.finish(&mut out);
    let txs = transactions(out);
    assert_eq!(txs.len(), 1);
    assert!(!txs[0].has_query && txs[0].has_response);
}

#[test]
fn partial_tcp_messages_are_bounded_per_shard() {
    let config = AnalyzerConfig {
        dns: DnsConfig {
            max_stream_bytes: 8,
            ..DnsConfig::default()
        },
        ..AnalyzerConfig::default()
    };
    let mut dns = DnsAnalyzer::new(&config);
    let mut out = Vec::new();
    let query = framed(&encode_query(1, "a.example.test", DnsType::A));
    let (a, b) = query.split_at(20);
    dns.on_stream(&stream_ctx(S, 0), Direction::ToServer, a, &mut out);
    dns.on_stream(&stream_ctx(S, 0), Direction::ToServer, b, &mut out);
    dns.finish(&mut out);
    assert_eq!(out.len(), 0, "20 bytes held would exceed the bound");
    assert_eq!(dns.stream_bytes, 0);
}

#[test]
fn waiting_queries_are_bounded_in_bytes() {
    let config = AnalyzerConfig {
        dns: DnsConfig {
            max_pending_bytes: 1,
            ..DnsConfig::default()
        },
        ..AnalyzerConfig::default()
    };
    let mut sc = Scenario::new();
    for i in 0..3u16 {
        sc.dns(
            hosts::workstation(),
            hosts::router(),
            &DnsExchange::new(format!("n{i}.test"), DnsType::A)
                .with_id(i)
                .unanswered(),
        );
    }
    let mut dns = DnsAnalyzer::new(&config);
    let mut out = Vec::new();
    feed(&mut dns, sc.packets(), &mut out);
    // One query at a time may wait, whatever its size.
    assert_eq!(out.len(), 2);
    assert_eq!(dns.waiting.len(), 1);
}
