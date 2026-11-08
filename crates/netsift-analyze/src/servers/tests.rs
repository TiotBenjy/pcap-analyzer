//! Tests of the `servers` analyzer: synthetic exchanges through the real flow layer, and direct
//! `on_stream` calls to control TCP segmentation and gaps.

use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr};

use netsift_fixtures::proto::kerberos as krb;
use netsift_fixtures::scenario::{Scenario, TcpOptions};
use netsift_fixtures::scenarios::hosts;
use netsift_fixtures::servers::{REALM, servers_hosts, servers_showcase};
use netsift_flow::{Direction, Endpoint, FlowId, FlowKey, StreamCtx};

use super::{KdcReply, ServerRecord, ServersAnalyzer, ServersConfig};
use crate::analyzer::Analyzer;
use crate::record::Record;
use crate::registry::AnalyzerConfig;
use crate::testutil;

fn analyzer() -> ServersAnalyzer {
    ServersAnalyzer::new(&AnalyzerConfig::default())
}

fn server_records(records: Vec<Record>) -> Vec<ServerRecord> {
    records
        .into_iter()
        .filter_map(|r| match r {
            Record::Server(s) => Some(s),
            _ => None,
        })
        .collect()
}

fn run(sc: &Scenario) -> Vec<ServerRecord> {
    server_records(testutil::run(&mut analyzer(), sc.packets()))
}

/// One line per record, without timestamps.
fn render(records: &[ServerRecord]) -> String {
    let mut out = String::new();
    for r in records {
        match r {
            ServerRecord::Dhcp(d) => writeln!(
                out,
                "dhcp {} -> {} op={} type={:?} xid={:08x} mac={:?} yiaddr={:?} server_id={:?} \
                 requested={:?} mask={:?} routers={:?} dns={:?} lease={:?} hostname={:?}",
                d.src_ip,
                d.dst_ip,
                d.op,
                d.message_type,
                d.xid,
                d.client_mac,
                d.yiaddr,
                d.server_id,
                d.requested_ip,
                d.subnet_mask,
                d.routers,
                d.dns_servers,
                d.lease_s,
                d.hostname
            ),
            ServerRecord::Ntp(n) => writeln!(
                out,
                "ntp {} -> {} v{} stratum={} ref={:?}",
                n.server, n.client, n.version, n.stratum, n.reference
            ),
            ServerRecord::Kerberos(k) => writeln!(
                out,
                "kerberos {} -> {} transport={} {} realm={:?} error={:?}",
                k.server,
                k.client,
                k.transport,
                k.kind.as_str(),
                k.realm,
                k.error_code
            ),
        }
        .unwrap();
    }
    out
}

#[test]
fn showcase_records() {
    let mut sc = Scenario::new();
    servers_showcase(&mut sc);
    let records = run(&sc);
    insta::assert_snapshot!(render(&records));
}

#[test]
fn tcp_reply_split_in_small_segments_is_reassembled() {
    let mut sc = Scenario::new();
    let dc = servers_hosts::domain_controller();
    let mut opts = TcpOptions::new(88);
    opts.mss = 7;
    let mut s = sc.tcp_open(hosts::workstation(), dc, &opts);
    s.client_send(&krb::tcp_record(&krb::kdc_req(true, REALM, "jdoe")));
    // Two replies on the same connection.
    let mut replies = krb::tcp_record(&krb::kdc_rep(true, REALM, "jdoe"));
    replies.extend(krb::tcp_record(&krb::krb_error(6, REALM)));
    s.server_send(&replies);
    s.close();
    let records = run(&sc);
    let kinds: Vec<_> = records
        .iter()
        .map(|r| match r {
            ServerRecord::Kerberos(k) => (k.kind, k.transport, k.realm.clone()),
            other => panic!("unexpected {other:?}"),
        })
        .collect();
    assert_eq!(
        kinds,
        vec![
            (KdcReply::TgsRep, 6, Some(REALM.to_owned())),
            (KdcReply::Error, 6, Some(REALM.to_owned())),
        ]
    );
}

fn key() -> FlowKey {
    FlowKey {
        proto: 6,
        client: Endpoint {
            ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            port: 50_000,
        },
        server: Endpoint {
            ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            port: 88,
        },
    }
}

fn ctx(id: i64, gap: u64) -> StreamCtx {
    StreamCtx {
        ts_ns: 1,
        chunk_id: 0,
        frame: 0,
        id: FlowId(id),
        key: key(),
        gap_before: gap,
    }
}

#[test]
fn a_gap_abandons_the_flow_and_requests_are_ignored() {
    let mut a = analyzer();
    let mut out = Vec::new();
    let reply = krb::tcp_record(&krb::kdc_rep(false, REALM, "jdoe"));
    // Client-to-server data is never parsed.
    a.on_stream(&ctx(1, 0), Direction::ToServer, &reply, &mut out);
    assert_eq!(out, Vec::new());
    // Half a reply, a gap, then a complete one: nothing is emitted for this flow any more.
    a.on_stream(&ctx(1, 0), Direction::ToClient, &reply[..3], &mut out);
    a.on_stream(&ctx(1, 10), Direction::ToClient, &reply, &mut out);
    a.on_stream(&ctx(1, 0), Direction::ToClient, &reply, &mut out);
    assert_eq!(out, Vec::new());
}

#[test]
fn foreign_framing_on_port_88_is_dropped() {
    let mut a = analyzer();
    let mut out = Vec::new();
    // High bit of the length prefix set: not a message.
    a.on_stream(
        &ctx(2, 0),
        Direction::ToClient,
        &[0x80, 0, 0, 4, 1, 2, 3, 4],
        &mut out,
    );
    let reply = krb::tcp_record(&krb::kdc_rep(false, REALM, "jdoe"));
    a.on_stream(&ctx(2, 0), Direction::ToClient, &reply, &mut out);
    assert_eq!(out, Vec::new());
    // Random bytes with a plausible prefix: framed, not recognized.
    a.on_stream(
        &ctx(3, 0),
        Direction::ToClient,
        &[0, 0, 0, 3, 9, 9, 9],
        &mut out,
    );
    assert_eq!(out, Vec::new());
}

#[test]
fn heads_are_bounded_and_a_cut_message_is_emitted_at_flow_end() {
    let config = AnalyzerConfig {
        servers: ServersConfig {
            max_kerberos_flows: 1,
            max_kerberos_head: 64,
        },
        ..AnalyzerConfig::default()
    };
    let mut a = ServersAnalyzer::new(&config);
    let mut out = Vec::new();
    let reply = krb::tcp_record(&krb::kdc_rep(false, REALM, "jdoe"));
    // The head (64 bytes) is enough for the realm; the rest of the message is skipped.
    a.on_stream(&ctx(4, 0), Direction::ToClient, &reply, &mut out);
    assert_eq!(out.len(), 1);
    // A second flow is over the flow limit.
    a.on_stream(&ctx(5, 0), Direction::ToClient, &reply, &mut out);
    assert_eq!(out.len(), 1);
    // The first one starts another reply, cut by the end of the flow.
    a.on_stream(&ctx(4, 0), Direction::ToClient, &reply[..40], &mut out);
    assert_eq!(out.len(), 1);
    let end = netsift_flow::FlowCtx {
        id: FlowId(4),
        key: key(),
        first_ts_ns: 0,
        last_ts_ns: 9,
        to_server: netsift_flow::DirStats::default(),
        to_client: netsift_flow::DirStats::default(),
        tcp_state: None,
        end: netsift_flow::EndReason::EndOfCapture,
    };
    a.on_flow_end(&end, &mut out);
    assert_eq!(out.len(), 2);
    assert!(matches!(&out[1], Record::Server(ServerRecord::Kerberos(k)) if k.ts == 9));
}

#[test]
fn udp_noise_on_server_ports_is_ignored() {
    let mut sc = Scenario::new();
    let (a, b) = (hosts::workstation(), hosts::router());
    sc.udp(b, a, 123, 40_000, &[0x24; 20]);
    sc.udp(b, a, 88, 40_001, &[0x6b, 0x01, 0x00]);
    sc.udp(b, a, 67, 68, &[2; 100]);
    // Client-mode NTP from port 123 (symmetric clients) is not a server response.
    sc.udp(a, b, 123, 123, &netsift_fixtures::proto::ntp::request(1));
    assert_eq!(run(&sc), Vec::new());
}
