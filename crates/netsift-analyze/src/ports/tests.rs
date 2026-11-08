use std::fmt::Write as _;
use std::net::Ipv4Addr;

use netsift_fixtures::craft::{Side, TcpConv, TcpSeg};
use netsift_fixtures::scenario::{DnsExchange, FtpLogin, HttpGet, TcpOptions, TlsHandshake};
use netsift_fixtures::scenarios::{Kind, generate, hosts};
use netsift_fixtures::{Host, Packet, Scenario};

use super::*;
use crate::testutil;

fn target() -> Host {
    Host::v4([0x02, 0x00, 0x5e, 0x10, 0x00, 0x50], [192, 168, 1, 50])
}

fn ports_of(packets: &[Packet], config: &AnalyzerConfig) -> Vec<OpenPortSeen> {
    let mut analyzer = PortsAnalyzer::new(config);
    merge_ports(&testutil::run(&mut analyzer, packets))
}

fn render(ports: &[OpenPortSeen]) -> String {
    let mut s = String::new();
    for p in ports {
        writeln!(
            s,
            "{} {}/{} iana={} evidence={} detected={} banner={:?} {}..{}",
            p.ip,
            if p.transport == ip_proto::TCP {
                "tcp"
            } else {
                "udp"
            },
            p.port,
            p.iana().unwrap_or("-"),
            p.evidence.as_str(),
            p.detected.unwrap_or("-"),
            p.banner.as_deref().unwrap_or(""),
            p.first_ts,
            p.last_ts
        )
        .unwrap();
    }
    s
}

/// SYN-ACK on 80 and 443, RST on 22 (closed), one DNS exchange over UDP (spec fixture).
fn scan_scenario() -> Vec<Packet> {
    let mut sc = Scenario::new();
    let ws = hosts::workstation();
    for (i, port) in [80_u16, 443, 22].into_iter().enumerate() {
        let conv = TcpConv::new(ws, target(), 40_000 + u16::try_from(i).unwrap(), port);
        sc.push_frame(conv.syn());
        if port == 22 {
            let rst = TcpSeg::new(0).rst().ack(conv.seq(Side::Client, 0));
            sc.push_frame(conv.frame(Side::Server, &rst, &[]));
        } else {
            sc.push_frame(conv.syn_ack());
            sc.push_frame(conv.rst(Side::Client, 0));
        }
    }
    sc.dns(
        ws,
        hosts::router(),
        &DnsExchange::a("www.example.test", [203, 0, 113, 80]),
    );
    sc.into_packets()
}

#[test]
fn syn_scan_and_udp_reply_give_exactly_three_ports() {
    let ports = ports_of(&scan_scenario(), &AnalyzerConfig::default());
    let keys: Vec<_> = ports
        .iter()
        .map(|p| (p.ip.to_string(), p.transport, p.port, p.evidence))
        .collect();
    assert_eq!(
        keys,
        vec![
            ("192.168.1.1".to_owned(), 17, 53, PortEvidence::UdpReply),
            ("192.168.1.50".to_owned(), 6, 80, PortEvidence::SynAck),
            ("192.168.1.50".to_owned(), 6, 443, PortEvidence::SynAck),
        ]
    );
    // The client ports never count: the workstation answered nothing.
    assert!(ports.iter().all(|p| p.ip != hosts::workstation().ip));
}

#[test]
fn services_and_banners_are_detected_from_server_data() {
    let mut sc = Scenario::new();
    let ws = hosts::workstation();
    let server = target();
    sc.http_get(ws, server, &HttpGet::default());
    sc.tls_handshake(ws, server, &TlsHandshake::default());
    sc.ftp_login(ws, server, &FtpLogin::default());
    let mut ssh = sc.tcp_open(ws, server, &TcpOptions::new(2222));
    ssh.server_send(b"SSH-2.0-OpenSSH_9.6\r\n");
    ssh.client_send(b"SSH-2.0-client\r\n");
    ssh.close();
    insta::assert_snapshot!(render(&ports_of(
        &sc.into_packets(),
        &AnalyzerConfig::default()
    )));
}

#[test]
fn midstream_connections_use_the_service_port() {
    let mut sc = Scenario::new();
    let ws = hosts::workstation();
    // Picked up midstream: the first packet seen is the server greeting.
    let smtp = TcpConv::new(ws, target(), 51_000, 25);
    sc.push_frame(smtp.data(Side::Server, 0, 0, b"220 mail.example.test ESMTP ready\r\n"));
    sc.push_frame(smtp.data(Side::Client, 0, 36, b"EHLO ws\r\n"));
    // Same, but the client speaks first: the client port is never taken for a service.
    let web = TcpConv::new(ws, target(), 51_001, 8080);
    sc.push_frame(web.data(Side::Client, 0, 0, b"GET / HTTP/1.1\r\n\r\n"));
    sc.push_frame(web.data(Side::Server, 0, 18, b"HTTP/1.1 200 OK\r\n\r\n"));
    // Two ephemeral ports: the server side cannot be told, nothing is recorded.
    let p2p = TcpConv::new(ws, target(), 50_001, 50_002);
    sc.push_frame(p2p.data(Side::Server, 0, 0, b"hello"));
    sc.push_frame(p2p.data(Side::Client, 0, 5, b"hello"));
    let ports = ports_of(&sc.into_packets(), &AnalyzerConfig::default());
    insta::assert_snapshot!(render(&ports));
    assert!(ports.iter().all(|p| p.evidence == PortEvidence::ServerData));
}

#[test]
fn demo_scenario_snapshot() {
    insta::assert_snapshot!(render(&ports_of(
        &generate(Kind::Demo, 3, 7),
        &AnalyzerConfig::default()
    )));
}

#[test]
fn results_do_not_depend_on_flush_settings() {
    let packets = [generate(Kind::Demo, 3, 7), scan_scenario()].concat();
    let mut packets = packets;
    packets.sort_by_key(|p| p.ts_ns);
    let tiny = AnalyzerConfig {
        ports: PortsConfig {
            max_pending: 1,
            flush_interval_ns: 0,
            ..PortsConfig::default()
        },
        ..AnalyzerConfig::default()
    };
    assert_eq!(
        render(&ports_of(&packets, &tiny)),
        render(&ports_of(&packets, &AnalyzerConfig::default()))
    );
}

#[test]
fn tracking_bound_keeps_syn_ack_detection() {
    let config = AnalyzerConfig {
        ports: PortsConfig {
            max_tracked_flows: 0,
            ..PortsConfig::default()
        },
        ..AnalyzerConfig::default()
    };
    let mut sc = Scenario::new();
    sc.http_get(hosts::workstation(), target(), &HttpGet::default());
    let ports = ports_of(&sc.into_packets(), &config);
    assert_eq!(ports.len(), 1);
    assert_eq!(ports[0].port, 80);
    // Without tracking, the content is not inspected.
    assert_eq!(ports[0].detected, None);
}

#[test]
fn content_detection() {
    let cases: [(&[u8], u16, Option<&str>); 14] = [
        (b"HTTP/1.1 200 OK\r\n", 8000, Some("http")),
        (b"SSH-2.0-dropbear\r\n", 2200, Some("ssh")),
        (&[0x16, 0x03, 0x03, 0x00, 0x31], 8443, Some("tls")),
        (&[0x15, 0x03, 0x01, 0x00, 0x02], 443, Some("tls")),
        (&[0x16, 0x03, 0x09, 0x00, 0x31], 443, None),
        (&[0, 0, 0, 0x40, 0xfe, b'S', b'M', b'B'], 445, Some("smb")),
        (&[0, 0, 0, 0x40, 0xff, b'S', b'M', b'B'], 139, Some("smb")),
        (b"220 (vsFTPd 3.0.5)\r\n", 2121, Some("ftp")),
        (b"220-mx.example ESMTP\r\n", 2525, Some("smtp")),
        (b"220 welcome\r\n", 21, Some("ftp")),
        (b"220 welcome\r\n", 9999, None),
        (b"+OK POP3 ready\r\n", 110, Some("pop3")),
        (b"* OK IMAP4rev1\r\n", 143, Some("imap")),
        (b"RFB 003.008\n", 5900, Some("vnc")),
    ];
    for (data, port, expected) in cases {
        assert_eq!(detect_service(data, port), expected, "{data:?}");
    }
    assert_eq!(detect_service(b"", 80), None);
    assert_eq!(detect_service(b"\x00", 445), None);
}

#[test]
fn banners_are_first_lines_of_greetings() {
    assert_eq!(
        banner(b"SSH-2.0-OpenSSH_9.6\r\nmore", Some("ssh")).as_deref(),
        Some("SSH-2.0-OpenSSH_9.6")
    );
    assert_eq!(
        banner(b"220 hi\x01\xff there\n", Some("ftp")).as_deref(),
        Some("220 hi.. there")
    );
    assert_eq!(banner(b"HTTP/1.1 200 OK\r\n", Some("http")), None);
    assert_eq!(banner(b"\r\n", Some("ssh")), None);
    let long = [b'A'; 1000];
    assert_eq!(banner(&long, Some("smtp")).unwrap().len(), MAX_BANNER);
}

#[test]
fn midstream_server_prefers_service_ports() {
    let key = |a: u16, b: u16| FlowKey {
        proto: ip_proto::TCP,
        client: Endpoint {
            ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            port: a,
        },
        server: Endpoint {
            ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            port: b,
        },
    };
    assert_eq!(
        midstream_server(&key(443, 50_000)).map(|e| e.port),
        Some(443)
    );
    assert_eq!(midstream_server(&key(50_000, 22)).map(|e| e.port), Some(22));
    assert_eq!(
        midstream_server(&key(50_000, 8080)).map(|e| e.port),
        Some(8080)
    );
    assert_eq!(midstream_server(&key(1863, 3389)).map(|e| e.port), None);
    assert_eq!(midstream_server(&key(80, 445)), None);
    assert_eq!(midstream_server(&key(50_000, 60_000)), None);
}

#[test]
fn hostile_payloads_never_panic() {
    let mut seed = 0x9e37_79b9_u32;
    for len in 0..300usize {
        let data: Vec<u8> = (0..len)
            .map(|_| {
                seed ^= seed << 13;
                seed ^= seed >> 17;
                seed ^= seed << 5;
                seed.to_le_bytes()[0]
            })
            .collect();
        let service = detect_service(&data, 21);
        let _ = banner(&data, service.or(Some("ssh")));
    }
}
