//! Frames produced by the scenario builder, decoded with etherparse and protocol parsers.

mod common;

use std::io::Cursor;
use std::net::{Ipv4Addr, Ipv6Addr};

use common::{check_tcp_connection, ip_pair, tcp_segment, udp_payload};
use netsift_fixtures::proto::netbios::{
    self, AnnouncementKind, HostAnnouncement, NetbiosName, SV_TYPE_MASTER_BROWSER, SV_TYPE_NT,
};
use netsift_fixtures::proto::png::{PNG_SIGNATURE, png_image};
use netsift_fixtures::proto::snmp::{SnmpValue, SnmpVersion};
use netsift_fixtures::proto::x509::{CertSpec, self_signed_certificate};
use netsift_fixtures::scenario::{
    DnsExchange, FtpLogin, HttpGet, Scenario, SnmpGet, TcpOptions, TlsHandshake,
};
use netsift_fixtures::scenarios::hosts;
use netsift_fixtures::{Host, Packet};
use simple_dns::rdata::RData;
use tls_parser::{TlsExtension, TlsMessage, TlsMessageHandshake};

fn frames(packets: &[Packet], range: std::ops::Range<usize>) -> Vec<&[u8]> {
    packets[range].iter().map(|p| p.data.as_slice()).collect()
}

#[test]
fn ethernet_and_ip_addresses_are_configurable() {
    let a = Host::v4([0x0a, 1, 2, 3, 4, 5], [10, 9, 8, 7]);
    let b = Host::v4([0x0a, 6, 7, 8, 9, 10], [172, 16, 0, 1]);
    let mut sc = Scenario::new();
    sc.udp(a, b, 1234, 5678, b"hello");
    let p = &sc.packets()[0];
    assert_eq!(&p.data[..6], &b.mac);
    assert_eq!(&p.data[6..12], &a.mac);
    assert_eq!(ip_pair(&p.data), ("10.9.8.7".into(), "172.16.0.1".into()));
    assert_eq!(udp_payload(&p.data), Some((1234, 5678, b"hello".to_vec())));
    assert_eq!(p.ts_ns, netsift_fixtures::scenario::DEFAULT_START_NS);
}

#[test]
fn dns_queries_and_responses_of_several_types() {
    let mut sc = Scenario::new();
    let (ws, resolver) = (hosts::workstation(), hosts::router());
    let v6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x42);
    let a = sc.dns(
        ws,
        resolver,
        &DnsExchange::a("a.example.test", [192, 0, 2, 1]).with_id(7),
    );
    let aaaa = sc.dns(
        hosts::workstation_v6(),
        hosts::router_v6(),
        &DnsExchange::aaaa("v6.example.test", v6),
    );
    let cname = sc.dns(
        ws,
        resolver,
        &DnsExchange::cname("www.example.test", "cdn.example.net", [192, 0, 2, 2]),
    );
    let nx = sc.dns(
        ws,
        resolver,
        &DnsExchange::nxdomain(
            "nope.example.test",
            netsift_fixtures::proto::dns::DnsType::Mx,
        ),
    );
    let lost = sc.dns(
        ws,
        resolver,
        &DnsExchange::a("lost.example.test", [192, 0, 2, 3]).unanswered(),
    );
    assert_eq!(lost.response, None);
    let packets = sc.packets();

    let decode = |idx: usize| {
        let (sport, dport, payload) = udp_payload(&packets[idx].data).unwrap();
        (sport, dport, payload)
    };

    // A
    let (sport, dport, q) = decode(a.query);
    assert_eq!((sport, dport), (a.client_port, 53));
    let q = simple_dns::Packet::parse(&q).unwrap();
    assert_eq!(q.id(), 7);
    assert_eq!(q.questions[0].qname.to_string(), "a.example.test");
    let (sport, dport, r) = decode(a.response.unwrap());
    assert_eq!((sport, dport), (53, a.client_port));
    let r = simple_dns::Packet::parse(&r).unwrap();
    assert_eq!(r.id(), 7);
    match &r.answers[0].rdata {
        RData::A(rec) => assert_eq!(Ipv4Addr::from(rec.address), Ipv4Addr::new(192, 0, 2, 1)),
        other => panic!("unexpected {other:?}"),
    }
    assert_eq!(r.answers[0].name.to_string(), "a.example.test");

    // AAAA over IPv6
    let resp = aaaa.response.unwrap();
    assert_eq!(ip_pair(&packets[resp].data).0, "2001:db8:1::1");
    let payload = decode(resp).2;
    let r = simple_dns::Packet::parse(&payload).unwrap();
    assert_eq!(r.id(), aaaa.id);
    match &r.answers[0].rdata {
        RData::AAAA(rec) => assert_eq!(Ipv6Addr::from(rec.address), v6),
        other => panic!("unexpected {other:?}"),
    }

    // CNAME chain
    let payload = decode(cname.response.unwrap()).2;
    let r = simple_dns::Packet::parse(&payload).unwrap();
    assert_eq!(r.answers.len(), 2);
    match &r.answers[0].rdata {
        RData::CNAME(target) => assert_eq!(target.0.to_string(), "cdn.example.net"),
        other => panic!("unexpected {other:?}"),
    }
    assert_eq!(r.answers[1].name.to_string(), "cdn.example.net");

    // NXDOMAIN
    let payload = decode(nx.response.unwrap()).2;
    let r = simple_dns::Packet::parse(&payload).unwrap();
    assert_eq!(r.rcode(), simple_dns::RCODE::NameError);
    assert_eq!(r.answers.len(), 0);
}

#[test]
fn http_get_is_a_coherent_tcp_connection_with_a_png_body() {
    let mut sc = Scenario::new();
    let mut get = HttpGet::default();
    get.tcp.mss = 512;
    get.tcp.client_port = Some(50_000);
    let ex = sc.http_get(hosts::workstation(), hosts::web_server(), &get);
    let packets = sc.packets();
    assert_eq!(ex.packets, 0..packets.len());
    assert!(
        ex.response.len() > 3,
        "response split over several segments"
    );

    let segs: Vec<_> = packets
        .iter()
        .map(|p| tcp_segment(&p.data).unwrap())
        .collect();
    assert!(segs[0].syn && segs[0].ack.is_none());
    assert!(segs[1].syn && segs[1].ack.is_some());
    assert!(!segs[2].syn && segs[2].ack.is_some());
    assert_eq!((segs[0].src_port, segs[0].dst_port), (50_000, 80));
    for i in ex.response.clone() {
        assert_eq!(segs[i].src_port, 80);
        assert_eq!(
            segs[i].psh,
            i + 1 == ex.response.end,
            "PSH on the last segment"
        );
    }

    let (client, server) = check_tcp_connection(&frames(packets, ex.packets.clone()), 512);
    assert_eq!(client, get.request_bytes());

    let mut headers = [httparse::EMPTY_HEADER; 16];
    let mut req = httparse::Request::new(&mut headers);
    assert!(req.parse(&client).unwrap().is_complete());
    assert_eq!(req.method, Some("GET"));
    assert_eq!(req.path, Some("/images/logo.png"));

    let mut headers = [httparse::EMPTY_HEADER; 16];
    let mut resp = httparse::Response::new(&mut headers);
    let body_start = match resp.parse(&server).unwrap() {
        httparse::Status::Complete(n) => n,
        httparse::Status::Partial => panic!("incomplete response head"),
    };
    assert_eq!(resp.code, Some(200));
    let length: usize = resp
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("content-length"))
        .map(|h| std::str::from_utf8(h.value).unwrap().parse().unwrap())
        .unwrap();
    let body = &server[body_start..];
    assert_eq!(body.len(), length);
    assert_png(body, 128, 96);
}

fn assert_png(data: &[u8], width: u32, height: u32) {
    assert_eq!(&data[..8], &PNG_SIGNATURE);
    assert_eq!(&data[12..16], b"IHDR");
    let reader = png::Decoder::new(Cursor::new(data)).read_info().unwrap();
    let info = reader.info();
    assert_eq!((info.width, info.height), (width, height));
    assert_eq!(info.color_type, png::ColorType::Rgb);
    let mut reader = reader;
    let mut buf = vec![0; reader.output_buffer_size().unwrap()];
    let frame = reader.next_frame(&mut buf).unwrap();
    assert_eq!(frame.buffer_size(), (width * height * 3) as usize);
}

#[test]
fn png_images_decode() {
    for (w, h) in [(1, 1), (16, 9), (300, 200)] {
        assert_png(&png_image(w, h), w, h);
    }
}

#[test]
fn tls_handshake_parses_with_tls_parser_and_x509_parser() {
    let mut sc = Scenario::new();
    let mut hs = TlsHandshake::new("vault.example.test");
    hs.tcp.mss = 400;
    let ex = sc.tls_handshake(hosts::workstation(), hosts::tls_server(), &hs);
    let packets = sc.packets();
    assert!(
        ex.response.len() > 1,
        "server flight spans several segments"
    );
    let (client, server) = check_tcp_connection(&frames(packets, ex.packets.clone()), 400);
    assert_eq!(tcp_segment(&packets[0].data).unwrap().dst_port, 443);

    let (rest, record) = tls_parser::parse_tls_plaintext(&client).unwrap();
    assert_eq!(rest.len(), 0);
    let TlsMessage::Handshake(TlsMessageHandshake::ClientHello(ch)) = &record.msg[0] else {
        panic!("expected ClientHello");
    };
    let offered: Vec<u16> = ch.ciphers.iter().map(|c| c.0).collect();
    assert_eq!(offered, hs.cipher_suites);
    let (_, exts) = tls_parser::parse_tls_client_hello_extensions(ch.ext.unwrap()).unwrap();
    let sni = exts.iter().find_map(|e| match e {
        TlsExtension::SNI(names) => Some(names[0].1),
        _ => None,
    });
    assert_eq!(sni, Some(&b"vault.example.test"[..]));
    let alpn = exts.iter().find_map(|e| match e {
        TlsExtension::ALPN(protos) => Some(protos.clone()),
        _ => None,
    });
    assert_eq!(alpn, Some(vec![&b"h2"[..], &b"http/1.1"[..]]));

    let mut rest = server.as_slice();
    let mut messages = Vec::new();
    while !rest.is_empty() {
        let (r, record) = tls_parser::parse_tls_plaintext(rest).unwrap();
        messages.extend(record.msg);
        rest = r;
    }
    assert_eq!(messages.len(), 3);
    let TlsMessage::Handshake(TlsMessageHandshake::ServerHello(sh)) = &messages[0] else {
        panic!("expected ServerHello");
    };
    assert_eq!(sh.cipher.0, hs.selected_suite);
    let (_, sexts) = tls_parser::parse_tls_extensions(sh.ext.unwrap()).unwrap();
    assert!(
        sexts
            .iter()
            .any(|e| matches!(e, TlsExtension::ALPN(p) if p == &vec![&b"h2"[..]]))
    );
    let TlsMessage::Handshake(TlsMessageHandshake::Certificate(certs)) = &messages[1] else {
        panic!("expected Certificate");
    };
    assert_eq!(certs.cert_chain.len(), 1);
    assert_eq!(certs.cert_chain[0].data, hs.certificate_chain[0].as_slice());
    assert!(matches!(
        messages[2],
        TlsMessage::Handshake(TlsMessageHandshake::ServerDone(_))
    ));
    assert_self_signed(certs.cert_chain[0].data, "vault.example.test");
}

fn assert_self_signed(der: &[u8], cn: &str) {
    use x509_parser::prelude::*;
    let (rest, cert) = X509Certificate::from_der(der).unwrap();
    assert_eq!(rest.len(), 0);
    assert_eq!(cert.version(), X509Version::V3);
    let subject_cn = cert
        .subject()
        .iter_common_name()
        .next()
        .unwrap()
        .as_str()
        .unwrap();
    assert_eq!(subject_cn, cn);
    assert_eq!(
        cert.subject().to_string(),
        cert.issuer().to_string(),
        "self-signed"
    );
    assert_eq!(cert.validity().not_before.timestamp(), 1_672_531_200);
    assert_eq!(cert.validity().not_after.timestamp(), 1_988_150_400);
    let san = cert.subject_alternative_name().unwrap().unwrap();
    assert!(
        san.value
            .general_names
            .iter()
            .any(|n| matches!(n, GeneralName::DNSName(d) if *d == cn))
    );
    assert!(cert.public_key().parsed().is_ok());
}

#[test]
fn certificates_cover_generalized_time_and_long_names() {
    let mut spec = CertSpec::new("long-validity.example.test");
    spec.not_after = 4_102_444_800 + 86_400; // 2100-01-02: GeneralizedTime
    spec.dns_names.push("alt.example.test".into());
    spec.serial = u64::MAX;
    let der = self_signed_certificate(&spec);
    let (_, cert) = x509_parser::parse_x509_certificate(&der).unwrap();
    assert_eq!(cert.validity().not_after.timestamp(), spec.not_after);
    assert_eq!(
        cert.raw_serial(),
        &[0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
    );
}

#[test]
fn nbns_query_response_and_registration() {
    let mut sc = Scenario::new();
    let name = NetbiosName::new("FILESRV01", netbios::SUFFIX_SERVER);
    let reg = sc.nbns_registration(hosts::file_server(), hosts::broadcast(), 1, &name, false);
    let q = sc.nbns_query(hosts::workstation(), hosts::broadcast(), 2, &name);
    let r = sc.nbns_query_response(hosts::file_server(), hosts::workstation(), 2, &name);
    let packets = sc.packets();

    let encoded = name.encode();
    let (sp, dp, reg_payload) = udp_payload(&packets[reg].data).unwrap();
    assert_eq!((sp, dp), (137, 137));
    assert_eq!(&packets[reg].data[..6], &[0xff; 6], "broadcast MAC");
    assert_eq!(ip_pair(&packets[reg].data).1, "192.168.1.255");
    assert_eq!(&reg_payload[2..4], &[0x29, 0x10], "registration, RD, B");
    assert_eq!(&reg_payload[4..12], &[0, 1, 0, 0, 0, 0, 0, 1]);
    assert_eq!(&reg_payload[12..46], &encoded);
    assert_eq!(&reg_payload[reg_payload.len() - 4..], &[192, 168, 1, 20]);
    assert_eq!(
        decode_netbios_name(&reg_payload[13..45]),
        ("FILESRV01".into(), 0x20)
    );

    let (_, _, q_payload) = udp_payload(&packets[q].data).unwrap();
    assert_eq!(&q_payload[..4], &[0, 2, 0x01, 0x10]);
    assert_eq!(&q_payload[12..46], &encoded);
    assert_eq!(&q_payload[46..], &[0, 0x20, 0, 1], "NB, IN");

    let (_, _, r_payload) = udp_payload(&packets[r].data).unwrap();
    assert_eq!(&r_payload[..4], &[0, 2, 0x85, 0x00]);
    assert_eq!(&r_payload[r_payload.len() - 4..], &[192, 168, 1, 20]);
}

fn decode_netbios_name(half_ascii: &[u8]) -> (String, u8) {
    let raw: Vec<u8> = half_ascii
        .chunks(2)
        .map(|c| ((c[0] - b'A') << 4) | (c[1] - b'A'))
        .collect();
    let name = String::from_utf8(raw[..15].to_vec()).unwrap();
    (name.trim_end().to_owned(), raw[15])
}

#[test]
fn smb_browser_host_announcement() {
    let mut sc = Scenario::new();
    let ann = HostAnnouncement {
        kind: AnnouncementKind::LocalMaster,
        server_name: "dc01".into(),
        os_major: 6,
        os_minor: 1,
        server_type: SV_TYPE_NT | SV_TYPE_MASTER_BROWSER,
        comment: "Domain controller".into(),
        ..HostAnnouncement::default()
    };
    let idx = sc.smb_host_announcement(hosts::file_server(), hosts::broadcast(), &ann);
    let (sp, dp, dgm) = udp_payload(&sc.packets()[idx].data).unwrap();
    assert_eq!((sp, dp), (138, 138));
    assert_eq!(dgm[0], 0x11, "DIRECT_GROUP datagram");
    assert_eq!(&dgm[4..8], &[192, 168, 1, 20]);
    assert_eq!(u16::from_be_bytes([dgm[8], dgm[9]]), 138);
    let dgm_len = usize::from(u16::from_be_bytes([dgm[10], dgm[11]]));
    assert_eq!(dgm_len, dgm.len() - 14);
    assert_eq!(decode_netbios_name(&dgm[15..47]), ("DC01".into(), 0x00));
    assert_eq!(
        decode_netbios_name(&dgm[49..81]),
        ("WORKGROUP".into(), 0x1e)
    );

    let smb = &dgm[82..];
    assert_eq!(&smb[..5], b"\xffSMB\x25");
    assert_eq!(smb[32], 17, "word count");
    let data_count = usize::from(u16::from_le_bytes([smb[33 + 22], smb[33 + 23]]));
    let data_offset = usize::from(u16::from_le_bytes([smb[33 + 24], smb[33 + 25]]));
    assert_eq!(&smb[69..86], b"\\MAILSLOT\\BROWSE\0");
    let browser = &smb[data_offset..data_offset + data_count];
    assert_eq!(data_offset + data_count, smb.len());
    assert_eq!(browser[0], 0x0f, "LocalMasterAnnouncement");
    assert_eq!(
        u32::from_le_bytes(browser[2..6].try_into().unwrap()),
        720_000
    );
    assert_eq!(&browser[6..22], b"DC01\0\0\0\0\0\0\0\0\0\0\0\0");
    assert_eq!(&browser[22..24], &[6, 1], "OS version");
    assert_eq!(
        u32::from_le_bytes(browser[24..28].try_into().unwrap()),
        SV_TYPE_NT | SV_TYPE_MASTER_BROWSER
    );
    assert_eq!(&browser[30..32], &[0x55, 0xaa]);
    assert_eq!(&browser[32..], b"Domain controller\0");
}

#[test]
fn snmp_v1_and_v2c_requests_carry_the_community() {
    for version in [SnmpVersion::V1, SnmpVersion::V2c] {
        let mut sc = Scenario::new();
        let get = SnmpGet {
            version,
            community: "s3cr3t-community".into(),
            request_id: 4242,
            ..SnmpGet::default()
        };
        let ex = sc.snmp_get(hosts::workstation(), hosts::router(), &get);
        let (sp, dp, req) = udp_payload(&sc.packets()[ex.request].data).unwrap();
        assert_eq!((sp, dp), (ex.client_port, 161));
        let parse = match version {
            SnmpVersion::V1 => snmp_parser::parse_snmp_v1,
            SnmpVersion::V2c => snmp_parser::parse_snmp_v2c,
        };
        let (rest, msg) = parse(&req).unwrap();
        assert_eq!(rest.len(), 0);
        assert_eq!(msg.community, "s3cr3t-community");
        assert_eq!(msg.pdu_type(), snmp_parser::PduType::GetRequest);
        let oids: Vec<String> = msg.vars_iter().map(|v| v.oid.to_id_string()).collect();
        assert_eq!(oids, get.oids);

        let (_, _, resp) = udp_payload(&sc.packets()[ex.response.unwrap()].data).unwrap();
        let (_, msg) = parse(&resp).unwrap();
        assert_eq!(msg.pdu_type(), snmp_parser::PduType::Response);
        assert_eq!(msg.vars_iter().count(), 2);
    }
}

#[test]
fn snmp_value_encodings() {
    let mut sc = Scenario::new();
    let get = SnmpGet {
        oids: vec!["1.3.6.1.2.1.1.3.0".into(), "1.3.6.1.2.1.2.2.1.10.1".into()],
        response: Some(vec![
            SnmpValue::TimeTicks(123_456),
            SnmpValue::Counter32(u32::MAX),
        ]),
        ..SnmpGet::default()
    };
    let ex = sc.snmp_get(hosts::workstation(), hosts::router(), &get);
    let (_, _, resp) = udp_payload(&sc.packets()[ex.response.unwrap()].data).unwrap();
    let (_, msg) = snmp_parser::parse_snmp_v2c(&resp).unwrap();
    let vals: Vec<String> = msg.vars_iter().map(|v| format!("{:?}", v.val)).collect();
    assert!(vals[0].contains("123456"), "{vals:?}");
    assert!(vals[1].contains("4294967295"), "{vals:?}");
}

#[test]
fn ftp_login_over_tcp_21() {
    let mut sc = Scenario::new();
    let login = FtpLogin {
        user: "bob".into(),
        password: "hunter2".into(),
        accepted: false,
        ..FtpLogin::default()
    };
    let ex = sc.ftp_login(hosts::workstation(), hosts::ftp_server(), &login);
    let packets = sc.packets();
    let (client, server) = check_tcp_connection(&frames(packets, ex.packets.clone()), 1460);
    assert_eq!(client, b"USER bob\r\nPASS hunter2\r\nQUIT\r\n");
    let server = String::from_utf8(server).unwrap();
    assert!(server.starts_with("220 (vsFTPd 3.0.5)\r\n331 "));
    assert!(server.contains("\r\n530 Login incorrect.\r\n221 Goodbye.\r\n"));
    let user = tcp_segment(&packets[ex.user.start].data).unwrap();
    assert_eq!(user.dst_port, 21);
    assert_eq!(user.payload, b"USER bob\r\n");
    assert_eq!(
        tcp_segment(&packets[ex.pass.start].data).unwrap().payload,
        b"PASS hunter2\r\n"
    );
}

#[test]
fn tcp_over_ipv6_and_explicit_ports() {
    let mut sc = Scenario::new();
    let mut opts = TcpOptions::new(8080);
    opts.client_port = Some(40_000);
    opts.mss = 100;
    let mut s = sc.tcp_open(hosts::workstation_v6(), hosts::router_v6(), &opts);
    s.client_send(&[b'x'; 250]);
    s.scenario().advance(1_000_000_000);
    s.server_send(&[b'y'; 99]);
    let range = s.close();
    let packets = sc.packets();
    let (c, srv) = check_tcp_connection(&frames(packets, range), 100);
    assert_eq!((c.len(), srv.len()), (250, 99));
    assert_eq!(ip_pair(&packets[0].data).0, "2001:db8:1::10");
    let first = tcp_segment(&packets[0].data).unwrap();
    assert_eq!((first.src_port, first.dst_port), (40_000, 8080));
    assert!(
        packets.windows(2).all(|w| w[0].ts_ns < w[1].ts_ns),
        "time is monotonic"
    );
}

#[test]
fn ephemeral_ports_and_seeds_are_deterministic() {
    let run = |seed| {
        let mut sc = Scenario::new().with_seed(seed);
        (sc.ephemeral_port(), sc.ephemeral_port())
    };
    assert_eq!(run(5), run(5));
    let (p1, p2) = run(5);
    assert_eq!(p2, p1 + 1);
    assert!(p1 >= 49_152);
}
