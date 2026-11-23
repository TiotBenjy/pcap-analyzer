//! Tests of the SIP analyzer on the synthetic showcase (`netsift_fixtures::sip`).

use std::fmt::Write as _;

use netsift_fixtures::Scenario;
use netsift_fixtures::sip::{self as fx, sip_hosts};

use super::{SipAnalyzer, SipRecord, SipTransport};
use crate::record::{Credential, Record, SecretState};
use crate::registry::AnalyzerConfig;
use crate::testutil;

fn run(sc: &Scenario) -> (Vec<SipRecord>, Vec<Credential>) {
    let mut analyzer = SipAnalyzer::new(&AnalyzerConfig::default());
    let records = testutil::run(&mut analyzer, sc.packets());
    let mut sip = Vec::new();
    let mut creds = Vec::new();
    for r in records {
        match r {
            Record::Sip(s) => sip.push(*s),
            Record::Credential(c) => creds.push(c),
            other => panic!("unexpected record {other:?}"),
        }
    }
    (sip, creds)
}

#[test]
fn showcase_messages_are_all_recorded() {
    let mut sc = Scenario::new();
    let n = fx::sip_showcase(&mut sc);
    let (sip, _) = run(&sc);
    assert_eq!(sip.len(), n.messages());
    assert_eq!(
        sip.iter().filter(|r| r.message.is_request()).count(),
        n.requests
    );
    assert_eq!(
        sip.iter()
            .filter(|r| r.scanner == Some("SIPVicious"))
            .count(),
        n.scanner
    );
    // RTP is never taken for SIP.
    assert!(sip.iter().all(|r| r.src.port == fx::PORT
        || r.dst.port == fx::PORT
        || r.src.port == fx::SCANNER_PORT));
    // Every UDP message carries its flow.
    assert!(sip.iter().all(|r| r.flow_id.is_some()));
}

#[test]
fn tcp_messages_are_framed_across_segments() {
    let mut sc = Scenario::new();
    fx::sip_tcp_call(&mut sc, fx::CALL_TCP, &fx::carol_phone(), &fx::pbx_party());
    let (sip, _) = run(&sc);
    let kinds: Vec<String> = sip
        .iter()
        .map(|r| {
            assert_eq!(r.transport, SipTransport::Tcp);
            match r.message.status() {
                Some(s) => format!("{s} {}", r.message.method().unwrap_or("-")),
                None => r.message.method().unwrap_or("-").to_owned(),
            }
        })
        .collect();
    assert_eq!(
        kinds,
        [
            "INVITE",
            "100 INVITE",
            "180 INVITE",
            "200 INVITE",
            "ACK",
            "BYE",
            "200 BYE"
        ]
    );
    let invite = &sip[0];
    assert_eq!(invite.src.ip, sip_hosts::carol().ip);
    assert_eq!(invite.dst.port, fx::PORT);
    assert!(invite.message.sdp.is_some());
    assert!(invite.message.size > 200, "split over several segments");
    // The 180 came in the same segment as the 100; the 200 answer goes server -> client.
    assert_eq!(sip[2].src.ip, sip_hosts::pbx().ip);
}

#[test]
fn a_gap_or_garbage_abandons_the_direction() {
    use netsift_fixtures::scenario::TcpOptions;
    let mut sc = Scenario::new();
    let mut tcp = sc.tcp_open(
        sip_hosts::alice(),
        sip_hosts::pbx(),
        &TcpOptions::new(fx::PORT),
    );
    tcp.client_send(b"\x16\x03\x01\x00\x05hello");
    tcp.client_send(b"OPTIONS sip:a SIP/2.0\r\nContent-Length: 0\r\n\r\n");
    tcp.server_send(b"SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n");
    tcp.close();
    let (sip, _) = run(&sc);
    // The client side starts with TLS-like bytes: abandoned; the server side is still read.
    assert_eq!(sip.len(), 1);
    assert_eq!(sip[0].message.status(), Some(200));
}

#[test]
fn digest_authorization_becomes_a_metadata_only_credential() {
    let mut sc = Scenario::new();
    fx::sip_register(
        &mut sc,
        fx::CALL_REGISTER,
        &fx::alice_phone(),
        &fx::pbx_party(),
    );
    let (sip, creds) = run(&sc);
    assert_eq!(sip.len(), 4);
    assert_eq!(sip[1].message.challenge_realm.as_deref(), Some(fx::REALM));
    assert_eq!(creds.len(), 1);
    let c = &creds[0];
    assert_eq!((c.source_protocol, c.kind), ("sip", "sip-digest"));
    assert_eq!(c.secret_state, SecretState::MetadataOnly);
    assert_eq!(c.username.as_deref(), Some("201"));
    assert_eq!(c.domain.as_deref(), Some(fx::REALM));
    assert_eq!((c.secret.as_ref(), c.hashcat_line.as_ref()), (None, None));
    assert_eq!(c.client.unwrap().ip, sip_hosts::alice().ip);
    let keys: Vec<&str> = c.details.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(keys, ["method", "uri", "algorithm", "header"]);
}

#[test]
fn showcase_records_snapshot() {
    let mut sc = Scenario::new();
    fx::sip_showcase(&mut sc);
    let (sip, creds) = run(&sc);
    let mut s = String::new();
    for r in &sip {
        let m = &r.message;
        let first = match m.status() {
            Some(code) => format!("{code} ({})", m.method().unwrap_or("-")),
            None => m.method().unwrap_or("-").to_owned(),
        };
        let media: Vec<String> = m
            .sdp
            .as_ref()
            .map(|sdp| {
                sdp.media
                    .iter()
                    .map(|x| {
                        let addr = sdp.address(x).map_or("-".to_owned(), |a| a.to_string());
                        format!("{} {addr}:{} {}", x.media, x.port, x.codecs.join("/"))
                    })
                    .collect()
            })
            .unwrap_or_default();
        writeln!(
            s,
            "{} {} {}:{} -> {}:{} {first} call={} cseq={} from={} to={} agent={} scanner={} media=[{}] size={} trunc={}",
            r.ts,
            r.transport.as_str(),
            r.src.ip,
            r.src.port,
            r.dst.ip,
            r.dst.port,
            m.call_id.as_deref().map_or("-", |c| c.get(..c.len().min(40)).unwrap_or(c)),
            m.cseq.map_or("-".to_owned(), |c| c.to_string()),
            m.from.uri.as_deref().unwrap_or("-"),
            m.to.uri.as_deref().unwrap_or("-"),
            m.software().map_or("-", |a| a.get(..a.len().min(24)).unwrap_or(a)),
            r.scanner.unwrap_or("-"),
            media.join(", "),
            m.size,
            m.headers_truncated,
        )
        .unwrap();
    }
    for c in &creds {
        writeln!(s, "credential {c:?}").unwrap();
    }
    insta::assert_snapshot!(s);
}

#[test]
fn a_large_delivery_is_framed_in_pieces_not_abandoned() {
    use crate::analyzer::Analyzer as _;
    use netsift_flow::{Direction, Endpoint, FlowId, FlowKey, StreamCtx};
    let key = FlowKey {
        proto: 6,
        client: Endpoint {
            ip: sip_hosts::alice().ip,
            port: 50_000,
        },
        server: Endpoint {
            ip: sip_hosts::pbx().ip,
            port: fx::PORT,
        },
    };
    let ctx = StreamCtx {
        ts_ns: 1,
        chunk_id: 0,
        frame: 0,
        id: FlowId(7),
        key,
        gap_before: 0,
    };
    let one = b"OPTIONS sip:pbx SIP/2.0\r\nCall-ID: x\r\nContent-Length: 0\r\n\r\n";
    let count = 3 * netsift_dissect::sip::MAX_MESSAGE / one.len();
    let data: Vec<u8> = one
        .iter()
        .copied()
        .cycle()
        .take(one.len() * count)
        .collect();
    let mut analyzer = SipAnalyzer::new(&AnalyzerConfig::default());
    let mut out = Vec::new();
    analyzer.on_stream(&ctx, Direction::ToServer, &data, &mut out);
    assert_eq!(out.len(), count, "{} bytes delivered at once", data.len());
}
