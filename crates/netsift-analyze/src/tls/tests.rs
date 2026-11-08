use std::collections::BTreeMap;

use netsift_dissect::Decoded;
use netsift_fixtures::Packet;
use netsift_fixtures::proto::tls as wire;
use netsift_fixtures::proto::x509::{CertSpec, certificate};
use netsift_fixtures::scenario::{Scenario, TcpOptions, TlsAlert, TlsHandshake};
use netsift_fixtures::scenarios::{self, hosts};
use netsift_flow::{FlowConfig, FlowSink, FlowTable, PacketCtx};
use sha2::{Digest as _, Sha256};

use super::*;
use crate::analyzer::BlobRef;

/// Records plus an in-memory blob store.
#[derive(Default)]
struct TestSink {
    records: Vec<Record>,
    blobs: BTreeMap<[u8; 32], Vec<u8>>,
    puts: usize,
}

impl RecordSink for TestSink {
    fn emit(&mut self, record: Record) {
        self.records.push(record);
    }

    fn put_blob(&mut self, data: &[u8]) -> Option<BlobRef> {
        self.puts += 1;
        let sha256: [u8; 32] = Sha256::digest(data).into();
        self.blobs.entry(sha256).or_insert_with(|| data.to_vec());
        Some(BlobRef {
            sha256,
            size: data.len() as u64,
        })
    }
}

struct Fan<'a> {
    tls: &'a mut TlsAnalyzer,
    out: &'a mut TestSink,
}

impl FlowSink for Fan<'_> {
    fn on_packet(&mut self, _ctx: &PacketCtx, _pkt: &Decoded<'_>) {}

    fn on_stream(&mut self, ctx: &StreamCtx, dir: Direction, data: &[u8]) {
        self.tls.on_stream(ctx, dir, data, self.out);
    }

    fn on_flow_end(&mut self, ctx: &FlowCtx) {
        self.tls.on_flow_end(ctx, self.out);
    }
}

fn analyze_with(config: &AnalyzerConfig, packets: &[Packet]) -> (Vec<TlsSession>, TestSink) {
    let mut tls = TlsAnalyzer::new(config);
    let mut out = TestSink::default();
    let mut table = FlowTable::new(FlowConfig::default());
    {
        let mut fan = Fan {
            tls: &mut tls,
            out: &mut out,
        };
        for (i, p) in packets.iter().enumerate() {
            let len = u32::try_from(p.data.len()).unwrap();
            table.process(p.ts_ns, 0, i as u64, p.linktype, len, &p.data, &mut fan);
        }
        table.finish(&mut fan);
    }
    tls.finish(&mut out);
    let sessions = out
        .records
        .iter()
        .map(|r| match r {
            Record::Tls(s) => (**s).clone(),
            other => panic!("unexpected record {other:?}"),
        })
        .collect();
    (sessions, out)
}

fn analyze(packets: &[Packet]) -> (Vec<TlsSession>, TestSink) {
    analyze_with(&AnalyzerConfig::default(), packets)
}

fn one(hs: &TlsHandshake) -> (TlsSession, TestSink) {
    let mut sc = Scenario::new();
    sc.tls_handshake(hosts::workstation(), hosts::tls_server(), hs);
    let (mut sessions, sink) = analyze(sc.packets());
    assert_eq!(sessions.len(), 1, "{sessions:?}");
    (sessions.remove(0), sink)
}

#[test]
fn tls12_with_expired_self_signed_certificate() {
    let mut spec = CertSpec::new("legacy.example.test");
    spec.not_before = 1_262_304_000;
    spec.not_after = scenarios::EXPIRED_NOT_AFTER;
    let der = certificate(&spec);
    let mut hs = TlsHandshake::new("legacy.example.test");
    hs.certificate_chain = vec![der.clone()];
    hs.complete = true;
    let (s, sink) = one(&hs);

    assert_eq!(s.sni(), Some("legacy.example.test"));
    assert_eq!(s.offered_version(), Some(0x0303));
    assert_eq!(s.version(), Some(0x0303));
    assert_eq!(s.alpn(), Some("h2"));
    assert_eq!(
        s.client_hello.as_ref().unwrap().alpn,
        vec!["h2", "http/1.1"]
    );
    let cipher = s.cipher.unwrap();
    assert_eq!(cipher.id, wire::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
    assert_eq!(cipher.name, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256");
    assert_eq!(cipher.weak, None);
    assert_eq!(s.outcome, Outcome::Complete);
    assert_eq!(s.cert_status, CertStatus::Present);
    assert!(!s.resumed);
    assert_eq!(s.alert, None);
    assert_eq!(s.server.port, 443);

    // Certificate: parsed, stored once, issues at the session time.
    assert_eq!(s.certificates.len(), 1);
    let c = &s.certificates[0];
    assert!(c.stored);
    assert_eq!(c.sha256, <[u8; 32]>::from(Sha256::digest(&der)));
    assert_eq!(sink.blobs.get(&c.sha256), Some(&der));
    let info = c.info.as_ref().unwrap();
    assert_eq!(info.subject_cn.as_deref(), Some("legacy.example.test"));
    assert!(info.self_signed);
    assert_eq!(s.cert_issues, cert_issue::EXPIRED | cert_issue::SELF_SIGNED);

    // JA3 written by hand from the fixture ClientHello: suites of DEFAULT_CIPHER_SUITES,
    // extensions SNI, extended_master_secret, renegotiation_info, supported_groups,
    // ec_point_formats, signature_algorithms, ALPN; groups x25519, secp256r1, secp384r1;
    // point formats: uncompressed.
    let ja3 = s.ja3.as_ref().unwrap();
    assert_eq!(
        ja3.text,
        "771,49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,\
         0-23-65281-10-11-13-16,29-23-24,0"
    );
    assert_eq!(ja3.hash, fingerprint::md5_hex(ja3.text.as_bytes()));
    // JA4: TLS 1.2, SNI, 12 suites, 7 extensions, ALPN h2.
    assert!(
        s.ja4.as_deref().unwrap().starts_with("t12d1207h2_"),
        "{:?}",
        s.ja4
    );
    // Names of every offered suite known to the registry.
    assert_eq!(s.cipher_names.len(), 12);
}

#[test]
fn tls13_with_sni_alpn_and_grease() {
    let (s, sink) = one(&TlsHandshake::tls13("www.example.test"));
    let ch = s.client_hello.as_ref().unwrap();
    assert_eq!(s.sni(), Some("www.example.test"));
    assert_eq!(ch.alpn, vec!["h2", "http/1.1"]);
    assert_eq!(s.offered_version(), Some(0x0304));
    assert_eq!(s.version(), Some(0x0304));
    assert_eq!(s.server_hello.as_ref().unwrap().legacy_version, 0x0303);
    // ALPN is encrypted in TLS 1.3 (EncryptedExtensions).
    assert_eq!(s.alpn(), None);
    assert_eq!(s.cipher.unwrap().name, "TLS_AES_128_GCM_SHA256");
    assert_eq!(s.cert_status, CertStatus::Encrypted);
    assert_eq!(s.certificates, Vec::new());
    assert_eq!(sink.puts, 0);
    assert_eq!(s.outcome, Outcome::Complete);
    // GREASE kept in the decoded lists, excluded from the fingerprints.
    assert!(hello::is_grease(ch.cipher_suites[0]));
    assert!(hello::is_grease(ch.extensions[0]));
    assert!(hello::is_grease(*ch.extensions.last().unwrap()));
    assert!(hello::is_grease(ch.supported_versions[0]));
    assert_eq!(ch.key_share_groups, vec![wire::GROUP_X25519]);
    let ja3 = s.ja3.unwrap();
    assert!(
        ja3.text.starts_with("771,4865-4866-4867-49195-"),
        "{}",
        ja3.text
    );
    assert!(
        ja3.text.contains(",0-23-65281-10-11-13-16-43-51,"),
        "{}",
        ja3.text
    );
    // 8 suites, 9 extensions (GREASE excluded), ALPN h2.
    assert!(
        s.ja4.as_deref().unwrap().starts_with("t13d0809h2_"),
        "{:?}",
        s.ja4
    );
}

#[test]
fn hello_retry_request_in_middlebox_compatibility_mode() {
    let mut hs = TlsHandshake::tls13("retry.example.test");
    hs.hello_retry = true;
    let (s, _) = one(&hs);
    let sh = s.server_hello.as_ref().unwrap();
    assert!(!sh.retry, "the second ServerHello is kept");
    assert_ne!(sh.random, hello::HELLO_RETRY_RANDOM);
    assert_eq!(s.version(), Some(0x0304));
    assert_eq!(s.cipher.unwrap().name, "TLS_AES_128_GCM_SHA256");
    assert_eq!(s.outcome, Outcome::Complete);
    assert_eq!(s.sni(), Some("retry.example.test"));
    assert_eq!(s.cert_status, CertStatus::Encrypted);
}

#[test]
fn scanner_hello_with_hundreds_of_suites() {
    let hello = wire::ClientHello {
        version: 0x0303,
        random: [1; 32],
        session_id: Vec::new(),
        cipher_suites: (1..=320).collect(),
        sni: None,
        alpn: Vec::new(),
        supported_versions: Vec::new(),
        key_share_groups: Vec::new(),
        grease: None,
    };
    let bytes = wire::client_hello_record(&hello);
    let sessions = run_stream(&[(Direction::ToServer, bytes, 0)]);
    let ch = sessions[0].client_hello.as_ref().unwrap();
    assert_eq!(ch.cipher_suites.len(), 320);
    assert!(sessions[0].ja4.as_deref().unwrap().starts_with("t12i99"));
    assert_eq!(
        sessions[0].ja3.as_ref().unwrap().text.matches('-').count(),
        319 + 6
    );
}

#[test]
fn client_hello_split_over_tiny_segments() {
    let mut hs = TlsHandshake::tls13("fragmented.example.test");
    hs.tcp.mss = 37;
    let (s, _) = one(&hs);
    assert_eq!(s.sni(), Some("fragmented.example.test"));
    let (reference, _) = one(&TlsHandshake::tls13("fragmented.example.test"));
    assert_eq!(s.ja3, reference.ja3);
    assert_eq!(s.ja4, reference.ja4);
    assert_eq!(s.outcome, Outcome::Complete);
}

#[test]
fn certificate_chain_and_non_standard_port() {
    let mut leaf = CertSpec::new("shop.example.test");
    leaf.issuer = Some("NetSift Test CA".to_owned());
    let mut ca = CertSpec::new("NetSift Test CA");
    ca.ca = true;
    let mut hs = TlsHandshake::new("shop.example.test");
    hs.certificate_chain = vec![certificate(&leaf), certificate(&ca)];
    hs.server_key_exchange = true;
    hs.tcp = TcpOptions::new(4443);
    // Certificates larger than one segment.
    hs.tcp.mss = 200;
    let (s, sink) = one(&hs);
    assert_eq!(s.server.port, 4443);
    assert_eq!(s.certificates.len(), 2);
    let leaf_info = s.certificates[0].info.as_ref().unwrap();
    assert_eq!(leaf_info.issuer_cn.as_deref(), Some("NetSift Test CA"));
    assert!(!leaf_info.self_signed);
    assert!(s.certificates[1].info.as_ref().unwrap().is_ca);
    // A self-signed root at the end of the chain is not an issue.
    assert_eq!(s.cert_issues, 0);
    assert_eq!(sink.blobs.len(), 2);
    assert_eq!(s.outcome, Outcome::Partial);
}

#[test]
fn alerts_unanswered_hellos_and_weak_suites() {
    let mut hs = TlsHandshake::new("legacy.example.test");
    hs.cipher_suites = vec![0x002f, 0x000a];
    hs.selected_suite = 0x000a;
    hs.alert = Some(TlsAlert {
        level: 2,
        description: 42,
        from_server: false,
    });
    let (s, _) = one(&hs);
    assert_eq!(
        s.alert,
        Some(Alert {
            level: 2,
            description: 42,
            from_server: false
        })
    );
    assert_eq!(s.outcome, Outcome::Partial);
    assert_eq!(s.cipher.unwrap().weak, Some("3des"));

    let mut hs = TlsHandshake::tls13("blocked.example.test");
    hs.respond = false;
    let (s, _) = one(&hs);
    assert!(s.server_hello.is_none());
    assert_eq!(s.version(), None);
    assert_eq!(s.cipher, None);
    assert_eq!(s.cert_status, CertStatus::None);
    assert_eq!(s.outcome, Outcome::Partial);

    let mut hs = TlsHandshake::new("printer.example.test");
    hs.client_version = 0x0301;
    hs.server_version = 0x0301;
    hs.cipher_suites = vec![0x0005];
    hs.selected_suite = 0x0005;
    hs.complete = true;
    let (s, _) = one(&hs);
    assert_eq!(s.version(), Some(0x0301));
    assert_eq!(s.cipher.unwrap().weak, Some("rc4"));
    assert!(
        s.ja4.as_deref().unwrap().starts_with("t10d0107h2_"),
        "{:?}",
        s.ja4
    );
}

#[test]
fn showcase_sessions_and_suite_names_once_per_shard() {
    let mut sc = Scenario::new();
    scenarios::tls_showcase(&mut sc);
    let (sessions, _) = analyze(sc.packets());
    assert_eq!(sessions.len(), 8);
    let names: usize = sessions.iter().map(|s| s.cipher_names.len()).sum();
    let mut ids: Vec<u16> = sessions
        .iter()
        .flat_map(|s| s.cipher_names.iter().map(|c| c.id))
        .collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), names, "each suite name is sent once");
    let complete = sessions
        .iter()
        .filter(|s| s.outcome == Outcome::Complete)
        .count();
    assert_eq!(complete, 5);
}

#[test]
fn non_tls_flows_are_ignored() {
    let mut sc = Scenario::new();
    sc.http_get(
        hosts::workstation(),
        hosts::web_server(),
        &netsift_fixtures::scenario::HttpGet::default(),
    );
    sc.ftp_login(
        hosts::workstation(),
        hosts::ftp_server(),
        &netsift_fixtures::scenario::FtpLogin::default(),
    );
    let (sessions, _) = analyze(sc.packets());
    assert_eq!(sessions, Vec::new());
}

#[test]
fn flow_and_memory_bounds() {
    let mut sc = Scenario::new();
    for _ in 0..3 {
        sc.tls_handshake(
            hosts::workstation(),
            hosts::tls_server(),
            &TlsHandshake::default(),
        );
    }
    let mut config = AnalyzerConfig::default();
    config.tls.max_flows = 1;
    // The handshakes never reach application data: the three flows are followed at the same
    // time until they end, so only the first one fits.
    assert_eq!(analyze_with(&config, sc.packets()).0.len(), 1);
    config.tls.max_flows = 3;

    // A chain message above the reassembly bound: hellos kept, certificates dropped.
    config.tls.max_handshake_message = 320;
    let (sessions, sink) = analyze_with(&config, sc.packets());
    assert_eq!(sessions.len(), 3);
    assert!(sessions.iter().all(|s| s.certificates.is_empty()));
    assert_eq!(sink.blobs, BTreeMap::new());

    // Certificates above the size bound are skipped.
    let mut config = AnalyzerConfig::default();
    config.tls.max_certificate = 16;
    let (sessions, _) = analyze_with(&config, sc.packets());
    assert!(sessions.iter().all(|s| s.certificates.is_empty()));
}

/// Stream events built by hand: hostile records must never panic nor emit garbage.
fn ctx(id: i64) -> StreamCtx {
    let ep = |last: u8, port| Endpoint {
        ip: std::net::IpAddr::from([10, 0, 0, last]),
        port,
    };
    StreamCtx {
        ts_ns: 1_700_000_000_000_000_000,
        chunk_id: 0,
        frame: 0,
        id: FlowId(id),
        key: FlowKey {
            proto: 6,
            client: ep(1, 50_000),
            server: ep(2, 443),
        },
        gap_before: 0,
    }
}

fn end(id: i64) -> FlowCtx {
    let c = ctx(id);
    FlowCtx {
        id: c.id,
        key: c.key,
        first_ts_ns: c.ts_ns,
        last_ts_ns: c.ts_ns,
        to_server: netsift_flow::DirStats::default(),
        to_client: netsift_flow::DirStats::default(),
        tcp_state: None,
        end: netsift_flow::EndReason::Closed,
    }
}

fn client_hello_bytes() -> Vec<u8> {
    wire::client_hello_record(&wire::ClientHello {
        version: 0x0303,
        random: [1; 32],
        session_id: vec![2; 32],
        cipher_suites: vec![0x1301, 0xc02f],
        sni: Some("hostile.example.test".to_owned()),
        alpn: vec!["h2".to_owned()],
        supported_versions: vec![0x0304],
        key_share_groups: vec![wire::GROUP_X25519],
        grease: None,
    })
}

fn run_stream(chunks: &[(Direction, Vec<u8>, u64)]) -> Vec<TlsSession> {
    let mut tls = TlsAnalyzer::new(&AnalyzerConfig::default());
    let mut out = TestSink::default();
    for (dir, data, gap) in chunks {
        let mut c = ctx(1);
        c.gap_before = *gap;
        tls.on_stream(&c, *dir, data, &mut out);
    }
    tls.on_flow_end(&end(1), &mut out);
    out.records
        .into_iter()
        .map(|r| match r {
            Record::Tls(s) => *s,
            other => panic!("{other:?}"),
        })
        .collect()
}

#[test]
fn hostile_streams() {
    let hello = client_hello_bytes();
    // Truncated ClientHello: tracked, nothing decoded, nothing emitted.
    assert_eq!(
        run_stream(&[(Direction::ToServer, hello[..60].to_vec(), 0)]),
        Vec::new()
    );
    // Every truncation of the hello body inside a complete record: no panic, never garbage.
    for cut in 9..hello.len() {
        let mut bytes = hello[..cut].to_vec();
        let body_len = u16::try_from(cut - 5).unwrap();
        bytes[3..5].copy_from_slice(&body_len.to_be_bytes());
        let hs_len = u32::try_from(cut - 9).unwrap().to_be_bytes();
        bytes[6..9].copy_from_slice(&hs_len[1..]);
        for s in run_stream(&[(Direction::ToServer, bytes, 0)]) {
            assert!(
                s.sni()
                    .is_none_or(|n| "hostile.example.test".starts_with(n))
            );
        }
    }
    // Inconsistent lengths: handshake length larger than the record, extension lengths lying.
    let mut lying = hello.clone();
    lying[6..9].copy_from_slice(&[0x00, 0xff, 0xff]);
    assert_eq!(run_stream(&[(Direction::ToServer, lying, 0)]), Vec::new());
    // key_share (type 51, 38 bytes) claims 65535 bytes.
    let at = hello
        .windows(4)
        .position(|w| w == [0x00, 0x33, 0x00, 0x26])
        .unwrap();
    let mut bad_ext = hello.clone();
    bad_ext[at + 2..at + 4].copy_from_slice(&[0xff, 0xff]);
    let sessions = run_stream(&[(Direction::ToServer, bad_ext, 0)]);
    assert_eq!(sessions.len(), 1);
    // The earlier extensions survive a malformed last one.
    assert_eq!(sessions[0].sni(), Some("hostile.example.test"));
    // A gap in the client stream abandons it; the first hello was already decoded.
    let sessions = run_stream(&[
        (Direction::ToServer, hello.clone(), 0),
        (Direction::ToServer, vec![0xee; 100], 50),
    ]);
    assert_eq!(sessions[0].sni(), Some("hostile.example.test"));
    // Not TLS: ignored.
    assert_eq!(
        run_stream(&[(Direction::ToServer, b"SSH-2.0-OpenSSH\r\n".to_vec(), 0)]),
        Vec::new()
    );
    // A ServerHello first (client side not captured) is followed.
    let sh = wire::server_hello_record(&wire::ServerHello {
        version: 0x0303,
        random: [3; 32],
        session_id: Vec::new(),
        cipher_suite: 0xc02f,
        alpn: None,
        selected_version: None,
    });
    let sessions = run_stream(&[(Direction::ToClient, sh, 0)]);
    assert_eq!(sessions[0].version(), Some(0x0303));
    assert!(sessions[0].ja3.is_none());
    // Garbage certificates: digests kept, fields absent.
    let mut flight = wire::server_hello_record(&wire::ServerHello {
        version: 0x0303,
        random: [3; 32],
        session_id: Vec::new(),
        cipher_suite: 0xc02f,
        alpn: None,
        selected_version: None,
    });
    flight.extend(wire::certificate_record(&[b"garbage".to_vec()]));
    let sessions = run_stream(&[
        (Direction::ToServer, hello, 0),
        (Direction::ToClient, flight, 0),
    ]);
    assert_eq!(sessions[0].certificates.len(), 1);
    assert!(sessions[0].certificates[0].info.is_none());
    assert_eq!(sessions[0].cert_status, CertStatus::Present);
}

#[test]
fn looks_like_tls_prefixes() {
    assert!(looks_like_tls(&[22], 1));
    assert!(looks_like_tls(&[22, 3, 1, 0, 200, 1], 1));
    assert!(!looks_like_tls(&[22, 3, 1, 0, 200, 2], 1));
    assert!(!looks_like_tls(&[22, 3, 9], 1));
    assert!(!looks_like_tls(&[23, 3, 3], 1));
    assert!(!looks_like_tls(&[], 1));
}
