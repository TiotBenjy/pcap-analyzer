//! End-to-end imports of synthetic TLS traffic: `tls_*` tables, certificate blobs, and a
//! `ClientHello` split over two TCP segments that land in two different chunks.

use std::fmt::Write as _;
use std::path::Path;

use netsift_engine::{CancelToken, IngestOptions, IngestReport, ingest};
use netsift_fixtures::proto::x509::{CertSpec, certificate};
use netsift_fixtures::scenario::{Scenario, TlsHandshake};
use netsift_fixtures::scenarios::{self, hosts};
use netsift_fixtures::{Encoding, Naming, Packet, SplitBy, SplitOptions, split_to_dir, write_file};
use netsift_store::tls::{TlsSessionFilter, sessions_page};
use netsift_store::{Catalog, OpenMode, PageRequest, Session};
use sha2::{Digest as _, Sha256};
use tempfile::TempDir;

fn import(catalog: &Catalog, input: &Path) -> IngestReport {
    ingest(
        catalog,
        input,
        &IngestOptions::default(),
        &CancelToken::new(),
        &mut |_| {},
    )
    .unwrap()
}

fn open(catalog: &Catalog, report: &IngestReport) -> Session {
    catalog
        .open_session(&report.session, OpenMode::ReadOnly)
        .unwrap()
}

fn render(session: &Session) -> String {
    let mut out = String::new();
    let mut stmt = session
        .conn()
        .prepare(
            "SELECT s.client_port || ' | ' || s.server_ip || ':' || s.server_port || ' | ' || \
             coalesce(s.sni, '-') || ' | ' || printf('%04x>%04x', coalesce(s.offered_version, 0), \
             coalesce(s.version, 0)) || ' | ' || coalesce(s.cipher_name, '-') || ' | ' || \
             coalesce(s.cipher_weak, '-') || ' | ' || s.alpn_offered || ' | ' || \
             coalesce(s.alpn, '-') || ' | ' || coalesce(s.ja4, '-') || ' | ' || s.outcome || \
             ' | alert=' || coalesce(s.alert_desc, '-') || ' | ' || s.cert_status || ' | certs=' || \
             s.cert_count || ' | issues=' || s.cert_issues || ' | ' || coalesce(c.subject_cn, '-') \
             FROM tls_sessions s LEFT JOIN tls_certificates c ON c.sha256 = s.leaf_sha256 \
             ORDER BY s.ts",
        )
        .unwrap();
    let rows = stmt.query_map([], |r| r.get::<_, String>(0)).unwrap();
    for row in rows {
        writeln!(out, "{}", row.unwrap()).unwrap();
    }
    out
}

#[test]
fn showcase_sessions_tables_and_blobs() {
    let tmp = TempDir::new().unwrap();
    let catalog = Catalog::open(tmp.path().join("data")).unwrap();
    let mut sc = Scenario::new();
    scenarios::tls_showcase(&mut sc);
    let file = tmp.path().join("tls.pcap");
    write_file(&file, sc.packets(), &Encoding::pcap()).unwrap();
    let report = import(&catalog, &file);
    let session = open(&catalog, &report);
    insta::assert_snapshot!(render(&session));

    // Certificates (leaf + CA of the shop, expired legacy one, printer, intranet), each stored
    // once as a DER blob.
    let mut stmt = session
        .conn()
        .prepare("SELECT sha256, stored FROM tls_certificates ORDER BY sha256")
        .unwrap();
    let certs: Vec<(String, bool)> = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(certs.len(), 5);
    for (sha, stored) in &certs {
        assert!(stored);
        let der = std::fs::read(session.blob_path(sha).unwrap()).unwrap();
        let digest = Sha256::digest(&der).iter().fold(String::new(), |mut s, b| {
            write!(s, "{b:02x}").unwrap();
            s
        });
        assert_eq!(&digest, sha);
    }
    // Suite names of every negotiated suite.
    let named: i64 = session
        .conn()
        .query_row(
            "SELECT count(*) FROM tls_sessions s WHERE s.cipher_suite IS NOT NULL \
             AND NOT EXISTS (SELECT 1 FROM tls_cipher_suites c WHERE c.id = s.cipher_suite)",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(named, 0);
}

#[test]
fn client_hello_across_two_segments_and_two_chunks() {
    let tmp = TempDir::new().unwrap();
    let catalog = Catalog::open(tmp.path().join("data")).unwrap();
    let mut sc = Scenario::new();
    let mut hs = TlsHandshake::new("split.example.test");
    // The ClientHello (~230 bytes) needs two segments; the leaf is a fresh certificate.
    hs.tcp.mss = 150;
    hs.certificate_chain = vec![certificate(&CertSpec::new("split.example.test"))];
    let ex = sc.tls_handshake(hosts::workstation(), hosts::tls_server(), &hs);
    assert_eq!(ex.request.len(), 2, "two ClientHello segments");
    let packets: Vec<Packet> = sc.into_packets();

    // Reference: one file.
    let single = tmp.path().join("single.pcap");
    write_file(&single, &packets, &Encoding::pcap()).unwrap();
    let reference = open(&catalog, &import(&catalog, &single));

    // Same traffic, the second ClientHello segment starts a new chunk.
    let dir = tmp.path().join("chunks");
    let opts = SplitOptions::new(SplitBy::At(vec![ex.request.start + 1]), Naming::Dumpcap)
        .with_prefix("tls");
    let (_, paths) = split_to_dir(&dir, &packets, &opts).unwrap();
    assert_eq!(paths.len(), 2);
    let chunked = open(&catalog, &import(&catalog, &dir));

    let page = |s: &Session| {
        sessions_page(
            s.conn(),
            &TlsSessionFilter::default(),
            false,
            &PageRequest::first(10),
        )
        .unwrap()
        .items
    };
    let a = page(&reference);
    let b = page(&chunked);
    assert_eq!(a.len(), 1);
    assert_eq!(a, b);
    assert_eq!(a[0].sni.as_deref(), Some("split.example.test"));
    assert!(a[0].ja3.is_some());
    assert_eq!(a[0].cert_count, 1);
    assert_eq!(render(&reference), render(&chunked));
}
