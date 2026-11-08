use super::*;
use crate::migrate::migrate;
use crate::records::{StoreRecord, is_row_level};
use crate::schema::SESSION_SCHEMA;

fn db() -> Connection {
    let mut conn = Connection::open_in_memory().unwrap();
    migrate(&mut conn, &SESSION_SCHEMA).unwrap();
    conn
}

fn cert(sha: char, cn: &str, self_signed: bool, not_after: i64) -> CertificateRow {
    CertificateRow {
        sha256: sha.to_string().repeat(64),
        sha1: sha.to_string().repeat(40),
        size: 512,
        stored: false,
        parsed: true,
        subject: Some(format!("CN={cn}")),
        subject_cn: Some(cn.to_owned()),
        issuer: Some(if self_signed {
            format!("CN={cn}")
        } else {
            "CN=Fixture CA".to_owned()
        }),
        issuer_cn: Some(if self_signed { cn } else { "Fixture CA" }.to_owned()),
        serial: Some("1001".to_owned()),
        not_before: Some(0),
        not_after: Some(not_after),
        san: vec![format!("DNS:{cn}")],
        key_algorithm: Some("EC".to_owned()),
        key_bits: Some(256),
        signature_algorithm: Some("ecdsa-with-SHA256".to_owned()),
        self_signed,
        is_ca: false,
    }
}

fn session(id: u64, ts: i64, version: Option<u16>, suite: Option<u16>) -> TlsSessionRow {
    TlsSessionRow {
        id,
        ts,
        client_ip: "192.168.1.10".parse().unwrap(),
        client_port: 50_000,
        server_ip: "198.51.100.43".parse().unwrap(),
        server_port: 443,
        sni: Some(format!("host{id}.example.test")),
        offered_version: Some(0x0304),
        version,
        cipher_suite: suite,
        cipher_name: suite.map(|s| format!("SUITE_{s:04x}")),
        cipher_weak: (suite == Some(0x000a)).then(|| "3des".to_owned()),
        alpn_offered: vec!["h2".to_owned(), "http/1.1".to_owned()],
        alpn: Some("h2".to_owned()),
        ja3: Some("771,4865,0,29,0".to_owned()),
        ja3_hash: Some("0".repeat(32)),
        ja4: Some("t13d0101h2_000000000000_000000000000".to_owned()),
        compression: Some(0),
        resumed: false,
        outcome: TlsOutcome::Complete,
        alert: None,
        cert_status: CertStatus::Present,
        cert_issues: 0,
        client_hello: Some(ClientHelloRow {
            legacy_version: 0x0303,
            random: "00".repeat(32),
            cipher_suites: vec![0x0a0a, 0x1301, 0x000a],
            compressions: vec![0],
            extensions: vec![0, 16, 43],
            ..ClientHelloRow::default()
        }),
        server_hello: suite.map(|s| ServerHelloRow {
            legacy_version: 0x0303,
            random: "11".repeat(32),
            cipher_suite: s,
            extensions: vec![43],
            selected_version: version,
            ..ServerHelloRow::default()
        }),
        certificates: Vec::new(),
        cipher_names: vec![
            CipherNameRow {
                id: 0x1301,
                name: "TLS_AES_128_GCM_SHA256".to_owned(),
                weak: None,
            },
            CipherNameRow {
                id: 0x000a,
                name: "TLS_RSA_WITH_3DES_EDE_CBC_SHA".to_owned(),
                weak: Some("3des".to_owned()),
            },
        ],
    }
}

fn put(conn: &Connection, row: TlsSessionRow) {
    StoreRecord::Tls(Box::new(row)).insert(conn).unwrap();
}

#[test]
fn sessions_pages_filters_and_details() {
    let conn = db();
    let ca_signed = cert('a', "shared.example.test", false, 10_000);
    let expired = cert('b', "old.example.test", true, 50);
    let mut s1 = session(1, 100, Some(0x0304), Some(0x1301));
    s1.certificates = vec![ca_signed.clone()];
    let mut s2 = session(2, 200, Some(0x0303), Some(0x000a));
    s2.certificates = vec![expired, ca_signed];
    s2.cert_issues = cert_issue::EXPIRED | cert_issue::SELF_SIGNED;
    let s3 = session(3, 300, None, None);
    put(&conn, s1);
    put(&conn, s2);
    put(&conn, s3.clone());
    // A replay changes nothing.
    put(&conn, s3);

    let all = TlsSessionFilter::default();
    assert_eq!(count_sessions(&conn, &all).unwrap(), 3);
    let p1 = sessions_page(&conn, &all, true, &PageRequest::first(2)).unwrap();
    assert_eq!(
        p1.items.iter().map(|s| s.id).collect::<Vec<_>>(),
        vec![3, 2]
    );
    let p2 = sessions_page(
        &conn,
        &all,
        true,
        &PageRequest {
            limit: 2,
            cursor: p1.next_cursor,
        },
    )
    .unwrap();
    assert_eq!(p2.items.iter().map(|s| s.id).collect::<Vec<_>>(), vec![1]);
    assert_eq!(p2.next_cursor, None);
    let first = &p2.items[0];
    assert_eq!(
        first.leaf_subject_cn.as_deref(),
        Some("shared.example.test")
    );
    assert_eq!(first.alpn_offered, vec!["h2", "http/1.1"]);
    assert_eq!(first.cert_count, 1);

    let only = |f: TlsSessionFilter| -> Vec<i64> {
        sessions_page(&conn, &f, false, &PageRequest::first(10))
            .unwrap()
            .items
            .iter()
            .map(|s| s.id)
            .collect()
    };
    let f = |version, suite, q: Option<&str>, weak, issues| TlsSessionFilter {
        version,
        suite,
        q: q.map(str::to_owned),
        weak_only: weak,
        cert_issues_only: issues,
    };
    assert_eq!(only(f(Some(0x0303), None, None, false, false)), vec![2]);
    assert_eq!(only(f(None, Some(0x1301), None, false, false)), vec![1]);
    assert_eq!(only(f(None, None, Some("HOST3"), false, false)), vec![3]);
    assert_eq!(
        only(f(None, None, Some("198.51"), false, false)),
        vec![1, 2, 3]
    );
    assert_eq!(
        only(f(None, None, Some("%"), false, false)),
        Vec::<i64>::new()
    );
    assert_eq!(only(f(None, None, None, true, false)), vec![2]);
    assert_eq!(only(f(None, None, None, false, true)), vec![2]);
    assert_eq!(
        count_sessions(&conn, &f(None, None, None, true, false)).unwrap(),
        1
    );

    let d = session_detail(&conn, 2).unwrap().unwrap();
    assert_eq!(d.certificates.len(), 2);
    assert_eq!(
        d.certificates[0].subject_cn.as_deref(),
        Some("old.example.test")
    );
    assert_eq!(
        d.client_hello.unwrap().cipher_suites,
        vec![0x0a0a, 0x1301, 0x000a]
    );
    assert_eq!(d.server_hello.unwrap().selected_version, Some(0x0303));
    assert_eq!(
        d.cipher_names.iter().map(|c| c.id).collect::<Vec<_>>(),
        vec![0x000a, 0x1301]
    );
    assert!(session_detail(&conn, 42).unwrap().is_none());
}

#[test]
fn stats_and_certificates() {
    let conn = db();
    let shared = cert('a', "shared.example.test", false, 10_000);
    let expired = cert('b', "old.example.test", true, 50);
    for (id, version, suite) in [
        (1, Some(0x0304), Some(0x1301)),
        (2, Some(0x0304), Some(0x1301)),
        (3, Some(0x0303), Some(0x000a)),
        (4, None, None),
    ] {
        let mut s = session(id, i64::try_from(id).unwrap() * 10, version, suite);
        if id == 3 {
            s.certificates = vec![expired.clone(), shared.clone()];
            s.cert_issues = cert_issue::EXPIRED;
            s.sni = Some("host1.example.test".to_owned());
        } else if id < 3 {
            s.certificates = vec![shared.clone()];
        }
        put(&conn, s);
    }
    let st = stats(
        &conn,
        StatsLimits {
            versions: 8,
            suites: 15,
            sni: 15,
        },
    )
    .unwrap();
    assert_eq!((st.other_versions, st.other_suites), (0, 0));
    assert_eq!(st.sessions, 4);
    assert_eq!(st.weak_sessions, 1);
    assert_eq!(st.cert_issue_sessions, 1);
    assert_eq!(st.certificates, 2);
    assert_eq!(
        st.versions,
        vec![(Some(0x0304), 2), (None, 1), (Some(0x0303), 1)]
    );
    assert_eq!(st.suites[0].suite, 0x1301);
    assert_eq!(st.suites[0].count, 2);
    assert_eq!(st.suites[1].weak.as_deref(), Some("3des"));
    assert_eq!(st.pairs.len(), 2);
    assert_eq!(st.sni[0], ("host1.example.test".to_owned(), 2));

    let all = CertificateFilter::default();
    let page = certificates_page(&conn, &all, &PageRequest::first(10)).unwrap();
    let rows: Vec<_> = page
        .items
        .iter()
        .map(|c| (c.certificate.subject_cn.clone().unwrap(), c.sessions))
        .collect();
    assert_eq!(
        rows,
        vec![
            ("old.example.test".to_owned(), 1),
            ("shared.example.test".to_owned(), 3)
        ]
    );
    let problems = CertificateFilter {
        problems_only: true,
        capture_start: Some(10),
        capture_end: Some(100),
        ..CertificateFilter::default()
    };
    assert_eq!(count_certificates(&conn, &problems).unwrap(), 1);
    let q = CertificateFilter {
        q: Some("DNS:shared".to_owned()),
        ..CertificateFilter::default()
    };
    assert_eq!(count_certificates(&conn, &q).unwrap(), 1);
    assert_eq!(
        certificate(&conn, &"a".repeat(64))
            .unwrap()
            .unwrap()
            .subject_cn
            .as_deref(),
        Some("shared.example.test")
    );
    assert!(certificate(&conn, "zz").unwrap().is_none());
}

#[test]
fn stats_stay_bounded_with_many_distinct_versions_and_suites() {
    let conn = db();
    for i in 0..300u16 {
        let mut s = session(
            u64::from(i) + 1,
            i64::from(i),
            Some(0x1000 + i),
            Some(0x2000 + i),
        );
        s.cipher_names.clear();
        s.client_hello = None;
        s.server_hello = None;
        put(&conn, s);
    }
    // Two frequent ones.
    for i in 0..5u64 {
        put(&conn, session(1000 + i, 0, Some(0x0304), Some(0x1301)));
    }
    let limits = StatsLimits {
        versions: 8,
        suites: 15,
        sni: 15,
    };
    let st = stats(&conn, limits).unwrap();
    assert_eq!(st.versions.len(), 8);
    assert_eq!(st.versions[0], (Some(0x0304), 5));
    assert_eq!(st.other_versions, 305 - 5 - 7);
    assert_eq!(st.suites.len(), 15);
    assert_eq!(st.other_suites, 305 - 5 - 14);
    assert!(st.pairs.len() <= 9 * 16, "{}", st.pairs.len());
    let total: u64 = st.pairs.iter().map(|p| p.2).sum();
    assert_eq!(total, 305);
    assert!(st.pairs.contains(&(Some(0x0304), Some(0x1301), 5)));
    assert!(st.pairs.iter().any(|p| p.0.is_none() && p.1.is_none()));
    assert_eq!(st.sni.len(), 15);
}

#[test]
fn stored_flag_is_merged_and_a_rejected_session_leaves_nothing() {
    let conn = db();
    let mut c = cert('c', "x.example.test", false, 1);
    let mut s = session(10, 1, Some(0x0303), Some(0x1301));
    s.certificates = vec![c.clone()];
    put(&conn, s);
    c.stored = true;
    let mut s = session(11, 2, Some(0x0303), Some(0x1301));
    s.certificates = vec![c];
    put(&conn, s);
    let stored: bool = conn
        .query_row("SELECT stored FROM tls_certificates", [], |r| r.get(0))
        .unwrap();
    assert!(stored);

    conn.execute_batch(
        "CREATE TRIGGER refuse BEFORE INSERT ON tls_session_certificates \
         BEGIN SELECT RAISE(ABORT, 'refused'); END;",
    )
    .unwrap();
    let mut s = session(12, 3, Some(0x0303), Some(0x1301));
    s.certificates = vec![cert('d', "y.example.test", false, 1)];
    let err = StoreRecord::Tls(Box::new(s)).insert(&conn).unwrap_err();
    assert!(is_row_level(&err), "{err}");
    let n: i64 = conn
        .query_row(
            "SELECT (SELECT count(*) FROM tls_sessions WHERE id = 12) \
             + (SELECT count(*) FROM tls_client_hellos WHERE session_id = 12) \
             + (SELECT count(*) FROM tls_certificates WHERE sha256 LIKE 'd%')",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(n, 0);
}

#[test]
fn blob_paths_are_validated() {
    use crate::session::blob_relpath;
    let hex = "ab".repeat(32);
    assert_eq!(
        blob_relpath(&hex).unwrap(),
        std::path::Path::new("ab").join(&hex)
    );
    for bad in [
        "",
        "../etc",
        &"AB".repeat(32),
        &"ab".repeat(31),
        &format!("{}/x", "a".repeat(62)),
    ] {
        assert!(blob_relpath(bad).is_none(), "{bad}");
    }
}
