//! Tests of the credential emitters over synthetic captures (real flow layer).

use netsift_fixtures::Scenario;
use netsift_fixtures::credentials::{
    self as fx, SaslMech,
    credential_hosts::{directory, mail_server},
};
use netsift_fixtures::scenario::{FtpLogin, SmbNtlm, SnmpGet, TcpOptions};
use netsift_fixtures::scenarios::hosts;

use super::CredentialsAnalyzer;
use crate::analyzer::Analyzer;
use crate::http::HttpAnalyzer;
use crate::record::{Credential, Record, SecretState};
use crate::registry::AnalyzerConfig;
use crate::smb::SmbAnalyzer;
use crate::testutil::run;

fn creds_of(analyzer: &mut dyn Analyzer, sc: &Scenario) -> Vec<Credential> {
    run(analyzer, sc.packets())
        .into_iter()
        .filter_map(|r| match r {
            Record::Credential(c) => Some(c),
            _ => None,
        })
        .collect()
}

fn creds(sc: &Scenario) -> Vec<Credential> {
    creds_of(
        &mut CredentialsAnalyzer::new(&AnalyzerConfig::default()),
        sc,
    )
}

fn detail<'a>(c: &'a Credential, key: &str) -> Option<&'a str> {
    c.details
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

/// One line per credential, secrets included (fixture values only).
fn render(all: &[Credential]) -> String {
    let opt = |o: &Option<String>| o.clone().unwrap_or_else(|| "-".to_owned());
    all.iter()
        .map(|c| {
            let ep = |e: Option<netsift_flow::Endpoint>| {
                e.map_or_else(|| "-".to_owned(), |e| format!("{}:{}", e.ip, e.port))
            };
            let details: Vec<String> = c.details.iter().map(|(k, v)| format!("{k}={v}")).collect();
            format!(
                "{}/{} {} -> {} user={} domain={} ws={} {} secret={} mode={} line={} [{}]",
                c.source_protocol,
                c.kind,
                ep(c.client),
                ep(c.server),
                opt(&c.username),
                opt(&c.domain),
                opt(&c.workstation),
                c.secret_state.as_str(),
                opt(&c.secret),
                c.hashcat_mode
                    .map_or_else(|| "-".to_owned(), |m| m.to_string()),
                opt(&c.hashcat_line),
                details.join(" "),
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn ftp_login_with_its_result() {
    let mut sc = Scenario::new();
    sc.ftp_login(
        hosts::workstation(),
        hosts::ftp_server(),
        &FtpLogin::default(),
    );
    sc.ftp_login(
        hosts::workstation(),
        hosts::ftp_server(),
        &FtpLogin {
            user: "anonymous".to_owned(),
            password: "guest@example.test".to_owned(),
            accepted: false,
            ..FtpLogin::default()
        },
    );
    let all = creds(&sc);
    assert_eq!(all.len(), 2, "{all:?}");
    let c = &all[0];
    assert_eq!((c.source_protocol, c.kind), ("ftp", "ftp"));
    assert_eq!(c.username.as_deref(), Some("alice"));
    assert_eq!(c.secret.as_deref(), Some("s3cret-fixture"));
    assert_eq!(c.secret_state, SecretState::Plaintext);
    assert_eq!(c.server.map(|s| s.port), Some(21));
    assert_eq!(detail(c, "result"), Some("accepted"));
    assert_eq!(detail(&all[1], "result"), Some("rejected"));
    assert_eq!(detail(&all[1], "anonymous"), Some("true"));
}

#[test]
fn snmp_communities_of_requests_and_responses() {
    let mut sc = Scenario::new();
    sc.snmp_get(hosts::workstation(), hosts::router(), &SnmpGet::default());
    let all = creds(&sc);
    // The request and its response both carry the community: same manager -> agent pair.
    assert_eq!(all.len(), 2);
    for c in &all {
        assert_eq!((c.source_protocol, c.kind), ("snmp", "snmp"));
        assert_eq!(c.secret.as_deref(), Some("public"));
        assert_eq!(c.client.map(|e| e.ip), Some(hosts::workstation().ip));
        assert_eq!(c.server.map(|e| e.port), Some(161));
        assert_eq!(detail(c, "version"), Some("v2c"));
    }
}

#[test]
fn mail_mechanisms() {
    let mut sc = Scenario::new();
    let (ws, mx) = (hosts::workstation(), mail_server());
    fx::smtp_auth(
        &mut sc,
        ws,
        mx,
        SaslMech::Plain,
        "alice@example.test",
        "p1",
        true,
    );
    fx::smtp_auth(&mut sc, ws, mx, SaslMech::Login, "bob", "p2", false);
    fx::smtp_auth(&mut sc, ws, mx, SaslMech::CramMd5, "carol", "", true);
    fx::pop3_login(&mut sc, ws, mx, "dave", "p3");
    fx::imap_login(&mut sc, ws, mx, "erin", "p 4", false);
    let all = creds(&sc);
    let summary: Vec<_> = all
        .iter()
        .map(|c| {
            (
                c.source_protocol,
                detail(c, "mechanism").unwrap_or_default(),
                c.username.clone().unwrap_or_default(),
                c.secret.clone().unwrap_or_default(),
                detail(c, "result").unwrap_or_default(),
            )
        })
        .collect();
    let s = |v: &str| v.to_owned();
    assert_eq!(
        summary,
        vec![
            (
                "smtp",
                "PLAIN",
                s("alice@example.test"),
                s("p1"),
                "accepted"
            ),
            ("smtp", "LOGIN", s("bob"), s("p2"), "rejected"),
            ("smtp", "CRAM-MD5", s("carol"), s(""), "accepted"),
            ("pop3", "USER/PASS", s("dave"), s("p3"), "accepted"),
            ("imap", "LOGIN", s("erin"), s("p 4"), "rejected"),
        ]
    );
    let cram = &all[2];
    assert_eq!(cram.kind, "mail");
    assert_eq!(cram.secret_state, SecretState::Recoverable);
    assert_eq!(cram.hashcat_mode, Some(16400));
    assert!(
        cram.hashcat_line
            .as_deref()
            .unwrap()
            .starts_with("$cram_md5$PDE4OTYu")
    );
}

#[test]
fn ldap_simple_binds() {
    let mut sc = Scenario::new();
    let dn = "cn=svc,dc=corp,dc=example";
    fx::ldap_simple_bind(&mut sc, hosts::workstation(), directory(), dn, "pw-ok", 0);
    fx::ldap_simple_bind(&mut sc, hosts::workstation(), directory(), dn, "pw-bad", 49);
    // Anonymous bind: no credential.
    netsift_fixtures::servers::servers_showcase(&mut sc);
    let all = creds(&sc);
    assert_eq!(all.len(), 2, "{all:?}");
    assert_eq!(all[0].username.as_deref(), Some(dn));
    assert_eq!(all[0].secret.as_deref(), Some("pw-ok"));
    assert_eq!(detail(&all[0], "result"), Some("accepted"));
    assert_eq!(detail(&all[1], "result"), Some("rejected"));
    assert_eq!(
        detail(&all[1], "result_code"),
        Some("49 (invalidCredentials)")
    );
}

#[test]
fn ldap_bind_split_over_segments() {
    // A tiny MSS splits the BER message over many segments.
    let mut sc = Scenario::new();
    let mut s = sc.tcp_open(
        hosts::workstation(),
        directory(),
        &TcpOptions {
            mss: 5,
            ..TcpOptions::new(389)
        },
    );
    s.client_send(&fx::ldap_bind_request(7, "uid=x", "segmented"));
    s.server_send(&fx::ldap_bind_response(7, 0));
    s.close();
    let all = creds(&sc);
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].secret.as_deref(), Some("segmented"));
}

#[test]
fn unanswered_credentials_are_emitted_at_the_end() {
    let mut sc = Scenario::new();
    let mut s = sc.tcp_open(
        hosts::workstation(),
        hosts::ftp_server(),
        &TcpOptions::new(21),
    );
    s.client_send(b"USER bob\r\nPASS never-answered\r\n");
    // No close: the flow ends with the capture.
    let all = creds(&sc);
    assert_eq!(all.len(), 1);
    assert_eq!(detail(&all[0], "result"), None);
}

#[test]
fn midstream_connection_is_reoriented() {
    // Only the server's data and the client's PASS: the flow key may be reversed, the
    // credential still names the FTP server as server.
    let mut sc = Scenario::new();
    let mut s = sc.tcp_open(
        hosts::workstation(),
        hosts::ftp_server(),
        &TcpOptions::new(21),
    );
    s.client_send(b"PASS x\r\n");
    s.server_send(b"230 ok\r\n");
    s.close();
    let mut packets = sc.into_packets();
    packets.drain(..3); // drop the handshake
    let mut a = CredentialsAnalyzer::new(&AnalyzerConfig::default());
    let out = run(&mut a, &packets);
    let c: Vec<_> = out
        .into_iter()
        .filter_map(|r| match r {
            Record::Credential(c) => Some(c),
            _ => None,
        })
        .collect();
    assert_eq!(c.len(), 1, "{c:?}");
    assert_eq!(c[0].server.map(|e| e.port), Some(21));
}

#[test]
fn credentials_per_flow_are_bounded() {
    let mut sc = Scenario::new();
    let mut s = sc.tcp_open(
        hosts::workstation(),
        hosts::ftp_server(),
        &TcpOptions::new(21),
    );
    for i in 0..(super::MAX_PER_FLOW + 20) {
        s.client_send(format!("USER u{i}\r\nPASS p{i}\r\n").as_bytes());
        s.server_send(b"530 no\r\n");
    }
    s.close();
    assert_eq!(creds(&sc).len(), super::MAX_PER_FLOW);
}

#[test]
fn hostile_streams_never_panic() {
    // Random-looking bytes on every parsed port, both directions.
    for port in [21u16, 25, 110, 143, 389, 587] {
        let mut sc = Scenario::new();
        let mut s = sc.tcp_open(hosts::workstation(), mail_server(), &TcpOptions::new(port));
        let junk: Vec<u8> = (0..3000u32)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 13).to_le_bytes()[0])
            .collect();
        s.client_send(&junk);
        s.server_send(&junk);
        s.client_send(b"AUTH PLAIN ====\r\nAUTH LOGIN\r\n*\r\na LOGIN {3}\r\n");
        s.server_send(&[0x30, 0x84, 0xff, 0xff, 0xff, 0xff]);
        s.close();
        let _ = creds(&sc);
    }
    // Truncated SNMP datagrams.
    let mut sc = Scenario::new();
    for cut in [0usize, 1, 2, 5, 9] {
        sc.udp(
            hosts::workstation(),
            hosts::router(),
            40_000,
            161,
            &[0x30, 0x82, 0x01, 0x00, 0x02][..cut.min(5)],
        );
    }
    assert_eq!(creds(&sc).len(), 0);
}

#[test]
fn http_basic_proxy_forms_and_ntlm() {
    let mut sc = Scenario::new();
    let ws = hosts::workstation();
    let intranet = fx::credential_hosts::intranet();
    fx::http_basic(&mut sc, ws, intranet, "admin", "basic-pw", false);
    fx::http_basic(
        &mut sc,
        ws,
        fx::credential_hosts::proxy(),
        "px",
        "proxy-pw",
        true,
    );
    fx::http_ntlm(&mut sc, ws, intranet, &SmbNtlm::v2("mmartin", "CONTOSO"));
    // Login form in a body, and a password in a query string.
    let mut s = sc.tcp_open(ws, intranet, &TcpOptions::new(80));
    let body = b"login=jdoe&pass_word=x&password=form%20pw&remember=1";
    s.client_send(
        format!(
            "POST /login?next=%2F HTTP/1.1\r\nHost: intranet.example.test\r\n\
             Content-Type: application/x-www-form-urlencoded; charset=UTF-8\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .as_bytes(),
    );
    s.client_send(body);
    s.server_send(b"HTTP/1.1 302 Found\r\nLocation: /\r\nContent-Length: 0\r\n\r\n");
    s.client_send(b"GET /api?user=svc&pwd=q-pw HTTP/1.1\r\nHost: intranet.example.test\r\n\r\n");
    s.server_send(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    // A search form without password: nothing.
    s.client_send(b"GET /search?q=password HTTP/1.1\r\nHost: intranet.example.test\r\n\r\n");
    s.server_send(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    s.close();

    let all = creds_of(&mut HttpAnalyzer::new(&AnalyzerConfig::default()), &sc);
    insta::assert_snapshot!(render(&all));
    assert_eq!(all.len(), 5, "{}", render(&all));
}

#[test]
fn showcase_records() {
    // Every emitter of the showcase, through the three analyzers that emit credentials.
    let mut sc = Scenario::new();
    fx::credentials_showcase(&mut sc);
    let config = AnalyzerConfig::default();
    let mut all = creds_of(&mut CredentialsAnalyzer::new(&config), &sc);
    all.extend(creds_of(&mut HttpAnalyzer::new(&config), &sc));
    all.extend(creds_of(&mut SmbAnalyzer::new(&config), &sc));
    all.sort_by_key(|c| c.ts);
    insta::assert_snapshot!(render(&all));
    // Debug never shows a secret.
    for c in &all {
        let debug = format!("{c:?}");
        if let Some(secret) = &c.secret {
            assert!(
                !debug.contains(secret.as_str()) || secret.is_empty(),
                "{debug}"
            );
        }
        if let Some(line) = &c.hashcat_line {
            assert!(!debug.contains(line.as_str()), "{debug}");
        }
    }
}
