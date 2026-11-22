//! Tests of the `telnet` analyzer over synthetic captures (real flow layer).

use std::fmt::Write as _;

use netsift_fixtures::Scenario;
use netsift_fixtures::scenario::TcpOptions;
use netsift_fixtures::telnet::{self as fx, SHOWCASE, telnet_hosts};

use super::{LoginResult, MAX_BYTES, MAX_LINES, Speaker, TelnetAnalyzer, TelnetSession};
use crate::record::{Credential, Record};
use crate::registry::AnalyzerConfig;
use crate::testutil::run;

fn records(sc: &Scenario) -> (Vec<TelnetSession>, Vec<Credential>) {
    let mut analyzer = TelnetAnalyzer::new(&AnalyzerConfig::default());
    let mut sessions = Vec::new();
    let mut creds = Vec::new();
    for r in run(&mut analyzer, sc.packets()) {
        match r {
            Record::Telnet(s) => sessions.push(*s),
            Record::Credential(c) => creds.push(c),
            other => panic!("unexpected record {other:?}"),
        }
    }
    sessions.sort_by_key(|s| s.flow_id);
    (sessions, creds)
}

/// Transcript with speaker tags (`{c:...}` client, `{p:...}` secret), secrets included.
fn transcript(s: &TelnetSession) -> String {
    s.transcript
        .iter()
        .map(|r| match r.speaker {
            Speaker::Server => r.text.clone(),
            Speaker::Client => format!("{{c:{}}}", r.text),
            Speaker::Secret => format!("{{p:{}}}", r.text),
        })
        .collect()
}

fn render(sessions: &[TelnetSession], creds: &[Credential]) -> String {
    let opt = |o: &Option<String>| o.clone().unwrap_or_else(|| "-".to_owned());
    let mut out = String::new();
    for s in sessions {
        let _ = writeln!(
            out,
            "== {}:{} -> {}:{} user={} env_user={} login={} attempts={} terminal={} window={} \
             options=[{}] bytes={} lines={} truncated={}",
            s.client.ip,
            s.client.port,
            s.server.ip,
            s.server.port,
            opt(&s.username),
            opt(&s.env_user),
            s.login.map_or("-", LoginResult::as_str),
            s.login_attempts,
            opt(&s.terminal),
            s.window
                .map_or_else(|| "-".to_owned(), |(c, r)| format!("{c}x{r}")),
            s.options.join(","),
            s.transcript_bytes,
            s.transcript_lines,
            s.truncated,
        );
        if s.truncated {
            let text = transcript(s);
            let head: String = text.lines().take(14).collect::<Vec<_>>().join("\n");
            let _ = writeln!(out, "{head}\n[... {} lines]", text.lines().count());
        } else {
            out.push_str(&transcript(s));
            out.push('\n');
        }
    }
    out.push_str("== credentials\n");
    for c in creds {
        let details: Vec<String> = c.details.iter().map(|(k, v)| format!("{k}={v}")).collect();
        let _ = writeln!(
            out,
            "{}/{} {} -> {} user={} secret={} [{}]",
            c.source_protocol,
            c.kind,
            c.client.map_or_else(String::new, |e| e.ip.to_string()),
            c.server
                .map_or_else(String::new, |e| format!("{}:{}", e.ip, e.port)),
            opt(&c.username),
            opt(&c.secret),
            details.join(" "),
        );
    }
    out
}

#[test]
fn showcase_sessions_and_credentials() {
    let mut sc = Scenario::new();
    fx::telnet_showcase(&mut sc);
    let (sessions, creds) = records(&sc);
    assert_eq!(sessions.len() as u64, SHOWCASE.sessions);
    assert_eq!(creds.len() as u64, SHOWCASE.credentials);
    let count =
        |f: &dyn Fn(&TelnetSession) -> bool| sessions.iter().filter(|s| f(s)).count() as u64;
    assert_eq!(count(&|s| s.login_attempts > 0), SHOWCASE.logins);
    assert_eq!(
        count(&|s| s.login == Some(LoginResult::Accepted)),
        SHOWCASE.accepted
    );
    assert_eq!(
        count(&|s| s.login == Some(LoginResult::Rejected)),
        SHOWCASE.rejected
    );
    assert_eq!(count(&|s| s.truncated), SHOWCASE.truncated);
    insta::assert_snapshot!(render(&sessions, &creds));
}

#[test]
fn truncated_session_respects_the_bounds() {
    let mut sc = Scenario::new();
    fx::long_session(
        &mut sc,
        telnet_hosts::laptop(),
        telnet_hosts::camera(),
        "root",
        "cam-fixture",
    );
    let (sessions, creds) = records(&sc);
    let s = &sessions[0];
    assert!(s.truncated);
    assert!(s.transcript_lines <= MAX_LINES);
    assert!(usize::try_from(s.transcript_bytes).unwrap() <= MAX_BYTES);
    let text: usize = s.transcript.iter().map(|r| r.text.len()).sum();
    assert_eq!(text as u64, s.transcript_bytes);
    // The login happened before the bound: still detected.
    assert_eq!(creds.len(), 1);
    assert_eq!(s.login, Some(LoginResult::Accepted));
    assert_eq!(s.server.port, fx::ALT_PORT);
}

#[test]
fn split_iac_sequences_give_the_same_session_as_whole_segments() {
    let mut sc = Scenario::new();
    fx::split_iac(
        &mut sc,
        telnet_hosts::workstation(),
        telnet_hosts::unix_server(),
        "ops",
        "split-fixture",
    );
    let (sessions, creds) = records(&sc);
    let s = &sessions[0];
    assert_eq!(s.terminal.as_deref(), Some("ANSI"));
    assert_eq!(s.username.as_deref(), Some("ops"));
    assert_eq!(creds[0].secret.as_deref(), Some("split-fixture"));
    let text = transcript(s);
    // `IAC EC` erased the mistyped letter; `IAC IAC` gave a data byte (invalid UTF-8 here).
    assert!(text.contains("login: {c:ops\n}"), "{text}");
    assert!(text.contains("banner \u{fffd}\u{fffd}\n$ "), "{text}");
    assert!(!text.contains('\u{1b}'));
}

#[test]
fn connection_picked_up_in_the_middle_is_oriented_by_port() {
    // The capture starts after the handshake: the first packet seen is the server's.
    let mut sc = Scenario::new();
    let mut s = sc.tcp_open(
        telnet_hosts::workstation(),
        telnet_hosts::unix_server(),
        &TcpOptions::new(fx::PORT),
    );
    s.server_send(b"login: ");
    s.client_send(b"bob\r\n");
    s.server_send(b"Password:");
    s.client_send(b"mid-fixture\r\n");
    s.server_send(b"\r\nLogin incorrect\r\n");
    s.close();
    let packets: Vec<_> = sc.packets()[3..].to_vec();
    let mut analyzer = TelnetAnalyzer::new(&AnalyzerConfig::default());
    let out = run(&mut analyzer, &packets);
    let session = out
        .iter()
        .find_map(|r| match r {
            Record::Telnet(s) => Some(s),
            _ => None,
        })
        .unwrap();
    assert_eq!(session.server.port, fx::PORT);
    assert_eq!(session.login, Some(LoginResult::Rejected));
    assert_eq!(session.username.as_deref(), Some("bob"));
}

#[test]
fn other_ports_and_empty_connections_are_ignored() {
    let mut sc = Scenario::new();
    let mut s = sc.tcp_open(
        telnet_hosts::workstation(),
        telnet_hosts::unix_server(),
        &TcpOptions::new(8023),
    );
    s.server_send(b"login: ");
    s.close();
    let s = sc.tcp_open(
        telnet_hosts::workstation(),
        telnet_hosts::unix_server(),
        &TcpOptions::new(fx::PORT),
    );
    s.close();
    let (sessions, creds) = records(&sc);
    assert_eq!((sessions.len(), creds.len()), (0, 0));
}

#[test]
fn debug_output_never_shows_secrets() {
    let mut sc = Scenario::new();
    fx::telnet_showcase(&mut sc);
    let (sessions, creds) = records(&sc);
    let debug = format!("{sessions:?} {creds:?}");
    for secret in [
        "user-fixture",
        "switch-fixture",
        "cam-fixture",
        "split-fixture",
    ] {
        assert!(!debug.contains(secret), "{secret} leaked");
    }
    let runs: Vec<_> = sessions.iter().flat_map(|s| s.transcript.clone()).collect();
    assert!(!format!("{runs:?}").contains("user-fixture"));
}

#[test]
fn shard_budget_truncates_new_transcripts() {
    let mut sc = Scenario::new();
    fx::unix_login(
        &mut sc,
        telnet_hosts::workstation(),
        telnet_hosts::unix_server(),
        "fake",
        "user-fixture",
    );
    let mut analyzer = TelnetAnalyzer::new(&AnalyzerConfig::default());
    analyzer.budget = 40;
    let out = run(&mut analyzer, sc.packets());
    let session = out
        .iter()
        .find_map(|r| match r {
            Record::Telnet(s) => Some(s),
            _ => None,
        })
        .unwrap();
    assert!(session.truncated);
    assert_eq!(session.transcript_bytes, 40);
    // The budget is given back at the end of the flow.
    assert_eq!(analyzer.budget, 40);
}
