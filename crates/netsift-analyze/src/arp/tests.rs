//! Tests of the `arp` analyzer on synthetic captures (`netsift_fixtures::arp`).

use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr};

use netsift_fixtures::arp::{ArpFrame, arp_hosts, arp_showcase};
use netsift_fixtures::scenario::Scenario;
use netsift_fixtures::scenarios::hosts;
use netsift_fixtures::time::NS_PER_SEC;

use super::{ANSWER_WINDOW_NS, ArpAnalyzer, ArpKind, ArpMessage, MAX_PENDING};
use crate::record::Record;
use crate::registry::AnalyzerConfig;
use crate::testutil;

fn run(sc: &Scenario) -> Vec<ArpMessage> {
    let mut analyzer = ArpAnalyzer::new(&AnalyzerConfig::default());
    testutil::run(&mut analyzer, sc.packets())
        .into_iter()
        .filter_map(|r| match r {
            Record::Arp(m) => Some(m),
            _ => None,
        })
        .collect()
}

fn mac(m: Option<[u8; 6]>) -> String {
    m.map_or_else(
        || "-".to_owned(),
        |m| {
            m.iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(":")
        },
    )
}

fn ip(i: Option<IpAddr>) -> String {
    i.map_or_else(|| "-".to_owned(), |i| i.to_string())
}

/// One line per message, time relative to the first.
fn render(messages: &[ArpMessage]) -> String {
    let t0 = messages.first().map_or(0, |m| m.ts_ns);
    let mut out = String::new();
    for m in messages {
        writeln!(
            out,
            "+{:>6}ms #{:<2} op={} {:<10} {} {:<13} -> {} {:<13}{}{}",
            (m.ts_ns - t0) / 1_000_000,
            m.frame,
            m.operation,
            m.kind.as_str(),
            mac(m.sender_mac),
            ip(m.sender_ip),
            mac(m.target_mac),
            ip(m.target_ip),
            if m.binds { " binds" } else { "" },
            if m.unsolicited { " unsolicited" } else { "" },
        )
        .unwrap();
    }
    out
}

#[test]
fn showcase_types_and_flags() {
    let mut sc = Scenario::new();
    let expected = arp_showcase(&mut sc);
    let messages = run(&sc);
    assert_eq!(messages.len(), sc.len());
    let count = |k: ArpKind| messages.iter().filter(|m| m.kind == k).count();
    assert_eq!(count(ArpKind::Request), expected.requests);
    assert_eq!(count(ArpKind::Reply), expected.replies);
    assert_eq!(count(ArpKind::Gratuitous), expected.gratuitous);
    assert_eq!(count(ArpKind::Probe), expected.probes);
    let unsolicited: Vec<_> = messages.iter().filter(|m| m.unsolicited).collect();
    assert_eq!(unsolicited.len(), expected.unsolicited);
    assert!(
        unsolicited
            .iter()
            .all(|m| m.sender_mac == Some(arp_hosts::intruder().mac))
    );
    // The probe announces nothing; the others do.
    assert!(
        messages
            .iter()
            .all(|m| m.binds == (m.kind != ArpKind::Probe))
    );
    insta::assert_snapshot!("arp_showcase", render(&messages));
}

#[test]
fn replies_of_the_first_window_are_never_flagged() {
    let mut sc = Scenario::new();
    // A reply with no request, at the start of the capture: its request may predate it.
    sc.arp_reply(hosts::router(), hosts::workstation());
    sc.advance(ANSWER_WINDOW_NS + NS_PER_SEC);
    // The same reply later is unsolicited; after a request it is not.
    sc.arp_reply(hosts::router(), hosts::workstation());
    sc.arp_exchange(hosts::workstation(), hosts::router());
    // An answer that comes too late is unsolicited again.
    sc.arp_request(hosts::workstation(), [192, 168, 1, 1]);
    sc.advance(ANSWER_WINDOW_NS + NS_PER_SEC);
    sc.arp_reply(hosts::router(), hosts::workstation());
    let flags: Vec<_> = run(&sc)
        .iter()
        .filter(|m| m.kind == ArpKind::Reply)
        .map(|m| m.unsolicited)
        .collect();
    assert_eq!(flags, vec![false, true, false, true]);
}

#[test]
fn a_defended_probe_is_answered() {
    let mut sc = Scenario::new();
    sc.advance(1);
    sc.arp_request(hosts::workstation(), [192, 168, 1, 99]);
    sc.advance(ANSWER_WINDOW_NS + NS_PER_SEC);
    sc.arp_probe(arp_hosts::laptop().mac, [192, 168, 1, 20]);
    // The owner defends the address: reply to 0.0.0.0.
    sc.arp(&ArpFrame {
        eth_dst: arp_hosts::laptop().mac,
        operation: 2,
        sender_mac: hosts::file_server().mac,
        sender_ip: Ipv4Addr::new(192, 168, 1, 20),
        target_mac: arp_hosts::laptop().mac,
        target_ip: Ipv4Addr::UNSPECIFIED,
    });
    let m = run(&sc);
    assert_eq!(m[2].kind, ArpKind::Reply);
    assert!(!m[2].unsolicited);
}

#[test]
fn other_operations_and_odd_senders() {
    let mut sc = Scenario::new();
    let frame = |operation, sender_mac: [u8; 6]| ArpFrame {
        eth_dst: [0xff; 6],
        operation,
        sender_mac,
        sender_ip: Ipv4Addr::new(192, 168, 1, 7),
        target_mac: [0; 6],
        target_ip: Ipv4Addr::new(192, 168, 1, 8),
    };
    sc.arp(&frame(3, [2, 0, 0, 0, 0, 7])); // RARP request
    sc.arp(&frame(1, [0x01, 0, 0x5e, 0, 0, 1])); // multicast sender MAC
    sc.arp(&frame(1, [0; 6])); // zero sender MAC
    let m = run(&sc);
    assert_eq!(m[0].kind, ArpKind::Other);
    assert!(!m[0].binds);
    assert_eq!(m[1].kind, ArpKind::Request);
    assert!(!m[1].binds);
    assert!(!m[2].binds);
}

#[test]
fn pending_requests_are_bounded() {
    let asker = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let fill = |a: &mut ArpAnalyzer| {
        for i in 0..u32::try_from(MAX_PENDING).unwrap() {
            a.remember(1, asker, IpAddr::V4(Ipv4Addr::from(i)));
        }
        assert_eq!(a.pending.len(), MAX_PENDING);
    };
    let other = IpAddr::V4(Ipv4Addr::from(u32::MAX));
    // Full of expired requests: they are dropped.
    let mut a = ArpAnalyzer::default();
    fill(&mut a);
    a.remember(1 + 2 * ANSWER_WINDOW_NS, asker, other);
    assert_eq!(a.pending.len(), 1);
    // Full of live requests: forgotten all at once, memory stays bounded.
    let mut a = ArpAnalyzer::default();
    fill(&mut a);
    a.remember(2, asker, other);
    assert_eq!(a.pending.len(), 1);
    // Refreshing a known request never evicts.
    let mut a = ArpAnalyzer::default();
    fill(&mut a);
    a.remember(3, asker, IpAddr::V4(Ipv4Addr::from(0)));
    assert_eq!(a.pending.len(), MAX_PENDING);
}
