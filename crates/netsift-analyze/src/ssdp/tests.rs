//! Tests of the SSDP parser and analyzer.

use std::fmt::Write as _;

use netsift_fixtures::Scenario;
use netsift_fixtures::ssdp::{self, ShowcaseCounts};

use super::parser::{MAX_FIELD, MAX_RAW, SsdpKind, parse, raw_text};
use super::{SsdpAnalyzer, SsdpRecord};
use crate::record::Record;
use crate::registry::AnalyzerConfig;
use crate::testutil;

// ---- parser ------------------------------------------------------------------------------------

#[test]
fn notify_alive_is_decoded() {
    let d = ssdp::gateway();
    let m = parse(d.notify(d.device_type, "ssdp:alive").as_bytes());
    assert_eq!(m.kind, SsdpKind::Notify);
    assert_eq!(m.nts.as_deref(), Some("alive"));
    assert_eq!(m.target.as_deref(), Some(d.device_type));
    assert_eq!(m.device_type(), Some(d.device_type));
    assert_eq!(m.uuid.as_deref(), Some(d.uuid));
    assert_eq!(m.server.as_deref(), Some(d.server));
    assert_eq!(m.location.as_deref(), Some(d.location.as_str()));
    assert_eq!(m.max_age, Some(120));
    assert_eq!(m.status, None);
    assert!(!m.raw_truncated);
    assert!(
        m.raw
            .starts_with("NOTIFY * HTTP/1.1\nHOST: 239.255.255.250:1900\n")
    );
    assert!(!m.raw.contains('\r'));
}

#[test]
fn byebye_search_and_response_are_decoded() {
    let d = ssdp::tv();
    let bye = parse(d.notify(ssdp::ROOT_DEVICE, "ssdp:byebye").as_bytes());
    assert_eq!(bye.kind, SsdpKind::Notify);
    assert_eq!(bye.nts.as_deref(), Some("byebye"));
    assert_eq!(bye.uuid.as_deref(), Some(d.uuid));
    assert_eq!(bye.location, None);
    assert_eq!(bye.device_type(), None);

    let s = parse(ssdp::search("239.255.255.250:1900", ssdp::ALL, 3, "Agent/1").as_bytes());
    assert_eq!(s.kind, SsdpKind::Search);
    assert_eq!(s.target.as_deref(), Some(ssdp::ALL));
    assert_eq!(s.mx, Some(3));
    assert_eq!(s.user_agent.as_deref(), Some("Agent/1"));
    assert_eq!((s.nts, s.uuid), (None, None));

    let r = parse(d.response(d.device_type).as_bytes());
    assert_eq!(r.kind, SsdpKind::Response);
    assert_eq!(r.status, Some(200));
    assert_eq!(r.target.as_deref(), Some(d.device_type));
    assert_eq!(r.uuid.as_deref(), Some(d.uuid));
    assert_eq!(r.max_age, Some(1800));
}

#[test]
fn uuid_target_gives_the_device_and_lower_case() {
    let m = parse(
        b"NOTIFY * HTTP/1.1\r\nNT: uuid:ABCDEF-01\r\nNTS: ssdp:update\r\nUSN: uuid:ABCDEF-01\r\n\r\n",
    );
    assert_eq!(m.uuid.as_deref(), Some("abcdef-01"));
    assert_eq!(m.nts.as_deref(), Some("update"));
    let other = parse(b"NOTIFY * HTTP/1.1\r\nNT: uuid:Z\r\nNTS: custom:thing\r\n\r\n");
    assert_eq!(other.uuid.as_deref(), Some("z"));
    assert_eq!(other.nts.as_deref(), Some("custom:thing"));
}

#[test]
fn field_quirks_are_tolerated() {
    // LF-only line ends, lower-case names, spaces after a name (response), an invalid header
    // line, no final empty line, quoted max-age among other directives.
    let m = parse(
        b"HTTP/1.1 200 OK\nst: upnp:rootdevice\nUSN : uuid:aa::upnp:rootdevice\n\
          bad line without colon\ncache-control: no-cache=\"x\", max-age = \"60\"\nLocation: http://h/d.xml",
    );
    assert_eq!(m.kind, SsdpKind::Response);
    assert_eq!(m.target.as_deref(), Some("upnp:rootdevice"));
    assert_eq!(m.uuid.as_deref(), Some("aa"));
    assert_eq!(m.max_age, Some(60));
    // The last line, without its end, is not read: it may have been cut.
    assert_eq!(m.location, None);
}

#[test]
fn first_header_wins_and_numbers_saturate() {
    let m = parse(b"M-SEARCH * HTTP/1.1\r\nST: a\r\nST: b\r\nMX: 99999999999\r\n\r\n");
    assert_eq!(m.target.as_deref(), Some("a"));
    assert_eq!(m.mx, Some(u32::MAX));
    let m = parse(b"M-SEARCH * HTTP/1.1\r\nMX: -1\r\nMX: 2\r\n\r\n");
    assert_eq!(m.mx, Some(2));
}

#[test]
fn malformed_messages_are_invalid_with_their_raw_text() {
    for input in [
        &b""[..],
        b"\x00\x01\x02\xff\xfe binary",
        b"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
        b"SUBSCRIBE * HTTP/1.1\r\nNT: x\r\n\r\n",
        b"NOTIFY * HTTP/9\r\n\r\n",
        b"HTTP/1.1 abc OK\r\n\r\n",
        b"just text without line end",
    ] {
        let m = parse(input);
        assert_eq!(m.kind, SsdpKind::Invalid, "{input:?}");
        assert_eq!((m.target.as_deref(), m.uuid.as_deref()), (None, None));
        assert_eq!(m.size, input.len());
    }
    let m = parse(b"\x00\x01\x02\xff\xfe binary\r\nline");
    assert_eq!(
        m.raw,
        "\u{fffd}\u{fffd}\u{fffd}\u{fffd}\u{fffd} binary\nline"
    );
}

#[test]
fn too_many_headers_make_the_message_invalid() {
    let mut m = String::from("NOTIFY * HTTP/1.1\r\n");
    for i in 0..100 {
        let _ = write!(m, "X-{i}: v\r\n");
    }
    m.push_str("\r\n");
    assert_eq!(parse(m.as_bytes()).kind, SsdpKind::Invalid);
}

#[test]
fn fields_and_raw_text_are_bounded() {
    let big = ssdp::oversized_notify();
    let m = parse(big.as_bytes());
    assert_eq!(m.kind, SsdpKind::Notify);
    let server = m.server.unwrap_or_default();
    assert_eq!(server.len(), MAX_FIELD);
    assert!(m.raw_truncated);
    assert!(m.raw.len() <= MAX_RAW);
    assert_eq!(m.size, big.len());
    // Multi-byte characters are cut on a boundary.
    let value = "é".repeat(400);
    let m = parse(format!("M-SEARCH * HTTP/1.1\r\nST: {value}\r\n\r\n").as_bytes());
    let st = m.target.unwrap_or_default();
    assert!(st.len() <= MAX_FIELD && st.chars().all(|c| c == 'é'));
}

#[test]
fn control_characters_never_reach_fields_or_raw_text() {
    let (raw, truncated) = raw_text(b"A\r\nB\rC\x1b[31mD\tE\x7f");
    assert_eq!(raw, "A\nB\nC\u{fffd}[31mD\tE\u{fffd}");
    assert!(!truncated);
    // httparse refuses control bytes in values: the line is skipped, never kept.
    let m = parse(b"NOTIFY * HTTP/1.1\r\nSERVER: a\x1bb\r\nNT: x\r\n\r\n");
    assert!(
        m.server
            .as_deref()
            .is_none_or(|s| !s.chars().any(char::is_control))
    );
    assert_eq!(m.target.as_deref(), Some("x"));
}

#[test]
fn arbitrary_bytes_never_panic() {
    let mut seed = 0x1234_5678_u64;
    for len in 0..600 {
        let bytes: Vec<u8> = (0..len)
            .map(|_| {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                seed.to_le_bytes()[3]
            })
            .collect();
        let m = parse(&bytes);
        assert!(m.raw.len() <= 3 * MAX_RAW);
        // Prefixed with a valid start line.
        let mut framed = b"NOTIFY * HTTP/1.1\r\n".to_vec();
        framed.extend_from_slice(&bytes);
        let _ = parse(&framed);
    }
}

// ---- analyzer ----------------------------------------------------------------------------------

fn showcase() -> (Vec<netsift_fixtures::Packet>, ShowcaseCounts) {
    let mut sc = Scenario::new();
    let counts = ssdp::ssdp_showcase(&mut sc);
    (sc.into_packets(), counts)
}

fn records(packets: &[netsift_fixtures::Packet]) -> Vec<SsdpRecord> {
    let mut analyzer = SsdpAnalyzer::new(&AnalyzerConfig::default());
    testutil::run(&mut analyzer, packets)
        .into_iter()
        .filter_map(|r| match r {
            Record::Ssdp(r) => Some(*r),
            _ => None,
        })
        .collect()
}

#[test]
fn showcase_gives_one_record_per_datagram() {
    let (packets, n) = showcase();
    let recs = records(&packets);
    assert_eq!(recs.len(), n.total());
    let count = |k: SsdpKind| recs.iter().filter(|r| r.message.kind == k).count();
    assert_eq!(count(SsdpKind::Notify), n.notify());
    assert_eq!(count(SsdpKind::Search), n.search);
    assert_eq!(count(SsdpKind::Response), n.response);
    assert_eq!(count(SsdpKind::Invalid), n.invalid);
    let byebye = recs
        .iter()
        .filter(|r| r.message.nts.as_deref() == Some("byebye"))
        .count();
    assert_eq!(byebye, n.byebye);
    // Multicast announcements and searches, unicast answers; IPv6 included.
    assert!(recs.iter().any(|r| r.dst.ip.is_ipv6() && r.multicast));
    assert!(
        recs.iter()
            .filter(|r| r.message.kind == SsdpKind::Response)
            .all(|r| !r.multicast && r.src.port == 1900)
    );
}

#[test]
fn other_udp_and_empty_datagrams_are_ignored() {
    let mut sc = Scenario::new();
    let ws = netsift_fixtures::scenarios::hosts::workstation();
    let group = ssdp::ssdp_hosts::multicast_v4();
    sc.udp(ws, group, 50_000, 1901, b"NOTIFY * HTTP/1.1\r\n\r\n");
    sc.udp(ws, group, 50_000, 1900, b"");
    assert_eq!(records(sc.packets()), Vec::new());
}

fn render(recs: &[SsdpRecord]) -> String {
    let mut out = String::new();
    for r in recs {
        let m = &r.message;
        let _ = writeln!(
            out,
            "{} {}:{} -> {}:{} mc={} kind={} nts={} status={} target={} uuid={} server={} ua={} \
             location={} max_age={} mx={} size={} raw={}{}",
            r.ts,
            r.src.ip,
            r.src.port,
            r.dst.ip,
            r.dst.port,
            r.multicast,
            m.kind.as_str(),
            m.nts.as_deref().unwrap_or("-"),
            m.status.map_or("-".to_owned(), |s| s.to_string()),
            m.target.as_deref().unwrap_or("-"),
            m.uuid.as_deref().unwrap_or("-"),
            m.server
                .as_deref()
                .map_or("-".to_owned(), |s| format!("{}b", s.len())),
            m.user_agent.as_deref().unwrap_or("-"),
            m.location.as_deref().unwrap_or("-"),
            m.max_age.map_or("-".to_owned(), |v| v.to_string()),
            m.mx.map_or("-".to_owned(), |v| v.to_string()),
            m.size,
            m.raw.len(),
            if m.raw_truncated { "+" } else { "" },
        );
    }
    out
}

#[test]
fn showcase_records_snapshot() {
    let (packets, _) = showcase();
    insta::assert_snapshot!(render(&records(&packets)));
}
