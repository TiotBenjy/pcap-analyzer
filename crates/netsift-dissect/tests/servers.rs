//! DHCP, NTP and Kerberos parsers on synthetic messages (netsift-fixtures), truncated and hostile
//! input included.

use std::net::Ipv4Addr;

use netsift_dissect::{dhcp, kerberos, ntp};
use netsift_fixtures::proto::dhcp::{DhcpMessage, DhcpType};
use netsift_fixtures::proto::kerberos as krb;
use netsift_fixtures::proto::ntp as ntp_fx;
use proptest::prelude::*;

const MAC: [u8; 6] = [0x02, 0, 0x5e, 0x10, 0, 0x30];

fn ack() -> DhcpMessage {
    let mut m = DhcpMessage::new(DhcpType::Ack, 0xdead_beef, MAC);
    m.yiaddr = Ipv4Addr::new(192, 168, 1, 30);
    m.server_id = Some(Ipv4Addr::new(192, 168, 1, 1));
    m.subnet_mask = Some(Ipv4Addr::new(255, 255, 255, 0));
    m.routers = vec![Ipv4Addr::new(192, 168, 1, 1)];
    m.dns_servers = vec![Ipv4Addr::new(192, 168, 1, 1), Ipv4Addr::new(192, 0, 2, 53)];
    m.lease_time = Some(86_400);
    m.hostname = Some("laptop-30".to_owned());
    m
}

#[test]
fn dhcp_ack_options_are_decoded() {
    let msg = dhcp::parse(&ack().encode()).unwrap();
    assert_eq!(msg.op, dhcp::BOOTREPLY);
    assert_eq!(msg.xid, 0xdead_beef);
    assert_eq!(msg.client_mac(), Some(MAC));
    assert_eq!(msg.message_type, Some(dhcp::MessageType::Ack));
    assert_eq!(msg.message_type.unwrap().as_str(), "ack");
    assert_eq!(msg.yiaddr, Ipv4Addr::new(192, 168, 1, 30));
    assert_eq!(msg.server_id, Some(Ipv4Addr::new(192, 168, 1, 1)));
    assert_eq!(msg.subnet_mask, Some(Ipv4Addr::new(255, 255, 255, 0)));
    assert_eq!(msg.routers, vec![Ipv4Addr::new(192, 168, 1, 1)]);
    assert_eq!(msg.dns_servers.len(), 2);
    assert_eq!(msg.lease_time, Some(86_400));
    assert_eq!(msg.hostname.as_deref(), Some("laptop-30"));
    assert!(!msg.malformed);
}

#[test]
fn dhcp_request_carries_the_requested_address() {
    let mut m = DhcpMessage::new(DhcpType::Request, 7, MAC);
    m.requested_ip = Some(Ipv4Addr::new(10, 0, 0, 9));
    let msg = dhcp::parse(&m.encode()).unwrap();
    assert_eq!(msg.op, dhcp::BOOTREQUEST);
    assert_eq!(msg.message_type, Some(dhcp::MessageType::Request));
    assert_eq!(msg.requested_ip, Some(Ipv4Addr::new(10, 0, 0, 9)));
    assert_eq!(msg.hostname, None);
}

#[test]
fn dhcp_rejects_short_and_foreign_payloads() {
    assert!(dhcp::parse(&[]).is_none());
    assert!(dhcp::parse(&[1; 100]).is_none());
    let mut bad_op = ack().encode();
    bad_op[0] = 3;
    assert!(dhcp::parse(&bad_op).is_none());
}

#[test]
fn dhcp_truncated_or_odd_options_are_flagged_not_fatal() {
    let full = ack().encode();
    // Fixed header only: plain BOOTP.
    let bootp = dhcp::parse(&full[..dhcp::FIXED_LEN]).unwrap();
    assert!(!bootp.malformed);
    assert_eq!(bootp.message_type, None);
    // Bad magic cookie.
    let mut cookie = full.clone();
    cookie[dhcp::FIXED_LEN] = 0;
    assert!(dhcp::parse(&cookie).unwrap().malformed);
    // Cut in the middle of an option value.
    let cut = dhcp::parse(&full[..full.len() - 5]).unwrap();
    assert!(cut.malformed);
    assert_eq!(cut.message_type, Some(dhcp::MessageType::Ack));
    // Wrong option sizes are ignored, a hostile host name is sanitized and bounded.
    let mut odd = full[..dhcp::FIXED_LEN + 4].to_vec();
    odd.extend_from_slice(&[53, 2, 5, 5, 54, 3, 1, 2, 3, 0, 0, 12, 200]);
    odd.extend(std::iter::repeat_n(b'a', 100).chain([0x07; 100]));
    odd.push(255);
    let msg = dhcp::parse(&odd).unwrap();
    assert_eq!(msg.message_type, None);
    assert_eq!(msg.server_id, None);
    assert_eq!(
        msg.hostname.as_deref().map(str::len),
        Some(dhcp::MAX_HOSTNAME_LEN)
    );
    assert!(!msg.malformed);
    // Only padding up to the option limit, without end option.
    let mut pads = full[..dhcp::FIXED_LEN + 4].to_vec();
    pads.extend(std::iter::repeat_n(0, 1000));
    pads.push(1);
    assert!(dhcp::parse(&pads).unwrap().malformed);
}

#[test]
fn ntp_server_response_and_references() {
    let h = ntp::parse(&ntp_fx::response(2, [192, 0, 2, 1], 5)).unwrap();
    assert_eq!((h.version, h.mode, h.stratum), (4, ntp::mode::SERVER, 2));
    assert_eq!(h.reference(false), "192.0.2.1");
    assert_eq!(h.reference(true), "c0000201");
    let gps = ntp::parse(&ntp_fx::response(1, *b"GPS\0", 5)).unwrap();
    assert_eq!(gps.reference(false), "GPS");
    let kiss = ntp::parse(&ntp_fx::encode(4, 4, 0, *b"RA\x01E", 0)).unwrap();
    assert_eq!(kiss.reference(false), "RAE");
    let client = ntp::parse(&ntp_fx::request(1)).unwrap();
    assert_eq!(
        (client.mode, client.reference(false).as_str()),
        (ntp::mode::CLIENT, "")
    );
}

#[test]
fn ntp_rejects_short_and_bad_versions() {
    assert!(ntp::parse(&ntp_fx::request(1)[..47]).is_none());
    assert!(ntp::parse(&ntp_fx::encode(4, 0, 2, [0; 4], 0)).is_none());
    assert!(ntp::parse(&ntp_fx::encode(4, 7, 2, [0; 4], 0)).is_none());
}

#[test]
fn kerberos_kdc_messages_are_recognized_with_their_realm() {
    let rep = kerberos::parse(&krb::kdc_rep(false, "CORP.EXAMPLE", "jdoe")).unwrap();
    assert_eq!(rep.kind, kerberos::MessageKind::AsRep);
    assert_eq!(rep.realm.as_deref(), Some("CORP.EXAMPLE"));
    assert!(rep.kind.is_kdc_reply() && !rep.truncated);

    let tgs = kerberos::parse(&krb::kdc_rep(true, "CORP.EXAMPLE", "jdoe")).unwrap();
    assert_eq!(tgs.kind.as_str(), "tgs_rep");

    let err = kerberos::parse(&krb::krb_error(krb::ERR_PREAUTH_REQUIRED, "CORP.EXAMPLE")).unwrap();
    assert_eq!(err.kind, kerberos::MessageKind::KrbError);
    assert_eq!(err.error_code, Some(25));
    assert_eq!(err.realm.as_deref(), Some("CORP.EXAMPLE"));

    let req = kerberos::parse(&krb::kdc_req(false, "CORP.EXAMPLE", "jdoe")).unwrap();
    assert_eq!(req.kind, kerberos::MessageKind::AsReq);
    assert!(!req.kind.is_kdc_reply());
    assert_eq!(req.realm.as_deref(), Some("CORP.EXAMPLE"));
    let tgs_req = kerberos::parse(&krb::kdc_req(true, "CORP.EXAMPLE", "jdoe")).unwrap();
    assert_eq!(tgs_req.kind, kerberos::MessageKind::TgsReq);
}

#[test]
fn kerberos_head_of_a_long_message_keeps_kind_and_realm() {
    let rep = krb::kdc_rep(false, "CORP.EXAMPLE", "jdoe");
    let head = kerberos::parse(&rep[..80]).unwrap();
    assert_eq!(head.kind, kerberos::MessageKind::AsRep);
    assert_eq!(head.realm.as_deref(), Some("CORP.EXAMPLE"));
    assert!(head.truncated);
    // Too short to check pvno and msg-type: not recognized.
    assert!(kerberos::parse(&rep[..6]).is_none());
}

#[test]
fn kerberos_rejects_lookalikes() {
    assert!(kerberos::parse(&[]).is_none());
    // Application tag 11 but wrong msg-type (13).
    let mut rep = krb::kdc_rep(false, "R", "u");
    let pos = rep.windows(3).position(|w| w == [0x02, 0x01, 11]).unwrap();
    rep[pos + 2] = 13;
    assert!(kerberos::parse(&rep).is_none());
    // Wrong pvno.
    let mut err = krb::krb_error(6, "R");
    let pos = err.windows(3).position(|w| w == [0x02, 0x01, 5]).unwrap();
    err[pos + 2] = 4;
    assert!(kerberos::parse(&err).is_none());
    // Unknown application number, indefinite length, high tag number.
    assert!(kerberos::parse(&[0x61, 0x03, 0x30, 0x01, 0x00]).is_none());
    assert!(kerberos::parse(&[0x6b, 0x80, 0x30, 0x00]).is_none());
    assert!(kerberos::parse(&[0x7f, 0x01, 0x00]).is_none());
}

#[test]
fn kerberos_tcp_record_prefix() {
    let record = krb::tcp_record(&[0x6b, 0x00]);
    assert_eq!(kerberos::tcp_record_len(&record), Some(2));
    assert_eq!(kerberos::tcp_record_len(&[0x80, 0, 0, 1]), None);
    assert_eq!(kerberos::tcp_record_len(&[0, 0]), None);
}

fn check(data: &[u8]) {
    let _ = dhcp::parse(data).map(|m| m.client_mac());
    let _ = ntp::parse(data).map(|h| (h.reference(false), h.reference(true)));
    let _ = kerberos::parse(data);
    let _ = kerberos::tcp_record_len(data);
}

fn seeds() -> Vec<Vec<u8>> {
    vec![
        ack().encode(),
        ntp_fx::response(1, *b"GPS\0", 0),
        krb::kdc_rep(false, "CORP.EXAMPLE", "jdoe"),
        krb::krb_error(25, "CORP.EXAMPLE"),
        krb::kdc_req(true, "CORP.EXAMPLE", "jdoe"),
    ]
}

proptest! {
    #[test]
    fn never_panics_on_random_bytes(data in proptest::collection::vec(any::<u8>(), 0..600)) {
        check(&data);
    }

    #[test]
    fn never_panics_on_mutated_messages(
        seed in 0usize..5,
        edits in proptest::collection::vec((any::<usize>(), any::<u8>()), 1..8),
        cut in any::<usize>(),
    ) {
        let mut data = seeds()[seed].clone();
        for (pos, byte) in edits {
            let len = data.len();
            data[pos % len] = byte;
        }
        let len = data.len();
        data.truncate(cut % (len + 1));
        check(&data);
    }
}
