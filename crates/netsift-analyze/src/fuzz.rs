//! Entry points of the cargo-fuzz targets (`fuzz/`, feature `fuzzing`, never enabled by the
//! application). They reach parsers that are private to their module without widening the
//! public API: each function runs parsers on arbitrary bytes and drops what they return.
//!
//! The analyzers themselves are fuzzed through their public [`crate::Analyzer`] interface; only
//! the pure parsers below need this door.

use std::net::{IpAddr, Ipv4Addr};

use netsift_flow::{Endpoint, FlowId, FlowKey};

use crate::http::{BodyState, HttpHeader, MessageView, Role};
use crate::record::Record;
use crate::smb::ntlmssp::{self, NtlmMessage};
use crate::smb::{browser, message, os};

/// Most NBSS frames walked in one input.
const MAX_FRAMES: usize = 64;
/// Most header lines taken from one input.
const MAX_HEADERS: usize = 64;

/// Server challenge paired with a fuzzed AUTHENTICATE: the hashcat line only hex-encodes it, so
/// a fixed value loses nothing.
const SERVER_CHALLENGE: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];

/// NTLMSSP (`smb::ntlmssp`): any message (found anywhere in the input, as behind a SPNEGO
/// wrapping), then, for an AUTHENTICATE, its hashcat line with [`SERVER_CHALLENGE`].
pub fn ntlmssp(data: &[u8]) {
    if let Some(NtlmMessage::Authenticate(auth)) = ntlmssp::parse(data) {
        let _ = ntlmssp::hashcat(SERVER_CHALLENGE, &auth);
    }
}

/// SMB and NetBIOS (`smb::message`, `smb::browser`, `smb::os`): the input as a sequence of NBSS
/// frames, as one bare PDU, and as a NetBIOS datagram (UDP 138).
pub fn smb(data: &[u8]) {
    let mut rest = data;
    for _ in 0..MAX_FRAMES {
        let Some((_, _, total)) = message::nbss_header(rest) else {
            break;
        };
        let end = total.min(rest.len());
        if let Some(pdu) = rest.get(4..end) {
            let _ = message::parse_pdu(pdu);
        }
        match rest.get(end..) {
            Some(next) if !next.is_empty() => rest = next,
            _ => break,
        }
    }
    let _ = message::parse_pdu(data);
    if let Some(a) = browser::parse_datagram(data) {
        let _ = a.destination.display();
        let _ = os::os_label(a.os_major, a.os_minor);
    }
}

/// SNMP v1/v2c communities (`credentials::snmp`).
pub fn snmp(data: &[u8]) {
    let _ = crate::credentials::snmp::parse(data);
}

/// HTTP credentials (`http::auth`): Basic and NTLM / Negotiate headers, login forms and query
/// strings, `application/x-www-form-urlencoded` decoding.
///
/// Input: a request target on the first line, then `Name: value` header lines, an empty line
/// and the body. The headers are first seen in a response (a `WWW-Authenticate` NTLM challenge
/// is remembered), then in a request, as on a real connection. Returns the number of
/// credentials emitted.
pub fn http_auth(data: &[u8]) -> usize {
    let (head, body) = split_head(data);
    let text = String::from_utf8_lossy(head);
    let mut lines = text.lines();
    let target = lines.next().unwrap_or_default();
    let headers: Vec<HttpHeader> = lines
        .filter_map(|l| l.split_once(':'))
        .take(MAX_HEADERS)
        .map(|(n, v)| HttpHeader {
            name: n.trim().to_owned(),
            value: v.trim().to_owned(),
        })
        .collect();
    let key = FlowKey {
        proto: 6,
        client: Endpoint {
            ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            port: 49152,
        },
        server: Endpoint {
            ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
            port: 80,
        },
    };
    let mut state = crate::http::auth::AuthState::default();
    let mut out: Vec<Record> = Vec::new();
    for (role, method, status) in [
        (Role::Response, None, Some(401)),
        (Role::Request, Some("POST"), None),
    ] {
        let view = MessageView {
            flow: FlowId(1),
            key: &key,
            role,
            ts_ns: 0,
            frame: 0,
            method,
            target: method.map(|_| target),
            status,
            headers: &headers,
            state: BodyState::Complete,
            body,
            body_complete: true,
        };
        crate::http::auth::inspect(&view, &mut state, &mut out);
    }
    for record in &out {
        // Formatting must not panic either (secrets are redacted by `Debug`).
        let _ = format!("{record:?}");
    }
    out.len()
}

/// Splits at the first empty line (`\n\n`).
fn split_head(data: &[u8]) -> (&[u8], &[u8]) {
    for (i, w) in data.windows(2).enumerate() {
        if w == b"\n\n" {
            return (
                data.get(..i).unwrap_or_default(),
                data.get(i + 2..).unwrap_or_default(),
            );
        }
    }
    (data, &[])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_points_accept_any_bytes() {
        let samples: [&[u8]; 5] = [
            b"",
            b"\x00\x00\x00\x04\xfeSMB",
            b"NTLMSSP\x00\x03\x00\x00\x00",
            b"/login?password=x\nAuthorization: Basic dTpw\n\npassword=a%2",
            b"\x30\x03\x02\x01\x00",
        ];
        for s in samples {
            ntlmssp(s);
            smb(s);
            snmp(s);
            let _ = http_auth(s);
        }
    }

    #[test]
    fn http_auth_reaches_basic_and_form_credentials() {
        assert_eq!(http_auth(b"/x\nAuthorization: Basic dTpw\n\n"), 1);
        let form = b"/login\nContent-Type: application/x-www-form-urlencoded\n\nuser=a&password=b";
        assert_eq!(http_auth(form), 1);
    }

    #[test]
    fn split_head_cuts_at_the_empty_line() {
        let (head, body) = split_head(b"/x\nAuthorization: Basic dTpw\n\nbody");
        assert_eq!(head, b"/x\nAuthorization: Basic dTpw");
        assert_eq!(body, b"body");
    }
}
