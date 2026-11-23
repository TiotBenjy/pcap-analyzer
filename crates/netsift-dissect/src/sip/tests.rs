use std::fmt::Write as _;

use super::*;

const INVITE: &str = "INVITE sip:bob@biloxi.example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.example.com:5060;branch=z9hG4bK776asdhds\r\n\
Max-Forwards: 70\r\n\
To: Bob <sip:bob@biloxi.example.com>\r\n\
From: \"Alice \\\"A\\\" Liddell\" <sip:alice@atlanta.example.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.example.com\r\n\
CSeq: 314159 INVITE\r\n\
Contact: <sip:alice@pc33.atlanta.example.com>\r\n\
User-Agent: Softphone/1.2\r\n\
Content-Type: application/sdp\r\n\
Content-Length: 132\r\n\
\r\n\
v=0\r\n\
o=alice 2890844526 2890844526 IN IP4 192.0.2.10\r\n\
s=-\r\n\
c=IN IP4 192.0.2.10\r\n\
t=0 0\r\n\
m=audio 49170 RTP/AVP 0 8\r\n\
a=sendrecv\r\n";

#[test]
fn parses_a_request_with_sdp() {
    let m = parse(INVITE.as_bytes()).unwrap();
    assert_eq!(
        m.start,
        StartLine::Request {
            method: "INVITE".to_owned(),
            uri: "sip:bob@biloxi.example.com".to_owned()
        }
    );
    assert!(m.is_request());
    assert_eq!(m.method(), Some("INVITE"));
    assert_eq!(
        m.call_id.as_deref(),
        Some("a84b4c76e66710@pc33.atlanta.example.com")
    );
    assert_eq!(m.from.name.as_deref(), Some("Alice \"A\" Liddell"));
    assert_eq!(m.from.uri.as_deref(), Some("sip:alice@atlanta.example.com"));
    assert_eq!(m.from.tag.as_deref(), Some("1928301774"));
    assert_eq!(m.to.name.as_deref(), Some("Bob"));
    assert_eq!(m.to.tag, None);
    assert_eq!(
        (m.cseq, m.cseq_method.as_deref()),
        (Some(314_159), Some("INVITE"))
    );
    assert_eq!(
        m.contact.as_deref(),
        Some("sip:alice@pc33.atlanta.example.com")
    );
    assert_eq!(
        m.via.as_deref(),
        Some("SIP/2.0/UDP pc33.atlanta.example.com:5060")
    );
    assert_eq!(m.software(), Some("Softphone/1.2"));
    assert_eq!(m.content_type.as_deref(), Some("application/sdp"));
    let sdp = m.sdp.unwrap();
    assert_eq!(sdp.media[0].port, 49170);
    assert_eq!(sdp.media[0].codecs, ["PCMU", "PCMA"]);
    assert_eq!(m.size, INVITE.len());
    assert!(!m.raw_truncated);
    assert!(!m.raw.contains('\r'));
}

#[test]
fn parses_responses_compact_forms_folding_and_lf() {
    let text = "SIP/2.0 180 Ringing\n\
v: SIP/2.0/TCP 192.0.2.4;branch=z9hG4bKnashds8\n\
f: sip:alice@example.com;tag=88sja8x\n\
t: <sip:bob@example.com>;tag=a6c85cf\n\
i: 3848276298220188511@example.com\n\
CSEQ: 1\n  invite\n\
server: PBX\n\tversion 2\n\
l: 0\n\n";
    let m = parse(text.as_bytes()).unwrap();
    assert_eq!(
        m.start,
        StartLine::Response {
            status: 180,
            reason: "Ringing".to_owned()
        }
    );
    assert_eq!(m.status(), Some(180));
    assert_eq!(m.method(), Some("INVITE"));
    assert_eq!(m.from.uri.as_deref(), Some("sip:alice@example.com"));
    assert_eq!(m.from.tag.as_deref(), Some("88sja8x"));
    assert_eq!(m.to.tag.as_deref(), Some("a6c85cf"));
    assert_eq!(m.server.as_deref(), Some("PBX version 2"));
    assert_eq!(m.software(), Some("PBX version 2"));
    assert_eq!(m.content_length, Some(0));
    let reason = parse(b"SIP/2.0 486 Busy  Here\r\n\r\n").unwrap();
    assert_eq!(
        reason.start,
        StartLine::Response {
            status: 486,
            reason: "Busy  Here".to_owned()
        }
    );
}

#[test]
fn digest_keeps_only_non_secret_parameters() {
    let text = "REGISTER sip:registrar.example.com SIP/2.0\r\n\
Call-ID: reg-1\r\n\
CSeq: 2 REGISTER\r\n\
Authorization: Digest username=\"alice\", realm=\"example.com\", nonce=\"ea9c8e88df84f1cec4341ae6cbe5a359\", uri=\"sip:registrar.example.com\", response=\"dfe56131d1958046689d83306477ecc\", algorithm=MD5, qop=auth, nc=00000001, cnonce=\"0a4f113b\"\r\n\
Expires: 3600\r\n\r\n";
    let m = parse(text.as_bytes()).unwrap();
    let auth = m.auth.unwrap();
    assert_eq!(auth.header, AuthHeader::Authorization);
    assert_eq!(auth.username.as_deref(), Some("alice"));
    assert_eq!(auth.realm.as_deref(), Some("example.com"));
    assert_eq!(auth.uri.as_deref(), Some("sip:registrar.example.com"));
    assert_eq!(auth.algorithm.as_deref(), Some("MD5"));
    assert_eq!(auth.qop.as_deref(), Some("auth"));
    assert_eq!(m.expires, Some(3600));
    assert!(!format!("{auth:?}").contains("ea9c8e88"));

    let challenge = parse(
        b"SIP/2.0 407 Proxy Authentication Required\r\nProxy-Authenticate: Digest realm=\"pbx\", nonce=\"x\"\r\n\r\n",
    )
    .unwrap();
    assert_eq!(challenge.challenge_realm.as_deref(), Some("pbx"));
    let basic = parse(b"OPTIONS sip:a SIP/2.0\r\nAuthorization: Basic YWxpY2U=\r\n\r\n").unwrap();
    assert!(basic.auth.is_none());
    let proxy =
        parse(b"INVITE sip:a SIP/2.0\r\nProxy-Authorization: digest username=bob\r\n\r\n").unwrap();
    assert_eq!(proxy.auth.unwrap().header, AuthHeader::ProxyAuthorization);
}

#[test]
fn rejects_what_is_not_sip() {
    for bad in [
        &b""[..],
        b"\x00\x01\x02\x03",
        b"GET / HTTP/1.1\r\n\r\n",
        b"HTTP/1.1 200 OK\r\n\r\n",
        b"INVITE sip:a SIP/3.0\r\n\r\n",
        b"INVITE sip:a\r\n\r\n",
        b"SIP/2.0 99 Too Low\r\n\r\n",
        b"SIP/2.0 2000 Big\r\n\r\n",
        b"IN VITE sip:a SIP/2.0\r\n\r\n",
    ] {
        assert!(parse(bad).is_none(), "{:?}", String::from_utf8_lossy(bad));
    }
}

#[test]
fn bounds_fields_headers_and_raw_text() {
    let mut text = String::from("OPTIONS sip:100@192.0.2.4 SIP/2.0\r\n");
    let _ = write!(text, "Call-ID: {}\r\n", "c".repeat(1000));
    let _ = write!(text, "User-Agent: {}\r\n", "é".repeat(1000));
    text.push_str("Subject: bidi\u{202E}text\u{1}\r\n");
    for i in 0..100 {
        let _ = write!(text, "X-Pad-{i}: {}\r\n", "p".repeat(40));
    }
    text.push_str("To: <sip:late@example.com>\r\n\r\n");
    let m = parse(text.as_bytes()).unwrap();
    assert_eq!(m.call_id.as_ref().unwrap().len(), MAX_CALL_ID);
    assert!(m.user_agent.as_ref().unwrap().len() <= MAX_FIELD);
    assert!(m.headers_truncated);
    assert!(m.to.uri.is_none(), "headers past the bound are ignored");
    assert!(m.raw_truncated);
    assert!(m.raw.len() <= 3 * MAX_RAW);
    assert!(
        !m.raw
            .chars()
            .any(|c| (c.is_control() && c != '\n' && c != '\t') || is_invisible(c))
    );
}

#[test]
fn cut_datagram_and_content_length_bound_the_body() {
    // No final empty line: the head is read up to its end.
    let cut = parse(b"BYE sip:bob@example.com SIP/2.0\r\nCall-ID: x1\r\nCSeq: 2 BYE").unwrap();
    assert_eq!(cut.call_id.as_deref(), Some("x1"));
    assert_eq!(cut.cseq_method.as_deref(), Some("BYE"));
    // The body stops at Content-Length: the trailing line is not SDP.
    let body = "SIP/2.0 200 OK\r\nContent-Type: application/sdp\r\nContent-Length: 20\r\n\r\n\
        c=IN IP4 192.0.2.1\r\nm=audio 4000 RTP/AVP 0\r\n";
    let m = parse(body.as_bytes()).unwrap();
    let sdp = m.sdp.unwrap();
    assert_eq!(sdp.connection, Some("192.0.2.1".parse().unwrap()));
    assert_eq!(sdp.media.len(), 0);
}

#[test]
fn frames_a_tcp_stream() {
    let one = "MESSAGE sip:bob@example.com SIP/2.0\r\nl: 5\r\n\r\nhello";
    let mut stream = one.as_bytes().to_vec();
    stream.extend_from_slice(b"SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n");
    assert_eq!(message_len(&stream), Ok(Some(one.len())));
    let rest = &stream[one.len()..];
    assert_eq!(message_len(rest), Ok(Some(rest.len())));
    // Partial: first line incomplete, head incomplete, body incomplete.
    assert_eq!(message_len(b"MESS"), Ok(None));
    assert_eq!(message_len(b"MESSAGE sip:b SIP/2.0\r\nl: 5"), Ok(None));
    assert_eq!(message_len(&stream[..one.len() - 1]), Ok(None));
    // No Content-Length over TCP: an empty body.
    assert_eq!(
        message_len(b"OPTIONS sip:b SIP/2.0\r\n\r\nNEXT"),
        Ok(Some(25))
    );
    assert_eq!(
        message_len(b"\x16\x03\x01\x02\x00"),
        Err(FrameError::NotSip)
    );
    assert_eq!(message_len(b"GET / HTTP/1.1\r\n"), Err(FrameError::NotSip));
    assert_eq!(
        message_len(b"OPTIONS sip:b SIP/2.0\r\nContent-Length: abc\r\n\r\n"),
        Err(FrameError::BadLength)
    );
    assert_eq!(
        message_len(b"OPTIONS sip:b SIP/2.0\r\nContent-Length: 999999\r\n\r\n"),
        Err(FrameError::TooLarge)
    );
    let endless = format!("OPTIONS sip:b SIP/2.0\r\n{}", "X-A: b\r\n".repeat(4000));
    assert_eq!(message_len(endless.as_bytes()), Err(FrameError::TooLarge));
    assert_eq!(keepalive_len(b"\r\n\r\nINVITE"), 4);
    assert_eq!(keepalive_len(b"INVITE"), 0);
}

#[test]
fn sdp_media_beyond_the_bound_are_flagged() {
    let mut body = String::from("c=IN IP4 192.0.2.1\r\n");
    for i in 0..12 {
        let _ = write!(body, "m=audio {} RTP/AVP 0\r\n", 4000 + i * 2);
    }
    let sdp = crate::sdp::parse(body.as_bytes()).unwrap();
    assert_eq!(sdp.media.len(), crate::sdp::MAX_MEDIA);
    assert!(sdp.media_truncated);
}

mod props {
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn never_panics_and_stays_bounded(data in proptest::collection::vec(any::<u8>(), 0..2048)) {
            if let Some(m) = super::parse(&data) {
                prop_assert!(m.raw.len() <= 3 * super::MAX_RAW);
                prop_assert!(m.call_id.as_ref().is_none_or(|c| c.len() <= super::MAX_CALL_ID));
            }
            let _ = super::message_len(&data);
        }

        #[test]
        fn sip_like_input_never_panics(
            lines in proptest::collection::vec("[A-Za-z:;=<>\" @.0-9/\t-]{0,40}", 0..30)
        ) {
            let text = format!("INVITE sip:x SIP/2.0\r\n{}\r\n\r\n", lines.join("\r\n"));
            prop_assert!(super::parse(text.as_bytes()).is_some());
            let _ = super::message_len(text.as_bytes());
        }
    }
}

#[test]
fn raw_text_masks_the_authentication_secrets() {
    let text = "REGISTER sip:registrar.example.com SIP/2.0\r\n\
Call-ID: reg-1\r\n\
Authorization: Digest username=\"alice\", realm=\"example.com\",\r\n \
nonce=\"ea9c8e88df84f1cec4341ae6cbe5a359\", uri=\"sip:registrar.example.com\",\r\n\
\tresponse=\"dfe56131d1958046689d83306477ecc\", algorithm=MD5, cnonce=\"0a4f113b\", opaque=\"5ccc\", nc=00000001\r\n\
Proxy-Authorization: Basic dXNlcjpzZWNyZXQ=\r\n\
WWW-Authenticate: Digest realm=\"pbx\", nonce=\"ea9c8e88df84f1cec4341ae6cbe5a359\"\r\n\
proxy-authorization:NewScheme token=abcdef\r\n\
Authentication-Info: nextnonce=\"47364c23432d2e131a5fb210812c\", rspauth=\"7d4a\"\r\n\
Content-Length: 0\r\n\r\n";
    let m = parse(text.as_bytes()).unwrap();
    for secret in [
        "ea9c8e88df84f1cec4341ae6cbe5a359",
        "dfe56131d1958046689d83306477ecc",
        "0a4f113b",
        "5ccc",
        "dXNlcjpzZWNyZXQ=",
        "abcdef",
        "47364c23432d2e131a5fb210812c",
        "7d4a",
    ] {
        assert!(!m.raw.contains(secret), "{secret} in {}", m.raw);
    }
    // Identity and context stay readable; the parsed fields are unchanged.
    assert!(
        m.raw.contains(
            "Authorization: Digest username=\"alice\", realm=\"example.com\", nonce=<masked>, \
         uri=\"sip:registrar.example.com\", response=<masked>, algorithm=MD5, cnonce=<masked>, \
         opaque=<masked>, nc=<masked>\n"
        ),
        "{}",
        m.raw
    );
    assert!(m.raw.contains("Proxy-Authorization: <masked>\n"));
    assert!(
        m.raw
            .contains("WWW-Authenticate: Digest realm=\"pbx\", nonce=<masked>\n")
    );
    assert!(m.raw.contains("proxy-authorization: <masked>\n"));
    assert!(m.raw.contains("Authentication-Info: <masked>\n"));
    assert!(
        m.raw
            .starts_with("REGISTER sip:registrar.example.com SIP/2.0\nCall-ID: reg-1\n")
    );
    assert!(m.raw.ends_with("Content-Length: 0\n\n"));
    assert_eq!(m.auth.as_ref().unwrap().username.as_deref(), Some("alice"));
    assert_eq!(m.challenge_realm.as_deref(), Some("pbx"));
    assert!(
        !format!("{m:?}").contains("Call-ID: reg-1"),
        "Debug never prints the raw text"
    );
}

#[test]
fn masking_spares_the_body_and_survives_a_cut_header() {
    // The body is not a head: a line that looks like a header is kept.
    let body = "MESSAGE sip:b SIP/2.0\r\nContent-Length: 30\r\n\r\nAuthorization: Basic not-head\n";
    let m = parse(body.as_bytes()).unwrap();
    assert!(m.raw.ends_with("\n\nAuthorization: Basic not-head\n"));
    // A datagram cut inside the value: what is there is masked, no line end is added.
    let cut = parse(b"INVITE sip:b SIP/2.0\r\nAuthorization: Basic dXNlcjpw").unwrap();
    assert_eq!(cut.raw, "INVITE sip:b SIP/2.0\nAuthorization: <masked>");
    assert_eq!(redact_auth("no header"), "no header");
}

#[test]
fn content_length_out_of_range_is_refused() {
    assert_eq!(
        message_len(b"OPTIONS sip:b SIP/2.0\r\nContent-Length: -5\r\n\r\n"),
        Err(FrameError::BadLength)
    );
    assert_eq!(
        message_len(b"OPTIONS sip:b SIP/2.0\r\nContent-Length: 99999999999999\r\n\r\n"),
        Err(FrameError::TooLarge)
    );
    // A folded continuation line is never read as Content-Length (as `collect_headers` does).
    assert_eq!(
        message_len(b"OPTIONS sip:b SIP/2.0\r\nSubject: a\r\n Content-Length: 5\r\n\r\nNEXT"),
        Ok(Some(57))
    );
    let m = parse(b"OPTIONS sip:b SIP/2.0\r\nContent-Length: -5\r\n\r\n").unwrap();
    assert_eq!(m.content_length, None);
}
