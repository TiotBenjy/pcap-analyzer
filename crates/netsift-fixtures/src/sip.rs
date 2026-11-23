//! SIP exchanges (RFC 3261) for the SIP view: a complete call with its RTP streams, a rejected
//! call, a cancelled call, a registration challenged then authenticated with Digest, a
//! `friendly-scanner` sweep, a call over TCP (messages split across segments and two messages
//! in one segment) and a message with oversized headers.
//!
//! Addresses, numbers and names are invented (private and documentation ranges only). The Digest
//! response is a fixed placeholder, not computed from any password.

use std::fmt::Write as _;

use crate::packet::Host;
use crate::scenario::{Scenario, TcpOptions};
use crate::scenarios::hosts;
use crate::time::NS_PER_MS;

/// SIP port.
pub const PORT: u16 = 5060;
/// Source port of the scanner (`SIPVicious` uses an arbitrary local port).
pub const SCANNER_PORT: u16 = 5070;
/// `User-Agent` of the `SIPVicious` scanner.
pub const FRIENDLY_SCANNER: &str = "friendly-scanner";
/// Digest realm of the PBX.
pub const REALM: &str = "pbx.example.test";
/// RTP packets sent each way by [`sip_call`] (one every 100 ms).
pub const RTP_PACKETS: usize = 30;

/// Hosts of the SIP exchanges.
pub mod sip_hosts {
    use super::{Host, hosts};

    /// PBX (registrar and proxy), 10.20.0.2.
    pub fn pbx() -> Host {
        Host::v4([0x02, 0x00, 0x5e, 0x20, 0x00, 0x02], [10, 20, 0, 2])
    }

    /// Desk phone of Alice, 10.20.0.21.
    pub fn alice() -> Host {
        Host::v4([0x02, 0x00, 0x5e, 0x20, 0x00, 0x21], [10, 20, 0, 21])
    }

    /// Softphone of Bob, 10.20.0.22.
    pub fn bob() -> Host {
        Host::v4([0x02, 0x00, 0x5e, 0x20, 0x00, 0x22], [10, 20, 0, 22])
    }

    /// Phone of Carol, registered over TCP, 10.20.0.23.
    pub fn carol() -> Host {
        Host::v4([0x02, 0x00, 0x5e, 0x20, 0x00, 0x23], [10, 20, 0, 23])
    }

    /// Unused address swept by the scanner, 10.20.0.30.
    pub fn unused() -> Host {
        Host::v4([0x02, 0x00, 0x5e, 0x20, 0x00, 0x30], [10, 20, 0, 30])
    }

    /// Scanner on the Internet, 203.0.113.66, reached through the router MAC.
    pub fn scanner() -> Host {
        Host::v4(hosts::router().mac, [203, 0, 113, 66])
    }
}

use sip_hosts::{alice, bob, carol, pbx, scanner, unused};

/// A phone: its host, SIP user, display name and software.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Phone {
    pub host: Host,
    pub user: &'static str,
    pub name: &'static str,
    pub agent: &'static str,
    /// First RTP port of its calls.
    pub rtp_port: u16,
}

impl Phone {
    fn ip(&self) -> String {
        self.host.ip.to_string()
    }

    /// `sip:<user>@<ip>`.
    pub fn uri(&self) -> String {
        format!("sip:{}@{}", self.user, self.ip())
    }

    /// `"Name" <sip:user@ip>`.
    fn name_addr(&self) -> String {
        format!("\"{}\" <{}>", self.name, self.uri())
    }
}

pub fn alice_phone() -> Phone {
    Phone {
        host: alice(),
        user: "201",
        name: "Alice",
        agent: "Deskphone 7.4.2",
        rtp_port: 40_000,
    }
}

pub fn bob_phone() -> Phone {
    Phone {
        host: bob(),
        user: "202",
        name: "Bob",
        agent: "Softphone/3.1",
        rtp_port: 42_000,
    }
}

pub fn carol_phone() -> Phone {
    Phone {
        host: carol(),
        user: "203",
        name: "Carol",
        agent: "Conference Unit 2.0",
        rtp_port: 44_000,
    }
}

/// The PBX as a phone-like party (answers in the name of extension 300).
pub fn pbx_party() -> Phone {
    Phone {
        host: pbx(),
        user: "300",
        name: "Support",
        agent: "Example PBX 18.2",
        rtp_port: 46_000,
    }
}

/// A SIP message under construction: first line, headers in order, optional SDP body.
#[derive(Debug, Clone)]
pub struct Message {
    first: String,
    headers: Vec<(String, String)>,
    body: String,
}

impl Message {
    pub fn request(method: &str, uri: &str) -> Self {
        Self {
            first: format!("{method} {uri} SIP/2.0"),
            headers: Vec::new(),
            body: String::new(),
        }
    }

    pub fn response(status: u16, reason: &str) -> Self {
        Self {
            first: format!("SIP/2.0 {status} {reason}"),
            headers: Vec::new(),
            body: String::new(),
        }
    }

    #[must_use]
    pub fn header(mut self, name: &str, value: impl Into<String>) -> Self {
        self.headers.push((name.to_owned(), value.into()));
        self
    }

    /// SDP offer or answer of `ip`, one audio stream on `port` (PCMU, PCMA, telephone events).
    #[must_use]
    pub fn sdp(mut self, ip: &str, port: u16) -> Self {
        self.body = format!(
            "v=0\r\no=- 3912 3912 IN IP4 {ip}\r\ns=call\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             m=audio {port} RTP/AVP 0 8 101\r\na=rtpmap:101 telephone-event/8000\r\na=sendrecv\r\n"
        );
        self.headers
            .push(("Content-Type".to_owned(), "application/sdp".to_owned()));
        self
    }

    /// The message text with its `Content-Length`.
    pub fn bytes(&self) -> Vec<u8> {
        let mut s = String::new();
        s.push_str(&self.first);
        s.push_str("\r\n");
        for (n, v) in &self.headers {
            let _ = write!(s, "{n}: {v}\r\n");
        }
        let _ = write!(s, "Content-Length: {}\r\n\r\n", self.body.len());
        s.push_str(&self.body);
        s.into_bytes()
    }
}

/// Headers shared by the messages of one dialog.
#[derive(Debug, Clone)]
struct Dialog {
    call_id: String,
    from: String,
    to: String,
    /// `tag` of the answering side, once known.
    to_tag: Option<String>,
    via: String,
}

impl Dialog {
    fn new(call_id: &str, caller: &Phone, callee_uri: &str, transport: &str) -> Self {
        Self {
            call_id: call_id.to_owned(),
            from: format!("{};tag={}", caller.name_addr(), tag_of(call_id, 'f')),
            to: format!("<{callee_uri}>"),
            to_tag: None,
            via: format!(
                "SIP/2.0/{transport} {}:{PORT};branch=z9hG4bK{}",
                caller.ip(),
                tag_of(call_id, 'b')
            ),
        }
    }

    fn to(&self) -> String {
        match &self.to_tag {
            Some(t) => format!("{};tag={t}", self.to),
            None => self.to.clone(),
        }
    }

    fn request(&self, method: &str, uri: &str, cseq: u32, agent: &str) -> Message {
        Message::request(method, uri)
            .header("Via", self.via.clone())
            .header("Max-Forwards", "70")
            .header("From", self.from.clone())
            .header("To", self.to())
            .header("Call-ID", self.call_id.clone())
            .header("CSeq", format!("{cseq} {method}"))
            .header("User-Agent", agent)
    }

    fn response(&self, status: u16, reason: &str, cseq: u32, method: &str, agent: &str) -> Message {
        Message::response(status, reason)
            .header("Via", self.via.clone())
            .header("From", self.from.clone())
            .header("To", self.to())
            .header("Call-ID", self.call_id.clone())
            .header("CSeq", format!("{cseq} {method}"))
            .header("Server", agent)
    }
}

/// A short deterministic tag derived from a Call-ID.
fn tag_of(call_id: &str, salt: char) -> String {
    let h = call_id
        .bytes()
        .chain(std::iter::once(u8::try_from(salt).unwrap_or(b'_')))
        .fold(0xcbf2_9ce4_8422_2325_u64, |h, b| {
            (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3)
        });
    format!("{:08x}", h & 0xffff_ffff)
}

/// Sends a message over UDP from `src` to `dst` (both on port 5060).
fn send(sc: &mut Scenario, src: &Phone, dst: &Phone, msg: &Message) -> usize {
    sc.udp(src.host, dst.host, PORT, PORT, &msg.bytes())
}

/// One RTP packet (RFC 3550): version 2, payload type 0 (PCMU), 20 ms of audio.
pub fn rtp_packet(seq: u16, ssrc: u32) -> Vec<u8> {
    let mut p = Vec::with_capacity(12 + 160);
    p.extend_from_slice(&[0x80, 0x00]);
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(&(u32::from(seq) * 160).to_be_bytes());
    p.extend_from_slice(&ssrc.to_be_bytes());
    p.extend(std::iter::repeat_n(0xff_u8, 160));
    p
}

/// RTP both ways between two media endpoints, `packets` each way, one pair every 100 ms.
pub fn rtp(sc: &mut Scenario, a: (Host, u16), b: (Host, u16), packets: usize) {
    for i in 0..packets {
        let seq = u16::try_from(i).unwrap_or(u16::MAX);
        sc.udp(a.0, b.0, a.1, b.1, &rtp_packet(seq, 0x1111_0001));
        sc.udp(b.0, a.0, b.1, a.1, &rtp_packet(seq, 0x2222_0002));
        sc.advance(100 * NS_PER_MS);
    }
}

/// A complete call over UDP: INVITE with SDP, 100, 180, 200 with SDP, ACK, RTP both ways for
/// `rtp_packets` x 100 ms, BYE from the callee, 200.
pub fn sip_call(
    sc: &mut Scenario,
    call_id: &str,
    caller: &Phone,
    callee: &Phone,
    rtp_packets: usize,
) {
    let mut d = Dialog::new(call_id, caller, &callee.uri(), "UDP");
    let invite = d
        .request("INVITE", &callee.uri(), 1, caller.agent)
        .header("Contact", format!("<{}>", caller.uri()))
        .sdp(&caller.ip(), caller.rtp_port);
    send(sc, caller, callee, &invite);
    send(
        sc,
        callee,
        caller,
        &d.response(100, "Trying", 1, "INVITE", callee.agent),
    );
    d.to_tag = Some(tag_of(call_id, 't'));
    sc.advance(800 * NS_PER_MS);
    send(
        sc,
        callee,
        caller,
        &d.response(180, "Ringing", 1, "INVITE", callee.agent),
    );
    sc.advance(2_000 * NS_PER_MS);
    let ok = d
        .response(200, "OK", 1, "INVITE", callee.agent)
        .header("Contact", format!("<{}>", callee.uri()))
        .sdp(&callee.ip(), callee.rtp_port);
    send(sc, callee, caller, &ok);
    send(
        sc,
        caller,
        callee,
        &d.request("ACK", &callee.uri(), 1, caller.agent),
    );
    rtp(
        sc,
        (caller.host, caller.rtp_port),
        (callee.host, callee.rtp_port),
        rtp_packets,
    );
    // The callee hangs up: its BYE goes the other way, From and To swapped.
    let bye = Message::request("BYE", &caller.uri())
        .header(
            "Via",
            format!(
                "SIP/2.0/UDP {}:{PORT};branch=z9hG4bK{}",
                callee.ip(),
                tag_of(call_id, 'y')
            ),
        )
        .header("From", d.to())
        .header("To", d.from.clone())
        .header("Call-ID", call_id)
        .header("CSeq", "1 BYE")
        .header("User-Agent", callee.agent);
    send(sc, callee, caller, &bye);
    let bye_ok = Message::response(200, "OK")
        .header("From", d.to())
        .header("To", d.from.clone())
        .header("Call-ID", call_id)
        .header("CSeq", "1 BYE")
        .header("Server", caller.agent);
    send(sc, caller, callee, &bye_ok);
}

/// A call rejected by the callee: INVITE, 100, 486 Busy Here, ACK.
pub fn sip_rejected(sc: &mut Scenario, call_id: &str, caller: &Phone, callee: &Phone) {
    let mut d = Dialog::new(call_id, caller, &callee.uri(), "UDP");
    let invite = d
        .request("INVITE", &callee.uri(), 1, caller.agent)
        .sdp(&caller.ip(), caller.rtp_port + 10);
    send(sc, caller, callee, &invite);
    send(
        sc,
        callee,
        caller,
        &d.response(100, "Trying", 1, "INVITE", callee.agent),
    );
    d.to_tag = Some(tag_of(call_id, 't'));
    sc.advance(300 * NS_PER_MS);
    send(
        sc,
        callee,
        caller,
        &d.response(486, "Busy Here", 1, "INVITE", callee.agent),
    );
    send(
        sc,
        caller,
        callee,
        &d.request("ACK", &callee.uri(), 1, caller.agent),
    );
}

/// A call cancelled by the caller while ringing: INVITE, 180, CANCEL, 200 (CANCEL), 487, ACK.
pub fn sip_cancelled(sc: &mut Scenario, call_id: &str, caller: &Phone, callee: &Phone) {
    let mut d = Dialog::new(call_id, caller, &callee.uri(), "UDP");
    let invite = d
        .request("INVITE", &callee.uri(), 1, caller.agent)
        .sdp(&caller.ip(), caller.rtp_port + 20);
    send(sc, caller, callee, &invite);
    let to_before = d.clone();
    d.to_tag = Some(tag_of(call_id, 't'));
    send(
        sc,
        callee,
        caller,
        &d.response(180, "Ringing", 1, "INVITE", callee.agent),
    );
    sc.advance(4_000 * NS_PER_MS);
    send(
        sc,
        caller,
        callee,
        &to_before.request("CANCEL", &callee.uri(), 1, caller.agent),
    );
    send(
        sc,
        callee,
        caller,
        &d.response(200, "OK", 1, "CANCEL", callee.agent),
    );
    send(
        sc,
        callee,
        caller,
        &d.response(487, "Request Terminated", 1, "INVITE", callee.agent),
    );
    send(
        sc,
        caller,
        callee,
        &d.request("ACK", &callee.uri(), 1, caller.agent),
    );
}

/// A registration: REGISTER, 401 with a Digest challenge, REGISTER with `Authorization:
/// Digest` (placeholder response), 200 OK.
pub fn sip_register(sc: &mut Scenario, call_id: &str, phone: &Phone, registrar: &Phone) {
    let aor = format!("sip:{}@{REALM}", phone.user);
    let registrar_uri = format!("sip:{REALM}");
    let mut d = Dialog::new(call_id, phone, &aor, "UDP");
    // A REGISTER names the same AOR in From and To.
    d.from = format!("<{aor}>;tag={}", tag_of(call_id, 'f'));
    let base = |cseq: u32| {
        d.request("REGISTER", &registrar_uri, cseq, phone.agent)
            .header("Contact", format!("<{}>", phone.uri()))
            .header("Expires", "3600")
    };
    send(sc, phone, registrar, &base(1));
    let challenge = d
        .response(401, "Unauthorized", 1, "REGISTER", registrar.agent)
        .header(
            "WWW-Authenticate",
            format!(
                "Digest realm=\"{REALM}\", nonce=\"5f2a7c{}\", algorithm=MD5",
                tag_of(call_id, 'n')
            ),
        );
    send(sc, registrar, phone, &challenge);
    sc.advance(50 * NS_PER_MS);
    let auth = base(2).header(
        "Authorization",
        format!(
            "Digest username=\"{}\", realm=\"{REALM}\", nonce=\"5f2a7c{}\", uri=\"{registrar_uri}\", \
             response=\"00000000000000000000000000000000\", algorithm=MD5",
            phone.user,
            tag_of(call_id, 'n')
        ),
    );
    send(sc, phone, registrar, &auth);
    let ok = d
        .response(200, "OK", 2, "REGISTER", registrar.agent)
        .header("Contact", format!("<{}>;expires=3600", phone.uri()))
        .header("Expires", "3600");
    send(sc, registrar, phone, &ok);
}

/// A `SIPVicious` sweep: one `OPTIONS` with `User-Agent: friendly-scanner` to each target, never
/// answered (as in the reference capture).
pub fn sip_scan(sc: &mut Scenario, targets: &[Host]) {
    let src = scanner();
    for (i, t) in targets.iter().enumerate() {
        let uri = format!("sip:100@{}", t.ip);
        let call_id = format!("8369256053991101772252{i:02}");
        let msg = Message::request("OPTIONS", &uri)
            .header(
                "Via",
                format!(
                    "SIP/2.0/UDP {}:{SCANNER_PORT};branch=z9hG4bK-16759{i:05};rport",
                    src.ip
                ),
            )
            .header("Max-Forwards", "70")
            .header(
                "From",
                format!("\"sipvicious\"<sip:100@{}>;tag=6364616561353438", src.ip),
            )
            .header("To", format!("\"sipvicious\"<sip:100@{}>", src.ip))
            .header("Call-ID", call_id)
            .header("CSeq", "1 OPTIONS")
            .header("Contact", format!("sip:100@{}:{SCANNER_PORT}", src.ip))
            .header("Accept", "application/sdp")
            .header("User-Agent", FRIENDLY_SCANNER);
        sc.udp(src, *t, SCANNER_PORT, PORT, &msg.bytes());
        sc.advance(20 * NS_PER_MS);
    }
}

/// A call over TCP to the PBX: the INVITE split over several segments (small MSS), 100 and 180
/// sent in one burst, 200 with SDP, ACK, then BYE from the caller and 200. No RTP follows.
pub fn sip_tcp_call(sc: &mut Scenario, call_id: &str, caller: &Phone, callee: &Phone) {
    let mut opts = TcpOptions::new(PORT);
    opts.mss = 200;
    let mut d = Dialog::new(call_id, caller, &callee.uri(), "TCP");
    let mut tcp = sc.tcp_open(caller.host, callee.host, &opts);
    let invite = d
        .request("INVITE", &callee.uri(), 1, caller.agent)
        .sdp(&caller.ip(), caller.rtp_port);
    tcp.client_send(&invite.bytes());
    d.to_tag = Some(tag_of(call_id, 't'));
    let mut burst = d.response(100, "Trying", 1, "INVITE", callee.agent).bytes();
    burst.extend_from_slice(
        &d.response(180, "Ringing", 1, "INVITE", callee.agent)
            .bytes(),
    );
    tcp.server_send(&burst);
    tcp.scenario().advance(1_000 * NS_PER_MS);
    tcp.server_send(
        &d.response(200, "OK", 1, "INVITE", callee.agent)
            .sdp(&callee.ip(), callee.rtp_port)
            .bytes(),
    );
    // A keep-alive (RFC 5626) between two messages.
    let mut ack = b"\r\n\r\n".to_vec();
    ack.extend_from_slice(&d.request("ACK", &callee.uri(), 1, caller.agent).bytes());
    tcp.client_send(&ack);
    tcp.scenario().advance(5_000 * NS_PER_MS);
    tcp.client_send(&d.request("BYE", &callee.uri(), 2, caller.agent).bytes());
    tcp.server_send(&d.response(200, "OK", 2, "BYE", callee.agent).bytes());
    tcp.close();
}

/// An `OPTIONS` with far too many and too long headers, answered by the PBX.
pub fn sip_oversized(sc: &mut Scenario, from: &Phone, to: &Phone) {
    let d = Dialog::new("oversized-0000dead@10.20.0.22", from, &to.uri(), "UDP");
    let mut msg = d.request("OPTIONS", &to.uri(), 1, &"X".repeat(900));
    for i in 0..100 {
        msg = msg.header(&format!("X-Padding-{i}"), "p".repeat(24));
    }
    send(sc, from, to, &msg);
    send(sc, to, from, &d.response(200, "OK", 1, "OPTIONS", to.agent));
}

/// What [`sip_showcase`] sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShowcaseCounts {
    pub requests: usize,
    pub responses: usize,
    /// Messages with the `friendly-scanner` user agent.
    pub scanner: usize,
    /// Call-IDs (dialogs).
    pub dialogs: usize,
    /// Dialogs with an INVITE.
    pub calls: usize,
    /// RTP packets (both ways).
    pub rtp: usize,
}

impl ShowcaseCounts {
    pub fn messages(&self) -> usize {
        self.requests + self.responses
    }
}

/// Call-ID of the complete call of the showcase.
pub const CALL_COMPLETE: &str = "call-complete-7f3a@10.20.0.21";
/// Call-ID of the rejected call.
pub const CALL_REJECTED: &str = "call-rejected-19c2@10.20.0.21";
/// Call-ID of the cancelled call.
pub const CALL_CANCELLED: &str = "call-cancelled-55e1@10.20.0.22";
/// Call-ID of the registration.
pub const CALL_REGISTER: &str = "register-alice-0b7d@10.20.0.21";
/// Call-ID of the call over TCP.
pub const CALL_TCP: &str = "call-tcp-a0c4@10.20.0.23";

/// Every case above, a few hundred milliseconds apart.
pub fn sip_showcase(sc: &mut Scenario) -> ShowcaseCounts {
    let (a, b, c, p) = (alice_phone(), bob_phone(), carol_phone(), pbx_party());
    sip_register(sc, CALL_REGISTER, &a, &p);
    sc.advance(500 * NS_PER_MS);
    sip_call(sc, CALL_COMPLETE, &a, &b, RTP_PACKETS);
    sc.advance(500 * NS_PER_MS);
    sip_rejected(sc, CALL_REJECTED, &a, &p);
    sc.advance(500 * NS_PER_MS);
    sip_cancelled(sc, CALL_CANCELLED, &b, &a);
    sc.advance(500 * NS_PER_MS);
    let targets = [pbx(), alice(), bob(), unused()];
    sip_scan(sc, &targets);
    sc.advance(500 * NS_PER_MS);
    sip_tcp_call(sc, CALL_TCP, &c, &p);
    sc.advance(500 * NS_PER_MS);
    sip_oversized(sc, &b, &p);
    ShowcaseCounts {
        // REGISTER x2, INVITE+ACK+BYE, INVITE+ACK, INVITE+CANCEL+ACK, OPTIONS x4,
        // INVITE+ACK+BYE (TCP), OPTIONS.
        requests: 2 + 3 + 2 + 3 + targets.len() + 3 + 1,
        // 401+200, 100+180+200+200, 100+486, 180+200+487, 100+180+200+200 (TCP), 200.
        responses: 2 + 4 + 2 + 3 + 4 + 1,
        scanner: targets.len(),
        dialogs: 5 + targets.len() + 1,
        calls: 4,
        rtp: 2 * RTP_PACKETS,
    }
}

/// One periodic round of the demonstration: a short call from Alice or Bob to the other, and on
/// even rounds a registration refresh of Carol.
pub fn sip_round(sc: &mut Scenario, round: usize) {
    // New RTP ports each round, as phones do: a port reused within the UDP flow timeout would
    // fold the streams of two calls into one flow.
    let offset = (u16::try_from(round % 400).unwrap_or(0) + 1) * 2;
    let mut a = alice_phone();
    let mut b = bob_phone();
    a.rtp_port += offset;
    b.rtp_port += offset;
    let (c, p) = (carol_phone(), pbx_party());
    let (caller, callee) = if round.is_multiple_of(2) {
        (&a, &b)
    } else {
        (&b, &a)
    };
    sip_call(
        sc,
        &format!("round-{round:04}@{}", caller.host.ip),
        caller,
        callee,
        10,
    );
    if round.is_multiple_of(2) {
        sc.advance(200 * NS_PER_MS);
        sip_register(sc, &format!("refresh-{round:04}@10.20.0.23"), &c, &p);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_carry_their_length_and_showcase_counts_add_up() {
        let m = Message::request("OPTIONS", "sip:a@b").sdp("192.0.2.1", 4000);
        let text = String::from_utf8(m.bytes()).unwrap();
        let (head, body) = text.split_once("\r\n\r\n").unwrap();
        assert!(head.contains(&format!("Content-Length: {}", body.len())));

        let mut sc = Scenario::new();
        let n = sip_showcase(&mut sc);
        assert_eq!(n.messages(), 18 + 16);
        let scans = sc
            .packets()
            .iter()
            .filter(|p| p.data.windows(16).any(|w| w == FRIENDLY_SCANNER.as_bytes()))
            .count();
        assert_eq!(scans, n.scanner);
    }

    #[test]
    fn rtp_packets_are_version_2() {
        let p = rtp_packet(7, 1);
        assert_eq!(p.len(), 172);
        assert_eq!(p[0] >> 6, 2);
        assert_eq!(u16::from_be_bytes([p[2], p[3]]), 7);
    }
}
