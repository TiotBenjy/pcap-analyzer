//! Deterministic scenario builder: a packet clock plus helpers that emit complete protocol
//! exchanges as Ethernet frames.
//!
//! Every packet is stamped with the scenario clock, which then advances by a fixed gap
//! (default 500 us). Ports, TCP initial sequence numbers, DNS ids and TLS randoms come from
//! a seeded generator: the same calls on the same seed always produce identical bytes.

use std::net::{IpAddr, Ipv6Addr};
use std::ops::Range;

use etherparse::{PacketBuilder, TcpOptionElement};

use crate::packet::{Host, LINKTYPE_ETHERNET, Packet};
use crate::proto::der::parse_oid;
use crate::proto::dns::{self, DnsAnswer, DnsData, DnsType};
use crate::proto::netbios::{self, HostAnnouncement, NetbiosName};
use crate::proto::png::png_image;
use crate::proto::snmp::{PduType, SnmpMessage, SnmpValue, SnmpVersion};
use crate::proto::tls::{self, ClientHello, ServerHello};
use crate::proto::x509::{CertSpec, self_signed_certificate};
use crate::rng::SplitMix64;
use crate::time::{NS_PER_SEC, NS_PER_US};

/// 2023-11-14T22:13:20Z, the default start of every scenario.
pub const DEFAULT_START_NS: i64 = 1_700_000_000 * NS_PER_SEC;
/// Default clock advance between two consecutive packets.
pub const DEFAULT_GAP_NS: i64 = 500 * NS_PER_US;
/// Default generator seed.
pub const DEFAULT_SEED: u64 = 0x004e_6574_5369_6674; // "NetSift"

const FIRST_EPHEMERAL_PORT: u16 = 49_152;
const NBNS_TTL: u32 = 300_000;

/// Packet sequence under construction.
#[derive(Debug, Clone)]
pub struct Scenario {
    clock_ns: i64,
    gap_ns: i64,
    interface: u32,
    ttl: u8,
    rng: SplitMix64,
    next_port: u16,
    /// Next IPv4 identification, when enabled by [`Scenario::with_ip_ids`] (0 otherwise).
    next_ip_id: Option<u16>,
    packets: Vec<Packet>,
}

impl Default for Scenario {
    fn default() -> Self {
        Self::new()
    }
}

impl Scenario {
    /// Scenario starting at [`DEFAULT_START_NS`] with [`DEFAULT_SEED`].
    pub fn new() -> Self {
        Self::starting_at(DEFAULT_START_NS)
    }

    /// Scenario whose first packet is stamped `start_ns`.
    pub fn starting_at(start_ns: i64) -> Self {
        assert!(start_ns >= 0, "timestamps before 1970 are not supported");
        Self {
            clock_ns: start_ns,
            gap_ns: DEFAULT_GAP_NS,
            interface: 0,
            ttl: 64,
            rng: SplitMix64::new(DEFAULT_SEED),
            next_port: FIRST_EPHEMERAL_PORT,
            next_ip_id: None,
            packets: Vec::new(),
        }
    }

    /// Reseeds the generator (ports, ISNs, ids, randoms).
    #[must_use]
    pub fn with_seed(mut self, seed: u64) -> Self {
        self.rng = SplitMix64::new(seed);
        self.next_port = FIRST_EPHEMERAL_PORT + u16::try_from(seed % 1000).unwrap_or_default();
        self
    }

    /// Sets the clock advance between two consecutive packets.
    #[must_use]
    pub fn with_gap(mut self, gap_ns: i64) -> Self {
        assert!(gap_ns >= 0, "the packet gap cannot be negative");
        self.gap_ns = gap_ns;
        self
    }

    /// Numbers the IPv4 identification field of the following UDP and TCP frames from
    /// `first` (incremented per IPv4 frame, wrapping). Off by default, so that the bytes of
    /// existing scenarios stay identical (their IPv4 identification is 0).
    #[must_use]
    pub fn with_ip_ids(mut self, first: u16) -> Self {
        self.next_ip_id = Some(first);
        self
    }

    /// Sets the IPv4 identification of `frame` when [`Scenario::with_ip_ids`] is enabled.
    fn stamp_ip_id(&mut self, frame: &mut [u8]) {
        if let Some(id) = self.next_ip_id
            && crate::craft::set_ipv4_ident(frame, id)
        {
            self.next_ip_id = Some(id.wrapping_add(1));
        }
    }

    /// Stamps the following packets with this capture interface.
    pub fn set_interface(&mut self, interface: u32) {
        self.interface = interface;
    }

    /// Current clock: timestamp of the next packet.
    pub fn now(&self) -> i64 {
        self.clock_ns
    }

    /// Moves the clock forward (idle time between exchanges).
    pub fn advance(&mut self, ns: i64) {
        assert!(ns >= 0, "the clock only moves forward");
        self.clock_ns += ns;
    }

    pub fn packets(&self) -> &[Packet] {
        &self.packets
    }

    pub fn len(&self) -> usize {
        self.packets.len()
    }

    pub fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }

    pub fn into_packets(self) -> Vec<Packet> {
        self.packets
    }

    /// Removes and returns the packets built so far, keeping the clock, ports and generator
    /// state (for streaming large captures). Indices returned afterwards restart at 0.
    pub fn take_packets(&mut self) -> Vec<Packet> {
        std::mem::take(&mut self.packets)
    }

    /// Next ephemeral client port (49152..=65535, wrapping).
    pub fn ephemeral_port(&mut self) -> u16 {
        let port = self.next_port;
        self.next_port = if port == u16::MAX {
            FIRST_EPHEMERAL_PORT
        } else {
            port + 1
        };
        port
    }

    /// Appends a raw Ethernet frame at the current clock; returns its index.
    pub fn push_frame(&mut self, data: Vec<u8>) -> usize {
        self.packets.push(Packet {
            ts_ns: self.clock_ns,
            linktype: LINKTYPE_ETHERNET,
            interface: self.interface,
            data,
        });
        self.clock_ns += self.gap_ns;
        self.packets.len() - 1
    }

    /// One UDP datagram; returns its packet index.
    pub fn udp(&mut self, src: Host, dst: Host, sport: u16, dport: u16, payload: &[u8]) -> usize {
        let mut frame = build_frame(&src, &dst, self.ttl, &L4::Udp { sport, dport }, payload);
        self.stamp_ip_id(&mut frame);
        self.push_frame(frame)
    }

    /// Opens a TCP connection (three-way handshake) and returns a session to exchange data.
    pub fn tcp_open(&mut self, client: Host, server: Host, opts: &TcpOptions) -> TcpSession<'_> {
        let cport = opts.client_port.unwrap_or_else(|| self.ephemeral_port());
        let client_isn = self.rng.next_u32();
        let server_isn = self.rng.next_u32();
        let start = self.packets.len();
        let mut s = TcpSession {
            sc: self,
            client,
            server,
            cport,
            sport: opts.server_port,
            client_next: client_isn,
            server_next: server_isn,
            mss: usize::from(opts.mss.max(1)),
            mss_option: opts.mss,
            window: opts.window,
            start,
        };
        s.segment(Side::Client, TcpFlags::SYN, &[]);
        s.client_next = s.client_next.wrapping_add(1);
        s.segment(Side::Server, TcpFlags::SYN_ACK, &[]);
        s.server_next = s.server_next.wrapping_add(1);
        s.segment(Side::Client, TcpFlags::ACK, &[]);
        s
    }

    /// DNS query over UDP and, unless disabled, its response.
    pub fn dns(&mut self, client: Host, server: Host, ex: &DnsExchange) -> DnsIndices {
        let cport = ex.client_port.unwrap_or_else(|| self.ephemeral_port());
        let id = ex
            .id
            .unwrap_or_else(|| u16::try_from(self.rng.next_u32() >> 16).unwrap_or_default());
        let query = self.udp(
            client,
            server,
            cport,
            ex.server_port,
            &dns::encode_query(id, &ex.name, ex.qtype),
        );
        let response = ex.respond.then(|| {
            let payload = dns::encode_response(id, &ex.name, ex.qtype, ex.rcode, &ex.answers);
            self.udp(server, client, ex.server_port, cport, &payload)
        });
        DnsIndices {
            client_port: cport,
            id,
            query,
            response,
        }
    }

    /// Full HTTP/1.1 GET: handshake, request, segmented response, FIN exchange.
    pub fn http_get(&mut self, client: Host, server: Host, get: &HttpGet) -> TcpExchange {
        let mut s = self.tcp_open(client, server, &get.tcp);
        let request = s.client_send(&get.request_bytes());
        let response = s.server_send(&get.response_bytes());
        let client_port = s.client_port();
        let packets = s.close();
        TcpExchange {
            client_port,
            packets,
            request,
            response,
        }
    }

    /// TLS 1.2 handshake start: `ClientHello`, then `ServerHello`, `Certificate` and
    /// `ServerHelloDone` in one server flight, then connection close.
    pub fn tls_handshake(&mut self, client: Host, server: Host, hs: &TlsHandshake) -> TcpExchange {
        let client_hello = ClientHello {
            random: self.rng.bytes(),
            session_id: self.rng.bytes::<32>().to_vec(),
            cipher_suites: hs.cipher_suites.clone(),
            sni: hs.sni.clone(),
            alpn: hs.alpn.clone(),
        };
        let server_hello = ServerHello {
            random: self.rng.bytes(),
            session_id: self.rng.bytes::<32>().to_vec(),
            cipher_suite: hs.selected_suite,
            alpn: hs.selected_alpn.clone(),
        };
        let mut flight = tls::server_hello_record(&server_hello);
        flight.extend_from_slice(&tls::certificate_record(&hs.certificate_chain));
        flight.extend_from_slice(&tls::server_hello_done_record());

        let mut s = self.tcp_open(client, server, &hs.tcp);
        let request = s.client_send(&tls::client_hello_record(&client_hello));
        let response = s.server_send(&flight);
        let client_port = s.client_port();
        let packets = s.close();
        TcpExchange {
            client_port,
            packets,
            request,
            response,
        }
    }

    /// NBNS broadcast name query (UDP 137 -> 137).
    pub fn nbns_query(&mut self, client: Host, to: Host, id: u16, name: &NetbiosName) -> usize {
        self.udp(client, to, 137, 137, &netbios::nbns_name_query(id, name))
    }

    /// Positive NBNS answer from `responder` (its own IPv4 address) to `client`.
    pub fn nbns_query_response(
        &mut self,
        responder: Host,
        client: Host,
        id: u16,
        name: &NetbiosName,
    ) -> usize {
        let addr = responder.ipv4().expect("NBNS requires IPv4");
        let payload = netbios::nbns_name_query_response(id, name, NBNS_TTL, addr);
        self.udp(responder, client, 137, 137, &payload)
    }

    /// NBNS broadcast registration of `name` for `host`'s IPv4 address.
    pub fn nbns_registration(
        &mut self,
        host: Host,
        to: Host,
        id: u16,
        name: &NetbiosName,
        group: bool,
    ) -> usize {
        let addr = host.ipv4().expect("NBNS requires IPv4");
        let payload = netbios::nbns_name_registration(id, name, NBNS_TTL, addr, group);
        self.udp(host, to, 137, 137, &payload)
    }

    /// SMB browser announcement: NetBIOS datagram (UDP 138 -> 138) carrying an SMB
    /// transaction to `\MAILSLOT\BROWSE`.
    pub fn smb_host_announcement(&mut self, host: Host, to: Host, ann: &HostAnnouncement) -> usize {
        let source_ip = host.ipv4().expect("NetBIOS datagrams require IPv4");
        let dgm_id = u16::try_from(self.rng.next_u32() >> 16).unwrap_or_default();
        let smb = netbios::smb_mailslot_browse(&ann.encode());
        let source = NetbiosName::new(ann.server_name.clone(), netbios::SUFFIX_WORKSTATION);
        let payload =
            netbios::netbios_group_datagram(dgm_id, source_ip, &source, &ann.destination(), &smb);
        self.udp(host, to, 138, 138, &payload)
    }

    /// SNMP request (UDP -> 161) with community string, and optional agent response.
    pub fn snmp_get(&mut self, manager: Host, agent: Host, get: &SnmpGet) -> SnmpIndices {
        let cport = get.client_port.unwrap_or_else(|| self.ephemeral_port());
        let oids: Vec<Vec<u32>> = get.oids.iter().map(|o| parse_oid(o)).collect();
        let message = SnmpMessage {
            version: get.version,
            community: get.community.clone(),
            pdu: get.pdu,
            request_id: get.request_id,
            error_status: 0,
            error_index: 0,
            varbinds: oids.iter().map(|o| (o.clone(), SnmpValue::Null)).collect(),
        };
        let request = self.udp(manager, agent, cport, 161, &message.encode());
        let response = get.response.as_ref().map(|values| {
            let reply = SnmpMessage {
                pdu: PduType::Response,
                varbinds: oids.iter().cloned().zip(values.iter().cloned()).collect(),
                ..message.clone()
            };
            self.udp(agent, manager, 161, cport, &reply.encode())
        });
        SnmpIndices {
            client_port: cport,
            request,
            response,
        }
    }

    /// FTP control session: banner, `USER`, `PASS`, reply, optional `QUIT`, close.
    pub fn ftp_login(&mut self, client: Host, server: Host, login: &FtpLogin) -> FtpIndices {
        let mut s = self.tcp_open(client, server, &login.tcp);
        s.server_send(format!("220 {}\r\n", login.banner).as_bytes());
        let user = s.client_send(format!("USER {}\r\n", login.user).as_bytes());
        s.server_send(
            format!("331 Please specify the password for {}.\r\n", login.user).as_bytes(),
        );
        let pass = s.client_send(format!("PASS {}\r\n", login.password).as_bytes());
        let reply: &[u8] = if login.accepted {
            b"230 Login successful.\r\n"
        } else {
            b"530 Login incorrect.\r\n"
        };
        s.server_send(reply);
        if login.quit {
            s.client_send(b"QUIT\r\n");
            s.server_send(b"221 Goodbye.\r\n");
        }
        let client_port = s.client_port();
        let packets = s.close();
        FtpIndices {
            client_port,
            packets,
            user,
            pass,
        }
    }
}

/// TCP connection parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpOptions {
    /// Client port; `None` picks the next ephemeral port.
    pub client_port: Option<u16>,
    pub server_port: u16,
    /// Maximum segment size used to split payloads (both directions), announced in SYNs.
    pub mss: u16,
    pub window: u16,
}

impl TcpOptions {
    pub fn new(server_port: u16) -> Self {
        Self {
            client_port: None,
            server_port,
            mss: 1460,
            window: 64_240,
        }
    }
}

/// Open TCP connection inside a [`Scenario`]. Data is split into MSS-sized segments; each
/// burst is acknowledged by the peer with a pure ACK.
#[derive(Debug)]
pub struct TcpSession<'a> {
    sc: &'a mut Scenario,
    client: Host,
    server: Host,
    cport: u16,
    sport: u16,
    client_next: u32,
    server_next: u32,
    mss: usize,
    mss_option: u16,
    window: u16,
    start: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Side {
    Client,
    Server,
}

#[allow(clippy::struct_excessive_bools)] // TCP flags are bits by nature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TcpFlags {
    syn: bool,
    ack: bool,
    psh: bool,
    fin: bool,
}

impl TcpFlags {
    const SYN: Self = Self {
        syn: true,
        ack: false,
        psh: false,
        fin: false,
    };
    const SYN_ACK: Self = Self {
        syn: true,
        ack: true,
        psh: false,
        fin: false,
    };
    const ACK: Self = Self {
        syn: false,
        ack: true,
        psh: false,
        fin: false,
    };
    const PSH_ACK: Self = Self {
        syn: false,
        ack: true,
        psh: true,
        fin: false,
    };
    const FIN_ACK: Self = Self {
        syn: false,
        ack: true,
        psh: false,
        fin: true,
    };
}

impl TcpSession<'_> {
    pub fn client_port(&self) -> u16 {
        self.cport
    }

    /// Next sequence number the client will use.
    pub fn client_next_seq(&self) -> u32 {
        self.client_next
    }

    /// Next sequence number the server will use.
    pub fn server_next_seq(&self) -> u32 {
        self.server_next
    }

    /// The underlying scenario (for example to advance the clock mid-connection).
    pub fn scenario(&mut self) -> &mut Scenario {
        self.sc
    }

    /// Client -> server data; returns the indices of the data segments.
    pub fn client_send(&mut self, data: &[u8]) -> Range<usize> {
        self.send(Side::Client, data)
    }

    /// Server -> client data; returns the indices of the data segments.
    pub fn server_send(&mut self, data: &[u8]) -> Range<usize> {
        self.send(Side::Server, data)
    }

    /// Client-initiated close (FIN, FIN, ACK); returns the range of the whole connection.
    pub fn close(mut self) -> Range<usize> {
        self.segment(Side::Client, TcpFlags::FIN_ACK, &[]);
        self.client_next = self.client_next.wrapping_add(1);
        self.segment(Side::Server, TcpFlags::FIN_ACK, &[]);
        self.server_next = self.server_next.wrapping_add(1);
        self.segment(Side::Client, TcpFlags::ACK, &[]);
        self.start..self.sc.packets.len()
    }

    fn send(&mut self, side: Side, data: &[u8]) -> Range<usize> {
        let first = self.sc.packets.len();
        let count = data.chunks(self.mss).count();
        for (i, piece) in data.chunks(self.mss).enumerate() {
            let flags = if i + 1 == count {
                TcpFlags::PSH_ACK
            } else {
                TcpFlags::ACK
            };
            self.segment(side, flags, piece);
            let len = u32::try_from(piece.len()).expect("segment fits in u32");
            match side {
                Side::Client => self.client_next = self.client_next.wrapping_add(len),
                Side::Server => self.server_next = self.server_next.wrapping_add(len),
            }
        }
        let range = first..self.sc.packets.len();
        if !range.is_empty() {
            let peer = match side {
                Side::Client => Side::Server,
                Side::Server => Side::Client,
            };
            self.segment(peer, TcpFlags::ACK, &[]);
        }
        range
    }

    fn segment(&mut self, side: Side, flags: TcpFlags, payload: &[u8]) -> usize {
        let (src, dst, sport, dport, seq, ack) = match side {
            Side::Client => (
                self.client,
                self.server,
                self.cport,
                self.sport,
                self.client_next,
                self.server_next,
            ),
            Side::Server => (
                self.server,
                self.client,
                self.sport,
                self.cport,
                self.server_next,
                self.client_next,
            ),
        };
        let l4 = L4::Tcp {
            sport,
            dport,
            seq,
            ack: flags.ack.then_some(ack),
            flags,
            window: self.window,
            mss: flags.syn.then_some(self.mss_option),
        };
        let mut frame = build_frame(&src, &dst, self.sc.ttl, &l4, payload);
        self.sc.stamp_ip_id(&mut frame);
        self.sc.push_frame(frame)
    }
}

enum L4 {
    Udp {
        sport: u16,
        dport: u16,
    },
    Tcp {
        sport: u16,
        dport: u16,
        seq: u32,
        ack: Option<u32>,
        flags: TcpFlags,
        window: u16,
        mss: Option<u16>,
    },
}

fn build_frame(src: &Host, dst: &Host, ttl: u8, l4: &L4, payload: &[u8]) -> Vec<u8> {
    let eth = PacketBuilder::ethernet2(src.mac, dst.mac);
    let ip = match (src.ip, dst.ip) {
        (IpAddr::V4(s), IpAddr::V4(d)) => eth.ipv4(s.octets(), d.octets(), ttl),
        (IpAddr::V6(s), IpAddr::V6(d)) => eth.ipv6(s.octets(), d.octets(), ttl),
        _ => panic!("source and destination must use the same IP version"),
    };
    let mut out = Vec::new();
    match *l4 {
        L4::Udp { sport, dport } => {
            let b = ip.udp(sport, dport);
            out.reserve(b.size(payload.len()));
            b.write(&mut out, payload).expect("valid UDP frame");
        }
        L4::Tcp {
            sport,
            dport,
            seq,
            ack,
            flags,
            window,
            mss,
        } => {
            let mut b = ip.tcp(sport, dport, seq, window);
            if flags.syn {
                b = b.syn();
            }
            if let Some(ack) = ack {
                b = b.ack(ack);
            }
            if flags.psh {
                b = b.psh();
            }
            if flags.fin {
                b = b.fin();
            }
            if let Some(mss) = mss {
                b = b
                    .options(&[TcpOptionElement::MaximumSegmentSize(mss)])
                    .expect("MSS option fits");
            }
            out.reserve(b.size(payload.len()));
            b.write(&mut out, payload).expect("valid TCP frame");
        }
    }
    out
}

/// A DNS query and its optional response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsExchange {
    /// Transaction id; `None` draws one from the scenario generator.
    pub id: Option<u16>,
    pub name: String,
    pub qtype: DnsType,
    pub answers: Vec<DnsAnswer>,
    pub rcode: u8,
    /// Emit the response packet.
    pub respond: bool,
    pub client_port: Option<u16>,
    pub server_port: u16,
}

impl DnsExchange {
    /// Query of type `qtype` with an empty, successful answer section.
    pub fn new(name: impl Into<String>, qtype: DnsType) -> Self {
        Self {
            id: None,
            name: name.into(),
            qtype,
            answers: Vec::new(),
            rcode: 0,
            respond: true,
            client_port: None,
            server_port: 53,
        }
    }

    /// `A` query answered with `ip`.
    pub fn a(name: impl Into<String>, ip: [u8; 4]) -> Self {
        let mut ex = Self::new(name, DnsType::A);
        ex.answers
            .push(DnsAnswer::new(ex.name.clone(), 300, DnsData::A(ip.into())));
        ex
    }

    /// `AAAA` query answered with `ip`.
    pub fn aaaa(name: impl Into<String>, ip: Ipv6Addr) -> Self {
        let mut ex = Self::new(name, DnsType::Aaaa);
        ex.answers
            .push(DnsAnswer::new(ex.name.clone(), 300, DnsData::Aaaa(ip)));
        ex
    }

    /// `A` query answered with a CNAME to `target`, then `target` -> `ip`.
    pub fn cname(name: impl Into<String>, target: impl Into<String>, ip: [u8; 4]) -> Self {
        let target = target.into();
        let mut ex = Self::new(name, DnsType::A);
        ex.answers.push(DnsAnswer::new(
            ex.name.clone(),
            3600,
            DnsData::Cname(target.clone()),
        ));
        ex.answers
            .push(DnsAnswer::new(target, 60, DnsData::A(ip.into())));
        ex
    }

    /// Query answered with `NXDOMAIN`.
    pub fn nxdomain(name: impl Into<String>, qtype: DnsType) -> Self {
        let mut ex = Self::new(name, qtype);
        ex.rcode = dns::RCODE_NXDOMAIN;
        ex
    }

    #[must_use]
    pub fn with_id(mut self, id: u16) -> Self {
        self.id = Some(id);
        self
    }

    /// Query without response (unanswered transaction).
    #[must_use]
    pub fn unanswered(mut self) -> Self {
        self.respond = false;
        self
    }
}

/// Packet indices of a DNS exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsIndices {
    pub client_port: u16,
    pub id: u16,
    pub query: usize,
    pub response: Option<usize>,
}

/// Packet indices of a request/response exchange over one TCP connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpExchange {
    pub client_port: u16,
    /// Whole connection, handshake to final ACK.
    pub packets: Range<usize>,
    /// Client data segments.
    pub request: Range<usize>,
    /// Server data segments.
    pub response: Range<usize>,
}

/// HTTP/1.1 GET with its response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpGet {
    pub host: String,
    pub path: String,
    pub user_agent: String,
    pub extra_headers: Vec<(String, String)>,
    pub status: u16,
    pub reason: String,
    pub content_type: String,
    pub body: Vec<u8>,
    pub tcp: TcpOptions,
}

impl Default for HttpGet {
    /// `GET /images/logo.png` on `www.example.test`, answered with a 128x96 PNG.
    fn default() -> Self {
        Self {
            host: "www.example.test".to_owned(),
            path: "/images/logo.png".to_owned(),
            user_agent: "Mozilla/5.0 (X11; Linux x86_64) NetSiftFixtures/1.0".to_owned(),
            extra_headers: Vec::new(),
            status: 200,
            reason: "OK".to_owned(),
            content_type: "image/png".to_owned(),
            body: png_image(128, 96),
            tcp: TcpOptions::new(80),
        }
    }
}

impl HttpGet {
    pub fn request_bytes(&self) -> Vec<u8> {
        let mut req = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nAccept: */*\r\n",
            self.path, self.host, self.user_agent
        );
        for (k, v) in &self.extra_headers {
            req.push_str(k);
            req.push_str(": ");
            req.push_str(v);
            req.push_str("\r\n");
        }
        req.push_str("\r\n");
        req.into_bytes()
    }

    pub fn response_bytes(&self) -> Vec<u8> {
        let head = format!(
            "HTTP/1.1 {} {}\r\nServer: nginx/1.24.0\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            self.status,
            self.reason,
            self.content_type,
            self.body.len()
        );
        let mut out = head.into_bytes();
        out.extend_from_slice(&self.body);
        out
    }
}

/// TLS 1.2 handshake parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsHandshake {
    pub sni: Option<String>,
    pub alpn: Vec<String>,
    pub cipher_suites: Vec<u16>,
    pub selected_suite: u16,
    pub selected_alpn: Option<String>,
    /// DER certificates, leaf first.
    pub certificate_chain: Vec<Vec<u8>>,
    pub tcp: TcpOptions,
}

impl TlsHandshake {
    /// Handshake with SNI `server_name` and a self-signed certificate for it.
    pub fn new(server_name: &str) -> Self {
        Self {
            sni: Some(server_name.to_owned()),
            alpn: vec!["h2".to_owned(), "http/1.1".to_owned()],
            cipher_suites: tls::DEFAULT_CIPHER_SUITES.to_vec(),
            selected_suite: tls::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            selected_alpn: Some("h2".to_owned()),
            certificate_chain: vec![self_signed_certificate(&CertSpec::new(server_name))],
            tcp: TcpOptions::new(443),
        }
    }
}

impl Default for TlsHandshake {
    fn default() -> Self {
        Self::new("secure.example.test")
    }
}

/// SNMP request parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnmpGet {
    pub version: SnmpVersion,
    pub community: String,
    pub pdu: PduType,
    pub request_id: i32,
    /// Dotted OIDs.
    pub oids: Vec<String>,
    /// Values returned by the agent (one per OID); `None` for no response.
    pub response: Option<Vec<SnmpValue>>,
    pub client_port: Option<u16>,
}

impl Default for SnmpGet {
    /// v2c `GetRequest` with community `public` for `sysDescr.0` and `sysName.0`.
    fn default() -> Self {
        Self {
            version: SnmpVersion::V2c,
            community: "public".to_owned(),
            pdu: PduType::GetRequest,
            request_id: 1,
            oids: vec![
                "1.3.6.1.2.1.1.1.0".to_owned(),
                "1.3.6.1.2.1.1.5.0".to_owned(),
            ],
            response: Some(vec![
                SnmpValue::OctetString(b"Linux router01 6.1.0 x86_64".to_vec()),
                SnmpValue::OctetString(b"router01".to_vec()),
            ]),
            client_port: None,
        }
    }
}

/// Packet indices of an SNMP exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnmpIndices {
    pub client_port: u16,
    pub request: usize,
    pub response: Option<usize>,
}

/// FTP login parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FtpLogin {
    pub user: String,
    pub password: String,
    pub banner: String,
    /// `230` when true, `530` otherwise.
    pub accepted: bool,
    pub quit: bool,
    pub tcp: TcpOptions,
}

impl Default for FtpLogin {
    fn default() -> Self {
        Self {
            user: "alice".to_owned(),
            password: "s3cret-fixture".to_owned(),
            banner: "(vsFTPd 3.0.5)".to_owned(),
            accepted: true,
            quit: true,
            tcp: TcpOptions::new(21),
        }
    }
}

/// Packet indices of an FTP login.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FtpIndices {
    pub client_port: u16,
    pub packets: Range<usize>,
    /// Segments carrying `USER`.
    pub user: Range<usize>,
    /// Segments carrying `PASS`.
    pub pass: Range<usize>,
}
