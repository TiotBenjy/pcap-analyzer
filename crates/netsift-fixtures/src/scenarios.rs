//! Ready-made hosts and scenarios (documentation address ranges only: RFC 1918, RFC 5737,
//! RFC 3849).

use std::net::Ipv6Addr;

use crate::packet::{Host, Packet};
use crate::proto::dns::DnsType;
use crate::proto::netbios::{self, HostAnnouncement, NetbiosName};
use crate::scenario::{DnsExchange, FtpLogin, HttpGet, Scenario, SnmpGet, TlsHandshake};
use crate::time::{NS_PER_MS, NS_PER_SEC};

/// Hosts used by the built-in scenarios.
pub mod hosts {
    use super::{Host, Ipv6Addr};

    /// LAN workstation, 192.168.1.10.
    pub fn workstation() -> Host {
        Host::v4([0x02, 0x00, 0x5e, 0x10, 0x00, 0x10], [192, 168, 1, 10])
    }

    /// Same workstation over IPv6, `2001:db8:1::10`.
    pub fn workstation_v6() -> Host {
        Host::v6(
            [0x02, 0x00, 0x5e, 0x10, 0x00, 0x10],
            Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 0x10),
        )
    }

    /// Router, DNS resolver and SNMP agent, 192.168.1.1.
    pub fn router() -> Host {
        Host::v4([0x02, 0x00, 0x5e, 0x10, 0x00, 0x01], [192, 168, 1, 1])
    }

    /// Router over IPv6, `2001:db8:1::1`.
    pub fn router_v6() -> Host {
        Host::v6(
            [0x02, 0x00, 0x5e, 0x10, 0x00, 0x01],
            Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 1),
        )
    }

    /// Remote web server 203.0.113.80, reached through the router MAC.
    pub fn web_server() -> Host {
        Host::v4(router().mac, [203, 0, 113, 80])
    }

    /// Remote TLS server 198.51.100.43, reached through the router MAC.
    pub fn tls_server() -> Host {
        Host::v4(router().mac, [198, 51, 100, 43])
    }

    /// LAN file server, 192.168.1.20.
    pub fn file_server() -> Host {
        Host::v4([0x02, 0x00, 0x5e, 0x10, 0x00, 0x20], [192, 168, 1, 20])
    }

    /// LAN FTP server, 192.168.1.21.
    pub fn ftp_server() -> Host {
        Host::v4([0x02, 0x00, 0x5e, 0x10, 0x00, 0x21], [192, 168, 1, 21])
    }

    /// Subnet broadcast, 192.168.1.255.
    pub fn broadcast() -> Host {
        Host::broadcast_v4([192, 168, 1, 255])
    }
}

/// Idle time inserted between two exchanges of the demo scenario.
pub const EXCHANGE_GAP_NS: i64 = 50 * NS_PER_MS;

/// Built-in single-protocol scenarios, selectable by name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    /// One exchange of every protocol below.
    Demo,
    Dns,
    Http,
    Tls,
    Nbns,
    Smb,
    Snmp,
    Ftp,
}

impl Kind {
    pub const ALL: [Self; 8] = [
        Self::Demo,
        Self::Dns,
        Self::Http,
        Self::Tls,
        Self::Nbns,
        Self::Smb,
        Self::Snmp,
        Self::Ftp,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Self::Demo => "demo",
            Self::Dns => "dns",
            Self::Http => "http",
            Self::Tls => "tls",
            Self::Nbns => "nbns",
            Self::Smb => "smb",
            Self::Snmp => "snmp",
            Self::Ftp => "ftp",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.name() == name)
    }

    /// Appends one round of this scenario to `sc`.
    pub fn append_to(self, sc: &mut Scenario) {
        match self {
            Self::Demo => demo_round(sc),
            Self::Dns => dns_round(sc),
            Self::Http => {
                sc.http_get(
                    hosts::workstation(),
                    hosts::web_server(),
                    &HttpGet::default(),
                );
            }
            Self::Tls => {
                sc.tls_handshake(
                    hosts::workstation(),
                    hosts::tls_server(),
                    &TlsHandshake::default(),
                );
            }
            Self::Nbns => nbns_round(sc),
            Self::Smb => {
                sc.smb_host_announcement(
                    hosts::file_server(),
                    hosts::broadcast(),
                    &HostAnnouncement::default(),
                );
            }
            Self::Snmp => {
                sc.snmp_get(hosts::workstation(), hosts::router(), &SnmpGet::default());
            }
            Self::Ftp => {
                sc.ftp_login(
                    hosts::workstation(),
                    hosts::ftp_server(),
                    &FtpLogin::default(),
                );
            }
        }
    }
}

/// `rounds` rounds of `kind`, one second apart, starting at the default timestamp.
pub fn generate(kind: Kind, rounds: usize, seed: u64) -> Vec<Packet> {
    let mut sc = Scenario::new().with_seed(seed);
    for round in 0..rounds {
        if round > 0 {
            sc.advance(NS_PER_SEC);
        }
        kind.append_to(&mut sc);
    }
    sc.into_packets()
}

/// The demo scenario: one exchange of every supported protocol.
pub fn demo() -> Scenario {
    let mut sc = Scenario::new();
    demo_round(&mut sc);
    sc
}

fn demo_round(sc: &mut Scenario) {
    let ws = hosts::workstation();
    nbns_round(sc);
    sc.advance(EXCHANGE_GAP_NS);
    dns_round(sc);
    sc.advance(EXCHANGE_GAP_NS);
    sc.http_get(ws, hosts::web_server(), &HttpGet::default());
    sc.advance(EXCHANGE_GAP_NS);
    sc.tls_handshake(ws, hosts::tls_server(), &TlsHandshake::default());
    sc.advance(EXCHANGE_GAP_NS);
    sc.smb_host_announcement(
        hosts::file_server(),
        hosts::broadcast(),
        &HostAnnouncement::default(),
    );
    sc.advance(EXCHANGE_GAP_NS);
    sc.snmp_get(ws, hosts::router(), &SnmpGet::default());
    sc.advance(EXCHANGE_GAP_NS);
    sc.ftp_login(ws, hosts::ftp_server(), &FtpLogin::default());
}

fn dns_round(sc: &mut Scenario) {
    let ws = hosts::workstation();
    let resolver = hosts::router();
    sc.dns(
        ws,
        resolver,
        &DnsExchange::a("www.example.test", [203, 0, 113, 80]),
    );
    sc.dns(
        hosts::workstation_v6(),
        hosts::router_v6(),
        &DnsExchange::aaaa(
            "www.example.test",
            Ipv6Addr::new(0x2001, 0xdb8, 0x80, 0, 0, 0, 0, 0x80),
        ),
    );
    sc.dns(
        ws,
        resolver,
        &DnsExchange::cname(
            "secure.example.test",
            "edge.cdn.example.net",
            [198, 51, 100, 43],
        ),
    );
    sc.dns(
        ws,
        resolver,
        &DnsExchange::nxdomain("missing.example.test", DnsType::A),
    );
}

fn nbns_round(sc: &mut Scenario) {
    let server = hosts::file_server();
    let name = NetbiosName::new("FILESRV01", netbios::SUFFIX_SERVER);
    sc.nbns_registration(server, hosts::broadcast(), 0x7101, &name, false);
    sc.nbns_query(hosts::workstation(), hosts::broadcast(), 0x7102, &name);
    sc.nbns_query_response(server, hosts::workstation(), 0x7102, &name);
}

/// One fragmented UDP datagram of [`fragmentation`], as the receiver should rebuild it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FragmentedDatagram {
    pub src: Host,
    pub dst: Host,
    pub sport: u16,
    pub dport: u16,
    /// UDP payload after reassembly.
    pub payload: Vec<u8>,
    /// Number of fragment frames sent for this datagram.
    pub frames: usize,
}

/// Deterministic payload of `len` bytes, different for each `seed`.
fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| u8::try_from(i % 251).unwrap_or_default() ^ seed)
        .collect()
}

/// IP fragmentation scenario: four UDP datagrams (two IPv4, two IPv6) sent as fragments,
/// each completed by its last frame, in this order:
///
/// 1. IPv4, 3000-byte payload, three fragments sent out of order (last, first, first again
///    as an exact duplicate, middle);
/// 2. IPv4, 2000-byte payload, two fragments overlapping by 8 identical bytes, with a forged
///    fragment (zeros over bytes 512..1024) between them that a "first arrival wins"
///    reassembler must ignore;
/// 3. IPv6, 3000-byte payload, three fragments in reverse order with the middle one repeated;
/// 4. IPv6, same overlap and forged fragment as case 2.
///
/// The packets use the scenario clock (500 us apart); the expected datagrams are returned in
/// completion order.
pub fn fragmentation() -> (Scenario, Vec<FragmentedDatagram>) {
    use crate::craft::{FragSpec, fragment_frames, ip_payload, udp_frame};

    let mut sc = Scenario::new();
    let mut expected = Vec::new();
    let cases: [(Host, Host, u32, usize, u8); 4] = [
        (hosts::workstation(), hosts::router(), 0x0101, 3000, 1),
        (hosts::workstation(), hosts::router(), 0x0102, 2000, 2),
        (
            hosts::workstation_v6(),
            hosts::router_v6(),
            0xdead_0001,
            3000,
            3,
        ),
        (
            hosts::workstation_v6(),
            hosts::router_v6(),
            0xdead_0002,
            2000,
            4,
        ),
    ];
    for (i, (src, dst, ident, len, seed)) in cases.into_iter().enumerate() {
        let (sport, dport) = (40_000 + u16::from(seed), 9_000);
        let payload = pattern(len, seed);
        let frame = udp_frame(&src, &dst, sport, dport, &payload);
        let body = ip_payload(&frame).expect("IP frame").to_vec();
        let specs = if i % 2 == 0 {
            let even = FragSpec::even(&body, 1232);
            assert_eq!(even.len(), 3, "three fragments");
            if i == 0 {
                vec![
                    even[2].clone(),
                    even[0].clone(),
                    even[0].clone(),
                    even[1].clone(),
                ]
            } else {
                vec![
                    even[2].clone(),
                    even[1].clone(),
                    even[1].clone(),
                    even[0].clone(),
                ]
            }
        } else {
            vec![
                FragSpec::slice(&body, 0..1024),
                FragSpec::new(512, true, vec![0u8; 512]),
                FragSpec::slice(&body, 1016..body.len()),
            ]
        };
        let frames = fragment_frames(&frame, ident, &specs);
        let count = frames.len();
        for f in frames {
            sc.push_frame(f);
        }
        expected.push(FragmentedDatagram {
            src,
            dst,
            sport,
            dport,
            payload,
            frames: count,
        });
    }
    (sc, expected)
}
