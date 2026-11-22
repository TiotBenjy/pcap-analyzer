//! Traffic spread over time (P5.2, global time filter): [`BURSTS`] bursts of mixed traffic
//! [`BURST_GAP_NS`] apart, plus one long TCP connection active across all of them.
//!
//! Each burst carries its own records (DNS names, HTTP image, TLS server name, SMB NTLM
//! session, FTP account: one per burst) and records repeated in every burst, which the store
//! folds into one row spanning the bursts (SMB host announcement, SNMP community, the same HTTP
//! image). The long connection starts [`LONG_LEAD_NS`] before the first burst, so it is longer
//! than an hour (`netsift_store::range::LONG_FLOW_NS`), and sends a segment every
//! [`KEEPALIVE_NS`], below the idle timeout of the flow table.

use std::net::Ipv6Addr;

use crate::images;
use crate::packet::Packet;
use crate::proto::dns::DnsType;
use crate::proto::netbios::HostAnnouncement;
use crate::scenario::{
    DEFAULT_START_NS, DnsExchange, FtpLogin, HttpGet, Scenario, SmbNtlm, SnmpGet, TcpOptions,
    TlsHandshake,
};
use crate::scenarios::hosts;
use crate::time::NS_PER_SEC;

/// Number of bursts.
pub const BURSTS: usize = 3;
/// Time between the starts of two bursts (ten minutes).
pub const BURST_GAP_NS: i64 = 600 * NS_PER_SEC;
/// Start of the long connection before the first burst (two hours).
pub const LONG_LEAD_NS: i64 = 7200 * NS_PER_SEC;
/// Interval between two segments of the long connection (four minutes).
pub const KEEPALIVE_NS: i64 = 240 * NS_PER_SEC;
/// Server port of the long connection (no analyzer claims it).
pub const LONG_PORT: u16 = 5000;

/// The spread capture and the time span of each part.
#[derive(Debug, Clone)]
pub struct Spread {
    /// Every packet, in time order.
    pub packets: Vec<Packet>,
    /// First and last packet time (ns) of each burst, in order.
    pub bursts: Vec<(i64, i64)>,
    /// First and last packet time (ns) of the long connection.
    pub long_flow: (i64, i64),
}

/// Start of burst `i`.
pub fn burst_start(i: usize) -> i64 {
    DEFAULT_START_NS + LONG_LEAD_NS + i64::try_from(i).unwrap_or(0) * BURST_GAP_NS
}

/// Builds the spread capture ([`BURSTS`] bursts).
pub fn spread() -> Spread {
    spread_with(BURSTS)
}

/// The spread capture with `count` bursts: with many, one burst is a narrow share of each table
/// (the narrow plan of the range aggregates, `netsift_store::range`).
pub fn spread_with(count: usize) -> Spread {
    let mut packets = Vec::new();
    let mut bursts = Vec::new();
    for i in 0..count {
        let mut sc = Scenario::starting_at(burst_start(i)).with_seed(100 + i as u64);
        burst(&mut sc, i);
        let part = sc.into_packets();
        let first = part.first().map_or(0, |p| p.ts_ns);
        let last = part.last().map_or(0, |p| p.ts_ns);
        bursts.push((first, last));
        packets.extend(part);
    }
    let last_burst_end = bursts.last().map_or(DEFAULT_START_NS, |b| b.1);
    let long = long_connection(last_burst_end + 60 * NS_PER_SEC);
    let long_flow = (
        long.first().map_or(0, |p| p.ts_ns),
        long.last().map_or(0, |p| p.ts_ns),
    );
    packets.extend(long);
    packets.sort_by_key(|p| p.ts_ns);
    Spread {
        packets,
        bursts,
        long_flow,
    }
}

fn burst(sc: &mut Scenario, i: usize) {
    let ws = hosts::workstation();
    let gap = 20_000_000; // 20 ms between exchanges
    sc.dns(
        ws,
        hosts::router(),
        &DnsExchange::a(format!("burst{i}.example.test"), [203, 0, 113, 80]),
    );
    sc.advance(gap);
    sc.dns(
        ws,
        hosts::router(),
        &DnsExchange::nxdomain(format!("missing{i}.example.test"), DnsType::A),
    );
    sc.advance(gap);
    // A second client -> server pair (IPv6).
    sc.dns(
        hosts::workstation_v6(),
        hosts::router_v6(),
        &DnsExchange::aaaa(
            format!("burst{i}.example.test"),
            Ipv6Addr::new(0x2001, 0xdb8, 0x80, 0, 0, 0, 0, 0x80),
        ),
    );
    sc.advance(gap);
    // An image of its own, then the image shared by every burst.
    sc.http_get(
        ws,
        hosts::web_server(),
        &HttpGet {
            path: format!("/images/burst{i}.png"),
            body: images::png(64, 48, i),
            ..HttpGet::default()
        },
    );
    sc.advance(gap);
    sc.http_get(ws, hosts::web_server(), &HttpGet::default());
    sc.advance(gap);
    sc.tls_handshake(
        ws,
        hosts::tls_server(),
        &TlsHandshake::new(&format!("burst{i}.example.test")),
    );
    sc.advance(gap);
    sc.smb_host_announcement(
        hosts::file_server(),
        hosts::broadcast(),
        &HostAnnouncement::default(),
    );
    sc.advance(gap);
    sc.smb_ntlm(
        ws,
        hosts::file_server(),
        &SmbNtlm::v2(&format!("user{i}"), "EXAMPLE"),
    );
    sc.advance(gap);
    sc.snmp_get(ws, hosts::router(), &SnmpGet::default());
    sc.advance(gap);
    sc.ftp_login(
        ws,
        hosts::ftp_server(),
        &FtpLogin {
            user: format!("ftpuser{i}"),
            ..FtpLogin::default()
        },
    );
}

/// The long connection, from [`DEFAULT_START_NS`] until `end_ns`.
fn long_connection(end_ns: i64) -> Vec<Packet> {
    let mut sc = Scenario::starting_at(DEFAULT_START_NS).with_seed(7);
    let mut s = sc.tcp_open(
        hosts::workstation(),
        hosts::file_server(),
        &TcpOptions::new(LONG_PORT),
    );
    while s.scenario().now() < end_ns {
        s.scenario().advance(KEEPALIVE_NS);
        s.client_send(b"ping\n");
    }
    s.close();
    sc.into_packets()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bursts_are_apart_and_inside_the_long_connection() {
        let s = spread();
        assert_eq!(s.bursts.len(), BURSTS);
        for pair in s.bursts.windows(2) {
            assert!(pair[1].0 - pair[0].1 > BURST_GAP_NS / 2);
        }
        let (first, last) = s.long_flow;
        assert!(last - first > 3600 * NS_PER_SEC);
        assert!(first < s.bursts[0].0 && last > s.bursts[BURSTS - 1].1);
        assert!(s.packets.windows(2).all(|w| w[0].ts_ns <= w[1].ts_ns));
        // A burst lasts well under a second.
        assert!(s.bursts.iter().all(|(a, b)| b - a < NS_PER_SEC));
    }
}
