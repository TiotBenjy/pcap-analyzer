//! IANA service names of TCP and UDP ports, embedded at build time.
//!
//! Source: the IANA "Service Name and Transport Protocol Port Number Registry" (CC0 1.0),
//! compacted by `scripts/gen-iana-services.py` into `data/iana-services.csv` (procedure in
//! `data/README.md`). Nothing is fetched at run time. The table is parsed once, on first use,
//! into a sorted vector (about 6 300 entries) searched by binary search.

use std::sync::OnceLock;

use crate::classify::ip_proto;

const CSV: &str = include_str!("../data/iana-services.csv");

/// Transports of one entry (`b`, `t`, `u` in the file).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Transports {
    Both,
    Tcp,
    Udp,
}

impl Transports {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "b" => Some(Self::Both),
            "t" => Some(Self::Tcp),
            "u" => Some(Self::Udp),
            _ => None,
        }
    }

    fn matches(self, transport: u8) -> bool {
        match self {
            Self::Both => transport == ip_proto::TCP || transport == ip_proto::UDP,
            Self::Tcp => transport == ip_proto::TCP,
            Self::Udp => transport == ip_proto::UDP,
        }
    }
}

type Entry = (u16, Transports, &'static str);

fn table() -> &'static [Entry] {
    static TABLE: OnceLock<Vec<Entry>> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut entries: Vec<Entry> = CSV
            .lines()
            .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
            .filter_map(|line| {
                let mut fields = line.splitn(3, ',');
                let port = fields.next()?.parse().ok()?;
                let transports = Transports::parse(fields.next()?)?;
                let name = fields.next()?.trim();
                (!name.is_empty()).then_some((port, transports, name))
            })
            .collect();
        // The file is sorted; sorting again keeps the search correct if it is edited by hand.
        entries.sort_by_key(|e| e.0);
        entries
    })
}

/// IANA service name of `port` for the IP protocol `transport` (6 TCP, 17 UDP), if assigned.
pub fn iana_service(transport: u8, port: u16) -> Option<&'static str> {
    let table = table();
    let start = table.partition_point(|e| e.0 < port);
    table
        .get(start..)?
        .iter()
        .take_while(|e| e.0 == port)
        .find(|e| e.1.matches(transport))
        .map(|e| e.2)
}

/// Number of entries of the embedded table (diagnostics and tests).
pub fn table_len() -> usize {
    table().len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ip_proto::{ICMP, TCP, UDP};

    #[test]
    fn every_data_line_is_parsed() {
        let data_lines = CSV
            .lines()
            .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
            .count();
        assert_eq!(table_len(), data_lines);
        assert!(table_len() > 5_000, "the registry looks truncated");
    }

    #[test]
    fn well_known_ports() {
        for (transport, port, name) in [
            (TCP, 22, Some("ssh")),
            (TCP, 80, Some("http")),
            (TCP, 443, Some("https")),
            (UDP, 53, Some("domain")),
            (TCP, 53, Some("domain")),
            (TCP, 1863, Some("msnp")),
            (TCP, 3389, Some("ms-wbt-server")),
            (UDP, 5353, Some("mdns")),
            (TCP, 6010, Some("x11")),
            (TCP, 0, None),
            (ICMP, 80, None),
        ] {
            assert_eq!(iana_service(transport, port), name, "{transport}/{port}");
        }
    }

    #[test]
    fn transport_specific_entries() {
        // Some ports carry different names (or none) on TCP and UDP.
        let both = (1..=u16::MAX)
            .filter(|p| iana_service(TCP, *p).is_some() != iana_service(UDP, *p).is_some())
            .count();
        assert!(both > 0, "the table should have TCP-only or UDP-only ports");
        assert_eq!(iana_service(UDP, 49_151), iana_service(UDP, 49_151));
    }
}
