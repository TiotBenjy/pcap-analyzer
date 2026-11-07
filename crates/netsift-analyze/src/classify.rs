//! Application protocol classification of packets and flows.
//!
//! Order of precedence for a packet:
//! 1. the flow it belongs to: well-known server port, then client port (both directions of a
//!    flow get the same label);
//! 2. outside a flow: the well-known port among the two ports of the packet (the lower one
//!    when both are known, so that both directions agree);
//! 3. fallback on the transport: `tcp`, `udp`, `icmp`, `ip` (any other IP protocol), and
//!    `non_ip` for frames without an IP layer (ARP, undecodable frames...).
//!
//! `other` is never produced: the UI reserves it for the "Others" bucket of top-N charts.
//!
//! Labels are stable, lower case, and aligned with the UI palette (`ui/src/charts/palette.ts`).
//! They are stored in the database (`timeseries.proto`, `flows.app_proto`): never rename one.

use std::fmt;

use netsift_dissect::Decoded;
use netsift_flow::{FlowKey, PacketCtx};

/// IP protocol numbers used by the classification.
pub mod ip_proto {
    pub const ICMP: u8 = 1;
    pub const TCP: u8 = 6;
    pub const UDP: u8 = 17;
    pub const ICMPV6: u8 = 58;
}

/// Application protocol label (traffic category).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AppProto {
    // Identified by a well-known port.
    Dhcp,
    Dns,
    Ftp,
    Http,
    Imap,
    Kerberos,
    Ldap,
    Netbios,
    Ntp,
    Pop3,
    Rdp,
    Sip,
    Smb,
    Smtp,
    Snmp,
    Ssdp,
    Ssh,
    Syslog,
    Telnet,
    Tls,
    // Fallbacks.
    Tcp,
    Udp,
    Icmp,
    /// IP packet of another protocol (GRE, ESP, IGMP...).
    Ip,
    /// Frame without an IP layer.
    NonIp,
}

impl AppProto {
    /// Every label, in declaration order.
    pub const ALL: [Self; 25] = [
        Self::Dhcp,
        Self::Dns,
        Self::Ftp,
        Self::Http,
        Self::Imap,
        Self::Kerberos,
        Self::Ldap,
        Self::Netbios,
        Self::Ntp,
        Self::Pop3,
        Self::Rdp,
        Self::Sip,
        Self::Smb,
        Self::Smtp,
        Self::Snmp,
        Self::Ssdp,
        Self::Ssh,
        Self::Syslog,
        Self::Telnet,
        Self::Tls,
        Self::Tcp,
        Self::Udp,
        Self::Icmp,
        Self::Ip,
        Self::NonIp,
    ];

    /// Stable label stored in the database.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Dhcp => "dhcp",
            Self::Dns => "dns",
            Self::Ftp => "ftp",
            Self::Http => "http",
            Self::Imap => "imap",
            Self::Kerberos => "kerberos",
            Self::Ldap => "ldap",
            Self::Netbios => "netbios",
            Self::Ntp => "ntp",
            Self::Pop3 => "pop3",
            Self::Rdp => "rdp",
            Self::Sip => "sip",
            Self::Smb => "smb",
            Self::Smtp => "smtp",
            Self::Snmp => "snmp",
            Self::Ssdp => "ssdp",
            Self::Ssh => "ssh",
            Self::Syslog => "syslog",
            Self::Telnet => "telnet",
            Self::Tls => "tls",
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Icmp => "icmp",
            Self::Ip => "ip",
            Self::NonIp => "non_ip",
        }
    }

    /// Parses a stored label.
    pub fn from_label(label: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.as_str() == label)
    }

    /// True for the fallbacks (`tcp`, `udp`, `icmp`, `ip`, `non_ip`).
    pub const fn is_fallback(self) -> bool {
        matches!(
            self,
            Self::Tcp | Self::Udp | Self::Icmp | Self::Ip | Self::NonIp
        )
    }
}

impl fmt::Display for AppProto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Protocol registered on a well-known port for this IP protocol (TCP or UDP only).
pub fn well_known(ip_proto: u8, port: u16) -> Option<AppProto> {
    let tcp = ip_proto == ip_proto::TCP;
    let udp = ip_proto == ip_proto::UDP;
    if !tcp && !udp {
        return None;
    }
    let proto = match port {
        20 | 21 if tcp => AppProto::Ftp,
        22 if tcp => AppProto::Ssh,
        23 if tcp => AppProto::Telnet,
        25 | 587 if tcp => AppProto::Smtp,
        53 => AppProto::Dns,
        67 | 68 | 546 | 547 if udp => AppProto::Dhcp,
        80 | 8080 if tcp => AppProto::Http,
        88 => AppProto::Kerberos,
        110 if tcp => AppProto::Pop3,
        123 if udp => AppProto::Ntp,
        137 | 138 => AppProto::Netbios,
        139 | 445 if tcp => AppProto::Smb,
        143 if tcp => AppProto::Imap,
        161 | 162 if udp => AppProto::Snmp,
        389 | 3268 => AppProto::Ldap,
        443 | 465 | 636 | 853 | 993 | 995 | 8443 if tcp => AppProto::Tls,
        514 if udp => AppProto::Syslog,
        1900 if udp => AppProto::Ssdp,
        3389 if tcp => AppProto::Rdp,
        5060 => AppProto::Sip,
        5353 | 5355 if udp => AppProto::Dns,
        _ => return None,
    };
    Some(proto)
}

/// Fallback label from the IP protocol number.
pub fn transport_fallback(ip_proto: u8) -> AppProto {
    match ip_proto {
        ip_proto::TCP => AppProto::Tcp,
        ip_proto::UDP => AppProto::Udp,
        ip_proto::ICMP | ip_proto::ICMPV6 => AppProto::Icmp,
        _ => AppProto::Ip,
    }
}

/// Protocol identified by a well-known port of the flow: server port first, then client port.
pub fn flow_app_proto(key: &FlowKey) -> Option<AppProto> {
    well_known(key.proto, key.server.port).or_else(|| well_known(key.proto, key.client.port))
}

/// Label of a flow, with the transport fallback.
pub fn classify_flow(key: &FlowKey) -> AppProto {
    flow_app_proto(key).unwrap_or_else(|| transport_fallback(key.proto))
}

/// Label of two ports of a packet outside any flow: the known one, the lower when both are.
pub fn classify_ports(ip_proto: u8, a: u16, b: u16) -> AppProto {
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    well_known(ip_proto, lo)
        .or_else(|| well_known(ip_proto, hi))
        .unwrap_or_else(|| transport_fallback(ip_proto))
}

/// Label of a packet: its flow when it has one, otherwise its ports, otherwise its transport.
pub fn classify_packet(ctx: &PacketCtx, pkt: &Decoded<'_>) -> AppProto {
    if let Some(flow) = &ctx.flow {
        return classify_flow(&flow.key);
    }
    let Some(ip) = pkt.ip() else {
        return AppProto::NonIp;
    };
    match pkt.ports() {
        Some((src, dst)) => classify_ports(ip.protocol, src, dst),
        None => transport_fallback(ip.protocol),
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use netsift_flow::{Endpoint, FlowKey};

    use super::*;

    fn key(proto: u8, client_port: u16, server_port: u16) -> FlowKey {
        FlowKey {
            proto,
            client: Endpoint {
                ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                port: client_port,
            },
            server: Endpoint {
                ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                port: server_port,
            },
        }
    }

    #[test]
    fn labels_are_stable_and_unique() {
        let labels: Vec<_> = AppProto::ALL.iter().map(|p| p.as_str()).collect();
        let mut sorted = labels.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), labels.len());
        for p in AppProto::ALL {
            assert_eq!(AppProto::from_label(p.as_str()), Some(p));
            assert!(
                p.as_str()
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
                "{p}"
            );
        }
        // Labels with a fixed color in ui/src/charts/palette.ts.
        for label in ["http", "tls", "dns", "smb", "netbios", "udp", "tcp", "icmp"] {
            assert!(AppProto::from_label(label).is_some(), "{label}");
        }
        // Reserved by the UI for the "Others" bucket of top-N charts.
        assert_eq!(AppProto::from_label("other"), None);
    }

    #[test]
    fn well_known_ports() {
        use ip_proto::{TCP, UDP};
        let cases = [
            (UDP, 53, Some(AppProto::Dns)),
            (TCP, 53, Some(AppProto::Dns)),
            (UDP, 5353, Some(AppProto::Dns)),
            (TCP, 80, Some(AppProto::Http)),
            (TCP, 8080, Some(AppProto::Http)),
            (UDP, 80, None),
            (TCP, 443, Some(AppProto::Tls)),
            (TCP, 8443, Some(AppProto::Tls)),
            (UDP, 443, None),
            (TCP, 445, Some(AppProto::Smb)),
            (TCP, 139, Some(AppProto::Smb)),
            (UDP, 137, Some(AppProto::Netbios)),
            (UDP, 138, Some(AppProto::Netbios)),
            (UDP, 161, Some(AppProto::Snmp)),
            (UDP, 162, Some(AppProto::Snmp)),
            (TCP, 21, Some(AppProto::Ftp)),
            (TCP, 389, Some(AppProto::Ldap)),
            (UDP, 88, Some(AppProto::Kerberos)),
            (UDP, 123, Some(AppProto::Ntp)),
            (UDP, 67, Some(AppProto::Dhcp)),
            (UDP, 68, Some(AppProto::Dhcp)),
            (UDP, 1900, Some(AppProto::Ssdp)),
            (UDP, 5060, Some(AppProto::Sip)),
            (TCP, 5060, Some(AppProto::Sip)),
            (TCP, 40_000, None),
            (1, 53, None),
        ];
        for (proto, port, expected) in cases {
            assert_eq!(well_known(proto, port), expected, "{proto}/{port}");
        }
    }

    #[test]
    fn flows_prefer_the_server_port() {
        assert_eq!(classify_flow(&key(6, 51_000, 443)), AppProto::Tls);
        // Client on a known port talking to a known server port: the server wins.
        assert_eq!(classify_flow(&key(6, 80, 445)), AppProto::Smb);
        assert_eq!(classify_flow(&key(17, 53, 40_000)), AppProto::Dns);
        assert_eq!(classify_flow(&key(6, 50_000, 50_001)), AppProto::Tcp);
        assert_eq!(flow_app_proto(&key(6, 50_000, 50_001)), None);
        assert_eq!(classify_flow(&key(17, 50_000, 50_001)), AppProto::Udp);
        assert_eq!(classify_flow(&key(1, 0, 0)), AppProto::Icmp);
        assert_eq!(classify_flow(&key(58, 0, 0)), AppProto::Icmp);
        assert_eq!(classify_flow(&key(47, 0, 0)), AppProto::Ip);
    }

    #[test]
    fn packet_ports_are_symmetric() {
        assert_eq!(classify_ports(17, 40_000, 53), AppProto::Dns);
        assert_eq!(classify_ports(17, 53, 40_000), AppProto::Dns);
        assert_eq!(classify_ports(6, 80, 445), classify_ports(6, 445, 80));
        assert_eq!(classify_ports(6, 80, 445), AppProto::Http);
        assert_eq!(classify_ports(6, 40_000, 40_001), AppProto::Tcp);
    }
}
