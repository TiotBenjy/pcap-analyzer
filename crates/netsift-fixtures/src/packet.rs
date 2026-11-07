//! Packet and endpoint types shared by the scenario builder, the writers and the splitter.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// `LINKTYPE_ETHERNET` (IEEE 802.3 / Ethernet II).
pub const LINKTYPE_ETHERNET: u32 = 1;
/// `LINKTYPE_RAW` (raw IPv4/IPv6, no link-layer header).
pub const LINKTYPE_RAW: u32 = 101;

/// One captured frame, as it will be written to a capture file.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Packet {
    /// Capture timestamp, nanoseconds since the Unix epoch, UTC. Must be non-negative.
    pub ts_ns: i64,
    /// Link-layer type of `data` (see `LINKTYPE_*`).
    pub linktype: u32,
    /// Logical capture interface. pcapng writers map it to the interface description block
    /// with the same index; pcap writers ignore it.
    pub interface: u32,
    /// Frame bytes, starting with the link-layer header.
    pub data: Vec<u8>,
}

impl Packet {
    /// Ethernet frame captured on interface 0.
    pub fn ethernet(ts_ns: i64, data: Vec<u8>) -> Self {
        Self {
            ts_ns,
            linktype: LINKTYPE_ETHERNET,
            interface: 0,
            data,
        }
    }
}

/// A network endpoint: MAC address and IP address (both configurable).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Host {
    pub mac: [u8; 6],
    pub ip: IpAddr,
}

impl Host {
    /// Ethernet broadcast MAC address.
    pub const BROADCAST_MAC: [u8; 6] = [0xff; 6];

    pub fn new(mac: [u8; 6], ip: IpAddr) -> Self {
        Self { mac, ip }
    }

    /// IPv4 endpoint.
    pub fn v4(mac: [u8; 6], ip: [u8; 4]) -> Self {
        Self::new(mac, IpAddr::V4(Ipv4Addr::from(ip)))
    }

    /// IPv6 endpoint.
    pub fn v6(mac: [u8; 6], ip: Ipv6Addr) -> Self {
        Self::new(mac, IpAddr::V6(ip))
    }

    /// Broadcast destination: `ff:ff:ff:ff:ff:ff` and the given (subnet) broadcast address.
    pub fn broadcast_v4(ip: [u8; 4]) -> Self {
        Self::v4(Self::BROADCAST_MAC, ip)
    }

    /// The IPv4 address, if this endpoint is IPv4.
    pub fn ipv4(&self) -> Option<Ipv4Addr> {
        match self.ip {
            IpAddr::V4(v4) => Some(v4),
            IpAddr::V6(_) => None,
        }
    }
}
