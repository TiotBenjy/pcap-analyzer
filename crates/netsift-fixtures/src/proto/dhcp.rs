//! DHCP / BOOTP message encoder (RFC 2131, options of RFC 2132).

use std::net::Ipv4Addr;

/// BOOTP operation codes.
pub const BOOTREQUEST: u8 = 1;
pub const BOOTREPLY: u8 = 2;

/// Magic cookie that starts the options field (RFC 2131 3).
pub const MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];

/// DHCP message types (option 53).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DhcpType {
    Discover,
    Offer,
    Request,
    Decline,
    Ack,
    Nak,
    Release,
    Inform,
}

impl DhcpType {
    pub fn code(self) -> u8 {
        match self {
            Self::Discover => 1,
            Self::Offer => 2,
            Self::Request => 3,
            Self::Decline => 4,
            Self::Ack => 5,
            Self::Nak => 6,
            Self::Release => 7,
            Self::Inform => 8,
        }
    }

    /// BOOTP operation carrying this type.
    pub fn op(self) -> u8 {
        match self {
            Self::Offer | Self::Ack | Self::Nak => BOOTREPLY,
            _ => BOOTREQUEST,
        }
    }
}

/// One DHCP message. `None` / empty fields are not encoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhcpMessage {
    pub kind: DhcpType,
    pub xid: u32,
    pub chaddr: [u8; 6],
    pub ciaddr: Ipv4Addr,
    pub yiaddr: Ipv4Addr,
    pub siaddr: Ipv4Addr,
    pub giaddr: Ipv4Addr,
    /// Option 54.
    pub server_id: Option<Ipv4Addr>,
    /// Option 50.
    pub requested_ip: Option<Ipv4Addr>,
    /// Option 1.
    pub subnet_mask: Option<Ipv4Addr>,
    /// Option 3.
    pub routers: Vec<Ipv4Addr>,
    /// Option 6.
    pub dns_servers: Vec<Ipv4Addr>,
    /// Option 51, seconds.
    pub lease_time: Option<u32>,
    /// Option 12.
    pub hostname: Option<String>,
}

impl DhcpMessage {
    /// Message of type `kind` from the client `chaddr`, every address unset.
    pub fn new(kind: DhcpType, xid: u32, chaddr: [u8; 6]) -> Self {
        Self {
            kind,
            xid,
            chaddr,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: Ipv4Addr::UNSPECIFIED,
            giaddr: Ipv4Addr::UNSPECIFIED,
            server_id: None,
            requested_ip: None,
            subnet_mask: None,
            routers: Vec::new(),
            dns_servers: Vec::new(),
            lease_time: None,
            hostname: None,
        }
    }

    /// Wire bytes: 236-byte BOOTP header, magic cookie, options, end option.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(300);
        out.push(self.kind.op());
        out.push(1); // htype: Ethernet
        out.push(6); // hlen
        out.push(0); // hops
        out.extend_from_slice(&self.xid.to_be_bytes());
        out.extend_from_slice(&[0, 0]); // secs
        out.extend_from_slice(&0x8000_u16.to_be_bytes()); // flags: broadcast
        for addr in [self.ciaddr, self.yiaddr, self.siaddr, self.giaddr] {
            out.extend_from_slice(&addr.octets());
        }
        out.extend_from_slice(&self.chaddr);
        out.extend_from_slice(&[0; 10]); // chaddr padding
        out.extend_from_slice(&[0; 64]); // sname
        out.extend_from_slice(&[0; 128]); // file
        out.extend_from_slice(&MAGIC_COOKIE);
        option(&mut out, 53, &[self.kind.code()]);
        if let Some(ip) = self.server_id {
            option(&mut out, 54, &ip.octets());
        }
        if let Some(ip) = self.requested_ip {
            option(&mut out, 50, &ip.octets());
        }
        if let Some(ip) = self.subnet_mask {
            option(&mut out, 1, &ip.octets());
        }
        if !self.routers.is_empty() {
            option(&mut out, 3, &addresses(&self.routers));
        }
        if !self.dns_servers.is_empty() {
            option(&mut out, 6, &addresses(&self.dns_servers));
        }
        if let Some(lease) = self.lease_time {
            option(&mut out, 51, &lease.to_be_bytes());
        }
        if let Some(name) = &self.hostname {
            option(&mut out, 12, name.as_bytes());
        }
        out.push(255);
        out
    }
}

fn addresses(list: &[Ipv4Addr]) -> Vec<u8> {
    list.iter().flat_map(Ipv4Addr::octets).collect()
}

fn option(out: &mut Vec<u8>, code: u8, value: &[u8]) {
    out.push(code);
    out.push(u8::try_from(value.len()).expect("DHCP option value fits in 255 bytes"));
    out.extend_from_slice(value);
}
