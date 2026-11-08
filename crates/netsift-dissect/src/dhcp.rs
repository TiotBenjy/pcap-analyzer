//! DHCP / BOOTP message parser (RFC 951, RFC 2131; options of RFC 2132).
//!
//! Only the fixed header and the options the Servers view uses are decoded: message type (53),
//! server identifier (54), requested address (50), subnet mask (1), routers (3), DNS servers (6),
//! lease time (51) and host name (12). Captures are hostile input, so the parser is bounded:
//! - the options are walked once, each one consuming at least one byte, and the walk stops at
//!   the end option, at the end of the buffer, or after [`MAX_OPTIONS`] options;
//! - at most [`MAX_ADDRESSES`] addresses are kept per list option;
//! - the host name is cut at [`MAX_HOSTNAME_LEN`] bytes and keeps printable ASCII only;
//! - the first occurrence of an option wins (long options split per RFC 3396 and the option
//!   overload of the `sname` / `file` fields are not decoded).
//!
//! A message whose fixed header is complete is always returned; [`Message::malformed`] tells
//! that the options were cut or missing their magic cookie.

use std::net::Ipv4Addr;

use crate::bytes::{array, be32, u8_at};

/// Fixed BOOTP header length (before the magic cookie).
pub const FIXED_LEN: usize = 236;
/// Magic cookie that starts the options (RFC 2131 3).
pub const MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];
/// Options walked per message.
pub const MAX_OPTIONS: usize = 255;
/// Addresses kept per list option (routers, DNS servers).
pub const MAX_ADDRESSES: usize = 8;
/// Longest host name kept, in bytes.
pub const MAX_HOSTNAME_LEN: usize = 64;

/// BOOTP operation code.
pub const BOOTREQUEST: u8 = 1;
pub const BOOTREPLY: u8 = 2;

/// DHCP message type (option 53).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageType {
    Discover,
    Offer,
    Request,
    Decline,
    Ack,
    Nak,
    Release,
    Inform,
    /// Any other value (lease queries, RFC 3203 FORCERENEW...).
    Other(u8),
}

impl MessageType {
    pub fn from_code(code: u8) -> Self {
        match code {
            1 => Self::Discover,
            2 => Self::Offer,
            3 => Self::Request,
            4 => Self::Decline,
            5 => Self::Ack,
            6 => Self::Nak,
            7 => Self::Release,
            8 => Self::Inform,
            other => Self::Other(other),
        }
    }

    /// Stable lower-case label (`other` for unknown values).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Discover => "discover",
            Self::Offer => "offer",
            Self::Request => "request",
            Self::Decline => "decline",
            Self::Ack => "ack",
            Self::Nak => "nak",
            Self::Release => "release",
            Self::Inform => "inform",
            Self::Other(_) => "other",
        }
    }
}

/// A decoded DHCP or plain BOOTP message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// [`BOOTREQUEST`] or [`BOOTREPLY`].
    pub op: u8,
    pub htype: u8,
    pub hlen: u8,
    pub xid: u32,
    pub ciaddr: Ipv4Addr,
    pub yiaddr: Ipv4Addr,
    pub siaddr: Ipv4Addr,
    pub giaddr: Ipv4Addr,
    /// Raw client hardware address field.
    pub chaddr: [u8; 16],
    /// `None` for plain BOOTP (no option 53).
    pub message_type: Option<MessageType>,
    pub server_id: Option<Ipv4Addr>,
    pub requested_ip: Option<Ipv4Addr>,
    pub subnet_mask: Option<Ipv4Addr>,
    pub routers: Vec<Ipv4Addr>,
    pub dns_servers: Vec<Ipv4Addr>,
    /// Lease time in seconds (`0xffffffff`: infinite).
    pub lease_time: Option<u32>,
    pub hostname: Option<String>,
    /// The options are truncated, cut by the option limit, or lack the magic cookie.
    pub malformed: bool,
}

impl Message {
    /// Ethernet client address, when the hardware type is Ethernet (1) with a 6-byte address.
    pub fn client_mac(&self) -> Option<[u8; 6]> {
        if self.htype == 1 && self.hlen == 6 {
            array(&self.chaddr, 0)
        } else {
            None
        }
    }
}

fn ipv4(data: &[u8], off: usize) -> Option<Ipv4Addr> {
    array::<4>(data, off).map(Ipv4Addr::from)
}

/// Parses one UDP payload. `None` when it is shorter than the fixed header or its operation
/// code is neither request nor reply.
pub fn parse(data: &[u8]) -> Option<Message> {
    let op = u8_at(data, 0)?;
    if (op != BOOTREQUEST && op != BOOTREPLY) || data.len() < FIXED_LEN {
        return None;
    }
    let mut msg = Message {
        op,
        htype: u8_at(data, 1)?,
        hlen: u8_at(data, 2)?,
        xid: be32(data, 4)?,
        ciaddr: ipv4(data, 12)?,
        yiaddr: ipv4(data, 16)?,
        siaddr: ipv4(data, 20)?,
        giaddr: ipv4(data, 24)?,
        chaddr: array(data, 28)?,
        message_type: None,
        server_id: None,
        requested_ip: None,
        subnet_mask: None,
        routers: Vec::new(),
        dns_servers: Vec::new(),
        lease_time: None,
        hostname: None,
        malformed: false,
    };
    match array::<4>(data, FIXED_LEN) {
        Some(MAGIC_COOKIE) => {}
        // Plain BOOTP without vendor extensions.
        None if data.len() == FIXED_LEN => return Some(msg),
        _ => {
            msg.malformed = true;
            return Some(msg);
        }
    }
    let options = data.get(FIXED_LEN.saturating_add(4)..).unwrap_or_default();
    parse_options(options, &mut msg);
    Some(msg)
}

fn parse_options(mut rest: &[u8], msg: &mut Message) {
    for _ in 0..MAX_OPTIONS {
        let Some((&code, tail)) = rest.split_first() else {
            // Ran out of bytes without an end option: tolerated (padding may be stripped).
            return;
        };
        match code {
            0 => {
                rest = tail;
                continue;
            }
            255 => return,
            _ => {}
        }
        let Some((&len, tail)) = tail.split_first() else {
            msg.malformed = true;
            return;
        };
        let Some((value, tail)) = tail.split_at_checked(usize::from(len)) else {
            msg.malformed = true;
            return;
        };
        apply_option(code, value, msg);
        rest = tail;
    }
    // Option limit reached before the end option.
    if !rest.is_empty() && rest.first() != Some(&255) {
        msg.malformed = true;
    }
}

fn single_ip(value: &[u8]) -> Option<Ipv4Addr> {
    (value.len() == 4).then(|| ipv4(value, 0)).flatten()
}

fn ip_list(value: &[u8]) -> Vec<Ipv4Addr> {
    value
        .as_chunks::<4>()
        .0
        .iter()
        .take(MAX_ADDRESSES)
        .map(|c| Ipv4Addr::from(*c))
        .collect()
}

fn apply_option(code: u8, value: &[u8], msg: &mut Message) {
    match code {
        53 if msg.message_type.is_none() => {
            if let [t] = value {
                msg.message_type = Some(MessageType::from_code(*t));
            }
        }
        54 if msg.server_id.is_none() => msg.server_id = single_ip(value),
        50 if msg.requested_ip.is_none() => msg.requested_ip = single_ip(value),
        1 if msg.subnet_mask.is_none() => msg.subnet_mask = single_ip(value),
        3 if msg.routers.is_empty() => msg.routers = ip_list(value),
        6 if msg.dns_servers.is_empty() => msg.dns_servers = ip_list(value),
        51 if msg.lease_time.is_none() => {
            msg.lease_time = (value.len() == 4).then(|| be32(value, 0)).flatten();
        }
        12 if msg.hostname.is_none() => msg.hostname = hostname(value),
        _ => {}
    }
}

/// Printable ASCII of a host name option, cut at [`MAX_HOSTNAME_LEN`]; trailing NULs (sent by
/// some clients) are dropped. `None` when nothing printable is left.
fn hostname(value: &[u8]) -> Option<String> {
    let name: String = value
        .iter()
        .take(MAX_HOSTNAME_LEN)
        .take_while(|b| **b != 0)
        .filter(|b| b.is_ascii_graphic())
        .map(|b| char::from(*b))
        .collect();
    (!name.is_empty()).then_some(name)
}
