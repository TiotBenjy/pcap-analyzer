//! NTP header parser (RFC 5905; versions 1 to 4). Only the fixed 48-byte header is read:
//! extension fields and authenticators are ignored.

use std::fmt::Write as _;
use std::net::Ipv4Addr;

use crate::bytes::{array, u8_at};

/// Fixed NTP header length.
pub const HEADER_LEN: usize = 48;

/// Association modes.
pub mod mode {
    pub const SYMMETRIC_ACTIVE: u8 = 1;
    pub const SYMMETRIC_PASSIVE: u8 = 2;
    pub const CLIENT: u8 = 3;
    pub const SERVER: u8 = 4;
    pub const BROADCAST: u8 = 5;
    pub const CONTROL: u8 = 6;
}

/// A decoded NTP header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Leap indicator (0..=3).
    pub leap: u8,
    /// Version number (1..=4).
    pub version: u8,
    /// Association mode, see [`mode`].
    pub mode: u8,
    /// 0: unspecified / kiss-o'-death, 1: primary server, 2..=15: secondary, 16: unsynchronized.
    pub stratum: u8,
    pub poll: i8,
    pub precision: i8,
    /// Raw reference identifier.
    pub reference_id: [u8; 4],
}

impl Header {
    /// Readable reference identifier:
    /// - stratum 0 and 1: the ASCII code (kiss code, or source such as `GPS`, `PPS`), printable
    ///   characters only;
    /// - stratum 2 and more: the IPv4 address of the upstream server (`ipv6_server`: an IPv6
    ///   server puts the first bytes of an MD5 hash there, shown in hexadecimal).
    ///
    /// Empty when the field is all zero.
    pub fn reference(&self, ipv6_server: bool) -> String {
        if self.reference_id == [0; 4] {
            return String::new();
        }
        if self.stratum <= 1 {
            return self
                .reference_id
                .iter()
                .take_while(|b| **b != 0)
                .filter(|b| b.is_ascii_graphic())
                .map(|b| char::from(*b))
                .collect();
        }
        if ipv6_server {
            return self
                .reference_id
                .iter()
                .fold(String::with_capacity(8), |mut s, b| {
                    let _ = write!(s, "{b:02x}");
                    s
                });
        }
        Ipv4Addr::from(self.reference_id).to_string()
    }
}

/// Parses one UDP payload. `None` when shorter than [`HEADER_LEN`] or the version is not 1..=4
/// (random traffic on port 123).
pub fn parse(data: &[u8]) -> Option<Header> {
    if data.len() < HEADER_LEN {
        return None;
    }
    let first = u8_at(data, 0)?;
    let version = (first >> 3) & 0x07;
    if !(1..=4).contains(&version) {
        return None;
    }
    Some(Header {
        leap: first >> 6,
        version,
        mode: first & 0x07,
        stratum: u8_at(data, 1)?,
        poll: i8::from_be_bytes([u8_at(data, 2)?]),
        precision: i8::from_be_bytes([u8_at(data, 3)?]),
        reference_id: array(data, 12)?,
    })
}
