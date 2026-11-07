//! Pure, I/O-free, fuzzable protocol parsers (L2 to L7).
//!
//! The entry point is [`decode`]: it takes the capture linktype and the raw frame
//! bytes and returns a [`Decoded`] describing the link, network and transport layers,
//! plus the remaining payload borrowed from the frame. Decoding is best effort: a frame
//! that is only partially decodable keeps the layers obtained and reports the failing
//! layer in [`Decoded::error`].
//!
//! Supported linktypes: see [`linktype::SUPPORTED`].
//!
//! ```
//! use netsift_dissect::{decode, linktype};
//!
//! let frame = [0u8; 10]; // too short for Ethernet
//! let d = decode(linktype::ETHERNET, &frame);
//! assert!(d.network.is_none());
//! assert!(d.error.is_some());
//! assert_eq!(d.payload.len(), 10);
//! ```
#![forbid(unsafe_code)]
// Captures are hostile input: parsers must never panic (see CLAUDE.md).
// Tests are exempted through clippy.toml (allow-*-in-tests).
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unreachable,
    clippy::arithmetic_side_effects
)]

mod bytes;
mod decoded;
mod error;
pub mod ethertype;
mod ipext;
mod link;
pub mod linktype;
mod net;
mod transport;
mod wifi;

pub use decoded::{
    ArpInfo, Decoded, Fragment, IcmpInfo, IpExtensions, IpInfo, IpVersion, LinkInfo, LinkKind, Llc,
    MAX_IPV6_EXTENSIONS, MAX_VLAN_TAGS, MacAddr, Network, RadiotapInfo, SllInfo, TcpFlags, TcpInfo,
    TcpOptions, Transport, UdpInfo, VlanTag, Vlans, WifiFrameType, WifiInfo,
};
pub use error::{DecodeError, ErrorKind, Layer};
pub use transport::{decode_transport, proto};

/// Crate name, used by smoke tests and diagnostics.
pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");

/// Decodes one captured frame of the given `LINKTYPE_*` from link to transport layer.
///
/// Never fails as a whole and never panics: unsupported linktypes and malformed or
/// truncated headers are reported in [`Decoded::error`], with every layer decoded
/// before the failure kept. No byte is copied: [`Decoded::payload`] borrows `data`.
pub fn decode(linktype: u32, data: &[u8]) -> Decoded<'_> {
    let mut d = Decoded::new(linktype, data);
    if let Err(e) = link::decode(&mut d, linktype, data) {
        d.error = Some(e);
    }
    d.finish();
    d
}

#[cfg(test)]
mod tests {
    #[test]
    fn smoke() {
        assert_eq!(super::CRATE_NAME, "netsift-dissect");
    }
}
