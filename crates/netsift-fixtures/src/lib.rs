//! Synthetic pcap generator and chunk splitter (development only).
//!
//! - [`scenario`]: deterministic scenario builder (Ethernet, IPv4/IPv6, UDP, TCP with
//!   coherent sequence numbers) with DNS, HTTP (PNG body), TLS (self-signed certificate),
//!   NBNS, SMB browser, SNMP and FTP exchanges; [`scenarios`]: ready-made hosts and scenarios.
//!
//! Nothing here is random unless seeded: identical calls produce identical bytes.

pub mod packet;
pub mod proto;
pub mod rng;
pub mod scenario;
pub mod scenarios;
pub mod time;

pub use packet::{Host, LINKTYPE_ETHERNET, LINKTYPE_RAW, Packet};
pub use scenario::Scenario;

/// Crate name, used by smoke tests and diagnostics.
pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");
