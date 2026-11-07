//! Synthetic pcap generator and chunk splitter (development only).
//!
//! - [`scenario`]: deterministic scenario builder (Ethernet, IPv4/IPv6, UDP, TCP with
//!   coherent sequence numbers) with DNS, HTTP (PNG body), TLS (self-signed certificate),
//!   NBNS, SMB browser, SNMP and FTP exchanges; [`scenarios`]: ready-made hosts and scenarios.
//! - [`writer`]: pcap (us/ns, both byte orders), pcapng (multiple IDBs, `if_tsresol`), gzip.
//! - [`split`]: chunk splitter by size, duration, packet count or explicit boundaries, with
//!   the dumpcap, dumpcap `nametimenum`, editcap and tcpdump `-C` naming conventions.
//! - [`craft`]: hand-crafted frames for the flow layer (TCP segments with any sequence
//!   number or flag, UDP, ICMP echo, IPv4 / IPv6 fragments with overlaps and duplicates).
//! - [`anomaly`]: helpers to damage or arrange chunk sets (missing, duplicated, truncated,
//!   empty, mixed formats, several prefixes, overlapping interfaces, cross-chunk exchanges).
//!
//! Nothing here is random unless seeded: identical calls produce identical bytes.
//!
//! ```
//! use netsift_fixtures::scenario::{DnsExchange, Scenario};
//! use netsift_fixtures::scenarios::hosts;
//! use netsift_fixtures::writer::{Encoding, encode};
//!
//! let mut sc = Scenario::new();
//! sc.dns(hosts::workstation(), hosts::router(), &DnsExchange::a("example.test", [192, 0, 2, 1]));
//! let file = encode(sc.packets(), &Encoding::pcap()).unwrap();
//! assert_eq!(file.len(), 24 + sc.packets().iter().map(|p| 16 + p.data.len()).sum::<usize>());
//! ```

pub mod anomaly;
pub mod craft;
pub mod packet;
pub mod proto;
pub mod rng;
pub mod scenario;
pub mod scenarios;
pub mod split;
pub mod time;
pub mod writer;

pub use packet::{Host, LINKTYPE_ETHERNET, LINKTYPE_RAW, Packet};
pub use scenario::Scenario;
pub use split::{Chunk, ChunkSink, Naming, SplitBy, SplitOptions, split, split_to_dir};
pub use writer::{Encoding, FileFormat, Interface, TsResolution, encode, write_file};

/// Crate name, used by smoke tests and diagnostics.
pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");
