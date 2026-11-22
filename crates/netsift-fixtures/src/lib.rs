//! Synthetic pcap generator and chunk splitter (development only).
//!
//! - [`scenario`]: deterministic scenario builder (Ethernet, IPv4/IPv6, UDP, TCP with
//!   coherent sequence numbers) with DNS, HTTP (PNG body), TLS (self-signed certificate),
//!   NBNS, SMB browser, SNMP and FTP exchanges; [`scenarios`]: ready-made hosts and scenarios.
//! - [`credentials`]: SMTP AUTH, POP3, IMAP, LDAP simple bind, HTTP Basic and HTTP NTLM
//!   exchanges (Credentials view).
//! - [`arp`]: ARP requests, replies, probes, gratuitous ARP and cache poisoning (ARP view).
//! - [`ethernet`]: link-layer showcase (vendors, VLAN and Q-in-Q tags, EtherTypes, LLC).
//! - [`ftp`]: FTP control sessions with passive, active and EPSV data connections (FTP view).
//! - [`servers`]: DHCP, NTP, Kerberos, DNS SRV and LDAP exchanges (Servers view).
//! - [`sip`]: SIP calls (complete, rejected, cancelled, over TCP) with RTP, a Digest
//!   registration and a `friendly-scanner` sweep (SIP view).
//! - [`ssdp`]: SSDP announcements, searches, answers and malformed datagrams (SSDP view).
//! - [`telnet`]: Telnet logins, option negotiation, long and split sessions (Telnet view).
//! - [`writer`]: pcap (us/ns, both byte orders), pcapng (multiple IDBs, `if_tsresol`), gzip,
//!   zstd, LZ4 frame.
//! - [`split`]: chunk splitter by size, duration, packet count or explicit boundaries, with
//!   the dumpcap, dumpcap `nametimenum`, editcap and tcpdump `-C` naming conventions.
//! - [`mix`]: large mixed-traffic captures streamed window by window (benchmarks).
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
pub mod arp;
pub mod craft;
pub mod credentials;
pub mod ethernet;
pub mod ftp;
pub mod http_mix;
pub mod images;
pub mod mix;
pub mod packet;
pub mod proto;
pub mod rng;
pub mod scenario;
pub mod scenarios;
pub mod servers;
pub mod sip;
pub mod split;
pub mod spread;
pub mod ssdp;
pub mod telnet;
pub mod time;
pub mod writer;

pub use packet::{Host, LINKTYPE_ETHERNET, LINKTYPE_RAW, Packet};
pub use scenario::Scenario;
pub use split::{Chunk, ChunkSink, Naming, SplitBy, SplitOptions, split, split_to_dir};
pub use writer::{Encoding, FileFormat, Interface, TsResolution, encode, write_file};

/// Crate name, used by smoke tests and diagnostics.
pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");
