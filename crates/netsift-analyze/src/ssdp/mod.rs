//! The `ssdp` analyzer and its parser.
//!
//! - [`parser`]: SSDP / HTTPU message parser (`NOTIFY`, `M-SEARCH`, responses), bounded and
//!   tolerant;
//! - [`analyzer`]: the [`Analyzer`](crate::Analyzer) implementation, one record per datagram on
//!   UDP port 1900 (`ssdp_messages`, folded into `ssdp_devices` by the store).

mod analyzer;
pub mod parser;

pub use analyzer::{SsdpAnalyzer, SsdpRecord};
pub use parser::{SsdpKind, SsdpMessage};

#[cfg(test)]
mod tests;
