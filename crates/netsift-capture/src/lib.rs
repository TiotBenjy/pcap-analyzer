//! Reading pcap/pcapng/gz files, detecting and ordering chunk sets.
//!
//! Module ownership (parallel tasks, see docs/ROADMAP.md):
//! - [`source`]: shared, frozen interface (`PacketSource`, `RawPacket`, ...);
//! - [`reader`]: single-file readers and format detection (task P1.1);
//! - [`chunkset`]: folder inventory, grouping, ordering, continuity checks, k-way merge (task P1.2).
//!
//! Captures are hostile input: no panic paths in library code (tests exempted by clippy.toml).

#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

pub mod chunkset;
pub mod reader;
pub mod source;

pub use source::{CaptureError, CaptureFormat, CaptureInfo, PacketSource, RawPacket, ReadWarning};

/// Crate name, used by smoke tests and diagnostics.
pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");

#[cfg(test)]
mod tests {
    #[test]
    fn smoke() {
        assert_eq!(super::CRATE_NAME, "netsift-capture");
    }
}
