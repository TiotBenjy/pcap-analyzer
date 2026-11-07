//! IP defragmentation, flow table and bounded TCP reassembly.
//!
//! Module ownership (parallel tasks, see docs/ROADMAP.md):
//! - [`api`]: shared, frozen interface with the engine (`FlowSink`, `FlowKey`, `FlowCtx`, ...);
//! - [`table`]: the flow table (policies documented there), built on private modules:
//!   `defrag` (bounded IPv4 / IPv6 defragmentation), `tcp` (one-direction TCP reassembly)
//!   and `ranges` (byte-range helpers).

// Captures are hostile input: no panics, no unchecked arithmetic (tests exempted through
// clippy.toml, and explicitly for arithmetic).
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

pub mod api;
mod defrag;
mod ranges;
pub mod table;
mod tcp;

pub use api::{
    DirStats, Direction, EndReason, Endpoint, FlowConfig, FlowCtx, FlowId, FlowKey, FlowSink,
    PacketCtx, PacketFlow, StreamCtx, TcpState, shard_hash,
};
pub use table::FlowTable;

/// Crate name, used by smoke tests and diagnostics.
pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");

#[cfg(test)]
mod tests {
    #[test]
    fn smoke() {
        assert_eq!(super::CRATE_NAME, "netsift-flow");
    }
}
