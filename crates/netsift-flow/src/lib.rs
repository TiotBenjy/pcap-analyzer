//! IP defragmentation, flow table and bounded TCP reassembly.
//!
//! Module ownership (parallel tasks, see docs/ROADMAP.md):
//! - [`api`]: shared, frozen interface with the engine (`FlowSink`, `FlowKey`, `FlowCtx`, ...);
//! - [`table`]: the flow table, placeholder until task P1.6 (which may add private modules).

// Captures are hostile input: no panics (tests exempted through clippy.toml).
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

pub mod api;
pub mod table;

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
