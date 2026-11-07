//! Ingestion pipeline orchestration: threads, progress, cancellation.
//!
//! [`ingest`] imports a capture file or a folder of chunks into a new session:
//!
//! 1. [`plan_input`]: inventory, grouping into chunk sets, [`GroupSelection`];
//! 2. one reader thread (`ChunkSetSource`: ordering, k-way merge, continuity checks);
//! 3. one decoder thread routing every packet to a flow shard (`shard_hash`);
//! 4. N shard threads, each with its own `FlowTable` and analyzer instances;
//! 5. the single store writer thread (`netsift-store`).
//!
//! Progress is reported through a callback on the calling thread; cancellation through a
//! shared [`CancelToken`].

// Captures are hostile input: no panic paths in library code (tests exempted by clippy.toml).
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

mod error;
mod ingest;
mod options;
mod pipeline;
mod plan;
pub mod translate;

pub use error::EngineError;
pub use ingest::{INTERRUPTED_DETAIL, IngestReport, ingest, recover_interrupted};
pub use options::{CancelToken, IngestOptions, MAX_SHARDS, Phase, Progress, default_shards};
pub use pipeline::ANALYZER_PANICKED;
pub use plan::{GroupSelection, GroupSummary, InputPlan, kind_name, plan_input};

/// Crate name, used by smoke tests and diagnostics.
pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");

#[cfg(test)]
mod tests {
    #[test]
    fn smoke() {
        assert_eq!(super::CRATE_NAME, "netsift-engine");
    }
}
