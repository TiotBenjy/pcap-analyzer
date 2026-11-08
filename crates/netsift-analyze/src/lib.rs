//! Analyzer trait, per-protocol analyzers and traffic classification.
//!
//! - [`Analyzer`]: the frozen trait every protocol analyzer implements (one instance per flow
//!   shard, no shared mutable state), fed by the engine with the events of the flow layer;
//! - [`Record`]: what analyzers emit through a [`RecordSink`]; the engine translates records
//!   into store rows (registration point: one variant per analyzer);
//! - [`Registry`]: the list of built-in analyzers, instantiated once per shard
//!   (registration point: one line per analyzer);
//! - [`classify`]: application protocol labels ([`AppProto`]) from flows and well-known ports;
//! - [`core`]: the built-in `core` analyzer (traffic time series, hosts, flows).
//!
//! [`geo`] (address categories, countries) is re-exported for the engine, which loads the
//! country database shared by every shard ([`AnalyzerConfig::geo`]).
//!
//! The flow layer and the decoder are re-exported ([`flow`], [`dissect`]) so that the engine
//! and analyzers use exactly the types of the trait signatures.

// Captures are hostile input: no panic paths in library code (tests exempted by clippy.toml).
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

pub mod analyzer;
pub mod classify;
pub mod core;
pub mod record;
pub mod registry;

pub use analyzer::{Analyzer, AnalyzerId, BlobRef, RecordSink};
pub use classify::AppProto;
pub use netsift_dissect as dissect;
pub use netsift_flow as flow;
pub use netsift_geo as geo;
pub use record::{FlowSummary, HostSeen, Record, TrafficSample};
pub use registry::{AnalyzerConfig, CoreConfig, Factory, Registry, factory};

/// Crate name, used by smoke tests and diagnostics.
pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");

#[cfg(test)]
mod tests {
    #[test]
    fn smoke() {
        assert_eq!(super::CRATE_NAME, "netsift-analyze");
    }
}
