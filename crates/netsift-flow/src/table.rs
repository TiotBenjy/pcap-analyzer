//! Flow table: IP defragmentation, flow tracking, TCP reassembly, packet-time expiry.
//!
//! **Placeholder until task P1.6**: decodes each frame and reports it through
//! [`FlowSink::on_packet`] without any flow (`flow: None`), so that the engine (P1.7) can be built
//! and tested against the frozen API. P1.6 replaces the body of this module, not its signatures.

use netsift_dissect::decode;

use crate::api::{FlowConfig, FlowSink, PacketCtx};

/// One flow table per shard. Not `Sync`: owned by a single worker thread.
#[derive(Debug)]
pub struct FlowTable {
    config: FlowConfig,
}

impl FlowTable {
    pub fn new(config: FlowConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &FlowConfig {
        &self.config
    }

    /// Processes one captured frame. `wire_len` is the original length on the wire.
    /// Frames must be passed in non-decreasing time order per shard (the engine guarantees it;
    /// small backward steps must be tolerated, never panic).
    pub fn process(
        &mut self,
        ts_ns: i64,
        chunk_id: u32,
        linktype: u32,
        wire_len: u32,
        data: &[u8],
        sink: &mut dyn FlowSink,
    ) {
        let pkt = decode(linktype, data);
        let ctx = PacketCtx {
            ts_ns,
            chunk_id,
            wire_len,
            flow: None,
        };
        sink.on_packet(&ctx, &pkt);
    }

    /// Flushes every remaining flow with `EndReason::EndOfCapture`, then pending fragments.
    pub fn finish(&mut self, sink: &mut dyn FlowSink) {
        let _ = sink;
    }

    /// Number of flows currently tracked (for progress and memory reporting).
    pub fn active_flows(&self) -> usize {
        0
    }
}
