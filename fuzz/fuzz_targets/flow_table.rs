//! Flow layer (`netsift_flow`): IP defragmentation, flow tracking and expiry, TCP reassembly.
//! A linktype selector byte, then frames ([`netsift_fuzz::frames`]) with time steps (forward,
//! small backward jumps, jumps beyond the flow timeouts), with small table bounds so that LRU
//! eviction and buffer limits are reached. Checks the bounds and the final flush.
#![no_main]

use libfuzzer_sys::fuzz_target;
use netsift_analyze::dissect::{Decoded, linktype};
use netsift_analyze::flow::{
    Direction, FlowConfig, FlowCtx, FlowSink, FlowTable, PacketCtx, StreamCtx,
};
use netsift_fuzz::{BASE_TS_NS, frames, step_ns};

/// Counts what the table reports (the `Debug` of each context is formatted too).
#[derive(Default)]
struct Count {
    packets: u64,
    stream_bytes: u64,
    ended: u64,
}

impl FlowSink for Count {
    fn on_packet(&mut self, ctx: &PacketCtx, pkt: &Decoded<'_>) {
        let _ = (pkt.ports(), format!("{ctx:?}"));
        self.packets += 1;
    }

    fn on_stream(&mut self, ctx: &StreamCtx, _dir: Direction, data: &[u8]) {
        let _ = format!("{ctx:?}");
        self.stream_bytes += data.len() as u64;
    }

    fn on_flow_end(&mut self, ctx: &FlowCtx) {
        let _ = format!("{ctx:?}");
        self.ended += 1;
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&sel, rest)) = data.split_first() else {
        return;
    };
    let lt = linktype::SUPPORTED[usize::from(sel) % linktype::SUPPORTED.len()];
    // Small bounds so that eviction, buffer limits and defragmentation limits are reached.
    let config = FlowConfig {
        max_flows: 8,
        max_stream_buffer: 4096,
        max_buffered_bytes: 16_384,
        max_defrag_bytes: 8192,
        ..FlowConfig::default()
    };
    let mut table = FlowTable::new(config);
    let mut sink = Count::default();
    let mut ts = BASE_TS_NS;
    for (frame, f) in (0u64..).zip(frames(rest)) {
        ts = ts.saturating_add(step_ns(f.step));
        let len = u32::try_from(f.data.len()).unwrap_or(u32::MAX);
        table.process(ts, 0, frame, lt, len, f.data, &mut sink);
        assert!(table.active_flows() <= config.max_flows);
    }
    table.finish(&mut sink);
    let _ = (sink.packets, sink.stream_bytes, sink.ended);
    assert_eq!(table.active_flows(), 0);
});
