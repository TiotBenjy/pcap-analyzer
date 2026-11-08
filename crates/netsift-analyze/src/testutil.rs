//! Test harness: feeds synthetic packets through a flow table into one analyzer.

use netsift_dissect::Decoded;
use netsift_fixtures::Packet;
use netsift_flow::{Direction, FlowConfig, FlowCtx, FlowSink, FlowTable, PacketCtx, StreamCtx};

use crate::analyzer::Analyzer;
use crate::record::Record;

struct Sink<'a> {
    analyzer: &'a mut dyn Analyzer,
    out: Vec<Record>,
}

impl FlowSink for Sink<'_> {
    fn on_packet(&mut self, ctx: &PacketCtx, pkt: &Decoded<'_>) {
        self.analyzer.on_packet(ctx, pkt, &mut self.out);
    }
    fn on_stream(&mut self, ctx: &StreamCtx, dir: Direction, data: &[u8]) {
        self.analyzer.on_stream(ctx, dir, data, &mut self.out);
    }
    fn on_flow_end(&mut self, ctx: &FlowCtx) {
        self.analyzer.on_flow_end(ctx, &mut self.out);
    }
}

/// Runs `packets` (in time order) through a default flow table into `analyzer`, then ends every
/// flow and the analyzer; returns the emitted records.
pub(crate) fn run(analyzer: &mut dyn Analyzer, packets: &[Packet]) -> Vec<Record> {
    let mut table = FlowTable::new(FlowConfig::default());
    let mut sink = Sink {
        analyzer,
        out: Vec::new(),
    };
    for (frame, p) in packets.iter().enumerate() {
        let wire_len = u32::try_from(p.data.len()).unwrap();
        table.process(
            p.ts_ns,
            0,
            frame as u64,
            p.linktype,
            wire_len,
            &p.data,
            &mut sink,
        );
    }
    table.finish(&mut sink);
    sink.analyzer.finish(&mut sink.out);
    sink.out
}
