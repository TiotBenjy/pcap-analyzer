//! Every built-in analyzer, behind a flow table, as one engine shard runs them: the input is a
//! conversation ([`netsift_fuzz::conversation`]: protocol, ports, TCP handshake and close, then
//! segments) turned into raw IPv4 frames with coherent TCP sequence numbers. The records are
//! then translated into store rows, as the engine does.
#![no_main]

use libfuzzer_sys::fuzz_target;
use netsift_engine::translate;
use netsift_fuzz::{Sink, builtin_analyzers, conversation, drive_flow, segments};

fuzz_target!(|data: &[u8]| {
    let Some((conv, rest)) = conversation(data) else {
        return;
    };
    let mut analyzers = builtin_analyzers();
    let mut sink = Sink::default();
    drive_flow(&mut analyzers, &conv, &segments(rest), &mut sink);
    for record in sink.records {
        if let Some(row) = translate::to_store(record) {
            let _ = translate::approx_size(&row);
        }
    }
});
