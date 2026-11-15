//! End to end without the store: capture reader, flow table, every built-in analyzer and the
//! translation into store rows. The input is a whole capture file (pcap, pcapng, gzip).
#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use netsift_analyze::flow::{FlowConfig, FlowTable};
use netsift_capture::reader;
use netsift_engine::translate;
use netsift_fuzz::{Fanout, Sink, builtin_analyzers, finish};

/// Most packets read from one input.
const MAX_PACKETS: usize = 4096;

fuzz_target!(|data: &[u8]| {
    let Ok(mut source) = reader::from_reader(Cursor::new(data.to_vec())) else {
        return;
    };
    let mut analyzers = builtin_analyzers();
    let mut sink = Sink::default();
    let mut table = FlowTable::new(FlowConfig::default());
    {
        let mut fanout = Fanout {
            analyzers: &mut analyzers,
            sink: &mut sink,
        };
        let mut frame = 0u64;
        while let Ok(Some(p)) = source.next_packet() {
            table.process(
                p.ts_ns,
                0,
                frame,
                p.linktype,
                p.orig_len,
                &p.data,
                &mut fanout,
            );
            frame += 1;
            if frame as usize >= MAX_PACKETS {
                break;
            }
        }
        table.finish(&mut fanout);
    }
    finish(&mut analyzers, &mut sink);
    for record in sink.records {
        if let Some(row) = translate::to_store(record) {
            let _ = translate::approx_size(&row);
        }
    }
});
