//! Telnet: a selector byte, then a conversation ([`netsift_fuzz::segments`]). Bit 7 of the
//! selector feeds the segments of both directions to one pure `IAC` decoder
//! (`netsift_dissect::telnet`, sub-negotiation payloads decoded); otherwise the conversation goes
//! to `on_stream` of the `telnet` analyzer (bit 0: port 23 or 2323).
#![no_main]

use libfuzzer_sys::fuzz_target;
use netsift_analyze::Analyzer;
use netsift_analyze::dissect::telnet::{self, Decoder, Event};
use netsift_analyze::telnet::TelnetAnalyzer;
use netsift_fuzz::{Sink, analyzer_config, drive_stream, segments};

fuzz_target!(|data: &[u8]| {
    let Some((&sel, rest)) = data.split_first() else {
        return;
    };
    let segs = segments(rest);
    if sel & 0x80 != 0 {
        let mut decoder = Decoder::new();
        for seg in &segs {
            if seg.gap > 0 {
                decoder.reset();
            }
            decoder.feed(seg.data, &mut |event| {
                if let Event::Subnegotiation { data, .. } = event {
                    assert!(data.len() <= telnet::MAX_SUBNEG);
                    let _ = telnet::parse_ttype(data);
                    let _ = telnet::parse_naws(data);
                    let _ = telnet::parse_environ(data);
                }
            });
        }
        return;
    }
    let port = if sel & 1 == 0 { 23 } else { 2323 };
    let mut analyzers: Vec<Box<dyn Analyzer>> = vec![TelnetAnalyzer::boxed(&analyzer_config())];
    let mut sink = Sink::default();
    drive_stream(&mut analyzers, 49152, port, &segs, &mut sink);
});
