//! HTTP/1.x analyzer (`http`): request and response heads, body framing (length, chunked,
//! close), content decoding (gzip, deflate, brotli), objects and credentials. The input is a
//! conversation ([`netsift_fuzz::segments`]) fed to `on_stream` of one TCP flow to port 80.
#![no_main]

use libfuzzer_sys::fuzz_target;
use netsift_analyze::Analyzer;
use netsift_analyze::http::HttpAnalyzer;
use netsift_fuzz::{Sink, analyzer_config, drive_stream, segments};

fuzz_target!(|data: &[u8]| {
    let mut analyzers: Vec<Box<dyn Analyzer>> = vec![HttpAnalyzer::boxed(&analyzer_config())];
    let mut sink = Sink::default();
    drive_stream(&mut analyzers, 49152, 80, &segments(data), &mut sink);
});
