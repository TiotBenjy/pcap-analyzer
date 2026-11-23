//! MQTT: a selector byte, then a conversation ([`netsift_fuzz::segments`]). Bit 7 of the
//! selector reads the segments of both directions as one stream of packets for the pure parser
//! (`netsift_dissect::mqtt`, every version); otherwise the conversation goes to `on_stream` of
//! the `mqtt` analyzer (bit 0: port 1883, or another port where only a first CONNECT counts).
#![no_main]

use libfuzzer_sys::fuzz_target;
use netsift_analyze::Analyzer;
use netsift_analyze::dissect::mqtt::{self, HeaderStatus, Version};
use netsift_analyze::mqtt::MqttAnalyzer;
use netsift_fuzz::{Sink, analyzer_config, drive_stream, segments};

fuzz_target!(|data: &[u8]| {
    let Some((&sel, rest)) = data.split_first() else {
        return;
    };
    let segs = segments(rest);
    if sel & 0x80 != 0 {
        let stream: Vec<u8> = segs.iter().flat_map(|s| s.data.iter().copied()).collect();
        let _ = mqtt::starts_connect(&stream);
        let mut pos = 0usize;
        while let Some(buf) = stream.get(pos..) {
            let HeaderStatus::Valid(h) = mqtt::fixed_header(buf) else {
                break;
            };
            let start = usize::from(h.header_len);
            let body = buf.get(start..).unwrap_or_default();
            let prefix = body
                .get(..body.len().min(mqtt::MAX_PACKET_PREFIX))
                .unwrap_or_default();
            for v in [Version::V31, Version::V311, Version::V5] {
                let _ = mqtt::parse_packet(h, prefix, v);
            }
            let size = usize::try_from(h.size()).unwrap_or(usize::MAX);
            if size == 0 {
                break;
            }
            pos = pos.saturating_add(size);
        }
        return;
    }
    let port = if sel & 1 == 0 { 1883 } else { 11883 };
    let mut analyzers: Vec<Box<dyn Analyzer>> = vec![MqttAnalyzer::boxed(&analyzer_config())];
    let mut sink = Sink::default();
    drive_stream(&mut analyzers, 49152, port, &segs, &mut sink);
});
