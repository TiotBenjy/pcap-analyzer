//! Link to transport decoding (`netsift_dissect::decode`): a linktype selector byte, then one
//! frame.
#![no_main]

use libfuzzer_sys::fuzz_target;
use netsift_analyze::dissect::{self, linktype};
use netsift_analyze::flow::shard_hash;

fuzz_target!(|data: &[u8]| {
    let Some((&sel, frame)) = data.split_first() else {
        return;
    };
    let lt = linktype::SUPPORTED
        .get(usize::from(sel) % (linktype::SUPPORTED.len() + 1))
        .copied()
        .unwrap_or(u32::from(sel));
    let d = dissect::decode(lt, frame);
    let _ = (d.ip(), d.tcp(), d.udp(), d.ports());
    let _ = shard_hash(&d);
    let _ = format!("{d:?}");
    // The transport decoder also accepts reassembled IP payloads.
    if let Some(ip) = d.ip() {
        let _ = dissect::decode_transport(ip.protocol, d.ip_payload);
    }
});
