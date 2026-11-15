//! DNS / mDNS / LLMNR and NBNS messages (`netsift_dissect::dns`).
#![no_main]

use libfuzzer_sys::fuzz_target;
use netsift_analyze::dissect::dns::{self, Flavor};

fuzz_target!(|data: &[u8]| {
    for flavor in [Flavor::Dns, Flavor::Nbns] {
        let Ok(msg) = dns::parse(data, flavor) else {
            continue;
        };
        let h = &msg.header;
        let _ = (h.is_response(), h.truncated());
        let _ = dns::opcode_name(flavor, h.opcode());
        let _ = dns::rcode_name(flavor, h.rcode());
        for q in &msg.questions {
            let _ = dns::type_name(flavor, q.qtype);
        }
        for r in &msg.records {
            let _ = dns::type_name(flavor, r.rtype);
            let _ = dns::rdata_text(&r.data);
        }
        let _ = msg.answers().count();
        let _ = format!("{msg:?}");
    }
});
