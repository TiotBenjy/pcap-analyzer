//! LDAP simple binds (`credentials::ldap`: BER message framing, then `ldap-parser`). The input
//! is a conversation ([`netsift_fuzz::segments`]) fed to `on_stream` of one TCP flow to port 389.
#![no_main]

use libfuzzer_sys::fuzz_target;
use netsift_analyze::{Analyzer, CredentialsAnalyzer};
use netsift_fuzz::{Sink, analyzer_config, drive_stream, segments};

fuzz_target!(|data: &[u8]| {
    let mut analyzers: Vec<Box<dyn Analyzer>> =
        vec![CredentialsAnalyzer::boxed(&analyzer_config())];
    let mut sink = Sink::default();
    drive_stream(&mut analyzers, 49152, 389, &segments(data), &mut sink);
});
