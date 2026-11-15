//! Line protocols of the credentials analyzer (`credentials::lineproto`: FTP, SMTP AUTH, POP3,
//! IMAP). A selector byte picks the server port, then a conversation
//! ([`netsift_fuzz::segments`]) is fed to `on_stream` of one TCP flow.
#![no_main]

use libfuzzer_sys::fuzz_target;
use netsift_analyze::{Analyzer, CredentialsAnalyzer};
use netsift_fuzz::{Sink, analyzer_config, drive_stream, segments};

/// FTP, SMTP, POP3, IMAP.
const PORTS: [u16; 4] = [21, 25, 110, 143];

fuzz_target!(|data: &[u8]| {
    let Some((&sel, rest)) = data.split_first() else {
        return;
    };
    let port = PORTS[usize::from(sel) % PORTS.len()];
    let mut analyzers: Vec<Box<dyn Analyzer>> =
        vec![CredentialsAnalyzer::boxed(&analyzer_config())];
    let mut sink = Sink::default();
    drive_stream(&mut analyzers, 49152, port, &segments(rest), &mut sink);
});
