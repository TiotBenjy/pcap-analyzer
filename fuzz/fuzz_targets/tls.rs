//! TLS (`tls`). Mode byte, even: the pure parsers on the rest of the input (record layer
//! reassembly, client and server hellos, JA3 / JA4, X.509 certificate); odd: the TLS analyzer
//! fed with a conversation ([`netsift_fuzz::segments`]) on one TCP flow to port 443.
#![no_main]

use std::sync::LazyLock;

use libfuzzer_sys::fuzz_target;
use netsift_analyze::Analyzer;
use netsift_analyze::tls::stream::{DirParser, Event};
use netsift_analyze::tls::{TlsAnalyzer, cert, fingerprint, hello};
use netsift_fuzz::{Sink, analyzer_config, drive_stream, segments};

/// Handshake message bound of the analyzer's default settings.
static MAX_MESSAGE: LazyLock<usize> = LazyLock::new(|| analyzer_config().tls.max_handshake_message);

fn handshake(msg: &[u8]) {
    let (Some(&kind), Some(body)) = (msg.first(), msg.get(4..)) else {
        return;
    };
    match kind {
        1 => {
            if let Some(ch) = hello::parse_client_hello(body) {
                let _ = (ch.approx_size(), ch.offered_version());
                let _ = fingerprint::ja3(&ch);
                let _ = fingerprint::ja4(&ch);
            }
        }
        2 => {
            if let Some(sh) = hello::parse_server_hello(body) {
                let _ = (sh.approx_size(), sh.version());
            }
        }
        _ => {}
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    if mode & 1 == 1 {
        let mut analyzers: Vec<Box<dyn Analyzer>> = vec![TlsAnalyzer::boxed(&analyzer_config())];
        let mut sink = Sink::default();
        drive_stream(&mut analyzers, 49152, 443, &segments(rest), &mut sink);
        return;
    }
    // Record layer, fed in two halves (records split across segments).
    let mut parser = DirParser::default();
    let mut events = Vec::new();
    let (a, b) = rest.split_at(rest.len() / 2);
    parser.feed(a, *MAX_MESSAGE, &mut events);
    parser.feed(b, *MAX_MESSAGE, &mut events);
    let _ = parser.buffered();
    for e in &events {
        if let Event::Handshake(msg) = e {
            handshake(msg);
        }
    }
    // Bare handshake bodies and certificates.
    let _ = hello::parse_client_hello(rest).map(|ch| fingerprint::ja4(&ch));
    let _ = hello::parse_server_hello(rest);
    if let Some(info) = cert::parse(rest) {
        let _ = info.weak_key();
    }
});
