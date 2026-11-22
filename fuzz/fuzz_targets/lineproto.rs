//! Line protocols: the credentials analyzer (`credentials::lineproto`: FTP, SMTP AUTH, POP3,
//! IMAP) and, on the FTP port, the `ftp` analyzer (transcript, data-channel announcements) and
//! the pure FTP line parsers of `netsift_dissect::ftp`. A selector byte picks the server port,
//! then a conversation ([`netsift_fuzz::segments`]) is fed to `on_stream` of one TCP flow.
#![no_main]

use libfuzzer_sys::fuzz_target;
use netsift_analyze::dissect::ftp;
use netsift_analyze::ftp::FtpAnalyzer;
use netsift_analyze::{Analyzer, CredentialsAnalyzer};
use netsift_fuzz::{Sink, analyzer_config, drive_stream, segments};

/// FTP, SMTP, POP3, IMAP.
const PORTS: [u16; 4] = [21, 25, 110, 143];

fuzz_target!(|data: &[u8]| {
    let Some((&sel, rest)) = data.split_first() else {
        return;
    };
    let port = PORTS[usize::from(sel) % PORTS.len()];
    let config = analyzer_config();
    let mut analyzers: Vec<Box<dyn Analyzer>> = vec![CredentialsAnalyzer::boxed(&config)];
    if port == 21 {
        analyzers.push(FtpAnalyzer::boxed(&config));
        for line in String::from_utf8_lossy(rest).lines() {
            if let Some(cmd) = ftp::parse_command(line) {
                let _ = ftp::parse_port_arg(cmd.arg);
                let _ = ftp::parse_eprt_arg(cmd.arg);
            }
            if let Some(reply) = ftp::parse_reply(line) {
                let _ = ftp::parse_pasv_reply(reply.text);
                let _ = ftp::parse_epsv_reply(reply.text);
            }
        }
    }
    let mut sink = Sink::default();
    drive_stream(&mut analyzers, 49152, port, &segments(rest), &mut sink);
});
