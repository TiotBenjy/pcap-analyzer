//! pcap / pcapng readers and their gzip, zstd and LZ4 frame decompressors
//! (`netsift_capture::reader`): the input is a whole capture file.
#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use netsift_capture::reader;

/// Most packets read from one input.
const MAX_PACKETS: usize = 100_000;

fuzz_target!(|data: &[u8]| {
    let Ok(mut source) = reader::from_reader(Cursor::new(data.to_vec())) else {
        return;
    };
    let _ = format!("{:?}", source.info());
    for _ in 0..MAX_PACKETS {
        match source.next_packet() {
            Ok(Some(p)) => assert!(p.data.len() <= reader::MAX_PACKET_LEN as usize),
            Ok(None) | Err(_) => break,
        }
    }
    // The stream stays ended after the end or an error.
    assert!(matches!(source.next_packet(), Ok(None)));
    assert!(source.warnings().len() <= reader::MAX_WARNINGS);
    let _ = source.bytes_read();
});
