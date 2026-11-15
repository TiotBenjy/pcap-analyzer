//! pcapng writer: files written by `PcapNgWriter` read back identically with our reader.

use std::io::Cursor;

use netsift_capture::writer::PcapNgWriter;
use netsift_capture::{CaptureFormat, PacketSource, reader};

struct Pkt {
    linktype: u32,
    snaplen: u32,
    ts_ns: i64,
    orig_len: u32,
    data: Vec<u8>,
}

fn pkt(linktype: u32, snaplen: u32, ts_ns: i64, orig_len: u32, len: usize) -> Pkt {
    Pkt {
        linktype,
        snaplen,
        ts_ns,
        orig_len,
        data: (0..len).map(|i| u8::try_from(i % 251).unwrap()).collect(),
    }
}

fn read_all(file: Vec<u8>) -> (Box<dyn PacketSource>, Vec<netsift_capture::RawPacket>) {
    let mut source = reader::from_reader(Cursor::new(file)).unwrap();
    let mut out = Vec::new();
    while let Some(p) = source.next_packet().unwrap() {
        out.push(p);
    }
    (source, out)
}

#[test]
fn round_trip_keeps_order_timestamps_lengths_and_link_types() {
    let packets = vec![
        pkt(1, 262_144, 1_700_000_000_000_000_001, 60, 60),
        pkt(101, 65_535, 1_700_000_000_000_000_002, 1500, 40),
        pkt(1, 262_144, 1_700_000_000_999_999_999, 61, 61),
        pkt(113, 0, 1_700_000_001_000_000_000, 33, 33),
        // Same link type, other snaplen: a fourth interface.
        pkt(1, 96, 1_700_000_002_123_456_789, 1514, 96),
        pkt(101, 65_535, 1_700_000_003_000_000_000, 7, 7),
        pkt(1, 262_144, 1_700_000_004_000_000_000, 0, 0),
    ];
    let mut w = PcapNgWriter::new(Vec::new(), "NetSift test").unwrap();
    for p in &packets {
        w.write_packet(p.linktype, p.snaplen, p.ts_ns, p.orig_len, &p.data)
            .unwrap();
    }
    assert_eq!(w.packets(), 7);
    assert_eq!(w.interfaces(), 4);
    let written = w.bytes_written();
    let file = w.into_inner().unwrap();
    assert_eq!(u64::try_from(file.len()).unwrap(), written);

    let (source, read) = read_all(file);
    assert_eq!(source.info().format, CaptureFormat::PcapNg);
    assert_eq!(source.info().linktypes, vec![1, 101, 113]);
    assert!(source.warnings().is_empty(), "{:?}", source.warnings());
    assert_eq!(read.len(), packets.len());
    for (p, r) in packets.iter().zip(&read) {
        assert_eq!(r.ts_ns, p.ts_ns);
        assert_eq!(r.linktype, p.linktype);
        assert_eq!(r.orig_len, p.orig_len.max(u32::try_from(p.data.len()).unwrap()));
        assert_eq!(r.data.as_ref(), p.data.as_slice());
    }
}

#[test]
fn empty_export_is_a_valid_capture() {
    let file = PcapNgWriter::new(Vec::new(), "NetSift")
        .unwrap()
        .into_inner()
        .unwrap();
    let (source, read) = read_all(file);
    assert_eq!(source.info().format, CaptureFormat::PcapNg);
    assert!(read.is_empty());
}
