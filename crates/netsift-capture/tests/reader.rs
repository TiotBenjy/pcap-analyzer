//! Tests of the single-file readers on hand-built pcap / pcapng / gzip bytes.

use std::io::{Cursor, Read, Write};

use flate2::Compression;
use flate2::write::GzEncoder;
use netsift_capture::reader::{MAX_PACKET_LEN, MAX_WARNINGS, from_reader, open};
use netsift_capture::{CaptureError, CaptureFormat, PacketSource, RawPacket, ReadWarning};
use proptest::prelude::*;

// ---------------------------------------------------------------------------------------------
// Builders
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum E {
    Le,
    Be,
}

impl E {
    fn u16(self, v: u16) -> [u8; 2] {
        match self {
            E::Le => v.to_le_bytes(),
            E::Be => v.to_be_bytes(),
        }
    }
    fn u32(self, v: u32) -> [u8; 4] {
        match self {
            E::Le => v.to_le_bytes(),
            E::Be => v.to_be_bytes(),
        }
    }
    fn i64(self, v: i64) -> [u8; 8] {
        match self {
            E::Le => v.to_le_bytes(),
            E::Be => v.to_be_bytes(),
        }
    }
}

struct Rec<'a> {
    sec: u32,
    frac: u32,
    data: &'a [u8],
    orig: u32,
}

fn rec(sec: u32, frac: u32, data: &[u8]) -> Rec<'_> {
    Rec {
        sec,
        frac,
        data,
        orig: u32::try_from(data.len()).unwrap(),
    }
}

fn pcap_header(e: E, nanos: bool, linktype: u32, snaplen: u32) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend(e.u32(if nanos { 0xa1b2_3c4d } else { 0xa1b2_c3d4 }));
    out.extend(e.u16(2));
    out.extend(e.u16(4));
    out.extend(e.u32(0)); // thiszone
    out.extend(e.u32(0)); // sigfigs
    out.extend(e.u32(snaplen));
    out.extend(e.u32(linktype));
    out
}

fn pcap_record(e: E, r: &Rec<'_>) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend(e.u32(r.sec));
    out.extend(e.u32(r.frac));
    out.extend(e.u32(u32::try_from(r.data.len()).unwrap()));
    out.extend(e.u32(r.orig));
    out.extend(r.data);
    out
}

fn pcap(e: E, nanos: bool, records: &[Rec<'_>]) -> Vec<u8> {
    let mut out = pcap_header(e, nanos, 1, 65535);
    for r in records {
        out.extend(pcap_record(e, r));
    }
    out
}

fn pad4(v: &mut Vec<u8>) {
    while !v.len().is_multiple_of(4) {
        v.push(0);
    }
}

fn block(e: E, block_type: u32, body: &[u8]) -> Vec<u8> {
    let mut body = body.to_vec();
    pad4(&mut body);
    let total = u32::try_from(body.len() + 12).unwrap();
    let mut out = Vec::new();
    out.extend(e.u32(block_type));
    out.extend(e.u32(total));
    out.extend(body);
    out.extend(e.u32(total));
    out
}

fn shb(e: E) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend(e.u32(0x1a2b_3c4d));
    body.extend(e.u16(1));
    body.extend(e.u16(0));
    body.extend(e.i64(-1)); // section length unknown
    // One option (shb_userappl) to check it is skipped.
    body.extend(e.u16(4));
    body.extend(e.u16(3));
    body.extend(b"abc\0");
    body.extend(e.u16(0));
    body.extend(e.u16(0));
    block(e, 0x0a0d_0d0a, &body)
}

fn option(e: E, code: u16, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend(e.u16(code));
    out.extend(e.u16(u16::try_from(value.len()).unwrap()));
    out.extend(value);
    pad4(&mut out);
    out
}

fn idb(e: E, linktype: u16, snaplen: u32, tsresol: Option<u8>, tsoffset: Option<i64>) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend(e.u16(linktype));
    body.extend(e.u16(0));
    body.extend(e.u32(snaplen));
    body.extend(option(e, 2, b"eth0")); // if_name
    if let Some(r) = tsresol {
        body.extend(option(e, 9, &[r]));
    }
    if let Some(o) = tsoffset {
        body.extend(option(e, 14, &e.i64(o)));
    }
    body.extend(option(e, 0, &[]));
    block(e, 1, &body)
}

fn epb(e: E, iface: u32, ts: u64, data: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend(e.u32(iface));
    body.extend(e.u32(u32::try_from(ts >> 32).unwrap()));
    body.extend(e.u32(u32::try_from(ts & 0xffff_ffff).unwrap()));
    body.extend(e.u32(u32::try_from(data.len()).unwrap()));
    body.extend(e.u32(u32::try_from(data.len()).unwrap() + 100));
    body.extend(data);
    pad4(&mut body);
    body.extend(option(e, 1, b"comment"));
    body.extend(option(e, 0, &[]));
    block(e, 6, &body)
}

fn pb(e: E, iface: u16, ts: u64, data: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend(e.u16(iface));
    body.extend(e.u16(0)); // drops count
    body.extend(e.u32(u32::try_from(ts >> 32).unwrap()));
    body.extend(e.u32(u32::try_from(ts & 0xffff_ffff).unwrap()));
    body.extend(e.u32(u32::try_from(data.len()).unwrap()));
    body.extend(e.u32(u32::try_from(data.len()).unwrap()));
    body.extend(data);
    block(e, 2, &body)
}

fn spb(e: E, orig: u32, data: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend(e.u32(orig));
    body.extend(data);
    block(e, 3, &body)
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut enc = GzEncoder::new(Vec::new(), Compression::default());
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

fn src(bytes: Vec<u8>) -> Box<dyn PacketSource> {
    from_reader(Cursor::new(bytes)).unwrap()
}

/// Reads every packet; panics on a hard error.
fn read_all(source: &mut dyn PacketSource) -> Vec<RawPacket> {
    let mut packets = Vec::new();
    while let Some(p) = source.next_packet().unwrap() {
        packets.push(p);
    }
    // End of stream is sticky.
    assert!(source.next_packet().unwrap().is_none());
    packets
}

/// Reads until the end or the first error, never more than `max` packets.
fn drain(source: &mut dyn PacketSource, max: usize) {
    for _ in 0..max {
        match source.next_packet() {
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => break,
        }
    }
}

const SEC: i64 = 1_000_000_000;

// ---------------------------------------------------------------------------------------------
// pcap
// ---------------------------------------------------------------------------------------------

#[test]
fn pcap_all_magics_and_byte_orders() {
    for e in [E::Le, E::Be] {
        for nanos in [false, true] {
            let bytes = pcap(
                e,
                nanos,
                &[
                    rec(1_700_000_000, 123, b"abcd"),
                    rec(1_700_000_001, 0, b"xyz"),
                ],
            );
            let mut s = src(bytes);
            assert_eq!(s.info().format, CaptureFormat::Pcap);
            assert!(!s.info().compressed);
            assert_eq!(s.info().linktypes, vec![1]);
            assert_eq!(s.info().snaplen, Some(65535));
            let p = read_all(s.as_mut());
            assert_eq!(p.len(), 2);
            let frac_ns = if nanos { 123 } else { 123_000 };
            assert_eq!(p[0].ts_ns, 1_700_000_000 * SEC + frac_ns);
            assert_eq!(p[0].offset, 24);
            assert_eq!(p[0].linktype, 1);
            assert_eq!(p[0].chunk_id, 0);
            assert_eq!(&p[0].data[..], b"abcd");
            assert_eq!(p[1].ts_ns, 1_700_000_001 * SEC);
            assert_eq!(p[1].offset, 24 + 16 + 4);
            assert_eq!(s.warnings(), []);
        }
    }
}

#[test]
fn pcap_keeps_orig_len_and_masks_fcs_bits_of_linktype() {
    let mut bytes = pcap_header(E::Le, false, 0x1000_0069, 128);
    bytes.extend(pcap_record(
        E::Le,
        &Rec {
            sec: 1,
            frac: 0,
            data: b"hello",
            orig: 1500,
        },
    ));
    let mut s = src(bytes);
    assert_eq!(s.info().linktypes, vec![0x69]);
    let p = read_all(s.as_mut());
    assert_eq!(p[0].orig_len, 1500);
    assert_eq!(p[0].data.len(), 5);
}

#[test]
fn pcap_header_only_is_empty() {
    let mut s = src(pcap(E::Le, false, &[]));
    assert_eq!(read_all(s.as_mut()), []);
    assert_eq!(s.warnings(), []);
}

#[test]
fn pcap_truncated_global_header_is_malformed() {
    let bytes = pcap(E::Le, false, &[])[..20].to_vec();
    assert!(matches!(
        from_reader(Cursor::new(bytes)),
        Err(CaptureError::Malformed { offset: 0, .. })
    ));
}

#[test]
fn pcap_truncated_tail_in_header_and_in_data() {
    let full = pcap(E::Le, false, &[rec(1, 0, b"first"), rec(2, 0, b"second")]);
    let second_offset = 24 + 16 + 5;
    // Cut inside the second record header, then inside its data.
    for cut in [second_offset + 3, second_offset + 16 + 2] {
        let mut s = src(full[..cut].to_vec());
        let p = read_all(s.as_mut());
        assert_eq!(p.len(), 1);
        assert_eq!(
            s.warnings(),
            &[ReadWarning::TruncatedTail {
                offset: u64::try_from(second_offset).unwrap()
            }]
        );
    }
}

#[test]
fn pcap_timestamp_backwards_keeps_packet() {
    let bytes = pcap(
        E::Be,
        false,
        &[rec(10, 0, b"a"), rec(5, 0, b"b"), rec(6, 0, b"c")],
    );
    let mut s = src(bytes);
    let p = read_all(s.as_mut());
    assert_eq!(p.len(), 3);
    assert_eq!(
        s.warnings(),
        &[ReadWarning::TimestampBackwards {
            offset: 24 + 17,
            previous_ns: 10 * SEC,
            ts_ns: 5 * SEC,
        }]
    );
}

#[test]
fn pcap_max_timestamp_does_not_overflow() {
    let bytes = pcap(E::Le, false, &[rec(u32::MAX, u32::MAX, b"x")]);
    let mut s = src(bytes);
    let p = read_all(s.as_mut());
    assert_eq!(
        p[0].ts_ns,
        i64::from(u32::MAX) * SEC + i64::from(u32::MAX) * 1000
    );
}

#[test]
fn pcap_hostile_lengths() {
    // Record length above the cap: fatal, no allocation attempted.
    let mut bytes = pcap_header(E::Le, false, 1, 65535);
    bytes.extend(E::Le.u32(1));
    bytes.extend(E::Le.u32(0));
    bytes.extend(E::Le.u32(u32::MAX));
    bytes.extend(E::Le.u32(u32::MAX));
    let mut s = src(bytes);
    assert!(matches!(
        s.next_packet(),
        Err(CaptureError::Malformed { offset: 24, .. })
    ));
    assert!(s.next_packet().unwrap().is_none());

    // Record length just under the cap on a tiny file: truncated tail, small allocation.
    let mut bytes = pcap_header(E::Le, false, 1, 65535);
    bytes.extend(E::Le.u32(1));
    bytes.extend(E::Le.u32(0));
    bytes.extend(E::Le.u32(MAX_PACKET_LEN));
    bytes.extend(E::Le.u32(MAX_PACKET_LEN));
    bytes.extend(b"only a few bytes");
    let mut s = src(bytes);
    assert_eq!(read_all(s.as_mut()), []);
    assert_eq!(s.warnings(), &[ReadWarning::TruncatedTail { offset: 24 }]);
}

// ---------------------------------------------------------------------------------------------
// pcapng
// ---------------------------------------------------------------------------------------------

#[test]
fn pcapng_basic_both_byte_orders() {
    for e in [E::Le, E::Be] {
        let mut bytes = shb(e);
        bytes.extend(idb(e, 1, 262_144, None, None));
        let first = bytes.len();
        bytes.extend(epb(e, 0, 1_700_000_000_123_456, b"packet-1"));
        bytes.extend(epb(e, 0, 1_700_000_001_000_000, b"p2"));
        let mut s = src(bytes);
        assert_eq!(s.info().format, CaptureFormat::PcapNg);
        assert_eq!(s.info().linktypes, vec![1]);
        assert_eq!(s.info().snaplen, Some(262_144));
        let p = read_all(s.as_mut());
        assert_eq!(p.len(), 2);
        assert_eq!(p[0].ts_ns, 1_700_000_000_123_456_000);
        assert_eq!(p[0].offset, u64::try_from(first).unwrap());
        assert_eq!(&p[0].data[..], b"packet-1");
        assert_eq!(p[0].orig_len, 108);
        assert_eq!(&p[1].data[..], b"p2");
        assert_eq!(s.warnings(), []);
    }
}

#[test]
fn pcapng_multiple_interfaces_with_resolutions_and_offset() {
    let e = E::Le;
    let mut bytes = shb(e);
    bytes.extend(idb(e, 1, 0, None, None)); // µs (default)
    bytes.extend(idb(e, 105, 0, Some(9), None)); // ns
    bytes.extend(idb(e, 113, 0, Some(0x80 | 0x0a), None)); // 2^-10 s
    bytes.extend(idb(e, 1, 0, Some(3), Some(100))); // ms, +100 s
    bytes.extend(epb(e, 0, 2_000_000, b"a"));
    bytes.extend(epb(e, 1, 3_000_000_000, b"b"));
    bytes.extend(epb(e, 2, 4 * 1024 + 512, b"c"));
    bytes.extend(epb(e, 3, 5_250, b"d"));
    let mut s = src(bytes);
    assert_eq!(s.info().linktypes, vec![1, 105, 113]);
    assert_eq!(s.info().snaplen, Some(0));
    let p = read_all(s.as_mut());
    let got: Vec<(i64, u32)> = p.iter().map(|p| (p.ts_ns, p.linktype)).collect();
    assert_eq!(
        got,
        vec![
            (2 * SEC, 1),
            (3 * SEC, 105),
            (4 * SEC + SEC / 2, 113),
            (105 * SEC + SEC / 4, 1),
        ]
    );
    assert_eq!(s.warnings(), []);
}

#[test]
fn pcapng_multiple_sections_reset_interfaces_and_byte_order() {
    let mut bytes = shb(E::Le);
    bytes.extend(idb(E::Le, 1, 0, None, None));
    bytes.extend(epb(E::Le, 0, 1_000_000, b"le"));
    bytes.extend(shb(E::Be));
    bytes.extend(idb(E::Be, 101, 0, Some(9), None));
    bytes.extend(epb(E::Be, 0, 2 * 1_000_000_000, b"be"));
    // Interface 1 does not exist in the second section.
    let bad = bytes.len();
    bytes.extend(epb(E::Be, 1, 3 * 1_000_000_000, b"bad"));
    bytes.extend(shb(E::Le));
    // Interface 0 is no longer declared after the third SHB.
    let orphan = bytes.len();
    bytes.extend(epb(E::Le, 0, 4_000_000, b"orphan"));
    bytes.extend(idb(E::Le, 228, 0, None, None));
    bytes.extend(epb(E::Le, 0, 5_000_000, b"ip"));
    let mut s = src(bytes);
    let p = read_all(s.as_mut());
    let got: Vec<(i64, u32, &[u8])> = p
        .iter()
        .map(|p| (p.ts_ns, p.linktype, &p.data[..]))
        .collect();
    assert_eq!(
        got,
        vec![
            (SEC, 1, &b"le"[..]),
            (2 * SEC, 101, &b"be"[..]),
            (5 * SEC, 228, &b"ip"[..]),
        ]
    );
    assert_eq!(s.info().linktypes, vec![1, 101, 228]);
    let skipped: Vec<u64> = s
        .warnings()
        .iter()
        .map(|w| match w {
            ReadWarning::SkippedRecord { offset, .. } => *offset,
            other => panic!("unexpected warning {other:?}"),
        })
        .collect();
    assert_eq!(
        skipped,
        vec![u64::try_from(bad).unwrap(), u64::try_from(orphan).unwrap()]
    );
}

#[test]
fn pcapng_simple_and_obsolete_packet_blocks() {
    let e = E::Be;
    let mut bytes = shb(e);
    bytes.extend(idb(e, 1, 4, None, None)); // snaplen 4
    bytes.extend(pb(e, 0, 7_000_000, b"obsolete"));
    bytes.extend(spb(e, 3, b"abc"));
    // SPB truncated to the snaplen; takes the last timestamp of the section.
    bytes.extend(spb(e, 10, b"0123456789"));
    let mut s = src(bytes);
    let p = read_all(s.as_mut());
    let got: Vec<(i64, &[u8], u32)> = p
        .iter()
        .map(|p| (p.ts_ns, &p.data[..], p.orig_len))
        .collect();
    assert_eq!(
        got,
        vec![
            (7 * SEC, &b"obsolete"[..], 8),
            (7 * SEC, &b"abc"[..], 3),
            (7 * SEC, &b"0123"[..], 10),
        ]
    );
    assert_eq!(s.warnings(), []);
}

#[test]
fn pcapng_spb_at_file_start_is_skipped() {
    let e = E::Le;
    let mut bytes = shb(e);
    bytes.extend(idb(e, 1, 0, None, None));
    let first = bytes.len();
    bytes.extend(spb(e, 3, b"abc"));
    bytes.extend(epb(e, 0, 2_000_000, b"ts"));
    // A new section reuses the last timestamp of the file.
    bytes.extend(shb(e));
    bytes.extend(idb(e, 1, 0, None, None));
    bytes.extend(spb(e, 3, b"def"));
    let mut s = src(bytes);
    let p = read_all(s.as_mut());
    let got: Vec<(i64, &[u8])> = p.iter().map(|p| (p.ts_ns, &p.data[..])).collect();
    assert_eq!(got, vec![(2 * SEC, &b"ts"[..]), (2 * SEC, &b"def"[..])]);
    assert_eq!(
        s.warnings(),
        &[ReadWarning::SkippedRecord {
            offset: u64::try_from(first).unwrap(),
            reason: "simple packet block without a reference timestamp".into(),
        }]
    );
}

#[test]
fn pcapng_negative_tsoffset_on_a_packet() {
    for e in [E::Le, E::Be] {
        let mut bytes = shb(e);
        bytes.extend(idb(e, 1, 0, Some(6), Some(-1_000)));
        bytes.extend(epb(e, 0, 1_700_000_000_250_000, b"x"));
        let mut s = src(bytes);
        let p = read_all(s.as_mut());
        assert_eq!(p[0].ts_ns, (1_700_000_000 - 1_000) * SEC + SEC / 4);
    }
}

#[test]
fn pcapng_section_header_trailer_mismatch_is_reported() {
    let e = E::Le;
    let mut bytes = shb(e);
    bytes.extend(idb(e, 1, 0, None, None));
    bytes.extend(epb(e, 0, 1_000_000, b"a"));
    let second = bytes.len();
    let mut bad_shb = shb(E::Be);
    let n = bad_shb.len();
    bad_shb[n - 4..].copy_from_slice(&E::Be.u32(12));
    bytes.extend(bad_shb);
    // The section still applies: big-endian, interfaces reset.
    bytes.extend(idb(E::Be, 101, 0, None, None));
    bytes.extend(epb(E::Be, 0, 2_000_000, b"b"));
    let mut s = src(bytes);
    let p = read_all(s.as_mut());
    let got: Vec<(i64, u32)> = p.iter().map(|p| (p.ts_ns, p.linktype)).collect();
    assert_eq!(got, vec![(SEC, 1), (2 * SEC, 101)]);
    assert!(matches!(
        s.warnings(),
        [ReadWarning::SkippedRecord { offset, .. }] if *offset == u64::try_from(second).unwrap()
    ));
}

#[test]
fn pcapng_spb_without_interface_is_skipped() {
    let e = E::Le;
    let mut bytes = shb(e);
    bytes.extend(spb(e, 3, b"abc"));
    let mut s = src(bytes);
    assert_eq!(read_all(s.as_mut()), []);
    assert!(matches!(s.warnings(), [ReadWarning::SkippedRecord { .. }]));
}

#[test]
fn pcapng_unknown_and_ignored_blocks() {
    let e = E::Le;
    let mut bytes = shb(e);
    bytes.extend(idb(e, 1, 0, None, None));
    let unknown = bytes.len();
    bytes.extend(block(e, 0x0000_0123, b"whatever"));
    bytes.extend(block(e, 5, &[0; 20])); // interface statistics: silently skipped
    bytes.extend(block(e, 4, &[0; 8])); // name resolution: silently skipped
    bytes.extend(epb(e, 0, 1_000_000, b"after"));
    let mut s = src(bytes);
    let p = read_all(s.as_mut());
    assert_eq!(p.len(), 1);
    assert_eq!(&p[0].data[..], b"after");
    assert_eq!(
        s.warnings(),
        &[ReadWarning::UnknownBlock {
            offset: u64::try_from(unknown).unwrap(),
            block_type: 0x123,
        }]
    );
}

#[test]
fn pcapng_timestamp_backwards() {
    let e = E::Le;
    let mut bytes = shb(e);
    bytes.extend(idb(e, 1, 0, None, None));
    bytes.extend(epb(e, 0, 5_000_000, b"a"));
    let back = bytes.len();
    bytes.extend(epb(e, 0, 4_000_000, b"b"));
    let mut s = src(bytes);
    assert_eq!(read_all(s.as_mut()).len(), 2);
    assert_eq!(
        s.warnings(),
        &[ReadWarning::TimestampBackwards {
            offset: u64::try_from(back).unwrap(),
            previous_ns: 5 * SEC,
            ts_ns: 4 * SEC,
        }]
    );
}

#[test]
fn pcapng_timestamp_overflow_is_skipped() {
    let e = E::Le;
    let mut bytes = shb(e);
    bytes.extend(idb(e, 1, 0, Some(0), None)); // seconds
    bytes.extend(epb(e, 0, u64::MAX, b"far future"));
    bytes.extend(epb(e, 0, 1, b"ok"));
    let mut s = src(bytes);
    let p = read_all(s.as_mut());
    assert_eq!(p.len(), 1);
    assert_eq!(p[0].ts_ns, SEC);
    assert!(matches!(s.warnings(), [ReadWarning::SkippedRecord { .. }]));
}

#[test]
fn pcapng_truncated_tail() {
    let e = E::Le;
    let mut bytes = shb(e);
    bytes.extend(idb(e, 1, 0, None, None));
    bytes.extend(epb(e, 0, 1_000_000, b"complete"));
    let last = bytes.len();
    bytes.extend(epb(e, 0, 2_000_000, b"incomplete"));
    for cut in [last + 5, last + 20, bytes.len() - 1] {
        let mut s = src(bytes[..cut].to_vec());
        assert_eq!(read_all(s.as_mut()).len(), 1);
        assert_eq!(
            s.warnings(),
            &[ReadWarning::TruncatedTail {
                offset: u64::try_from(last).unwrap()
            }]
        );
    }
}

#[test]
fn pcapng_info_is_known_before_the_first_packet_is_read() {
    let e = E::Le;
    let mut bytes = shb(e);
    bytes.extend(block(e, 4, &[0; 8]));
    bytes.extend(idb(e, 127, 2048, None, None));
    bytes.extend(epb(e, 0, 1, b"x"));
    let s = src(bytes);
    assert_eq!(s.info().linktypes, vec![127]);
    assert_eq!(s.info().snaplen, Some(2048));
}

#[test]
fn pcapng_hostile_lengths() {
    let e = E::Le;
    // Block total length absurdly large: malformed.
    let mut bytes = shb(e);
    let off = bytes.len();
    bytes.extend(e.u32(6));
    bytes.extend(e.u32(0xffff_fff0));
    bytes.extend([0; 32]);
    let mut s = src(bytes);
    assert!(matches!(
        s.next_packet(),
        Err(CaptureError::Malformed { offset, .. }) if offset == u64::try_from(off).unwrap()
    ));

    // Block length too small / not a multiple of 4.
    for len in [8u32, 13] {
        let mut bytes = shb(e);
        bytes.extend(e.u32(6));
        bytes.extend(e.u32(len));
        bytes.extend([0; 32]);
        let mut s = src(bytes);
        assert!(matches!(
            s.next_packet(),
            Err(CaptureError::Malformed { .. })
        ));
    }

    // Large (but allowed) EPB length on a tiny file: truncated tail, no big allocation.
    let mut bytes = shb(e);
    bytes.extend(idb(e, 1, 0, None, None));
    let off = bytes.len();
    bytes.extend(e.u32(6));
    bytes.extend(e.u32(60 * 1024 * 1024));
    bytes.extend([0; 64]);
    let mut s = src(bytes);
    assert_eq!(read_all(s.as_mut()), []);
    assert_eq!(
        s.warnings(),
        &[ReadWarning::TruncatedTail {
            offset: u64::try_from(off).unwrap()
        }]
    );

    // Unknown block bigger than the file: streamed skip, truncated tail.
    let mut bytes = shb(e);
    bytes.extend(e.u32(0x99));
    bytes.extend(e.u32(200 * 1024 * 1024));
    bytes.extend([0; 64]);
    let mut s = src(bytes);
    assert_eq!(read_all(s.as_mut()), []);
    assert!(matches!(s.warnings(), [ReadWarning::TruncatedTail { .. }]));

    // EPB whose captured length exceeds its block; IDB with a lying option length.
    let mut bytes = shb(e);
    let mut idb_body = Vec::new();
    idb_body.extend(e.u16(1));
    idb_body.extend(e.u16(0));
    idb_body.extend(e.u32(0));
    idb_body.extend(e.u16(9));
    idb_body.extend(e.u16(0xffff));
    bytes.extend(block(e, 1, &idb_body));
    let mut epb_body = Vec::new();
    epb_body.extend(e.u32(0));
    epb_body.extend(e.u32(0));
    epb_body.extend(e.u32(1));
    epb_body.extend(e.u32(0xffff_ff00));
    epb_body.extend(e.u32(4));
    epb_body.extend(b"data");
    bytes.extend(block(e, 6, &epb_body));
    bytes.extend(epb(e, 0, 2, b"ok"));
    let mut s = src(bytes);
    let p = read_all(s.as_mut());
    assert_eq!(p.len(), 1);
    assert_eq!(p[0].ts_ns, 2000);
    assert!(matches!(s.warnings(), [ReadWarning::SkippedRecord { .. }]));
}

#[test]
fn pcapng_trailer_mismatch_skips_block() {
    let e = E::Le;
    let mut bytes = shb(e);
    bytes.extend(idb(e, 1, 0, None, None));
    let mut bad = epb(e, 0, 1, b"bad");
    let n = bad.len();
    bad[n - 4..].copy_from_slice(&e.u32(4));
    bytes.extend(bad);
    bytes.extend(epb(e, 0, 2, b"ok"));
    let mut s = src(bytes);
    let p = read_all(s.as_mut());
    assert_eq!(p.len(), 1);
    assert_eq!(&p[0].data[..], b"ok");
    assert!(matches!(s.warnings(), [ReadWarning::SkippedRecord { .. }]));
}

#[test]
fn pcapng_truncated_first_section_header_is_malformed() {
    let bytes = shb(E::Le)[..20].to_vec();
    assert!(matches!(
        from_reader(Cursor::new(bytes)),
        Err(CaptureError::Malformed { offset: 0, .. })
    ));
}

#[test]
fn warnings_are_bounded() {
    // Every other packet goes back in time.
    let count = 2 * (MAX_WARNINGS + 50);
    let records: Vec<Rec<'_>> = (0..count)
        .map(|i| rec(if i % 2 == 0 { 10 } else { 5 }, 0, b""))
        .collect();
    let mut s = src(pcap(E::Le, false, &records));
    assert_eq!(read_all(s.as_mut()).len(), count);
    assert_eq!(s.warnings().len(), MAX_WARNINGS);
    assert!(matches!(
        s.warnings()[MAX_WARNINGS - 2],
        ReadWarning::TimestampBackwards { .. }
    ));
    assert!(matches!(
        s.warnings().last(),
        Some(ReadWarning::SkippedRecord { reason, .. })
            if reason == "warning limit reached; further warnings dropped"
    ));
}

#[test]
fn gzip_bad_crc_is_malformed_then_ends() {
    let records: Vec<Rec<'_>> = (0..10).map(|i| rec(i, 0, b"payload")).collect();
    let mut compressed = gzip(&pcap(E::Le, false, &records));
    // The gzip trailer is CRC32 then ISIZE: corrupt the CRC.
    let n = compressed.len();
    compressed[n - 8] ^= 0xff;
    let mut s = src(compressed);
    let mut count = 0;
    let err = loop {
        match s.next_packet() {
            Ok(Some(_)) => count += 1,
            Ok(None) => panic!("bad CRC not detected after {count} packets"),
            Err(e) => break e,
        }
    };
    assert!(matches!(err, CaptureError::Malformed { .. }), "{err:?}");
    assert!(s.next_packet().unwrap().is_none());
    assert!(s.next_packet().unwrap().is_none());
}

#[test]
fn io_error_ends_the_stream() {
    struct FailAfter(Cursor<Vec<u8>>);
    impl Read for FailAfter {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            match self.0.read(buf)? {
                0 => Err(std::io::Error::other("disk gone")),
                n => Ok(n),
            }
        }
    }
    let mut bytes = pcap(E::Le, false, &[rec(1, 0, b"a")]);
    bytes.extend(&[0; 7]); // partial record header, then the error
    let mut s = from_reader(FailAfter(Cursor::new(bytes))).unwrap();
    let mut seen_error = false;
    loop {
        match s.next_packet() {
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(CaptureError::Io(_)) => seen_error = true,
            Err(e) => panic!("unexpected {e:?}"),
        }
    }
    assert!(seen_error);
    assert!(s.next_packet().unwrap().is_none());
}

#[test]
fn pcapng_unsupported_version_is_malformed() {
    let mut bytes = shb(E::Le);
    bytes[12] = 2;
    assert!(matches!(
        from_reader(Cursor::new(bytes)),
        Err(CaptureError::Malformed { offset: 0, .. })
    ));
}

// ---------------------------------------------------------------------------------------------
// Detection, gzip, files
// ---------------------------------------------------------------------------------------------

#[test]
fn unknown_formats() {
    let mut bad_bom = shb(E::Le);
    bad_bom[8..12].copy_from_slice(&[1, 2, 3, 4]);
    let cases: Vec<Vec<u8>> = vec![
        vec![],
        vec![0xd4],
        b"GET / HTTP/1.1\r\n".to_vec(),
        vec![0; 100],
        b"\x0a\x0d\x0d\x0a".to_vec(),
        bad_bom,
        // Modified (Kuznetzov) pcap is not supported.
        vec![0x34, 0xcd, 0xb2, 0xa1, 0, 0, 0, 0],
        gzip(b""),
        gzip(b"definitely not a capture"),
        gzip(&gzip(&pcap(E::Le, false, &[rec(1, 0, b"x")]))),
        vec![
            0x1f, 0x8b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        ],
    ];
    for bytes in cases {
        assert!(
            matches!(
                from_reader(Cursor::new(bytes.clone())),
                Err(CaptureError::UnknownFormat)
            ),
            "{bytes:02x?}"
        );
    }
}

#[test]
fn gzip_pcap_and_pcapng() {
    let plain_pcap = pcap(E::Le, true, &[rec(1, 5, b"one"), rec(2, 6, b"two")]);
    let mut plain_ng = shb(E::Be);
    plain_ng.extend(idb(E::Be, 1, 0, None, None));
    plain_ng.extend(epb(E::Be, 0, 3_000_000, b"three"));
    for (plain, count) in [(plain_pcap, 2), (plain_ng, 1)] {
        let compressed = gzip(&plain);
        let mut s = src(compressed.clone());
        assert!(s.info().compressed);
        let p = read_all(s.as_mut());
        assert_eq!(p.len(), count);
        assert_eq!(s.warnings(), []);
        // Progress counts compressed bytes, all of them by the end.
        assert_eq!(s.bytes_read(), u64::try_from(compressed.len()).unwrap());
        // Offsets are positions in the decompressed stream.
        assert!(p[0].offset >= 24);
    }
}

#[test]
fn gzip_multi_member() {
    let plain = pcap(E::Le, false, &[rec(1, 0, b"first"), rec(2, 0, b"second")]);
    let (a, b) = plain.split_at(30);
    let mut bytes = gzip(a);
    bytes.extend(gzip(b));
    let mut s = src(bytes);
    assert_eq!(read_all(s.as_mut()).len(), 2);
}

#[test]
fn gzip_truncated_stream_is_a_truncated_tail() {
    let mut records = Vec::new();
    let payload = vec![0x5a; 200];
    for i in 0..200 {
        records.push(rec(i, 0, &payload));
    }
    let compressed = gzip(&pcap(E::Le, false, &records));
    let cut = compressed[..compressed.len() / 2].to_vec();
    let mut s = src(cut);
    let mut count = 0;
    loop {
        match s.next_packet() {
            Ok(Some(_)) => count += 1,
            Ok(None) => break,
            Err(e) => panic!("unexpected error after {count} packets: {e}"),
        }
    }
    assert!(count > 0 && count < 200);
    assert!(matches!(s.warnings(), [ReadWarning::TruncatedTail { .. }]));
}

#[test]
fn bytes_read_tracks_the_underlying_file() {
    let bytes = pcap(E::Le, false, &[rec(1, 0, b"x")]);
    let len = u64::try_from(bytes.len()).unwrap();
    let mut s = src(bytes);
    read_all(s.as_mut());
    assert_eq!(s.bytes_read(), len);
}

#[test]
fn open_detects_by_magic_not_extension() {
    let dir = tempfile::tempdir().unwrap();
    // A gzip pcapng named like a plain pcap.
    let mut ng = shb(E::Le);
    ng.extend(idb(E::Le, 1, 0, None, None));
    ng.extend(epb(E::Le, 0, 1, b"x"));
    let path = dir.path().join("capture.pcap");
    std::fs::write(&path, gzip(&ng)).unwrap();
    let mut s = open(&path).unwrap();
    assert_eq!(s.info().format, CaptureFormat::PcapNg);
    assert!(s.info().compressed);
    assert_eq!(read_all(s.as_mut()).len(), 1);

    let path = dir.path().join("notes.pcapng");
    std::fs::write(&path, b"hello world").unwrap();
    assert!(matches!(open(&path), Err(CaptureError::UnknownFormat)));

    let path = dir.path().join("empty.pcap");
    std::fs::write(&path, b"").unwrap();
    assert!(matches!(open(&path), Err(CaptureError::UnknownFormat)));

    assert!(matches!(
        open(&dir.path().join("missing.pcap")),
        Err(CaptureError::Io(_))
    ));
}

#[test]
fn source_is_send() {
    fn assert_send<T: Send + ?Sized>() {}
    assert_send::<dyn PacketSource>();
    let s = src(pcap(E::Le, false, &[]));
    std::thread::spawn(move || drop(s)).join().unwrap();
}

#[test]
fn slow_reader_one_byte_at_a_time() {
    struct OneByte(Cursor<Vec<u8>>);
    impl Read for OneByte {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = buf.len().min(1);
            self.0.read(&mut buf[..n])
        }
    }
    let mut ng = shb(E::Le);
    ng.extend(idb(E::Le, 1, 0, None, None));
    ng.extend(epb(E::Le, 0, 1, b"slow"));
    let mut s = from_reader(OneByte(Cursor::new(gzip(&ng)))).unwrap();
    assert_eq!(&read_all(s.as_mut())[0].data[..], b"slow");
}

// ---------------------------------------------------------------------------------------------
// Property tests: never panic on arbitrary input
// ---------------------------------------------------------------------------------------------

fn prefixes() -> Vec<Vec<u8>> {
    let mut ng_le = shb(E::Le);
    ng_le.extend(idb(E::Le, 1, 0, Some(0x85), Some(-3)));
    let mut ng_be = shb(E::Be);
    ng_be.extend(idb(E::Be, 1, 0, None, None));
    vec![
        vec![0xd4, 0xc3, 0xb2, 0xa1],
        vec![0xa1, 0xb2, 0xc3, 0xd4],
        vec![0x4d, 0x3c, 0xb2, 0xa1],
        vec![0xa1, 0xb2, 0x3c, 0x4d],
        vec![0x0a, 0x0d, 0x0d, 0x0a],
        pcap_header(E::Le, false, 1, 65535),
        pcap_header(E::Be, true, 1, 65535),
        ng_le,
        ng_be,
        vec![0x1f, 0x8b],
    ]
}

fn sample_file() -> Vec<u8> {
    let e = E::Le;
    let mut bytes = shb(e);
    bytes.extend(idb(e, 1, 0, Some(9), Some(10)));
    bytes.extend(idb(e, 105, 64, Some(0x8a), None));
    bytes.extend(epb(e, 0, 1_000, b"aaaa"));
    bytes.extend(spb(e, 70, &[1; 70]));
    bytes.extend(pb(e, 1, 2_000, b"bbbb"));
    bytes.extend(block(e, 0x77, b"zz"));
    bytes.extend(shb(E::Be));
    bytes.extend(idb(E::Be, 1, 0, None, None));
    bytes.extend(epb(E::Be, 0, 3_000, b"cccc"));
    bytes
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn never_panics_on_prefixed_garbage(
        which in 0usize..10,
        tail in proptest::collection::vec(any::<u8>(), 0..2048),
        gz in any::<bool>(),
    ) {
        let mut bytes = prefixes()[which].clone();
        bytes.extend(tail);
        if gz {
            bytes = gzip(&bytes);
        }
        if let Ok(mut s) = from_reader(Cursor::new(bytes)) {
            drain(s.as_mut(), 10_000);
            let _ = s.warnings();
            let _ = s.bytes_read();
        }
    }

    #[test]
    fn never_panics_on_mutated_valid_files(
        flips in proptest::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 1..16),
        cut in any::<prop::sample::Index>(),
        pcapng in any::<bool>(),
    ) {
        let mut bytes = if pcapng {
            sample_file()
        } else {
            pcap(E::Le, false, &[rec(1, 2, b"abc"), rec(3, 4, &[9; 300]), rec(5, 6, b"")])
        };
        for (idx, value) in flips {
            let i = idx.index(bytes.len());
            bytes[i] = value;
        }
        bytes.truncate(cut.index(bytes.len() + 1));
        if let Ok(mut s) = from_reader(Cursor::new(bytes)) {
            drain(s.as_mut(), 10_000);
        }
    }
}
