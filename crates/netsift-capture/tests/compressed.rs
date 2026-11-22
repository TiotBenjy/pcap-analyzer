//! zstd and LZ4 frame compressed captures (task P5.7), on synthetic files from
//! `netsift-fixtures`: transparent decompression, equivalence with the plain file, truncated and
//! corrupt streams, bounds.

use std::io::{Cursor, Read};

use netsift_capture::reader::{MAX_ZSTD_WINDOW, from_reader, open};
use netsift_capture::{CaptureError, CaptureFormat, PacketSource, RawPacket, ReadWarning};
use netsift_fixtures::scenarios::{Kind, generate};
use netsift_fixtures::writer::{Compress, encode, gzip, lz4, lz4_with, zstd};
use netsift_fixtures::{Encoding, Packet};
use proptest::prelude::*;

const ZSTD_MAGIC: [u8; 4] = [0x28, 0xb5, 0x2f, 0xfd];
const LZ4_MAGIC: [u8; 4] = [0x04, 0x22, 0x4d, 0x18];

fn src(bytes: Vec<u8>) -> Box<dyn PacketSource> {
    from_reader(Cursor::new(bytes)).unwrap()
}

fn read_all(source: &mut dyn PacketSource) -> Vec<RawPacket> {
    let mut packets = Vec::new();
    while let Some(p) = source.next_packet().unwrap() {
        packets.push(p);
    }
    assert!(source.next_packet().unwrap().is_none());
    packets
}

/// Reads until the end or the first error: (packets, error).
fn read_until_error(source: &mut dyn PacketSource) -> (usize, Option<CaptureError>) {
    let mut count = 0;
    loop {
        match source.next_packet() {
            Ok(Some(_)) => count += 1,
            Ok(None) => return (count, None),
            Err(e) => {
                // Any error ends the stream.
                assert!(source.next_packet().unwrap().is_none());
                return (count, Some(e));
            }
        }
    }
}

fn traffic() -> Vec<Packet> {
    generate(Kind::Demo, 3, 7)
}

/// About 1.7 MB of packets, more than the zstd window of the fixture encoder and than LZ4 blocks
/// of 64 KiB (the `lz4` tool writes 4 MiB blocks: a block is released once complete).
fn big_traffic() -> Vec<Packet> {
    generate(Kind::Demo, 40, 3)
}

fn plain(packets: &[Packet], pcapng: bool) -> Vec<u8> {
    let enc = if pcapng {
        Encoding::pcapng()
    } else {
        Encoding::pcap_ns()
    };
    encode(packets, &enc).unwrap()
}

fn compress(c: Compress, data: &[u8]) -> Vec<u8> {
    c.apply(data).unwrap()
}

/// zstd, and LZ4 with 64 KiB blocks, for tests that need decoded data before the end.
fn streamable(raw: &[u8]) -> [(Compress, Vec<u8>); 2] {
    let info = lz4_flex::frame::FrameInfo::new()
        .block_size(lz4_flex::frame::BlockSize::Max64KB)
        .content_checksum(true);
    [
        (Compress::Zstd, zstd(raw)),
        (Compress::Lz4, lz4_with(raw, info).unwrap()),
    ]
}

const CODECS: [Compress; 2] = [Compress::Zstd, Compress::Lz4];

/// Skippable frame (same layout in zstd and LZ4).
fn skippable(nibble: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0x50 | nibble, 0x2a, 0x4d, 0x18];
    out.extend(u32::try_from(payload.len()).unwrap().to_le_bytes());
    out.extend(payload);
    out
}

#[test]
fn zstd_and_lz4_read_like_the_plain_file() {
    let packets = traffic();
    for pcapng in [false, true] {
        let raw = plain(&packets, pcapng);
        let reference = read_all(src(raw.clone()).as_mut());
        assert_eq!(reference.len(), packets.len());
        for c in CODECS {
            let bytes = compress(c, &raw);
            let mut s = src(bytes.clone());
            assert!(s.info().compressed, "{c:?}");
            let format = if pcapng {
                CaptureFormat::PcapNg
            } else {
                CaptureFormat::Pcap
            };
            assert_eq!(s.info().format, format);
            // Same packets, same offsets (positions in the decompressed stream).
            assert_eq!(read_all(s.as_mut()), reference, "{c:?} pcapng={pcapng}");
            assert_eq!(s.warnings(), []);
            // Progress counts compressed bytes, all of them by the end.
            assert_eq!(s.bytes_read(), u64::try_from(bytes.len()).unwrap(), "{c:?}");
        }
    }
}

#[test]
fn large_files_stream_through_the_decoders() {
    let raw = plain(&big_traffic(), true);
    assert!(raw.len() > 1_500_000, "{}", raw.len());
    let reference = read_all(src(raw.clone()).as_mut());
    let linked = lz4_flex::frame::FrameInfo::new()
        .block_mode(lz4_flex::frame::BlockMode::Linked)
        .block_size(lz4_flex::frame::BlockSize::Max64KB)
        .block_checksums(true)
        .content_checksum(true)
        .content_size(Some(u64::try_from(raw.len()).unwrap()));
    let big_blocks =
        lz4_flex::frame::FrameInfo::new().block_size(lz4_flex::frame::BlockSize::Max4MB);
    for (label, bytes) in [
        ("zstd", zstd(&raw)),
        ("lz4", lz4(&raw).unwrap()),
        ("lz4 4 MiB blocks", lz4_with(&raw, big_blocks).unwrap()),
        ("lz4 linked", lz4_with(&raw, linked).unwrap()),
    ] {
        assert!(bytes.len() < raw.len(), "{label} compresses");
        assert_eq!(read_all(src(bytes).as_mut()), reference, "{label}");
    }
}

#[test]
fn open_detects_compression_by_magic_not_extension() {
    let dir = tempfile::tempdir().unwrap();
    let raw = plain(&traffic(), true);
    for (name, c) in [("a.pcap", Compress::Zstd), ("b.pcap.gz", Compress::Lz4)] {
        let path = dir.path().join(name);
        std::fs::write(&path, compress(c, &raw)).unwrap();
        let mut s = open(&path).unwrap();
        assert!(s.info().compressed);
        assert_eq!(s.info().format, CaptureFormat::PcapNg);
        assert_eq!(read_all(s.as_mut()).len(), traffic().len());
    }
    // A plain capture named like a compressed one.
    let path = dir.path().join("c.pcapng.zst");
    std::fs::write(&path, &raw).unwrap();
    assert!(!open(&path).unwrap().info().compressed);
}

#[test]
fn concatenated_frames_and_skippable_frames() {
    let raw = plain(&traffic(), false);
    let (a, b) = raw.split_at(raw.len() / 3);
    for c in CODECS {
        // pzstd style: a skippable frame before each frame, others between them.
        let mut bytes = skippable(0, &[0, 0, 0, 0]);
        bytes.extend(compress(c, a));
        bytes.extend(skippable(0xf, &[7; 300]));
        bytes.extend(skippable(3, &[]));
        bytes.extend(compress(c, b));
        bytes.extend(skippable(1, b"trailing"));
        let mut s = src(bytes.clone());
        assert!(s.info().compressed);
        assert_eq!(
            read_all(s.as_mut()),
            read_all(src(raw.clone()).as_mut()),
            "{c:?}"
        );
        assert_eq!(s.bytes_read(), u64::try_from(bytes.len()).unwrap());
    }
}

#[test]
fn leading_skippable_frames_are_bounded() {
    let raw = plain(&traffic(), false);
    for c in CODECS {
        // 2 MiB of skippable data before the first frame: not probed as a capture.
        let mut bytes = skippable(0, &vec![0; 2 * 1024 * 1024]);
        bytes.extend(compress(c, &raw));
        assert!(matches!(
            from_reader(Cursor::new(bytes)),
            Err(CaptureError::UnknownFormat)
        ));
    }
    // Only skippable frames, or a skippable frame cut short.
    for bytes in [
        skippable(0, b"abc"),
        skippable(0, &[1; 64])[..20].to_vec(),
        [skippable(0, b""), skippable(1, b"")].concat(),
    ] {
        assert!(matches!(
            from_reader(Cursor::new(bytes)),
            Err(CaptureError::UnknownFormat)
        ));
    }
}

#[test]
fn truncated_streams_are_a_truncated_tail() {
    let raw = plain(&big_traffic(), true);
    let total = read_all(src(raw.clone()).as_mut()).len();
    for (c, bytes) in streamable(&raw) {
        for cut in [bytes.len() / 2, bytes.len() * 9 / 10, bytes.len() - 1] {
            let mut s = src(bytes[..cut].to_vec());
            let (count, error) = read_until_error(s.as_mut());
            assert!(error.is_none(), "{c:?} cut {cut}: {error:?}");
            // Cut inside the final checksum: every packet is out, the cut is still reported.
            let all = cut == bytes.len() - 1;
            assert!(
                count > 0 && (count < total || all),
                "{c:?} cut {cut}: {count}"
            );
            assert!(
                matches!(s.warnings(), [ReadWarning::TruncatedTail { .. }]),
                "{c:?} cut {cut}: {:?}",
                s.warnings()
            );
        }
    }
}

/// Offsets of the LZ4 block boundaries of a frame without content size nor checksums.
fn lz4_block_ends(bytes: &[u8]) -> Vec<usize> {
    let mut at = 7; // magic, FLG, BD, HC
    let mut ends = Vec::new();
    loop {
        let word = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        if word == 0 {
            return ends;
        }
        at += 4 + usize::try_from(word & 0x7fff_ffff).unwrap();
        ends.push(at);
    }
}

#[test]
fn lz4_cut_on_a_block_boundary_is_a_truncated_tail() {
    let raw = plain(&big_traffic(), true);
    let info = lz4_flex::frame::FrameInfo::new().block_size(lz4_flex::frame::BlockSize::Max64KB);
    let bytes = lz4_with(&raw, info).unwrap();
    let ends = lz4_block_ends(&bytes);
    assert!(ends.len() > 10);
    for &cut in &ends[..ends.len() - 1] {
        let mut s = src(bytes[..cut].to_vec());
        let (_, error) = read_until_error(s.as_mut());
        assert!(error.is_none(), "cut {cut}: {error:?}");
        assert!(
            matches!(s.warnings(), [ReadWarning::TruncatedTail { .. }]),
            "cut {cut}: {:?}",
            s.warnings()
        );
    }
    // Cut right after the end mark: complete.
    let mut s = src(bytes[..ends[ends.len() - 1] + 4].to_vec());
    assert_eq!(read_until_error(s.as_mut()).1.map(|e| e.to_string()), None);
    assert_eq!(s.warnings(), []);
}

#[test]
fn small_truncated_zstd_file_is_malformed_not_unknown() {
    // The whole content stays in the decoder window: nothing is released before the cut.
    let bytes = zstd(&plain(&traffic()[..3], false));
    let cut = bytes[..bytes.len() - 6].to_vec();
    match from_reader(Cursor::new(cut)) {
        Err(CaptureError::Malformed { reason, .. }) => {
            assert!(reason.contains("zstd stream cut short"), "{reason}");
        }
        Ok(mut s) => {
            // Or the header got out: then the end is a truncated tail.
            let (_, error) = read_until_error(s.as_mut());
            assert!(error.is_none());
            assert!(matches!(s.warnings(), [ReadWarning::TruncatedTail { .. }]));
        }
        Err(e) => panic!("{e:?}"),
    }
}

#[test]
fn corrupt_streams_are_malformed_then_end() {
    let raw = plain(&big_traffic(), false);
    for (c, bytes) in streamable(&raw) {
        // Content checksum (last 4 bytes of the frame).
        let mut bad_sum = bytes.clone();
        let n = bad_sum.len();
        bad_sum[n - 2] ^= 0x55;
        // Garbage after the last frame.
        let mut trailing = bytes.clone();
        trailing.extend(b"garbage!");
        for (label, bad) in [("checksum", bad_sum), ("trailing", trailing)] {
            let mut s = src(bad);
            let (count, error) = read_until_error(s.as_mut());
            assert!(count > 0, "{c:?} {label}");
            match error {
                Some(CaptureError::Malformed { reason, .. }) => {
                    let name = if c == Compress::Zstd { "zstd" } else { "lz4" };
                    assert!(
                        reason.starts_with(&format!("corrupt {name} stream")),
                        "{reason}"
                    );
                }
                other => panic!("{c:?} {label}: {other:?}"),
            }
        }
    }
}

#[test]
fn lz4_block_checksum_and_size_errors() {
    let raw = plain(&traffic(), true);
    let info = lz4_flex::frame::FrameInfo::new()
        .block_size(lz4_flex::frame::BlockSize::Max64KB)
        .block_checksums(true);
    let bytes = lz4_with(&raw, info).unwrap();
    // First block: size word at 7, data, then its checksum.
    let word = u32::from_le_bytes(bytes[7..11].try_into().unwrap());
    let len = usize::try_from(word & 0x7fff_ffff).unwrap();
    let mut bad = bytes.clone();
    bad[11 + len] ^= 1;
    assert!(matches!(
        from_reader(Cursor::new(bad)),
        Err(CaptureError::UnknownFormat)
    ));
    // A block larger than the declared maximum.
    let mut big = bytes.clone();
    big[7..11].copy_from_slice(&(64 * 1024 + 1u32).to_le_bytes());
    assert!(matches!(
        from_reader(Cursor::new(big)),
        Err(CaptureError::UnknownFormat)
    ));
    // Header checksum.
    let mut hc = bytes.clone();
    hc[6] ^= 0xff;
    assert!(matches!(
        from_reader(Cursor::new(hc)),
        Err(CaptureError::UnknownFormat)
    ));
}

/// zstd frame built by hand: raw blocks, no checksum.
fn zstd_frame(window_descriptor: u8, dict_id: Option<u8>, content: &[u8]) -> Vec<u8> {
    let mut out = ZSTD_MAGIC.to_vec();
    out.push(u8::from(dict_id.is_some()));
    out.push(window_descriptor);
    out.extend(dict_id);
    let size = u32::try_from(content.len()).unwrap();
    let header = 1 | (size << 3); // last block, raw
    out.extend(&header.to_le_bytes()[..3]);
    out.extend(content);
    out
}

#[test]
fn zstd_window_is_bounded() {
    let raw = plain(&traffic()[..2], false);
    // Window log 25 (32 MiB): accepted.
    assert_eq!(MAX_ZSTD_WINDOW, 32 * 1024 * 1024);
    let ok = zstd_frame(15 << 3, None, &raw);
    assert_eq!(read_all(src(ok).as_mut()).len(), 2);
    // Window log 26 (64 MiB): refused before any allocation, with the reason.
    for descriptor in [16 << 3, 0xff] {
        match from_reader(Cursor::new(zstd_frame(descriptor, None, &raw))) {
            Err(CaptureError::Malformed { offset: 0, reason }) => {
                assert!(
                    reason.contains("unsupported zstd stream: window"),
                    "{reason}"
                );
            }
            other => panic!("{descriptor:#x}: {:?}", other.map(|_| ())),
        }
    }
    // A later frame with a too large window ends the stream with a malformed error.
    let mut two = zstd(&raw);
    two.extend(zstd_frame(20 << 3, None, b"x"));
    let mut s = src(two);
    let (count, error) = read_until_error(s.as_mut());
    assert_eq!(count, 2);
    assert!(
        matches!(&error, Some(CaptureError::Malformed { reason, .. }) if reason.contains("window")),
        "{error:?}"
    );
}

#[test]
fn dictionaries_and_legacy_lz4_are_not_supported() {
    let raw = plain(&traffic()[..2], false);
    match from_reader(Cursor::new(zstd_frame(15 << 3, Some(7), &raw))) {
        Err(CaptureError::Malformed { reason, .. }) => assert!(reason.contains("dictionar")),
        other => panic!("{:?}", other.map(|_| ())),
    }
    // LZ4 frame with a dictionary id: FLG 0x61 (version 1, independent, dict id).
    let mut desc = vec![0x61, 0x40];
    desc.extend(7u32.to_le_bytes());
    let hc = u8::try_from((twox_hash::XxHash32::oneshot(0, &desc) >> 8) & 0xff).unwrap();
    let mut frame = LZ4_MAGIC.to_vec();
    frame.extend(&desc);
    frame.push(hc);
    frame.extend(0u32.to_le_bytes());
    match from_reader(Cursor::new(frame)) {
        Err(CaptureError::Malformed { reason, .. }) => assert!(reason.contains("dictionar")),
        other => panic!("{:?}", other.map(|_| ())),
    }
    // Legacy LZ4 (`lz4 -l`) is not detected as compressed.
    let legacy = [0x02, 0x21, 0x4c, 0x18, 0, 0, 0, 0, 0, 0, 0, 0];
    assert!(matches!(
        from_reader(Cursor::new(legacy.to_vec())),
        Err(CaptureError::UnknownFormat)
    ));
}

#[test]
fn unknown_and_nested_compressed_content() {
    let raw = plain(&traffic()[..2], true);
    let cases: Vec<Vec<u8>> = vec![
        zstd(b""),
        lz4(b"").unwrap(),
        zstd(b"definitely not a capture"),
        lz4(b"definitely not a capture").unwrap(),
        zstd(&gzip(&raw).unwrap()),
        lz4(&zstd(&raw)).unwrap(),
        gzip(&lz4(&raw).unwrap()).unwrap(),
        ZSTD_MAGIC.to_vec(),
        [&LZ4_MAGIC[..], &[0xff; 8]].concat(),
        [&ZSTD_MAGIC[..], &[0xff; 8]].concat(),
    ];
    for bytes in cases {
        let result = from_reader(Cursor::new(bytes.clone()));
        assert!(
            matches!(
                result,
                Err(CaptureError::UnknownFormat | CaptureError::Malformed { .. })
            ),
            "{:02x?}",
            &bytes[..bytes.len().min(16)]
        );
    }
    // Nested compression: recognized and refused.
    for bytes in [zstd(&gzip(&raw).unwrap()), lz4(&zstd(&raw)).unwrap()] {
        assert!(matches!(
            from_reader(Cursor::new(bytes)),
            Err(CaptureError::UnknownFormat)
        ));
    }
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
    let raw = plain(&traffic(), true);
    let reference = read_all(src(raw.clone()).as_mut());
    for c in CODECS {
        let mut s = from_reader(OneByte(Cursor::new(compress(c, &raw)))).unwrap();
        assert_eq!(read_all(s.as_mut()), reference, "{c:?}");
    }
}

#[test]
fn io_error_below_the_decoder_stays_an_io_error() {
    struct FailAfter(Cursor<Vec<u8>>);
    impl Read for FailAfter {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            match self.0.read(buf)? {
                0 => Err(std::io::Error::other("disk gone")),
                n => Ok(n),
            }
        }
    }
    let raw = plain(&big_traffic(), false);
    for (c, bytes) in streamable(&raw) {
        let mut s = from_reader(FailAfter(Cursor::new(bytes[..bytes.len() / 2].to_vec()))).unwrap();
        let (_, error) = read_until_error(s.as_mut());
        assert!(
            matches!(&error, Some(CaptureError::Io(e)) if e.to_string() == "disk gone"),
            "{c:?}: {error:?}"
        );
    }
}

fn sample(pcapng: bool) -> Vec<u8> {
    plain(&traffic()[..6], pcapng)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn never_panics_on_mutated_compressed_files(
        flips in proptest::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 1..12),
        cut in any::<prop::sample::Index>(),
        pcapng in any::<bool>(),
        zst in any::<bool>(),
    ) {
        let c = if zst { Compress::Zstd } else { Compress::Lz4 };
        let mut bytes = compress(c, &sample(pcapng));
        for (idx, value) in flips {
            let i = idx.index(bytes.len());
            bytes[i] = value;
        }
        bytes.truncate(cut.index(bytes.len() + 1));
        if let Ok(mut s) = from_reader(Cursor::new(bytes)) {
            for _ in 0..10_000 {
                match s.next_packet() {
                    Ok(Some(_)) => {}
                    Ok(None) | Err(_) => break,
                }
            }
            let _ = s.warnings();
            let _ = s.bytes_read();
        }
    }

    #[test]
    fn never_panics_on_garbage_after_a_magic(
        tail in proptest::collection::vec(any::<u8>(), 0..2048),
        zst in any::<bool>(),
    ) {
        let mut bytes = if zst { ZSTD_MAGIC.to_vec() } else { LZ4_MAGIC.to_vec() };
        bytes.extend(tail);
        if let Ok(mut s) = from_reader(Cursor::new(bytes)) {
            for _ in 0..10_000 {
                match s.next_packet() {
                    Ok(Some(_)) => {}
                    Ok(None) | Err(_) => break,
                }
            }
        }
    }
}
