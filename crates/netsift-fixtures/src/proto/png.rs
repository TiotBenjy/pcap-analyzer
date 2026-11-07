//! Deterministic, valid PNG images (8-bit RGB, zlib-compressed, CRC-checked chunks).

use std::io::Write as _;

use flate2::Compression;
use flate2::write::ZlibEncoder;

/// PNG file signature.
pub const PNG_SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];

/// A `width` x `height` RGB gradient, identical for identical arguments.
///
/// # Panics
/// If a dimension is zero.
pub fn png_image(width: u32, height: u32) -> Vec<u8> {
    assert!(width > 0 && height > 0, "PNG dimensions must be non-zero");
    let mut raw = Vec::new();
    for y in 0..height {
        raw.push(0); // filter type: None
        for x in 0..width {
            raw.push(channel(x * 255 / width));
            raw.push(channel(y * 255 / height));
            raw.push(channel((x + y) * 7 % 256));
        }
    }
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&raw).expect("in-memory write");
    let idat = encoder.finish().expect("in-memory write");

    let mut ihdr = Vec::with_capacity(13);
    ihdr.extend_from_slice(&width.to_be_bytes());
    ihdr.extend_from_slice(&height.to_be_bytes());
    // Bit depth 8, colour type 2 (RGB), compression 0, filter 0, interlace 0.
    ihdr.extend_from_slice(&[8, 2, 0, 0, 0]);

    let mut out = PNG_SIGNATURE.to_vec();
    push_chunk(&mut out, *b"IHDR", &ihdr);
    push_chunk(&mut out, *b"IDAT", &idat);
    push_chunk(&mut out, *b"IEND", &[]);
    out
}

fn channel(v: u32) -> u8 {
    u8::try_from(v.min(255)).unwrap_or(u8::MAX)
}

fn push_chunk(out: &mut Vec<u8>, kind: [u8; 4], data: &[u8]) {
    let len = u32::try_from(data.len()).expect("chunk fits in u32");
    out.extend_from_slice(&len.to_be_bytes());
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(&kind);
    hasher.update(data);
    out.extend_from_slice(&kind);
    out.extend_from_slice(data);
    out.extend_from_slice(&hasher.finalize().to_be_bytes());
}
