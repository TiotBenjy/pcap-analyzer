//! Streaming decompression of compressed capture files: gzip (`flate2`), zstd (`ruzstd`) and
//! the LZ4 frame format of the `lz4` tool (frame layer here, blocks decoded by `lz4_flex`).
//!
//! Every decoder is a [`Read`] adapter with bounded memory, whatever the file size:
//! - zstd: at most [`MAX_ZSTD_WINDOW`] of history per stream; larger windows are refused before
//!   any allocation (`zstd --long` or `--ultra` levels 21 and 22 exceed it);
//! - LZ4: one block (at most 4 MiB, as declared by the frame and checked) plus 64 KiB of
//!   history in linked-block mode.
//!
//! Errors use [`io::ErrorKind`] so that the reader maps them uniformly:
//! - `UnexpectedEof`: the compressed stream was cut short (file still being written);
//! - `InvalidData`: corrupt stream (bad block, checksum mismatch, garbage after the last frame);
//! - `Unsupported`: valid but outside our bounds (window too large, dictionary, legacy LZ4).
//!
//! Skippable frames (same layout in zstd and LZ4) are skipped by streaming, never buffered.
//! Known limit: `ruzstd` releases the last window of a zstd frame only when the frame ends, so
//! a truncated zstd file loses up to one window of decoded data before its truncation point.

use std::hash::Hasher as _;
use std::io::{self, Cursor, Read};

use ruzstd::decoding::errors::{FrameDecoderError, FrameHeaderError};
use ruzstd::decoding::{BlockDecodingStrategy, FrameDecoder};
use twox_hash::XxHash32;

/// Compression of a capture file, detected from its magic number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Codec {
    Gzip,
    Zstd,
    Lz4,
}

impl Codec {
    /// Recognizes a compressed stream from its first bytes.
    pub(crate) fn detect(prefix: &[u8]) -> Option<Self> {
        if prefix.starts_with(&GZIP_MAGIC) {
            Some(Self::Gzip)
        } else if prefix.starts_with(&ZSTD_MAGIC) {
            Some(Self::Zstd)
        } else if prefix.starts_with(&LZ4_MAGIC) {
            Some(Self::Lz4)
        } else {
            None
        }
    }

    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Gzip => "gzip",
            Self::Zstd => "zstd",
            Self::Lz4 => "lz4",
        }
    }
}

pub(crate) const GZIP_MAGIC: [u8; 2] = [0x1f, 0x8b];
/// zstd frame magic 0xFD2FB528, little endian.
pub(crate) const ZSTD_MAGIC: [u8; 4] = [0x28, 0xb5, 0x2f, 0xfd];
/// LZ4 frame magic 0x184D2204, little endian.
pub(crate) const LZ4_MAGIC: [u8; 4] = [0x04, 0x22, 0x4d, 0x18];
/// Legacy LZ4 format (`lz4 -l`), not supported.
const LZ4_LEGACY_MAGIC: [u8; 4] = [0x02, 0x21, 0x4c, 0x18];

/// Largest zstd window accepted: 32 MiB (window log 25). Covers every level of the `zstd`
/// tool up to `--ultra -20`; the reference decoder itself refuses more than 128 MiB by default.
pub const MAX_ZSTD_WINDOW: u64 = 32 * 1024 * 1024;

/// History kept between linked LZ4 blocks (format constant).
const LZ4_WINDOW: usize = 64 * 1024;

/// Skippable frame magic (0x184D2A50 to 0x184D2A5F, little endian), shared by zstd and LZ4.
pub(crate) fn is_skippable(magic: &[u8]) -> bool {
    matches!(magic, [m, 0x2a, 0x4d, 0x18, ..] if m & 0xf0 == 0x50)
}

pub(crate) fn truncated() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "compressed stream cut short")
}

fn corrupt(reason: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason.into())
}

fn unsupported(reason: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, reason.into())
}

/// Fills `buf` as far as the stream allows; returns the number of bytes read.
fn read_up_to<R: Read + ?Sized>(r: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while let Some(dst) = buf.get_mut(filled..) {
        if dst.is_empty() {
            break;
        }
        match r.read(dst) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

/// Reads exactly `buf.len()` bytes; a short read is a truncated stream.
fn read_exact_or_cut<R: Read + ?Sized>(r: &mut R, buf: &mut [u8]) -> io::Result<()> {
    if read_up_to(r, buf)? == buf.len() {
        Ok(())
    } else {
        Err(truncated())
    }
}

fn read_u32_le<R: Read + ?Sized>(r: &mut R) -> io::Result<u32> {
    let mut b = [0u8; 4];
    read_exact_or_cut(r, &mut b)?;
    Ok(u32::from_le_bytes(b))
}

/// Discards `len` bytes without buffering them; a short stream is a truncated stream.
pub(crate) fn skip<R: Read + ?Sized>(r: &mut R, len: u64) -> io::Result<()> {
    let copied = io::copy(&mut r.take(len), &mut io::sink())?;
    if copied == len {
        Ok(())
    } else {
        Err(truncated())
    }
}

/// Outcome of reading the magic number of the next frame.
enum NextFrame {
    /// Clean end of stream on a frame boundary.
    End,
    /// Magic number of a frame that is not skippable.
    Magic([u8; 4]),
}

/// Reads the next frame magic, skipping skippable frames.
fn next_frame<R: Read + ?Sized>(r: &mut R) -> io::Result<NextFrame> {
    loop {
        let mut magic = [0u8; 4];
        match read_up_to(r, &mut magic)? {
            0 => return Ok(NextFrame::End),
            4 => {}
            _ => return Err(truncated()),
        }
        if !is_skippable(&magic) {
            return Ok(NextFrame::Magic(magic));
        }
        let len = read_u32_le(r)?;
        skip(r, u64::from(len))?;
    }
}

/// Remembers whether the underlying stream reached its end, to tell a truncated zstd stream
/// (`ruzstd` reports both truncation and corruption as decoding errors) from a corrupt one, and
/// keeps an I/O error of the underlying stream, which `ruzstd` would turn into a decoding error.
struct EofTracker<R> {
    inner: R,
    eof: bool,
    failed: Option<io::Error>,
}

impl<R: Read> Read for EofTracker<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.inner.read(buf) {
            Ok(n) => {
                if n == 0 && !buf.is_empty() {
                    self.eof = true;
                }
                Ok(n)
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => Err(e),
            Err(e) => {
                let copy = io::Error::new(e.kind(), e.to_string());
                self.failed = Some(e);
                Err(copy)
            }
        }
    }
}

/// zstd decoder: concatenated frames, skippable frames, content checksums verified.
pub(crate) struct ZstdReader<R> {
    src: EofTracker<R>,
    /// Decoder of the current frame; a new one per frame, so that the window of a frame is
    /// allocated as data is decoded rather than reserved up front.
    frame: Option<FrameDecoder>,
    done: bool,
}

impl<R: Read> ZstdReader<R> {
    pub(crate) fn new(inner: R) -> Self {
        Self {
            src: EofTracker {
                inner,
                eof: false,
                failed: None,
            },
            frame: None,
            done: false,
        }
    }

    /// Starts the next frame; `false` at the clean end of the stream.
    fn start_frame(&mut self) -> io::Result<bool> {
        let magic = match next_frame(&mut self.src)? {
            NextFrame::End => return Ok(false),
            NextFrame::Magic(magic) => magic,
        };
        if magic != ZSTD_MAGIC {
            return Err(corrupt("unexpected data after the last frame"));
        }
        let mut frame = FrameDecoder::new();
        frame.set_max_window_size(MAX_ZSTD_WINDOW);
        let header = Cursor::new(magic).chain(&mut self.src);
        if let Err(e) = frame.init(header) {
            return Err(self.decode_error(e));
        }
        self.frame = Some(frame);
        Ok(true)
    }

    fn decode_error(&mut self, e: FrameDecoderError) -> io::Error {
        if let Some(failed) = self.src.failed.take() {
            return failed;
        }
        let window = |requested: u64| {
            unsupported(format!(
                "window of {} MiB exceeds the {} MiB limit",
                requested.div_ceil(1024 * 1024),
                MAX_ZSTD_WINDOW / (1024 * 1024)
            ))
        };
        match e {
            FrameDecoderError::WindowSizeTooBig { requested, .. } => window(requested),
            FrameDecoderError::FrameHeaderError(FrameHeaderError::WindowTooBig { got })
            | FrameDecoderError::FailedToInitialize(FrameHeaderError::WindowTooBig { got }) => {
                window(got)
            }
            FrameDecoderError::DictNotProvided { .. } => {
                unsupported("dictionaries are not supported")
            }
            _ if self.src.eof => truncated(),
            other => corrupt(other.to_string()),
        }
    }

    /// Next decoded bytes, or `Ok(0)` at the clean end of the stream.
    fn read_inner(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let Some(frame) = self.frame.as_mut() else {
                if self.start_frame()? {
                    continue;
                }
                return Ok(0);
            };
            if frame.can_collect() > 0 {
                let n = frame.read(buf)?;
                if n > 0 {
                    return Ok(n);
                }
            }
            if frame.is_finished() {
                // Every byte of the frame has been read: the computed checksum is final.
                if let (Some(stored), Some(computed)) = (
                    frame.get_checksum_from_data(),
                    frame.get_calculated_checksum(),
                ) && stored != computed
                {
                    return Err(corrupt("content checksum mismatch"));
                }
                self.frame = None;
                continue;
            }
            if let Err(e) = frame.decode_blocks(&mut self.src, BlockDecodingStrategy::UptoBlocks(1))
            {
                return Err(self.decode_error(e));
            }
        }
    }
}

impl<R: Read> Read for ZstdReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.done || buf.is_empty() {
            return Ok(0);
        }
        let result = self.read_inner(buf);
        // Any error, or the end, is final.
        if matches!(result, Ok(0) | Err(_)) {
            self.done = true;
            self.frame = None;
        }
        result
    }
}

/// Parameters of the current LZ4 frame.
struct Lz4Frame {
    max_block: usize,
    linked: bool,
    block_checksum: bool,
    content_checksum: bool,
    content_size: Option<u64>,
    decoded: u64,
    hasher: XxHash32,
}

/// LZ4 frame decoder (format of the `lz4` tool): concatenated frames, skippable frames,
/// independent or linked blocks, header, block and content checksums verified.
pub(crate) struct Lz4Reader<R> {
    src: R,
    frame: Option<Lz4Frame>,
    /// Compressed bytes of the current block.
    block: Vec<u8>,
    /// Decoded bytes of the current block, `out[pos..end]` not yet returned.
    out: Vec<u8>,
    pos: usize,
    end: usize,
    /// Last decoded bytes (at most 64 KiB), the dictionary of the next linked block.
    history: Vec<u8>,
    done: bool,
}

impl<R: Read> Lz4Reader<R> {
    pub(crate) fn new(src: R) -> Self {
        Self {
            src,
            frame: None,
            block: Vec::new(),
            out: Vec::new(),
            pos: 0,
            end: 0,
            history: Vec::new(),
            done: false,
        }
    }

    /// Reads the next frame header; `false` at the clean end of the stream.
    fn start_frame(&mut self) -> io::Result<bool> {
        let magic = match next_frame(&mut self.src)? {
            NextFrame::End => return Ok(false),
            NextFrame::Magic(magic) => magic,
        };
        if magic == LZ4_LEGACY_MAGIC {
            return Err(unsupported("legacy frame format (lz4 -l) is not supported"));
        }
        if magic != LZ4_MAGIC {
            return Err(corrupt("unexpected data after the last frame"));
        }
        // Frame descriptor: FLG, BD, optional content size (8) and dictionary id (4), HC.
        let mut fixed = [0u8; 2];
        read_exact_or_cut(&mut self.src, &mut fixed)?;
        let [flg, bd] = fixed;
        if flg >> 6 != 0b01 {
            return Err(corrupt("unsupported frame version"));
        }
        if flg & 0b10 != 0 || bd & 0x8f != 0 {
            return Err(corrupt("reserved frame descriptor bits set"));
        }
        let has_size = flg & 0b1000 != 0;
        let has_dict = flg & 0b1 != 0;
        let mut size = [0u8; 8];
        if has_size {
            read_exact_or_cut(&mut self.src, &mut size)?;
        }
        let mut dict = [0u8; 4];
        if has_dict {
            read_exact_or_cut(&mut self.src, &mut dict)?;
        }
        let mut hc = [0u8; 1];
        read_exact_or_cut(&mut self.src, &mut hc)?;
        let [hc] = hc;
        let mut hasher = XxHash32::with_seed(0);
        hasher.write(&fixed);
        if has_size {
            hasher.write(&size);
        }
        if has_dict {
            hasher.write(&dict);
        }
        if u32::from(hc) != (hasher.finish_32() >> 8) & 0xff {
            return Err(corrupt("frame header checksum mismatch"));
        }
        if has_dict {
            return Err(unsupported("dictionaries are not supported"));
        }
        let max_block = match (bd >> 4) & 0x7 {
            4 => 64 * 1024,
            5 => 256 * 1024,
            6 => 1024 * 1024,
            7 => 4 * 1024 * 1024,
            _ => return Err(corrupt("invalid block maximum size")),
        };
        let content_size = has_size.then(|| u64::from_le_bytes(size));
        if self.out.len() < max_block {
            self.out.resize(max_block, 0);
        }
        self.history.clear();
        self.frame = Some(Lz4Frame {
            max_block,
            linked: flg & 0b10_0000 == 0,
            block_checksum: flg & 0b1_0000 != 0,
            content_checksum: flg & 0b100 != 0,
            content_size,
            decoded: 0,
            hasher: XxHash32::with_seed(0),
        });
        Ok(true)
    }

    /// Decodes the next block of the current frame into `out` (nothing at the end mark, which
    /// closes the frame).
    fn next_block(&mut self) -> io::Result<()> {
        let Some(frame) = self.frame.as_mut() else {
            return Ok(());
        };
        // Inside a frame, the end of the stream before the end mark is a truncation.
        let word = read_u32_le(&mut self.src)?;
        if word == 0 {
            if frame.content_checksum {
                let stored = read_u32_le(&mut self.src)?;
                if stored != frame.hasher.finish_32() {
                    return Err(corrupt("content checksum mismatch"));
                }
            }
            if frame.content_size.is_some_and(|size| size != frame.decoded) {
                return Err(corrupt("content size mismatch"));
            }
            self.frame = None;
            return Ok(());
        }
        let stored_raw = word & 0x8000_0000 != 0;
        let len = usize::try_from(word & 0x7fff_ffff).unwrap_or(usize::MAX);
        if len > frame.max_block {
            return Err(corrupt("block larger than the declared maximum"));
        }
        // Bounded by the declared maximum (4 MiB at most).
        self.block.resize(len, 0);
        read_exact_or_cut(&mut self.src, &mut self.block)?;
        if frame.block_checksum {
            let stored = read_u32_le(&mut self.src)?;
            if stored != XxHash32::oneshot(0, &self.block) {
                return Err(corrupt("block checksum mismatch"));
            }
        }
        let out = self
            .out
            .get_mut(..frame.max_block)
            .ok_or_else(|| corrupt("block buffer"))?;
        let n = if stored_raw {
            let dst = out.get_mut(..len).ok_or_else(|| corrupt("block buffer"))?;
            dst.copy_from_slice(&self.block);
            len
        } else if frame.linked {
            lz4_flex::block::decompress_into_with_dict(&self.block, out, &self.history)
                .map_err(|e| corrupt(format!("block: {e}")))?
        } else {
            lz4_flex::block::decompress_into(&self.block, out)
                .map_err(|e| corrupt(format!("block: {e}")))?
        };
        let decoded = out.get(..n).ok_or_else(|| corrupt("block buffer"))?;
        frame.decoded = frame
            .decoded
            .saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
        if frame.content_size.is_some_and(|size| frame.decoded > size) {
            return Err(corrupt("content size mismatch"));
        }
        if frame.content_checksum {
            frame.hasher.write(decoded);
        }
        if frame.linked {
            keep_tail(&mut self.history, decoded, LZ4_WINDOW);
        }
        self.pos = 0;
        self.end = n;
        Ok(())
    }

    fn read_inner(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.pos < self.end {
                let available = self.out.get(self.pos..self.end).unwrap_or_default();
                let n = available.len().min(buf.len());
                if let (Some(dst), Some(src)) = (buf.get_mut(..n), available.get(..n)) {
                    dst.copy_from_slice(src);
                }
                self.pos += n;
                return Ok(n);
            }
            if self.frame.is_some() {
                self.next_block()?;
            } else if !self.start_frame()? {
                return Ok(0);
            }
        }
    }
}

impl<R: Read> Read for Lz4Reader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.done || buf.is_empty() {
            return Ok(0);
        }
        let result = self.read_inner(buf);
        if matches!(result, Ok(0) | Err(_)) {
            self.done = true;
            self.frame = None;
        }
        result
    }
}

/// Appends `data` to `history`, keeping only its last `cap` bytes.
fn keep_tail(history: &mut Vec<u8>, data: &[u8], cap: usize) {
    if data.len() >= cap {
        history.clear();
        history.extend_from_slice(data.get(data.len() - cap..).unwrap_or(data));
    } else {
        let excess = (history.len() + data.len()).saturating_sub(cap);
        history.drain(..excess.min(history.len()));
        history.extend_from_slice(data);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skippable_magic_range() {
        assert!(is_skippable(&[0x50, 0x2a, 0x4d, 0x18]));
        assert!(is_skippable(&[0x5f, 0x2a, 0x4d, 0x18, 0]));
        assert!(!is_skippable(&[0x60, 0x2a, 0x4d, 0x18]));
        assert!(!is_skippable(&[0x50, 0x2a, 0x4d]));
        assert!(!is_skippable(&LZ4_MAGIC));
    }

    #[test]
    fn history_keeps_the_last_window() {
        let mut h = Vec::new();
        keep_tail(&mut h, &[1, 2, 3], 4);
        assert_eq!(h, [1, 2, 3]);
        keep_tail(&mut h, &[4, 5], 4);
        assert_eq!(h, [2, 3, 4, 5]);
        keep_tail(&mut h, &[6, 7, 8, 9, 10], 4);
        assert_eq!(h, [7, 8, 9, 10]);
    }

    #[test]
    fn detection() {
        assert_eq!(Codec::detect(&[0x1f, 0x8b, 8]), Some(Codec::Gzip));
        assert_eq!(Codec::detect(&ZSTD_MAGIC), Some(Codec::Zstd));
        assert_eq!(Codec::detect(&LZ4_MAGIC), Some(Codec::Lz4));
        assert_eq!(Codec::detect(&LZ4_LEGACY_MAGIC), None);
        assert_eq!(Codec::detect(&[0x28, 0xb5]), None);
    }
}
