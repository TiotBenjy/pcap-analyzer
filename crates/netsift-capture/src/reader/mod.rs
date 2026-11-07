//! Single-file readers: pcap, pcapng, gzip, detection by magic number (task P1.1).
//!
//! The parsers are hand-written rather than built on `pcap-file`: that gives full control over
//! truncated tails, length caps and warnings, which matter more here than API convenience.
//!
//! Design rules (captures are hostile input):
//! - the format is detected from the magic number, never from the file extension;
//! - reading is streaming through a [`BufReader`]: memory stays bounded whatever the file size;
//! - no buffer is sized from an unchecked length field: lengths are capped first, and buffers
//!   grow with the bytes actually present in the file;
//! - timestamps are converted to `i64` nanoseconds with checked arithmetic;
//! - an incomplete last record yields [`ReadWarning::TruncatedTail`] then `Ok(None)`.

#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

mod pcap;
mod pcapng;

use std::collections::HashSet;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Cursor, Read};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use flate2::read::MultiGzDecoder;

use crate::source::{CaptureError, CaptureFormat, CaptureInfo, PacketSource, ReadWarning};

/// Largest captured packet accepted (pcap `incl_len`, pcapng packet blocks): 64 MiB.
pub const MAX_PACKET_LEN: u32 = 64 * 1024 * 1024;

/// Largest pcapng block total length accepted before the framing is declared corrupt: 256 MiB.
/// Blocks that are skipped (unknown types) are streamed, never buffered.
pub const MAX_BLOCK_LEN: u32 = 256 * 1024 * 1024;

/// Maximum number of warnings kept per file; further warnings are dropped (bounded memory).
pub const MAX_WARNINGS: usize = 10_000;

/// Read buffer size of the underlying stream.
const BUF_CAPACITY: usize = 256 * 1024;

/// Initial capacity cap of packet buffers: larger buffers grow with the data actually read.
const INITIAL_ALLOC_CAP: usize = 64 * 1024;

/// Bytes needed to recognize every supported format (pcapng: block type, length, byte order).
const PREFIX_LEN: usize = 12;

const GZIP_MAGIC: [u8; 2] = [0x1f, 0x8b];

/// Opens a capture file, detecting pcap, pcapng and gzip-compressed variants by magic number.
pub fn open(path: &Path) -> Result<Box<dyn PacketSource>, CaptureError> {
    let file = File::open(path)?;
    from_reader(file)
}

/// Same as [`open`] on any byte stream (tests, in-memory data).
///
/// [`PacketSource::bytes_read`] counts the bytes consumed from `reader` itself, i.e. the
/// compressed bytes when the stream is gzip.
pub fn from_reader<R: Read + Send + 'static>(
    reader: R,
) -> Result<Box<dyn PacketSource>, CaptureError> {
    let counter = Arc::new(AtomicU64::new(0));
    let mut counted = CountingReader {
        inner: reader,
        counter: Arc::clone(&counter),
    };
    let prefix = read_prefix(&mut counted)?;

    if prefix.starts_with(&GZIP_MAGIC) {
        let mut decoder = MultiGzDecoder::new(Cursor::new(prefix).chain(counted));
        let inner = match read_prefix(&mut decoder) {
            Ok(inner) => inner,
            // A broken gzip header means this is not a capture we can read.
            Err(CaptureError::Io(e))
                if matches!(
                    e.kind(),
                    io::ErrorKind::InvalidInput | io::ErrorKind::InvalidData
                ) =>
            {
                return Err(CaptureError::UnknownFormat);
            }
            Err(e) => return Err(e),
        };
        // Nested gzip is not supported.
        if inner.starts_with(&GZIP_MAGIC) {
            return Err(CaptureError::UnknownFormat);
        }
        let format = detect(&inner).ok_or(CaptureError::UnknownFormat)?;
        build(
            format,
            Box::new(Cursor::new(inner).chain(decoder)),
            counter,
            true,
        )
    } else {
        let format = detect(&prefix).ok_or(CaptureError::UnknownFormat)?;
        build(
            format,
            Box::new(Cursor::new(prefix).chain(counted)),
            counter,
            false,
        )
    }
}

/// Recognizes the container from the first bytes of the (decompressed) stream.
fn detect(prefix: &[u8]) -> Option<CaptureFormat> {
    let magic = prefix.get(..4)?;
    match magic {
        [0xd4, 0xc3, 0xb2, 0xa1]
        | [0xa1, 0xb2, 0xc3, 0xd4]
        | [0x4d, 0x3c, 0xb2, 0xa1]
        | [0xa1, 0xb2, 0x3c, 0x4d] => Some(CaptureFormat::Pcap),
        [0x0a, 0x0d, 0x0d, 0x0a] => {
            let bom = prefix.get(8..12)?;
            pcapng::byte_order(bom).map(|_| CaptureFormat::PcapNg)
        }
        _ => None,
    }
}

fn build(
    format: CaptureFormat,
    stream: Box<dyn Read + Send>,
    counter: Arc<AtomicU64>,
    compressed: bool,
) -> Result<Box<dyn PacketSource>, CaptureError> {
    let core = Core::new(Input::new(stream), counter, format, compressed);
    Ok(match format {
        CaptureFormat::Pcap => Box::new(pcap::PcapReader::open(core)?),
        CaptureFormat::PcapNg => Box::new(pcapng::PcapNgReader::open(core)?),
    })
}

/// Reads up to [`PREFIX_LEN`] bytes (fewer at end of stream).
fn read_prefix<R: Read>(reader: &mut R) -> Result<Vec<u8>, CaptureError> {
    let mut buf = [0u8; PREFIX_LEN];
    let mut filled = 0;
    while let Some(dst) = buf.get_mut(filled..) {
        if dst.is_empty() {
            break;
        }
        match reader.read(dst) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(buf.get(..filled).unwrap_or_default().to_vec())
}

/// Counts bytes pulled from the file on disk (below the decompressor), for progress reporting.
struct CountingReader<R> {
    inner: R,
    counter: Arc<AtomicU64>,
}

impl<R: Read> Read for CountingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.counter
            .fetch_add(u64::try_from(n).unwrap_or(u64::MAX), Ordering::Relaxed);
        Ok(n)
    }
}

/// Buffered (decompressed) input stream that tracks its byte position.
///
/// A premature end of stream reported by the decompressor (`UnexpectedEof`, a truncated `.gz`)
/// is treated like an end of file and remembered, so that it surfaces as a truncated tail even
/// when it falls on a record boundary.
struct Input {
    inner: BufReader<Box<dyn Read + Send>>,
    pos: u64,
    cut_short: bool,
}

impl Input {
    fn new(stream: Box<dyn Read + Send>) -> Self {
        Self {
            inner: BufReader::with_capacity(BUF_CAPACITY, stream),
            pos: 0,
            cut_short: false,
        }
    }

    /// Fills `buf` as far as possible; returns the number of bytes read (short at end of file).
    fn read_full(&mut self, buf: &mut [u8]) -> Result<usize, CaptureError> {
        let mut filled = 0;
        while let Some(dst) = buf.get_mut(filled..) {
            if dst.is_empty() {
                break;
            }
            match self.inner.read(dst) {
                Ok(0) => break,
                Ok(n) => filled += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                    self.cut_short = true;
                    break;
                }
                Err(e) => return Err(e.into()),
            }
        }
        self.advance(filled);
        Ok(filled)
    }

    /// Reads up to `len` bytes into a new buffer; shorter only at end of file.
    ///
    /// The initial allocation is capped: the buffer grows with the data actually present, so a
    /// lying length on a short file never triggers a large allocation.
    fn read_vec(&mut self, len: usize) -> Result<Vec<u8>, CaptureError> {
        let mut buf = Vec::with_capacity(len.min(INITIAL_ALLOC_CAP));
        let limit = u64::try_from(len).unwrap_or(u64::MAX);
        match Read::by_ref(&mut self.inner)
            .take(limit)
            .read_to_end(&mut buf)
        {
            Ok(_) => {}
            // Bytes read before the error are kept in `buf`.
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => self.cut_short = true,
            Err(e) => return Err(e.into()),
        }
        self.advance(buf.len());
        Ok(buf)
    }

    /// Skips up to `len` bytes without buffering them; returns the number skipped.
    fn skip(&mut self, len: u64) -> Result<u64, CaptureError> {
        let mut left = len;
        while left > 0 {
            let available = match self.inner.fill_buf() {
                Ok(chunk) => chunk.len(),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                    self.cut_short = true;
                    0
                }
                Err(e) => return Err(e.into()),
            };
            if available == 0 {
                break;
            }
            let step = usize::try_from(left).map_or(available, |l| l.min(available));
            self.inner.consume(step);
            self.advance(step);
            left -= u64::try_from(step).unwrap_or(left);
        }
        Ok(len - left)
    }

    fn advance(&mut self, n: usize) {
        self.pos = self
            .pos
            .saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
    }
}

/// State shared by the pcap and pcapng readers.
struct Core {
    input: Input,
    info: CaptureInfo,
    seen_linktypes: HashSet<u32>,
    counter: Arc<AtomicU64>,
    warnings: Vec<ReadWarning>,
    previous_ts: Option<i64>,
    done: bool,
}

impl Core {
    fn new(input: Input, counter: Arc<AtomicU64>, format: CaptureFormat, compressed: bool) -> Self {
        Self {
            input,
            info: CaptureInfo {
                format,
                compressed,
                linktypes: Vec::new(),
                snaplen: None,
            },
            seen_linktypes: HashSet::new(),
            counter,
            warnings: Vec::new(),
            previous_ts: None,
            done: false,
        }
    }

    fn warn(&mut self, warning: ReadWarning) {
        if self.warnings.len() < MAX_WARNINGS {
            self.warnings.push(warning);
        }
    }

    fn skipped(&mut self, offset: u64, reason: impl Into<String>) {
        self.warn(ReadWarning::SkippedRecord {
            offset,
            reason: reason.into(),
        });
    }

    /// Records a new link type (distinct values, in order of first appearance).
    fn add_linktype(&mut self, linktype: u32) {
        if self.seen_linktypes.insert(linktype) {
            self.info.linktypes.push(linktype);
        }
    }

    /// Emits [`ReadWarning::TimestampBackwards`] when `ts_ns` goes back in time.
    fn check_order(&mut self, offset: u64, ts_ns: i64) {
        if let Some(previous_ns) = self.previous_ts
            && ts_ns < previous_ns
        {
            self.warn(ReadWarning::TimestampBackwards {
                offset,
                previous_ns,
                ts_ns,
            });
        }
        self.previous_ts = Some(ts_ns);
    }

    /// Ends reading at the end of the stream, on a record boundary: a clean end, unless the
    /// decompressor reported that its input was cut short.
    fn end_of_stream(&mut self, offset: u64) {
        if self.input.cut_short {
            self.truncated(offset);
        } else {
            self.done = true;
        }
    }

    /// Ends reading after an incomplete last record.
    fn truncated(&mut self, offset: u64) {
        self.warn(ReadWarning::TruncatedTail { offset });
        self.done = true;
    }

    /// Ends reading on a fatal format error.
    fn malformed(&mut self, offset: u64, reason: impl Into<String>) -> CaptureError {
        self.done = true;
        CaptureError::Malformed {
            offset,
            reason: reason.into(),
        }
    }

    fn bytes_read(&self) -> u64 {
        self.counter.load(Ordering::Relaxed)
    }
}

/// Byte order of a pcap file or pcapng section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Endian {
    Little,
    Big,
}

impl Endian {
    fn u16_at(self, buf: &[u8], at: usize) -> Option<u16> {
        let bytes = field::<2>(buf, at)?;
        Some(match self {
            Self::Little => u16::from_le_bytes(bytes),
            Self::Big => u16::from_be_bytes(bytes),
        })
    }

    fn u32_at(self, buf: &[u8], at: usize) -> Option<u32> {
        let bytes = field::<4>(buf, at)?;
        Some(match self {
            Self::Little => u32::from_le_bytes(bytes),
            Self::Big => u32::from_be_bytes(bytes),
        })
    }

    fn i64_at(self, buf: &[u8], at: usize) -> Option<i64> {
        let bytes = field::<8>(buf, at)?;
        Some(match self {
            Self::Little => i64::from_le_bytes(bytes),
            Self::Big => i64::from_be_bytes(bytes),
        })
    }
}

/// Copies `N` bytes at `at`, or `None` when out of bounds.
fn field<const N: usize>(buf: &[u8], at: usize) -> Option<[u8; N]> {
    buf.get(at..at.checked_add(N)?)?.try_into().ok()
}
