//! Message bodies: framing (length, chunked, until close), content decoding (gzip, deflate,
//! brotli) with bounded output, and retention of the decoded bytes under a per-shard budget.

use std::io::{self, Write};

use super::types::{BodyState, HttpConfig, RATIO_CHECK_MIN};

/// Longest chunk-size line (size, extensions, CRLF).
const MAX_CHUNK_LINE: usize = 4096;
/// Longest trailer section of a chunked body.
const MAX_TRAILERS: usize = 16 * 1024;
/// Most hexadecimal digits of a chunk size (a `u64`).
const MAX_CHUNK_DIGITS: usize = 16;
/// Internal buffer of the brotli decoder.
const BROTLI_BUFFER: usize = 4096;
/// Decoded bytes kept for MIME sniffing when bodies are not stored.
const SNIFF_BYTES: usize = 512;

/// Resources shared by every flow of one analyzer instance (one shard).
#[derive(Debug)]
pub(crate) struct Shared {
    pub(crate) config: HttpConfig,
    /// Decoded bytes currently retained, all bodies together.
    pub(crate) retained: usize,
    /// Content decoders alive.
    pub(crate) decoders: usize,
    /// Brotli decoders alive (also counted in `decoders`).
    pub(crate) brotli: usize,
}

impl Shared {
    pub(crate) fn new(config: HttpConfig) -> Self {
        Self {
            config,
            retained: 0,
            decoders: 0,
            brotli: 0,
        }
    }

    fn available(&self) -> usize {
        self.config.max_retained_bytes.saturating_sub(self.retained)
    }
}

/// How the end of a body is found (RFC 9112, section 6.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Framing {
    Length(u64),
    Chunked,
    UntilClose,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Chunk {
    /// Reading a chunk-size line: digits so far, value, past the digits (extension).
    Size {
        line: usize,
        digits: usize,
        value: u64,
        ext: bool,
    },
    Data(u64),
    /// After the data of a chunk: CRLF expected.
    DataEnd {
        cr: bool,
    },
    /// Trailer section: length of the current line, total read.
    Trailer {
        line: usize,
        total: usize,
    },
}

impl Chunk {
    const START: Self = Self::Size {
        line: 0,
        digits: 0,
        value: 0,
        ext: false,
    };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reading {
    Length(u64),
    Chunked(Chunk),
    UntilClose,
    Done,
    Malformed,
}

/// Result of [`BodyReader::feed`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Fed {
    /// Bytes of the input that belong to this body.
    pub(crate) used: usize,
    /// The body ended (complete or malformed).
    pub(crate) done: bool,
}

/// What a finished body yields: its figures and its decoded bytes (the retained prefix).
#[derive(Debug)]
pub(crate) struct Finished {
    pub(crate) wire_len: u64,
    pub(crate) decoded_len: u64,
    pub(crate) chunked: bool,
    pub(crate) state: BodyState,
    /// Decoded bytes kept in memory; the whole body only when `fully_retained`.
    pub(crate) data: Vec<u8>,
    pub(crate) fully_retained: bool,
}

/// Reads one body from the stream of its direction.
#[derive(Debug)]
pub(crate) struct BodyReader {
    reading: Reading,
    chunked: bool,
    wire_len: u64,
    /// Bytes were lost inside the body.
    gap: bool,
    collector: Collector,
}

impl BodyReader {
    pub(crate) fn new(framing: Framing, encoding: Option<&str>, shared: &mut Shared) -> Self {
        let reading = match framing {
            Framing::Length(0) => Reading::Done,
            Framing::Length(n) => Reading::Length(n),
            Framing::Chunked => Reading::Chunked(Chunk::START),
            Framing::UntilClose => Reading::UntilClose,
        };
        Self {
            reading,
            chunked: framing == Framing::Chunked,
            wire_len: 0,
            gap: false,
            collector: Collector::new(encoding, shared),
        }
    }

    pub(crate) fn is_done(&self) -> bool {
        matches!(self.reading, Reading::Done | Reading::Malformed)
    }

    /// Consumes the bytes of `data` that belong to the body.
    pub(crate) fn feed(&mut self, data: &[u8], shared: &mut Shared) -> Fed {
        let mut used = 0usize;
        while used < data.len() && !self.is_done() {
            let rest = data.get(used..).unwrap_or_default();
            let n = match self.reading {
                Reading::Length(remaining) => {
                    let n = take(remaining, rest.len());
                    self.collector
                        .write(rest.get(..n).unwrap_or_default(), shared);
                    let left = remaining.saturating_sub(n as u64);
                    self.reading = if left == 0 {
                        Reading::Done
                    } else {
                        Reading::Length(left)
                    };
                    n
                }
                Reading::UntilClose => {
                    self.collector.write(rest, shared);
                    rest.len()
                }
                Reading::Chunked(state) => self.chunked_step(state, rest, shared),
                Reading::Done | Reading::Malformed => 0,
            };
            used = used.saturating_add(n);
            self.wire_len = self.wire_len.saturating_add(n as u64);
        }
        Fed {
            used,
            done: self.is_done(),
        }
    }

    /// One step of the chunked decoder; returns the bytes consumed (at least one).
    fn chunked_step(&mut self, state: Chunk, rest: &[u8], shared: &mut Shared) -> usize {
        if let Chunk::Data(remaining) = state {
            let n = take(remaining, rest.len());
            self.collector
                .write(rest.get(..n).unwrap_or_default(), shared);
            let left = remaining.saturating_sub(n as u64);
            self.reading = Reading::Chunked(if left == 0 {
                Chunk::DataEnd { cr: false }
            } else {
                Chunk::Data(left)
            });
            return n;
        }
        let Some(&b) = rest.first() else {
            return 0;
        };
        self.reading = match chunk_byte(state, b) {
            Some(Step::Next(next)) => Reading::Chunked(next),
            Some(Step::End) => Reading::Done,
            None => Reading::Malformed,
        };
        1
    }

    /// `len` bytes were lost in the body. Returns false when the body cannot continue
    /// (framing lost): the caller then ends it.
    pub(crate) fn gap(&mut self, len: u64, shared: &mut Shared) -> bool {
        self.gap = true;
        self.collector.interrupt(shared);
        self.wire_len = self.wire_len.saturating_add(len);
        match self.reading {
            Reading::Length(remaining) if len < remaining => {
                self.reading = Reading::Length(remaining - len);
                true
            }
            Reading::Length(remaining) if len == remaining => {
                self.reading = Reading::Done;
                true
            }
            Reading::Chunked(Chunk::Data(remaining)) if len < remaining => {
                self.reading = Reading::Chunked(Chunk::Data(remaining - len));
                true
            }
            Reading::Chunked(Chunk::Data(remaining)) if len == remaining => {
                self.reading = Reading::Chunked(Chunk::DataEnd { cr: false });
                true
            }
            Reading::UntilClose => true,
            _ => false,
        }
    }

    /// Ends the body. `clean_end`: the connection closed normally (a body read until the
    /// close is then complete).
    pub(crate) fn finish(mut self, clean_end: bool, shared: &mut Shared) -> Finished {
        let framing_state = match self.reading {
            Reading::Done => None,
            Reading::Malformed => Some(BodyState::Malformed),
            Reading::UntilClose if clean_end => None,
            _ => Some(BodyState::Incomplete),
        };
        let complete_input = framing_state.is_none() && !self.gap;
        let decode = self.collector.finish(complete_input, shared);
        let state = if self.gap {
            // A size or ratio stop happened before the loss: it says more than the gap.
            match decode.state {
                Some(stop @ (BodyState::Truncated | BodyState::Bomb)) => stop,
                _ => BodyState::Incomplete,
            }
        } else {
            framing_state
                .or(decode.state)
                .unwrap_or(if self.wire_len == 0 && decode.total == 0 {
                    BodyState::None
                } else {
                    BodyState::Complete
                })
        };
        Finished {
            wire_len: self.wire_len,
            decoded_len: decode.total,
            chunked: self.chunked,
            state,
            fully_retained: decode.fully_retained,
            data: decode.data,
        }
    }

    /// Releases the resources of a body that is dropped without being finished.
    #[cfg(test)]
    pub(crate) fn discard(mut self, shared: &mut Shared) {
        drop(self.collector.finish(false, shared));
    }
}

fn take(remaining: u64, available: usize) -> usize {
    usize::try_from(remaining).map_or(available, |r| r.min(available))
}

enum Step {
    Next(Chunk),
    End,
}

/// Chunked framing, one byte at a time outside chunk data (lenient on bare LF line ends).
fn chunk_byte(state: Chunk, b: u8) -> Option<Step> {
    match state {
        Chunk::Size {
            line,
            digits,
            value,
            ext,
        } => {
            let line = line.saturating_add(1);
            if line > MAX_CHUNK_LINE {
                return None;
            }
            if b == b'\n' {
                return match (digits, value) {
                    (0, _) => None,
                    (_, 0) => Some(Step::Next(Chunk::Trailer { line: 0, total: 0 })),
                    (_, v) => Some(Step::Next(Chunk::Data(v))),
                };
            }
            if !ext && let Some(d) = hex(b) {
                if digits >= MAX_CHUNK_DIGITS {
                    return None;
                }
                return Some(Step::Next(Chunk::Size {
                    line,
                    digits: digits + 1,
                    value: (value << 4) | u64::from(d),
                    ext,
                }));
            }
            // Past the digits: optional whitespace, extensions, CR.
            if digits == 0 && !matches!(b, b' ' | b'\t') {
                return None;
            }
            Some(Step::Next(Chunk::Size {
                line,
                digits,
                value,
                ext: true,
            }))
        }
        Chunk::DataEnd { cr } => match b {
            b'\r' if !cr => Some(Step::Next(Chunk::DataEnd { cr: true })),
            b'\n' => Some(Step::Next(Chunk::START)),
            _ => None,
        },
        Chunk::Trailer { line, total } => {
            let total = total.saturating_add(1);
            if total > MAX_TRAILERS {
                return None;
            }
            match b {
                b'\n' if line == 0 => Some(Step::End),
                b'\n' => Some(Step::Next(Chunk::Trailer { line: 0, total })),
                // A CR alone does not start a trailer line.
                b'\r' if line == 0 => Some(Step::Next(Chunk::Trailer { line: 0, total })),
                _ => Some(Step::Next(Chunk::Trailer {
                    line: line.saturating_add(1),
                    total,
                })),
            }
        }
        Chunk::Data(_) => None,
    }
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Output of the content decoder: bounded count, retained prefix.
#[derive(Debug, Default)]
struct Sink {
    data: Vec<u8>,
    /// Decoded bytes produced (at most `limit`).
    total: u64,
    limit: u64,
    /// Still appending to `data` (stops for good once a byte was not kept).
    keep: bool,
    /// Bytes that may still be retained during the current write (shard budget).
    allowance: usize,
    /// Bytes retained during the current write.
    added: usize,
    /// Most bytes kept for this body.
    keep_cap: usize,
    truncated: bool,
}

impl Sink {
    fn new(limit: u64, keep_cap: usize) -> Self {
        Self {
            limit,
            keep: true,
            keep_cap,
            ..Self::default()
        }
    }
}

impl Write for Sink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let room = self.limit.saturating_sub(self.total);
        if room == 0 {
            self.truncated = true;
            return Err(io::Error::other("body size limit reached"));
        }
        let n = take(room, buf.len());
        let accepted = buf.get(..n).unwrap_or_default();
        if self.keep {
            let k = n
                .min(self.allowance)
                .min(self.keep_cap.saturating_sub(self.data.len()));
            self.data
                .extend_from_slice(accepted.get(..k).unwrap_or_default());
            self.allowance -= k;
            self.added = self.added.saturating_add(k);
            if k < n {
                self.keep = false;
            }
        }
        self.total = self.total.saturating_add(n as u64);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

enum Decoder {
    Identity,
    /// `deflate` before its first byte: zlib-wrapped (RFC 9110) or raw (seen in practice).
    Deflate,
    Gzip(Box<flate2::write::MultiGzDecoder<Sink>>),
    Zlib(Box<flate2::write::ZlibDecoder<Sink>>),
    RawDeflate(Box<flate2::write::DeflateDecoder<Sink>>),
    Brotli(Box<brotli_decompressor::DecompressorWriter<Sink>>),
    /// Decoding stopped (error, limit, gap); the outcome is in `Collector::stopped`.
    Stopped,
}

impl std::fmt::Debug for Decoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::Identity => "identity",
            Self::Deflate => "deflate",
            Self::Gzip(_) => "gzip",
            Self::Zlib(_) => "zlib",
            Self::RawDeflate(_) => "raw-deflate",
            Self::Brotli(_) => "brotli",
            Self::Stopped => "stopped",
        };
        f.write_str(name)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Coding {
    Identity,
    Gzip,
    Deflate,
    Brotli,
    Unsupported,
}

/// The content coding to undo, from a `Content-Encoding` value. Only one coding is decoded;
/// stacked codings are left encoded.
fn coding(value: Option<&str>) -> Coding {
    let Some(value) = value else {
        return Coding::Identity;
    };
    let mut codings = value
        .split(',')
        .map(str::trim)
        .filter(|c| !c.is_empty() && !c.eq_ignore_ascii_case("identity"));
    let (Some(first), None) = (codings.next(), codings.next()) else {
        return if value.split(',').all(|c| {
            let c = c.trim();
            c.is_empty() || c.eq_ignore_ascii_case("identity")
        }) {
            Coding::Identity
        } else {
            Coding::Unsupported
        };
    };
    match first.to_ascii_lowercase().as_str() {
        "gzip" | "x-gzip" => Coding::Gzip,
        "deflate" => Coding::Deflate,
        "br" => Coding::Brotli,
        _ => Coding::Unsupported,
    }
}

/// Decodes a body and keeps the decoded bytes, within the limits of [`HttpConfig`].
#[derive(Debug)]
struct Collector {
    decoder: Decoder,
    /// The sink, while no decoder owns it (identity, before a deflate stream starts, stopped).
    sink: Option<Sink>,
    /// Encoded bytes written so far.
    encoded: u64,
    /// Why decoding stopped, when it did.
    stopped: Option<BodyState>,
    /// A decoder slot of [`Shared::decoders`] is held.
    slot: bool,
    /// A slot of [`Shared::brotli`] is held.
    brotli_slot: bool,
}

struct Decoded {
    total: u64,
    data: Vec<u8>,
    fully_retained: bool,
    state: Option<BodyState>,
}

impl Collector {
    fn new(encoding: Option<&str>, shared: &mut Shared) -> Self {
        let config = &shared.config;
        let keep_cap = if config.store_bodies {
            usize::MAX
        } else {
            config.preview_bytes.max(SNIFF_BYTES)
        };
        let sink = Sink::new(config.max_body_bytes, keep_cap);
        let mut c = Self {
            decoder: Decoder::Identity,
            sink: None,
            encoded: 0,
            stopped: None,
            slot: false,
            brotli_slot: false,
        };
        let kind = coding(encoding);
        if kind == Coding::Identity {
            c.sink = Some(sink);
            return c;
        }
        let no_brotli = kind == Coding::Brotli && shared.brotli >= config.max_brotli_decoders;
        if kind == Coding::Unsupported || no_brotli || shared.decoders >= config.max_decoders {
            // Kept as received.
            c.sink = Some(sink);
            c.stopped = Some(BodyState::NotDecoded);
            return c;
        }
        shared.decoders = shared.decoders.saturating_add(1);
        c.slot = true;
        if kind == Coding::Brotli {
            shared.brotli = shared.brotli.saturating_add(1);
            c.brotli_slot = true;
        }
        c.decoder = match kind {
            Coding::Gzip => Decoder::Gzip(Box::new(flate2::write::MultiGzDecoder::new(sink))),
            Coding::Brotli => Decoder::Brotli(Box::new(
                brotli_decompressor::DecompressorWriter::new(sink, BROTLI_BUFFER),
            )),
            _ => {
                c.sink = Some(sink);
                Decoder::Deflate
            }
        };
        c
    }

    fn sink_mut(&mut self) -> Option<&mut Sink> {
        match &mut self.decoder {
            Decoder::Gzip(d) => Some(d.get_mut()),
            Decoder::Zlib(d) => Some(d.get_mut()),
            Decoder::RawDeflate(d) => Some(d.get_mut()),
            Decoder::Brotli(d) => Some(d.get_mut()),
            Decoder::Identity | Decoder::Deflate | Decoder::Stopped => self.sink.as_mut(),
        }
    }

    fn write(&mut self, data: &[u8], shared: &mut Shared) {
        if data.is_empty() {
            return;
        }
        if let Decoder::Deflate = self.decoder {
            self.start_deflate(data);
        }
        self.encoded = self.encoded.saturating_add(data.len() as u64);
        let available = shared.available();
        let Some(sink) = self.sink_mut() else {
            return;
        };
        sink.allowance = available;
        sink.added = 0;
        // Not decoded (identity, unsupported coding) or decoding stopped: raw bytes are only
        // counted while nothing went wrong.
        let raw_ok = self.stopped.is_none() || self.stopped == Some(BodyState::NotDecoded);
        let result = match &mut self.decoder {
            Decoder::Gzip(d) => d.write_all(data),
            Decoder::Zlib(d) => d.write_all(data),
            Decoder::RawDeflate(d) => d.write_all(data),
            Decoder::Brotli(d) => d.write_all(data),
            Decoder::Identity | Decoder::Stopped | Decoder::Deflate => match self.sink.as_mut() {
                Some(sink) if raw_ok => sink.write_all(data),
                _ => Ok(()),
            },
        };
        let (added, total, truncated) = self
            .sink_mut()
            .map_or((0, 0, false), |s| (s.added, s.total, s.truncated));
        shared.retained = shared.retained.saturating_add(added);
        if result.is_err() {
            self.stop(
                if truncated {
                    BodyState::Truncated
                } else {
                    BodyState::DecodeError
                },
                shared,
            );
        } else if total > RATIO_CHECK_MIN
            && total
                > self
                    .encoded
                    .saturating_mul(shared.config.max_decompression_ratio)
        {
            self.stop(BodyState::Bomb, shared);
        }
    }

    fn start_deflate(&mut self, first: &[u8]) {
        let Some(sink) = self.sink.take() else {
            self.decoder = Decoder::Stopped;
            return;
        };
        let zlib = match first {
            [cmf, flg, ..] => {
                cmf & 0x0F == 8
                    && cmf >> 4 <= 7
                    && (u16::from(*cmf) << 8 | u16::from(*flg)) % 31 == 0
            }
            [cmf] => cmf & 0x0F == 8 && cmf >> 4 <= 7,
            [] => false,
        };
        self.decoder = if zlib {
            Decoder::Zlib(Box::new(flate2::write::ZlibDecoder::new(sink)))
        } else {
            Decoder::RawDeflate(Box::new(flate2::write::DeflateDecoder::new(sink)))
        };
    }

    /// Stops decoding for good and keeps the output produced so far.
    fn stop(&mut self, reason: BodyState, shared: &mut Shared) {
        if self.stopped.is_none() || self.stopped == Some(BodyState::NotDecoded) {
            self.stopped = Some(reason);
        }
        let decoder = std::mem::replace(&mut self.decoder, Decoder::Stopped);
        let sink = match decoder {
            Decoder::Gzip(mut d) => Some(std::mem::take(d.get_mut())),
            Decoder::Zlib(mut d) => Some(std::mem::take(d.get_mut())),
            Decoder::RawDeflate(mut d) => Some(std::mem::take(d.get_mut())),
            Decoder::Brotli(mut d) => Some(std::mem::take(d.get_mut())),
            Decoder::Identity | Decoder::Deflate | Decoder::Stopped => None,
        };
        if let Some(sink) = sink {
            self.sink = Some(sink);
        }
        self.release_slot(shared);
    }

    fn release_slot(&mut self, shared: &mut Shared) {
        if self.slot {
            self.slot = false;
            shared.decoders = shared.decoders.saturating_sub(1);
        }
        if self.brotli_slot {
            self.brotli_slot = false;
            shared.brotli = shared.brotli.saturating_sub(1);
        }
    }

    /// Bytes are missing: a compressed stream cannot go on, raw bytes stop being kept.
    fn interrupt(&mut self, shared: &mut Shared) {
        match self.decoder {
            Decoder::Identity => {
                if let Some(s) = self.sink.as_mut() {
                    s.keep = false;
                }
            }
            Decoder::Stopped => {}
            _ => {
                let state = self.stopped.unwrap_or(BodyState::Incomplete);
                self.stop(state, shared);
                self.stopped = Some(state);
            }
        }
    }

    /// Flushes the decoder. `complete_input`: every encoded byte was received.
    fn finish(&mut self, complete_input: bool, shared: &mut Shared) -> Decoded {
        let available = shared.available();
        if let Some(s) = self.sink_mut() {
            s.allowance = available;
            s.added = 0;
        }
        let flushed = match &mut self.decoder {
            Decoder::Gzip(d) => Some(d.try_finish()),
            Decoder::Zlib(d) => Some(d.try_finish()),
            Decoder::RawDeflate(d) => Some(d.try_finish()),
            Decoder::Brotli(d) => Some(d.close()),
            Decoder::Identity | Decoder::Deflate | Decoder::Stopped => None,
        };
        let added = self.sink_mut().map_or(0, |s| s.added);
        shared.retained = shared.retained.saturating_add(added);
        if let Some(Err(_)) = flushed {
            let truncated = self.sink_mut().is_some_and(|s| s.truncated);
            let reason = match (truncated, complete_input) {
                (true, _) => BodyState::Truncated,
                (false, true) => BodyState::DecodeError,
                (false, false) => BodyState::Incomplete,
            };
            self.stop(reason, shared);
        } else {
            self.stop(self.stopped.unwrap_or(BodyState::Complete), shared);
        }
        let sink = self.sink.take().unwrap_or_default();
        shared.retained = shared.retained.saturating_sub(sink.data.len());
        let state = match self.stopped {
            Some(BodyState::Complete) => None,
            other => other,
        };
        Decoded {
            total: sink.total,
            fully_retained: sink.keep && !sink.truncated,
            data: sink.data,
            state,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Bodies stored (fully retained), as P3.6 will configure it.
    fn storing() -> HttpConfig {
        HttpConfig {
            store_bodies: true,
            ..HttpConfig::default()
        }
    }

    fn shared() -> Shared {
        Shared::new(storing())
    }

    fn read_all(
        framing: Framing,
        encoding: Option<&str>,
        input: &[u8],
        step: usize,
    ) -> (Finished, usize) {
        let mut sh = shared();
        let mut r = BodyReader::new(framing, encoding, &mut sh);
        let mut used = 0;
        for piece in input.chunks(step.max(1)) {
            if r.is_done() {
                break;
            }
            used += r.feed(piece, &mut sh).used;
        }
        let f = r.finish(true, &mut sh);
        assert_eq!(sh.retained, 0, "budget released");
        assert_eq!(sh.decoders, 0, "decoder slot released");
        assert_eq!(sh.brotli, 0, "brotli slot released");
        (f, used)
    }

    #[test]
    fn content_length_stops_at_the_end() {
        let (f, used) = read_all(Framing::Length(5), None, b"helloGET /", 3);
        assert_eq!(used, 5);
        assert_eq!(f.data, b"hello");
        assert_eq!(f.state, BodyState::Complete);
        assert_eq!((f.wire_len, f.decoded_len), (5, 5));
    }

    #[test]
    fn chunked_with_extensions_and_trailers_byte_by_byte() {
        let wire = b"4;name=v\r\nWiki\r\n5\r\npedia\r\nE\r\n in\r\n\r\nchunks.\r\n0\r\nExpires: x\r\n\r\nNEXT";
        for step in [1, 2, 7, 1000] {
            let (f, used) = read_all(Framing::Chunked, None, wire, step);
            assert_eq!(used, wire.len() - 4, "step {step}");
            assert_eq!(f.data, b"Wikipedia in\r\n\r\nchunks.");
            assert_eq!(f.state, BodyState::Complete);
            assert!(f.chunked);
        }
    }

    #[test]
    fn chunked_accepts_bare_lf() {
        let (f, _) = read_all(Framing::Chunked, None, b"3\nabc\n0\n\n", 100);
        assert_eq!(f.data, b"abc");
        assert_eq!(f.state, BodyState::Complete);
    }

    #[test]
    fn malformed_chunked_is_reported() {
        for wire in [
            &b"zz\r\nabc"[..],
            b"3\r\nabcX\r\n",
            b"11111111111111111\r\n",
            b"\r\n",
        ] {
            let mut sh = shared();
            let mut r = BodyReader::new(Framing::Chunked, None, &mut sh);
            let fed = r.feed(wire, &mut sh);
            assert!(fed.done, "{wire:?}");
            assert_eq!(r.finish(true, &mut sh).state, BodyState::Malformed);
        }
        // An endless chunk-size line is bounded.
        let mut sh = shared();
        let mut r = BodyReader::new(Framing::Chunked, None, &mut sh);
        let long = [b' '; MAX_CHUNK_LINE + 10];
        let mut line = b"1".to_vec();
        line.extend_from_slice(&long);
        assert!(r.feed(&line, &mut sh).done);
    }

    #[test]
    fn huge_chunk_size_does_not_allocate() {
        let mut sh = shared();
        let mut r = BodyReader::new(Framing::Chunked, None, &mut sh);
        let fed = r.feed(b"FFFFFFFFFFFFFFFF\r\nabc", &mut sh);
        assert!(!fed.done);
        let f = r.finish(true, &mut sh);
        assert_eq!(f.state, BodyState::Incomplete);
        assert_eq!(f.data, b"abc");
    }

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    fn brotli(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        {
            let mut w = brotli::CompressorWriter::new(&mut out, 4096, 9, 22);
            w.write_all(data).unwrap();
        }
        out
    }

    #[test]
    fn gzip_deflate_and_brotli_are_decoded_incrementally() {
        let text = b"The quick brown fox jumps over the lazy dog. ".repeat(50);
        let mut zlib = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
        zlib.write_all(&text).unwrap();
        let zlib = zlib.finish().unwrap();
        let mut raw = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::fast());
        raw.write_all(&text).unwrap();
        let raw = raw.finish().unwrap();
        for (enc, wire) in [
            ("gzip", gzip(&text)),
            ("x-gzip", gzip(&text)),
            ("deflate", zlib),
            ("deflate", raw),
            ("br", brotli(&text)),
        ] {
            let (f, _) = read_all(Framing::Length(wire.len() as u64), Some(enc), &wire, 7);
            assert_eq!(f.state, BodyState::Complete, "{enc}");
            assert_eq!(f.data, text, "{enc}");
            assert_eq!(f.decoded_len, text.len() as u64);
            assert_eq!(f.wire_len, wire.len() as u64);
            assert!(f.fully_retained);
        }
    }

    #[test]
    fn corrupt_and_unsupported_codings() {
        let (f, _) = read_all(Framing::Length(6), Some("gzip"), b"garbag", 100);
        assert_eq!(f.state, BodyState::DecodeError);
        let (f, _) = read_all(Framing::Length(4), Some("zstd"), b"abcd", 100);
        assert_eq!(f.state, BodyState::NotDecoded);
        assert_eq!(f.data, b"abcd");
        let (f, _) = read_all(Framing::Length(4), Some("gzip, br"), b"abcd", 100);
        assert_eq!(f.state, BodyState::NotDecoded);
        let (f, _) = read_all(Framing::Length(4), Some("identity"), b"abcd", 100);
        assert_eq!(f.state, BodyState::Complete);
    }

    #[test]
    fn truncated_gzip_is_incomplete() {
        let wire = gzip(&[7u8; 10_000]);
        let half = &wire[..wire.len() / 2];
        let mut sh = shared();
        let mut r = BodyReader::new(Framing::Length(wire.len() as u64), Some("gzip"), &mut sh);
        r.feed(half, &mut sh);
        let f = r.finish(false, &mut sh);
        assert_eq!(f.state, BodyState::Incomplete);
        assert_eq!(sh.decoders, 0);
    }

    fn bomb_config(max_body: u64, ratio: u64) -> Shared {
        Shared::new(HttpConfig {
            max_body_bytes: max_body,
            max_decompression_ratio: ratio,
            ..storing()
        })
    }

    #[test]
    fn gzip_bomb_is_cut_at_the_body_limit() {
        // 64 MiB of zeros compress to about 64 KiB: a ratio around 1000.
        let wire = gzip(&vec![0u8; 64 * 1024 * 1024]);
        assert!(wire.len() < 100 * 1024);
        // Ratio check disabled: the size bound stops decoding.
        let mut sh = bomb_config(8 * 1024 * 1024, u64::MAX);
        let mut r = BodyReader::new(Framing::Length(wire.len() as u64), Some("gzip"), &mut sh);
        r.feed(&wire, &mut sh);
        let f = r.finish(true, &mut sh);
        assert_eq!(f.state, BodyState::Truncated);
        assert_eq!(f.decoded_len, 8 * 1024 * 1024);
        assert!(f.data.len() <= 8 * 1024 * 1024);
        assert!(!f.fully_retained);
        // Default ratio: stopped early as a bomb.
        let mut sh = shared();
        let mut r = BodyReader::new(Framing::Length(wire.len() as u64), Some("gzip"), &mut sh);
        r.feed(&wire, &mut sh);
        let f = r.finish(true, &mut sh);
        assert_eq!(f.state, BodyState::Bomb);
        assert!(f.decoded_len < 64 * 1024 * 1024);
    }

    #[test]
    fn brotli_bomb_is_bounded() {
        let wire = brotli(&vec![b'a'; 32 * 1024 * 1024]);
        assert!(wire.len() < 64 * 1024, "{}", wire.len());
        let mut sh = bomb_config(4 * 1024 * 1024, u64::MAX);
        let mut r = BodyReader::new(Framing::Length(wire.len() as u64), Some("br"), &mut sh);
        r.feed(&wire, &mut sh);
        let f = r.finish(true, &mut sh);
        assert_eq!(f.state, BodyState::Truncated);
        assert_eq!(f.decoded_len, 4 * 1024 * 1024);
        let mut sh = shared();
        let mut r = BodyReader::new(Framing::Length(wire.len() as u64), Some("br"), &mut sh);
        r.feed(&wire, &mut sh);
        assert_eq!(r.finish(true, &mut sh).state, BodyState::Bomb);
    }

    #[test]
    fn retention_budget_is_shared_and_released() {
        let mut sh = Shared::new(HttpConfig {
            max_retained_bytes: 10,
            ..storing()
        });
        let mut a = BodyReader::new(Framing::Length(8), None, &mut sh);
        let mut b = BodyReader::new(Framing::Length(8), None, &mut sh);
        a.feed(b"aaaaaaaa", &mut sh);
        assert_eq!(sh.retained, 8);
        b.feed(b"bbbbbbbb", &mut sh);
        assert_eq!(sh.retained, 10);
        let fb = b.finish(true, &mut sh);
        assert_eq!(fb.data, b"bb");
        assert!(!fb.fully_retained);
        assert_eq!(fb.decoded_len, 8);
        let fa = a.finish(true, &mut sh);
        assert!(fa.fully_retained);
        assert_eq!(sh.retained, 0);
    }

    #[test]
    fn decoder_slots_are_bounded() {
        let mut sh = Shared::new(HttpConfig {
            max_decoders: 1,
            ..HttpConfig::default()
        });
        let a = BodyReader::new(Framing::Length(8), Some("gzip"), &mut sh);
        let b = BodyReader::new(Framing::Length(8), Some("gzip"), &mut sh);
        assert_eq!(sh.decoders, 1);
        assert_eq!(b.finish(true, &mut sh).state, BodyState::Incomplete);
        a.discard(&mut sh);
        assert_eq!(sh.decoders, 0);
    }

    #[test]
    fn gaps_inside_a_known_length_keep_the_framing() {
        let mut sh = shared();
        let mut r = BodyReader::new(Framing::Length(10), None, &mut sh);
        r.feed(b"abc", &mut sh);
        assert!(r.gap(4, &mut sh));
        let fed = r.feed(b"xyzNEXT", &mut sh);
        assert_eq!(fed.used, 3);
        assert!(fed.done);
        let f = r.finish(true, &mut sh);
        assert_eq!(f.state, BodyState::Incomplete);
        assert_eq!(f.wire_len, 10);
        assert_eq!(f.data, b"abc");
        // A gap past the end of the body loses the framing.
        let mut r = BodyReader::new(Framing::Length(10), None, &mut sh);
        assert!(!r.gap(11, &mut sh));
        r.discard(&mut sh);
    }

    #[test]
    fn coding_parser() {
        assert_eq!(coding(None), Coding::Identity);
        assert_eq!(coding(Some(" GZIP ")), Coding::Gzip);
        assert_eq!(coding(Some("identity, br")), Coding::Brotli);
        assert_eq!(coding(Some("identity,")), Coding::Identity);
        assert_eq!(coding(Some("compress")), Coding::Unsupported);
    }

    #[test]
    fn brotli_decoders_have_their_own_bound() {
        // Idle brotli streams announcing a 16 MiB window: only `max_brotli_decoders` of them
        // get a decoder, the others are kept encoded.
        let mut sh = Shared::new(HttpConfig {
            max_brotli_decoders: 2,
            ..HttpConfig::default()
        });
        let mut stream = Vec::new();
        {
            let mut w = brotli::CompressorWriter::new(&mut stream, 4096, 9, 24);
            let noise: Vec<u8> = (0..(1u32 << 20))
                .map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8)
                .collect();
            w.write_all(&noise).unwrap();
        }
        let header = stream[..2].to_vec();
        let mut open: Vec<BodyReader> = (0..5)
            .map(|_| {
                let mut r = BodyReader::new(Framing::Length(1 << 20), Some("br"), &mut sh);
                r.feed(&header, &mut sh);
                r
            })
            .collect();
        assert_eq!((sh.brotli, sh.decoders), (2, 2));
        // gzip still gets decoders.
        let gz = BodyReader::new(Framing::Length(10), Some("gzip"), &mut sh);
        assert_eq!(sh.decoders, 3);
        gz.discard(&mut sh);
        let last = open.pop().unwrap();
        assert_eq!(last.finish(true, &mut sh).state, BodyState::Incomplete);
        let first = open.remove(0);
        first.discard(&mut sh);
        assert_eq!(sh.brotli, 1);
        // A slot freed: the next brotli body is decoded again.
        let text = b"brotli again ".repeat(20);
        let wire = brotli(&text);
        let mut r = BodyReader::new(Framing::Length(wire.len() as u64), Some("br"), &mut sh);
        r.feed(&wire, &mut sh);
        assert_eq!(r.finish(true, &mut sh).state, BodyState::Complete);
        for r in open {
            r.discard(&mut sh);
        }
        assert_eq!((sh.brotli, sh.decoders), (0, 0));
    }

    #[test]
    fn without_storage_only_the_start_of_a_body_is_kept() {
        let mut sh = Shared::new(HttpConfig {
            store_bodies: false,
            ..HttpConfig::default()
        });
        let body = vec![b'a'; 100_000];
        let mut r = BodyReader::new(Framing::Length(body.len() as u64), None, &mut sh);
        r.feed(&body, &mut sh);
        assert_eq!(sh.retained, 4096);
        let f = r.finish(true, &mut sh);
        assert_eq!(f.state, BodyState::Complete);
        assert_eq!(f.decoded_len, 100_000);
        assert_eq!(f.data.len(), 4096);
        assert!(!f.fully_retained);
        assert_eq!(sh.retained, 0);
    }

    #[test]
    fn a_gap_covering_the_rest_of_a_chunk_keeps_the_framing() {
        let mut sh = shared();
        let mut r = BodyReader::new(Framing::Chunked, None, &mut sh);
        r.feed(b"5\r\nab", &mut sh);
        assert!(r.gap(3, &mut sh));
        let fed = r.feed(b"\r\n2\r\nok\r\n0\r\n\r\nNEXT", &mut sh);
        assert!(fed.done);
        let f = r.finish(true, &mut sh);
        assert_eq!(f.state, BodyState::Incomplete);
        assert_eq!(f.decoded_len, 4);
    }

    #[test]
    fn a_gap_does_not_hide_a_size_stop() {
        let wire = gzip(&vec![0u8; 4 * 1024 * 1024]);
        let mut sh = bomb_config(1024 * 1024, u64::MAX);
        let total = wire.len() as u64 + 1000;
        let mut r = BodyReader::new(Framing::Length(total), Some("gzip"), &mut sh);
        r.feed(&wire, &mut sh);
        assert!(r.gap(500, &mut sh));
        let f = r.finish(true, &mut sh);
        assert_eq!(f.state, BodyState::Truncated);
    }
}
