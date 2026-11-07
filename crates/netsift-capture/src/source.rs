//! Shared interface between the file readers (`reader`, task P1.1) and the chunk-set layer
//! (`chunkset`, task P1.2). Frozen before both tasks start: change it only by agreement.

use bytes::Bytes;

/// On-disk capture container, detected from the magic number (never from the extension).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CaptureFormat {
    /// Classic libpcap format (microsecond or nanosecond precision, either endianness).
    Pcap,
    /// pcapng (one or more sections, one or more interfaces).
    PcapNg,
}

/// Static description of an opened capture file, available right after opening.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureInfo {
    pub format: CaptureFormat,
    /// True when the file was transparently decompressed (`.gz`, detected by magic).
    pub compressed: bool,
    /// Link types seen so far, in order of first appearance (pcapng: one per interface).
    pub linktypes: Vec<u32>,
    /// Snapshot length of the first interface, when the format declares one.
    pub snaplen: Option<u32>,
}

/// One packet as read from a capture file, before any decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawPacket {
    /// Capture timestamp, nanoseconds since the Unix epoch, UTC.
    pub ts_ns: i64,
    /// Index of the chunk in its chunk set. Readers set 0; the chunk-set layer overwrites it.
    pub chunk_id: u32,
    /// Byte offset of the packet record in the (decompressed) file, for diagnostics and export.
    pub offset: u64,
    /// Link-layer type of this packet (pcapng: from its interface description block).
    pub linktype: u32,
    /// Original length on the wire (may exceed `data.len()` when truncated by the snaplen).
    pub orig_len: u32,
    /// Captured bytes.
    pub data: Bytes,
}

/// Non-fatal conditions met while reading; they become rows of the `anomalies` table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadWarning {
    /// The last record is incomplete (file still being written when copied): it was skipped.
    TruncatedTail { offset: u64 },
    /// A timestamp is earlier than the previous one in the same file (packet kept).
    TimestampBackwards {
        offset: u64,
        previous_ns: i64,
        ts_ns: i64,
    },
    /// A pcapng block type that is not handled was skipped.
    UnknownBlock { offset: u64, block_type: u32 },
    /// A record was malformed but the reader could resynchronize and continue.
    SkippedRecord { offset: u64, reason: String },
}

/// Errors that stop reading a file.
#[derive(Debug, thiserror::Error)]
pub enum CaptureError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("not a pcap or pcapng file")]
    UnknownFormat,
    #[error("malformed capture at offset {offset}: {reason}")]
    Malformed { offset: u64, reason: String },
}

/// A sequential source of packets: one capture file (P1.1) or a whole chunk set (P1.2).
///
/// Implementations must be streaming (bounded memory regardless of file size) and must never
/// panic on hostile input.
pub trait PacketSource: Send {
    /// Format details known after opening.
    fn info(&self) -> &CaptureInfo;

    /// Next packet in file order, `Ok(None)` at the end (including after a truncated tail).
    fn next_packet(&mut self) -> Result<Option<RawPacket>, CaptureError>;

    /// Bytes consumed from the underlying (compressed) file so far, for progress reporting.
    fn bytes_read(&self) -> u64;

    /// Warnings accumulated so far (not cleared by reading them).
    fn warnings(&self) -> &[ReadWarning];
}
