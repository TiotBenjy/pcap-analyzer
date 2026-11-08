//! The analyzer trait (frozen at the end of phase 1, see `docs/ARCHITECTURE.md`).

use std::fmt;

use netsift_dissect::Decoded;
use netsift_flow::{Direction, FlowCtx, PacketCtx, StreamCtx};

use crate::record::Record;

/// Stable identifier of an analyzer (`"core"`, `"dns"`, `"http"`...): lower case, ASCII.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AnalyzerId(pub &'static str);

impl AnalyzerId {
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

impl fmt::Display for AnalyzerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

/// Reference to an extracted object stored in the session's `blobs/` directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BlobRef {
    /// SHA-256 of the content, which is also its file name (`blobs/ab/abcdef...`).
    pub sha256: [u8; 32],
    /// Size of the content in bytes.
    pub size: u64,
}

impl BlobRef {
    /// Lower-case hexadecimal digest.
    pub fn to_hex(&self) -> String {
        use std::fmt::Write as _;
        self.sha256
            .iter()
            .fold(String::with_capacity(64), |mut s, b| {
                let _ = write!(s, "{b:02x}");
                s
            })
    }
}

/// Destination of the records emitted by analyzers. The engine buffers them and forwards them
/// in batches to the single store writer.
pub trait RecordSink {
    fn emit(&mut self, record: Record);

    /// Stores an extracted object (file, image, certificate...) and returns its reference, to
    /// be put in a record. Intended implementation (engine, task P3.6): the shard hashes the
    /// content and writes it under `blobs/` itself, deduplicated by SHA-256; blob contents never
    /// travel through the writer channel, only their [`BlobRef`]. Returns `None` when blobs
    /// are not supported (the default) or the object could not be stored: the analyzer then
    /// records the metadata without content.
    fn put_blob(&mut self, _data: &[u8]) -> Option<BlobRef> {
        None
    }

    /// Same as [`RecordSink::put_blob`] for extracted files that are not bounded by their
    /// analyzer (HTTP objects): the engine charges them to the blob budget of the session
    /// (`IngestOptions::max_blob_bytes`) and returns `None` once it is spent. Bounded
    /// metadata blobs (certificates) use `put_blob` and are never refused for budget.
    fn put_object(&mut self, data: &[u8]) -> Option<BlobRef> {
        self.put_blob(data)
    }
}

/// Collects records in memory (tests, small buffers).
impl RecordSink for Vec<Record> {
    fn emit(&mut self, record: Record) {
        self.push(record);
    }
}

/// A protocol analyzer.
///
/// - One instance per flow shard: an analyzer never shares mutable state with another shard.
///   Every packet of a flow (both directions, every IP fragment) reaches the same shard, in
///   capture order.
/// - All time is packet time (`ts_ns`), never the wall clock.
/// - Global aggregations (counters, top N) are done in SQL at read time: records must be
///   mergeable whatever the number of shards (see the merge rules of `netsift-store`).
/// - Captures are hostile input: never panic, bound every buffer.
pub trait Analyzer: Send {
    /// Stable identifier, see [`AnalyzerId`].
    fn id(&self) -> AnalyzerId;

    /// Every decoded packet, after IP defragmentation.
    fn on_packet(&mut self, _ctx: &PacketCtx, _pkt: &Decoded<'_>, _out: &mut dyn RecordSink) {}

    /// In-order reassembled TCP payload of one direction of a flow.
    fn on_stream(
        &mut self,
        _ctx: &StreamCtx,
        _dir: Direction,
        _data: &[u8],
        _out: &mut dyn RecordSink,
    ) {
    }

    /// End of a flow (closed, timed out, evicted or end of capture), exactly once per flow.
    fn on_flow_end(&mut self, _ctx: &FlowCtx, _out: &mut dyn RecordSink) {}

    /// End of the capture (or cancellation), after every flow has ended: flush what is left.
    fn finish(&mut self, _out: &mut dyn RecordSink) {}
}
