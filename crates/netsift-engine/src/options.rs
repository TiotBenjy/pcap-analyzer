//! Import options, cancellation token and progress snapshots.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use netsift_analyze::Registry;
use netsift_analyze::flow::FlowConfig;
use netsift_capture::chunkset::{Opener, ReadOptions};
use netsift_store::WriterConfig;

use crate::plan::GroupSelection;

const MIB: u64 = 1 << 20;

/// Upper bound of [`IngestOptions::shards`].
pub const MAX_SHARDS: usize = 256;

/// Options of [`crate::ingest`].
#[derive(Clone)]
pub struct IngestOptions {
    /// Session name; defaults to the chunk set label (or the input file name).
    pub name: Option<String>,
    /// Chunk set to import when the input folder holds several.
    pub selection: GroupSelection,
    /// Inventory sub-directories too.
    pub recursive: bool,
    /// Number of flow shards (worker threads); `None` = cores - 2, at least 1.
    pub shards: Option<usize>,
    pub flow: FlowConfig,
    pub read: ReadOptions,
    /// Analyzers instantiated in every shard.
    pub analyzers: Registry,
    pub writer: WriterConfig,
    /// A packet batch (reader -> decoder -> shard) is sent at this many packets...
    pub batch_packets: usize,
    /// ... or at this many captured bytes, whichever comes first.
    pub batch_bytes: u64,
    /// Capacity of each packet channel, in batches.
    pub channel_batches: usize,
    /// Hard bound on the captured bytes in flight between the reader and the shards (queued
    /// or being processed); the reader waits beyond it. Must exceed the largest packet
    /// (`netsift_capture::reader::MAX_PACKET_LEN`, 64 MiB) to keep the pipeline flowing.
    pub max_in_flight_bytes: u64,
    /// A shard sends its records to the writer at this many records...
    pub record_batch: usize,
    /// ... or at this approximate size in bytes, whichever comes first.
    pub record_batch_bytes: usize,
    /// Interval between two progress callbacks.
    pub progress_interval: Duration,
    /// Opener of the chunk files during the import (default: `netsift_capture::reader::open`).
    /// Tests and alternative readers inject their own.
    pub opener: Option<Arc<Opener>>,
    /// Test hook: shards behave as if the writer had stopped once this many records were
    /// sent. Not part of the stable API.
    #[doc(hidden)]
    pub fail_writer_after_records: Option<u64>,
}

impl Default for IngestOptions {
    fn default() -> Self {
        Self {
            name: None,
            selection: GroupSelection::Single,
            recursive: false,
            shards: None,
            flow: FlowConfig::default(),
            read: ReadOptions::default(),
            analyzers: Registry::default(),
            writer: WriterConfig {
                // Messages are record batches of at most `record_batch_bytes`.
                channel_capacity: 32,
                ..WriterConfig::default()
            },
            batch_packets: 256,
            batch_bytes: MIB,
            channel_batches: 8,
            max_in_flight_bytes: 256 * MIB,
            record_batch: 4096,
            record_batch_bytes: 1 << 20,
            progress_interval: Duration::from_millis(200),
            opener: None,
            fail_writer_after_records: None,
        }
    }
}

impl fmt::Debug for IngestOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IngestOptions")
            .field("name", &self.name)
            .field("selection", &self.selection)
            .field("recursive", &self.recursive)
            .field("shards", &self.shards)
            .field("flow", &self.flow)
            .field("read", &self.read)
            .field("analyzers", &self.analyzers)
            .field("writer", &self.writer)
            .field("batch_packets", &self.batch_packets)
            .field("batch_bytes", &self.batch_bytes)
            .field("channel_batches", &self.channel_batches)
            .field("max_in_flight_bytes", &self.max_in_flight_bytes)
            .field("record_batch", &self.record_batch)
            .field("record_batch_bytes", &self.record_batch_bytes)
            .field("progress_interval", &self.progress_interval)
            .field("opener", &self.opener.as_ref().map(|_| "custom"))
            .field("fail_writer_after_records", &self.fail_writer_after_records)
            .finish()
    }
}

impl IngestOptions {
    /// Effective number of shards.
    pub fn shard_count(&self) -> usize {
        match self.shards {
            Some(n) => n.clamp(1, MAX_SHARDS),
            None => default_shards(),
        }
    }
}

/// Cores - 2 (one reader, one decoder), at least 1.
pub fn default_shards() -> usize {
    std::thread::available_parallelism()
        .map_or(1, std::num::NonZero::get)
        .saturating_sub(2)
        .clamp(1, MAX_SHARDS)
}

/// Shared cancellation flag. Cancelling stops reading; what was read is still analyzed and
/// written, and the session ends `incomplete` (browsable).
#[derive(Debug, Clone, Default)]
pub struct CancelToken(Arc<AtomicBool>);

impl CancelToken {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.0.store(true, Ordering::Relaxed);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

/// Stage of an import.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Reading and analyzing packets.
    Reading,
    /// Reading is over: flows are flushed and the last rows written.
    Finishing,
    /// Everything is written (last callback).
    Done,
}

/// Progress snapshot passed to the progress callback.
#[derive(Debug, Clone, PartialEq)]
pub struct Progress {
    pub phase: Phase,
    /// Bytes consumed from the chunk files (compressed size for `.gz`).
    pub bytes_read: u64,
    /// Total size of the chunk files read by the import.
    pub bytes_total: u64,
    pub packets: u64,
    /// Chunk being read (id = index in the chunk set), when any.
    pub chunk: Option<u32>,
    /// File name of that chunk.
    pub chunk_name: Option<String>,
    /// Number of chunk files read by the import.
    pub chunks_total: usize,
    /// Wall-clock time since the start of the import.
    pub elapsed: Duration,
}

impl Progress {
    /// Read fraction in `[0, 1]`.
    #[allow(clippy::cast_precision_loss)]
    pub fn fraction(&self) -> f64 {
        if self.bytes_total == 0 {
            return if self.phase == Phase::Reading {
                0.0
            } else {
                1.0
            };
        }
        (self.bytes_read as f64 / self.bytes_total as f64).clamp(0.0, 1.0)
    }

    /// Average read throughput in bytes per second.
    #[allow(clippy::cast_precision_loss)]
    pub fn bytes_per_sec(&self) -> f64 {
        let secs = self.elapsed.as_secs_f64();
        if secs > 0.0 {
            self.bytes_read as f64 / secs
        } else {
            0.0
        }
    }

    /// Estimated remaining reading time, once some data has been read.
    #[allow(clippy::cast_precision_loss)]
    pub fn eta(&self) -> Option<Duration> {
        let rate = self.bytes_per_sec();
        if rate <= 0.0 || self.phase != Phase::Reading {
            return None;
        }
        let remaining = self.bytes_total.saturating_sub(self.bytes_read) as f64;
        Duration::try_from_secs_f64(remaining / rate).ok()
    }
}
