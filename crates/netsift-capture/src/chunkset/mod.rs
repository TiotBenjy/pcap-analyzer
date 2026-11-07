//! Chunk sets: folder inventory, grouping by name pattern, numeric ordering, continuity
//! checks and k-way merge of overlapping chunks (task P1.2, see `docs/CHUNKED_CAPTURES.md`).
//!
//! Typical use:
//!
//! ```no_run
//! use std::path::Path;
//! use netsift_capture::PacketSource;
//! use netsift_capture::chunkset::{self, ChunkSetSource, InventoryOptions, ReadOptions};
//!
//! let inventory = chunkset::inventory(Path::new("/captures/run1"), &InventoryOptions::default())?;
//! let grouping = chunkset::group(&inventory);
//! // Several groups: the caller lets the user pick one, or merges them (`ChunkGroup::merge`).
//! let group = grouping.groups.into_iter().next().ok_or("no capture")?;
//! let mut source = ChunkSetSource::new(&group, ReadOptions::default());
//! while let Some(packet) = source.next_packet()? {
//!     // packet.chunk_id is the index of the chunk in `group.members`.
//! #   let _ = packet;
//! }
//! let anomalies = source.anomalies();
//! # let _ = anomalies;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod checks;
mod group;
mod inventory;
mod merge;
mod naming;

use std::path::{Path, PathBuf};

pub use checks::{Anomaly, AnomalyKind, ChunkSpan, ContinuityConfig, GapThreshold, timing_checks};
pub use group::{ChunkGroup, ChunkMember, GroupKind, Grouping, MemberStatus, group, group_entries};
pub use inventory::{
    CaptureMeta, DEFAULT_MAX_FILES, EntryKind, FINGERPRINT_LEN, Fingerprint, Inventory,
    InventoryEntry, InventoryOptions, MAX_DEPTH, MIN_CAPTURE_LEN, WalkError, inventory,
    inventory_with,
};
pub use merge::{ChunkSetSource, MAX_ANOMALIES, ReadOptions};

use crate::source::{CaptureError, PacketSource, RawPacket};

/// Opens one capture file. The default is [`crate::reader::open`]; tests inject fakes.
pub type Opener = dyn Fn(&Path) -> Result<Box<dyn PacketSource>, CaptureError> + Send + Sync;

/// Errors of the chunk-set layer. Only the inventoried path itself can fail: problems with
/// individual files are reported as entries and anomalies.
#[derive(Debug, thiserror::Error)]
pub enum ChunkSetError {
    #[error("cannot read {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// Statistics of one chunk, from a full read (inventory `full_scan`, or the import itself).
/// They feed the `chunks` table: packet count, first and last timestamps.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChunkStats {
    pub packets: u64,
    /// Sum of the captured lengths of the packets.
    pub captured_bytes: u64,
    /// Timestamp of the first packet in file order.
    pub first_ts: Option<i64>,
    /// Timestamp of the last packet in file order.
    pub last_ts: Option<i64>,
    /// Smallest timestamp (differs from `first_ts` when timestamps go backwards).
    pub min_ts: Option<i64>,
    /// Largest timestamp.
    pub max_ts: Option<i64>,
    /// Error that stopped reading early, if any.
    pub error: Option<String>,
    /// True once the chunk has been read to its end (or to an error).
    pub complete: bool,
}

impl ChunkStats {
    fn record(&mut self, packet: &RawPacket) {
        let ts = packet.ts_ns;
        self.packets = self.packets.saturating_add(1);
        self.captured_bytes = self
            .captured_bytes
            .saturating_add(u64::try_from(packet.data.len()).unwrap_or(u64::MAX));
        self.first_ts.get_or_insert(ts);
        self.last_ts = Some(ts);
        self.min_ts = Some(self.min_ts.map_or(ts, |m| m.min(ts)));
        self.max_ts = Some(self.max_ts.map_or(ts, |m| m.max(ts)));
    }

    /// Reads the rest of `source` to its end (or first error).
    fn read_rest(&mut self, source: &mut dyn PacketSource) {
        loop {
            match source.next_packet() {
                Ok(Some(packet)) => self.record(&packet),
                Ok(None) => break,
                Err(e) => {
                    self.error = Some(e.to_string());
                    break;
                }
            }
        }
        self.complete = true;
    }

    /// Time span of the chunk, `None` when it holds no packet.
    pub fn span(&self, chunk: u32) -> Option<ChunkSpan> {
        Some(ChunkSpan {
            chunk,
            start_ns: self.min_ts?,
            end_ns: self.max_ts?,
        })
    }
}

/// Chunk id of the member at `index` (saturates; groups never approach 2^32 files).
fn chunk_id(index: usize) -> u32 {
    u32::try_from(index).unwrap_or(u32::MAX)
}
