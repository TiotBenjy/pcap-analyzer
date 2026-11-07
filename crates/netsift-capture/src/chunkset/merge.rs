//! Reading a chunk group as one capture: lazy k-way merge by timestamp.
//!
//! Chunks are opened in order of their first timestamp (from the inventory), and only when the
//! merge reaches that timestamp. Disjoint chunks are therefore read one after the other with a
//! single file open; overlapping chunks are merged through a min-heap holding one packet per
//! open chunk. Memory is bounded by the number of open chunks ([`ReadOptions::max_open`]).
//!
//! Clock stepping back at a chunk boundary (last packet of chunk N later than the first of
//! chunk N+1, e.g. an NTP correction between two files): chunk N+1 is opened as soon as the
//! merge reaches its first timestamp, so its first packets are interleaved with the tail of
//! chunk N. The output stays in timestamp order (file order is not preserved across the
//! boundary) and an [`AnomalyKind::Overlap`] is reported. A clock stepping back *inside* a chunk
//! cannot be reordered (the merge holds one packet per chunk): those packets are delivered in
//! file order, reported by the reader (`TimestampBackwards`) and by
//! [`AnomalyKind::OutOfOrder`].

use std::cmp::{Ordering, Reverse};
use std::collections::{BinaryHeap, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;

use super::checks::{self, Anomaly, AnomalyKind, ContinuityConfig};
use super::group::ChunkGroup;
use super::{ChunkStats, Opener};
use crate::reader::MAX_WARNINGS;
use crate::source::{
    CaptureError, CaptureFormat, CaptureInfo, PacketSource, RawPacket, ReadWarning,
};

/// Maximum number of anomalies kept by a [`ChunkSetSource`]; a final
/// [`AnomalyKind::LimitReached`] marks the cut.
pub const MAX_ANOMALIES: usize = 100_000;

/// Distinct link types tracked in [`ChunkSetSource::info`].
const MAX_LINKTYPES: usize = 256;

/// Options of [`ChunkSetSource`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadOptions {
    /// Maximum number of chunk files open at once during a k-way merge (default 64). Beyond it,
    /// packets may come out of timestamp order ([`AnomalyKind::MergeFanoutLimit`]).
    pub max_open: usize,
    pub continuity: ContinuityConfig,
}

impl Default for ReadOptions {
    fn default() -> Self {
        Self {
            max_open: 64,
            continuity: ContinuityConfig::default(),
        }
    }
}

/// Next packet of an open chunk, ordered by (timestamp, chunk id, offset).
struct Head {
    chunk: u32,
    packet: RawPacket,
}

impl Head {
    fn key(&self) -> (i64, u32, u64) {
        (self.packet.ts_ns, self.chunk, self.packet.offset)
    }
}

impl PartialEq for Head {
    fn eq(&self, other: &Self) -> bool {
        self.key() == other.key()
    }
}
impl Eq for Head {}
impl PartialOrd for Head {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Head {
    fn cmp(&self, other: &Self) -> Ordering {
        self.key().cmp(&other.key())
    }
}

/// Per-chunk reading state, indexed by chunk id.
#[derive(Default)]
struct Slot {
    path: Option<PathBuf>,
    /// Inventoried size: the progress contribution of the chunk once read.
    size: u64,
    first_ts: Option<i64>,
    reader: Option<Box<dyn PacketSource>>,
    /// Reader warnings already copied.
    warnings_seen: usize,
    stats: ChunkStats,
}

/// A chunk group read as a single [`PacketSource`], in global timestamp order.
///
/// - [`RawPacket::chunk_id`] is the index of the chunk in [`ChunkGroup::members`];
/// - equal timestamps are ordered by chunk id, then by offset in the file;
/// - only [`super::MemberStatus::Active`] members are read (duplicates and unreadable files
///   are reported in [`ChunkSetSource::anomalies`]);
/// - an error in one chunk ends that chunk only: it becomes an [`AnomalyKind::ReadError`] (and
///   a [`ReadWarning::SkippedRecord`]) and the other chunks are still read; `next_packet`
///   itself never fails;
/// - [`PacketSource::bytes_read`] reaches [`ChunkSetSource::total_bytes`] at the end.
pub struct ChunkSetSource {
    opener: Arc<Opener>,
    options: ReadOptions,
    slots: Vec<Slot>,
    /// Active chunks not opened yet, by (first timestamp, chunk id); no packet known = last.
    pending: VecDeque<u32>,
    heap: BinaryHeap<Reverse<Head>>,
    /// Chunk ids of the open files (at most `max_open`).
    open: Vec<u32>,
    finished_bytes: u64,
    total_bytes: u64,
    info: CaptureInfo,
    warnings: Vec<ReadWarning>,
    anomalies: Vec<Anomaly>,
    fanout_reported: bool,
    /// Timestamp of the previously delivered packet.
    last_ts: Option<i64>,
    /// Index of the [`AnomalyKind::OutOfOrder`] anomaly, once reported.
    out_of_order: Option<usize>,
    done: bool,
}

impl ChunkSetSource {
    /// Reads `group` with the default opener ([`crate::reader::open`]).
    pub fn new(group: &ChunkGroup, options: ReadOptions) -> Self {
        Self::with_opener(group, options, Arc::new(crate::reader::open))
    }

    /// Reads `group` with an injected opener. Files are opened lazily, never here.
    pub fn with_opener(group: &ChunkGroup, options: ReadOptions, opener: Arc<Opener>) -> Self {
        let mut slots: Vec<Slot> = group.members.iter().map(|_| Slot::default()).collect();
        let mut info = CaptureInfo {
            format: CaptureFormat::Pcap,
            compressed: false,
            linktypes: Vec::new(),
            snaplen: None,
        };
        let mut first_info = true;
        let mut total_bytes = 0u64;
        let mut pending = Vec::new();
        for (chunk, member) in group.active() {
            let Some(meta) = member.entry.capture() else {
                continue;
            };
            if first_info {
                info.format = meta.info.format;
                info.snaplen = meta.info.snaplen;
                first_info = false;
            }
            info.compressed |= meta.info.compressed;
            for lt in &meta.info.linktypes {
                add_linktype(&mut info, *lt);
            }
            total_bytes = total_bytes.saturating_add(member.entry.size);
            if let Some(slot) = usize::try_from(chunk).ok().and_then(|i| slots.get_mut(i)) {
                slot.path = Some(member.entry.path.clone());
                slot.size = member.entry.size;
                slot.first_ts = meta.first_ts;
                pending.push((meta.first_ts.is_none(), meta.first_ts, chunk));
            }
        }
        pending.sort_unstable();
        let mut source = Self {
            opener,
            options,
            slots,
            pending: pending.into_iter().map(|(_, _, chunk)| chunk).collect(),
            heap: BinaryHeap::new(),
            open: Vec::new(),
            finished_bytes: 0,
            total_bytes,
            info,
            warnings: Vec::new(),
            anomalies: Vec::new(),
            fanout_reported: false,
            last_ts: None,
            out_of_order: None,
            done: false,
        };
        for anomaly in checks::static_checks(group) {
            source.push_anomaly(anomaly);
        }
        source
    }

    /// Total size in bytes of the chunks read, the denominator of the progress.
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    /// Continuity anomalies: those known from the inventory from the start, reader warnings and
    /// errors as chunks are read, and time gaps and overlaps once the end is reached.
    pub fn anomalies(&self) -> &[Anomaly] {
        &self.anomalies
    }

    /// Statistics per chunk, indexed by chunk id (complete once the chunk has been read).
    pub fn chunk_stats(&self) -> impl ExactSizeIterator<Item = &ChunkStats> {
        self.slots.iter().map(|s| &s.stats)
    }

    /// Chunk ids of the files currently open (the "current chunk" of the progress display).
    pub fn open_chunks(&self) -> &[u32] {
        &self.open
    }

    /// True once every chunk has been read.
    pub fn is_finished(&self) -> bool {
        self.done
    }

    fn slot(&mut self, chunk: u32) -> Option<&mut Slot> {
        self.slots.get_mut(usize::try_from(chunk).ok()?)
    }

    fn push_anomaly(&mut self, anomaly: Anomaly) {
        let len = self.anomalies.len();
        if len + 1 < MAX_ANOMALIES {
            self.anomalies.push(anomaly);
        } else if len + 1 == MAX_ANOMALIES {
            self.anomalies.push(Anomaly {
                chunk: None,
                kind: AnomalyKind::LimitReached {
                    limit: MAX_ANOMALIES,
                },
            });
        }
    }

    fn push_warning(&mut self, warning: ReadWarning) {
        let len = self.warnings.len();
        if len + 1 < MAX_WARNINGS {
            self.warnings.push(warning);
        } else if len + 1 == MAX_WARNINGS {
            self.warnings.push(ReadWarning::SkippedRecord {
                offset: 0,
                reason: "warning limit reached; further warnings dropped".into(),
            });
        }
    }

    /// Counts a packet delivered earlier than its predecessor, in a single group-level anomaly.
    fn note_out_of_order(&mut self, step_ns: i64) {
        if let Some(Anomaly {
            kind:
                AnomalyKind::OutOfOrder {
                    packets,
                    max_backstep_ns,
                },
            ..
        }) = self.out_of_order.and_then(|i| self.anomalies.get_mut(i))
        {
            *packets = packets.saturating_add(1);
            *max_backstep_ns = (*max_backstep_ns).max(step_ns);
            return;
        }
        if self.out_of_order.is_none() {
            let before = self.anomalies.len();
            self.push_anomaly(Anomaly {
                chunk: None,
                kind: AnomalyKind::OutOfOrder {
                    packets: 1,
                    max_backstep_ns: step_ns,
                },
            });
            // Only when actually stored (not cut by the anomaly limit).
            if matches!(
                self.anomalies.last(),
                Some(Anomaly {
                    kind: AnomalyKind::OutOfOrder { .. },
                    ..
                })
            ) && self.anomalies.len() > before
            {
                self.out_of_order = Some(before);
            }
        }
    }

    /// Opens a pending chunk and loads its first packet into the heap.
    fn open_chunk(&mut self, chunk: u32) {
        let Some(path) = self.slot(chunk).and_then(|s| s.path.clone()) else {
            return;
        };
        match (self.opener)(&path) {
            Ok(reader) => {
                if let Some(slot) = self.slot(chunk) {
                    slot.reader = Some(reader);
                    self.open.push(chunk);
                    self.pull(chunk);
                }
            }
            Err(e) => {
                self.chunk_error(chunk, &e);
                self.close(chunk);
            }
        }
    }

    /// Reads the next packet of an open chunk into the heap, or closes the chunk at its end.
    fn pull(&mut self, chunk: u32) {
        let Some(slot) = self.slot(chunk) else { return };
        let Some(reader) = slot.reader.as_mut() else {
            return;
        };
        let result = reader.next_packet();
        let new_warnings: Vec<ReadWarning> = reader
            .warnings()
            .get(slot.warnings_seen..)
            .unwrap_or_default()
            .to_vec();
        slot.warnings_seen = reader.warnings().len();
        if let Ok(Some(packet)) = &result {
            slot.stats.record(packet);
        }
        for warning in new_warnings {
            self.push_warning(warning.clone());
            self.push_anomaly(Anomaly {
                chunk: Some(chunk),
                kind: AnomalyKind::Read(warning),
            });
        }
        match result {
            Ok(Some(packet)) => self.heap.push(Reverse(Head { chunk, packet })),
            Ok(None) => self.close(chunk),
            Err(e) => {
                self.chunk_error(chunk, &e);
                self.close(chunk);
            }
        }
    }

    fn chunk_error(&mut self, chunk: u32, error: &CaptureError) {
        let reason = error.to_string();
        let offset = match error {
            CaptureError::Malformed { offset, .. } => *offset,
            _ => 0,
        };
        if let Some(slot) = self.slot(chunk) {
            slot.stats.error = Some(reason.clone());
        }
        self.push_warning(ReadWarning::SkippedRecord {
            offset,
            reason: format!("chunk {chunk}: {reason}"),
        });
        self.push_anomaly(Anomaly {
            chunk: Some(chunk),
            kind: AnomalyKind::ReadError { reason },
        });
    }

    fn close(&mut self, chunk: u32) {
        let Some(slot) = self.slot(chunk) else { return };
        let was_open = slot.reader.take().is_some();
        slot.stats.complete = true;
        let size = slot.size;
        if was_open {
            self.open.retain(|&c| c != chunk);
        }
        self.finished_bytes = self.finished_bytes.saturating_add(size);
    }

    /// End of the set: time gaps and overlaps from the actual packet timestamps.
    fn finish(&mut self) {
        self.done = true;
        let spans: Vec<_> = self
            .slots
            .iter()
            .enumerate()
            .filter_map(|(i, s)| s.stats.span(super::chunk_id(i)))
            .collect();
        for anomaly in checks::timing_checks(&spans, &self.options.continuity) {
            self.push_anomaly(anomaly);
        }
    }

    /// True when the next pending chunk must be opened before emitting the heap's minimum.
    fn should_open_next(&self) -> Option<u32> {
        let &next = self.pending.front()?;
        let Some(Reverse(head)) = self.heap.peek() else {
            return Some(next);
        };
        let first_ts = self
            .slots
            .get(usize::try_from(next).ok()?)
            .and_then(|s| s.first_ts)?;
        (first_ts <= head.packet.ts_ns).then_some(next)
    }
}

fn add_linktype(info: &mut CaptureInfo, linktype: u32) {
    if info.linktypes.len() < MAX_LINKTYPES && !info.linktypes.contains(&linktype) {
        info.linktypes.push(linktype);
    }
}

impl PacketSource for ChunkSetSource {
    /// Format and snaplen of the first chunk; `compressed` if any chunk is; link types of all
    /// chunks (completed as packets with new link types are read).
    fn info(&self) -> &CaptureInfo {
        &self.info
    }

    fn next_packet(&mut self) -> Result<Option<RawPacket>, CaptureError> {
        loop {
            if self.done {
                return Ok(None);
            }
            if let Some(next) = self.should_open_next() {
                let limit = self.options.max_open.max(1);
                if self.open.len() < limit {
                    self.pending.pop_front();
                    self.open_chunk(next);
                    continue;
                }
                if !self.fanout_reported {
                    self.fanout_reported = true;
                    self.push_anomaly(Anomaly {
                        chunk: None,
                        kind: AnomalyKind::MergeFanoutLimit { limit },
                    });
                }
            }
            let Some(Reverse(Head { chunk, mut packet })) = self.heap.pop() else {
                self.finish();
                return Ok(None);
            };
            self.pull(chunk);
            packet.chunk_id = chunk;
            add_linktype(&mut self.info, packet.linktype);
            if let Some(previous) = self.last_ts
                && packet.ts_ns < previous
            {
                self.note_out_of_order(previous.saturating_sub(packet.ts_ns));
            }
            self.last_ts = Some(packet.ts_ns);
            return Ok(Some(packet));
        }
    }

    fn bytes_read(&self) -> u64 {
        let open: u64 = self
            .open
            .iter()
            .filter_map(|&c| {
                let slot = self.slots.get(usize::try_from(c).ok()?)?;
                Some(slot.reader.as_ref()?.bytes_read().min(slot.size))
            })
            .fold(0, u64::saturating_add);
        self.finished_bytes.saturating_add(open)
    }

    fn warnings(&self) -> &[ReadWarning] {
        &self.warnings
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::path::Path;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

    use bytes::Bytes;

    use super::*;
    use crate::chunkset::group::GroupKind;
    use crate::chunkset::inventory::{CaptureMeta, EntryKind, Fingerprint, InventoryEntry};

    /// Scripted content of a fake chunk.
    #[derive(Clone, Default)]
    struct Script {
        /// Packet timestamps (offset = 100 + 10 * index).
        ts: Vec<i64>,
        linktype: u32,
        /// Warnings reported after the given number of packets.
        warn_after: Option<(usize, ReadWarning)>,
        /// Error returned after the given number of packets.
        fail_after: Option<usize>,
        /// Refuse to open.
        open_error: bool,
    }

    struct Fake {
        script: Script,
        next: usize,
        info: CaptureInfo,
        warnings: Vec<ReadWarning>,
        open: Arc<AtomicUsize>,
        size: u64,
    }

    impl Drop for Fake {
        fn drop(&mut self) {
            self.open.fetch_sub(1, AtomicOrdering::SeqCst);
        }
    }

    impl PacketSource for Fake {
        fn info(&self) -> &CaptureInfo {
            &self.info
        }
        fn next_packet(&mut self) -> Result<Option<RawPacket>, CaptureError> {
            if let Some((n, w)) = &self.script.warn_after
                && *n == self.next
                && self.warnings.is_empty()
            {
                self.warnings.push(w.clone());
            }
            if self.script.fail_after == Some(self.next) {
                self.next = usize::MAX;
                return Err(CaptureError::Malformed {
                    offset: 7,
                    reason: "bad".into(),
                });
            }
            let Some(&ts) = self.script.ts.get(self.next) else {
                return Ok(None);
            };
            let offset = 100 + 10 * self.next as u64;
            self.next += 1;
            Ok(Some(RawPacket {
                ts_ns: ts,
                chunk_id: 0,
                offset,
                linktype: self.script.linktype,
                orig_len: 4,
                data: Bytes::from_static(b"data"),
            }))
        }
        fn bytes_read(&self) -> u64 {
            if self.next >= self.script.ts.len() {
                self.size
            } else {
                self.size / 2
            }
        }
        fn warnings(&self) -> &[ReadWarning] {
            &self.warnings
        }
    }

    struct World {
        scripts: HashMap<String, Script>,
        open: Arc<AtomicUsize>,
        max_open: Arc<Mutex<usize>>,
    }

    impl World {
        fn new(scripts: &[(&str, Script)]) -> Self {
            Self {
                scripts: scripts
                    .iter()
                    .map(|(n, s)| ((*n).to_owned(), s.clone()))
                    .collect(),
                open: Arc::new(AtomicUsize::new(0)),
                max_open: Arc::new(Mutex::new(0)),
            }
        }

        fn opener(&self) -> Arc<Opener> {
            let scripts = self.scripts.clone();
            let open = Arc::clone(&self.open);
            let max_open = Arc::clone(&self.max_open);
            Arc::new(move |path: &Path| {
                let name = path.file_name().unwrap().to_str().unwrap();
                let script = scripts[name].clone();
                if script.open_error {
                    return Err(CaptureError::UnknownFormat);
                }
                let now = open.fetch_add(1, AtomicOrdering::SeqCst) + 1;
                let mut max = max_open.lock().unwrap();
                *max = (*max).max(now);
                Ok(Box::new(Fake {
                    info: CaptureInfo {
                        format: CaptureFormat::PcapNg,
                        compressed: false,
                        linktypes: vec![script.linktype],
                        snaplen: None,
                    },
                    script,
                    next: 0,
                    warnings: Vec::new(),
                    open: Arc::clone(&open),
                    size: 1000,
                }) as Box<dyn PacketSource>)
            })
        }

        /// A group of all scripts, in the order given (sequence numbers 1, 2, ...).
        fn group(&self, names: &[&str]) -> ChunkGroup {
            let entries = names
                .iter()
                .enumerate()
                .map(|(i, name)| {
                    let script = &self.scripts[*name];
                    let entry = InventoryEntry {
                        path: Path::new("/fake").join(name),
                        name: (*name).to_owned(),
                        size: 1000,
                        mtime_ns: None,
                        fingerprint: Some(Fingerprint::of_bytes(name.as_bytes())),
                        kind: EntryKind::Capture(Box::new(CaptureMeta {
                            info: CaptureInfo {
                                format: CaptureFormat::PcapNg,
                                compressed: i == 1,
                                linktypes: vec![script.linktype],
                                snaplen: None,
                            },
                            first_ts: script.ts.first().copied(),
                            read_error: None,
                            warnings: Vec::new(),
                            first_packet: None,
                            scan: None,
                        })),
                    };
                    (entry, Some(i as u64 + 1))
                })
                .collect();
            ChunkGroup::new(GroupKind::Dumpcap, "fake".into(), entries)
        }

        fn max_open(&self) -> usize {
            *self.max_open.lock().unwrap()
        }
    }

    fn script(ts: &[i64]) -> Script {
        Script {
            ts: ts.to_vec(),
            linktype: 1,
            ..Script::default()
        }
    }

    fn drain(source: &mut ChunkSetSource) -> Vec<(i64, u32, u64)> {
        let mut out = Vec::new();
        while let Some(p) = source.next_packet().unwrap() {
            out.push((p.ts_ns, p.chunk_id, p.offset));
        }
        out
    }

    #[test]
    fn disjoint_chunks_are_concatenated_one_file_at_a_time() {
        let world = World::new(&[
            ("a", script(&[1, 2, 3])),
            ("b", script(&[4, 5])),
            ("c", script(&[6])),
        ]);
        let group = world.group(&["a", "b", "c"]);
        let mut source =
            ChunkSetSource::with_opener(&group, ReadOptions::default(), world.opener());
        assert_eq!(source.total_bytes(), 3000);
        assert_eq!(source.bytes_read(), 0);
        let packets = drain(&mut source);
        let ts: Vec<_> = packets.iter().map(|p| p.0).collect();
        let chunks: Vec<_> = packets.iter().map(|p| p.1).collect();
        assert_eq!(ts, vec![1, 2, 3, 4, 5, 6]);
        assert_eq!(chunks, vec![0, 0, 0, 1, 1, 2]);
        assert_eq!(world.max_open(), 1);
        assert_eq!(world.open.load(AtomicOrdering::SeqCst), 0);
        assert_eq!(source.bytes_read(), 3000);
        assert!(source.is_finished());
        assert_eq!(source.anomalies(), &[]);
        assert!(source.info().compressed);
        let stats: Vec<_> = source
            .chunk_stats()
            .map(|s| (s.packets, s.first_ts, s.last_ts))
            .collect();
        assert_eq!(
            stats,
            vec![
                (3, Some(1), Some(3)),
                (2, Some(4), Some(5)),
                (1, Some(6), Some(6))
            ]
        );
        // Reading past the end stays at the end.
        assert_eq!(source.next_packet().unwrap(), None);
    }

    #[test]
    fn overlapping_chunks_are_merged_in_timestamp_order() {
        let world = World::new(&[
            ("eth0", script(&[10, 30, 30, 50, 70])),
            ("eth1", script(&[20, 30, 40, 80])),
            ("late", script(&[75, 90])),
        ]);
        let group = world.group(&["eth0", "eth1", "late"]);
        let mut source =
            ChunkSetSource::with_opener(&group, ReadOptions::default(), world.opener());
        let packets = drain(&mut source);
        assert_eq!(
            packets,
            vec![
                (10, 0, 100),
                (20, 1, 100),
                (30, 0, 110),
                (30, 0, 120),
                (30, 1, 110),
                (40, 1, 120),
                (50, 0, 130),
                (70, 0, 140),
                (75, 2, 100),
                (80, 1, 130),
                (90, 2, 110),
            ]
        );
        // eth0 ends (70) before `late` starts (75).
        assert_eq!(world.max_open(), 2);
        let kinds: Vec<_> = source
            .anomalies()
            .iter()
            .map(|a| (a.chunk, a.kind.clone()))
            .collect();
        assert_eq!(
            kinds,
            vec![
                (
                    Some(1),
                    AnomalyKind::Overlap {
                        previous: 0,
                        overlap_ns: 50
                    }
                ),
                (
                    Some(2),
                    AnomalyKind::Overlap {
                        previous: 1,
                        overlap_ns: 5
                    }
                ),
            ]
        );
    }

    #[test]
    fn chunks_out_of_time_order_are_read_by_first_timestamp() {
        // Sequence order b, a but a starts first (tcpdump ring buffer wrap-around).
        let world = World::new(&[("b", script(&[5, 6])), ("a", script(&[1, 2]))]);
        let group = world.group(&["b", "a"]);
        let mut source =
            ChunkSetSource::with_opener(&group, ReadOptions::default(), world.opener());
        assert_eq!(
            drain(&mut source),
            vec![(1, 1, 100), (2, 1, 110), (5, 0, 100), (6, 0, 110)]
        );
        assert_eq!(world.max_open(), 1);
        // Checked in reading order: no false overlap.
        assert_eq!(source.anomalies(), &[]);
    }

    #[test]
    fn fanout_limit_bounds_open_files() {
        let world = World::new(&[
            ("a", script(&[1, 4])),
            ("b", script(&[2, 5])),
            ("c", script(&[3, 6])),
        ]);
        let group = world.group(&["a", "b", "c"]);
        let options = ReadOptions {
            max_open: 2,
            ..ReadOptions::default()
        };
        let mut source = ChunkSetSource::with_opener(&group, options, world.opener());
        let ts: Vec<_> = drain(&mut source).into_iter().map(|p| p.0).collect();
        assert_eq!(ts.len(), 6);
        assert_eq!(world.max_open(), 2);
        assert!(
            source
                .anomalies()
                .iter()
                .any(|a| a.kind == AnomalyKind::MergeFanoutLimit { limit: 2 })
        );
    }

    #[test]
    fn fanout_limit_reports_the_applied_limit_and_out_of_order_output() {
        let world = World::new(&[
            ("a", script(&[1, 4])),
            ("b", script(&[2, 5])),
            ("c", script(&[3, 6])),
        ]);
        let group = world.group(&["a", "b", "c"]);
        let options = ReadOptions {
            max_open: 0,
            ..ReadOptions::default()
        };
        let mut source = ChunkSetSource::with_opener(&group, options, world.opener());
        let ts: Vec<_> = drain(&mut source).into_iter().map(|p| p.0).collect();
        // One file at a time: concatenation in first-timestamp order.
        assert_eq!(ts, vec![1, 4, 2, 5, 3, 6]);
        assert_eq!(world.max_open(), 1);
        let anomalies = source.anomalies();
        assert_eq!(
            anomalies[0].kind,
            AnomalyKind::MergeFanoutLimit { limit: 1 }
        );
        assert_eq!(
            anomalies[1].kind,
            AnomalyKind::OutOfOrder {
                packets: 2,
                max_backstep_ns: 2,
            }
        );
    }

    #[test]
    fn clock_stepping_back_at_a_chunk_boundary_is_reordered() {
        // Chunk b starts (5) before chunk a ends (10): an NTP step between the two files.
        let world = World::new(&[("a", script(&[1, 2, 10])), ("b", script(&[5, 11]))]);
        let group = world.group(&["a", "b"]);
        let mut source =
            ChunkSetSource::with_opener(&group, ReadOptions::default(), world.opener());
        let packets = drain(&mut source);
        let ts: Vec<_> = packets.iter().map(|p| (p.0, p.1)).collect();
        assert_eq!(ts, vec![(1, 0), (2, 0), (5, 1), (10, 0), (11, 1)]);
        assert_eq!(
            source.anomalies(),
            &[Anomaly {
                chunk: Some(1),
                kind: AnomalyKind::Overlap {
                    previous: 0,
                    overlap_ns: 5,
                },
            }]
        );
    }

    #[test]
    fn clock_stepping_back_inside_a_chunk_is_counted_once() {
        let world = World::new(&[("a", script(&[1, 5, 3, 4, 2]))]);
        let group = world.group(&["a"]);
        let mut source =
            ChunkSetSource::with_opener(&group, ReadOptions::default(), world.opener());
        drain(&mut source);
        assert_eq!(
            source.anomalies(),
            &[Anomaly {
                chunk: None,
                kind: AnomalyKind::OutOfOrder {
                    packets: 2,
                    max_backstep_ns: 2,
                },
            }]
        );
    }

    #[test]
    fn errors_and_warnings_of_one_chunk_do_not_stop_the_set() {
        let world = World::new(&[
            (
                "a",
                Script {
                    fail_after: Some(1),
                    ..script(&[1, 2, 3])
                },
            ),
            (
                "b",
                Script {
                    open_error: true,
                    ..script(&[4])
                },
            ),
            (
                "c",
                Script {
                    warn_after: Some((2, ReadWarning::TruncatedTail { offset: 120 })),
                    linktype: 105,
                    ..script(&[10, 11])
                },
            ),
        ]);
        let group = world.group(&["a", "b", "c"]);
        let mut source =
            ChunkSetSource::with_opener(&group, ReadOptions::default(), world.opener());
        let ts: Vec<_> = drain(&mut source).into_iter().map(|p| (p.0, p.1)).collect();
        assert_eq!(ts, vec![(1, 0), (10, 2), (11, 2)]);
        let kinds: Vec<_> = source
            .anomalies()
            .iter()
            .map(|a| (a.chunk, a.kind.code()))
            .collect();
        assert_eq!(
            kinds,
            vec![
                (Some(2), "linktype_change"),
                (Some(0), "read_error"),
                (Some(1), "read_error"),
                (Some(2), "truncated_tail"),
            ]
        );
        assert_eq!(source.warnings().len(), 3);
        assert_eq!(source.info().linktypes, vec![1, 105]);
        assert_eq!(source.bytes_read(), source.total_bytes());
        let errors: Vec<_> = source.chunk_stats().map(|s| s.error.is_some()).collect();
        assert_eq!(errors, vec![true, true, false]);
    }

    #[test]
    fn duplicates_and_chunks_without_packets() {
        let world = World::new(&[
            ("a", script(&[1, 2])),
            ("hdr", script(&[])),
            ("b", script(&[3])),
        ]);
        let mut group = world.group(&["a", "hdr", "b"]);
        let mut copy = group.members[0].clone();
        copy.entry.path = "/fake/copy/a".into();
        copy.status = super::super::MemberStatus::Duplicate { of: 0 };
        group.members.push(copy);
        let mut source =
            ChunkSetSource::with_opener(&group, ReadOptions::default(), world.opener());
        assert_eq!(source.total_bytes(), 3000);
        let ts: Vec<_> = drain(&mut source).into_iter().map(|p| (p.0, p.1)).collect();
        assert_eq!(ts, vec![(1, 0), (2, 0), (3, 2)]);
        assert_eq!(world.max_open(), 1);
        assert_eq!(source.bytes_read(), 3000);
        assert_eq!(source.anomalies()[0].kind, AnomalyKind::Duplicate { of: 0 });
    }

    #[test]
    fn empty_group_yields_nothing() {
        let group = ChunkGroup::new(GroupKind::Folder, "none".into(), Vec::new());
        let world = World::new(&[]);
        let mut source =
            ChunkSetSource::with_opener(&group, ReadOptions::default(), world.opener());
        assert_eq!(source.next_packet().unwrap(), None);
        assert_eq!(source.bytes_read(), 0);
        assert_eq!(source.total_bytes(), 0);
    }

    #[test]
    fn source_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<ChunkSetSource>();
    }
}
