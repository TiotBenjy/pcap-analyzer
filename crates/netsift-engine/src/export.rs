//! "Save PCAP": export of a whole session, a time range or one flow to a pcapng file
//! (`docs/specs/export-pcap.md`, ADR-021).
//!
//! The source chunks are read again with the import's own chunk-set reader
//! ([`ChunkSetSource`]): same order (k-way merge by timestamp, ties by chunk then offset), same
//! duplicate handling (duplicate and ignored chunks are never read). Only the chunks whose time
//! span (`chunks.first_ts..=last_ts`) intersects the request are opened; each of them is first
//! checked against what the import recorded (size, modification time, SHA-256 of the first
//! 64 KiB), and checked again once read, so that a file replaced or modified meanwhile never
//! yields a silently different export.
//!
//! Two steps, so that a caller can report source errors synchronously and run the long part
//! elsewhere: [`plan_export`] (database reads and source checks, fast) then [`ExportPlan::run`]
//! (streaming read and write, bounded memory, cancellable). The file is written as
//! `<dest>.part` and renamed to `<dest>` only when complete; the partial file is removed on
//! error and on cancellation.
//!
//! Flow selection: packets of both directions of the 5-tuple of the `flows` row, between its
//! first and last timestamps, with the same decoding as the flow table (`netsift_dissect`).
//! IP fragments: a first fragment (offset 0) carries the ports and is matched like any packet;
//! the following fragments of the same datagram (source, destination, identification) are
//! included when their first fragment was. Since the flow table dates a reassembled datagram by
//! its last fragment, the first fragments of a flow can precede `first_ts`: fragments are
//! accepted up to [`FRAGMENT_SLACK_NS`] before it. Not included: fragments that arrive before
//! their first fragment, and ICMP errors about the flow (they belong to an ICMP flow).
//!
//! The flow is found by its 5-tuple and time span, never by recomputing its id. Limit: two
//! successive flows with the same 5-tuple whose spans overlap (port reused at once, identical
//! timestamps) cannot be told apart: exporting either gives the packets of both.
//!
//! Timestamps going backwards: [`ChunkSetSource`] delivers each file in file order, so when the
//! import did not read the packets in timestamp order (`read_in_time_order`: `out_of_order`,
//! `timestamp_backwards` or `merge_fanout_limit` anomaly, truncated anomaly list, or no
//! end-of-import statistics), the read never stops early and a flow has no lower time bound
//! (its `first_ts` is the time of its first packet *read*, not the smallest): the chunk window
//! and the 5-tuple select the packets, which may then include an earlier flow with the same
//! 5-tuple in the chunks read.

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use netsift_analyze::dissect::{self, Transport, decode_transport};
use netsift_capture::chunkset::{
    AnomalyKind, ChunkGroup, ChunkMember, ChunkSetSource, EntryKind, GroupKind, InventoryEntry,
    MemberStatus, ReadOptions, probe_file,
};
use netsift_capture::writer::{PcapNgWriter, WriteError};
use netsift_capture::{CaptureError, PacketSource, RawPacket, ReadWarning};
use netsift_store::query::{PageRequest, chunks_page, flow_by_id, read_in_time_order};
use netsift_store::{ChunkRow, ChunkStatus, FlowRow, Session, StoreError};

use crate::options::CancelToken;

/// How long before a flow's first timestamp its IP fragments are still accepted: the flow
/// table's defragmentation timeout (`FlowConfig::defrag_timeout_ns`, 30 s).
pub const FRAGMENT_SLACK_NS: i64 = 30_000_000_000;
/// Suffix of the file being written.
pub const PART_SUFFIX: &str = ".part";
/// Fragmented datagrams of a flow being followed at once (bounded memory).
const MAX_FRAGMENT_KEYS: usize = 4096;
/// Minimum time between two progress callbacks.
const PROGRESS_EVERY: Duration = Duration::from_millis(200);
/// Write buffer of the output file.
const WRITE_BUFFER: usize = 1024 * 1024;
/// Chunk rows read per query.
const CHUNK_PAGE: u32 = 1000;

/// What to export.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Selection {
    /// Every packet of the session.
    Session,
    /// Packets with `from_ns <= ts <= to_ns`.
    Range { from_ns: i64, to_ns: i64 },
    /// Packets of the flow with this `flows.id`.
    Flow { id: u64 },
}

/// Progress of [`ExportPlan::run`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ExportProgress {
    /// Bytes read from the source files (compressed size for `.gz`).
    pub bytes_read: u64,
    /// Size of the source files to read.
    pub bytes_total: u64,
    pub packets: u64,
    pub bytes_written: u64,
}

/// Result of a successful export.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExportReport {
    pub packets: u64,
    /// Size of the file.
    pub bytes_written: u64,
    /// Source chunks read.
    pub chunks_read: usize,
    /// Read errors met in the sources (a chunk that stops early, a record skipped): the file
    /// may lack packets. The import met the same errors on the same files.
    pub read_errors: u64,
}

/// Errors of [`plan_export`] and [`ExportPlan::run`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ExportError {
    #[error("flow {0} not found")]
    FlowNotFound(u64),
    #[error("the end of the range is before its start")]
    InvalidRange,
    /// `name` is the file name only (the full path is in the session's `chunks` table).
    #[error("source file {name} is missing or unreadable")]
    SourceMissing { chunk: u32, name: String },
    #[error("source file {name} changed since the import ({what})")]
    SourceModified {
        chunk: u32,
        name: String,
        what: &'static str,
    },
    #[error("{} already exists", .0.display())]
    DestinationExists(PathBuf),
    #[error("export cancelled")]
    Cancelled,
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("cannot read the sources: {0}")]
    Read(#[from] CaptureError),
    #[error("cannot write the export: {0}")]
    Write(#[from] WriteError),
    #[error("cannot write the export: {0}")]
    Io(#[from] io::Error),
}

/// A checked export, ready to run.
pub struct ExportPlan {
    group: ChunkGroup,
    /// Link type of the first interface and snaplen of each member (by member index).
    sources: Vec<Option<(u32, u32)>>,
    /// Chunks to read, checked again after reading.
    needed: Vec<ChunkRow>,
    /// Inclusive bounds of the packet timestamps read.
    window: (i64, i64),
    filter: Option<FlowFilter>,
    /// The import read the packets in timestamp order (`read_in_time_order`): the read may stop
    /// at the first packet after the window.
    ordered: bool,
}

impl std::fmt::Debug for ExportPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExportPlan")
            .field("chunks", &self.needed.len())
            .field("window", &self.window)
            .field("flow", &self.filter.is_some())
            .field("ordered", &self.ordered)
            .finish_non_exhaustive()
    }
}

/// Reads what `selection` needs from the session database and checks the source chunks.
pub fn plan_export(session: &Session, selection: &Selection) -> Result<ExportPlan, ExportError> {
    let ordered = read_in_time_order(session.conn())?;
    let (window, filter) = match *selection {
        Selection::Session => ((i64::MIN, i64::MAX), None),
        Selection::Range { from_ns, to_ns } => {
            if to_ns < from_ns {
                return Err(ExportError::InvalidRange);
            }
            ((from_ns, to_ns), None)
        }
        Selection::Flow { id } => {
            let flow = flow_by_id(session.conn(), id)?.ok_or(ExportError::FlowNotFound(id))?;
            let filter = FlowFilter::new(&flow, ordered);
            // Out of order, a packet of the flow can be older than `first_ts` (the time of the
            // first packet read, not the smallest): no lower bound then.
            let from = if ordered {
                flow.first_ts.saturating_sub(FRAGMENT_SLACK_NS)
            } else {
                i64::MIN
            };
            ((from, flow.last_ts), Some(filter))
        }
    };
    let rows = all_chunks(session)?;
    let mut members = Vec::with_capacity(rows.len());
    let mut sources = Vec::with_capacity(rows.len());
    let mut needed = Vec::new();
    for row in rows {
        if is_needed(&row, window) {
            let entry = check(&row)?;
            sources.push(Some((
                row.linktypes.first().copied().unwrap_or(0),
                row.snaplen.unwrap_or(0),
            )));
            members.push(ChunkMember {
                entry,
                seq: None,
                status: MemberStatus::Active,
            });
            needed.push(row);
        } else {
            sources.push(None);
            members.push(placeholder(&row));
        }
    }
    // Built directly, without `ChunkGroup::new`: the members keep the order of the import.
    let group = ChunkGroup {
        kind: GroupKind::Merged,
        label: String::new(),
        members,
    };
    Ok(ExportPlan {
        group,
        sources,
        needed,
        window,
        filter,
        ordered,
    })
}

impl ExportPlan {
    /// Size of the source files to read (the denominator of the progress).
    pub fn total_bytes(&self) -> u64 {
        self.group.total_bytes()
    }

    /// Number of source chunks to read.
    pub fn chunks(&self) -> usize {
        self.needed.len()
    }

    /// Writes the export to `dest` (through `<dest>.part`). `progress` is called at most every
    /// 200 ms, and once at the end. On error or cancellation nothing is left on disk.
    pub fn run(
        mut self,
        dest: &Path,
        cancel: &CancelToken,
        progress: &mut dyn FnMut(&ExportProgress),
    ) -> Result<ExportReport, ExportError> {
        if dest.exists() {
            return Err(ExportError::DestinationExists(dest.to_path_buf()));
        }
        let part = part_path(dest);
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&part)
            .map_err(|e| match e.kind() {
                io::ErrorKind::AlreadyExists => ExportError::DestinationExists(part.clone()),
                _ => ExportError::Io(e),
            })?;
        let mut guard = PartGuard {
            path: part.clone(),
            armed: true,
        };
        let application = format!("NetSift {}", env!("CARGO_PKG_VERSION"));
        let mut writer =
            PcapNgWriter::new(BufWriter::with_capacity(WRITE_BUFFER, file), &application)?;
        let mut source = ChunkSetSource::new(&self.group, ReadOptions::default());
        let total = source.total_bytes();
        let (from, to) = self.window;
        let mut last_report = Instant::now();
        loop {
            if cancel.is_cancelled() {
                return Err(ExportError::Cancelled);
            }
            // Before any `continue`: skipped packets move the progress too.
            if last_report.elapsed() >= PROGRESS_EVERY {
                last_report = Instant::now();
                progress(&ExportProgress {
                    bytes_read: source.bytes_read().min(total),
                    bytes_total: total,
                    packets: writer.packets(),
                    bytes_written: writer.bytes_written(),
                });
            }
            let Some(packet) = source.next_packet()? else {
                break;
            };
            if packet.ts_ns > to {
                // In timestamp order, nothing later can be in range. Otherwise (a file whose
                // timestamps go backwards), an older packet may still come.
                if self.ordered {
                    break;
                }
                continue;
            }
            if packet.ts_ns < from {
                continue;
            }
            if let Some(filter) = self.filter.as_mut()
                && !filter.matches(&packet)
            {
                continue;
            }
            let snaplen = self.snaplen(&packet);
            writer.write_packet(
                packet.linktype,
                snaplen,
                packet.ts_ns,
                packet.orig_len,
                &packet.data,
            )?;
        }
        let read_errors = source
            .anomalies()
            .iter()
            .filter(|a| {
                matches!(
                    a.kind,
                    AnomalyKind::ReadError { .. }
                        | AnomalyKind::Read(ReadWarning::SkippedRecord { .. })
                )
            })
            .count();
        let report = ExportReport {
            packets: writer.packets(),
            bytes_written: writer.bytes_written(),
            chunks_read: self.needed.len(),
            read_errors: u64::try_from(read_errors).unwrap_or(u64::MAX),
        };
        let file = writer
            .into_inner()?
            .into_inner()
            .map_err(io::IntoInnerError::into_error)?;
        file.sync_all()?;
        drop(file);
        // A source replaced or modified while it was read would give a different export.
        for row in &self.needed {
            if cancel.is_cancelled() {
                return Err(ExportError::Cancelled);
            }
            check(row)?;
        }
        if dest.exists() {
            return Err(ExportError::DestinationExists(dest.to_path_buf()));
        }
        fs::rename(&part, dest)?;
        guard.armed = false;
        sync_parent(dest);
        progress(&ExportProgress {
            bytes_read: total,
            bytes_total: total,
            packets: report.packets,
            bytes_written: report.bytes_written,
        });
        Ok(report)
    }

    /// Snaplen of the interface of `packet`: the chunk's when the packet comes from its first
    /// interface (the only one whose snaplen the import records), else 0 (unknown).
    fn snaplen(&self, packet: &RawPacket) -> u32 {
        let Some((linktype, snaplen)) = usize::try_from(packet.chunk_id)
            .ok()
            .and_then(|i| self.sources.get(i).copied().flatten())
        else {
            return 0;
        };
        let fits = snaplen == 0 || u32::try_from(packet.data.len()).is_ok_and(|l| l <= snaplen);
        if packet.linktype == linktype && fits {
            snaplen
        } else {
            0
        }
    }
}

/// `<dest>.part`.
pub fn part_path(dest: &Path) -> PathBuf {
    let mut name = dest.file_name().unwrap_or_default().to_os_string();
    name.push(PART_SUFFIX);
    dest.with_file_name(name)
}

/// Removes the `*.pcapng.part` files of `dir` left by an interrupted export (crash, kill).
/// Returns how many were removed. Call it at startup, before any export runs.
pub fn remove_orphan_parts(dir: &Path) -> usize {
    let Ok(listing) = fs::read_dir(dir) else {
        return 0;
    };
    let suffix = format!(".pcapng{PART_SUFFIX}");
    listing
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .filter(|e| e.file_name().to_string_lossy().ends_with(&suffix))
        .filter(|e| fs::remove_file(e.path()).is_ok())
        .count()
}

/// Removes the partial file unless the export completed.
struct PartGuard {
    path: PathBuf,
    armed: bool,
}

impl Drop for PartGuard {
    fn drop(&mut self) {
        if self.armed
            && let Err(e) = fs::remove_file(&self.path)
            && e.kind() != io::ErrorKind::NotFound
        {
            tracing::warn!("cannot remove the partial export: {e}");
        }
    }
}

/// Best effort: makes the rename durable (not supported for directories on Windows).
fn sync_parent(path: &Path) {
    if let Some(parent) = path.parent()
        && let Ok(dir) = File::open(parent)
    {
        let _ = dir.sync_all();
    }
}

fn all_chunks(session: &Session) -> Result<Vec<ChunkRow>, StoreError> {
    let mut rows = Vec::new();
    let mut request = PageRequest::first(CHUNK_PAGE);
    loop {
        let page = chunks_page(session.conn(), &request)?;
        rows.extend(page.items);
        match page.next_cursor {
            Some(cursor) => request.cursor = Some(cursor),
            None => return Ok(rows),
        }
    }
}

/// True when the chunk was read by the import and its time span meets `window`. A chunk whose
/// end is unknown (import interrupted before reading it) is kept when it starts in time.
fn is_needed(row: &ChunkRow, (from, to): (i64, i64)) -> bool {
    let read =
        matches!(row.status, ChunkStatus::Ok | ChunkStatus::Truncated) && row.format.is_some();
    let Some(first) = row.first_ts else {
        return false;
    };
    read && first <= to && row.last_ts.is_none_or(|last| last >= from)
}

fn file_name(row: &ChunkRow) -> String {
    Path::new(&row.path)
        .file_name()
        .map_or_else(|| row.path.clone(), |n| n.to_string_lossy().into_owned())
}

/// Probes the source file of `row` and compares it with what the import recorded.
fn check(row: &ChunkRow) -> Result<InventoryEntry, ExportError> {
    let entry = probe_file(Path::new(&row.path));
    let name = file_name(row);
    let modified = |what| ExportError::SourceModified {
        chunk: row.id,
        name: name.clone(),
        what,
    };
    if matches!(entry.kind, EntryKind::Unreadable { .. }) {
        return Err(ExportError::SourceMissing {
            chunk: row.id,
            name,
        });
    }
    if entry.size != row.file_size {
        return Err(modified("size"));
    }
    if row.mtime_ns.is_some() && entry.mtime_ns != row.mtime_ns {
        return Err(modified("modification time"));
    }
    if row.head_hash.is_some() && entry.fingerprint.map(|f| f.to_hex()) != row.head_hash {
        return Err(modified("content"));
    }
    if entry.capture().is_none() {
        return Err(modified("content"));
    }
    Ok(entry)
}

/// Member that keeps the chunk numbering of the import but is never opened.
fn placeholder(row: &ChunkRow) -> ChunkMember {
    ChunkMember {
        entry: InventoryEntry {
            path: PathBuf::from(&row.path),
            name: file_name(row),
            size: row.file_size,
            mtime_ns: row.mtime_ns,
            fingerprint: None,
            kind: EntryKind::Unrecognized,
        },
        seq: None,
        status: MemberStatus::Skipped,
    }
}

/// Packets of one flow, both directions (see the module documentation).
struct FlowFilter {
    proto: u8,
    a: (IpAddr, u16),
    b: (IpAddr, u16),
    first_ts: i64,
    /// Packets older than `first_ts` are rejected (only when the session was read in order).
    strict_start: bool,
    /// Fragmented datagrams whose first fragment matched: (source, destination, id).
    fragments: HashSet<(IpAddr, IpAddr, u32)>,
}

impl FlowFilter {
    fn new(flow: &FlowRow, strict_start: bool) -> Self {
        Self {
            proto: flow.transport,
            a: (flow.src_ip, flow.src_port),
            b: (flow.dst_ip, flow.dst_port),
            first_ts: flow.first_ts,
            strict_start,
            fragments: HashSet::new(),
        }
    }

    fn tuple(&self, src: (IpAddr, u16), dst: (IpAddr, u16)) -> bool {
        (src == self.a && dst == self.b) || (src == self.b && dst == self.a)
    }

    fn matches(&mut self, packet: &RawPacket) -> bool {
        let decoded = dissect::decode(packet.linktype, &packet.data);
        let Some(ip) = decoded.ip().copied() else {
            return false;
        };
        let Some(fragment) = ip.fragment else {
            // Same conditions as the flow table: decoded without error, ports or 0.
            let too_early = self.strict_start && packet.ts_ns < self.first_ts;
            if decoded.error.is_some() || too_early || ip.protocol != self.proto {
                return false;
            }
            let (sport, dport) = decoded.ports().unwrap_or((0, 0));
            return self.tuple((ip.src, sport), (ip.dst, dport));
        };
        if fragment.next_header != self.proto {
            return false;
        }
        let key = (ip.src, ip.dst, fragment.id);
        if fragment.is_first() {
            let (sport, dport) = match decode_transport(fragment.next_header, decoded.ip_payload) {
                Ok(Some((Transport::Tcp(t), _))) => (t.src_port, t.dst_port),
                Ok(Some((Transport::Udp(u), _))) => (u.src_port, u.dst_port),
                _ => (0, 0),
            };
            if !self.tuple((ip.src, sport), (ip.dst, dport)) {
                return false;
            }
            if fragment.more && self.fragments.len() < MAX_FRAGMENT_KEYS {
                self.fragments.insert(key);
            }
            true
        } else if fragment.more {
            self.fragments.contains(&key)
        } else {
            // Last fragment: the datagram is complete.
            self.fragments.remove(&key)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn part_path_appends_the_suffix() {
        assert_eq!(
            part_path(Path::new("/x/a.pcapng")),
            PathBuf::from("/x/a.pcapng.part")
        );
    }

    #[test]
    fn orphan_parts_are_removed_and_nothing_else() {
        let tmp = tempfile::tempdir().unwrap();
        for name in ["a.pcapng.part", "b.pcapng", "c.part", "d.pcapng.part"] {
            fs::write(tmp.path().join(name), b"x").unwrap();
        }
        assert_eq!(remove_orphan_parts(tmp.path()), 2);
        let mut left: Vec<_> = fs::read_dir(tmp.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        left.sort();
        assert_eq!(left, ["b.pcapng", "c.part"]);
        assert_eq!(remove_orphan_parts(&tmp.path().join("missing")), 0);
    }
}
