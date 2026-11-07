//! Folder inventory: one entry per file, with capture metadata when the file opens.

use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use sha2::{Digest, Sha256};

use super::{ChunkSetError, ChunkStats, Opener};
use crate::source::{CaptureError, CaptureInfo, ReadWarning};

/// Files shorter than this cannot hold any capture header (pcapng needs 12 bytes to be detected).
pub const MIN_CAPTURE_LEN: u64 = 12;

/// Number of leading bytes hashed into [`Fingerprint`]: 64 KiB.
pub const FINGERPRINT_LEN: u64 = 64 * 1024;

/// Directory depth explored by a recursive inventory (the root is depth 0).
pub const MAX_DEPTH: usize = 32;

/// SHA-256 of the first [`FINGERPRINT_LEN`] bytes of a file (raw, compressed bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Fingerprint(pub [u8; 32]);

impl Fingerprint {
    /// Lowercase hexadecimal form, for storage and display.
    pub fn to_hex(&self) -> String {
        use std::fmt::Write as _;
        self.0.iter().fold(String::with_capacity(64), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
    }

    /// Fingerprint of an in-memory prefix (tests, callers hashing data themselves).
    pub fn of_bytes(data: &[u8]) -> Self {
        let cut = usize::try_from(FINGERPRINT_LEN).unwrap_or(usize::MAX);
        Self(Sha256::digest(data.get(..cut).unwrap_or(data)).into())
    }
}

/// Options of [`inventory`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct InventoryOptions {
    /// Descend into sub-directories (at most [`MAX_DEPTH`] levels; symlinked directories are
    /// not followed).
    pub recursive: bool,
    /// Read every packet of each capture to fill [`CaptureMeta::scan`] (last timestamp, packet
    /// count, warnings). Costs a full read of the folder; off by default.
    pub full_scan: bool,
}

/// Metadata of a file that opened as a capture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureMeta {
    pub info: CaptureInfo,
    /// Timestamp of the first packet, `None` when the file holds no packet.
    pub first_ts: Option<i64>,
    /// Error met while reading the first packet (or the whole file with `full_scan`).
    pub read_error: Option<String>,
    /// Reader warnings met while probing (all of them with `full_scan`).
    pub warnings: Vec<ReadWarning>,
    /// Full-read statistics, present when the inventory ran with `full_scan`.
    pub scan: Option<ChunkStats>,
}

/// What the inventory found in a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryKind {
    /// A pcap or pcapng file (possibly gzip-compressed).
    Capture(CaptureMeta),
    /// Zero-byte file.
    Empty,
    /// Fewer than [`MIN_CAPTURE_LEN`] bytes: cannot be a capture (or still being written).
    TooShort,
    /// Not a pcap/pcapng/gzip-capture file (detected by magic number).
    Unrecognized,
    /// Looks like a capture but cannot be opened (I/O error, truncated or corrupt header).
    Unreadable { reason: String },
}

/// One file of the inventory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InventoryEntry {
    pub path: PathBuf,
    /// File name (lossy UTF-8), the input of name-pattern grouping.
    pub name: String,
    /// Size on disk in bytes.
    pub size: u64,
    /// Modification time, nanoseconds since the Unix epoch, when available.
    pub mtime_ns: Option<i64>,
    /// Hash of the first 64 KiB, `None` when the file could not be read.
    pub fingerprint: Option<Fingerprint>,
    pub kind: EntryKind,
}

impl InventoryEntry {
    /// Capture metadata, when the file opened as a capture.
    pub fn capture(&self) -> Option<&CaptureMeta> {
        match &self.kind {
            EntryKind::Capture(meta) => Some(meta),
            _ => None,
        }
    }

    /// Timestamp of the first packet, when known.
    pub fn first_ts(&self) -> Option<i64> {
        self.capture().and_then(|m| m.first_ts)
    }

    /// Parent directory of the file.
    pub fn dir(&self) -> &Path {
        self.path.parent().unwrap_or(Path::new(""))
    }
}

/// A directory that could not be listed during a recursive inventory (not fatal).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalkError {
    pub path: PathBuf,
    pub reason: String,
}

/// Result of [`inventory`]: every regular file found, sorted by path.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Inventory {
    pub root: PathBuf,
    pub entries: Vec<InventoryEntry>,
    pub walk_errors: Vec<WalkError>,
}

impl Inventory {
    /// Files that are not captures (unrecognized, empty, too short, unreadable), for the report.
    pub fn rejected(&self) -> impl Iterator<Item = &InventoryEntry> {
        self.entries.iter().filter(|e| e.capture().is_none())
    }
}

/// Inventories `path` with the default opener ([`crate::reader::open`]).
///
/// `path` may be a directory or a single file (then the inventory holds that file only).
pub fn inventory(path: &Path, options: &InventoryOptions) -> Result<Inventory, ChunkSetError> {
    inventory_with(path, options, &crate::reader::open)
}

/// Same as [`inventory`] with an injected opener (tests, alternative readers).
///
/// Only an unreadable `path` itself is an error: per-file problems become entries.
pub fn inventory_with(
    path: &Path,
    options: &InventoryOptions,
    opener: &Opener,
) -> Result<Inventory, ChunkSetError> {
    let io_err = |source| ChunkSetError::Io {
        path: path.to_path_buf(),
        source,
    };
    let meta = fs::metadata(path).map_err(io_err)?;
    let mut inv = Inventory {
        root: path.to_path_buf(),
        ..Inventory::default()
    };
    let mut files = Vec::new();
    if meta.is_dir() {
        // The root must be listable; sub-directories only produce walk errors.
        let listing = fs::read_dir(path).map_err(io_err)?;
        collect(
            listing,
            0,
            options.recursive,
            &mut files,
            &mut inv.walk_errors,
        );
    } else {
        files.push(path.to_path_buf());
    }
    files.sort();
    inv.entries = files
        .into_iter()
        .map(|p| probe(p, options.full_scan, opener))
        .collect();
    Ok(inv)
}

fn collect(
    listing: fs::ReadDir,
    depth: usize,
    recursive: bool,
    files: &mut Vec<PathBuf>,
    errors: &mut Vec<WalkError>,
) {
    for item in listing {
        let item = match item {
            Ok(item) => item,
            Err(e) => {
                errors.push(WalkError {
                    path: PathBuf::new(),
                    reason: e.to_string(),
                });
                continue;
            }
        };
        let path = item.path();
        let Ok(file_type) = item.file_type() else {
            files.push(path);
            continue;
        };
        if file_type.is_dir() {
            if recursive && depth < MAX_DEPTH {
                match fs::read_dir(&path) {
                    Ok(sub) => collect(sub, depth + 1, recursive, files, errors),
                    Err(e) => errors.push(WalkError {
                        path,
                        reason: e.to_string(),
                    }),
                }
            }
        } else if file_type.is_symlink() {
            // Symlinks to files are inventoried; symlinks to directories are never followed.
            if fs::metadata(&path).is_ok_and(|m| m.is_file()) {
                files.push(path);
            }
        } else if file_type.is_file() {
            files.push(path);
        }
    }
}

/// Builds the entry of one file. Never fails: problems are described by [`EntryKind`].
pub(crate) fn probe(path: PathBuf, full_scan: bool, opener: &Opener) -> InventoryEntry {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut entry = InventoryEntry {
        name,
        size: 0,
        mtime_ns: None,
        fingerprint: None,
        kind: EntryKind::Empty,
        path,
    };
    match fs::metadata(&entry.path) {
        Ok(meta) => {
            entry.size = meta.len();
            entry.mtime_ns = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .and_then(|d| i64::try_from(d.as_nanos()).ok());
        }
        Err(e) => {
            entry.kind = EntryKind::Unreadable {
                reason: e.to_string(),
            };
            return entry;
        }
    }
    if entry.size == 0 {
        return entry;
    }
    match fingerprint_file(&entry.path) {
        Ok(fp) => entry.fingerprint = Some(fp),
        Err(e) => {
            entry.kind = EntryKind::Unreadable {
                reason: e.to_string(),
            };
            return entry;
        }
    }
    if entry.size < MIN_CAPTURE_LEN {
        entry.kind = EntryKind::TooShort;
        return entry;
    }
    entry.kind = match opener(&entry.path) {
        Ok(mut source) => {
            let info = source.info().clone();
            let (first_ts, read_error, scan) = if full_scan {
                let stats = ChunkStats::read_all(source.as_mut());
                (stats.first_ts, stats.error.clone(), Some(stats))
            } else {
                match source.next_packet() {
                    Ok(pkt) => (pkt.map(|p| p.ts_ns), None, None),
                    Err(e) => (None, Some(e.to_string()), None),
                }
            };
            EntryKind::Capture(CaptureMeta {
                // Interfaces declared before the first packet are now known.
                info: merge_info(info, source.info()),
                first_ts,
                read_error,
                warnings: source.warnings().to_vec(),
                scan,
            })
        }
        Err(CaptureError::UnknownFormat) => EntryKind::Unrecognized,
        Err(e) => EntryKind::Unreadable {
            reason: e.to_string(),
        },
    };
    entry
}

/// `info` completed with the link types `later` learned while reading.
fn merge_info(mut info: CaptureInfo, later: &CaptureInfo) -> CaptureInfo {
    for lt in &later.linktypes {
        if !info.linktypes.contains(lt) {
            info.linktypes.push(*lt);
        }
    }
    if info.snaplen.is_none() {
        info.snaplen = later.snaplen;
    }
    info
}

fn fingerprint_file(path: &Path) -> io::Result<Fingerprint> {
    let mut hasher = Sha256::new();
    let mut reader = File::open(path)?.take(FINGERPRINT_LEN);
    let mut buf = [0u8; 8192];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => hasher.update(buf.get(..n).unwrap_or_default()),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(Fingerprint(hasher.finalize().into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_hex_and_prefix() {
        let fp = Fingerprint::of_bytes(b"abc");
        assert_eq!(
            fp.to_hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let mut big = vec![7u8; 70_000];
        let a = Fingerprint::of_bytes(&big);
        big[69_999] = 8;
        assert_eq!(a, Fingerprint::of_bytes(&big));
    }

    #[test]
    fn file_fingerprint_matches_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        let data: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
        fs::write(&path, &data).unwrap();
        assert_eq!(
            fingerprint_file(&path).unwrap(),
            Fingerprint::of_bytes(&data)
        );
    }
}
