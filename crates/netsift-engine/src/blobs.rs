//! Extracted objects of a session, stored by their SHA-256 under `blobs/` (see
//! `netsift_store::session::blob_relpath`). Each shard writes its own blobs: contents never
//! travel through the writer channel, only their [`BlobRef`].

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

use netsift_analyze::BlobRef;
use netsift_store::session::blob_relpath;
use sha2::{Digest as _, Sha256};

/// Largest object stored (docs/ARCHITECTURE.md, "Performance").
pub const MAX_BLOB_SIZE: usize = 64 * 1024 * 1024;
/// Digests remembered per shard to skip the file system check of objects already written.
const MAX_KNOWN: usize = 65_536;

/// Blob store of one shard.
#[derive(Debug)]
pub(crate) struct BlobWriter {
    dir: Arc<PathBuf>,
    shard: usize,
    /// Names the temporary files of this shard.
    seq: u64,
    /// One warning per shard is enough.
    warned: bool,
    /// Digests of the blobs this shard wrote or found (bounded: cleared when full).
    known: HashSet<[u8; 32]>,
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

impl BlobWriter {
    pub(crate) fn new(dir: Arc<PathBuf>, shard: usize) -> Self {
        Self {
            dir,
            shard,
            seq: 0,
            warned: false,
            known: HashSet::new(),
        }
    }

    /// Stores `data` unless an identical blob exists. The file appears atomically (temporary
    /// file then rename), so concurrent shards storing the same content are harmless.
    pub(crate) fn put(&mut self, data: &[u8]) -> Option<BlobRef> {
        if data.len() > MAX_BLOB_SIZE {
            return None;
        }
        let sha256: [u8; 32] = Sha256::digest(data).into();
        let blob = BlobRef {
            sha256,
            size: u64::try_from(data.len()).ok()?,
        };
        if self.known.contains(&sha256) {
            return Some(blob);
        }
        let name = hex(&sha256);
        let path = self.dir.join(blob_relpath(&name)?);
        let stored = if path.is_file() {
            Ok(())
        } else {
            self.write(&path, &name, data)
        };
        match stored {
            Ok(()) => {
                if self.known.len() >= MAX_KNOWN {
                    self.known.clear();
                }
                self.known.insert(sha256);
                Some(blob)
            }
            Err(e) => {
                if !self.warned {
                    self.warned = true;
                    tracing::warn!(shard = self.shard, "cannot store an extracted object: {e}");
                }
                None
            }
        }
    }

    fn write(&mut self, path: &std::path::Path, name: &str, data: &[u8]) -> std::io::Result<()> {
        let parent = path
            .parent()
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
        std::fs::create_dir_all(parent)?;
        self.seq += 1;
        let tmp = parent.join(format!(
            ".{name}.{}.{}.{}.tmp",
            std::process::id(),
            self.shard,
            self.seq
        ));
        if let Err(e) = std::fs::write(&tmp, data) {
            // A partial temporary file (disk full) must not stay behind.
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
        if let Err(e) = std::fs::rename(&tmp, path) {
            let _ = std::fs::remove_file(&tmp);
            // Another shard may hold the same content open meanwhile (Windows then refuses to
            // replace it); an existing target has the same content, so that is not an error.
            if !path.is_file() {
                return Err(e);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stores_once_by_digest() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = Arc::new(tmp.path().join("blobs"));
        let mut a = BlobWriter::new(Arc::clone(&dir), 0);
        let mut b = BlobWriter::new(Arc::clone(&dir), 1);
        let r1 = a.put(b"certificate").unwrap();
        let r2 = b.put(b"certificate").unwrap();
        assert_eq!(r1, r2);
        assert_eq!(r1.size, 11);
        let name = r1.to_hex();
        let path = dir.join(&name[..2]).join(&name);
        assert_eq!(std::fs::read(&path).unwrap(), b"certificate");
        let files: Vec<_> = std::fs::read_dir(dir.join(&name[..2])).unwrap().collect();
        assert_eq!(files.len(), 1, "no temporary file left");
        assert!(a.put(&vec![0; MAX_BLOB_SIZE + 1]).is_none());
        // Known digests skip the file system: a removed file is not written again by `a`.
        std::fs::remove_file(&path).unwrap();
        assert_eq!(a.put(b"certificate"), Some(r1));
        assert!(!path.exists());
    }

    #[test]
    fn unwritable_directory_returns_none() {
        let tmp = tempfile::TempDir::new().unwrap();
        let file = tmp.path().join("not-a-dir");
        std::fs::write(&file, b"x").unwrap();
        let mut w = BlobWriter::new(Arc::new(file), 0);
        assert!(w.put(b"data").is_none());
        assert!(w.put(b"other").is_none());
    }
}
