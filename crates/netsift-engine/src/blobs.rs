//! Extracted objects of a session, stored by their SHA-256 under `blobs/` (see
//! `netsift_store::session::blob_relpath`). Each shard writes its own blobs: contents never
//! travel through the writer channel, only their [`BlobRef`].

use std::path::PathBuf;
use std::sync::Arc;

use netsift_analyze::BlobRef;
use netsift_store::session::blob_relpath;
use sha2::{Digest as _, Sha256};

/// Largest object stored (docs/ARCHITECTURE.md, "Performance").
pub const MAX_BLOB_SIZE: usize = 64 * 1024 * 1024;

/// Blob store of one shard.
#[derive(Debug)]
pub(crate) struct BlobWriter {
    dir: Arc<PathBuf>,
    shard: usize,
    /// Names the temporary files of this shard.
    seq: u64,
    /// One warning per shard is enough.
    warned: bool,
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
        let name = hex(&sha256);
        let path = self.dir.join(blob_relpath(&name)?);
        if path.is_file() {
            return Some(blob);
        }
        match self.write(&path, &name, data) {
            Ok(()) => Some(blob),
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
        std::fs::write(&tmp, data)?;
        if let Err(e) = std::fs::rename(&tmp, path) {
            let _ = std::fs::remove_file(&tmp);
            // Another shard may have stored the same content meanwhile (Windows refuses to
            // replace an existing file).
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
