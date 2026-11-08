//! State of the country database used by the imports, reported by `GET /server-info`.
//!
//! The database is opened (about 10 MiB, bounded by `netsift_geo::MAX_DB_BYTES`) only when the
//! file changes: the result is cached by size and modification time, so the About view sees a
//! database installed or replaced while the server runs (`./x.sh geoip`) without reopening it
//! on every request.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use std::time::SystemTime;

use netsift_geo::GeoDb;

use crate::dto::{GeoipInfo, GeoipStatus};

/// Size and modification time of the database file.
type Stamp = (u64, Option<SystemTime>);

pub(crate) struct GeoipProbe {
    path: PathBuf,
    cache: Mutex<Option<(Stamp, GeoipInfo)>>,
}

impl GeoipProbe {
    /// Probe of the database at `path` (the one the imports read).
    pub(crate) fn new(path: PathBuf) -> Self {
        Self {
            path,
            cache: Mutex::new(None),
        }
    }

    /// Current state of the database (blocking: file system and, after a change, a full read).
    pub(crate) fn info(&self) -> GeoipInfo {
        let Some(stamp) = stamp(&self.path) else {
            return GeoipInfo::missing();
        };
        let mut cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some((cached, info)) = cache.as_ref()
            && *cached == stamp
        {
            return info.clone();
        }
        let info = probe(&self.path);
        *cache = Some((stamp, info.clone()));
        info
    }
}

fn stamp(path: &Path) -> Option<Stamp> {
    let meta = std::fs::metadata(path).ok()?;
    meta.is_file().then(|| (meta.len(), meta.modified().ok()))
}

fn probe(path: &Path) -> GeoipInfo {
    match GeoDb::open(path) {
        Ok(db) => GeoipInfo {
            status: GeoipStatus::Available,
            built_at_us: i64::try_from(db.build_epoch())
                .ok()
                .and_then(|s| s.checked_mul(1_000_000)),
        },
        Err(e) if e.is_not_found() => GeoipInfo::missing(),
        Err(e) => {
            tracing::warn!(path = %path.display(), "GeoIP database unusable: {e}");
            GeoipInfo {
                status: GeoipStatus::Invalid,
                built_at_us: None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use netsift_geo::test_util::MmdbBuilder;

    use super::*;

    #[test]
    fn reports_missing_available_and_invalid_databases() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("geoip").join(netsift_geo::DB_FILE_NAME);
        let probe = GeoipProbe::new(path.clone());
        assert_eq!(probe.info(), GeoipInfo::missing());

        // A directory in place of the file is not a database.
        std::fs::create_dir_all(&path).unwrap();
        assert_eq!(probe.info().status, GeoipStatus::Missing);
        std::fs::remove_dir(&path).unwrap();

        MmdbBuilder::new()
            .network("8.8.8.0".parse::<IpAddr>().unwrap(), 24, "US")
            .write(&path)
            .unwrap();
        let info = probe.info();
        assert_eq!(info.status, GeoipStatus::Available);
        assert!(info.built_at_us.is_some());

        // Replaced by garbage of another size: the cache is invalidated.
        std::fs::write(&path, b"not a database").unwrap();
        assert_eq!(probe.info().status, GeoipStatus::Invalid);

        std::fs::remove_file(&path).unwrap();
        assert_eq!(probe.info().status, GeoipStatus::Missing);
    }
}
