//! Country database of the imports: state reported by `GET /server-info`, update by download
//! (`POST /geoip/download`) or from a file (`POST /geoip/import`), progress (`GET /geoip/update`).
//!
//! - Two candidate files: the user copy `<data_dir>/geoip/dbip-country-lite.mmdb` (written by
//!   the updates and by `./x.sh geoip`), read first, then the copy shipped with the desktop
//!   bundle. The loaded database is kept in memory and shared with the imports (`Arc<GeoDb>`).
//! - Hot reload: an update swaps the shared database once the new file is installed; imports
//!   started afterwards use it, a running import keeps the one it started with. A file replaced
//!   behind the server's back is noticed by its size, modification time and (Unix) inode.
//! - One update at a time; a refused file never replaces the current one (`netsift_geo::install`).

mod download;
#[cfg(test)]
mod tests;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use netsift_geo::{GeoDb, GeoError};

use crate::dto::{
    GeoipImportRequest, GeoipInfo, GeoipSource, GeoipStatus, GeoipUpdate, GeoipUpdatePhase,
};
use crate::extract::ApiJson;
use crate::{ApiError, AppState, blocking, fs};

pub(crate) use download::Source as DownloadSource;

pub(crate) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/geoip/download", post(download_latest))
        .route("/geoip/import", post(import_file))
        .route("/geoip/update", get(update_state))
}

/// Size, modification time and inode (0 where unknown) of a database file.
type Stamp = (u64, Option<SystemTime>, u64);
/// Stamps of the user file and of the bundled one.
type Key = (Option<Stamp>, Option<Stamp>);

struct Loaded {
    key: Option<Key>,
    db: Option<Arc<GeoDb>>,
    info: GeoipInfo,
}

pub(crate) struct Geoip {
    /// User copy: read first, written by the updates.
    user_path: PathBuf,
    /// Copy shipped with the application, read when the user copy is missing or unusable.
    bundled_path: Option<PathBuf>,
    loaded: Mutex<Loaded>,
    updating: AtomicBool,
    progress: Mutex<GeoipUpdate>,
    source: Mutex<DownloadSource>,
}

impl Geoip {
    pub(crate) fn new(user_path: PathBuf, bundled_path: Option<PathBuf>) -> Self {
        Self {
            user_path,
            bundled_path,
            loaded: Mutex::new(Loaded {
                key: None,
                db: None,
                info: GeoipInfo::missing(),
            }),
            updating: AtomicBool::new(false),
            progress: Mutex::new(GeoipUpdate::idle()),
            source: Mutex::new(DownloadSource::default()),
        }
    }

    /// Database to hand to a new import, and its state (blocking: file system and, after a
    /// change of the files, a full read).
    pub(crate) fn current(&self) -> (Option<Arc<GeoDb>>, GeoipInfo) {
        let key = self.key();
        let mut loaded = lock(&self.loaded);
        if loaded.key != Some(key) {
            let (db, info) = self.load(key);
            *loaded = Loaded {
                key: Some(key),
                db,
                info,
            };
        }
        (loaded.db.clone(), loaded.info.clone())
    }

    fn key(&self) -> Key {
        (
            stamp(&self.user_path),
            self.bundled_path.as_deref().and_then(stamp),
        )
    }

    fn load(&self, (user, bundled): Key) -> (Option<Arc<GeoDb>>, GeoipInfo) {
        let candidates = [
            (Some(self.user_path.as_path()), user, GeoipSource::User),
            (self.bundled_path.as_deref(), bundled, GeoipSource::Bundled),
        ];
        let mut invalid = false;
        for (path, stamp, source) in candidates {
            let (Some(path), Some(stamp)) = (path, stamp) else {
                continue;
            };
            match GeoDb::open(path) {
                Ok(db) => {
                    tracing::debug!(path = %path.display(), ?db, "GeoIP database loaded");
                    let info = info(&db, source, stamp);
                    return (Some(Arc::new(db)), info);
                }
                Err(e) if e.is_not_found() => {}
                Err(e) => {
                    tracing::warn!(path = %path.display(), "GeoIP database unusable: {e}");
                    invalid = true;
                }
            }
        }
        let info = if invalid {
            GeoipInfo {
                status: GeoipStatus::Invalid,
                ..GeoipInfo::missing()
            }
        } else {
            GeoipInfo::missing()
        };
        (None, info)
    }

    /// Validates and installs `bytes` (decoded database) as the user copy, then makes it the
    /// database of the next imports.
    fn install(&self, bytes: Vec<u8>) -> Result<GeoipInfo, ApiError> {
        let db = netsift_geo::install(&self.user_path, bytes).map_err(install_error)?;
        let key = self.key();
        let info = key.0.map_or_else(GeoipInfo::missing, |stamp| {
            info(&db, GeoipSource::User, stamp)
        });
        *lock(&self.loaded) = Loaded {
            key: Some(key),
            db: Some(Arc::new(db)),
            info: info.clone(),
        };
        tracing::info!(built_at_us = ?info.built_at_us, "GeoIP database updated");
        Ok(info)
    }

    fn set_progress(&self, update: GeoipUpdate) {
        *lock(&self.progress) = update;
    }

    fn source(&self) -> DownloadSource {
        lock(&self.source).clone()
    }

    #[cfg(test)]
    pub(crate) fn set_source(&self, source: DownloadSource) {
        *lock(&self.source) = source;
    }
}

/// Exclusive right to update the database; released (and the progress reset) on drop.
struct UpdateGuard(Arc<AppState>);

impl UpdateGuard {
    fn begin(state: &Arc<AppState>, phase: GeoipUpdatePhase) -> Result<Self, ApiError> {
        if state.geoip.updating.swap(true, Ordering::AcqRel) {
            return Err(ApiError::GeoipUpdateRunning);
        }
        state.geoip.set_progress(GeoipUpdate {
            phase,
            ..GeoipUpdate::idle()
        });
        Ok(Self(Arc::clone(state)))
    }
}

impl Drop for UpdateGuard {
    fn drop(&mut self) {
        self.0.geoip.set_progress(GeoipUpdate::idle());
        self.0.geoip.updating.store(false, Ordering::Release);
    }
}

/// `POST /geoip/download`: downloads the latest DB-IP database (ADR-015) and installs it.
async fn download_latest(State(state): State<Arc<AppState>>) -> Result<Json<GeoipInfo>, ApiError> {
    let guard = UpdateGuard::begin(&state, GeoipUpdatePhase::Downloading)?;
    let source = state.geoip.source();
    let progress = Arc::clone(&state);
    let raw = download::fetch(
        &source,
        SystemTime::now(),
        netsift_geo::MAX_COMPRESSED_BYTES,
        move |received, total| {
            progress.geoip.set_progress(GeoipUpdate {
                phase: GeoipUpdatePhase::Downloading,
                received_bytes: received,
                total_bytes: total,
            });
        },
    )
    .await
    .map_err(|e| {
        tracing::warn!("GeoIP download failed: {e}");
        match e {
            download::DownloadError::TooLarge => ApiError::GeoipTooLarge,
            _ => ApiError::GeoipDownloadFailed,
        }
    })?;
    // The guard moves into the blocking task: a client that disconnects does not release it
    // before the installation ends.
    let info = blocking(&state, move |s| {
        let _guard = guard;
        s.geoip.set_progress(GeoipUpdate {
            phase: GeoipUpdatePhase::Installing,
            ..GeoipUpdate::idle()
        });
        let bytes = netsift_geo::decode_database(raw).map_err(install_error)?;
        s.geoip.install(bytes)
    })
    .await?;
    Ok(Json(info))
}

/// `POST /geoip/import { path }`: installs a `.mmdb` or `.mmdb.gz` file chosen by the user
/// (native dialog in the desktop app, allowed roots in dev web mode).
async fn import_file(
    State(state): State<Arc<AppState>>,
    ApiJson(req): ApiJson<GeoipImportRequest>,
) -> Result<Json<GeoipInfo>, ApiError> {
    let guard = UpdateGuard::begin(&state, GeoipUpdatePhase::Installing)?;
    let info = blocking(&state, move |s| {
        let _guard = guard;
        let path = fs::resolve_input(s, &req.path)?;
        if !path.is_file() {
            return Err(ApiError::BadRequest("not a file".to_owned()));
        }
        let bytes = netsift_geo::read_database_file(&path).map_err(|e| match e {
            GeoError::Io(e) => {
                tracing::warn!(path = %path.display(), "cannot read the GeoIP file: {e}");
                ApiError::BadRequest("the file cannot be read".to_owned())
            }
            other => install_error(other),
        })?;
        s.geoip.install(bytes)
    })
    .await?;
    Ok(Json(info))
}

/// `GET /geoip/update`: progress of the running update (`idle` when none).
async fn update_state(State(state): State<Arc<AppState>>) -> Json<GeoipUpdate> {
    Json(lock(&state.geoip.progress).clone())
}

/// Problem of a refused or failed installation; details only in the logs.
fn install_error(e: GeoError) -> ApiError {
    match e {
        GeoError::TooLarge => ApiError::GeoipTooLarge,
        GeoError::Io(e) => {
            tracing::error!("cannot install the GeoIP database: {e}");
            ApiError::Internal
        }
        other => {
            tracing::warn!("GeoIP database refused: {other}");
            ApiError::GeoipInvalid
        }
    }
}

fn info(db: &GeoDb, source: GeoipSource, (size, modified, _): Stamp) -> GeoipInfo {
    GeoipInfo {
        status: GeoipStatus::Available,
        source: Some(source),
        built_at_us: i64::try_from(db.build_epoch())
            .ok()
            .and_then(|s| s.checked_mul(1_000_000)),
        size_bytes: Some(size),
        installed_at_us: modified.and_then(micros),
    }
}

fn micros(t: SystemTime) -> Option<i64> {
    i64::try_from(t.duration_since(UNIX_EPOCH).ok()?.as_micros()).ok()
}

fn stamp(path: &Path) -> Option<Stamp> {
    let meta = std::fs::metadata(path).ok()?;
    #[cfg(unix)]
    let inode = std::os::unix::fs::MetadataExt::ino(&meta);
    #[cfg(not(unix))]
    let inode = 0;
    meta.is_file()
        .then(|| (meta.len(), meta.modified().ok(), inode))
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}
