//! Settings kept by the server in `<data_dir>/settings.json`, so that the desktop app and the
//! dev web mode behave the same: the online checks run at startup are decided here, before any
//! page is loaded (ADR-025). Display preferences (theme, language) stay in the webview storage.
//!
//! - Safe defaults: every online setting is off until the user enables it.
//! - A missing file means the defaults; an unreadable, oversized or invalid file means the
//!   defaults too, with a warning in the logs (never its contents), and is replaced by the next
//!   change. Invalid entries of a valid file are dropped one by one.
//! - Writes are atomic: temporary file, `fsync`, rename. The file is only written by the routes
//!   below, one change at a time.
//!
//! Routes: `GET /settings`, `PUT /settings` (fields omitted are left unchanged) and
//! `PUT /settings/notices/{id}` (notice dismissed until its key changes). Refused in read-only
//! mode like every mutating route.

#[cfg(test)]
mod tests;

use std::collections::BTreeMap;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use axum::extract::{Path as UrlPath, State};
use axum::routing::{get, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::extract::ApiJson;
use crate::{ApiError, AppState, blocking};

/// Name of the settings file in the data directory.
pub(crate) const FILE_NAME: &str = "settings.json";
const TEMP_NAME: &str = "settings.json.tmp";
/// Larger files are not read (the real file is well under 1 KiB).
const MAX_FILE_BYTES: u64 = 64 * 1024;
/// Dismissed notices kept at most.
pub(crate) const MAX_DISMISSED: usize = 32;
const MAX_ID_LEN: usize = 64;
const MAX_KEY_LEN: usize = 64;

/// Settings of the server (`GET /settings`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(default)]
#[ts(export)]
pub struct Settings {
    pub online: OnlineSettings,
    /// Notices hidden by the user: notice id -> key it was hidden for (for example the month of
    /// a database or a version number). A notice shows again once its key changes.
    pub dismissed_notices: BTreeMap<String, String>,
}

/// Network requests made at startup, each off until the user enables it (ADR-025).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(default)]
#[ts(export)]
pub struct OnlineSettings {
    /// Ask DB-IP whether a newer country database is published.
    pub geoip_check: bool,
    /// Ask GitHub whether a newer release of NetSift is published.
    pub update_check: bool,
}

/// Body of `PUT /settings`: fields omitted are left unchanged.
#[derive(Debug, Clone, Default, Deserialize, TS)]
#[serde(deny_unknown_fields)]
#[ts(export)]
pub struct SettingsUpdate {
    #[serde(default)]
    #[ts(optional)]
    pub online: Option<OnlineSettingsUpdate>,
}

/// Online settings to change; fields omitted are left unchanged.
#[derive(Debug, Clone, Copy, Default, Deserialize, TS)]
#[serde(deny_unknown_fields)]
#[ts(export)]
pub struct OnlineSettingsUpdate {
    #[serde(default)]
    #[ts(optional)]
    pub geoip_check: Option<bool>,
    #[serde(default)]
    #[ts(optional)]
    pub update_check: Option<bool>,
}

/// Body of `PUT /settings/notices/{id}`.
#[derive(Debug, Clone, Deserialize, TS)]
#[serde(deny_unknown_fields)]
#[ts(export)]
pub struct NoticeDismissal {
    /// Key the notice is hidden for: 1 to 64 characters among letters, digits and `.` `_` `-`
    /// `+` `:`.
    pub key: String,
}

pub(crate) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/settings", get(get_settings).put(put_settings))
        .route("/settings/notices/{id}", put(dismiss_notice))
}

/// Settings loaded at startup and changed through the routes.
pub(crate) struct SettingsStore {
    path: PathBuf,
    current: Mutex<Settings>,
}

impl SettingsStore {
    /// Reads `<data_dir>/settings.json` (blocking, small file). Never fails: defaults instead.
    pub(crate) fn load(data_dir: &Path) -> Self {
        let path = data_dir.join(FILE_NAME);
        let current = read_file(&path);
        Self {
            path,
            current: Mutex::new(current),
        }
    }

    /// Current settings.
    pub(crate) fn get(&self) -> Settings {
        lock(&self.current).clone()
    }

    /// Applies `change`, writes the file, then makes the result current (blocking). A failed
    /// write leaves both the file and the current settings unchanged.
    fn update(
        &self,
        change: impl FnOnce(&mut Settings) -> Result<(), ApiError>,
    ) -> Result<Settings, ApiError> {
        let mut current = lock(&self.current);
        let mut next = current.clone();
        change(&mut next)?;
        if next != *current {
            write_file(&self.path, &next).map_err(|e| {
                tracing::error!("cannot write the settings: {e}");
                ApiError::Internal
            })?;
            *current = next;
        }
        Ok(current.clone())
    }
}

/// `GET /settings`.
async fn get_settings(State(state): State<Arc<AppState>>) -> Json<Settings> {
    Json(state.settings.get())
}

/// `PUT /settings`: changes the fields present in the body.
async fn put_settings(
    State(state): State<Arc<AppState>>,
    ApiJson(update): ApiJson<SettingsUpdate>,
) -> Result<Json<Settings>, ApiError> {
    let settings = blocking(&state, move |s| {
        s.settings.update(|settings| {
            if let Some(online) = update.online {
                if let Some(v) = online.geoip_check {
                    settings.online.geoip_check = v;
                }
                if let Some(v) = online.update_check {
                    settings.online.update_check = v;
                }
            }
            Ok(())
        })
    })
    .await?;
    tracing::info!(online = ?settings.online, "settings changed");
    Ok(Json(settings))
}

/// `PUT /settings/notices/{id}`: hides the notice `id` until its key differs from `key`.
async fn dismiss_notice(
    State(state): State<Arc<AppState>>,
    UrlPath(id): UrlPath<String>,
    ApiJson(body): ApiJson<NoticeDismissal>,
) -> Result<Json<Settings>, ApiError> {
    if !valid_id(&id) {
        return Err(ApiError::BadRequest("invalid notice id".to_owned()));
    }
    if !valid_key(&body.key) {
        return Err(ApiError::BadRequest("invalid notice key".to_owned()));
    }
    let settings = blocking(&state, move |s| {
        s.settings.update(|settings| {
            let map = &mut settings.dismissed_notices;
            if !map.contains_key(&id) && map.len() >= MAX_DISMISSED {
                return Err(ApiError::BadRequest(
                    "too many dismissed notices".to_owned(),
                ));
            }
            map.insert(id, body.key);
            Ok(())
        })
    })
    .await?;
    Ok(Json(settings))
}

/// Notice ids: lowercase letters, digits and `-` `_` `.`, starting with a letter or a digit.
fn valid_id(id: &str) -> bool {
    let mut chars = id.chars();
    id.len() <= MAX_ID_LEN
        && chars
            .next()
            .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "-_.".contains(c))
}

fn valid_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= MAX_KEY_LEN
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-+:".contains(c))
}

/// Settings of the file, or the defaults (with a warning unless the file is missing).
fn read_file(path: &Path) -> Settings {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Settings::default(),
        Err(e) => {
            tracing::warn!("cannot read the settings, defaults used: {e}");
            return Settings::default();
        }
    };
    let mut bytes = Vec::new();
    if let Err(e) = file.take(MAX_FILE_BYTES + 1).read_to_end(&mut bytes) {
        tracing::warn!("cannot read the settings, defaults used: {e}");
        return Settings::default();
    }
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_FILE_BYTES {
        tracing::warn!("settings file too large, defaults used");
        return Settings::default();
    }
    match serde_json::from_slice::<Settings>(&bytes) {
        Ok(settings) => sanitize(settings),
        Err(e) => {
            // Position only: the message of serde_json may quote the contents.
            tracing::warn!(
                line = e.line(),
                column = e.column(),
                "invalid settings file, defaults used"
            );
            Settings::default()
        }
    }
}

/// Drops the invalid dismissed notices (and those beyond [`MAX_DISMISSED`]).
fn sanitize(mut settings: Settings) -> Settings {
    let before = settings.dismissed_notices.len();
    settings.dismissed_notices = std::mem::take(&mut settings.dismissed_notices)
        .into_iter()
        .filter(|(id, key)| valid_id(id) && valid_key(key))
        .take(MAX_DISMISSED)
        .collect();
    let dropped = before - settings.dismissed_notices.len();
    if dropped > 0 {
        tracing::warn!(
            dropped,
            "invalid dismissed notices dropped from the settings"
        );
    }
    settings
}

/// Writes `settings` to `path` atomically (temporary file next to it, `fsync`, rename).
fn write_file(path: &Path, settings: &Settings) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(dir)?;
    let temp = dir.join(TEMP_NAME);
    let result = (|| {
        let mut bytes = serde_json::to_vec_pretty(settings).map_err(std::io::Error::other)?;
        bytes.push(b'\n');
        let mut file = std::fs::File::create(&temp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temp, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}
