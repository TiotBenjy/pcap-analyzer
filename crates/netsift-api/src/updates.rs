//! New versions of NetSift, from the GitHub releases of the repository (ADR-025).
//!
//! - Check: `GET https://api.github.com/repos/<owner>/<repo>/releases/latest` (repository of
//!   `[workspace.package]`, fixed at build time), JSON bounded to [`MAX_RELEASE_JSON`]. Sent at
//!   startup when `online.update_check` is on (silent on failure), or by `POST /updates/check`
//!   (click on "Check for updates"). Drafts, prereleases and versions equal to or older than the
//!   running one count as "up to date".
//! - Download, only on click and only in the desktop app (`ApiConfig::allow_any_path`, the path
//!   comes from the native save dialog): `POST /updates/download { asset, path }` accepts the
//!   name of an installer of the last checked release for this platform, never a URL. The
//!   server reads `SHA256SUMS.txt` of the same release, then downloads the installer to `path`
//!   through `Outbound::download_to` (temporary `.part` file, SHA-256 checked before the rename;
//!   nothing is left on a mismatch). Progress: `GET /updates/download`. Never installed.
//! - Hosts: `api.github.com` for the check; `github.com` and the asset storage it redirects to
//!   ([`DOWNLOAD_HOSTS`]) for the downloads.

mod release;
#[cfg(test)]
mod tests;

use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use futures_util::future::BoxFuture;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use tokio::task::JoinHandle;
use ts_rs::TS;

use crate::extract::ApiJson;
use crate::outbound::{Outbound, OutboundError, Policy};
use crate::{ApiConfig, ApiError, AppState, blocking};

pub use release::PackageFormat;
use release::{GhRelease, Installer, Platform};

/// Version of this build.
const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");
/// Repository of the published releases (`[workspace.package] repository`).
const REPOSITORY: &str = env!("CARGO_PKG_REPOSITORY");
const GITHUB_WEB: &str = "https://github.com/";
/// Host of the check.
const API_HOST: &str = "api.github.com";
/// Hosts of a download: `github.com` answers with a redirection to its asset storage. The list
/// follows GitHub: update it (and ADR-025) if GitHub moves its release files elsewhere.
const DOWNLOAD_HOSTS: &[&str] = &[
    "github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
];
const ACCEPT_GITHUB: &str = "application/vnd.github+json";
/// The release JSON (notes and a few assets) is a few tens of KiB.
const MAX_RELEASE_JSON: u64 = 1024 * 1024;
/// `SHA256SUMS.txt` has one line per published file.
const MAX_SUMS_BYTES: u64 = 64 * 1024;
/// Name of the checksum file published with each release (`release.yml`).
const SUMS_NAME: &str = "SHA256SUMS.txt";
/// Installers are ~100-200 MB: the size announced by the JSON plus this margin is allowed...
const SIZE_MARGIN: u64 = 1024 * 1024;
/// ...but never more than this.
const MAX_INSTALLER_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const DOWNLOAD_READ_TIMEOUT: Duration = Duration::from_secs(60);
const DOWNLOAD_TOTAL_TIMEOUT: Duration = Duration::from_hours(1);
const MAX_PATH_LEN: usize = 4_096;

const CHECK_FAILED: &str = "update-check-failed";

// ---------------------------------------------------------------------------------------------
// DTOs

/// `GET /updates`: state of the update check.
#[derive(Debug, Clone, Serialize, TS)]
#[ts(export)]
pub struct UpdateState {
    /// Version of the running application.
    pub current_version: String,
    /// A check is running (at startup or after a click).
    pub checking: bool,
    /// Last successful check since the server started.
    pub check: Option<UpdateCheck>,
    /// Installers can be downloaded by this server (desktop app, not read-only).
    pub can_download: bool,
}

/// Result of a check (`POST /updates/check`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct UpdateCheck {
    pub status: UpdateCheckStatus,
    pub current_version: String,
    /// Version of the latest published release (none published, or not a final release: null).
    pub latest_version: Option<String>,
    /// When the check was made (UTC microseconds).
    pub checked_at_us: i64,
    /// The newer release, when `status` is `available`.
    pub release: Option<UpdateRelease>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum UpdateCheckStatus {
    /// The running version is the latest one, or newer.
    UpToDate,
    /// A newer final release is published.
    Available,
}

/// A newer release.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct UpdateRelease {
    pub version: String,
    /// Release name on GitHub as plain text (control, bidirectional formatting and invisible
    /// characters dropped, one line, at most 120 characters): `NetSift vX.Y.Z` or
    /// `NetSift vX.Y.Z — <title>`.
    pub name: Option<String>,
    /// Short summary of the release: the part of `name` after the version, or the whole name
    /// when it was edited by hand without that prefix; none for the default name.
    pub title: Option<String>,
    /// Release notes as plain text (never to be rendered as HTML or Markdown), cut past 8 000
    /// characters.
    pub notes: String,
    pub notes_truncated: bool,
    /// Page of the release on GitHub (shown as a link in the web dev mode only).
    pub html_url: Option<String>,
    /// Installers for this platform, the one matching the installed format first.
    pub installers: Vec<UpdateInstaller>,
    /// The first installer is the format the application was installed from; false when that
    /// format is unknown (the user may choose another one).
    pub format_known: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct UpdateInstaller {
    /// File name in the release, also the default name in the save dialog.
    pub name: String,
    pub size: u64,
    pub format: PackageFormat,
}

/// Body of `POST /updates/download`.
#[derive(Debug, Clone, Deserialize, TS)]
#[serde(deny_unknown_fields)]
#[ts(export)]
pub struct UpdateDownloadRequest {
    /// Name of an installer of the last checked release (`UpdateInstaller::name`).
    pub asset: String,
    /// Absolute path chosen in the save dialog; its folder must exist.
    pub path: String,
}

/// `GET /updates/download`: the running or last download.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct UpdateDownload {
    pub phase: UpdateDownloadPhase,
    pub asset: Option<String>,
    pub received_bytes: u64,
    pub total_bytes: Option<u64>,
    /// Saved file, once `done`.
    pub path: Option<String>,
    /// Reason, once `failed`.
    pub error: Option<UpdateDownloadError>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum UpdateDownloadPhase {
    #[default]
    Idle,
    Downloading,
    Done,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum UpdateDownloadError {
    /// Network failure, timeout, refused host or unexpected status.
    Network,
    /// `SHA256SUMS.txt` missing, or without the installer: nothing downloaded.
    ChecksumMissing,
    /// The downloaded file does not match `SHA256SUMS.txt`: removed.
    ChecksumMismatch,
    /// Larger than announced.
    TooLarge,
    /// The file could not be written.
    Write,
    /// The application stopped during the download.
    Interrupted,
}

// ---------------------------------------------------------------------------------------------
// State

/// Where releases are read from (tests point it to a local server).
#[derive(Debug, Clone)]
pub(crate) struct Source {
    pub(crate) latest_url: String,
    /// `https://github.com/<owner>/<repo>/releases/`: release pages, and files under `download/`.
    pub(crate) release_prefix: String,
    pub(crate) check_policy: Policy,
    pub(crate) download_policy: Policy,
}

impl Source {
    fn download_prefix(&self) -> String {
        format!("{}download/", self.release_prefix)
    }
}

/// `<owner>/<repo>` of [`REPOSITORY`].
fn repository_path() -> &'static str {
    REPOSITORY
        .strip_prefix(GITHUB_WEB)
        .unwrap_or(REPOSITORY)
        .trim_end_matches('/')
}

impl Default for Source {
    fn default() -> Self {
        let repo = repository_path();
        Self {
            latest_url: format!("https://{API_HOST}/repos/{repo}/releases/latest"),
            release_prefix: format!("{GITHUB_WEB}{repo}/releases/"),
            check_policy: Policy::new(&[API_HOST]),
            download_policy: Policy::new(DOWNLOAD_HOSTS)
                .with_read_timeout(DOWNLOAD_READ_TIMEOUT)
                .with_total_timeout(DOWNLOAD_TOTAL_TIMEOUT),
        }
    }
}

/// Last successful check, with what a download needs.
struct Checked {
    info: UpdateCheck,
    installers: Vec<Installer>,
    sums_url: Option<String>,
}

/// State of the feature (`AppState::online`).
pub(crate) struct Updates {
    source: Mutex<Source>,
    platform: Mutex<Platform>,
    checking: AtomicUsize,
    last: Mutex<Option<Checked>>,
    downloading: AtomicBool,
    download: Mutex<UpdateDownload>,
    /// Task of the last download, awaited at shutdown ([`wait_download`]).
    task: Mutex<Option<JoinHandle<()>>>,
}

impl Default for Updates {
    fn default() -> Self {
        Self {
            source: Mutex::new(Source::default()),
            platform: Mutex::new(Platform::current()),
            checking: AtomicUsize::new(0),
            last: Mutex::new(None),
            downloading: AtomicBool::new(false),
            download: Mutex::new(UpdateDownload::default()),
            task: Mutex::new(None),
        }
    }
}

impl Updates {
    fn source(&self) -> Source {
        lock(&self.source).clone()
    }

    fn platform(&self) -> Platform {
        *lock(&self.platform)
    }

    fn set_download(&self, f: impl FnOnce(&mut UpdateDownload)) {
        f(&mut lock(&self.download));
    }

    #[cfg(test)]
    pub(crate) fn set_source(&self, source: Source) {
        *lock(&self.source) = source;
    }

    #[cfg(test)]
    pub(crate) fn set_platform(&self, platform: Platform) {
        *lock(&self.platform) = platform;
    }
}

/// Records the package format the application was installed from (desktop).
pub(crate) fn set_install_format(state: &AppState, format: Option<PackageFormat>) {
    lock(&state.online.get::<Updates>().platform).installed = format;
}

fn can_download(config: &ApiConfig) -> bool {
    config.allow_any_path && !config.read_only
}

// ---------------------------------------------------------------------------------------------
// Check

/// Counts a running check while alive.
struct Busy<'a>(&'a AtomicUsize);

impl<'a> Busy<'a> {
    fn enter(counter: &'a AtomicUsize) -> Self {
        counter.fetch_add(1, Ordering::AcqRel);
        Self(counter)
    }
}

impl Drop for Busy<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Reads the latest release and keeps the result.
async fn check(updates: &Updates) -> Result<UpdateCheck, OutboundError> {
    let source = updates.source();
    let platform = updates.platform();
    let _busy = Busy::enter(&updates.checking);
    let client = Outbound::new(source.check_policy.clone())?;
    let latest = match client
        .get_json::<GhRelease>(&source.latest_url, ACCEPT_GITHUB, MAX_RELEASE_JSON)
        .await
    {
        Ok(release) => Some(release),
        // No release published yet.
        Err(OutboundError::Status(StatusCode::NOT_FOUND)) => None,
        Err(e) => return Err(e),
    };
    let checked = evaluate(
        latest.as_ref(),
        CURRENT_VERSION,
        &platform,
        &source,
        now_us(),
    );
    let info = checked.info.clone();
    *lock(&updates.last) = Some(checked);
    Ok(info)
}

fn evaluate(
    latest: Option<&GhRelease>,
    current: &str,
    platform: &Platform,
    source: &Source,
    checked_at_us: i64,
) -> Checked {
    let latest_version = latest
        .filter(|r| !r.draft && !r.prerelease)
        .and_then(|r| release::tag_version(&r.tag_name))
        .filter(|v| v.pre.is_empty())
        .map(|v| v.to_string());
    let mut checked = Checked {
        info: UpdateCheck {
            status: UpdateCheckStatus::UpToDate,
            current_version: current.to_owned(),
            latest_version,
            checked_at_us,
            release: None,
        },
        installers: Vec::new(),
        sums_url: None,
    };
    let Some((release, version)) =
        latest.and_then(|r| release::newer_version(r, current).map(|v| (r, v)))
    else {
        return checked;
    };
    let prefix = source.download_prefix();
    let installers = release::installers(&release.assets, platform, &prefix);
    let (notes, notes_truncated) = release::plain_notes(release.body.as_deref());
    let name = release::plain_name(release.name.as_deref());
    let title = name
        .as_deref()
        .and_then(|n| release::release_title(n, &release.tag_name));
    checked.sums_url = release
        .assets
        .iter()
        .take(release::MAX_ASSETS)
        .find(|a| a.name == SUMS_NAME && release::valid_url(&a.browser_download_url, &prefix))
        .map(|a| a.browser_download_url.clone());
    checked.info.status = UpdateCheckStatus::Available;
    checked.info.release = Some(UpdateRelease {
        version: version.to_string(),
        name,
        title,
        notes,
        notes_truncated,
        html_url: release
            .html_url
            .clone()
            .filter(|u| release::valid_url(u, &source.release_prefix)),
        format_known: platform
            .installed
            .is_some_and(|f| installers.first().is_some_and(|i| i.format == f)),
        installers: installers
            .iter()
            .map(|i| UpdateInstaller {
                name: i.name.clone(),
                size: i.size,
                format: i.format,
            })
            .collect(),
    });
    checked.installers = installers;
    checked
}

/// Startup check (`online::STARTUP_CHECKS`, setting `update_check`): failures stay in the logs.
pub(crate) fn startup_check(state: Arc<AppState>) -> BoxFuture<'static, ()> {
    Box::pin(async move {
        let updates = state.online.get::<Updates>();
        match check(&updates).await {
            Ok(result) => tracing::info!(status = ?result.status, "update check done"),
            Err(e) => tracing::info!("update check failed: {e}"),
        }
    })
}

// ---------------------------------------------------------------------------------------------
// Routes

pub(crate) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/updates", get(get_state))
        .route("/updates/check", post(check_now))
        .route(
            "/updates/download",
            get(download_state).post(start_download),
        )
}

/// `GET /updates`.
async fn get_state(State(state): State<Arc<AppState>>) -> Json<UpdateState> {
    let updates = state.online.get::<Updates>();
    Json(UpdateState {
        current_version: CURRENT_VERSION.to_owned(),
        checking: updates.checking.load(Ordering::Acquire) > 0,
        check: lock(&updates.last).as_ref().map(|c| c.info.clone()),
        can_download: can_download(&state.config),
    })
}

/// `POST /updates/check`: checks now (click on "Check for updates").
async fn check_now(State(state): State<Arc<AppState>>) -> Result<Json<UpdateCheck>, ApiError> {
    let updates = state.online.get::<Updates>();
    check(&updates)
        .await
        .map(Json)
        .map_err(|e| e.into_problem(CHECK_FAILED, "Update check failed"))
}

/// `GET /updates/download`.
async fn download_state(State(state): State<Arc<AppState>>) -> Json<UpdateDownload> {
    Json(lock(&state.online.get::<Updates>().download).clone())
}

fn problem(status: StatusCode, kind: &'static str, title: &'static str) -> ApiError {
    ApiError::Feature {
        status,
        kind,
        title,
    }
}

/// `POST /updates/download { asset, path }`: starts the download (202), one at a time.
async fn start_download(
    State(state): State<Arc<AppState>>,
    ApiJson(req): ApiJson<UpdateDownloadRequest>,
) -> Result<(StatusCode, Json<UpdateDownload>), ApiError> {
    if !can_download(&state.config) {
        return Err(problem(
            StatusCode::FORBIDDEN,
            "update-download-unavailable",
            "Downloads are only available in the desktop app",
        ));
    }
    let updates = state.online.get::<Updates>();
    let (installer, sums_url) = {
        let last = lock(&updates.last);
        let Some(checked) = last.as_ref() else {
            return Err(problem(
                StatusCode::CONFLICT,
                "update-not-checked",
                "No update check yet",
            ));
        };
        let installer = checked
            .installers
            .iter()
            .find(|i| i.name == req.asset)
            .cloned()
            .ok_or_else(|| {
                problem(
                    StatusCode::BAD_REQUEST,
                    "update-asset-unknown",
                    "Not an installer of the latest release",
                )
            })?;
        (installer, checked.sums_url.clone())
    };
    let raw = req.path;
    let dest = blocking(&state, move |_| target_path(&raw)).await?;
    let guard = DownloadGuard::begin(&updates)?;
    updates.set_download(|d| {
        *d = UpdateDownload {
            phase: UpdateDownloadPhase::Downloading,
            asset: Some(installer.name.clone()),
            total_bytes: Some(installer.size),
            ..UpdateDownload::default()
        };
    });
    let snapshot = lock(&updates.download).clone();
    let shutdown = state.shutdown_signal();
    let task = tokio::spawn(async move {
        let updates = Arc::clone(&guard.0);
        let result = tokio::select! {
            r = run_download(&updates, &installer, sums_url.as_deref(), &dest) => r,
            () = shutdown => Err(UpdateDownloadError::Interrupted),
        };
        match result {
            Ok(()) => {
                tracing::info!(asset = %installer.name, "update downloaded");
                updates.set_download(|d| {
                    d.phase = UpdateDownloadPhase::Done;
                    d.path = Some(dest.to_string_lossy().into_owned());
                });
            }
            Err(error) => updates.set_download(|d| {
                d.phase = UpdateDownloadPhase::Failed;
                d.error = Some(error);
            }),
        }
        drop(guard);
    });
    *lock(&updates.task) = Some(task);
    Ok((StatusCode::ACCEPTED, Json(snapshot)))
}

/// Waits for the download task, if any, to end: called during the shutdown, once the shutdown
/// signal has stopped the download, so that its temporary file is removed before the exit.
pub(crate) async fn wait_download(state: &AppState) {
    let task = lock(&state.online.get::<Updates>().task).take();
    if let Some(task) = task {
        // A panicked or cancelled task has nothing more to clean.
        let _ = task.await;
    }
}

/// Exclusive right to download; on drop, a download still marked running is `interrupted`.
struct DownloadGuard(Arc<Updates>);

impl DownloadGuard {
    fn begin(updates: &Arc<Updates>) -> Result<Self, ApiError> {
        if updates.downloading.swap(true, Ordering::AcqRel) {
            return Err(problem(
                StatusCode::CONFLICT,
                "update-download-running",
                "A download is already running",
            ));
        }
        Ok(Self(Arc::clone(updates)))
    }
}

impl Drop for DownloadGuard {
    fn drop(&mut self) {
        self.0.set_download(|d| {
            if d.phase == UpdateDownloadPhase::Downloading {
                d.phase = UpdateDownloadPhase::Failed;
                d.error = Some(UpdateDownloadError::Interrupted);
            }
        });
        self.0.downloading.store(false, Ordering::Release);
    }
}

/// Destination of a download: absolute, without `..`, with a file name, in an existing folder,
/// not a folder itself. An existing file is replaced once the download is checked (the save
/// dialog has asked).
fn target_path(raw: &str) -> Result<PathBuf, ApiError> {
    let invalid = |title| problem(StatusCode::BAD_REQUEST, "update-path-invalid", title);
    let path = Path::new(raw);
    if raw.len() > MAX_PATH_LEN
        || !path.is_absolute()
        || path.components().any(|c| c == Component::ParentDir)
    {
        return Err(invalid("The destination must be an absolute path"));
    }
    if path.file_name().is_none() {
        return Err(invalid("The destination has no file name"));
    }
    if !path.parent().is_some_and(Path::is_dir) {
        return Err(invalid("The destination folder does not exist"));
    }
    if path.is_dir() {
        return Err(invalid("The destination is a folder"));
    }
    Ok(path.to_owned())
}

async fn run_download(
    updates: &Updates,
    installer: &Installer,
    sums_url: Option<&str>,
    dest: &Path,
) -> Result<(), UpdateDownloadError> {
    let client = Outbound::new(updates.source().download_policy).map_err(|e| download_error(&e))?;
    let sums_url = sums_url.ok_or(UpdateDownloadError::ChecksumMissing)?;
    let sums = client
        .get_bytes(sums_url, MAX_SUMS_BYTES, |_, _| {})
        .await
        .map_err(|e| download_error(&e))?;
    let expected = release::expected_sha256(&sums, &installer.name).ok_or_else(|| {
        tracing::warn!(asset = %installer.name, "no checksum for the installer");
        UpdateDownloadError::ChecksumMissing
    })?;
    let max_bytes = installer
        .size
        .saturating_add(SIZE_MARGIN)
        .min(MAX_INSTALLER_BYTES);
    client
        .download_to(
            &installer.url,
            dest,
            max_bytes,
            Some(&expected),
            |received, total| {
                updates.set_download(|d| {
                    d.received_bytes = received;
                    if total.is_some() {
                        d.total_bytes = total;
                    }
                });
            },
        )
        .await
        .map_err(|e| download_error(&e))?;
    Ok(())
}

fn download_error(e: &OutboundError) -> UpdateDownloadError {
    tracing::warn!("update download failed: {e}");
    match e {
        OutboundError::ChecksumMismatch | OutboundError::InvalidChecksum => {
            UpdateDownloadError::ChecksumMismatch
        }
        OutboundError::TooLarge => UpdateDownloadError::TooLarge,
        OutboundError::Io(_) => UpdateDownloadError::Write,
        _ => UpdateDownloadError::Network,
    }
}

fn now_us() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_micros()).ok())
        .unwrap_or(0)
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}
