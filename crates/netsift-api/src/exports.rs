//! "Save PCAP" routes (`docs/specs/export-pcap.md`, ADR-021).
//!
//! | Method | Path | Response |
//! |---|---|---|
//! | POST | `/sessions/{id}/exports/pcap` | 202 [`ExportJob`] |
//! | GET | `/sessions/{id}/exports` | [`ExportJob`] list, newest first |
//! | GET | `/exports/{job}` | [`ExportJob`] |
//! | POST | `/exports/{job}/cancel` | [`ExportJob`] |
//! | GET | `/exports/{job}/file` | the pcapng file, attachment, streamed |
//!
//! The request is checked synchronously (session state, flow, source chunks: problem+json on
//! failure), then the file is written by a dedicated thread around
//! [`netsift_engine::ExportPlan::run`] into `<data_dir>/exports/`, under a name chosen by the
//! server. Progress is read by polling the job; jobs live in memory (bounded), the files stay.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::{Body, Bytes};
use axum::extract::{Path as UrlPath, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use netsift_engine::{
    CancelToken, ExportError, ExportPlan, ExportProgress, ExportSelection, plan_export,
};
use netsift_store::SessionId;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncReadExt;
use tokio::sync::watch;
use ts_rs::TS;

use crate::extract::ApiJson;
use crate::overview::open_ready;
use crate::sessions::parse_id;
use crate::{ApiError, AppState, blocking};

/// Folder of the exported files under the data directory (the desktop opener scope).
pub const EXPORTS_DIR: &str = "exports";
/// Exports allowed to run at the same time.
pub(crate) const MAX_RUNNING: usize = 2;
/// Finished jobs kept in memory.
const MAX_FINISHED: usize = 32;
/// Read size of the download stream.
const STREAM_CHUNK: usize = 256 * 1024;

pub(crate) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/sessions/{id}/exports", get(list))
        .route("/sessions/{id}/exports/pcap", post(start))
        .route("/exports/{job}", get(status))
        .route("/exports/{job}/cancel", post(cancel))
        .route("/exports/{job}/file", get(file))
}

/// `POST /sessions/{id}/exports/pcap` body. Any other field (a file name, a path) is ignored:
/// the server names the file.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, TS)]
#[ts(export)]
#[serde(tag = "scope", rename_all = "snake_case")]
pub enum ExportRequest {
    /// Every packet of the session.
    Session,
    /// Packets with `from_us <= ts <= to_us` (inclusive at microsecond precision).
    Range { from_us: i64, to_us: i64 },
    /// Packets of one flow (`FlowInfo::id`).
    Flow { flow_id: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
#[serde(rename_all = "snake_case")]
pub enum ExportScope {
    Session,
    Range,
    Flow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
#[serde(rename_all = "snake_case")]
pub enum ExportState {
    Running,
    Done,
    Failed,
    Cancelled,
}

/// Why an export failed: the problem type and detail it would have had as a response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct ExportFailure {
    #[serde(rename = "type")]
    #[ts(rename = "type")]
    pub kind: String,
    pub title: String,
    /// HTTP status the problem would have had.
    pub status: u16,
    pub detail: Option<String>,
}

/// State of an export.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct ExportJob {
    pub id: String,
    pub session_id: String,
    pub scope: ExportScope,
    pub from_us: Option<i64>,
    pub to_us: Option<i64>,
    pub flow_id: Option<String>,
    pub state: ExportState,
    /// Name of the file, chosen by the server.
    pub file_name: String,
    /// Absolute path of the exports folder (desktop: opened with the opener plugin).
    pub folder: String,
    /// Absolute path of the file once written.
    pub path: Option<String>,
    pub packets: u64,
    pub bytes_written: u64,
    /// Bytes of the source files read so far, out of `bytes_total`.
    pub bytes_read: u64,
    pub bytes_total: u64,
    /// Read errors met in the source files (a file that ends early, a record skipped): the
    /// export may lack packets, as the import did.
    pub read_errors: u64,
    pub error: Option<ExportFailure>,
    /// Wall-clock creation time, microseconds since the epoch.
    pub created_at_us: i64,
}

// ---------------------------------------------------------------------------------------------
// Registry

struct Job {
    session: String,
    cancel: CancelToken,
    dest: PathBuf,
    status: Mutex<ExportJob>,
}

impl Job {
    fn snapshot(&self) -> ExportJob {
        lock(&self.status).clone()
    }

    fn update(&self, f: impl FnOnce(&mut ExportJob)) {
        f(&mut lock(&self.status));
    }

    fn is_finished(&self) -> bool {
        lock(&self.status).state != ExportState::Running
    }
}

pub(crate) struct Registry {
    /// Oldest first.
    jobs: Mutex<Vec<(String, Arc<Job>)>>,
    next: AtomicU64,
    running: Mutex<Vec<(u64, CancelToken)>>,
    active: watch::Sender<usize>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Registry {
    pub(crate) fn new() -> Self {
        Self {
            jobs: Mutex::new(Vec::new()),
            next: AtomicU64::new(0),
            running: Mutex::new(Vec::new()),
            active: watch::Sender::new(0),
        }
    }

    fn get(&self, id: &str) -> Option<Arc<Job>> {
        lock(&self.jobs)
            .iter()
            .find(|(k, _)| k == id)
            .map(|(_, j)| Arc::clone(j))
    }

    fn insert(&self, id: String, job: Arc<Job>) {
        let mut jobs = lock(&self.jobs);
        jobs.push((id, job));
        let finished = jobs.iter().filter(|(_, j)| j.is_finished()).count();
        let mut excess = finished.saturating_sub(MAX_FINISHED);
        jobs.retain(|(_, j)| {
            if excess > 0 && j.is_finished() {
                excess -= 1;
                false
            } else {
                true
            }
        });
    }

    pub(crate) fn cancel_all(&self) {
        for (_, token) in lock(&self.running).iter() {
            token.cancel();
        }
    }

    pub(crate) async fn wait_idle(&self) {
        let mut rx = self.active.subscribe();
        let _ = rx.wait_for(|n| *n == 0).await;
    }
}

/// Counts a live export thread; removed when dropped.
struct Running {
    state: Arc<AppState>,
    key: u64,
}

impl Running {
    fn new(state: &Arc<AppState>, cancel: &CancelToken) -> Result<Self, ApiError> {
        let registry = &state.exports;
        let key = registry.next.fetch_add(1, Ordering::Relaxed);
        {
            let mut running = lock(&registry.running);
            if running.len() >= MAX_RUNNING {
                return Err(ApiError::TooManyExports);
            }
            running.push((key, cancel.clone()));
            registry.active.send_replace(running.len());
        }
        if state.is_shutting_down() {
            cancel.cancel();
        }
        Ok(Self {
            state: Arc::clone(state),
            key,
        })
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        let registry = &self.state.exports;
        let mut running = lock(&registry.running);
        running.retain(|(k, _)| *k != self.key);
        registry.active.send_replace(running.len());
    }
}

// ---------------------------------------------------------------------------------------------
// Routes

pub(crate) fn exports_dir(state: &AppState) -> PathBuf {
    state.config.data_dir.join(EXPORTS_DIR)
}

fn now_us() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_micros()).unwrap_or(i64::MAX))
}

/// Engine selection of a request (timestamps in nanoseconds, the end inclusive to the µs).
fn selection(request: &ExportRequest) -> Result<ExportSelection, ApiError> {
    Ok(match request {
        ExportRequest::Session => ExportSelection::Session,
        ExportRequest::Range { from_us, to_us } => {
            if to_us < from_us {
                return Err(ApiError::BadRequest(
                    "the end of the range is before its start".to_owned(),
                ));
            }
            ExportSelection::Range {
                from_ns: from_us.saturating_mul(1000),
                to_ns: to_us.saturating_mul(1000).saturating_add(999),
            }
        }
        ExportRequest::Flow { flow_id } => ExportSelection::Flow {
            id: flow_id
                .parse()
                .map_err(|_| ApiError::BadRequest("invalid flow id".to_owned()))?,
        },
    })
}

/// File name chosen by the server: `netsift-<session>-<scope>-<job>.pcapng`, only
/// `[a-z0-9-]` before the extension (no client text, no traversal).
fn file_name(session: &SessionId, selection: &ExportSelection, job: &str) -> String {
    let session = session.as_str().get(..8).unwrap_or_default().to_lowercase();
    let job = job
        .get(job.len().saturating_sub(8)..)
        .unwrap_or_default()
        .to_lowercase();
    let scope = match selection {
        ExportSelection::Session => "session".to_owned(),
        ExportSelection::Range { .. } => "range".to_owned(),
        // The parsed id, never the client's text (`+5`, leading zeros): digits only, bounded.
        ExportSelection::Flow { id } => format!("flow-{id}"),
    };
    format!("netsift-{session}-{scope}-{job}.pcapng")
}

/// Problem of an engine error (paths and internal details are logged, never returned).
fn export_error(e: ExportError) -> ApiError {
    match e {
        ExportError::FlowNotFound(_) => ApiError::NotFound,
        ExportError::InvalidRange => ApiError::BadRequest(e.to_string()),
        ExportError::SourceMissing { .. } => ApiError::ExportSourceMissing(e.to_string()),
        ExportError::SourceModified { .. } => ApiError::ExportSourceModified(e.to_string()),
        ExportError::Store(inner) => inner.into(),
        other => {
            tracing::error!("export failed: {other}");
            ApiError::Internal
        }
    }
}

fn failure(e: &ApiError) -> ExportFailure {
    let (kind, detail) = e.problem();
    ExportFailure {
        kind,
        title: e.title().to_owned(),
        status: e.status(),
        detail,
    }
}

async fn start(
    State(state): State<Arc<AppState>>,
    UrlPath(id): UrlPath<String>,
    ApiJson(request): ApiJson<ExportRequest>,
) -> Result<(StatusCode, Json<ExportJob>), ApiError> {
    let id = parse_id(&id)?;
    let selection = selection(&request)?;
    let cancel = CancelToken::new();
    let running = Running::new(&state, &cancel)?;
    let session = id.clone();
    let plan: ExportPlan = blocking(&state, move |s| {
        let (_, session) = open_ready(s, &session)?;
        let plan = plan_export(&session, &selection).map_err(export_error)?;
        let dir = exports_dir(s);
        std::fs::create_dir_all(&dir).map_err(|e| {
            tracing::error!("cannot create the exports folder: {e}");
            ApiError::Internal
        })?;
        Ok(plan)
    })
    .await?;

    let job_id = SessionId::generate().to_string();
    let name = file_name(&id, &selection, &job_id);
    let folder = exports_dir(&state);
    let dest = folder.join(&name);
    let (scope, from_us, to_us, flow_id) = match &request {
        ExportRequest::Session => (ExportScope::Session, None, None, None),
        ExportRequest::Range { from_us, to_us } => {
            (ExportScope::Range, Some(*from_us), Some(*to_us), None)
        }
        ExportRequest::Flow { .. } => {
            let flow_id = match selection {
                ExportSelection::Flow { id } => Some(id.to_string()),
                _ => None,
            };
            (ExportScope::Flow, None, None, flow_id)
        }
    };
    let job = Arc::new(Job {
        session: id.to_string(),
        cancel: cancel.clone(),
        dest: dest.clone(),
        status: Mutex::new(ExportJob {
            id: job_id.clone(),
            session_id: id.to_string(),
            scope,
            from_us,
            to_us,
            flow_id,
            state: ExportState::Running,
            file_name: name,
            folder: folder.to_string_lossy().into_owned(),
            path: None,
            packets: 0,
            bytes_written: 0,
            bytes_read: 0,
            bytes_total: plan.total_bytes(),
            read_errors: 0,
            error: None,
            created_at_us: now_us(),
        }),
    });
    state.exports.insert(job_id, Arc::clone(&job));
    let thread_job = Arc::clone(&job);
    let spawned = std::thread::Builder::new()
        .name("netsift-export".to_owned())
        .spawn(move || run(&thread_job, plan, running));
    if let Err(e) = spawned {
        tracing::error!("cannot start the export thread: {e}");
        job.update(|s| {
            s.state = ExportState::Failed;
            s.error = Some(failure(&ApiError::Internal));
        });
    }
    Ok((StatusCode::ACCEPTED, Json(job.snapshot())))
}

/// Body of the export thread.
fn run(job: &Job, plan: ExportPlan, running: Running) {
    let _running = running;
    let mut progress = |p: &ExportProgress| {
        job.update(|s| {
            s.packets = p.packets;
            s.bytes_written = p.bytes_written;
            s.bytes_read = p.bytes_read;
            s.bytes_total = p.bytes_total;
        });
    };
    let result = plan.run(&job.dest, &job.cancel, &mut progress);
    job.update(|s| match result {
        Ok(report) => {
            s.state = ExportState::Done;
            s.packets = report.packets;
            s.bytes_written = report.bytes_written;
            s.bytes_read = s.bytes_total;
            s.read_errors = report.read_errors;
            s.path = Some(job.dest.to_string_lossy().into_owned());
        }
        Err(ExportError::Cancelled) => s.state = ExportState::Cancelled,
        Err(e) => {
            s.state = ExportState::Failed;
            s.error = Some(failure(&export_error(e)));
        }
    });
}

fn job(state: &AppState, raw: &str) -> Result<Arc<Job>, ApiError> {
    // Same alphabet and length as session ids: anything else is unknown.
    let id: SessionId = raw.parse().map_err(|_| ApiError::NotFound)?;
    state.exports.get(id.as_str()).ok_or(ApiError::NotFound)
}

async fn list(
    State(state): State<Arc<AppState>>,
    UrlPath(id): UrlPath<String>,
) -> Result<Json<Vec<ExportJob>>, ApiError> {
    let id = parse_id(&id)?;
    let jobs = lock(&state.exports.jobs)
        .iter()
        .rev()
        .filter(|(_, j)| j.session == id.as_str())
        .map(|(_, j)| j.snapshot())
        .collect();
    Ok(Json(jobs))
}

async fn status(
    State(state): State<Arc<AppState>>,
    UrlPath(raw): UrlPath<String>,
) -> Result<Json<ExportJob>, ApiError> {
    Ok(Json(job(&state, &raw)?.snapshot()))
}

/// Asks a running export to stop (it ends `cancelled`, its partial file removed); no effect on
/// a finished one.
async fn cancel(
    State(state): State<Arc<AppState>>,
    UrlPath(raw): UrlPath<String>,
) -> Result<Json<ExportJob>, ApiError> {
    let job = job(&state, &raw)?;
    job.cancel.cancel();
    Ok(Json(job.snapshot()))
}

/// The exported file (web mode download), streamed: never loaded in memory.
async fn file(
    State(state): State<Arc<AppState>>,
    UrlPath(raw): UrlPath<String>,
) -> Result<Response, ApiError> {
    let job = job(&state, &raw)?;
    let snapshot = job.snapshot();
    if snapshot.state != ExportState::Done {
        return Err(ApiError::Conflict("the export is not finished".to_owned()));
    }
    let file = tokio::fs::File::open(&job.dest)
        .await
        .map_err(|_| ApiError::NotFound)?;
    let len = file.metadata().await.map_err(|_| ApiError::NotFound)?.len();
    Ok(attachment(stream(file), len, &snapshot.file_name))
}

fn stream(file: tokio::fs::File) -> Body {
    let chunks = futures_util::stream::unfold(Some(file), |file| async move {
        let mut file = file?;
        let mut buf = vec![0u8; STREAM_CHUNK];
        match file.read(&mut buf).await {
            Ok(0) => None,
            Ok(n) => {
                buf.truncate(n);
                Some((Ok::<_, std::io::Error>(Bytes::from(buf)), Some(file)))
            }
            Err(e) => Some((Err(e), None)),
        }
    });
    Body::from_stream(chunks)
}

fn attachment(body: Body, len: u64, name: &str) -> Response {
    let mut res = body.into_response();
    let headers = res.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(len));
    if let Ok(v) = HeaderValue::from_str(&format!("attachment; filename=\"{name}\"")) {
        headers.insert(header::CONTENT_DISPOSITION, v);
    }
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("sandbox"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res
}

/// Removes the partial files left in the exports folder by an interrupted run.
pub(crate) fn remove_orphans(data_dir: &Path) {
    let removed = netsift_engine::export::remove_orphan_parts(&data_dir.join(EXPORTS_DIR));
    if removed > 0 {
        tracing::info!(removed, "interrupted export files removed");
    }
}

#[cfg(test)]
mod tests;
