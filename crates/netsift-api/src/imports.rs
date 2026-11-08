//! Import routes: scan, background import, cancellation and the SSE progress stream.
//!
//! An import runs on a dedicated thread around [`netsift_engine::ingest`]. Its state is kept in
//! an in-memory [`Registry`]: the latest progress, the warnings (continuity anomalies as the
//! engine finds them, see `Progress::new_anomalies`) and the final event, published
//! through a `watch` channel that any number of SSE subscribers read (each one at most every
//! [`PROGRESS_INTERVAL`]). Finished imports stay in the registry (bounded), so a late subscriber
//! immediately gets the final event; sessions unknown to the registry (previous run, CLI) get
//! a final event rebuilt from the catalog and the session database.

use std::collections::{HashMap, VecDeque};
use std::convert::Infallible;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use axum::extract::{Path as UrlPath, State};
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures_util::Stream;
use netsift_engine::{
    CancelToken, EngineError, GroupSelection, IngestOptions, InputPlan, Phase, Progress, ingest,
    kind_name, plan_input,
};
use netsift_store::catalog::MAX_NAME_LEN;
use netsift_store::{AnomalyRow, Catalog, SessionId, SessionState as StoreState};
use tokio::sync::{oneshot, watch};

use crate::contract::{
    AnomalyInfo, GroupPattern, ImportEvent, ImportProgress, ImportRequest, ImportResponse,
    ScanGroup, ScanRequest, ScanResponse, ScanSkippedFile,
};
use crate::extract::ApiJson;
use crate::sessions::{FAILED_MESSAGE, Stats, info, parse_id, session_dir};
use crate::{ApiError, AppState, blocking, convert, fs};

/// Engine progress interval and minimum time between two `progress` events of a stream.
pub(crate) const PROGRESS_INTERVAL: Duration = Duration::from_millis(250);
/// Interval of the SSE keep-alive comments.
const KEEP_ALIVE: Duration = Duration::from_secs(15);
/// Polling interval of a session imported by another process.
const STORED_POLL: Duration = Duration::from_secs(1);
/// Warnings (continuity anomalies) published per import.
const MAX_WARNINGS: usize = 200;
/// Finished imports kept in memory for late subscribers.
const MAX_FINISHED: usize = 32;
/// Anomalies listed per group, and skipped files listed, by a scan.
const MAX_SCAN_ANOMALIES: usize = 100;
const MAX_SCAN_SKIPPED: usize = 1_000;
/// Smallest capture file (`netsift_capture::chunkset::MIN_CAPTURE_LEN`).
const MIN_CAPTURE_LEN: u64 = 12;
/// Walk error reason of special files (`netsift_capture` inventory).
const NOT_REGULAR: &str = "not a regular file";

pub(crate) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/sessions/import", post(start))
        .route("/sessions/import/scan", post(scan))
        .route("/sessions/{id}/cancel", post(cancel))
        .route("/sessions/{id}/events", get(events))
}

// ---------------------------------------------------------------------------------------------
// Registry

/// What subscribers see of an import.
#[derive(Debug, Clone, Default)]
pub(crate) struct Status {
    pub(crate) progress: Option<ImportProgress>,
    pub(crate) warnings: Arc<Vec<AnomalyInfo>>,
    /// `done` or `failed`, once the import is over.
    pub(crate) last: Option<ImportEvent>,
}

pub(crate) struct ImportHandle {
    cancel: CancelToken,
    status: watch::Sender<Status>,
    /// Registration order, to drop the oldest finished imports first.
    order: u64,
}

impl ImportHandle {
    /// Latest progress, plus the anomalies found since the previous callback (at most
    /// [`MAX_WARNINGS`] over an import; the full list is in the `anomalies` table).
    fn publish(&self, progress: Option<ImportProgress>, anomalies: &[AnomalyRow]) {
        self.status.send_modify(|s| {
            if let Some(p) = progress {
                s.progress = Some(p);
            }
            let room = MAX_WARNINGS.saturating_sub(s.warnings.len());
            if room > 0 && !anomalies.is_empty() {
                let warnings = Arc::make_mut(&mut s.warnings);
                warnings.extend(
                    anomalies
                        .iter()
                        .take(room)
                        .map(|a| convert::anomaly_preview(a.clone(), None)),
                );
            }
        });
    }

    fn finish(&self, last: ImportEvent) {
        self.status.send_modify(|s| s.last = Some(last));
    }

    fn is_finished(&self) -> bool {
        self.status.borrow().last.is_some()
    }
}

pub(crate) struct Registry {
    imports: Mutex<HashMap<String, Arc<ImportHandle>>>,
    next_order: AtomicU64,
    /// Cancellation tokens of the live import threads.
    running: Mutex<HashMap<u64, CancelToken>>,
    /// Number of live import threads.
    active: watch::Sender<usize>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Registry {
    pub(crate) fn new() -> Self {
        Self {
            imports: Mutex::new(HashMap::new()),
            next_order: AtomicU64::new(0),
            running: Mutex::new(HashMap::new()),
            active: watch::Sender::new(0),
        }
    }

    fn get(&self, id: &str) -> Option<Arc<ImportHandle>> {
        lock(&self.imports).get(id).cloned()
    }

    /// Progress of a running import.
    pub(crate) fn live_progress(&self, id: &SessionId) -> Option<ImportProgress> {
        let handle = self.get(id.as_str())?;
        let status = handle.status.borrow();
        if status.last.is_some() {
            None
        } else {
            status.progress.clone()
        }
    }

    pub(crate) fn is_running(&self, id: &SessionId) -> bool {
        self.get(id.as_str()).is_some_and(|h| !h.is_finished())
    }

    pub(crate) fn forget(&self, id: &SessionId) {
        lock(&self.imports).remove(id.as_str());
    }

    fn register(&self, id: &SessionId, cancel: CancelToken) -> Arc<ImportHandle> {
        let handle = Arc::new(ImportHandle {
            cancel,
            status: watch::Sender::new(Status::default()),
            order: self.next_order.fetch_add(1, Ordering::Relaxed),
        });
        let mut imports = lock(&self.imports);
        imports.insert(id.to_string(), Arc::clone(&handle));
        let mut finished: Vec<(u64, String)> = imports
            .iter()
            .filter(|(_, h)| h.is_finished())
            .map(|(k, h)| (h.order, k.clone()))
            .collect();
        if finished.len() > MAX_FINISHED {
            finished.sort_unstable();
            let excess = finished.len() - MAX_FINISHED;
            for (_, key) in finished.into_iter().take(excess) {
                imports.remove(&key);
            }
        }
        handle
    }

    pub(crate) fn cancel_all(&self) {
        for token in lock(&self.running).values() {
            token.cancel();
        }
    }

    /// Number of live import threads.
    pub(crate) fn running_count(&self) -> usize {
        *self.active.borrow()
    }

    pub(crate) async fn wait_idle(&self) {
        let mut rx = self.active.subscribe();
        let _ = rx.wait_for(|n| *n == 0).await;
    }
}

/// Counts a live import thread; removed when dropped (thread end, or a failed spawn).
struct Running {
    state: Arc<AppState>,
    key: u64,
}

impl Running {
    /// Counts a new import, or refuses it when `max_imports` are already running.
    fn new(state: &Arc<AppState>, cancel: &CancelToken) -> Result<Self, ApiError> {
        let registry = &state.imports;
        let key = registry.next_order.fetch_add(1, Ordering::Relaxed);
        {
            let mut running = lock(&registry.running);
            if running.len() >= state.config.max_imports.max(1) {
                return Err(ApiError::TooManyImports);
            }
            running.insert(key, cancel.clone());
            registry.active.send_replace(running.len());
        }
        // Checked after the insertion: `begin_shutdown` sets the flag before cancelling.
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
        let registry = &self.state.imports;
        let mut running = lock(&registry.running);
        running.remove(&self.key);
        registry.active.send_replace(running.len());
    }
}

// ---------------------------------------------------------------------------------------------
// Scan

fn input_error(e: &EngineError) -> ApiError {
    match e {
        EngineError::Store(inner) => {
            tracing::error!("store error before import: {inner}");
            ApiError::Internal
        }
        other => ApiError::BadRequest(other.to_string()),
    }
}

fn pattern(kind: &str, single: bool) -> GroupPattern {
    match kind {
        "dumpcap" => GroupPattern::Dumpcap,
        "dumpcap_nametimenum" => GroupPattern::DumpcapNameTimeNum,
        "tcpdump" => GroupPattern::TcpdumpC,
        "common_prefix" if single => GroupPattern::SingleFile,
        "common_prefix" => GroupPattern::CommonPrefix,
        _ => GroupPattern::Folder,
    }
}

/// Reason of a non-capture file. The inventory classifies it; its kind is inferred from the
/// size and readability (a capture with a corrupt header reads as `unrecognized`).
fn skip_reason(size: u64, readable: bool) -> &'static str {
    if size == 0 {
        "empty"
    } else if !readable {
        "unreadable"
    } else if size < MIN_CAPTURE_LEN {
        "too_short"
    } else {
        "unrecognized"
    }
}

fn scan_response(plan: &InputPlan) -> ScanResponse {
    let input_is_file = plan.root.is_file();
    let groups = plan
        .grouping
        .groups
        .iter()
        .enumerate()
        .map(|(index, g)| {
            let kind = kind_name(g.kind);
            let firsts: Vec<i64> = g.active().filter_map(|(_, m)| m.entry.first_ts()).collect();
            let first = firsts.iter().min().copied();
            // Without a full read, the end is only known as the start of the last chunk.
            let last = firsts.iter().max().copied().filter(|l| Some(*l) > first);
            // Default continuity settings (the type lives in netsift-capture, not a dependency).
            #[allow(clippy::default_trait_access)]
            let config = Default::default();
            let anomalies = g
                .anomalies(&config)
                .iter()
                .take(MAX_SCAN_ANOMALIES)
                .map(|a| {
                    let fallback = a
                        .chunk
                        .and_then(|c| g.members.get(usize::try_from(c).ok()?))
                        .and_then(|m| m.entry.first_ts());
                    convert::anomaly_preview(
                        netsift_engine::translate::anomaly_row(a, &[]),
                        fallback,
                    )
                })
                .collect();
            let pattern = pattern(kind, input_is_file || g.members.len() == 1);
            ScanGroup {
                id: u32::try_from(index).unwrap_or(u32::MAX),
                pattern,
                prefix: if pattern == GroupPattern::Folder {
                    String::new()
                } else {
                    g.label.clone()
                },
                file_count: u32::try_from(g.active().count()).unwrap_or(u32::MAX),
                total_bytes: g.total_bytes(),
                first_ts_us: first.map(convert::us),
                last_ts_us: last.map(convert::us),
                anomalies,
            }
        })
        .collect();
    let ungrouped = plan.grouping.ungrouped.iter().map(|e| ScanSkippedFile {
        name: e.name.clone(),
        reason: skip_reason(e.size, e.fingerprint.is_some()).to_owned(),
    });
    let walk = plan.inventory.walk_errors.iter().map(|w| ScanSkippedFile {
        name: w.path.file_name().map_or_else(
            || w.path.to_string_lossy().into_owned(),
            |n| n.to_string_lossy().into_owned(),
        ),
        reason: if w.reason == NOT_REGULAR {
            "not_regular"
        } else {
            "unreadable"
        }
        .to_owned(),
    });
    ScanResponse {
        path: plan.root.to_string_lossy().into_owned(),
        groups,
        skipped: ungrouped.chain(walk).take(MAX_SCAN_SKIPPED).collect(),
        truncated: plan.inventory.limit_reached,
    }
}

async fn scan(
    State(state): State<Arc<AppState>>,
    ApiJson(req): ApiJson<ScanRequest>,
) -> Result<Json<ScanResponse>, ApiError> {
    blocking(&state, move |s| {
        let root = fs::resolve_input(s, &req.path)?;
        let plan = plan_input(&root, req.recursive).map_err(|e| input_error(&e))?;
        Ok(scan_response(&plan))
    })
    .await
    .map(Json)
}

// ---------------------------------------------------------------------------------------------
// Import

fn selection(ids: &[u32], groups: usize) -> Result<GroupSelection, ApiError> {
    let mut ids: Vec<usize> = ids
        .iter()
        .map(|&i| usize::try_from(i).unwrap_or(usize::MAX))
        .collect();
    ids.sort_unstable();
    ids.dedup();
    if let Some(bad) = ids.iter().find(|&&i| i >= groups) {
        return Err(ApiError::BadRequest(format!(
            "group {bad} does not exist ({groups} group(s) found)"
        )));
    }
    match ids.as_slice() {
        [] if groups > 1 => Err(ApiError::BadRequest(format!(
            "{groups} chunk sets found: choose group_ids"
        ))),
        [] => Ok(GroupSelection::Single),
        [only] => Ok(GroupSelection::Index(*only)),
        all if all.len() == groups => Ok(GroupSelection::MergeAll),
        _ => Err(ApiError::BadRequest(
            "merging a subset of the chunk sets is not supported: choose one group or all of them"
                .to_owned(),
        )),
    }
}

fn session_name(name: Option<String>) -> Result<Option<String>, ApiError> {
    let Some(name) = name else {
        return Ok(None);
    };
    let name = name.trim();
    if name.is_empty() {
        return Ok(None);
    }
    if name.len() > MAX_NAME_LEN || name.chars().any(char::is_control) {
        return Err(ApiError::BadRequest(
            "invalid session name (too long or control characters)".to_owned(),
        ));
    }
    Ok(Some(name.to_owned()))
}

struct Job {
    root: PathBuf,
    options: IngestOptions,
}

async fn start(
    State(state): State<Arc<AppState>>,
    ApiJson(req): ApiJson<ImportRequest>,
) -> Result<(StatusCode, Json<ImportResponse>), ApiError> {
    if state.is_shutting_down() {
        return Err(ApiError::Conflict("the server is shutting down".to_owned()));
    }
    if lock(&state.imports.running).len() >= state.config.max_imports.max(1) {
        // Answered before the inventory; checked again atomically when the thread starts.
        return Err(ApiError::TooManyImports);
    }
    let name = session_name(req.name)?;
    // Input errors (path, groups) are answered before any session exists.
    let job = blocking(&state, move |s| {
        let root = fs::resolve_input(s, &req.path)?;
        let plan = plan_input(&root, req.recursive).map_err(|e| input_error(&e))?;
        let selection = selection(&req.group_ids, plan.grouping.groups.len())?;
        plan.select(selection).map_err(|e| input_error(&e))?;
        let mut options = s.ingest_template.clone();
        // The database of this moment: a later update does not affect this import.
        options.analyzers.config_mut().geo = s.geoip.current().0;
        options.name = name;
        options.selection = selection;
        options.recursive = req.recursive;
        Ok(Job {
            root: plan.root,
            options,
        })
    })
    .await?;
    let session_id = spawn_import(&state, job).await?;
    Ok((StatusCode::ACCEPTED, Json(ImportResponse { session_id })))
}

/// Starts the import thread; resolves with the session id once the session exists.
async fn spawn_import(state: &Arc<AppState>, job: Job) -> Result<String, ApiError> {
    let (tx, rx) = oneshot::channel();
    let cancel = CancelToken::new();
    let running = Running::new(state, &cancel)?;
    let thread_state = Arc::clone(state);
    std::thread::Builder::new()
        .name("netsift-import".to_owned())
        .spawn(move || {
            let _running = running;
            run_import(&thread_state, &job, &cancel, tx);
        })
        .map_err(|e| {
            tracing::error!("cannot start an import thread: {e}");
            ApiError::Internal
        })?;
    rx.await.map_err(|_| ApiError::Internal)?
}

type Reply = oneshot::Sender<Result<String, ApiError>>;

fn attach(
    state: &AppState,
    id: &SessionId,
    cancel: &CancelToken,
    reply: &mut Option<Reply>,
) -> Arc<ImportHandle> {
    let handle = state.imports.register(id, cancel.clone());
    if let Some(reply) = reply.take() {
        let _ = reply.send(Ok(id.to_string()));
    }
    handle
}

fn progress_dto(p: &Progress) -> Option<ImportProgress> {
    let phase = match p.phase {
        Phase::Reading => "reading",
        Phase::Finishing => "finishing",
        Phase::Done => return None,
    };
    let chunk_count = u32::try_from(p.chunks_total).unwrap_or(u32::MAX);
    Some(ImportProgress {
        bytes_done: p.bytes_read,
        bytes_total: p.bytes_total,
        chunk_index: p.chunk.unwrap_or(0).min(chunk_count.saturating_sub(1)),
        chunk_count,
        chunk_name: p.chunk_name.clone().unwrap_or_default(),
        packets: p.packets,
        rate_bps: p.bytes_per_sec(),
        eta_s: p.eta().map(|d| d.as_secs_f64()),
        phase: phase.to_owned(),
    })
}

fn run_import(state: &AppState, job: &Job, cancel: &CancelToken, reply: Reply) {
    let catalog = match Catalog::open(&state.config.data_dir) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("cannot open the catalog for an import: {e}");
            let _ = reply.send(Err(ApiError::Internal));
            return;
        }
    };
    let mut reply = Some(reply);
    let mut handle: Option<Arc<ImportHandle>> = None;
    let result = ingest(
        &catalog,
        &job.root,
        &job.options,
        cancel,
        &mut |p: &Progress| {
            // The first callback names the session: the client gets its id right away.
            let h = handle.get_or_insert_with(|| attach(state, &p.session, cancel, &mut reply));
            h.publish(progress_dto(p), &p.new_anomalies);
        },
    );
    match result {
        Ok(report) => {
            let h = handle.unwrap_or_else(|| attach(state, &report.session, cancel, &mut reply));
            h.finish(ImportEvent::Done {
                state: convert::state(report.state),
                packets: report.packets,
                flows: report.flows,
                anomalies: u32::try_from(report.anomalies).unwrap_or(u32::MAX),
                duration_s: report.duration.as_secs_f64(),
            });
        }
        Err(EngineError::ImportFailed { session, reason }) => {
            tracing::warn!(session = %session, "import failed: {reason}");
            let h = handle.unwrap_or_else(|| attach(state, &session, cancel, &mut reply));
            h.finish(ImportEvent::Failed {
                message: FAILED_MESSAGE.to_owned(),
            });
        }
        Err(e) => match handle {
            Some(h) => {
                tracing::warn!("import failed: {e}");
                h.finish(ImportEvent::Failed {
                    message: FAILED_MESSAGE.to_owned(),
                });
            }
            None => {
                if let Some(reply) = reply.take() {
                    let _ = reply.send(Err(input_error(&e)));
                }
            }
        },
    }
}

async fn cancel(
    State(state): State<Arc<AppState>>,
    UrlPath(id): UrlPath<String>,
) -> Result<StatusCode, ApiError> {
    let id = parse_id(&id)?;
    blocking(&state, move |s| {
        info(s, &id)?;
        // Idempotent: cancelling a finished import does nothing.
        if let Some(h) = s.imports.get(id.as_str()) {
            h.cancel.cancel();
        }
        Ok(StatusCode::ACCEPTED)
    })
    .await
}

// ---------------------------------------------------------------------------------------------
// Event stream

/// Final event of a session that is not (or no longer) in the registry; `None` while it is
/// still `importing` (in another process).
fn stored_final(state: &AppState, id: &SessionId) -> Result<Option<ImportEvent>, ApiError> {
    let info = info(state, id)?;
    let event = match info.state {
        StoreState::Importing => return Ok(None),
        StoreState::Failed => ImportEvent::Failed {
            message: FAILED_MESSAGE.to_owned(),
        },
        StoreState::Ready | StoreState::Incomplete => {
            let stats = Stats::read(state, session_dir(state, id), info.state);
            #[allow(clippy::cast_precision_loss)]
            let duration_s = stats.duration_ms.map_or(0.0, |ms| ms as f64 / 1000.0);
            ImportEvent::Done {
                state: convert::state(info.state),
                packets: stats.packets,
                flows: stats.flows,
                anomalies: stats.anomalies,
                duration_s,
            }
        }
    };
    Ok(Some(event))
}

/// Per-subscriber cursor over an import.
struct Feed {
    state: Arc<AppState>,
    id: SessionId,
    live: Option<watch::Receiver<Status>>,
    shutdown: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>,
    pending: VecDeque<ImportEvent>,
    warnings_sent: usize,
    last_progress: Option<ImportProgress>,
    last_progress_at: Option<Instant>,
    finished: bool,
}

impl Feed {
    fn new(state: Arc<AppState>, id: SessionId) -> Self {
        let live = state.imports.get(id.as_str()).map(|h| h.status.subscribe());
        let shutdown = Box::pin(state.shutdown_signal());
        Self {
            state,
            id,
            live,
            shutdown,
            pending: VecDeque::new(),
            warnings_sent: 0,
            last_progress: None,
            last_progress_at: None,
            finished: false,
        }
    }

    /// Sleeps; false if the server started shutting down meanwhile.
    async fn sleep(&mut self, d: Duration) -> bool {
        tokio::select! {
            () = tokio::time::sleep(d) => true,
            () = &mut self.shutdown => false,
        }
    }

    fn absorb(&mut self, status: Status) {
        if let Some(p) = status.progress
            && status.last.is_none()
            && self.last_progress.as_ref() != Some(&p)
        {
            self.last_progress = Some(p.clone());
            self.last_progress_at = Some(Instant::now());
            self.pending.push_back(ImportEvent::Progress(p));
        }
        for w in status.warnings.iter().skip(self.warnings_sent) {
            self.pending.push_back(ImportEvent::Warning(w.clone()));
        }
        self.warnings_sent = self.warnings_sent.max(status.warnings.len());
        if let Some(last) = status.last {
            self.pending.push_back(last);
            self.finished = true;
        }
    }

    async fn next(&mut self) -> Option<ImportEvent> {
        loop {
            if let Some(event) = self.pending.pop_front() {
                return Some(event);
            }
            if self.finished {
                return None;
            }
            if self.live.is_some() {
                if let Some(at) = self.last_progress_at {
                    let wait = PROGRESS_INTERVAL.saturating_sub(at.elapsed());
                    if !wait.is_zero() && !self.sleep(wait).await {
                        return None;
                    }
                }
                let Some(rx) = self.live.as_mut() else {
                    continue;
                };
                let status = rx.borrow_and_update().clone();
                self.absorb(status);
                if !self.pending.is_empty() || self.finished {
                    continue;
                }
                let Some(rx) = self.live.as_mut() else {
                    continue;
                };
                tokio::select! {
                    changed = rx.changed() => {
                        // The handle was dropped (session deleted): rebuild from the catalog.
                        if changed.is_err() {
                            self.live = None;
                        }
                    }
                    () = &mut self.shutdown => return None,
                }
            } else {
                let id = self.id.clone();
                match blocking(&self.state, move |s| stored_final(s, &id)).await {
                    Ok(Some(event)) => {
                        self.pending.push_back(event);
                        self.finished = true;
                    }
                    Ok(None) => {
                        if let Some(h) = self.state.imports.get(self.id.as_str()) {
                            self.live = Some(h.status.subscribe());
                        } else if !self.sleep(STORED_POLL).await {
                            return None;
                        }
                    }
                    Err(_) => {
                        self.pending.push_back(ImportEvent::Failed {
                            message: "session not found".to_owned(),
                        });
                        self.finished = true;
                    }
                }
            }
        }
    }
}

fn sse_event(event: &ImportEvent) -> Event {
    let name = match event {
        ImportEvent::Progress(_) => "progress",
        ImportEvent::Warning(_) => "warning",
        ImportEvent::Done { .. } => "done",
        ImportEvent::Failed { .. } => "failed",
    };
    Event::default()
        .event(name)
        .json_data(event)
        .unwrap_or_else(|_| Event::default().comment("unserializable event"))
}

async fn events(
    State(state): State<Arc<AppState>>,
    UrlPath(id): UrlPath<String>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, ApiError> {
    let id = parse_id(&id)?;
    let checked = id.clone();
    blocking(&state, move |s| info(s, &checked).map(drop)).await?;
    let feed = Feed::new(Arc::clone(&state), id);
    let stream = futures_util::stream::unfold(feed, |mut feed| async move {
        let event = feed.next().await?;
        Some((Ok(sse_event(&event)), feed))
    });
    Ok(Sse::new(stream).keep_alive(KeepAlive::new().interval(KEEP_ALIVE).text("keep-alive")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_selection() {
        assert_eq!(selection(&[], 1).unwrap(), GroupSelection::Single);
        assert!(selection(&[], 2).is_err());
        assert_eq!(selection(&[1], 2).unwrap(), GroupSelection::Index(1));
        assert_eq!(selection(&[1, 0, 1], 2).unwrap(), GroupSelection::MergeAll);
        assert!(selection(&[0, 1], 3).is_err());
        assert!(selection(&[2], 2).is_err());
    }

    #[test]
    fn session_names() {
        assert_eq!(session_name(None).unwrap(), None);
        assert_eq!(session_name(Some("  ".into())).unwrap(), None);
        assert_eq!(
            session_name(Some(" a ".into())).unwrap().as_deref(),
            Some("a")
        );
        assert!(session_name(Some("a\nb".into())).is_err());
        assert!(session_name(Some("x".repeat(MAX_NAME_LEN + 1))).is_err());
    }

    #[test]
    fn published_warnings_are_bounded() {
        let handle = ImportHandle {
            cancel: CancelToken::new(),
            status: watch::Sender::new(Status::default()),
            order: 0,
        };
        let row = AnomalyRow {
            kind: "time_gap".to_owned(),
            chunk_id: Some(1),
            ts: Some(5_000),
            detail: serde_json::json!({ "gap_ns": 7_000 }),
        };
        // 250 rows over two callbacks: the first 200 are kept.
        handle.publish(None, &vec![row.clone(); 150]);
        handle.publish(None, &vec![row; 100]);
        let status = handle.status.borrow();
        assert_eq!(status.warnings.len(), MAX_WARNINGS);
        let first = &status.warnings[0];
        assert_eq!((first.id.clone(), first.ts_us), (None, Some(5)));
        assert_eq!(first.detail["gap_us"], 7);
        assert!(status.progress.is_none() && status.last.is_none());
    }

    #[test]
    fn skip_reasons() {
        assert_eq!(skip_reason(0, true), "empty");
        assert_eq!(skip_reason(5, false), "unreadable");
        assert_eq!(skip_reason(5, true), "too_short");
        assert_eq!(skip_reason(500, true), "unrecognized");
    }
}
