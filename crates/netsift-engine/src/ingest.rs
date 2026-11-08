//! Import of a capture file or folder into a new session of a catalog.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::atomic::AtomicU64;
use std::sync::mpsc::{RecvTimeoutError, sync_channel};
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use netsift_analyze::flow::FlowTable;
use netsift_analyze::geo;
use netsift_capture::PacketSource;
use netsift_capture::chunkset::{ChunkGroup, ChunkSetSource, ChunkStats};
use netsift_store::session::BLOBS_DIR;
use netsift_store::{
    Catalog, MetaRow, OpenMode, SessionId, SessionState, StoreError, StoreRecord, StoreSender,
    StoreWriter, WriterStats,
};

use crate::blobs::BlobBudget;
use crate::error::EngineError;
use crate::options::{CancelToken, IngestOptions, Phase, Progress};
use crate::pipeline::{
    ANALYZER_PANICKED, Batch, BatchLimits, Budget, ReaderOutcome, ReaderSetup, ShardOutcome,
    ShardSetup, Shared, WriterFault, run_decoder, run_reader, run_shard,
};
use crate::plan::{GroupSelection, kind_name, plan_input};
use crate::translate::{anomaly_row, chunk_rows};

/// Summary of a finished import (state `ready` or `incomplete`).
#[derive(Debug, Clone, PartialEq)]
pub struct IngestReport {
    pub session: SessionId,
    pub name: String,
    pub state: SessionState,
    /// Label of the chunk set imported.
    pub group: String,
    /// Members of the chunk set (read, duplicates and ignored files).
    pub chunks: usize,
    /// Chunk files read.
    pub chunks_read: usize,
    pub anomalies: usize,
    /// Anomaly count per kind (`time_gap`, `missing_sequence`...).
    pub anomaly_kinds: BTreeMap<&'static str, usize>,
    /// Raw frames read (before IP defragmentation; `timeseries` counts reassembled datagrams).
    pub packets: u64,
    /// Bytes read from the chunk files.
    pub bytes_read: u64,
    pub flows: u64,
    pub hosts: u64,
    pub shards: usize,
    pub duration: Duration,
    pub writer: WriterStats,
}

impl IngestReport {
    /// Average read throughput in bytes per second.
    #[allow(clippy::cast_precision_loss)]
    pub fn bytes_per_sec(&self) -> f64 {
        let secs = self.duration.as_secs_f64();
        if secs > 0.0 {
            self.bytes_read as f64 / secs
        } else {
            0.0
        }
    }
}

/// Imports `input` (a capture file or a folder of chunks) into a new session of `catalog`.
///
/// Lifecycle in the catalog: the session is created `importing`, then becomes `ready`,
/// `incomplete` (cancelled through `cancel`: what was read is analyzed and stays browsable) or
/// `failed` (then [`EngineError::ImportFailed`] is returned). Input errors (unreadable path, no
/// capture, several chunk sets without a selection) are returned before any session exists.
///
/// `progress` is called on the calling thread every [`IngestOptions::progress_interval`], then
/// once in [`Phase::Finishing`] and once in [`Phase::Done`].
pub fn ingest(
    catalog: &Catalog,
    input: &Path,
    options: &IngestOptions,
    cancel: &CancelToken,
    progress: &mut dyn FnMut(&Progress),
) -> Result<IngestReport, EngineError> {
    let started = Instant::now();
    let plan = plan_input(input, options.recursive)?;
    let group = plan.select(options.selection)?;
    let name = options
        .name
        .clone()
        .filter(|n| !n.trim().is_empty())
        .unwrap_or_else(|| default_name(&plan.root, &group));
    let info = catalog.create(&name, std::slice::from_ref(&plan.root), group.total_bytes())?;
    let session = info.id.clone();

    let ctx = RunCtx {
        catalog,
        session: &session,
        root: &plan.root,
        group: &group,
        options,
        cancel,
        started,
    };
    match ctx.run(progress) {
        Ok(mut report) => {
            report.name = info.name;
            set_final_state(catalog, &session, report.state, None)?;
            let size = dir_size(&catalog.session_dir(&session));
            if let Err(e) = catalog.set_sizes(&session, group.total_bytes(), size) {
                tracing::warn!(session = %session, "cannot record session sizes: {e}");
            }
            Ok(report)
        }
        Err(reason) => {
            // The import error is what the caller needs; a catalog error is only logged.
            let _ = set_final_state(catalog, &session, SessionState::Failed, Some(&reason));
            let _ = catalog.set_sizes(
                &session,
                group.total_bytes(),
                dir_size(&catalog.session_dir(&session)),
            );
            Err(EngineError::ImportFailed { session, reason })
        }
    }
}

/// Leaves `importing` for good: one retry (e.g. the catalog was briefly locked), then the
/// error is logged and returned. A session still `importing` after that is recovered as
/// `incomplete` by [`recover_interrupted`] at the next start.
fn set_final_state(
    catalog: &Catalog,
    session: &SessionId,
    state: SessionState,
    detail: Option<&str>,
) -> Result<(), EngineError> {
    match catalog.set_state(session, state, detail) {
        Ok(()) => Ok(()),
        Err(first) => {
            tracing::warn!(session = %session, "cannot set session state, retrying: {first}");
            std::thread::sleep(Duration::from_millis(200));
            catalog.set_state(session, state, detail).map_err(|e| {
                tracing::error!(session = %session, %state, "cannot set session state: {e}");
                EngineError::Store(e)
            })
        }
    }
}

/// Detail of the sessions recovered by [`recover_interrupted`].
pub const INTERRUPTED_DETAIL: &str = "import interrupted (application stopped)";

/// Marks every session still `importing` as `incomplete` (its data stays browsable) and
/// returns their ids. Call it once when the application starts, **before** starting any
/// import on this data directory: an import running in another process would be marked too.
pub fn recover_interrupted(catalog: &Catalog) -> Result<Vec<SessionId>, EngineError> {
    let mut recovered = Vec::new();
    for info in catalog.list()? {
        if info.state == SessionState::Importing {
            catalog.set_state(&info.id, SessionState::Incomplete, Some(INTERRUPTED_DETAIL))?;
            recovered.push(info.id);
        }
    }
    Ok(recovered)
}

fn default_name(root: &Path, group: &ChunkGroup) -> String {
    let label = group.label.trim();
    if !label.is_empty() {
        return label.to_owned();
    }
    root.file_name().map_or_else(
        || root.to_string_lossy().into_owned(),
        |n| n.to_string_lossy().into_owned(),
    )
}

/// Disk usage of a directory tree (best effort).
fn dir_size(dir: &Path) -> u64 {
    let mut total = 0u64;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for entry in entries.flatten() {
            match entry.file_type() {
                Ok(t) if t.is_dir() => stack.push(entry.path()),
                Ok(t) if t.is_file() => {
                    total = total.saturating_add(entry.metadata().map_or(0, |m| m.len()));
                }
                _ => {}
            }
        }
    }
    total
}

/// Joins the decoder and every shard (the reader is already joined), then checks the counts.
fn join_rest(
    reader: Option<ReaderOutcome>,
    decoder: Option<thread::ScopedJoinHandle<'_, bool>>,
    shard_handles: Vec<thread::ScopedJoinHandle<'_, Result<ShardOutcome, StoreError>>>,
    mut failure: Option<String>,
) -> Result<Threads, String> {
    // Shards first: their errors are more precise than the decoder's.
    let mut routed = 0u64;
    let mut panicked = 0u64;
    for (index, handle) in shard_handles.into_iter().enumerate() {
        match handle.join() {
            Ok(Ok(outcome)) => {
                routed += outcome.packets;
                panicked += outcome.panicked;
            }
            // Writer errors: the cause is reported by `StoreWriter::finish`.
            Ok(Err(e)) => note(&mut failure, format!("shard {index}: {e}")),
            Err(_) => note(&mut failure, format!("shard {index} panicked")),
        }
    }
    match decoder.map(thread::ScopedJoinHandle::join) {
        Some(Ok(true)) | None => {}
        Some(Ok(false)) => note(&mut failure, "a flow shard stopped early".to_owned()),
        Some(Err(_)) => note(&mut failure, "the decoder thread panicked".to_owned()),
    }
    let Some(reader) = reader else {
        return Err(failure.unwrap_or_else(|| "the reader did not run".to_owned()));
    };
    if let Some(e) = &reader.error {
        note(&mut failure, format!("read error: {e}"));
    }
    if reader.downstream_closed {
        note(&mut failure, "the pipeline stopped early".to_owned());
    }
    if routed != reader.packets {
        note(
            &mut failure,
            format!("{} packets read but {routed} analyzed", reader.packets),
        );
    }
    Ok(Threads {
        reader,
        failure,
        panicked,
    })
}

/// Smallest per-shard defragmentation buffer (one maximal IP datagram).
const MIN_DEFRAG_BYTES: usize = 64 * 1024;

/// See [`RunCtx::parts`].
struct Parts {
    capacity: usize,
    limits: BatchLimits,
    budget: Arc<Budget>,
    /// Bytes of extracted objects the import may still write (all shards).
    blob_budget: Arc<BlobBudget>,
    fault: Option<Arc<WriterFault>>,
    registry: netsift_analyze::Registry,
    flow: netsift_analyze::flow::FlowConfig,
}

/// Keeps the first failure reason.
fn note(failure: &mut Option<String>, reason: String) {
    failure.get_or_insert(reason);
}

struct RunCtx<'a> {
    catalog: &'a Catalog,
    session: &'a SessionId,
    root: &'a Path,
    group: &'a ChunkGroup,
    options: &'a IngestOptions,
    cancel: &'a CancelToken,
    started: Instant,
}

/// What the threads produced.
struct Threads {
    reader: ReaderOutcome,
    failure: Option<String>,
    /// Analyzer instances disabled after a panic (one anomaly row each).
    panicked: u64,
}

impl RunCtx<'_> {
    /// Runs the pipeline; any error becomes the `failed` detail of the session.
    fn run(&self, progress: &mut dyn FnMut(&Progress)) -> Result<IngestReport, String> {
        let session = self
            .catalog
            .open_session(self.session, OpenMode::Import)
            .map_err(|e| e.to_string())?;
        let writer = StoreWriter::spawn(session, self.options.writer).map_err(|e| e.to_string())?;
        let sender = writer.sender();
        // Chunk rows first, so that a running import already lists its files.
        let initial: Vec<StoreRecord> = chunk_rows(self.group, &[], &[])
            .into_iter()
            .map(StoreRecord::Chunk)
            .collect();
        let sent = sender.send_batch(initial);

        let shards = self.options.shard_count();
        let threads = if sent.is_ok() {
            self.run_threads(&sender, shards, progress)
        } else {
            Err("the store writer stopped".to_owned())
        };
        let threads = match threads {
            Ok(t) => t,
            Err(reason) => {
                drop(sender);
                let detail = writer.finish().err().map(|e| e.to_string());
                return Err(detail.unwrap_or(reason));
            }
        };

        let Threads {
            reader,
            failure,
            panicked,
        } = threads;
        let stats: Vec<ChunkStats> = reader.source.chunk_stats().cloned().collect();
        let anomalies = reader.source.anomalies();
        let mut tail: Vec<StoreRecord> = chunk_rows(self.group, &stats, anomalies)
            .into_iter()
            .map(StoreRecord::Chunk)
            .collect();
        tail.extend(
            anomalies
                .iter()
                .map(|a| StoreRecord::Anomaly(anomaly_row(a, &stats))),
        );
        let cancelled = reader.cancelled;
        let state = if cancelled {
            SessionState::Incomplete
        } else {
            SessionState::Ready
        };
        let recorded_state = if failure.is_some() {
            SessionState::Failed
        } else {
            state
        };
        tail.extend(
            self.meta(&reader, &stats, shards, recorded_state)
                .into_iter()
                .map(StoreRecord::Meta),
        );
        // A send error is reported by `finish` below.
        let _ = sender.send_batch(tail);
        drop(sender);
        let writer_stats = writer.finish().map_err(|e| e.to_string())?;
        // A failed end-of-import step leaves the session usable; it runs again at the next
        // opening (ADR-014).
        for (step, error) in &writer_stats.finalize.failed {
            tracing::warn!(
                step,
                "end-of-import step failed, retried at the next opening: {error}"
            );
        }
        if let Some(reason) = failure {
            return Err(reason);
        }
        if !cancelled {
            self.thumbnails();
        }

        let mut anomaly_kinds = BTreeMap::new();
        for a in anomalies {
            *anomaly_kinds.entry(a.kind.code()).or_insert(0) += 1;
        }
        let panicked = usize::try_from(panicked).unwrap_or(usize::MAX);
        if panicked > 0 {
            anomaly_kinds.insert(ANALYZER_PANICKED, panicked);
        }
        let (flows, hosts) = self.counts().map_err(|e| e.to_string())?;
        let report = IngestReport {
            session: self.session.clone(),
            name: String::new(),
            state,
            group: self.group.label.clone(),
            chunks: self.group.members.len(),
            chunks_read: self.group.active().count(),
            anomalies: anomalies.len().saturating_add(panicked),
            anomaly_kinds,
            packets: reader.packets,
            bytes_read: reader.source.bytes_read(),
            flows,
            hosts,
            shards,
            duration: self.started.elapsed(),
            writer: writer_stats,
        };
        progress(&self.done_progress(&report, reader.source.total_bytes()));
        Ok(report)
    }

    /// Thumbnails, once `objects` is built (end-of-import steps), outside the shards. A
    /// cancelled import skips them: the API renders what is missing on demand.
    fn thumbnails(&self) {
        let dir = self.catalog.session_dir(self.session);
        match crate::thumbs::generate_pending(&dir, self.cancel, crate::thumbs::PASS_TIME_LIMIT) {
            Ok(r) if r.left > 0 => {
                tracing::info!(left = r.left, "thumbnails left for on-demand rendering");
            }
            Ok(_) => {}
            Err(e) => tracing::warn!("cannot generate thumbnails: {e}"),
        }
    }

    /// Last callback, once everything is written.
    fn done_progress(&self, report: &IngestReport, bytes_total: u64) -> Progress {
        Progress {
            session: self.session.clone(),
            phase: Phase::Done,
            bytes_read: report.bytes_read,
            bytes_total,
            packets: report.packets,
            chunk: None,
            chunk_name: None,
            chunks_total: report.chunks_read,
            elapsed: report.duration,
            new_anomalies: Vec::new(),
        }
    }

    fn counts(&self) -> netsift_store::Result<(u64, u64)> {
        let session = self
            .catalog
            .open_session(self.session, OpenMode::ReadOnly)?;
        let conn = session.conn();
        let flows = netsift_store::query::count_flows(conn)?;
        let hosts: u64 = conn.query_row("SELECT count(*) FROM hosts", [], |r| r.get(0))?;
        Ok((flows, hosts))
    }

    fn source(&self) -> ChunkSetSource {
        match &self.options.opener {
            Some(opener) => {
                ChunkSetSource::with_opener(self.group, self.options.read, opener.clone())
            }
            None => ChunkSetSource::new(self.group, self.options.read),
        }
    }

    fn progress_snapshot(&self, shared: &Shared, total: u64, phase: Phase) -> Progress {
        use std::sync::atomic::Ordering;
        let chunk = shared.chunk();
        Progress {
            session: self.session.clone(),
            phase,
            bytes_read: shared.bytes_read.load(Ordering::Relaxed),
            bytes_total: total,
            packets: shared.packets.load(Ordering::Relaxed),
            chunk,
            chunk_name: chunk
                .and_then(|c| self.group.members.get(usize::try_from(c).ok()?))
                .map(|m| m.entry.name.clone()),
            chunks_total: self.group.active().count(),
            elapsed: self.started.elapsed(),
            new_anomalies: shared.take_anomalies(),
        }
    }

    /// Settings shared by the threads of one run.
    fn parts(&self, shards: usize) -> Parts {
        let o = self.options;
        let mut registry = o.analyzers.clone();
        registry.config_mut().blobs_dir = Some(Arc::new(
            self.catalog.session_dir(self.session).join(BLOBS_DIR),
        ));
        if registry.config().geo.is_none() {
            let path = o
                .geoip_path
                .clone()
                .unwrap_or_else(|| geo::default_path(self.catalog.root()));
            registry.config_mut().geo = geo::open_or_warn(&path);
        }
        // Flow bounds are global: each shard's table gets its share.
        let mut flow = o.flow;
        flow.max_flows = (flow.max_flows / shards.max(1)).max(1);
        flow.max_defrag_bytes = (flow.max_defrag_bytes / shards.max(1)).max(MIN_DEFRAG_BYTES);
        Parts {
            capacity: o.channel_batches.max(1),
            limits: BatchLimits {
                packets: o.batch_packets.max(1),
                bytes: o.batch_bytes.max(1),
            },
            budget: Arc::new(Budget::new(o.max_in_flight_bytes)),
            blob_budget: Arc::new(BlobBudget::new(o.max_blob_bytes)),
            fault: o.fail_writer_after_records.map(|n| {
                Arc::new(WriterFault {
                    remaining: AtomicU64::new(n),
                })
            }),
            registry,
            flow,
        }
    }

    /// Calls `progress` periodically until the reader signals its end.
    fn report_until_done(
        &self,
        done: &std::sync::mpsc::Receiver<()>,
        shared: &Shared,
        total: u64,
        progress: &mut dyn FnMut(&Progress),
    ) {
        let interval = self.options.progress_interval.max(Duration::from_millis(1));
        loop {
            progress(&self.progress_snapshot(shared, total, Phase::Reading));
            match done.recv_timeout(interval) {
                Err(RecvTimeoutError::Timeout) => {}
                Ok(()) | Err(RecvTimeoutError::Disconnected) => break,
            }
        }
    }

    fn run_threads(
        &self,
        sender: &StoreSender,
        shards: usize,
        progress: &mut dyn FnMut(&Progress),
    ) -> Result<Threads, String> {
        let source = self.source();
        let total = source.total_bytes();
        let shared = Shared::default();
        // Inventory findings (missing files, duplicates...) reach the first progress callback.
        shared.update(&source, 0);
        let parts = self.parts(shards);
        let capacity = parts.capacity;
        let limits = parts.limits;
        let budget = Arc::clone(&parts.budget);
        let end_ts = Arc::new(OnceLock::new());
        let (raw_tx, raw_rx) = sync_channel::<Batch>(capacity);
        let (done_tx, done_rx) = sync_channel::<()>(1);

        // Every spawned thread is joined explicitly below, whatever happens: no `?` leaves the
        // scope early, and joined panics do not propagate out of `thread::scope`.
        thread::scope(|s| {
            let mut failure: Option<String> = None;
            let spawn_err = |e: std::io::Error| format!("cannot start a thread: {e}");

            let mut shard_txs = Vec::with_capacity(shards);
            let mut shard_handles = Vec::with_capacity(shards);
            for index in 0..shards {
                let (tx, rx) = sync_channel::<Batch>(capacity);
                let setup = ShardSetup {
                    index,
                    table: FlowTable::new(parts.flow),
                    analyzers: parts.registry.build_shard(),
                    sender: sender.clone(),
                    max_records: self.options.record_batch,
                    max_record_bytes: self.options.record_batch_bytes,
                    fault: parts.fault.clone(),
                    end_ts: Arc::clone(&end_ts),
                    blobs_dir: parts.registry.config().blobs_dir.clone(),
                    blob_budget: Arc::clone(&parts.blob_budget),
                };
                match thread::Builder::new()
                    .name(format!("netsift-shard-{index}"))
                    .spawn_scoped(s, move || run_shard(&rx, setup))
                {
                    Ok(handle) => {
                        shard_txs.push(tx);
                        shard_handles.push(handle);
                    }
                    Err(e) => {
                        note(&mut failure, spawn_err(e));
                        break;
                    }
                }
            }

            // Decoder and reader only start when every shard is running.
            let mut decoder = None;
            let mut reader = None;
            if shard_handles.len() == shards {
                let decoder_budget = Arc::clone(&budget);
                match thread::Builder::new()
                    .name("netsift-decoder".into())
                    .spawn_scoped(s, move || {
                        run_decoder(&raw_rx, &shard_txs, &decoder_budget, limits)
                    }) {
                    Ok(handle) => decoder = Some(handle),
                    Err(e) => note(&mut failure, spawn_err(e)),
                }
            } else {
                drop(shard_txs);
                drop(raw_rx);
            }
            if decoder.is_some() {
                let setup = ReaderSetup {
                    tx: raw_tx,
                    shared: &shared,
                    cancel: self.cancel,
                    budget: Arc::clone(&budget),
                    limits,
                    end_ts: Arc::clone(&end_ts),
                };
                match thread::Builder::new()
                    .name("netsift-reader".into())
                    .spawn_scoped(s, move || {
                        let outcome = run_reader(source, setup);
                        drop(done_tx);
                        outcome
                    }) {
                    Ok(handle) => reader = Some(handle),
                    Err(e) => note(&mut failure, spawn_err(e)),
                }
            } else {
                drop(raw_tx);
                drop(done_tx);
            }

            if reader.is_some() {
                self.report_until_done(&done_rx, &shared, total, progress);
            }
            let reader = match reader.map(thread::ScopedJoinHandle::join) {
                Some(Ok(outcome)) => Some(outcome),
                Some(Err(_)) => {
                    note(&mut failure, "the reader thread panicked".to_owned());
                    None
                }
                None => None,
            };
            progress(&self.progress_snapshot(&shared, total, Phase::Finishing));

            join_rest(reader, decoder, shard_handles, failure)
        })
    }

    fn meta(
        &self,
        reader: &ReaderOutcome,
        stats: &[ChunkStats],
        shards: usize,
        state: SessionState,
    ) -> Vec<MetaRow> {
        let o = self.options;
        let selection = match o.selection {
            GroupSelection::Single => "single".to_owned(),
            GroupSelection::Index(i) => format!("index:{i}"),
            GroupSelection::MergeAll => "merge_all".to_owned(),
        };
        let analyzers: Vec<&str> = o.analyzers.ids().iter().map(|id| id.as_str()).collect();
        let first_ts = stats.iter().filter_map(|s| s.min_ts).min();
        let last_ts = stats.iter().filter_map(|s| s.max_ts).max();
        let captured: u64 = stats.iter().map(|s| s.captured_bytes).sum();
        let opt = |v: Option<i64>| v.map_or_else(String::new, |v| v.to_string());
        let pairs: Vec<(&str, String)> = vec![
            ("engine.version", env!("CARGO_PKG_VERSION").to_owned()),
            ("import.source", path_text(self.root)),
            ("import.group", self.group.label.clone()),
            ("import.group_kind", kind_name(self.group.kind).to_owned()),
            ("import.selection", selection),
            ("import.recursive", o.recursive.to_string()),
            ("import.shards", shards.to_string()),
            ("import.analyzers", analyzers.join(",")),
            // Read by the end-of-import pairing of the store (ADR-014).
            (
                netsift_store::dns::PAIR_WINDOW_META_KEY,
                o.analyzers.config().dns.pair_window_ns.to_string(),
            ),
            ("import.state", state.as_str().to_owned()),
            ("stats.packets", reader.packets.to_string()),
            ("stats.bytes_read", reader.source.bytes_read().to_string()),
            ("stats.captured_bytes", captured.to_string()),
            ("stats.chunks", self.group.members.len().to_string()),
            ("stats.chunks_read", self.group.active().count().to_string()),
            (
                "stats.anomalies",
                reader.source.anomalies().len().to_string(),
            ),
            ("stats.first_ts", opt(first_ts)),
            ("stats.last_ts", opt(last_ts)),
            (
                "stats.duration_ms",
                self.started.elapsed().as_millis().to_string(),
            ),
        ];
        pairs
            .into_iter()
            .map(|(k, v)| MetaRow {
                key: k.to_owned(),
                value: v,
            })
            .collect()
    }
}

fn path_text(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}
