//! Time ranges materialized for the aggregated views (P5.2b, ADR-030, `docs/specs/time-filter.md`,
//! « Agrégats précalculés »).
//!
//! Connections, Open Ports, Servers and Network read tables derived from the whole session:
//! conversations and traffic per host (written by the `connections` analyzer), open ports per host,
//! server roles and ranks, graph tables (end-of-import steps, ADR-014). Under a time range they are
//! derived again from the records of the range, by the code of those steps, into a **range
//! database**: a SQLite file that holds only these tables, under the same names and with the same
//! schema (copied from the session), plus a copy of `meta`. A view opens it as `main` with the
//! session attached as [`ATTACHED`]: an unqualified name finds the range table first and any other
//! table in the session, so the read queries of the views are unchanged.
//!
//! [`RangeCache`] builds the range database at the first request of a range (the request waits for
//! it, ADR-030), keeps the [`KEEP`] most recently used of a session, lets concurrent requests for a
//! range wait for one build, and interrupts a build when every request waiting for it is gone.
//! The file name carries a fingerprint of the session (schema, end-of-import steps, statistics,
//! version of the build): a migrated session gets new files, the old ones age out of the cache.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, SystemTime};

use rusqlite::Connection;

use crate::error::{Result, StoreError};
use crate::query::get_meta;
use crate::range::TimeRange;
use crate::session::{Session, open_read_only};

mod build;
mod fold;

pub use fold::MAX_LABELS;

/// Tables of a range database copied from the session schema (`meta` first): the same names and
/// columns as in the session, rows of the range.
pub const RANGE_TABLES: &[&str] = build::COPIED;

/// Range databases kept per session (least recently used evicted).
pub const KEEP: usize = 4;
/// Schema name of the session in the connection of a range database.
pub const ATTACHED: &str = "session";
/// Builds running at once over all sessions (each holds a page cache and sort files).
pub const MAX_BUILDS: usize = 2;
/// Bumped when the build changes what it writes: older range databases are no longer used.
const BUILD_VERSION: u32 = 1;
/// Extension of range databases.
const EXTENSION: &str = "db";
/// Suffix of a range database being built.
const PARTIAL: &str = "partial";
/// Age past which a partial file is left by a stopped process (a build writes continuously).
const STALE_PARTIAL: Duration = Duration::from_secs(3600);
/// How often a build checks whether its requests are gone.
const POLL: Duration = Duration::from_millis(50);
/// Attempts of [`RangeCache::open`] when the file it found disappears (evicted meanwhile) or a
/// build it waited for was interrupted.
const MAX_ATTEMPTS: usize = 4;

/// Cancellation flag of one request: set when its client is gone.
#[derive(Debug, Clone, Default)]
pub struct CancelFlag(Arc<AtomicBool>);

impl CancelFlag {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.0.store(true, Ordering::Relaxed);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

/// An opened range database: `main` holds the tables of the range, the session is attached.
#[derive(Debug)]
pub struct RangeView {
    conn: Connection,
    range: TimeRange,
}

impl RangeView {
    /// Connection to read the views from (read-only).
    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    /// The range of the tables, bounded to the captured period of the session.
    pub fn range(&self) -> TimeRange {
        self.range
    }

    fn open(file: &Path, session_db: &Path, range: TimeRange) -> Result<Self> {
        let conn = open_read_only(file)?;
        attach(&conn, session_db)?;
        Ok(Self { conn, range })
    }
}

/// True when `conn` reads a range database (its `main` is one).
pub fn is_range_db(conn: &Connection) -> Result<bool> {
    Ok(conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM main.sqlite_master WHERE type = 'table' AND name = 'range_meta')",
        [],
        |r| r.get(0),
    )?)
}

/// Attaches the session read-only under [`ATTACHED`] (URI with `mode=ro`: the build connection
/// is writable, the session must never be).
fn attach(conn: &Connection, session_db: &Path) -> Result<()> {
    conn.execute(
        &format!("ATTACH DATABASE ?1 AS {ATTACHED}"),
        [sqlite_uri(session_db)],
    )?;
    Ok(())
}

/// `file:` URI of `path`, read-only: reserved characters percent-encoded, Windows separators and
/// drive letters turned into a URI path.
fn sqlite_uri(path: &Path) -> String {
    // A URI path is absolute: a relative data directory (dev, benchmark) is resolved first.
    let path = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
    let text = path.to_string_lossy().replace('\\', "/");
    let mut uri = String::from("file:");
    if !text.starts_with('/') {
        uri.push('/');
    }
    for b in text.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'/' | b'-' | b'_' | b'.' | b'~' | b':') {
            uri.push(char::from(b));
        } else {
            let _ = write!(uri, "%{b:02X}");
        }
    }
    uri.push_str("?mode=ro");
    uri
}

/// What a finished build left for the requests waiting for it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Outcome {
    Ready,
    /// Every request was gone: interrupted, nothing written.
    Cancelled,
    Failed(String),
}

#[derive(Debug, Default)]
struct FlightState {
    waiters: Vec<CancelFlag>,
    outcome: Option<Outcome>,
}

/// One build and the requests waiting for it.
#[derive(Debug, Default)]
struct Flight {
    state: Mutex<FlightState>,
    done: Condvar,
}

impl Flight {
    fn lock(&self) -> MutexGuard<'_, FlightState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// True when every request waiting for the build is gone.
    fn abandoned(&self) -> bool {
        self.lock().waiters.iter().all(CancelFlag::is_cancelled)
    }

    fn finish(&self, outcome: Outcome) {
        self.lock().outcome = Some(outcome);
        self.done.notify_all();
    }

    /// Waits for the outcome; `None` when `cancel` is set first.
    fn wait(&self, cancel: &CancelFlag) -> Option<Outcome> {
        let mut state = self.lock();
        loop {
            if let Some(outcome) = &state.outcome {
                return Some(outcome.clone());
            }
            if cancel.is_cancelled() {
                return None;
            }
            state = self
                .done
                .wait_timeout(state, POLL)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }
}

/// Counting semaphore of the builds ([`MAX_BUILDS`]).
#[derive(Debug, Default)]
struct Gate {
    running: Mutex<usize>,
    freed: Condvar,
}

struct Slot<'a>(&'a Gate);

impl Drop for Slot<'_> {
    fn drop(&mut self) {
        let mut running = self
            .0
            .running
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        *running = running.saturating_sub(1);
        self.0.freed.notify_one();
    }
}

impl Gate {
    fn enter(&self, abandoned: &dyn Fn() -> bool) -> Result<Slot<'_>> {
        let mut running = self.running.lock().unwrap_or_else(PoisonError::into_inner);
        while *running >= MAX_BUILDS {
            if abandoned() {
                return Err(StoreError::Cancelled);
            }
            running = self
                .freed
                .wait_timeout(running, POLL)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        *running += 1;
        Ok(Slot(self))
    }
}

/// Range databases of the sessions of a process (see the module documentation).
#[derive(Debug, Default)]
pub struct RangeCache {
    flights: Mutex<HashMap<PathBuf, Arc<Flight>>>,
    gate: Gate,
    builds: AtomicU64,
}

impl RangeCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Builds started since the creation of the cache (tests, diagnostics).
    pub fn builds(&self) -> u64 {
        self.builds.load(Ordering::Relaxed)
    }

    /// The range database of `range` over `session`, from `dir` (one directory per session),
    /// built first when missing: the call then lasts as long as the build. Concurrent calls for
    /// the same range share one build. [`StoreError::Cancelled`] when `cancel` is set before the
    /// database is ready; the build stops when every caller waiting for it is cancelled.
    pub fn open(
        &self,
        session: &Session,
        dir: &Path,
        range: TimeRange,
        cancel: &CancelFlag,
    ) -> Result<RangeView> {
        let conn = session.conn();
        let range = bounded(conn, range)?;
        let file = dir.join(file_name(range, fingerprint(conn)?));
        let session_db = session.db_path();
        for _ in 0..MAX_ATTEMPTS {
            if cancel.is_cancelled() {
                return Err(StoreError::Cancelled);
            }
            if file.is_file() {
                match RangeView::open(&file, &session_db, range) {
                    Ok(view) => {
                        touch(&file);
                        return Ok(view);
                    }
                    // Evicted between the check and the opening: build it again.
                    Err(_) if !file.is_file() => continue,
                    Err(e) => return Err(e),
                }
            }
            let Some((flight, builder)) = self.join(&file, cancel) else {
                // Published between the check above and the lock: open it.
                continue;
            };
            if builder {
                // Even if the build panics, the waiters are released and the flight removed.
                let mut guard = BuildGuard {
                    cache: self,
                    file: &file,
                    flight: &flight,
                    outcome: None,
                };
                let result = self.build(&session_db, dir, &file, range, &flight);
                guard.outcome = Some(match &result {
                    Ok(()) => Outcome::Ready,
                    Err(StoreError::Cancelled) => Outcome::Cancelled,
                    Err(e) => Outcome::Failed(e.to_string()),
                });
                drop(guard);
                result?;
            } else {
                match flight.wait(cancel) {
                    // Ready: open it; cancelled while this caller still waits: build it again.
                    Some(Outcome::Ready | Outcome::Cancelled) => {}
                    Some(Outcome::Failed(reason)) => return Err(StoreError::RangeBuild(reason)),
                    None => return Err(StoreError::Cancelled),
                }
            }
        }
        Err(StoreError::RangeBuild(
            "the range database kept disappearing".to_owned(),
        ))
    }

    fn lock_flights(&self) -> MutexGuard<'_, HashMap<PathBuf, Arc<Flight>>> {
        self.flights.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Registers `cancel` as waiting for the build of `file`: `true` when the caller must build it;
    /// `None` when the file is there (a build published it after the caller looked: the rename
    /// happens before its flight is removed, both seen under the lock).
    fn join(&self, file: &Path, cancel: &CancelFlag) -> Option<(Arc<Flight>, bool)> {
        let mut flights = self.lock_flights();
        if let Some(flight) = flights.get(file) {
            flight.lock().waiters.push(cancel.clone());
            return Some((Arc::clone(flight), false));
        }
        if file.is_file() {
            return None;
        }
        let flight = Arc::new(Flight::default());
        flight.lock().waiters.push(cancel.clone());
        flights.insert(file.to_path_buf(), Arc::clone(&flight));
        Some((flight, true))
    }

    fn build(
        &self,
        session_db: &Path,
        dir: &Path,
        file: &Path,
        range: TimeRange,
        flight: &Flight,
    ) -> Result<()> {
        let abandoned = || flight.abandoned();
        let _slot = self.gate.enter(&abandoned)?;
        self.builds.fetch_add(1, Ordering::Relaxed);
        // Never `create_dir_all`: a session deleted meanwhile must not get its directory back.
        match std::fs::create_dir(dir) {
            Err(e) if e.kind() != std::io::ErrorKind::AlreadyExists => {
                return Err(StoreError::io(dir, e));
            }
            _ => {}
        }
        // A name of this build only: another process on the same data directory may build the
        // same range (its partial file is never touched here, except once stale).
        let partial = partial_path(file);
        let started = std::time::Instant::now();
        match build::build(session_db, &partial, range, &abandoned) {
            Ok(()) => {
                std::fs::rename(&partial, file).map_err(|e| StoreError::io(file, e))?;
                tracing::debug!(
                    file = %file.display(),
                    elapsed_ms = started.elapsed().as_millis(),
                    "range database built"
                );
                Self::evict(dir);
                Ok(())
            }
            Err(e) => {
                let _ = std::fs::remove_file(&partial);
                Err(e)
            }
        }
    }

    /// Keeps the [`KEEP`] most recently used range databases of `dir`; removes partial files of
    /// builds that are not running (an interrupted process). Best effort: a file still open
    /// elsewhere (Windows) stays until the next eviction.
    fn evict(dir: &Path) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        let mut ready: Vec<(SystemTime, PathBuf)> = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            match path.extension().and_then(|e| e.to_str()) {
                Some(EXTENSION) => {
                    let used = entry
                        .metadata()
                        .and_then(|m| m.modified())
                        .unwrap_or(SystemTime::UNIX_EPOCH);
                    ready.push((used, path));
                }
                // Left by a process stopped during a build: only once stale, since a partial file
                // of a running build (this process or another) is written continuously.
                Some(PARTIAL)
                    if entry
                        .metadata()
                        .and_then(|m| m.modified())
                        .ok()
                        .and_then(|m| m.elapsed().ok())
                        .is_some_and(|age| age >= STALE_PARTIAL) =>
                {
                    let _ = std::fs::remove_file(&path);
                }
                _ => {}
            }
        }
        ready.sort_by(|a, b| b.cmp(a));
        for (_, path) in ready.into_iter().skip(KEEP) {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// Releases the waiters of a build and removes its flight when the build ends, panic included
/// ([`Outcome::Failed`] when no outcome was set).
struct BuildGuard<'a> {
    cache: &'a RangeCache,
    file: &'a Path,
    flight: &'a Flight,
    outcome: Option<Outcome>,
}

impl Drop for BuildGuard<'_> {
    fn drop(&mut self) {
        self.cache.lock_flights().remove(self.file);
        let outcome = self
            .outcome
            .take()
            .unwrap_or_else(|| Outcome::Failed("the build stopped".to_owned()));
        self.flight.finish(outcome);
    }
}

/// `<range>.<pid>-<random>.db.partial`: unique per build, never confused with another process's.
fn partial_path(file: &Path) -> PathBuf {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u128(
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos()),
    );
    file.with_extension(format!(
        "{}-{:08x}.{EXTENSION}.{PARTIAL}",
        std::process::id(),
        h.finish() & 0xffff_ffff
    ))
}

/// Marks a range database as just used (its modification time orders the eviction).
fn touch(file: &Path) {
    if let Ok(f) = std::fs::File::options().write(true).open(file) {
        let _ = f.set_modified(SystemTime::now());
    }
}

/// `range` bounded to the captured period of the session (`stats.first_ts` / `stats.last_ts`):
/// every timestamp of the session lies inside, so the answers are the same, and ranges that only
/// differ outside the session share one database. A range outside the session becomes the empty
/// range just after it. Unchanged without statistics.
fn bounded(conn: &Connection, range: TimeRange) -> Result<TimeRange> {
    let bound = |key: &str| -> Result<Option<i64>> {
        Ok(get_meta(conn, key)?.and_then(|v| v.parse::<i64>().ok()))
    };
    let (Some(first), Some(last)) = (bound("stats.first_ts")?, bound("stats.last_ts")?) else {
        return Ok(range);
    };
    let end = last.saturating_add(1);
    let from = range.from_ns().max(first);
    let to = range.to_ns().min(end);
    Ok(TimeRange::new(from, to)
        .filter(|r| r.from_ns() < r.to_ns())
        .or_else(|| TimeRange::new(end, end))
        .unwrap_or(range))
}

/// Hash of what the content of a range database depends on, besides its range.
fn fingerprint(conn: &Connection) -> Result<u64> {
    let schema: String = conn.query_row(
        "SELECT count(*) || ':' || coalesce(max(version), 0) FROM schema_migrations",
        [],
        |r| r.get(0),
    )?;
    let steps = crate::finalize::finalizers_done(conn)?.join(",");
    let mut text = format!("{BUILD_VERSION}|{schema}|{steps}");
    for key in [
        "stats.first_ts",
        "stats.last_ts",
        "stats.packets",
        "stats.flows",
    ] {
        text.push('|');
        text.push_str(&get_meta(conn, key)?.unwrap_or_default());
    }
    Ok(fnv1a(text.as_bytes()))
}

/// 64-bit FNV-1a: stable across builds and platforms (a cache key, not a security measure).
fn fnv1a(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |h, b| {
        (h ^ u64::from(*b)).wrapping_mul(0x0100_0000_01b3)
    })
}

fn file_name(range: TimeRange, fingerprint: u64) -> String {
    format!(
        "{}_{}_{fingerprint:016x}.{EXTENSION}",
        range.from_ns(),
        range.to_ns()
    )
}

#[cfg(test)]
mod tests;
