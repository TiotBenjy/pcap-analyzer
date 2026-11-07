//! Batched writer: a single thread owns the session connection and commits records in
//! transactions of ~`batch_rows` rows or every `flush_interval`, whichever comes first.
//!
//! Producers (decoder, flow shards) send through cloneable [`StoreSender`]s over a bounded
//! channel, so a slow disk applies backpressure instead of growing memory.

use std::collections::BTreeMap;
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TryRecvError, sync_channel};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use rusqlite::Connection;

use crate::error::{Result, StoreError};
use crate::records::{StoreRecord, is_row_level};
use crate::session::Session;

/// Tuning of the writer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriterConfig {
    /// Commit once this many rows are pending.
    pub batch_rows: usize,
    /// Commit pending rows at the latest this long after the first one of the batch.
    pub flush_interval: Duration,
    /// Capacity of the channel, in messages (a message is one record or one `Vec`).
    pub channel_capacity: usize,
}

impl Default for WriterConfig {
    fn default() -> Self {
        Self {
            batch_rows: 50_000,
            flush_interval: Duration::from_millis(250),
            channel_capacity: 4096,
        }
    }
}

/// Counters returned by [`StoreWriter::finish`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WriterStats {
    /// Rows written per record kind ([`StoreRecord::kind`]).
    pub rows: BTreeMap<&'static str, u64>,
    /// Records rejected one by one (invalid value, constraint violation), per kind. They do
    /// not abort the batch; the rest of the import goes on.
    pub rejected: BTreeMap<&'static str, u64>,
    /// Committed transactions.
    pub batches: u64,
}

impl WriterStats {
    /// Total rows written.
    pub fn total_rows(&self) -> u64 {
        self.rows.values().sum()
    }

    /// Rows written for one kind.
    pub fn rows_of(&self, kind: &str) -> u64 {
        self.rows.get(kind).copied().unwrap_or(0)
    }

    /// Total records rejected.
    pub fn total_rejected(&self) -> u64 {
        self.rejected.values().sum()
    }
}

enum Msg {
    One(StoreRecord),
    Many(Vec<StoreRecord>),
    Finish,
}

/// Cloneable handle used by producers to feed the writer.
#[derive(Debug, Clone)]
pub struct StoreSender {
    tx: SyncSender<Msg>,
}

impl std::fmt::Debug for Msg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::One(_) => f.write_str("One"),
            Self::Many(v) => write!(f, "Many({})", v.len()),
            Self::Finish => f.write_str("Finish"),
        }
    }
}

impl StoreSender {
    /// Sends one record, blocking while the channel is full. Fails with
    /// [`StoreError::WriterClosed`] once the writer has stopped (the cause is reported by
    /// [`StoreWriter::finish`]).
    pub fn send(&self, record: StoreRecord) -> Result<()> {
        self.tx
            .send(Msg::One(record))
            .map_err(|_| StoreError::WriterClosed)
    }

    /// Sends several records as one message (cheaper for producers that buffer).
    pub fn send_batch(&self, records: Vec<StoreRecord>) -> Result<()> {
        if records.is_empty() {
            return Ok(());
        }
        self.tx
            .send(Msg::Many(records))
            .map_err(|_| StoreError::WriterClosed)
    }
}

/// Owner of the writer thread.
#[derive(Debug)]
pub struct StoreWriter {
    sender: StoreSender,
    handle: JoinHandle<Result<WriterStats>>,
}

impl StoreWriter {
    /// Moves the session connection to a new writer thread.
    pub fn spawn(session: Session, config: WriterConfig) -> Result<Self> {
        let conn = session.into_conn();
        let (tx, rx) = sync_channel(config.channel_capacity.max(1));
        let handle = std::thread::Builder::new()
            .name("netsift-store-writer".into())
            .spawn(move || run(conn, &rx, config))
            .map_err(|e| StoreError::io("<writer thread>", e))?;
        Ok(Self {
            sender: StoreSender { tx },
            handle,
        })
    }

    /// A new producer handle.
    pub fn sender(&self) -> StoreSender {
        self.sender.clone()
    }

    /// Sends one record (see [`StoreSender::send`]).
    pub fn send(&self, record: StoreRecord) -> Result<()> {
        self.sender.send(record)
    }

    /// Sends several records (see [`StoreSender::send_batch`]).
    pub fn send_batch(&self, records: Vec<StoreRecord>) -> Result<()> {
        self.sender.send_batch(records)
    }

    /// Writes everything still queued, commits, closes the connection and returns the
    /// statistics, or the first error met by the writer. Producers must be done: records
    /// sent through other senders after this call are dropped.
    pub fn finish(self) -> Result<WriterStats> {
        // If the thread already stopped on an error, the send fails and join reports it.
        let _ = self.sender.tx.send(Msg::Finish);
        drop(self.sender);
        self.handle.join().map_err(|_| StoreError::WriterPanicked)?
    }
}

struct Batch<'c> {
    conn: &'c Connection,
    config: WriterConfig,
    pending: usize,
    deadline: Option<Instant>,
    stats: WriterStats,
}

impl Batch<'_> {
    fn write(&mut self, record: &StoreRecord) -> Result<()> {
        if self.deadline.is_none() {
            self.conn.execute_batch("BEGIN")?;
            self.deadline = Some(Instant::now() + self.config.flush_interval);
        }
        // A failed statement only rolls itself back: the transaction stays usable.
        match record.insert(self.conn) {
            Ok(()) => *self.stats.rows.entry(record.kind()).or_insert(0) += 1,
            Err(e) if is_row_level(&e) => {
                *self.stats.rejected.entry(record.kind()).or_insert(0) += 1;
            }
            Err(e) => return Err(e),
        }
        self.pending += 1;
        if self.pending >= self.config.batch_rows {
            self.commit()?;
        }
        Ok(())
    }

    fn commit(&mut self) -> Result<()> {
        if self.deadline.take().is_some() {
            self.conn.execute_batch("COMMIT")?;
            self.stats.batches += 1;
        }
        self.pending = 0;
        Ok(())
    }

    fn handle(&mut self, msg: Msg) -> Result<bool> {
        match msg {
            Msg::One(r) => self.write(&r)?,
            Msg::Many(v) => {
                for r in &v {
                    self.write(r)?;
                }
            }
            Msg::Finish => return Ok(false),
        }
        if self.deadline.is_some_and(|d| Instant::now() >= d) {
            self.commit()?;
        }
        Ok(true)
    }
}

/// Prepared statements kept per connection: core tables plus every analyzer's upserts.
const STATEMENT_CACHE: usize = 128;

fn run(conn: Connection, rx: &Receiver<Msg>, config: WriterConfig) -> Result<WriterStats> {
    conn.set_prepared_statement_cache_capacity(STATEMENT_CACHE);
    let mut batch = Batch {
        conn: &conn,
        config: WriterConfig {
            batch_rows: config.batch_rows.max(1),
            ..config
        },
        pending: 0,
        deadline: None,
        stats: WriterStats::default(),
    };
    let result = event_loop(&mut batch, rx);
    if result.is_err() && !conn.is_autocommit() {
        // Keep the database consistent; the original error is what matters.
        let _ = conn.execute_batch("ROLLBACK");
    }
    result?;
    // Planner statistics for the read side, then fold the WAL back into the main file
    // (best effort: concurrent readers may prevent a full checkpoint).
    conn.execute_batch("PRAGMA optimize")?;
    let _ = conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()));
    let stats = std::mem::take(&mut batch.stats);
    drop(batch);
    conn.close().map_err(|(_, e)| StoreError::Sqlite(e))?;
    Ok(stats)
}

fn event_loop(batch: &mut Batch<'_>, rx: &Receiver<Msg>) -> Result<()> {
    loop {
        let msg = match batch.deadline {
            None => match rx.recv() {
                Ok(m) => m,
                Err(_) => break, // every sender dropped
            },
            Some(deadline) => {
                let wait = deadline.saturating_duration_since(Instant::now());
                match rx.recv_timeout(wait) {
                    Ok(m) => m,
                    Err(RecvTimeoutError::Timeout) => {
                        batch.commit()?;
                        continue;
                    }
                    Err(RecvTimeoutError::Disconnected) => break,
                }
            }
        };
        if !batch.handle(msg)? {
            // Finish: drain what was queued before it, best effort.
            loop {
                match rx.try_recv() {
                    Ok(Msg::Finish) => {}
                    Ok(m) => {
                        batch.handle(m)?;
                    }
                    Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
                }
            }
            break;
        }
    }
    batch.commit()
}
