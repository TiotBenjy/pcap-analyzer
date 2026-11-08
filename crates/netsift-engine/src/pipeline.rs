//! Threads of the pipeline (docs/ARCHITECTURE.md, "Modèle d'exécution du pipeline"):
//!
//! ```text
//! reader (ChunkSetSource) --batches--> decoder (decode + shard_hash) --batches--> N shards
//!                                                                      (FlowTable + analyzers)
//!                                                                              |
//!                                                                   records    v
//!                                                                     store writer thread
//! ```
//!
//! Memory is bounded in bytes, not only in messages: every captured byte in flight between the
//! reader and the shards is accounted in a shared [`Budget`]; the reader blocks while the budget
//! is exhausted. Batches are cut at a packet count **or** a byte size, whichever comes first,
//! and record batches sent to the writer likewise.
//!
//! The decoder is the only producer of each shard channel, so packets of a flow keep their
//! capture order. Shutdown cascades: the reader stops (end of input, cancellation or downstream
//! failure) and drops its sender, the decoder flushes and drops the shard senders, each shard
//! flushes its flows and analyzers. A panicking analyzer is disabled on its shard (reported as
//! an `analyzer_panicked` anomaly); the import goes on.

use std::any::Any;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender};
use std::sync::{Arc, Condvar, Mutex, OnceLock, PoisonError};
use std::time::Duration;

use netsift_analyze::dissect::{Decoded, decode};
use netsift_analyze::flow::{
    Direction, FlowCtx, FlowSink, FlowTable, PacketCtx, StreamCtx, shard_hash,
};
use netsift_analyze::{Analyzer, AnalyzerId, Record, RecordSink};
use netsift_capture::chunkset::{ChunkSetSource, ChunkStats};
use netsift_capture::{PacketSource, RawPacket};
use netsift_store::{AnomalyRow, StoreError, StoreRecord, StoreSender};

use crate::options::CancelToken;
use crate::translate::{anomaly_row, approx_size, to_store};

/// Sentinel of [`Shared::chunk`]: no chunk open.
const NO_CHUNK: u32 = u32::MAX;

/// Anomaly code of a disabled analyzer.
pub const ANALYZER_PANICKED: &str = "analyzer_panicked";

/// Maximum length kept from a panic message.
const MAX_PANIC_MESSAGE: usize = 512;

/// Counters updated by the reader, read by the progress loop.
#[derive(Debug)]
pub(crate) struct Shared {
    pub bytes_read: AtomicU64,
    pub packets: AtomicU64,
    pub chunk: AtomicU32,
    anomalies: Mutex<AnomalyLog>,
}

/// Continuity anomalies of the source not yet handed to the progress callback.
#[derive(Debug, Default)]
struct AnomalyLog {
    /// Anomalies of the source already converted.
    seen: usize,
    pending: Vec<AnomalyRow>,
}

impl Default for Shared {
    fn default() -> Self {
        Self {
            bytes_read: AtomicU64::new(0),
            packets: AtomicU64::new(0),
            chunk: AtomicU32::new(NO_CHUNK),
            anomalies: Mutex::new(AnomalyLog::default()),
        }
    }
}

impl Shared {
    pub fn chunk(&self) -> Option<u32> {
        Some(self.chunk.load(Ordering::Relaxed)).filter(|&c| c != NO_CHUNK)
    }

    pub fn update(&self, source: &ChunkSetSource, packets: u64) {
        self.bytes_read
            .store(source.bytes_read(), Ordering::Relaxed);
        self.packets.store(packets, Ordering::Relaxed);
        let chunk = source.open_chunks().last().copied().unwrap_or(NO_CHUNK);
        self.chunk.store(chunk, Ordering::Relaxed);
        let found = source.anomalies();
        let mut log = self
            .anomalies
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if found.len() > log.seen {
            // Rare (bounded by MAX_ANOMALIES): the stats copy only happens on new findings.
            let stats: Vec<ChunkStats> = source.chunk_stats().cloned().collect();
            let fresh: Vec<AnomalyRow> = found
                .iter()
                .skip(log.seen)
                .map(|a| anomaly_row(a, &stats))
                .collect();
            log.pending.extend(fresh);
            log.seen = found.len();
        }
    }

    /// Anomalies found since the previous call.
    pub fn take_anomalies(&self) -> Vec<AnomalyRow> {
        let mut log = self
            .anomalies
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        std::mem::take(&mut log.pending)
    }
}

/// Captured bytes in flight between the reader and the shards.
#[derive(Debug)]
pub(crate) struct Budget {
    used: Mutex<u64>,
    freed: Condvar,
    limit: u64,
}

impl Budget {
    pub fn new(limit: u64) -> Self {
        Self {
            used: Mutex::new(0),
            freed: Condvar::new(),
            limit: limit.max(1),
        }
    }

    /// Reserves `n` bytes, blocking while the budget is exhausted. A packet larger than the
    /// whole budget is admitted once nothing else is in flight. Returns `false` if the import
    /// was cancelled while waiting.
    fn acquire(&self, n: u64, cancel: &CancelToken) -> bool {
        let mut used = self
            .used
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while *used > 0 && used.saturating_add(n) > self.limit {
            if cancel.is_cancelled() {
                return false;
            }
            used = self
                .freed
                .wait_timeout(used, Duration::from_millis(50))
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .0;
        }
        *used = used.saturating_add(n);
        true
    }

    fn release(&self, n: u64) {
        if n == 0 {
            return;
        }
        let mut used = self
            .used
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *used = used.saturating_sub(n);
        drop(used);
        self.freed.notify_all();
    }

    #[cfg(test)]
    fn used(&self) -> u64 {
        *self
            .used
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// One packet and its global index in reading order (0-based).
pub(crate) struct Frame {
    pub index: u64,
    pub packet: RawPacket,
}

fn frame_bytes(frame: &Frame) -> u64 {
    u64::try_from(frame.packet.data.len()).unwrap_or(u64::MAX)
}

/// Packets travelling together on a channel. Their bytes return to the budget when the batch
/// is dropped (processed, or discarded by a failing thread), so the budget never leaks.
pub(crate) struct Batch {
    frames: Vec<Frame>,
    bytes: u64,
    budget: Arc<Budget>,
}

impl Batch {
    fn new(budget: &Arc<Budget>) -> Self {
        Self {
            frames: Vec::new(),
            bytes: 0,
            budget: Arc::clone(budget),
        }
    }

    /// Adds a frame whose bytes are already reserved in the budget.
    fn push(&mut self, frame: Frame) {
        self.bytes = self.bytes.saturating_add(frame_bytes(&frame));
        self.frames.push(frame);
    }

    fn len(&self) -> usize {
        self.frames.len()
    }

    fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }

    fn is_full(&self, limits: BatchLimits) -> bool {
        self.frames.len() >= limits.packets || self.bytes >= limits.bytes
    }

    /// Moves the frames out; their bytes stay reserved and travel with them (see
    /// [`Batch::push`] on the receiving batch).
    fn take(&mut self) -> Vec<Frame> {
        self.bytes = 0;
        std::mem::take(&mut self.frames)
    }
}

impl Drop for Batch {
    fn drop(&mut self) {
        self.budget.release(self.bytes);
    }
}

/// When a batch is sent: at `packets` packets or `bytes` captured bytes.
#[derive(Debug, Clone, Copy)]
pub(crate) struct BatchLimits {
    pub packets: usize,
    pub bytes: u64,
}

/// End state of the reader thread.
pub(crate) struct ReaderOutcome {
    pub source: ChunkSetSource,
    pub packets: u64,
    /// Reading stopped because of the cancellation token.
    pub cancelled: bool,
    /// Reading stopped because the decoder is gone (a downstream thread failed).
    pub downstream_closed: bool,
    /// Error returned by the source (not expected: chunk errors become anomalies).
    pub error: Option<String>,
}

pub(crate) struct ReaderSetup<'a> {
    pub tx: SyncSender<Batch>,
    pub shared: &'a Shared,
    pub cancel: &'a CancelToken,
    pub budget: Arc<Budget>,
    pub limits: BatchLimits,
    /// Set to the latest packet time read, before the reader closes its channel.
    pub end_ts: Arc<OnceLock<i64>>,
}

pub(crate) fn run_reader(mut source: ChunkSetSource, setup: ReaderSetup<'_>) -> ReaderOutcome {
    let ReaderSetup {
        tx,
        shared,
        cancel,
        budget,
        limits,
        end_ts,
    } = setup;
    let mut last_ts: Option<i64> = None;
    let mut batch = Batch::new(&budget);
    let mut packets = 0u64;
    let mut cancelled = false;
    let mut downstream_closed = false;
    let mut error = None;
    loop {
        // Checked before every packet: at most one packet is read after a cancellation.
        if cancel.is_cancelled() {
            cancelled = true;
            break;
        }
        match source.next_packet() {
            Ok(Some(packet)) => {
                let size = u64::try_from(packet.data.len()).unwrap_or(u64::MAX);
                last_ts = Some(last_ts.map_or(packet.ts_ns, |t| t.max(packet.ts_ns)));
                if !budget.acquire(size, cancel) {
                    // Cancelled while waiting: this packet is not analyzed.
                    cancelled = true;
                    break;
                }
                batch.push(Frame {
                    index: packets,
                    packet,
                });
                packets += 1;
                if batch.is_full(limits) {
                    shared.update(&source, packets);
                    let full = std::mem::replace(&mut batch, Batch::new(&budget));
                    if tx.send(full).is_err() {
                        downstream_closed = true;
                        break;
                    }
                }
            }
            Ok(None) => break,
            Err(e) => {
                error = Some(e.to_string());
                break;
            }
        }
    }
    // Published before the channel closes: shards read it once their input ends.
    if let Some(ts) = last_ts {
        let _ = end_ts.set(ts);
    }
    if !batch.is_empty() && !downstream_closed && tx.send(batch).is_err() {
        downstream_closed = true;
    }
    drop(tx);
    shared.update(&source, packets);
    ReaderOutcome {
        source,
        packets,
        cancelled,
        downstream_closed,
        error,
    }
}

/// Decodes each packet to route it to its shard. Returns `false` if a shard is gone.
pub(crate) fn run_decoder(
    rx: &Receiver<Batch>,
    shards: &[SyncSender<Batch>],
    budget: &Arc<Budget>,
    limits: BatchLimits,
) -> bool {
    let n = u64::try_from(shards.len().max(1)).unwrap_or(1);
    let mut pending: Vec<Batch> = shards.iter().map(|_| Batch::new(budget)).collect();
    for mut input in rx {
        for frame in input.take() {
            let hash = shard_hash(&decode(frame.packet.linktype, &frame.packet.data));
            let index = usize::try_from(hash % n).unwrap_or(0);
            let (Some(buf), Some(tx)) = (pending.get_mut(index), shards.get(index)) else {
                // Unreachable (index < n); the frame's bytes are released with it.
                budget.release(frame_bytes(&frame));
                continue;
            };
            buf.push(frame);
            if buf.is_full(limits) {
                let full = std::mem::replace(buf, Batch::new(budget));
                if tx.send(full).is_err() {
                    return false;
                }
            }
        }
    }
    for (buf, tx) in pending.into_iter().zip(shards) {
        if !buf.is_empty() && tx.send(buf).is_err() {
            return false;
        }
    }
    true
}

/// Test hook simulating a writer failure after a number of records (shared by all shards).
#[derive(Debug)]
pub(crate) struct WriterFault {
    pub remaining: AtomicU64,
}

/// Buffers translated records and sends them to the writer in batches bounded in count and
/// approximate size. After a writer error, records are dropped and the error is reported once
/// the shard is done.
struct WriterSink {
    sender: StoreSender,
    buf: Vec<StoreRecord>,
    buf_bytes: usize,
    max_records: usize,
    max_bytes: usize,
    error: Option<StoreError>,
    fault: Option<Arc<WriterFault>>,
}

impl WriterSink {
    fn push(&mut self, record: StoreRecord) {
        if self.error.is_some() {
            return;
        }
        self.buf_bytes = self.buf_bytes.saturating_add(approx_size(&record));
        self.buf.push(record);
        if self.buf.len() >= self.max_records || self.buf_bytes >= self.max_bytes {
            self.flush();
        }
    }

    fn flush(&mut self) {
        let batch = std::mem::take(&mut self.buf);
        self.buf_bytes = 0;
        if batch.is_empty() || self.error.is_some() {
            return;
        }
        if let Some(fault) = &self.fault {
            let n = u64::try_from(batch.len()).unwrap_or(u64::MAX);
            let accepted = fault
                .remaining
                .try_update(Ordering::SeqCst, Ordering::SeqCst, |r| r.checked_sub(n))
                .is_ok();
            if !accepted {
                self.error = Some(StoreError::WriterClosed);
                return;
            }
        }
        if let Err(e) = self.sender.send_batch(batch) {
            self.error = Some(e);
        }
    }
}

impl RecordSink for WriterSink {
    fn emit(&mut self, record: Record) {
        self.push(to_store(record));
    }
}

/// One analyzer of a shard; disabled after a panic.
struct Slot {
    analyzer: Box<dyn Analyzer>,
    id: AnalyzerId,
    enabled: bool,
}

fn panic_message(payload: &(dyn Any + Send)) -> String {
    let text = payload
        .downcast_ref::<&str>()
        .map(|s| (*s).to_owned())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "non-string panic payload".to_owned());
    match text.char_indices().nth(MAX_PANIC_MESSAGE) {
        Some((cut, _)) => text.get(..cut).unwrap_or_default().to_owned(),
        None => text,
    }
}

/// Adapter from the flow layer events to the analyzers of a shard.
struct Fanout<'a> {
    slots: &'a mut [Slot],
    out: &'a mut WriterSink,
    shard: usize,
    /// Analyzers disabled on this shard.
    panicked: &'a mut u64,
}

impl Fanout<'_> {
    /// Calls `f` on every enabled analyzer, isolating panics.
    fn each(
        &mut self,
        callback: &'static str,
        at: (Option<i64>, Option<u32>),
        mut f: impl FnMut(&mut dyn Analyzer, &mut WriterSink),
    ) {
        for slot in self.slots.iter_mut().filter(|s| s.enabled) {
            let out = &mut *self.out;
            let analyzer = slot.analyzer.as_mut();
            let result = catch_unwind(AssertUnwindSafe(|| f(analyzer, out)));
            if let Err(payload) = result {
                slot.enabled = false;
                *self.panicked += 1;
                let message = panic_message(payload.as_ref());
                tracing::error!(
                    analyzer = %slot.id,
                    shard = self.shard,
                    callback,
                    "analyzer panicked and was disabled on this shard: {message}"
                );
                self.out.push(StoreRecord::Anomaly(AnomalyRow {
                    kind: ANALYZER_PANICKED.to_owned(),
                    chunk_id: at.1,
                    ts: at.0,
                    detail: serde_json::json!({
                        "analyzer": slot.id.as_str(),
                        "shard": self.shard,
                        "callback": callback,
                        "message": message,
                    }),
                }));
            }
        }
    }
}

impl FlowSink for Fanout<'_> {
    fn on_packet(&mut self, ctx: &PacketCtx, pkt: &Decoded<'_>) {
        self.each(
            "on_packet",
            (Some(ctx.ts_ns), Some(ctx.chunk_id)),
            |a, out| a.on_packet(ctx, pkt, out),
        );
    }

    fn on_stream(&mut self, ctx: &StreamCtx, dir: Direction, data: &[u8]) {
        self.each(
            "on_stream",
            (Some(ctx.ts_ns), Some(ctx.chunk_id)),
            |a, out| a.on_stream(ctx, dir, data, out),
        );
    }

    fn on_flow_end(&mut self, ctx: &FlowCtx) {
        self.each("on_flow_end", (Some(ctx.last_ts_ns), None), |a, out| {
            a.on_flow_end(ctx, out);
        });
    }
}

/// Result of one shard.
#[derive(Debug, Default)]
pub(crate) struct ShardOutcome {
    /// Packets processed by the shard.
    pub packets: u64,
    /// Analyzers disabled after a panic.
    pub panicked: u64,
}

pub(crate) struct ShardSetup {
    pub index: usize,
    pub table: FlowTable,
    pub analyzers: Vec<Box<dyn Analyzer>>,
    pub sender: StoreSender,
    pub max_records: usize,
    pub max_record_bytes: usize,
    pub fault: Option<Arc<WriterFault>>,
    /// Latest packet time of the whole capture, set by the reader (see [`ReaderSetup`]).
    pub end_ts: Arc<OnceLock<i64>>,
}

pub(crate) fn run_shard(
    rx: &Receiver<Batch>,
    setup: ShardSetup,
) -> Result<ShardOutcome, StoreError> {
    let ShardSetup {
        index,
        mut table,
        analyzers,
        sender,
        max_records,
        max_record_bytes,
        fault,
        end_ts,
    } = setup;
    let mut slots: Vec<Slot> = analyzers
        .into_iter()
        .map(|analyzer| Slot {
            id: analyzer.id(),
            analyzer,
            enabled: true,
        })
        .collect();
    let mut out = WriterSink {
        sender,
        buf: Vec::new(),
        buf_bytes: 0,
        max_records: max_records.max(1),
        max_bytes: max_record_bytes.max(1),
        error: None,
        fault,
    };
    let mut packets = 0u64;
    let mut panicked = 0u64;
    for batch in rx {
        let mut fan = Fanout {
            slots: &mut slots,
            out: &mut out,
            shard: index,
            panicked: &mut panicked,
        };
        for frame in &batch.frames {
            let p = &frame.packet;
            // The wire length is never shorter than what was captured.
            let captured = u32::try_from(p.data.len()).unwrap_or(u32::MAX);
            table.process(
                p.ts_ns,
                p.chunk_id,
                frame.index,
                p.linktype,
                p.orig_len.max(captured),
                &p.data,
                &mut fan,
            );
        }
        packets += u64::try_from(batch.len()).unwrap_or(u64::MAX);
        // Bytes return to the budget here.
        drop(batch);
        if out.error.is_some() {
            // The writer is gone: stop consuming, which stops the decoder and the reader.
            break;
        }
    }
    let mut fan = Fanout {
        slots: &mut slots,
        out: &mut out,
        shard: index,
        panicked: &mut panicked,
    };
    // Every shard ends its flows at the same global time, whatever the traffic it saw, so that
    // the result does not depend on the number of shards.
    match end_ts.get() {
        Some(&end) => table.finish_at(end, &mut fan),
        // Nothing was read at all (or the reader never ran): no flow either.
        None => table.finish(&mut fan),
    }
    fan.each("finish", (None, None), |a, out| a.finish(out));
    out.flush();
    match out.error {
        Some(e) => Err(e),
        None => Ok(ShardOutcome { packets, panicked }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_blocks_until_bytes_are_released() {
        let budget = Arc::new(Budget::new(100));
        let cancel = CancelToken::new();
        assert!(budget.acquire(60, &cancel));
        // Oversized for the remaining room, but released by another thread.
        let other = Arc::clone(&budget);
        let releaser = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            other.release(60);
        });
        assert!(budget.acquire(60, &cancel));
        releaser.join().unwrap();
        assert_eq!(budget.used(), 60);
        // A packet larger than the budget passes when nothing else is in flight.
        budget.release(60);
        assert!(budget.acquire(1000, &cancel));
        cancel.cancel();
        assert!(!budget.acquire(1, &cancel));
    }

    #[test]
    fn dropped_batches_return_their_bytes() {
        let budget = Arc::new(Budget::new(1 << 20));
        let cancel = CancelToken::new();
        let mut batch = Batch::new(&budget);
        for index in 0..3 {
            assert!(budget.acquire(10, &cancel));
            batch.push(Frame {
                index,
                packet: RawPacket {
                    ts_ns: 0,
                    chunk_id: 0,
                    offset: 0,
                    linktype: 1,
                    orig_len: 10,
                    data: vec![0u8; 10].into(),
                },
            });
        }
        let mut moved = Batch::new(&budget);
        for frame in batch.take() {
            moved.push(frame);
        }
        drop(batch);
        assert_eq!(budget.used(), 30);
        drop(moved);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn panic_messages_are_truncated() {
        let long = "x".repeat(2000);
        assert_eq!(panic_message(&long).len(), MAX_PANIC_MESSAGE);
        assert_eq!(panic_message(&"boom"), "boom");
        assert_eq!(panic_message(&42u8), "non-string panic payload");
    }
}
