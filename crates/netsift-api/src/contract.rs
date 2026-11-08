//! Sessions and import API contract, shared by the backend (task P2.1) and the Captures view
//! (task P2.3). Frozen before both tasks start: change it only by agreement.
//!
//! JSON conventions (ADR-008):
//! - timestamps are **microseconds** since the Unix epoch, UTC (`*_us`), so that they stay exact
//!   as JavaScript numbers (nanoseconds would exceed 2^53); the database keeps nanoseconds;
//! - identifiers that may exceed 2^53 (flow ids, ...) are strings; session ids are ULID strings;
//! - byte and packet counters are plain numbers;
//! - field names are `snake_case`; enums are lowercase strings.
//!
//! Routes (prefix `/api/v1`, bearer token required):
//!
//! | Method | Path | Body | Response |
//! |---|---|---|---|
//! | GET | `/sessions` | | `Page<SessionSummary>` |
//! | GET | `/sessions/{id}` | | `SessionSummary` |
//! | PATCH | `/sessions/{id}` | `RenameRequest` | `SessionSummary` |
//! | DELETE | `/sessions/{id}` | | 204 (never touches the source captures) |
//! | POST | `/sessions/import/scan` | `ScanRequest` | `ScanResponse` |
//! | POST | `/sessions/import` | `ImportRequest` | `ImportResponse` (202) |
//! | POST | `/sessions/{id}/cancel` | | 202 |
//! | GET | `/sessions/{id}/events` | | SSE stream of `ImportEvent` (event name = variant tag) |
//! | GET | `/sessions/{id}/chunks` | | `Page<ChunkInfo>` |
//! | GET | `/sessions/{id}/anomalies` | | `Page<AnomalyInfo>` |
//! | GET | `/fs/browse?path=` | | `BrowseResponse` (dev web mode, allowed roots only) |
//!
//! List endpoints accept `?limit=` (default 100, max 1000) and `?cursor=` (opaque).
//! The SSE stream must be readable with `fetch` (the UI cannot use `EventSource`, which cannot
//! send the `Authorization` header); events are `event: <tag>\ndata: <json>\n\n`.

use serde::{Deserialize, Serialize};
use ts_rs::TS;

/// One page of a keyset-paginated list.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct Page<T> {
    pub items: Vec<T>,
    /// Opaque cursor for the next page, `null` on the last page.
    pub next_cursor: Option<String>,
    /// Total number of items when cheap to compute, otherwise `null`.
    pub total_estimate: Option<u64>,
}

/// Session lifecycle state (mirrors the catalog).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "lowercase")]
#[ts(export)]
pub enum SessionState {
    Importing,
    Ready,
    Incomplete,
    Failed,
}

/// Row of the sessions table.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct SessionSummary {
    /// ULID.
    pub id: String,
    pub name: String,
    /// Source paths as given at import (files or folders).
    pub sources: Vec<String>,
    pub created_us: i64,
    pub state: SessionState,
    /// Short reason for `failed` / `incomplete`, never containing secrets.
    pub state_detail: Option<String>,
    /// Captured period (first and last packet), `null` while unknown.
    pub first_ts_us: Option<i64>,
    pub last_ts_us: Option<i64>,
    /// Total size of the source files read.
    pub source_bytes: u64,
    pub packets: u64,
    pub chunk_count: u32,
    pub anomaly_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct RenameRequest {
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ScanRequest {
    /// File or folder, as seen by the backend (absolute path).
    pub path: String,
    #[serde(default)]
    pub recursive: bool,
}

/// Naming pattern that produced a group (`docs/CHUNKED_CAPTURES.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum GroupPattern {
    Dumpcap,
    DumpcapNameTimeNum,
    TcpdumpC,
    CommonPrefix,
    Folder,
    SingleFile,
}

/// Anomaly as returned by the API (scan preview or stored row).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct AnomalyInfo {
    /// Stored row id as a string, `null` when not stored yet (scan previews, `warning` events).
    pub id: Option<String>,
    /// Stable machine code (`missing_sequence`, `time_gap`, `overlap`, `duplicate`, ...).
    pub code: String,
    /// Index of the chunk concerned in its group, when any.
    pub chunk: Option<u32>,
    pub ts_us: Option<i64>,
    /// Structured details (gap duration, missing numbers, ...). Shape depends on `code`.
    #[ts(type = "Record<string, unknown>")]
    pub detail: serde_json::Value,
}

/// One detected chunk set.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ScanGroup {
    /// Index to pass back in `ImportRequest::group_ids`.
    pub id: u32,
    pub pattern: GroupPattern,
    /// Common file name prefix (empty for `folder`).
    pub prefix: String,
    pub file_count: u32,
    pub total_bytes: u64,
    pub first_ts_us: Option<i64>,
    pub last_ts_us: Option<i64>,
    /// Continuity problems detectable before import (missing numbers, duplicates, gaps).
    pub anomalies: Vec<AnomalyInfo>,
}

/// File of the scanned folder that belongs to no group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ScanSkippedFile {
    pub name: String,
    /// `empty`, `too_short`, `unrecognized`, `unreadable`, `not_regular`.
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ScanResponse {
    pub path: String,
    pub groups: Vec<ScanGroup>,
    pub skipped: Vec<ScanSkippedFile>,
    /// True when the inventory stopped at its file limit.
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ImportRequest {
    pub path: String,
    /// Groups to import as one session. Empty: the only group (error if several).
    /// Several ids: merged into one session.
    #[serde(default)]
    pub group_ids: Vec<u32>,
    /// Session name; default: folder or file name.
    pub name: Option<String>,
    #[serde(default)]
    pub recursive: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ImportResponse {
    pub session_id: String,
}

/// Import progress snapshot (event `progress`, at most a few per second).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ImportProgress {
    pub bytes_done: u64,
    pub bytes_total: u64,
    /// 0-based index of the chunk being read.
    pub chunk_index: u32,
    pub chunk_count: u32,
    pub chunk_name: String,
    pub packets: u64,
    /// Read throughput, bytes per second.
    pub rate_bps: f64,
    /// Estimated remaining seconds, `null` when unknown.
    pub eta_s: Option<f64>,
    /// `reading`, `finishing`.
    pub phase: String,
}

/// Events of `GET /sessions/{id}/events`. The SSE event name is the `type` tag.
/// A client connecting after the end immediately receives the final `done` or `failed`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[serde(tag = "type", rename_all = "snake_case")]
#[ts(export)]
pub enum ImportEvent {
    Progress(ImportProgress),
    Warning(AnomalyInfo),
    /// Import ended; `state` is `ready` or `incomplete` (cancelled).
    Done {
        state: SessionState,
        packets: u64,
        flows: u64,
        anomalies: u32,
        duration_s: f64,
    },
    Failed {
        message: String,
    },
}

/// Chunk of a session (sources tab and coverage timeline).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ChunkInfo {
    /// Index in the session's chunk set (reading order basis).
    pub id: u32,
    /// Sequence number parsed from the file name, when any.
    pub seq: Option<i64>,
    pub path: String,
    /// `pcap`, `pcapng`.
    pub format: String,
    pub compressed: bool,
    pub linktypes: Vec<u32>,
    pub first_ts_us: Option<i64>,
    pub last_ts_us: Option<i64>,
    pub packets: u64,
    pub bytes: u64,
    /// `ok`, `truncated`, `duplicate`, `skipped`.
    pub state: String,
}

/// Entry of the dev-mode folder browser.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct FsEntry {
    pub name: String,
    pub is_dir: bool,
    /// File size (0 for folders).
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct BrowseResponse {
    /// Absolute path listed (always inside an allowed root).
    pub path: String,
    /// Parent folder, `null` at an allowed root.
    pub parent: Option<String>,
    /// Allowed roots, for the breadcrumb.
    pub roots: Vec<String>,
    /// Folders first, then files, each sorted by name.
    pub entries: Vec<FsEntry>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn events_are_tagged_snake_case() {
        let e = ImportEvent::Failed {
            message: "x".into(),
        };
        assert_eq!(
            serde_json::to_value(&e).unwrap(),
            serde_json::json!({"type": "failed", "message": "x"})
        );
        let s = serde_json::to_value(SessionState::Incomplete).unwrap();
        assert_eq!(s, "incomplete");
        let p = serde_json::to_value(GroupPattern::DumpcapNameTimeNum).unwrap();
        assert_eq!(p, "dumpcap_name_time_num");
    }
}
