//! Conversions between store rows and contract DTOs (nanoseconds -> microseconds, ADR-008).

use std::time::{SystemTime, UNIX_EPOCH};

use netsift_store::query::AnomalyEntry;
use netsift_store::{AnomalyRow, ChunkRow, ChunkStatus};
use serde_json::Value;

use crate::contract::{AnomalyInfo, ChunkInfo, SessionState};

/// Nanoseconds to microseconds (floor, also for dates before 1970).
pub(crate) fn us(ns: i64) -> i64 {
    ns.div_euclid(1_000)
}

/// Wall clock, nanoseconds since the Unix epoch (same clock as the catalog dates).
pub(crate) fn now_ns() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_nanos()).unwrap_or(i64::MAX))
}

pub(crate) fn state(s: netsift_store::SessionState) -> SessionState {
    match s {
        netsift_store::SessionState::Importing => SessionState::Importing,
        netsift_store::SessionState::Ready => SessionState::Ready,
        netsift_store::SessionState::Incomplete => SessionState::Incomplete,
        netsift_store::SessionState::Failed => SessionState::Failed,
    }
}

/// Anomaly details: every integer member named `*_ns` becomes `*_us` (timestamps and
/// durations stay exact as JavaScript numbers). Other members are kept as they are.
pub(crate) fn detail(value: Value) -> Value {
    let Value::Object(map) = value else {
        return value;
    };
    map.into_iter()
        .map(|(key, v)| match (key.strip_suffix("_ns"), v.as_i64()) {
            (Some(stem), Some(ns)) => (format!("{stem}_us"), Value::from(us(ns))),
            _ => (key, v),
        })
        .collect::<serde_json::Map<_, _>>()
        .into()
}

pub(crate) fn chunk(row: ChunkRow) -> ChunkInfo {
    ChunkInfo {
        id: row.id,
        seq: row.seq,
        path: row.path,
        format: row
            .format
            .map_or_else(|| "unknown".to_owned(), |f| f.as_str().to_owned()),
        compressed: row.compressed,
        linktypes: row.linktypes,
        first_ts_us: row.first_ts.map(us),
        last_ts_us: row.last_ts.map(us),
        packets: row.packets,
        // Size on disk: known for every member (captured bytes are 0 for unread files).
        bytes: row.file_size,
        state: match row.status {
            ChunkStatus::Ok => "ok",
            ChunkStatus::Truncated => "truncated",
            ChunkStatus::Duplicate => "duplicate",
            ChunkStatus::Ignored => "skipped",
        }
        .to_owned(),
    }
}

pub(crate) fn anomaly(entry: AnomalyEntry) -> AnomalyInfo {
    AnomalyInfo {
        id: Some(entry.id.to_string()),
        code: entry.kind,
        chunk: entry.chunk_id,
        ts_us: entry.ts.map(us),
        detail: detail(entry.detail),
    }
}

/// Anomaly of a scan preview (not stored yet).
pub(crate) fn anomaly_preview(row: AnomalyRow, fallback_ts: Option<i64>) -> AnomalyInfo {
    AnomalyInfo {
        id: None,
        code: row.kind,
        chunk: row.chunk_id,
        ts_us: row.ts.or(fallback_ts).map(us),
        detail: detail(row.detail),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nanoseconds_become_microseconds() {
        assert_eq!(us(1_700_000_000_123_456_789), 1_700_000_000_123_456);
        assert_eq!(us(-1), -1);
        let d =
            detail(serde_json::json!({"gap_ns": 7_000_000_999_i64, "previous": 3, "reason": "x"}));
        assert_eq!(
            d,
            serde_json::json!({"gap_us": 7_000_000, "previous": 3, "reason": "x"})
        );
        assert_eq!(detail(Value::Null), Value::Null);
    }
}
