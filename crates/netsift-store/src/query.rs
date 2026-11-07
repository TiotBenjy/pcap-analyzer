//! Read queries and the keyset pagination helper shared with the API.
//!
//! Pagination never uses `OFFSET`: a page ends with an opaque cursor holding the
//! `(sort value, tie-breaker)` of its last row, and the next page starts strictly after it
//! with a row-value comparison that the sort index can serve.

use rusqlite::types::Value;
use rusqlite::{Connection, OptionalExtension, Row, ToSql};

use crate::error::{Result, StoreError};
use crate::records::{CHUNK_COLUMNS, ChunkRow, FLOW_COLUMNS, FlowRow, conversion};

/// Largest accepted page size.
pub const MAX_PAGE_LIMIT: u32 = 1000;
/// Largest accepted encoded cursor, in characters.
const MAX_CURSOR_LEN: usize = 2048;

/// What the client asks for.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PageRequest {
    /// Page size, clamped to `1..=MAX_PAGE_LIMIT` (0 means 100).
    pub limit: u32,
    /// Cursor returned with the previous page, `None` for the first page.
    pub cursor: Option<String>,
}

impl PageRequest {
    /// First page of `limit` rows.
    pub fn first(limit: u32) -> Self {
        Self {
            limit,
            cursor: None,
        }
    }

    fn effective_limit(&self) -> u32 {
        if self.limit == 0 {
            100
        } else {
            self.limit.min(MAX_PAGE_LIMIT)
        }
    }
}

/// One page of results.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page<T> {
    pub items: Vec<T>,
    /// Cursor of the next page, `None` on the last page.
    pub next_cursor: Option<String>,
}

/// Description of a keyset-paginated query.
///
/// Every SQL fragment is a `&'static str` (a constant, or chosen from a whitelist by the
/// caller): raw user input cannot reach the SQL text, user values go through `params`. The sort expression and the tie-breaker must be
/// non-NULL (wrap nullable columns in `coalesce`), and the tie-breaker must be unique, or
/// rows would be skipped or repeated. Filters use plain `?` placeholders.
#[derive(Debug, Clone, Copy)]
pub struct Keyset {
    /// `FROM` clause body (table or join).
    pub from: &'static str,
    /// Selected columns, read by the row mapper from index 0.
    pub select: &'static str,
    /// Sort expression.
    pub sort: &'static str,
    /// Unique tie-breaker (usually the primary key).
    pub tiebreak: &'static str,
    /// Descending order when true.
    pub descending: bool,
    /// Optional `WHERE` condition.
    pub filter: Option<&'static str>,
}

/// Runs one page of a keyset query.
pub fn keyset_page<T>(
    conn: &Connection,
    query: &Keyset,
    params: &[&dyn ToSql],
    request: &PageRequest,
    mut map: impl FnMut(&Row<'_>) -> rusqlite::Result<T>,
) -> Result<Page<T>> {
    let cursor = request.cursor.as_deref().map(decode_cursor).transpose()?;
    let (cmp, dir) = if query.descending {
        ("<", "DESC")
    } else {
        (">", "ASC")
    };
    let mut conditions = Vec::new();
    if let Some(filter) = query.filter {
        conditions.push(format!("({filter})"));
    }
    if cursor.is_some() {
        conditions.push(format!("({}, {}) {cmp} (?, ?)", query.sort, query.tiebreak));
    }
    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", conditions.join(" AND "))
    };
    let sql = format!(
        "SELECT {select}, {sort}, {tiebreak} FROM {from}{where_clause} \
         ORDER BY {sort} {dir}, {tiebreak} {dir} LIMIT ?",
        select = query.select,
        sort = query.sort,
        tiebreak = query.tiebreak,
        from = query.from,
    );
    let limit = request.effective_limit();
    let mut all: Vec<&dyn ToSql> = params.to_vec();
    if let Some((a, b)) = &cursor {
        all.push(a);
        all.push(b);
    }
    let fetch = i64::from(limit) + 1;
    all.push(&fetch);

    let mut stmt = conn.prepare(&sql)?;
    let n = stmt.column_count();
    let (sort_idx, tie_idx) = (n.saturating_sub(2), n.saturating_sub(1));
    let mut rows = stmt.query(all.as_slice())?;
    let mut items = Vec::new();
    let mut last_key = None;
    let mut has_more = false;
    while let Some(row) = rows.next()? {
        if items.len() >= usize::try_from(limit).unwrap_or(usize::MAX) {
            has_more = true;
            break;
        }
        items.push(map(row)?);
        last_key = Some((
            row.get::<_, Value>(sort_idx)?,
            row.get::<_, Value>(tie_idx)?,
        ));
    }
    let next_cursor = match (has_more, last_key) {
        (true, Some((a, b))) => Some(encode_cursor(&a, &b)?),
        _ => None,
    };
    Ok(Page { items, next_cursor })
}

/// Opaque cursor: hex of a two-element JSON array (URL-safe, no extra dependency).
fn encode_cursor(sort: &Value, tiebreak: &Value) -> Result<String> {
    let json = serde_json::to_string(&[value_to_json(sort)?, value_to_json(tiebreak)?])?;
    let mut out = String::with_capacity(json.len() * 2);
    for b in json.bytes() {
        out.push(char::from(HEX[usize::from(b >> 4)]));
        out.push(char::from(HEX[usize::from(b & 0x0F)]));
    }
    Ok(out)
}

const HEX: &[u8; 16] = b"0123456789abcdef";

fn decode_cursor(s: &str) -> Result<(Value, Value)> {
    if s.len() > MAX_CURSOR_LEN || !s.len().is_multiple_of(2) {
        return Err(StoreError::InvalidCursor);
    }
    let bytes = s
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|[h, l]| Some((hex_val(*h)? << 4) | hex_val(*l)?))
        .collect::<Option<Vec<u8>>>()
        .ok_or(StoreError::InvalidCursor)?;
    let parsed: Vec<serde_json::Value> =
        serde_json::from_slice(&bytes).map_err(|_| StoreError::InvalidCursor)?;
    match parsed.as_slice() {
        [a, b] => Ok((json_to_value(a)?, json_to_value(b)?)),
        _ => Err(StoreError::InvalidCursor),
    }
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

fn value_to_json(v: &Value) -> Result<serde_json::Value> {
    Ok(match v {
        Value::Integer(i) => serde_json::Value::from(*i),
        Value::Real(f) => serde_json::Number::from_f64(*f)
            .map(serde_json::Value::Number)
            .ok_or(StoreError::InvalidCursor)?,
        Value::Text(s) => serde_json::Value::from(s.as_str()),
        // NULL and BLOB sort keys are not supported (see `Keyset`).
        Value::Null | Value::Blob(_) => return Err(StoreError::InvalidCursor),
    })
}

fn json_to_value(v: &serde_json::Value) -> Result<Value> {
    match v {
        serde_json::Value::Number(n) => n
            .as_i64()
            .map(Value::Integer)
            .or_else(|| n.as_f64().map(Value::Real))
            .ok_or(StoreError::InvalidCursor),
        serde_json::Value::String(s) => Ok(Value::Text(s.clone())),
        _ => Err(StoreError::InvalidCursor),
    }
}

/// One page of chunks, in chunk-set order.
pub fn chunks_page(conn: &Connection, request: &PageRequest) -> Result<Page<ChunkRow>> {
    let query = Keyset {
        from: "chunks",
        select: CHUNK_COLUMNS,
        sort: "id",
        tiebreak: "id",
        descending: false,
        filter: None,
    };
    keyset_page(conn, &query, &[], request, ChunkRow::from_row)
}

/// An anomaly as stored.
#[derive(Debug, Clone, PartialEq)]
pub struct AnomalyEntry {
    pub id: i64,
    pub kind: String,
    pub chunk_id: Option<u32>,
    pub ts: Option<i64>,
    pub detail: serde_json::Value,
}

/// One page of anomalies, by timestamp (anomalies without timestamp last), then insertion
/// order. The sort expression matches the `anomalies_ts` index.
pub fn anomalies_page(conn: &Connection, request: &PageRequest) -> Result<Page<AnomalyEntry>> {
    let query = Keyset {
        from: "anomalies",
        select: "id, kind, chunk_id, ts, detail",
        sort: "coalesce(ts, 9223372036854775807)",
        tiebreak: "id",
        descending: false,
        filter: None,
    };
    keyset_page(conn, &query, &[], request, |r| {
        let detail: String = r.get(4)?;
        Ok(AnomalyEntry {
            id: r.get(0)?,
            kind: r.get(1)?,
            chunk_id: r.get(2)?,
            ts: r.get(3)?,
            detail: serde_json::from_str(&detail).map_err(|e| conversion(4, e))?,
        })
    })
}

/// Number of flows.
pub fn count_flows(conn: &Connection) -> Result<u64> {
    Ok(conn.query_row("SELECT count(*) FROM flows", [], |r| r.get(0))?)
}

/// Value of a `meta` key.
pub fn get_meta(conn: &Connection, key: &str) -> Result<Option<String>> {
    Ok(conn
        .query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0))
        .optional()?)
}

/// Sort keys accepted for flows (whitelist: the API maps its `sort` parameter onto it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowSort {
    FirstTs,
    LastTs,
    Bytes,
    Packets,
    DstPort,
}

impl FlowSort {
    fn expr(self) -> &'static str {
        match self {
            Self::FirstTs => "first_ts",
            Self::LastTs => "last_ts",
            Self::Bytes => "bytes_total",
            Self::Packets => "packets_total",
            Self::DstPort => "dst_port",
        }
    }
}

/// One page of flows.
pub fn flows_page(
    conn: &Connection,
    sort: FlowSort,
    descending: bool,
    request: &PageRequest,
) -> Result<Page<FlowRow>> {
    let query = Keyset {
        from: "flows",
        select: FLOW_COLUMNS,
        sort: sort.expr(),
        tiebreak: "id",
        descending,
        filter: None,
    };
    keyset_page(conn, &query, &[], request, FlowRow::from_row)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_round_trip() {
        for (a, b) in [
            (Value::Integer(-5), Value::Integer(i64::MAX)),
            (Value::Real(1.5), Value::Integer(0)),
            (Value::Real(2.0), Value::Text("x".into())),
            (Value::Text("é\"'".into()), Value::Integer(1)),
        ] {
            let c = encode_cursor(&a, &b).unwrap();
            assert!(c.bytes().all(|b| b.is_ascii_hexdigit()));
            assert_eq!(decode_cursor(&c).unwrap(), (a, b));
        }
    }

    #[test]
    fn rejects_hostile_cursors() {
        let long = "0".repeat(MAX_CURSOR_LEN + 2);
        for bad in [
            "zz",
            "abc",
            "",
            "5b5d",
            "5b315d",
            "5b6e756c6c2c315d",
            long.as_str(),
        ] {
            assert!(decode_cursor(bad).is_err(), "{bad}");
        }
        assert!(encode_cursor(&Value::Null, &Value::Integer(1)).is_err());
    }
}
