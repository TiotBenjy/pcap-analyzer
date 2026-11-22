//! Time range of the global time filter (P5.2, ADR-030, `docs/specs/time-filter.md`).
//!
//! A range is half-open in nanoseconds, `[from_ns, to_ns)`. Two shapes of condition:
//!
//! - a **point** record (DNS message, HTTP transaction, TLS session) is in the range when its
//!   timestamp is: `col >= from AND col < to`;
//! - a **folded** row (flow, credential, SMB announce or session, host) is in the range when its
//!   span overlaps it: `first < to AND last >= from`. Its counters stay those of the session.
//!
//! Lists add the conditions through [`Conditions`] (plain `?` placeholders); fixed aggregate
//! statements use the named parameters `:from` and `:to`, bound by [`query_ranged`]. In
//! aggregates the column is written `+col`: SQLite then cannot range-scan the timestamp index
//! (row lookups, slow on a wide range) and picks the covering index that ends with the
//! timestamp instead, without naming it (ADR-023 forbids `INDEXED BY` on deferred indexes).

use rusqlite::types::Value;
use rusqlite::{Connection, Row, ToSql};

use crate::error::Result;
use crate::query::Conditions;

/// Flows longer than this are found through the partial index `flows_long` (migration 0003):
/// the others started at most this long before the range, which the start-time index serves.
pub const LONG_FLOW_NS: i64 = 3_600_000_000_000;

/// Half-open time range `[from_ns, to_ns)`, nanoseconds since the Unix epoch (UTC).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TimeRange {
    from_ns: i64,
    to_ns: i64,
}

impl TimeRange {
    /// `None` when `to_ns < from_ns`; an empty range (`from == to`) matches nothing.
    pub fn new(from_ns: i64, to_ns: i64) -> Option<Self> {
        (from_ns <= to_ns).then_some(Self { from_ns, to_ns })
    }

    pub fn from_ns(self) -> i64 {
        self.from_ns
    }

    /// Exclusive end.
    pub fn to_ns(self) -> i64 {
        self.to_ns
    }

    pub fn contains(self, ts: i64) -> bool {
        ts >= self.from_ns && ts < self.to_ns
    }

    /// True when `[first, last]` (inclusive bounds, as stored) overlaps the range.
    pub fn overlaps(self, first: i64, last: i64) -> bool {
        first < self.to_ns && last >= self.from_ns
    }

    /// True when the range contains every timestamp of `[first, last]`.
    pub fn covers(self, first: i64, last: i64) -> bool {
        self.from_ns <= first && last < self.to_ns
    }

    /// The two bounds, in the order of the placeholders of every fragment below.
    pub fn values(self) -> [Value; 2] {
        [Value::Integer(self.from_ns), Value::Integer(self.to_ns)]
    }

    /// `col >= ? AND col < ?`: a point record, through the index of `col` (lists sorted by it).
    pub fn push_point(self, c: &mut Conditions, col: &'static str) {
        c.push_owned(format!("{col} >= ? AND {col} < ?"), self.values());
    }

    /// Same as [`Self::push_point`] without the index of `col` (`+col`): for a list sorted on
    /// another key whose sort index should be walked.
    pub fn push_point_scan(self, c: &mut Conditions, col: &'static str) {
        c.push_owned(format!("+{col} >= ? AND +{col} < ?"), self.values());
    }

    /// `first < ? AND last >= ?`: a folded row whose span overlaps the range.
    pub fn push_overlap(self, c: &mut Conditions, first: &'static str, last: &'static str) {
        c.push_owned(
            format!("{first} < ? AND {last} >= ?"),
            [Value::Integer(self.to_ns), Value::Integer(self.from_ns)],
        );
    }
}

/// ` AND +col >= :from AND +col < :to` when a range is set, else nothing: appended to the
/// `WHERE` clause of a fixed aggregate.
pub(crate) fn and_point(range: Option<TimeRange>, col: &str) -> String {
    range.map_or_else(String::new, |_| {
        format!(" AND +{col} >= :from AND +{col} < :to")
    })
}

/// Same as [`and_point`] for a statement without `WHERE` clause.
pub(crate) fn where_point(range: Option<TimeRange>, col: &str) -> String {
    range.map_or_else(String::new, |_| {
        format!(" WHERE +{col} >= :from AND +{col} < :to")
    })
}

/// ` AND first < :to AND last >= :from` when a range is set (folded rows).
pub(crate) fn and_overlap(range: Option<TimeRange>, first: &str, last: &str) -> String {
    range.map_or_else(String::new, |_| {
        format!(" AND {first} < :to AND {last} >= :from")
    })
}

/// Same as [`and_overlap`] for a statement without `WHERE` clause.
pub(crate) fn where_overlap(range: Option<TimeRange>, first: &str, last: &str) -> String {
    range.map_or_else(String::new, |_| {
        format!(" WHERE {first} < :to AND {last} >= :from")
    })
}

/// Prepares `sql`, binds `positional` to `?1`, `?2`... and the range to `:from` / `:to` when the
/// statement names them, then maps every row.
pub(crate) fn query_ranged<T>(
    conn: &Connection,
    sql: &str,
    positional: &[&dyn ToSql],
    range: Option<TimeRange>,
    mut map: impl FnMut(&Row<'_>) -> rusqlite::Result<T>,
) -> Result<Vec<T>> {
    let mut stmt = conn.prepare_cached(sql)?;
    for (i, p) in positional.iter().enumerate() {
        stmt.raw_bind_parameter(i + 1, p)?;
    }
    if let Some(r) = range {
        if let Some(i) = stmt.parameter_index(":from")? {
            stmt.raw_bind_parameter(i, r.from_ns)?;
        }
        if let Some(i) = stmt.parameter_index(":to")? {
            stmt.raw_bind_parameter(i, r.to_ns)?;
        }
    }
    let mut rows = stmt.raw_query();
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(map(row)?);
    }
    Ok(out)
}

/// [`query_ranged`] for a statement that returns exactly one row.
pub(crate) fn query_row_ranged<T>(
    conn: &Connection,
    sql: &str,
    positional: &[&dyn ToSql],
    range: Option<TimeRange>,
    map: impl FnMut(&Row<'_>) -> rusqlite::Result<T>,
) -> Result<T> {
    query_ranged(conn, sql, positional, range, map)?
        .into_iter()
        .next()
        .ok_or_else(|| rusqlite::Error::QueryReturnedNoRows.into())
}

/// Number of flows whose span overlaps `range`, in two disjoint branches (spec, « Index »):
/// flows started at most [`LONG_FLOW_NS`] before the range (index `(first_ts, last_ts)`), and
/// longer flows started earlier (partial index `flows_long`).
pub fn count_active_flows(conn: &Connection, range: TimeRange) -> Result<u64> {
    let n: i64 = conn.query_row(
        "SELECT (SELECT count(*) FROM flows WHERE first_ts >= ?1 - ?3 AND first_ts < ?2 \
                 AND last_ts >= ?1) \
              + (SELECT count(*) FROM flows WHERE last_ts - first_ts > 3600000000000 \
                 AND last_ts >= ?1 AND first_ts < ?1 - ?3)",
        rusqlite::params![range.from_ns, range.to_ns, LONG_FLOW_NS],
        |r| r.get(0),
    )?;
    Ok(u64::try_from(n).unwrap_or(0))
}

/// Number of hosts whose span overlaps `range` (index `(first_ts, last_ts)`).
pub fn count_active_hosts(conn: &Connection, range: TimeRange) -> Result<u64> {
    let n: i64 = conn.query_row(
        "SELECT count(*) FROM hosts WHERE first_ts < ?2 AND last_ts >= ?1",
        rusqlite::params![range.from_ns, range.to_ns],
        |r| r.get(0),
    )?;
    Ok(u64::try_from(n).unwrap_or(0))
}

/// Rows of an analysis module counted over a range, for the module cards of the overview: the
/// same rule as the list of the view (ADR-030).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleRows {
    Credentials,
    DnsMessages,
    HttpHeaders,
    HttpTransactions,
    Pictures,
    /// Announcements and SMB sessions (`smb_items`).
    Smb,
    TlsSessions,
}

impl ModuleRows {
    fn sql(self) -> &'static str {
        match self {
            Self::Credentials => {
                "SELECT count(*) FROM credentials WHERE first_ts < ?2 AND last_ts >= ?1"
            }
            Self::DnsMessages => "SELECT count(*) FROM dns_messages WHERE ts >= ?1 AND ts < ?2",
            Self::HttpHeaders => "SELECT count(*) FROM http_headers WHERE +ts >= ?1 AND +ts < ?2",
            Self::HttpTransactions => {
                "SELECT count(*) FROM http_transactions WHERE ts >= ?1 AND ts < ?2"
            }
            Self::Pictures => {
                "SELECT count(*) FROM objects o WHERE o.mime LIKE 'image/%' AND EXISTS \
                 (SELECT 1 FROM http_transactions t WHERE t.resp_sha256 = o.sha256 \
                  AND t.ts >= ?1 AND t.ts < ?2)"
            }
            Self::Smb => {
                "SELECT (SELECT count(*) FROM smb_announces WHERE first_ts < ?2 \
                         AND last_ts >= ?1) \
                      + (SELECT count(*) FROM smb_sessions WHERE first_ts < ?2 \
                         AND last_ts >= ?1)"
            }
            Self::TlsSessions => "SELECT count(*) FROM tls_sessions WHERE ts >= ?1 AND ts < ?2",
        }
    }

    /// Rows of the module within `range`.
    pub fn count(self, conn: &Connection, range: TimeRange) -> Result<u64> {
        let n: i64 = conn.query_row(
            self.sql(),
            rusqlite::params![range.from_ns, range.to_ns],
            |r| r.get(0),
        )?;
        Ok(u64::try_from(n).unwrap_or(0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds_are_half_open() {
        let r = TimeRange::new(10, 20).unwrap();
        assert!(r.contains(10));
        assert!(r.contains(19));
        assert!(!r.contains(20));
        assert!(!r.contains(9));
        assert!(r.overlaps(0, 10));
        assert!(r.overlaps(19, 100));
        assert!(!r.overlaps(20, 30));
        assert!(!r.overlaps(0, 9));
        assert!(r.covers(10, 19));
        assert!(!r.covers(10, 20));
        assert!(TimeRange::new(5, 4).is_none());
        assert!(!TimeRange::new(5, 5).unwrap().contains(5));
    }

    #[test]
    fn fragments_bind_in_order() {
        let r = TimeRange::new(1, 2).unwrap();
        let mut c = Conditions::new();
        r.push_point(&mut c, "m.ts");
        r.push_overlap(&mut c, "first_ts", "last_ts");
        assert_eq!(
            c.sql().unwrap(),
            "(m.ts >= ? AND m.ts < ?) AND (first_ts < ? AND last_ts >= ?)"
        );
        assert_eq!(and_point(None, "ts"), "");
        assert_eq!(and_point(Some(r), "ts"), " AND +ts >= :from AND +ts < :to");
    }

    #[test]
    fn named_bounds_are_bound_after_positional_ones() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE t (ts INTEGER, k TEXT); \
             INSERT INTO t VALUES (1, 'a'), (5, 'a'), (9, 'b'), (12, 'a');",
        )
        .unwrap();
        let r = TimeRange::new(5, 12).unwrap();
        let sql = format!(
            "SELECT count(*) FROM t WHERE k = ?1{}",
            and_point(Some(r), "ts")
        );
        let n: i64 = query_row_ranged(&conn, &sql, &[&"a"], Some(r), |row| row.get(0)).unwrap();
        assert_eq!(n, 1);
        let all = format!("SELECT count(*) FROM t{}", where_point(None, "ts"));
        let n: i64 = query_row_ranged(&conn, &all, &[], None, |row| row.get(0)).unwrap();
        assert_eq!(n, 4);
    }
}
