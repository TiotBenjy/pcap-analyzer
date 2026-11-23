//! Extracted objects (`objects` table, migration `0700_objects.sql`, task P3.6): end-of-import
//! step, thumbnail bookkeeping and the queries of the Pictures view.
//!
//! # Merge rules
//!
//! No shard writes this table. The end-of-import step [`finalize`] derives it from the
//! transactions whose response body was stored (`http_transactions.resp_sha256`) and from the FTP
//! transfers whose file was stored (`ftp_transfers.sha256`, `source` = `ftp`, `uri` = the path,
//! `flow_id` / `seq` = control flow and transfer): one row per digest, the first occurrence being
//! the smallest `(time, flow_id, seq)`, the count of occurrences and the last time aggregated over
//! every transaction and transfer. The result depends neither
//! on the arrival order of the transactions nor on the number of shards. The step is an upsert
//! that keeps the thumbnail columns (`width`, `height`, `thumb`) of rows already present, so a
//! replay never loses the generated thumbnails.

use std::net::IpAddr;

use rusqlite::types::Value;
use rusqlite::{Connection, OptionalExtension, ToSql, params};

use crate::connections::EndpointInfo;
use crate::error::Result;
use crate::query::{Keyset, Page, PageRequest, keyset_page};
use crate::range::{TimeRange, query_ranged, query_row_ranged};
use crate::records::conversion;

/// Thumbnail states (`objects.thumb`).
pub mod thumb {
    /// Not generated yet.
    pub const PENDING: &str = "pending";
    /// `thumbs/<aa>/<sha256>.png` exists.
    pub const READY: &str = "ready";
    /// Never rasterized (SVG).
    pub const NONE: &str = "none";
    /// Not decodable within the limits (corrupt, truncated, too large).
    pub const FAILED: &str = "failed";
}

/// End-of-import step `objects` (ADR-014): one row per stored body, see the module
/// documentation.
pub fn finalize(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "INSERT INTO objects (sha256, size, mime, declared_type, thumb, occurrences, first_ts, \
             last_ts, flow_id, seq, client_ip, server_ip, server_port, host, uri, source) \
         SELECT sha, size, mime, declared, \
                CASE WHEN mime = 'image/svg+xml' THEN 'none' ELSE 'pending' END, \
                n, first_ts, last_ts, flow_id, seq, client_ip, server_ip, server_port, host, uri, \
                source \
         FROM ( \
             SELECT *, count(*) OVER w AS n, max(first_ts) OVER w AS last_ts, \
                    row_number() OVER (PARTITION BY sha ORDER BY first_ts, flow_id, seq) AS rn \
             FROM ( \
                 SELECT t.resp_sha256 AS sha, t.resp_body_len AS size, t.resp_mime_magic AS mime, \
                        t.content_type AS declared, t.flow_id, t.seq, t.client_ip, t.server_ip, \
                        t.server_port, t.host, t.uri, 'http' AS source, \
                        coalesce(t.resp_ts, t.ts) AS first_ts \
                 FROM http_transactions AS t \
                 WHERE t.resp_sha256 IS NOT NULL AND t.resp_mime_magic IS NOT NULL \
                 UNION ALL \
                 SELECT f.sha256, f.bytes, f.mime, NULL, f.flow_id, f.seq, s.client_ip, \
                        s.server_ip, s.server_port, NULL, f.path, 'ftp', f.ts \
                 FROM ftp_transfers AS f JOIN ftp_sessions AS s ON s.flow_id = f.flow_id \
                 WHERE f.sha256 IS NOT NULL AND f.mime IS NOT NULL \
             ) \
             WINDOW w AS (PARTITION BY sha) \
         ) WHERE rn = 1 \
         ORDER BY first_ts, flow_id, seq \
         ON CONFLICT (sha256) DO UPDATE SET \
             size = excluded.size, mime = excluded.mime, declared_type = excluded.declared_type, \
             occurrences = excluded.occurrences, first_ts = excluded.first_ts, \
             last_ts = excluded.last_ts, flow_id = excluded.flow_id, seq = excluded.seq, \
             client_ip = excluded.client_ip, server_ip = excluded.server_ip, \
             server_port = excluded.server_port, host = excluded.host, uri = excluded.uri, \
             source = excluded.source;",
    )?;
    Ok(())
}

/// One object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectRow {
    pub id: i64,
    pub sha256: String,
    pub size: u64,
    pub mime: String,
    pub declared_type: Option<String>,
    pub width: Option<u32>,
    pub height: Option<u32>,
    /// See [`thumb`].
    pub thumb: String,
    pub occurrences: u64,
    pub first_ts: i64,
    pub last_ts: i64,
    pub flow_id: i64,
    pub seq: u32,
    pub client_ip: IpAddr,
    pub server_ip: IpAddr,
    pub server_port: u16,
    pub host: Option<String>,
    /// Request target (HTTP) or path (FTP).
    pub uri: Option<String>,
    /// `http` or `ftp`.
    pub source: String,
    /// What the session knows about both ends (`hosts`).
    pub client: EndpointInfo,
    pub server: EndpointInfo,
}

const COLUMNS: &str = "o.id, o.sha256, o.size, o.mime, o.declared_type, o.width, o.height, \
                       o.thumb, o.occurrences, o.first_ts, o.last_ts, o.flow_id, o.seq, \
                       o.client_ip, o.server_ip, o.server_port, o.host, o.uri, \
                       hc.names, hc.category, hc.country, hv.names, hv.category, hv.country, \
                       o.source";
/// `objects` with the hosts of both ends.
const FROM: &str = "objects AS o LEFT JOIN hosts AS hc ON hc.ip = o.client_ip \
                    LEFT JOIN hosts AS hv ON hv.ip = o.server_ip";

fn ip(raw: &str, col: usize) -> rusqlite::Result<IpAddr> {
    raw.parse().map_err(|e| conversion(col, e))
}

fn names(raw: Option<String>, col: usize) -> rusqlite::Result<Vec<String>> {
    raw.map_or_else(
        || Ok(Vec::new()),
        |raw| serde_json::from_str(&raw).map_err(|e| conversion(col, e)),
    )
}

fn unsigned(v: i64) -> u64 {
    u64::try_from(v).unwrap_or(0)
}

impl ObjectRow {
    fn from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        let dim = |v: Option<i64>| v.and_then(|v| u32::try_from(v).ok());
        Ok(Self {
            id: r.get(0)?,
            sha256: r.get(1)?,
            size: unsigned(r.get(2)?),
            mime: r.get(3)?,
            declared_type: r.get(4)?,
            width: dim(r.get(5)?),
            height: dim(r.get(6)?),
            thumb: r.get(7)?,
            occurrences: unsigned(r.get(8)?),
            first_ts: r.get(9)?,
            last_ts: r.get(10)?,
            flow_id: r.get(11)?,
            seq: u32::try_from(r.get::<_, i64>(12)?).unwrap_or(u32::MAX),
            client_ip: ip(&r.get::<_, String>(13)?, 13)?,
            server_ip: ip(&r.get::<_, String>(14)?, 14)?,
            server_port: u16::try_from(r.get::<_, i64>(15)?).unwrap_or(0),
            host: r.get(16)?,
            uri: r.get(17)?,
            client: EndpointInfo {
                names: names(r.get(18)?, 18)?,
                category: r.get(19)?,
                country: r.get(20)?,
            },
            server: EndpointInfo {
                names: names(r.get(21)?, 21)?,
                category: r.get(22)?,
                country: r.get(23)?,
            },
            source: r.get(24)?,
        })
    }
}

/// Filters of the object list (all optional, combined with AND).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ObjectFilter {
    /// Only images (the Pictures view).
    pub images_only: bool,
    /// Exact detected type (`image/png`).
    pub mime: Option<String>,
    /// Exact host.
    pub host: Option<String>,
    /// Text in the host or the request target.
    pub q: Option<String>,
    /// Size bounds, in bytes (inclusive).
    pub min_size: Option<u64>,
    pub max_size: Option<u64>,
    /// Only objects carried by at least one transaction whose time (`ts`) is within this range;
    /// their occurrences and times are then those of the range.
    pub range: Option<TimeRange>,
}

/// Sort key of the object list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ObjectSort {
    /// Order of first appearance.
    #[default]
    Time,
    Size,
}

const FILTER: &str = "(?1 = 0 OR o.mime LIKE 'image/%') \
     AND (?2 IS NULL OR o.mime = ?2) \
     AND (?3 IS NULL OR o.host = ?3) \
     AND (?4 IS NULL OR o.host LIKE ?4 ESCAPE '\\' OR o.uri LIKE ?4 ESCAPE '\\') \
     AND (?5 IS NULL OR o.size >= ?5) \
     AND (?6 IS NULL OR o.size <= ?6)";

/// Objects carried by a transaction or an FTP transfer of the range (`?7`, `?8`), for a page:
/// correlated look-ups (indexes `(resp_sha256, ts)` and `(sha256, ts)`) that stop with the page.
const RANGE_PAGE_FILTER: &str = "(EXISTS (SELECT 1 FROM http_transactions t \
    WHERE t.resp_sha256 = o.sha256 AND t.ts >= ?7 AND t.ts < ?8) \
    OR EXISTS (SELECT 1 FROM ftp_transfers f WHERE f.sha256 = o.sha256 \
    AND f.ts >= ?7 AND f.ts < ?8))";

/// Same objects for a count, which reads them all: the digests of the range are gathered once
/// (indexes on `ts`), then each object is a lookup in that set rather than two correlated
/// sub-queries (P5.8, `docs/PERFORMANCE.md`).
const RANGE_FILTER: &str = "o.sha256 IN (SELECT t.resp_sha256 FROM http_transactions t \
    WHERE t.ts >= ?7 AND t.ts < ?8 AND t.resp_sha256 IS NOT NULL \
    UNION ALL SELECT f.sha256 FROM ftp_transfers f \
    WHERE f.ts >= ?7 AND f.ts < ?8 AND f.sha256 IS NOT NULL)";

/// [`FILTER`] and its values, plus the range when set (`page`: the form for a keyset page).
fn filter_sql(f: &ObjectFilter, page: bool) -> (String, Vec<Value>) {
    let mut values = filter_params(f).to_vec();
    match f.range {
        None => (FILTER.to_owned(), values),
        Some(r) => {
            values.extend(r.values());
            let range = if page {
                RANGE_PAGE_FILTER
            } else {
                RANGE_FILTER
            };
            (format!("{FILTER} AND {range}"), values)
        }
    }
}

/// Occurrences and first and last times of an object within `range`.
fn fill_range(conn: &Connection, row: &mut ObjectRow, range: TimeRange) -> Result<()> {
    let (n, first, last): (i64, Option<i64>, Option<i64>) = conn
        .prepare_cached(
            "SELECT count(*), min(t), max(t) FROM ( \
                 SELECT coalesce(resp_ts, ts) AS t FROM http_transactions \
                 WHERE resp_sha256 = ?1 AND ts >= ?2 AND ts < ?3 \
                 UNION ALL \
                 SELECT ts FROM ftp_transfers WHERE sha256 = ?1 AND ts >= ?2 AND ts < ?3)",
        )?
        .query_row(params![row.sha256, range.from_ns(), range.to_ns()], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })?;
    row.occurrences = unsigned(n);
    row.first_ts = first.unwrap_or(row.first_ts);
    row.last_ts = last.unwrap_or(row.last_ts);
    Ok(())
}

/// `%text%` with the LIKE wildcards of `text` escaped.
fn like_pattern(q: Option<&str>) -> Option<String> {
    let q = q.map(str::trim).filter(|q| !q.is_empty())?;
    let mut out = String::with_capacity(q.len() + 2);
    out.push('%');
    for c in q.chars() {
        if matches!(c, '%' | '_' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('%');
    Some(out)
}

fn size_value(v: Option<u64>) -> Value {
    v.map_or(Value::Null, |v| {
        Value::Integer(i64::try_from(v).unwrap_or(i64::MAX))
    })
}

fn filter_params(f: &ObjectFilter) -> [Value; 6] {
    let text = |v: &Option<String>| v.clone().map_or(Value::Null, Value::Text);
    [
        Value::Integer(i64::from(f.images_only)),
        text(&f.mime),
        text(&f.host),
        like_pattern(f.q.as_deref()).map_or(Value::Null, Value::Text),
        size_value(f.min_size),
        size_value(f.max_size),
    ]
}

/// One page of objects (`descending`: newest or largest first).
pub fn objects_page(
    conn: &Connection,
    filter: &ObjectFilter,
    sort: ObjectSort,
    descending: bool,
    request: &PageRequest,
) -> Result<Page<ObjectRow>> {
    let (where_sql, values) = filter_sql(filter, true);
    let query = Keyset {
        from: FROM,
        select: COLUMNS,
        sort: match sort {
            ObjectSort::Time => "o.id",
            ObjectSort::Size => "o.size",
        },
        tiebreak: "o.id",
        descending,
        filter: Some(&where_sql),
    };
    let params: Vec<&dyn ToSql> = values.iter().map(|v| v as &dyn ToSql).collect();
    let mut page = keyset_page(conn, &query, &params, request, ObjectRow::from_row)?;
    if let Some(r) = filter.range {
        for row in &mut page.items {
            fill_range(conn, row, r)?;
        }
    }
    Ok(page)
}

/// Number of objects matching `filter`.
pub fn count_objects(conn: &Connection, filter: &ObjectFilter) -> Result<u64> {
    let (where_sql, values) = filter_sql(filter, false);
    let sql = format!("SELECT count(*) FROM objects AS o WHERE {where_sql}");
    let n: i64 = conn.query_row(&sql, rusqlite::params_from_iter(values.iter()), |r| {
        r.get(0)
    })?;
    Ok(unsigned(n))
}

/// One object by hex SHA-256.
pub fn object(conn: &Connection, sha256: &str) -> Result<Option<ObjectRow>> {
    let sql = format!("SELECT {COLUMNS} FROM {FROM} WHERE o.sha256 = ?1");
    Ok(conn
        .query_row(&sql, [sha256], ObjectRow::from_row)
        .optional()?)
}

/// Figures of the Pictures view and the options of its filters.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ObjectStats {
    /// Distinct objects and their total size.
    pub count: u64,
    pub bytes: u64,
    /// Transactions and FTP transfers that carried them.
    pub occurrences: u64,
    /// Objects per detected type, most frequent first.
    pub types: Vec<(String, u64)>,
    /// Hosts with the most objects (at most `top_hosts`), most frequent first.
    pub hosts: Vec<(String, u64)>,
}

/// Statistics over the objects (`images_only`: the Pictures view), of those carried by a
/// transaction of `range` when set (occurrences: the transactions of the range).
pub fn stats(
    conn: &Connection,
    images_only: bool,
    top_hosts: u32,
    range: Option<TimeRange>,
) -> Result<ObjectStats> {
    let images = i64::from(images_only);
    let in_range = range.map_or("", |_| {
        " AND o.sha256 IN (SELECT t.resp_sha256 FROM http_transactions t \
          WHERE t.ts >= ?98 AND t.ts < ?99 AND t.resp_sha256 IS NOT NULL \
          UNION ALL SELECT f.sha256 FROM ftp_transfers f \
          WHERE f.ts >= ?98 AND f.ts < ?99 AND f.sha256 IS NOT NULL)"
    });
    let (count, bytes, mut occurrences): (i64, i64, i64) = query_row_ranged(
        conn,
        &format!(
            "SELECT count(*), coalesce(sum(size), 0), coalesce(sum(occurrences), 0) \
             FROM objects o WHERE (?1 = 0 OR mime LIKE 'image/%'){in_range}"
        ),
        &[&images],
        range,
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    if range.is_some() {
        occurrences = query_row_ranged(
            conn,
            "SELECT (SELECT count(*) FROM http_transactions t \
                     JOIN objects o ON o.sha256 = t.resp_sha256 \
                     WHERE t.ts >= ?98 AND t.ts < ?99 AND (?1 = 0 OR o.mime LIKE 'image/%')) \
                  + (SELECT count(*) FROM ftp_transfers f JOIN objects o ON o.sha256 = f.sha256 \
                     WHERE f.ts >= ?98 AND f.ts < ?99 AND (?1 = 0 OR o.mime LIKE 'image/%'))",
            &[&images],
            range,
            |r| r.get(0),
        )?;
    }
    let pairs = |sql: &str, limit: i64| -> Result<Vec<(String, u64)>> {
        query_ranged(conn, sql, &[&images, &limit], range, |r| {
            Ok((r.get::<_, String>(0)?, unsigned(r.get(1)?)))
        })
    };
    Ok(ObjectStats {
        count: unsigned(count),
        bytes: unsigned(bytes),
        occurrences: unsigned(occurrences),
        types: pairs(
            &format!(
                "SELECT mime, count(*) AS n FROM objects o \
                 WHERE (?1 = 0 OR mime LIKE 'image/%'){in_range} \
                 GROUP BY mime ORDER BY n DESC, mime LIMIT ?2"
            ),
            64,
        )?,
        hosts: pairs(
            &format!(
                "SELECT host, count(*) AS n FROM objects o \
                 WHERE host IS NOT NULL AND (?1 = 0 OR mime LIKE 'image/%'){in_range} \
                 GROUP BY host ORDER BY n DESC, host LIMIT ?2"
            ),
            i64::from(top_hosts),
        )?,
    })
}

/// An object waiting for its thumbnail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingThumb {
    pub id: i64,
    pub sha256: String,
    pub size: u64,
    pub mime: String,
}

/// Up to `limit` objects whose thumbnail is still [`thumb::PENDING`], in order of appearance,
/// after the object `after_id` (keyset: pass the last `id` of the previous batch, 0 first).
pub fn pending_thumbs(conn: &Connection, after_id: i64, limit: u32) -> Result<Vec<PendingThumb>> {
    let mut stmt = conn.prepare_cached(
        "SELECT id, sha256, size, mime FROM objects WHERE thumb = 'pending' AND id > ?1 \
         ORDER BY id LIMIT ?2",
    )?;
    let rows = stmt
        .query_map(params![after_id, limit], |r| {
            Ok(PendingThumb {
                id: r.get(0)?,
                sha256: r.get(1)?,
                size: unsigned(r.get(2)?),
                mime: r.get(3)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// Objects whose thumbnail is still [`thumb::PENDING`].
pub fn count_pending_thumbs(conn: &Connection) -> Result<u64> {
    let n: i64 = conn.query_row(
        "SELECT count(*) FROM objects WHERE thumb = 'pending'",
        [],
        |r| r.get(0),
    )?;
    Ok(unsigned(n))
}

/// Outcome of the thumbnail of one object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThumbUpdate {
    pub sha256: String,
    /// [`thumb::READY`] or [`thumb::FAILED`].
    pub state: &'static str,
    /// Dimensions of the decoded image.
    pub width: Option<u32>,
    pub height: Option<u32>,
}

/// Records thumbnail outcomes, in one transaction.
pub fn set_thumbs(conn: &mut Connection, updates: &[ThumbUpdate]) -> Result<()> {
    let tx = conn.transaction()?;
    {
        let mut stmt =
            tx.prepare("UPDATE objects SET thumb = ?2, width = ?3, height = ?4 WHERE sha256 = ?1")?;
        for u in updates {
            stmt.execute(params![u.sha256, u.state, u.width, u.height])?;
        }
    }
    tx.commit()?;
    Ok(())
}

#[cfg(test)]
mod tests;
