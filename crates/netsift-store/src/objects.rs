//! Extracted objects (`objects` table, migration `0700_objects.sql`, task P3.6): end-of-import
//! step, thumbnail bookkeeping and the queries of the Pictures view.
//!
//! # Merge rules
//!
//! No shard writes this table. The end-of-import step [`finalize`] derives it from the
//! transactions whose response body was stored (`http_transactions.resp_sha256`): one row per
//! digest, the first occurrence being the smallest `(response time, flow_id, seq)`, the count of
//! occurrences and the last time aggregated over every transaction. The result depends neither
//! on the arrival order of the transactions nor on the number of shards. The step is an upsert
//! that keeps the thumbnail columns (`width`, `height`, `thumb`) of rows already present, so a
//! replay never loses the generated thumbnails.

use rusqlite::types::Value;
use rusqlite::{Connection, OptionalExtension, ToSql, params};

use crate::error::Result;
use crate::query::{Keyset, Page, PageRequest, keyset_page};

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
             last_ts, flow_id, seq, client_ip, server_ip, server_port, host, uri) \
         SELECT sha, size, mime, declared, \
                CASE WHEN mime = 'image/svg+xml' THEN 'none' ELSE 'pending' END, \
                n, first_ts, last_ts, flow_id, seq, client_ip, server_ip, server_port, host, uri \
         FROM ( \
             SELECT t.resp_sha256 AS sha, t.resp_body_len AS size, t.resp_mime_magic AS mime, \
                    t.content_type AS declared, t.flow_id, t.seq, t.client_ip, t.server_ip, \
                    t.server_port, t.host, t.uri, coalesce(t.resp_ts, t.ts) AS first_ts, \
                    count(*) OVER w AS n, max(coalesce(t.resp_ts, t.ts)) OVER w AS last_ts, \
                    row_number() OVER (PARTITION BY t.resp_sha256 \
                        ORDER BY coalesce(t.resp_ts, t.ts), t.flow_id, t.seq) AS rn \
             FROM http_transactions AS t \
             WHERE t.resp_sha256 IS NOT NULL AND t.resp_mime_magic IS NOT NULL \
             WINDOW w AS (PARTITION BY t.resp_sha256) \
         ) WHERE rn = 1 \
         ORDER BY first_ts, flow_id, seq \
         ON CONFLICT (sha256) DO UPDATE SET \
             size = excluded.size, mime = excluded.mime, declared_type = excluded.declared_type, \
             occurrences = excluded.occurrences, first_ts = excluded.first_ts, \
             last_ts = excluded.last_ts, flow_id = excluded.flow_id, seq = excluded.seq, \
             client_ip = excluded.client_ip, server_ip = excluded.server_ip, \
             server_port = excluded.server_port, host = excluded.host, uri = excluded.uri;",
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
    pub client_ip: String,
    pub server_ip: String,
    pub server_port: u16,
    pub host: Option<String>,
    pub uri: Option<String>,
}

const COLUMNS: &str = "o.id, o.sha256, o.size, o.mime, o.declared_type, o.width, o.height, \
                       o.thumb, o.occurrences, o.first_ts, o.last_ts, o.flow_id, o.seq, \
                       o.client_ip, o.server_ip, o.server_port, o.host, o.uri";

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
            client_ip: r.get(13)?,
            server_ip: r.get(14)?,
            server_port: u16::try_from(r.get::<_, i64>(15)?).unwrap_or(0),
            host: r.get(16)?,
            uri: r.get(17)?,
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
    let query = Keyset {
        from: "objects AS o",
        select: COLUMNS,
        sort: match sort {
            ObjectSort::Time => "o.id",
            ObjectSort::Size => "o.size",
        },
        tiebreak: "o.id",
        descending,
        filter: Some(FILTER),
    };
    let values = filter_params(filter);
    let params: Vec<&dyn ToSql> = values.iter().map(|v| v as &dyn ToSql).collect();
    keyset_page(conn, &query, &params, request, ObjectRow::from_row)
}

/// Number of objects matching `filter`.
pub fn count_objects(conn: &Connection, filter: &ObjectFilter) -> Result<u64> {
    let values = filter_params(filter);
    let sql = format!("SELECT count(*) FROM objects AS o WHERE {FILTER}");
    let n: i64 = conn.query_row(&sql, rusqlite::params_from_iter(values.iter()), |r| {
        r.get(0)
    })?;
    Ok(unsigned(n))
}

/// One object by hex SHA-256.
pub fn object(conn: &Connection, sha256: &str) -> Result<Option<ObjectRow>> {
    let sql = format!("SELECT {COLUMNS} FROM objects AS o WHERE o.sha256 = ?1");
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
    /// Transactions that carried them.
    pub occurrences: u64,
    /// Objects per detected type, most frequent first.
    pub types: Vec<(String, u64)>,
    /// Hosts with the most objects (at most `top_hosts`), most frequent first.
    pub hosts: Vec<(String, u64)>,
}

/// Statistics over the objects (`images_only`: the Pictures view).
pub fn stats(conn: &Connection, images_only: bool, top_hosts: u32) -> Result<ObjectStats> {
    let images = i64::from(images_only);
    let (count, bytes, occurrences): (i64, i64, i64) = conn.query_row(
        "SELECT count(*), coalesce(sum(size), 0), coalesce(sum(occurrences), 0) FROM objects \
         WHERE ?1 = 0 OR mime LIKE 'image/%'",
        [images],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    let pairs = |sql: &str, limit: i64| -> Result<Vec<(String, u64)>> {
        let mut stmt = conn.prepare(sql)?;
        let rows = stmt
            .query_map(params![images, limit], |r| {
                Ok((r.get::<_, String>(0)?, unsigned(r.get(1)?)))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    };
    Ok(ObjectStats {
        count: unsigned(count),
        bytes: unsigned(bytes),
        occurrences: unsigned(occurrences),
        types: pairs(
            "SELECT mime, count(*) AS n FROM objects WHERE ?1 = 0 OR mime LIKE 'image/%' \
             GROUP BY mime ORDER BY n DESC, mime LIMIT ?2",
            64,
        )?,
        hosts: pairs(
            "SELECT host, count(*) AS n FROM objects \
             WHERE host IS NOT NULL AND (?1 = 0 OR mime LIKE 'image/%') \
             GROUP BY host ORDER BY n DESC, host LIMIT ?2",
            i64::from(top_hosts),
        )?,
    })
}

/// An object waiting for its thumbnail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingThumb {
    pub sha256: String,
    pub size: u64,
    pub mime: String,
}

/// Objects whose thumbnail is still [`thumb::PENDING`], in order of appearance.
pub fn pending_thumbs(conn: &Connection) -> Result<Vec<PendingThumb>> {
    let mut stmt =
        conn.prepare("SELECT sha256, size, mime FROM objects WHERE thumb = 'pending' ORDER BY id")?;
    let rows = stmt
        .query_map([], |r| {
            Ok(PendingThumb {
                sha256: r.get(0)?,
                size: unsigned(r.get(1)?),
                mime: r.get(2)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
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
