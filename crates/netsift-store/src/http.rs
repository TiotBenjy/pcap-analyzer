//! HTTP tables (`migrations/0200_http.sql`): rows written by the `http` analyzer and the
//! queries of the HTTP and HTTP Headers views.
//!
//! Rows are plain inserts (one transaction and its headers per record, atomically): the set of
//! rows does not depend on arrival order, only their `id`s do.

use std::net::IpAddr;

use rusqlite::types::Value;
use rusqlite::{Connection, OptionalExtension, Row, ToSql, params};

use crate::connections::EndpointInfo;
use crate::error::{Result, StoreError};
use crate::query::{Keyset, Page, PageRequest, keyset_page};
use crate::records::conversion;

/// Method groups of the filters and charts, in display order (`other`: any other method, or no
/// request).
pub const METHOD_GROUPS: [&str; 9] = [
    "GET", "POST", "HEAD", "OPTIONS", "PUT", "PATCH", "DELETE", "CONNECT", "other",
];
/// Status classes, in display order (`none`: no response).
pub const STATUS_CLASSES: [&str; 7] = ["1xx", "2xx", "3xx", "4xx", "5xx", "other", "none"];
/// Entries of the top lists of [`stats`].
pub const TOP: usize = 10;
/// Status codes returned by [`stats`].
pub const TOP_STATUSES: usize = 20;
/// Searches shorter than this use `LIKE` (the trigram index needs three characters).
const MIN_FTS_CHARS: usize = 3;
/// Longest search text accepted.
pub const MAX_QUERY_CHARS: usize = 256;

/// Group of a method ([`METHOD_GROUPS`]).
pub fn method_group(method: Option<&str>) -> &'static str {
    method
        .and_then(|m| METHOD_GROUPS.iter().find(|g| **g == m).copied())
        .unwrap_or("other")
}

/// Class of a status code ([`STATUS_CLASSES`]).
pub fn status_class(status: Option<u16>) -> &'static str {
    match status {
        None => "none",
        Some(100..=199) => "1xx",
        Some(200..=299) => "2xx",
        Some(300..=399) => "3xx",
        Some(400..=499) => "4xx",
        Some(500..=599) => "5xx",
        Some(_) => "other",
    }
}

/// One message (request or response) of an [`HttpRow`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpMessageRow {
    pub ts: i64,
    pub frame: u64,
    pub head_len: u64,
    pub body_wire: u64,
    pub body_len: u64,
    /// Body state label (`complete`, `truncated`...).
    pub body_state: String,
    pub chunked: bool,
    pub encoding: Option<String>,
    pub mime_magic: Option<String>,
    /// Hex SHA-256 of the extracted object.
    pub sha256: Option<String>,
    pub preview: Option<String>,
    /// Header lines as sent: (name, value).
    pub headers: Vec<(String, String)>,
}

/// One HTTP transaction and its headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRow {
    pub flow_id: u64,
    pub seq: u32,
    pub client_ip: IpAddr,
    pub client_port: u16,
    pub server_ip: IpAddr,
    pub server_port: u16,
    pub ts: i64,
    pub end_ts: i64,
    pub method: Option<String>,
    pub uri: Option<String>,
    pub host: Option<String>,
    pub path: Option<String>,
    pub query: Option<String>,
    pub version: Option<String>,
    pub status: Option<u16>,
    pub reason: Option<String>,
    pub content_type: Option<String>,
    pub user_agent: Option<String>,
    pub referer: Option<String>,
    pub req_content_type: Option<String>,
    pub request: Option<HttpMessageRow>,
    pub response: Option<HttpMessageRow>,
}

fn sat(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

impl HttpRow {
    /// Approximate heap size (writer batches are bounded in bytes).
    pub fn heap_size(&self) -> usize {
        let opt = |s: &Option<String>| s.as_ref().map_or(0, String::len);
        let msg = |m: &Option<HttpMessageRow>| {
            m.as_ref().map_or(0, |m| {
                opt(&m.encoding)
                    + opt(&m.mime_magic)
                    + opt(&m.sha256)
                    + opt(&m.preview)
                    + m.headers
                        .iter()
                        .map(|(n, v)| n.len() + v.len() + 48)
                        .sum::<usize>()
            })
        };
        [
            &self.method,
            &self.uri,
            &self.host,
            &self.path,
            &self.query,
            &self.version,
            &self.reason,
            &self.content_type,
            &self.user_agent,
            &self.referer,
            &self.req_content_type,
        ]
        .into_iter()
        .map(opt)
        .sum::<usize>()
            + msg(&self.request)
            + msg(&self.response)
    }

    pub(crate) fn insert(&self, conn: &Connection) -> Result<()> {
        conn.execute_batch("SAVEPOINT http_row")?;
        let result = self.insert_rows(conn);
        if result.is_err() {
            conn.execute_batch("ROLLBACK TO http_row")?;
        }
        conn.execute_batch("RELEASE http_row")?;
        result
    }

    fn insert_rows(&self, conn: &Connection) -> Result<()> {
        let flow_id = i64::try_from(self.flow_id).map_err(|_| StoreError::InvalidValue {
            field: "http_transactions.flow_id",
            reason: "identifier above i64::MAX",
        })?;
        let req = self.request.as_ref();
        let resp = self.response.as_ref();
        let id: i64 = conn
            .prepare_cached(
                "INSERT INTO http_transactions (flow_id, seq, client_ip, client_port, server_ip, \
                 server_port, ts, end_ts, method, method_group, uri, host, path, query, version, \
                 status, status_key, status_class, reason, content_type, user_agent, referer, \
                 req_ts, req_frame, req_head_len, req_body_wire, req_body_len, req_body_state, \
                 req_chunked, req_encoding, req_content_type, req_mime_magic, req_sha256, \
                 req_preview, resp_ts, resp_frame, resp_head_len, resp_body_wire, resp_body_len, \
                 resp_body_state, resp_chunked, resp_encoding, resp_mime_magic, resp_sha256, \
                 resp_preview) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, \
                 ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27, ?28, ?29, \
                 ?30, ?31, ?32, ?33, ?34, ?35, ?36, ?37, ?38, ?39, ?40, ?41, ?42, ?43, ?44, ?45) \
                 RETURNING id",
            )?
            .query_row(
                params![
                    flow_id,
                    self.seq,
                    self.client_ip.to_string(),
                    self.client_port,
                    self.server_ip.to_string(),
                    self.server_port,
                    self.ts,
                    self.end_ts,
                    self.method,
                    method_group(self.method.as_deref()),
                    self.uri,
                    self.host,
                    self.path,
                    self.query,
                    self.version,
                    self.status,
                    self.status.map_or(-1, i64::from),
                    status_class(self.status),
                    self.reason,
                    self.content_type,
                    self.user_agent,
                    self.referer,
                    req.map(|m| m.ts),
                    req.map(|m| sat(m.frame)),
                    req.map(|m| sat(m.head_len)),
                    req.map(|m| sat(m.body_wire)),
                    req.map(|m| sat(m.body_len)),
                    req.map(|m| m.body_state.as_str()),
                    req.map(|m| m.chunked),
                    req.and_then(|m| m.encoding.as_deref()),
                    self.req_content_type,
                    req.and_then(|m| m.mime_magic.as_deref()),
                    req.and_then(|m| m.sha256.as_deref()),
                    req.and_then(|m| m.preview.as_deref()),
                    resp.map(|m| m.ts),
                    resp.map(|m| sat(m.frame)),
                    resp.map(|m| sat(m.head_len)),
                    resp.map(|m| sat(m.body_wire)),
                    resp.map_or(0, |m| sat(m.body_len)),
                    resp.map(|m| m.body_state.as_str()),
                    resp.map(|m| m.chunked),
                    resp.and_then(|m| m.encoding.as_deref()),
                    resp.and_then(|m| m.mime_magic.as_deref()),
                    resp.and_then(|m| m.sha256.as_deref()),
                    resp.and_then(|m| m.preview.as_deref()),
                ],
                |r| r.get(0),
            )?;
        let mut stmt = conn.prepare_cached(
            "INSERT INTO http_headers (transaction_id, direction, idx, name, name_lc, value) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )?;
        for (direction, message) in [("request", req), ("response", resp)] {
            for (idx, (name, value)) in message.iter().flat_map(|m| m.headers.iter()).enumerate() {
                stmt.execute(params![
                    id,
                    direction,
                    i64::try_from(idx).unwrap_or(i64::MAX),
                    name,
                    name.to_ascii_lowercase(),
                    value,
                ])?;
            }
        }
        Ok(())
    }
}

/// Filters of the transaction lists. `None` = no filter; an empty list matches nothing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HttpFilter {
    /// Method groups ([`METHOD_GROUPS`]).
    pub methods: Option<Vec<String>>,
    /// Status classes ([`STATUS_CLASSES`]) or exact codes (`"404"`).
    pub statuses: Option<Vec<String>>,
    /// Exact host.
    pub host: Option<String>,
    /// Text in the host, target or user agent.
    pub q: Option<String>,
    /// Transactions with a header of this name (case-insensitive).
    pub header_name: Option<String>,
    /// Transactions with a header whose name or value contains this text.
    pub header_q: Option<String>,
}

/// Sort key of the transaction lists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HttpSort {
    #[default]
    Time,
    /// Decoded size of the response body.
    Size,
    Status,
}

/// A transaction as listed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpEntry {
    pub id: i64,
    pub flow_id: i64,
    pub seq: u32,
    pub client_ip: IpAddr,
    pub client_port: u16,
    pub server_ip: IpAddr,
    pub server_port: u16,
    pub ts: i64,
    pub end_ts: i64,
    pub method: Option<String>,
    pub uri: Option<String>,
    pub host: Option<String>,
    pub path: Option<String>,
    pub query: Option<String>,
    pub version: Option<String>,
    pub status: Option<u16>,
    pub reason: Option<String>,
    pub content_type: Option<String>,
    pub user_agent: Option<String>,
    pub req_ts: Option<i64>,
    pub resp_ts: Option<i64>,
    pub req_body_len: Option<u64>,
    pub resp_body_len: u64,
    pub resp_body_state: Option<String>,
    /// What `hosts` knows about both ends.
    pub client: EndpointInfo,
    pub server: EndpointInfo,
}

/// Transactions with the `hosts` rows of both ends.
const ENTRY_FROM: &str = "http_transactions t \
    LEFT JOIN hosts hc ON hc.ip = t.client_ip LEFT JOIN hosts hs ON hs.ip = t.server_ip";
/// Columns of [`ENTRY_COLUMNS`].
const ENTRY_LEN: usize = 30;

const ENTRY_COLUMNS: &str = "t.id, t.flow_id, t.seq, t.client_ip, t.client_port, t.server_ip, \
    t.server_port, t.ts, t.end_ts, t.method, t.uri, t.host, t.path, t.query, t.version, t.status, \
    t.reason, t.content_type, t.user_agent, t.req_ts, t.resp_ts, t.req_body_len, t.resp_body_len, \
    t.resp_body_state, hc.names, hc.category, hc.country, hs.names, hs.category, hs.country";

fn ip(raw: &str, col: usize) -> rusqlite::Result<IpAddr> {
    raw.parse().map_err(|e| conversion(col, e))
}

fn names(raw: Option<String>, col: usize) -> rusqlite::Result<Vec<String>> {
    raw.map_or_else(
        || Ok(Vec::new()),
        |raw| serde_json::from_str(&raw).map_err(|e| conversion(col, e)),
    )
}

impl HttpEntry {
    fn from_row(r: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: r.get(0)?,
            flow_id: r.get(1)?,
            seq: r.get(2)?,
            client_ip: ip(&r.get::<_, String>(3)?, 3)?,
            client_port: r.get(4)?,
            server_ip: ip(&r.get::<_, String>(5)?, 5)?,
            server_port: r.get(6)?,
            ts: r.get(7)?,
            end_ts: r.get(8)?,
            method: r.get(9)?,
            uri: r.get(10)?,
            host: r.get(11)?,
            path: r.get(12)?,
            query: r.get(13)?,
            version: r.get(14)?,
            status: r.get(15)?,
            reason: r.get(16)?,
            content_type: r.get(17)?,
            user_agent: r.get(18)?,
            req_ts: r.get(19)?,
            resp_ts: r.get(20)?,
            req_body_len: r.get(21)?,
            resp_body_len: r.get(22)?,
            resp_body_state: r.get(23)?,
            client: EndpointInfo {
                names: names(r.get(24)?, 24)?,
                category: r.get(25)?,
                country: r.get(26)?,
            },
            server: EndpointInfo {
                names: names(r.get(27)?, 27)?,
                category: r.get(28)?,
                country: r.get(29)?,
            },
        })
    }
}

/// Every filter of [`HttpFilter`], with `NULL` parameters for the unused ones. The sort
/// indexes serve the order (`sort_queries_use_indexes`); the filters themselves are evaluated
/// row by row (building the condition from the active filters only is a follow-up).
pub(crate) const FILTER: &str = "(?1 IS NULL OR t.method_group IN (SELECT value FROM json_each(?1))) \
    AND (?2 IS NULL OR t.status_class IN (SELECT value FROM json_each(?2)) \
         OR CAST(t.status AS TEXT) IN (SELECT value FROM json_each(?2))) \
    AND (?3 IS NULL OR t.host = ?3) \
    AND (?4 IS NULL OR t.id IN (SELECT rowid FROM http_transactions_fts \
         WHERE http_transactions_fts MATCH ?4)) \
    AND (?5 IS NULL OR t.host LIKE ?5 ESCAPE '\\' OR t.uri LIKE ?5 ESCAPE '\\' \
         OR t.user_agent LIKE ?5 ESCAPE '\\') \
    AND ((?6 IS NULL AND ?7 IS NULL AND ?8 IS NULL) OR t.id IN ( \
         SELECT h.transaction_id FROM http_headers h \
         WHERE (?6 IS NULL OR h.name_lc = ?6) \
           AND (?7 IS NULL OR h.id IN (SELECT rowid FROM http_headers_fts \
                WHERE http_headers_fts MATCH ?7)) \
           AND (?8 IS NULL OR h.name LIKE ?8 ESCAPE '\\' OR h.value LIKE ?8 ESCAPE '\\')))";

/// A text search as (FTS5 phrase, LIKE pattern): one of them is used, depending on its length.
fn search(q: Option<&str>) -> Result<(Option<String>, Option<String>)> {
    let Some(q) = q.map(str::trim).filter(|q| !q.is_empty()) else {
        return Ok((None, None));
    };
    if q.chars().count() > MAX_QUERY_CHARS {
        return Err(StoreError::InvalidValue {
            field: "q",
            reason: "search text too long",
        });
    }
    if q.chars().count() >= MIN_FTS_CHARS {
        Ok((Some(format!("\"{}\"", q.replace('"', "\"\""))), None))
    } else {
        let escaped: String = q
            .chars()
            .flat_map(|c| match c {
                '\\' | '%' | '_' => vec!['\\', c],
                c => vec![c],
            })
            .collect();
        Ok((None, Some(format!("%{escaped}%"))))
    }
}

fn json_list(list: Option<&Vec<String>>) -> Result<Option<String>> {
    Ok(list.map(serde_json::to_string).transpose()?)
}

struct FilterParams([Option<String>; 8]);

impl FilterParams {
    fn new(filter: &HttpFilter) -> Result<Self> {
        let (fts, like) = search(filter.q.as_deref())?;
        let (hfts, hlike) = search(filter.header_q.as_deref())?;
        Ok(Self([
            json_list(filter.methods.as_ref())?,
            json_list(filter.statuses.as_ref())?,
            filter.host.clone(),
            fts,
            like,
            filter
                .header_name
                .as_deref()
                .map(|n| n.trim().to_ascii_lowercase())
                .filter(|n| !n.is_empty()),
            hfts,
            hlike,
        ]))
    }

    fn refs(&self) -> Vec<&dyn ToSql> {
        self.0.iter().map(|p| p as &dyn ToSql).collect()
    }
}

/// One page of transactions matching `filter`.
pub fn transactions_page(
    conn: &Connection,
    filter: &HttpFilter,
    sort: HttpSort,
    descending: bool,
    request: &PageRequest,
) -> Result<Page<HttpEntry>> {
    let params = FilterParams::new(filter)?;
    let query = Keyset {
        from: ENTRY_FROM,
        select: ENTRY_COLUMNS,
        sort: match sort {
            HttpSort::Time => "t.ts",
            HttpSort::Size => "t.resp_body_len",
            HttpSort::Status => "t.status_key",
        },
        tiebreak: "t.id",
        descending,
        filter: Some(FILTER),
    };
    keyset_page(conn, &query, &params.refs(), request, HttpEntry::from_row)
}

/// Number of transactions matching `filter`.
pub fn count_transactions(conn: &Connection, filter: &HttpFilter) -> Result<u64> {
    let params = FilterParams::new(filter)?;
    let n: i64 = conn.query_row(
        &format!("SELECT count(*) FROM http_transactions t WHERE {FILTER}"),
        params.refs().as_slice(),
        |r| r.get(0),
    )?;
    Ok(u64::try_from(n).unwrap_or(0))
}

/// One message of an [`HttpDetail`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpMessageDetail {
    pub ts: i64,
    pub frame: i64,
    pub head_len: u64,
    pub body_wire: u64,
    pub body_len: u64,
    pub body_state: String,
    pub chunked: bool,
    pub encoding: Option<String>,
    pub content_type: Option<String>,
    pub mime_magic: Option<String>,
    pub sha256: Option<String>,
    pub preview: Option<String>,
    pub headers: Vec<(String, String)>,
}

/// A transaction with both messages and the times of its flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpDetail {
    pub entry: HttpEntry,
    pub referer: Option<String>,
    pub request: Option<HttpMessageDetail>,
    pub response: Option<HttpMessageDetail>,
    /// First and last packet of the connection, when its flow is recorded.
    pub flow_first_ts: Option<i64>,
    pub flow_last_ts: Option<i64>,
}

fn message_detail(r: &Row<'_>, at: usize) -> rusqlite::Result<Option<HttpMessageDetail>> {
    let ts: Option<i64> = r.get(at)?;
    let Some(ts) = ts else {
        return Ok(None);
    };
    let state: Option<String> = r.get(at + 5)?;
    let chunked: Option<bool> = r.get(at + 6)?;
    Ok(Some(HttpMessageDetail {
        ts,
        frame: r.get::<_, Option<i64>>(at + 1)?.unwrap_or(0),
        head_len: r.get::<_, Option<u64>>(at + 2)?.unwrap_or(0),
        body_wire: r.get::<_, Option<u64>>(at + 3)?.unwrap_or(0),
        body_len: r.get::<_, Option<u64>>(at + 4)?.unwrap_or(0),
        body_state: state.unwrap_or_else(|| "none".to_owned()),
        chunked: chunked.unwrap_or(false),
        encoding: r.get(at + 7)?,
        content_type: r.get(at + 8)?,
        mime_magic: r.get(at + 9)?,
        sha256: r.get(at + 10)?,
        preview: r.get(at + 11)?,
        headers: Vec::new(),
    }))
}

/// One transaction by id, `None` when it does not exist.
pub fn transaction(conn: &Connection, id: i64) -> Result<Option<HttpDetail>> {
    let sql = format!(
        "SELECT {ENTRY_COLUMNS}, t.referer, \
         t.req_ts, t.req_frame, t.req_head_len, t.req_body_wire, t.req_body_len, \
         t.req_body_state, t.req_chunked, t.req_encoding, t.req_content_type, t.req_mime_magic, \
         t.req_sha256, t.req_preview, \
         t.resp_ts, t.resp_frame, t.resp_head_len, t.resp_body_wire, t.resp_body_len, \
         t.resp_body_state, t.resp_chunked, t.resp_encoding, t.content_type, t.resp_mime_magic, \
         t.resp_sha256, t.resp_preview, f.first_ts, f.last_ts \
         FROM {ENTRY_FROM} LEFT JOIN flows f ON f.id = t.flow_id WHERE t.id = ?1"
    );
    let detail = conn
        .query_row(&sql, [id], |r| {
            Ok(HttpDetail {
                entry: HttpEntry::from_row(r)?,
                referer: r.get(ENTRY_LEN)?,
                request: message_detail(r, ENTRY_LEN + 1)?,
                response: message_detail(r, ENTRY_LEN + 13)?,
                flow_first_ts: r.get(ENTRY_LEN + 25)?,
                flow_last_ts: r.get(ENTRY_LEN + 26)?,
            })
        })
        .optional()?;
    let Some(mut detail) = detail else {
        return Ok(None);
    };
    let mut stmt = conn.prepare_cached(
        "SELECT direction, name, value FROM http_headers WHERE transaction_id = ?1 \
         ORDER BY direction, idx",
    )?;
    let rows = stmt.query_map([id], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
        ))
    })?;
    for row in rows {
        let (direction, name, value) = row?;
        let target = if direction == "request" {
            detail.request.as_mut()
        } else {
            detail.response.as_mut()
        };
        if let Some(m) = target {
            m.headers.push((name, value));
        }
    }
    Ok(Some(detail))
}

/// A label and how many times it occurs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Count {
    pub key: String,
    pub count: u64,
}

/// Aggregates of the HTTP view.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HttpStats {
    pub transactions: u64,
    /// Every method group present, in [`METHOD_GROUPS`] order.
    pub methods: Vec<Count>,
    /// Every status class present, in [`STATUS_CLASSES`] order.
    pub status_classes: Vec<Count>,
    /// Most frequent status codes (at most [`TOP_STATUSES`]), by count.
    pub statuses: Vec<Count>,
    /// Most frequent response media types (at most [`TOP`]), and the rest.
    pub content_types: Vec<Count>,
    pub content_types_other: u64,
    pub hosts: Vec<Count>,
    pub host_count: u64,
    pub user_agents: Vec<Count>,
    pub user_agent_count: u64,
    /// Least frequent header names (number of transactions using them).
    pub rare_headers: Vec<Count>,
    pub header_count: u64,
}

fn counts(conn: &Connection, sql: &str, limit: usize) -> Result<Vec<Count>> {
    let mut stmt = conn.prepare(sql)?;
    let rows = stmt.query_map([i64::try_from(limit).unwrap_or(i64::MAX)], |r| {
        let key: Value = r.get(0)?;
        let key = match key {
            Value::Text(s) => s,
            Value::Integer(i) => i.to_string(),
            Value::Null => String::new(),
            _ => return Err(conversion(0, crate::StoreError::InvalidCursor)),
        };
        Ok(Count {
            key,
            count: u64::try_from(r.get::<_, i64>(1)?).unwrap_or(0),
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

fn scalar(conn: &Connection, sql: &str) -> Result<u64> {
    let n: i64 = conn.query_row(sql, [], |r| r.get(0))?;
    Ok(u64::try_from(n).unwrap_or(0))
}

fn ordered(found: Vec<Count>, order: &[&str]) -> Vec<Count> {
    let mut out: Vec<Count> = order
        .iter()
        .filter_map(|k| found.iter().find(|c| c.key == *k).cloned())
        .collect();
    out.extend(
        found
            .into_iter()
            .filter(|c| !order.contains(&c.key.as_str())),
    );
    out
}

/// Method groups with their transaction counts, in display order.
pub fn method_counts(conn: &Connection) -> Result<Vec<Count>> {
    let found = counts(
        conn,
        "SELECT method_group, count(*) FROM http_transactions GROUP BY method_group LIMIT ?1",
        METHOD_GROUPS.len(),
    )?;
    Ok(ordered(found, &METHOD_GROUPS))
}

/// Aggregates of the HTTP view.
pub fn stats(conn: &Connection) -> Result<HttpStats> {
    let transactions = scalar(conn, "SELECT count(*) FROM http_transactions")?;
    let status_classes = ordered(
        counts(
            conn,
            "SELECT status_class, count(*) FROM http_transactions GROUP BY status_class LIMIT ?1",
            STATUS_CLASSES.len(),
        )?,
        &STATUS_CLASSES,
    );
    let statuses = counts(
        conn,
        "SELECT status, count(*) c FROM http_transactions WHERE status IS NOT NULL \
         GROUP BY status ORDER BY c DESC, status LIMIT ?1",
        TOP_STATUSES,
    )?;
    let content_types = counts(
        conn,
        "SELECT content_type, count(*) c FROM http_transactions WHERE content_type IS NOT NULL \
         GROUP BY content_type ORDER BY c DESC, content_type LIMIT ?1",
        TOP,
    )?;
    let typed = scalar(
        conn,
        "SELECT count(*) FROM http_transactions WHERE content_type IS NOT NULL",
    )?;
    let shown: u64 = content_types.iter().map(|c| c.count).sum();
    Ok(HttpStats {
        transactions,
        methods: method_counts(conn)?,
        status_classes,
        statuses,
        content_types,
        content_types_other: typed.saturating_sub(shown),
        hosts: counts(
            conn,
            "SELECT host, count(*) c FROM http_transactions WHERE host IS NOT NULL \
             GROUP BY host ORDER BY c DESC, host LIMIT ?1",
            TOP,
        )?,
        host_count: scalar(conn, "SELECT count(DISTINCT host) FROM http_transactions")?,
        user_agents: counts(
            conn,
            "SELECT user_agent, count(*) c FROM http_transactions WHERE user_agent IS NOT NULL \
             GROUP BY user_agent ORDER BY c DESC, user_agent LIMIT ?1",
            TOP,
        )?,
        user_agent_count: scalar(
            conn,
            "SELECT count(DISTINCT user_agent) FROM http_transactions",
        )?,
        rare_headers: counts(
            conn,
            "SELECT name_lc, count(DISTINCT transaction_id) c FROM http_headers \
             GROUP BY name_lc ORDER BY c, name_lc LIMIT ?1",
            TOP,
        )?,
        header_count: scalar(conn, "SELECT count(*) FROM http_headers")?,
    })
}

/// Header names (lower case) by number of occurrences, most frequent first.
pub fn header_names(conn: &Connection, limit: usize) -> Result<Vec<Count>> {
    counts(
        conn,
        "SELECT name_lc, count(*) c FROM http_headers GROUP BY name_lc ORDER BY c DESC, name_lc \
         LIMIT ?1",
        limit,
    )
}

/// Number of header lines.
pub fn header_count(conn: &Connection) -> Result<u64> {
    scalar(conn, "SELECT count(*) FROM http_headers")
}

#[cfg(test)]
mod tests;
