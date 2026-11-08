//! HTTP routes (`http` analyzer, views HTTP and HTTP Headers).
//!
//! | Method | Path | Response |
//! |---|---|---|
//! | GET | `/sessions/{id}/http/stats` | [`HttpStats`] |
//! | GET | `/sessions/{id}/http/transactions?limit&cursor&sort&order&method&status&host&q` | `Page<HttpTransactionSummary>` |
//! | GET | `/sessions/{id}/http/transactions/{tid}` | [`HttpTransactionDetail`] |
//! | GET | `/sessions/{id}/http/headers/stats` | [`HttpHeaderStats`] |
//! | GET | `/sessions/{id}/http/headers?limit&cursor&method&name&q` | `Page<HttpTransactionSummary>` |
//!
//! Filters: `method` and `status` are comma-separated lists (absent: no filter, empty: nothing
//! matches); methods are the groups of [`netsift_store::http::METHOD_GROUPS`], statuses are
//! classes (`2xx`, `none`...) or codes (`404`). `q` searches the host, target and user agent
//! (transactions) or the header names and values (headers); `name` keeps transactions having a
//! header of that name. Header values are returned as captured: the UI masks the sensitive
//! ones (`Authorization`, `Cookie`...) by default; they are never logged.
//!
//! Same session rules as the overview: 404 unknown session, 409 while importing or failed.

use std::sync::Arc;

use axum::extract::{Path as UrlPath, State};
use axum::routing::get;
use axum::{Json, Router};
use netsift_store::PageRequest;
use netsift_store::http::{
    self as store, HttpDetail, HttpEntry, HttpFilter, HttpSort, METHOD_GROUPS, STATUS_CLASSES,
};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::contract::Page;
use crate::extract::ApiQuery;
use crate::overview::open_ready;
use crate::sessions::{DEFAULT_LIMIT, MAX_LIMIT, parse_id};
use crate::{ApiError, AppState, blocking, convert};

/// Header names returned by `/http/headers/stats` (autocompletion).
const MAX_HEADER_NAMES: usize = 200;

pub(crate) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/sessions/{id}/http/stats", get(stats))
        .route("/sessions/{id}/http/transactions", get(transactions))
        .route("/sessions/{id}/http/transactions/{tid}", get(transaction))
        .route("/sessions/{id}/http/headers/stats", get(header_stats))
        .route("/sessions/{id}/http/headers", get(headers))
}

/// A label and its number of transactions (or header lines).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct HttpCount {
    pub key: String,
    pub count: u64,
}

fn counts(v: Vec<store::Count>) -> Vec<HttpCount> {
    v.into_iter()
        .map(|c| HttpCount {
            key: c.key,
            count: c.count,
        })
        .collect()
}

/// `GET /sessions/{id}/http/stats`: charts and top lists of the HTTP view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct HttpStats {
    pub transactions: u64,
    /// Method groups present (`GET`...`CONNECT`, `other`), in display order.
    pub methods: Vec<HttpCount>,
    /// Status classes present (`1xx`...`5xx`, `other`, `none` = no response), in order.
    pub status_classes: Vec<HttpCount>,
    /// Most frequent status codes (at most 20), by count.
    pub statuses: Vec<HttpCount>,
    /// Top 10 response media types, and the count of the others.
    pub content_types: Vec<HttpCount>,
    pub content_types_other: u64,
    /// Top 10 hosts, and the number of distinct hosts.
    pub hosts: Vec<HttpCount>,
    pub host_count: u64,
    /// Top 10 user agents, and the number of distinct ones.
    pub user_agents: Vec<HttpCount>,
    pub user_agent_count: u64,
    /// The 10 least used header names (lower case), by number of transactions.
    pub rare_headers: Vec<HttpCount>,
    pub header_count: u64,
}

/// `GET /sessions/{id}/http/headers/stats`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct HttpHeaderStats {
    pub transactions: u64,
    pub header_count: u64,
    /// Method groups present, in display order.
    pub methods: Vec<HttpCount>,
    /// Header names (lower case) by number of lines, most used first (at most 200).
    pub names: Vec<HttpCount>,
}

/// One side of a connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct HttpEndpoint {
    pub ip: String,
    pub port: u16,
}

/// Row of the transaction lists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct HttpTransactionSummary {
    pub id: i64,
    /// Flow (`flows.id`), as a string: it may exceed 2^53.
    pub flow_id: String,
    /// Order of the transaction in its connection.
    pub seq: u32,
    pub client: HttpEndpoint,
    pub server: HttpEndpoint,
    /// Request time, else response time.
    pub ts_us: i64,
    pub end_ts_us: i64,
    /// `null` when the request was not captured.
    pub method: Option<String>,
    /// Request target as sent.
    pub uri: Option<String>,
    pub host: Option<String>,
    pub path: Option<String>,
    pub query: Option<String>,
    pub version: Option<String>,
    /// `null` when there is no response.
    pub status: Option<u16>,
    pub reason: Option<String>,
    /// Response media type.
    pub content_type: Option<String>,
    pub user_agent: Option<String>,
    /// Decoded body sizes.
    pub request_size: Option<u64>,
    pub response_size: u64,
    /// `complete`, `incomplete`, `truncated`, `bomb`, `decode_error`, `not_decoded`,
    /// `malformed`, `none`; `null` without response.
    pub response_state: Option<String>,
    /// Time between the request and the response, when both were seen.
    pub response_time_us: Option<i64>,
}

/// One message of [`HttpTransactionDetail`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct HttpMessageInfo {
    pub ts_us: i64,
    /// Frame of the first byte (global index in the session).
    pub frame: i64,
    /// Start line and headers.
    pub head_size: u64,
    /// Body bytes on the wire (chunked framing included) and decoded.
    pub body_wire_size: u64,
    pub body_size: u64,
    pub body_state: String,
    pub chunked: bool,
    pub content_encoding: Option<String>,
    /// Media type from `Content-Type`.
    pub content_type: Option<String>,
    /// MIME type sniffed from the content.
    pub mime_magic: Option<String>,
    /// SHA-256 of the extracted object (objects are extracted from task P3.6 on).
    pub sha256: Option<String>,
    /// Start of a textual body (at most 4 KiB), to be displayed escaped.
    pub preview: Option<String>,
    pub headers: Vec<HttpHeaderLine>,
}

/// One header line, as captured.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct HttpHeaderLine {
    pub name: String,
    pub value: String,
}

/// `GET /sessions/{id}/http/transactions/{tid}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct HttpTransactionDetail {
    pub summary: HttpTransactionSummary,
    pub referer: Option<String>,
    pub request: Option<HttpMessageInfo>,
    pub response: Option<HttpMessageInfo>,
    /// First and last packet of the connection.
    pub flow_first_ts_us: Option<i64>,
    pub flow_last_ts_us: Option<i64>,
}

fn summary(e: HttpEntry) -> HttpTransactionSummary {
    HttpTransactionSummary {
        id: e.id,
        flow_id: e.flow_id.to_string(),
        seq: e.seq,
        client: HttpEndpoint {
            ip: e.client_ip,
            port: e.client_port,
        },
        server: HttpEndpoint {
            ip: e.server_ip,
            port: e.server_port,
        },
        ts_us: convert::us(e.ts),
        end_ts_us: convert::us(e.end_ts),
        response_time_us: e
            .req_ts
            .zip(e.resp_ts)
            .map(|(req, resp)| convert::us(resp.saturating_sub(req))),
        method: e.method,
        uri: e.uri,
        host: e.host,
        path: e.path,
        query: e.query,
        version: e.version,
        status: e.status,
        reason: e.reason,
        content_type: e.content_type,
        user_agent: e.user_agent,
        request_size: e.req_body_len,
        response_size: e.resp_body_len,
        response_state: e.resp_body_state,
    }
}

fn message(m: store::HttpMessageDetail) -> HttpMessageInfo {
    HttpMessageInfo {
        ts_us: convert::us(m.ts),
        frame: m.frame,
        head_size: m.head_len,
        body_wire_size: m.body_wire,
        body_size: m.body_len,
        body_state: m.body_state,
        chunked: m.chunked,
        content_encoding: m.encoding,
        content_type: m.content_type,
        mime_magic: m.mime_magic,
        sha256: m.sha256,
        preview: m.preview,
        headers: m
            .headers
            .into_iter()
            .map(|(name, value)| HttpHeaderLine { name, value })
            .collect(),
    }
}

fn detail(d: HttpDetail) -> HttpTransactionDetail {
    HttpTransactionDetail {
        summary: summary(d.entry),
        referer: d.referer,
        request: d.request.map(message),
        response: d.response.map(message),
        flow_first_ts_us: d.flow_first_ts.map(convert::us),
        flow_last_ts_us: d.flow_last_ts.map(convert::us),
    }
}

#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
enum SortKey {
    #[default]
    Time,
    Size,
    Status,
}

#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Order {
    Asc,
    #[default]
    Desc,
}

#[derive(Debug, Default, Deserialize)]
struct TransactionsQuery {
    limit: Option<u32>,
    cursor: Option<String>,
    #[serde(default)]
    sort: SortKey,
    #[serde(default)]
    order: Order,
    method: Option<String>,
    status: Option<String>,
    host: Option<String>,
    q: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct HeadersQuery {
    limit: Option<u32>,
    cursor: Option<String>,
    method: Option<String>,
    name: Option<String>,
    q: Option<String>,
}

fn page_request(limit: Option<u32>, cursor: Option<String>) -> PageRequest {
    PageRequest {
        limit: match limit {
            None | Some(0) => DEFAULT_LIMIT,
            Some(n) => n.min(MAX_LIMIT),
        },
        cursor,
    }
}

fn list(raw: Option<&str>) -> Option<Vec<String>> {
    raw.map(|r| {
        r.split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToOwned::to_owned)
            .collect()
    })
}

fn methods(raw: Option<&str>) -> Result<Option<Vec<String>>, ApiError> {
    let methods = list(raw);
    if let Some(m) = methods
        .iter()
        .flatten()
        .find(|m| !METHOD_GROUPS.contains(&m.as_str()))
    {
        return Err(ApiError::BadRequest(format!(
            "method: unknown method group {m:?}"
        )));
    }
    Ok(methods)
}

fn statuses(raw: Option<&str>) -> Result<Option<Vec<String>>, ApiError> {
    let statuses = list(raw);
    let valid = |s: &str| {
        STATUS_CLASSES.contains(&s) || (s.len() == 3 && s.bytes().all(|b| b.is_ascii_digit()))
    };
    if statuses.iter().flatten().any(|s| !valid(s)) {
        return Err(ApiError::BadRequest(
            "status: expected status classes (2xx, none...) or codes".to_owned(),
        ));
    }
    Ok(statuses)
}

fn non_empty(s: Option<String>) -> Option<String> {
    s.map(|s| s.trim().to_owned()).filter(|s| !s.is_empty())
}

async fn stats(
    State(state): State<Arc<AppState>>,
    UrlPath(id): UrlPath<String>,
) -> Result<Json<HttpStats>, ApiError> {
    let id = parse_id(&id)?;
    blocking(&state, move |s| {
        let (_, session) = open_ready(s, &id)?;
        let st = store::stats(session.conn())?;
        Ok(HttpStats {
            transactions: st.transactions,
            methods: counts(st.methods),
            status_classes: counts(st.status_classes),
            statuses: counts(st.statuses),
            content_types: counts(st.content_types),
            content_types_other: st.content_types_other,
            hosts: counts(st.hosts),
            host_count: st.host_count,
            user_agents: counts(st.user_agents),
            user_agent_count: st.user_agent_count,
            rare_headers: counts(st.rare_headers),
            header_count: st.header_count,
        })
    })
    .await
    .map(Json)
}

fn page(
    state: &AppState,
    id: &netsift_store::SessionId,
    filter: &HttpFilter,
    sort: HttpSort,
    descending: bool,
    request: &PageRequest,
) -> Result<Page<HttpTransactionSummary>, ApiError> {
    let (_, session) = open_ready(state, id)?;
    let conn = session.conn();
    let page = store::transactions_page(conn, filter, sort, descending, request)?;
    // Counted with the first page only (the UI keeps it while scrolling).
    let total = if request.cursor.is_none() {
        Some(store::count_transactions(conn, filter)?)
    } else {
        None
    };
    Ok(Page {
        items: page.items.into_iter().map(summary).collect(),
        next_cursor: page.next_cursor,
        total_estimate: total,
    })
}

async fn transactions(
    State(state): State<Arc<AppState>>,
    UrlPath(id): UrlPath<String>,
    ApiQuery(query): ApiQuery<TransactionsQuery>,
) -> Result<Json<Page<HttpTransactionSummary>>, ApiError> {
    let id = parse_id(&id)?;
    let filter = HttpFilter {
        methods: methods(query.method.as_deref())?,
        statuses: statuses(query.status.as_deref())?,
        host: non_empty(query.host),
        q: non_empty(query.q),
        ..HttpFilter::default()
    };
    let sort = match query.sort {
        SortKey::Time => HttpSort::Time,
        SortKey::Size => HttpSort::Size,
        SortKey::Status => HttpSort::Status,
    };
    let descending = matches!(query.order, Order::Desc);
    let request = page_request(query.limit, query.cursor);
    blocking(&state, move |s| {
        page(s, &id, &filter, sort, descending, &request)
    })
    .await
    .map(Json)
}

async fn transaction(
    State(state): State<Arc<AppState>>,
    UrlPath((id, tid)): UrlPath<(String, String)>,
) -> Result<Json<HttpTransactionDetail>, ApiError> {
    let id = parse_id(&id)?;
    let tid: i64 = tid.parse().map_err(|_| ApiError::NotFound)?;
    blocking(&state, move |s| {
        let (_, session) = open_ready(s, &id)?;
        store::transaction(session.conn(), tid)?
            .map(detail)
            .ok_or(ApiError::NotFound)
    })
    .await
    .map(Json)
}

async fn header_stats(
    State(state): State<Arc<AppState>>,
    UrlPath(id): UrlPath<String>,
) -> Result<Json<HttpHeaderStats>, ApiError> {
    let id = parse_id(&id)?;
    blocking(&state, move |s| {
        let (_, session) = open_ready(s, &id)?;
        let conn = session.conn();
        let methods = counts(store::method_counts(conn)?);
        Ok(HttpHeaderStats {
            transactions: methods.iter().map(|m| m.count).sum(),
            header_count: store::header_count(conn)?,
            methods,
            names: counts(store::header_names(conn, MAX_HEADER_NAMES)?),
        })
    })
    .await
    .map(Json)
}

async fn headers(
    State(state): State<Arc<AppState>>,
    UrlPath(id): UrlPath<String>,
    ApiQuery(query): ApiQuery<HeadersQuery>,
) -> Result<Json<Page<HttpTransactionSummary>>, ApiError> {
    let id = parse_id(&id)?;
    let filter = HttpFilter {
        methods: methods(query.method.as_deref())?,
        header_name: non_empty(query.name),
        header_q: non_empty(query.q),
        ..HttpFilter::default()
    };
    let request = page_request(query.limit, query.cursor);
    blocking(&state, move |s| {
        page(s, &id, &filter, HttpSort::Time, true, &request)
    })
    .await
    .map(Json)
}

#[cfg(test)]
mod tests;
