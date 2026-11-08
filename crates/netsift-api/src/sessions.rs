//! Session routes: list, details, rename, delete, chunks and anomalies.

use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::{Path as UrlPath, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use netsift_store::catalog::SESSIONS_DIR;
use netsift_store::query::{anomalies_page, chunks_page, get_meta};
use netsift_store::{
    OpenMode, PageRequest, Session, SessionId, SessionInfo, SessionState as StoreState,
};
use serde::Deserialize;

use crate::contract::{AnomalyInfo, ChunkInfo, Page, RenameRequest, SessionSummary};
use crate::convert;
use crate::extract::{ApiJson, ApiQuery};
use crate::{ApiError, AppState, blocking};

/// Default and largest page sizes of the list routes.
pub(crate) const DEFAULT_LIMIT: u32 = 100;
pub(crate) const MAX_LIMIT: u32 = 1000;
/// Longest accepted cursor of the sessions list.
const MAX_CURSOR_LEN: usize = 128;

pub(crate) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/sessions", get(list))
        .route("/sessions/{id}", get(details).patch(rename).delete(delete))
        .route("/sessions/{id}/anomalies", get(anomalies))
        .route("/sessions/{id}/chunks", get(chunks))
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct PageQuery {
    limit: Option<u32>,
    cursor: Option<String>,
}

impl PageQuery {
    fn limit(&self) -> u32 {
        match self.limit {
            None | Some(0) => DEFAULT_LIMIT,
            Some(n) => n.min(MAX_LIMIT),
        }
    }

    fn request(self) -> PageRequest {
        PageRequest {
            limit: self.limit(),
            cursor: self.cursor,
        }
    }
}

/// Unknown or malformed ids are 404, like missing sessions.
pub(crate) fn parse_id(raw: &str) -> Result<SessionId, ApiError> {
    raw.parse().map_err(|_| ApiError::NotFound)
}

pub(crate) fn session_dir(state: &AppState, id: &SessionId) -> PathBuf {
    state.config.data_dir.join(SESSIONS_DIR).join(id.as_str())
}

/// Catalog entry, or 404.
pub(crate) fn info(state: &AppState, id: &SessionId) -> Result<SessionInfo, ApiError> {
    state
        .with_catalog(|c| Ok(c.get(id)?))?
        .ok_or(ApiError::NotFound)
}

/// Opens a session read-only (404 if it or its files are gone).
fn open(state: &AppState, id: &SessionId) -> Result<Session, ApiError> {
    let info = info(state, id)?;
    let dir = session_dir(state, id);
    if !dir.join(netsift_store::session::SESSION_DB).is_file() {
        return Err(ApiError::NotFound);
    }
    Ok(open_db(dir, info.state)?)
}

/// Opens a session database for reading. Finished sessions (`ready`, `incomplete`) created by an
/// older build are upgraded first (ADR-013); one being imported, or failed, is never written.
pub(crate) fn open_db(dir: PathBuf, state: StoreState) -> netsift_store::Result<Session> {
    match state {
        StoreState::Ready | StoreState::Incomplete => Session::open_upgrading(dir),
        StoreState::Importing | StoreState::Failed => Session::open(dir, OpenMode::ReadOnly),
    }
}

/// Figures of a session database (zero when it cannot be opened).
#[derive(Debug, Default)]
pub(crate) struct Stats {
    pub(crate) packets: u64,
    pub(crate) first_ts: Option<i64>,
    pub(crate) last_ts: Option<i64>,
    pub(crate) chunks: u32,
    pub(crate) anomalies: u32,
    pub(crate) flows: u64,
    pub(crate) duration_ms: Option<u64>,
}

fn count(session: &Session, table: &str) -> u32 {
    session
        .conn()
        .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| {
            r.get::<_, i64>(0)
        })
        .ok()
        .and_then(|n| u32::try_from(n).ok())
        .unwrap_or(0)
}

impl Stats {
    pub(crate) fn read(dir: PathBuf, state: StoreState) -> Self {
        open_db(dir, state).map_or_else(|_| Self::default(), |s| Self::of(&s))
    }

    /// Figures of an already open session.
    pub(crate) fn of(session: &Session) -> Self {
        let conn = session.conn();
        let meta = |key: &str| get_meta(conn, key).ok().flatten();
        let meta_i64 = |key: &str| meta(key).and_then(|v| v.parse::<i64>().ok());
        // Written at the end of the import; during it, the chunk rows give the period.
        let (chunk_first, chunk_last) = conn
            .query_row("SELECT min(first_ts), max(last_ts) FROM chunks", [], |r| {
                Ok((r.get::<_, Option<i64>>(0)?, r.get::<_, Option<i64>>(1)?))
            })
            .unwrap_or((None, None));
        Self {
            packets: meta("stats.packets")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0),
            first_ts: meta_i64("stats.first_ts").or(chunk_first),
            last_ts: meta_i64("stats.last_ts").or(chunk_last),
            chunks: count(session, "chunks"),
            anomalies: count(session, "anomalies"),
            flows: netsift_store::query::count_flows(conn).unwrap_or(0),
            duration_ms: meta("stats.duration_ms").and_then(|v| v.parse().ok()),
        }
    }
}

pub(crate) fn summary(state: &AppState, info: &SessionInfo) -> SessionSummary {
    let stats = Stats::read(session_dir(state, &info.id), info.state);
    let live = state.imports.live_progress(&info.id);
    SessionSummary {
        id: info.id.to_string(),
        name: info.name.clone(),
        sources: info
            .sources
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect(),
        created_us: convert::us(info.created_ns),
        state: convert::state(info.state),
        state_detail: public_detail(info.state, info.state_detail.as_deref()),
        first_ts_us: stats.first_ts.map(convert::us),
        last_ts_us: stats.last_ts.map(convert::us),
        source_bytes: info.source_bytes,
        packets: live.map_or(stats.packets, |p| p.packets),
        chunk_count: stats.chunks,
        anomaly_count: stats.anomalies,
    }
}

/// Message of a failed import as shown to clients: the engine's reason may carry paths or SQL
/// details, so it only goes to the log.
pub(crate) const FAILED_MESSAGE: &str = "import failed (details in the application log)";

/// State detail safe to expose: known fixed texts pass, a failure becomes [`FAILED_MESSAGE`],
/// anything else is dropped.
pub(crate) fn public_detail(state: StoreState, detail: Option<&str>) -> Option<String> {
    match state {
        StoreState::Failed => Some(FAILED_MESSAGE.to_owned()),
        _ => detail
            .filter(|d| *d == netsift_engine::INTERRUPTED_DETAIL)
            .map(str::to_owned),
    }
}

/// Cursor of the sessions list: `<created_ns>~<id>` of the last row (newest first).
fn encode_cursor(info: &SessionInfo) -> String {
    format!("{}~{}", info.created_ns, info.id)
}

fn decode_cursor(raw: &str) -> Result<(i64, String), ApiError> {
    let invalid = || ApiError::BadRequest("invalid pagination cursor".to_owned());
    if raw.len() > MAX_CURSOR_LEN {
        return Err(invalid());
    }
    let (ts, id) = raw.split_once('~').ok_or_else(invalid)?;
    Ok((ts.parse().map_err(|_| invalid())?, id.to_owned()))
}

async fn list(
    State(state): State<Arc<AppState>>,
    ApiQuery(query): ApiQuery<PageQuery>,
) -> Result<Json<Page<SessionSummary>>, ApiError> {
    blocking(&state, move |s| {
        let limit = usize::try_from(query.limit()).unwrap_or(usize::MAX);
        let after = query.cursor.as_deref().map(decode_cursor).transpose()?;
        let all = s.with_catalog(|c| Ok(c.list()?))?;
        let total = u64::try_from(all.len()).unwrap_or(u64::MAX);
        // `Catalog::list` is ordered by (created_ns, id) descending.
        let mut rest = all.into_iter().filter(|i| {
            after
                .as_ref()
                .is_none_or(|(ts, id)| (i.created_ns, i.id.as_str()) < (*ts, id.as_str()))
        });
        let page: Vec<SessionInfo> = rest.by_ref().take(limit).collect();
        let next_cursor = if rest.next().is_some() {
            page.last().map(encode_cursor)
        } else {
            None
        };
        Ok(Page {
            items: page.iter().map(|i| summary(s, i)).collect(),
            next_cursor,
            total_estimate: Some(total),
        })
    })
    .await
    .map(Json)
}

async fn details(
    State(state): State<Arc<AppState>>,
    UrlPath(id): UrlPath<String>,
) -> Result<Json<SessionSummary>, ApiError> {
    let id = parse_id(&id)?;
    blocking(&state, move |s| Ok(summary(s, &info(s, &id)?)))
        .await
        .map(Json)
}

async fn rename(
    State(state): State<Arc<AppState>>,
    UrlPath(id): UrlPath<String>,
    ApiJson(req): ApiJson<RenameRequest>,
) -> Result<Json<SessionSummary>, ApiError> {
    let id = parse_id(&id)?;
    blocking(&state, move |s| {
        s.with_catalog(|c| Ok(c.rename(&id, &req.name)?))?;
        Ok(summary(s, &info(s, &id)?))
    })
    .await
    .map(Json)
}

/// Removes the session directory (database, blobs, thumbnails) and its catalog entry. The
/// source captures are only referenced, never touched.
async fn delete(
    State(state): State<Arc<AppState>>,
    UrlPath(id): UrlPath<String>,
) -> Result<StatusCode, ApiError> {
    let id = parse_id(&id)?;
    blocking(&state, move |s| {
        // `importing` in the catalog means a live import: interrupted ones are recovered as
        // `incomplete` at startup. It may run in another process (CLI), outside the registry.
        let running = s.imports.is_running(&id) || info(s, &id)?.state == StoreState::Importing;
        if running {
            return Err(ApiError::Conflict(
                "the import is running; cancel it first".to_owned(),
            ));
        }
        s.with_catalog(|c| Ok(c.delete(&id)?))?;
        s.imports.forget(&id);
        Ok(StatusCode::NO_CONTENT)
    })
    .await
}

fn total(session: &Session, table: &str) -> u64 {
    u64::from(count(session, table))
}

async fn chunks(
    State(state): State<Arc<AppState>>,
    UrlPath(id): UrlPath<String>,
    ApiQuery(query): ApiQuery<PageQuery>,
) -> Result<Json<Page<ChunkInfo>>, ApiError> {
    let id = parse_id(&id)?;
    blocking(&state, move |s| {
        let session = open(s, &id)?;
        let page = chunks_page(session.conn(), &query.request())?;
        Ok(Page {
            items: page.items.into_iter().map(convert::chunk).collect(),
            next_cursor: page.next_cursor,
            total_estimate: Some(total(&session, "chunks")),
        })
    })
    .await
    .map(Json)
}

async fn anomalies(
    State(state): State<Arc<AppState>>,
    UrlPath(id): UrlPath<String>,
    ApiQuery(query): ApiQuery<PageQuery>,
) -> Result<Json<Page<AnomalyInfo>>, ApiError> {
    let id = parse_id(&id)?;
    blocking(&state, move |s| {
        let session = open(s, &id)?;
        let page = anomalies_page(session.conn(), &query.request())?;
        Ok(Page {
            items: page.items.into_iter().map(convert::anomaly).collect(),
            next_cursor: page.next_cursor,
            total_estimate: Some(total(&session, "anomalies")),
        })
    })
    .await
    .map(Json)
}
