//! Telnet view routes (`docs/specs/telnet.md`): sessions, their transcript and statistics.
//!
//! | Method | Path | Response |
//! |---|---|---|
//! | GET | `/sessions/{id}/telnet/stats` | [`TelnetStats`] |
//! | GET | `/sessions/{id}/telnet/sessions` | [`Page`](crate::contract::Page)`<`[`TelnetSessionInfo`]`>` |
//! | GET | `/sessions/{id}/telnet/sessions/{flow}` | [`TelnetSessionDetail`] |
//!
//! Time range (ADR-030): sessions are folded rows, listed and counted when their span overlaps the
//! range, with the counters of the whole connection; the detail is not filtered. Only the detail
//! carries the secrets typed at password prompts (like `/credentials/{entry}`), masked by the UI.

use std::sync::Arc;

use axum::extract::{Path as UrlPath, State};
use axum::routing::get;
use axum::{Json, Router};
use netsift_store::PageRequest;
use netsift_store::telnet::{self, LoginFilter, Speaker, TelnetEntry, TelnetFilter};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::contract::Page;
use crate::endpoint::Endpoint;
use crate::extract::ApiQuery;
use crate::overview::open_ready;
use crate::range::ApiRange;
use crate::sessions::parse_id;
use crate::{ApiError, AppState, blocking, convert};

/// Longest accepted search text, in bytes.
const MAX_FILTER_LEN: usize = 512;

pub(crate) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/sessions/{id}/telnet/stats", get(stats))
        .route("/sessions/{id}/telnet/sessions", get(sessions))
        .route("/sessions/{id}/telnet/sessions/{flow}", get(session))
}

/// Result of the logins of a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "lowercase")]
#[ts(export)]
pub enum TelnetLogin {
    /// One password was accepted.
    Accepted,
    /// Every decided attempt was rejected.
    Rejected,
}

/// `login=` filter of the list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
enum LoginQuery {
    Accepted,
    Rejected,
    /// A password typed without known result.
    Unknown,
    /// No password typed.
    None,
}

/// Window size announced by the client (`NAWS`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct TelnetWindow {
    pub cols: u16,
    pub rows: u16,
}

/// One Telnet connection, without its transcript.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct TelnetSessionInfo {
    /// Flow id (key of the list and of the detail route).
    pub flow_id: i64,
    pub first_ts_us: i64,
    pub last_ts_us: i64,
    pub client: Endpoint,
    pub client_port: u16,
    pub server: Endpoint,
    pub server_port: u16,
    /// Wire bytes of the whole connection, per direction (also under a time range).
    pub client_bytes: u64,
    pub server_bytes: u64,
    /// User of the accepted login, else of the last attempt, else `USER` of `NEW-ENVIRON`.
    pub username: Option<String>,
    /// `USER` sent in `NEW-ENVIRON`.
    pub env_user: Option<String>,
    /// `null` when no password was typed or nothing told the result.
    pub login: Option<TelnetLogin>,
    /// Passwords typed.
    pub login_attempts: u32,
    /// Terminal type (`TTYPE`).
    pub terminal: Option<String>,
    pub window: Option<TelnetWindow>,
    /// Options offered by one side and accepted by the other.
    pub options: Vec<String>,
    /// Size of the transcript (UTF-8 bytes) and its lines.
    pub transcript_bytes: u64,
    pub transcript_lines: u32,
    /// The transcript stopped at its bound (64 KiB or 2000 lines).
    pub truncated: bool,
}

fn info(e: TelnetEntry) -> TelnetSessionInfo {
    TelnetSessionInfo {
        flow_id: e.flow_id,
        first_ts_us: convert::us(e.first_ts),
        last_ts_us: convert::us(e.last_ts),
        client: Endpoint::new(e.client_ip, e.client),
        client_port: e.client_port,
        server: Endpoint::new(e.server_ip, e.server),
        server_port: e.server_port,
        client_bytes: e.client_bytes,
        server_bytes: e.server_bytes,
        username: e.username,
        env_user: e.env_user,
        login: match e.login.as_deref() {
            Some("accepted") => Some(TelnetLogin::Accepted),
            Some("rejected") => Some(TelnetLogin::Rejected),
            _ => None,
        },
        login_attempts: e.login_attempts,
        terminal: e.terminal,
        window: e.window.map(|(cols, rows)| TelnetWindow { cols, rows }),
        options: e.options,
        transcript_bytes: e.transcript_bytes,
        transcript_lines: e.transcript_lines,
        truncated: e.truncated,
    }
}

/// Who produced a run of the transcript.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "lowercase")]
#[ts(export)]
pub enum TelnetSpeaker {
    /// Typed by the client (server echo merged).
    Client,
    /// Output of the server.
    Server,
    /// Typed at a password prompt: sensitive, masked by default.
    Secret,
}

/// One run of the transcript: plain text (line ends `\n`, control characters removed), to be
/// displayed as text only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct TelnetRun {
    pub speaker: TelnetSpeaker,
    pub text: String,
}

/// `GET /telnet/sessions/{flow}`: a session and its transcript, secrets included.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct TelnetSessionDetail {
    pub session: TelnetSessionInfo,
    pub runs: Vec<TelnetRun>,
}

/// `GET /telnet/stats`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct TelnetStats {
    pub sessions: u64,
    /// Distinct client and server addresses.
    pub clients: u64,
    pub servers: u64,
    /// Sessions where a password was typed.
    pub logins: u64,
    pub accepted: u64,
    pub rejected: u64,
    pub truncated: u64,
}

#[derive(Debug, Default, Deserialize)]
struct SessionsQuery {
    limit: Option<u32>,
    cursor: Option<String>,
    /// Text in the addresses, user names, terminal or transcript (never the secrets).
    q: Option<String>,
    login: Option<LoginQuery>,
}

async fn stats(
    State(state): State<Arc<AppState>>,
    UrlPath(id): UrlPath<String>,
    ApiRange(range): ApiRange,
) -> Result<Json<TelnetStats>, ApiError> {
    let id = parse_id(&id)?;
    blocking(&state, move |s| {
        let (_, session) = open_ready(s, &id)?;
        let range = range.resolve(&session)?;
        let r = telnet::stats(session.conn(), range)?;
        Ok(TelnetStats {
            sessions: r.sessions,
            clients: r.clients,
            servers: r.servers,
            logins: r.logins,
            accepted: r.accepted,
            rejected: r.rejected,
            truncated: r.truncated,
        })
    })
    .await
    .map(Json)
}

async fn sessions(
    State(state): State<Arc<AppState>>,
    UrlPath(id): UrlPath<String>,
    ApiQuery(query): ApiQuery<SessionsQuery>,
    ApiRange(range): ApiRange,
) -> Result<Json<Page<TelnetSessionInfo>>, ApiError> {
    let id = parse_id(&id)?;
    let q = query
        .q
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty());
    if q.as_ref().is_some_and(|q| q.len() > MAX_FILTER_LEN) {
        return Err(ApiError::BadRequest("q: too long".to_owned()));
    }
    let mut filter = TelnetFilter {
        q,
        login: query.login.map(|l| match l {
            LoginQuery::Accepted => LoginFilter::Accepted,
            LoginQuery::Rejected => LoginFilter::Rejected,
            LoginQuery::Unknown => LoginFilter::Unknown,
            LoginQuery::None => LoginFilter::None,
        }),
        range: None,
    };
    let request = PageRequest {
        limit: query.limit.unwrap_or(0),
        cursor: query.cursor,
    };
    blocking(&state, move |s| {
        let (_, session) = open_ready(s, &id)?;
        filter.range = range.resolve(&session)?;
        let conn = session.conn();
        let page = telnet::sessions_page(conn, &filter, &request)?;
        Ok(Page {
            items: page.items.into_iter().map(info).collect(),
            next_cursor: page.next_cursor,
            total_estimate: Some(telnet::count_sessions(conn, &filter)?),
        })
    })
    .await
    .map(Json)
}

async fn session(
    State(state): State<Arc<AppState>>,
    UrlPath((id, flow)): UrlPath<(String, String)>,
) -> Result<Json<TelnetSessionDetail>, ApiError> {
    let id = parse_id(&id)?;
    let flow: i64 = flow.parse().map_err(|_| ApiError::NotFound)?;
    blocking(&state, move |s| {
        let (_, session) = open_ready(s, &id)?;
        let detail = telnet::session_detail(session.conn(), flow)?.ok_or(ApiError::NotFound)?;
        Ok(TelnetSessionDetail {
            session: info(detail.entry),
            runs: detail
                .transcript
                .into_iter()
                .map(|r| TelnetRun {
                    speaker: match r.speaker {
                        Speaker::Client => TelnetSpeaker::Client,
                        Speaker::Server => TelnetSpeaker::Server,
                        Speaker::Secret => TelnetSpeaker::Secret,
                    },
                    text: r.text,
                })
                .collect(),
        })
    })
    .await
    .map(Json)
}

#[cfg(test)]
mod tests;
