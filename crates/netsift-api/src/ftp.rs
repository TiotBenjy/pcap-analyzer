//! FTP view routes (`docs/specs/ftp.md`): control sessions, their transcript, transfers and
//! statistics.
//!
//! | Method | Path | Response |
//! |---|---|---|
//! | GET | `/sessions/{id}/ftp/stats` | [`FtpStats`] |
//! | GET | `/sessions/{id}/ftp/sessions?q&login&limit&cursor` | `Page<`[`FtpSessionInfo`]`>` |
//! | GET | `/sessions/{id}/ftp/sessions/{flow}` | [`FtpSessionDetail`] |
//! | GET | `/sessions/{id}/ftp/transfers?direction&q&session&limit&cursor` | `Page<`[`FtpTransferInfo`]`>` |
//!
//! No list serves a password: only the detail route of a session carries its transcript, whose
//! `PASS` / `ACCT` argument is flagged `secret` (masked by the UI, like a credential detail).
//!
//! Time range (ADR-030): sessions are folded rows that overlap the range (counters of the whole
//! session), transfers are point records (`ts`, the command); the detail is not filtered.

use std::sync::Arc;

use axum::extract::{Path as UrlPath, State};
use axum::routing::get;
use axum::{Json, Router};
use netsift_store::PageRequest;
use netsift_store::ftp::{
    self, FtpLineEntry, FtpSessionEntry, FtpSessionFilter, FtpTransferEntry, FtpTransferFilter,
    LoginFilter,
};
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
/// Transcript lines served by the detail route (the analyzer stores at most as many).
const MAX_LINES: u32 = 2000;
/// Transfers served by the detail route (the analyzer records at most as many).
const MAX_TRANSFERS: u32 = 1000;

pub(crate) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/sessions/{id}/ftp/stats", get(stats))
        .route("/sessions/{id}/ftp/sessions", get(sessions))
        .route("/sessions/{id}/ftp/sessions/{flow}", get(session))
        .route("/sessions/{id}/ftp/transfers", get(transfers))
}

/// Outcome of the login of a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "lowercase")]
#[ts(export)]
pub enum FtpLogin {
    /// A `230` reply was seen.
    Accepted,
    /// Only refusals (`530`...) were seen.
    Rejected,
    /// No login reply (filter value only).
    None,
}

/// What a transfer moves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "lowercase")]
#[ts(export)]
pub enum FtpDirection {
    /// `RETR`.
    Download,
    /// `STOR`, `STOU`, `APPE`.
    Upload,
    /// `LIST`, `NLST`, `MLSD`.
    Listing,
}

impl FtpDirection {
    fn as_str(self) -> &'static str {
        match self {
            Self::Download => "download",
            Self::Upload => "upload",
            Self::Listing => "listing",
        }
    }

    fn from_stored(s: &str) -> Self {
        match s {
            "upload" => Self::Upload,
            "listing" => Self::Listing,
            _ => Self::Download,
        }
    }
}

/// One control session (list row).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct FtpSessionInfo {
    /// Control flow id (string: may exceed 2^53), key of the detail route.
    pub flow_id: String,
    pub client: Endpoint,
    pub client_port: u16,
    pub server: Endpoint,
    pub server_port: u16,
    pub first_ts_us: i64,
    pub last_ts_us: i64,
    /// Text of the first `220` reply.
    pub banner: Option<String>,
    /// Last `USER` argument.
    pub username: Option<String>,
    /// `accepted`, `rejected`, or absent when no login reply was seen.
    pub login: Option<FtpLogin>,
    /// `AUTH TLS` accepted: the rest of the session is encrypted.
    pub tls: bool,
    /// Counters of the whole session (also under a time range).
    pub commands: u64,
    pub replies: u64,
    /// File transfer commands (downloads and uploads).
    pub files: u64,
    pub listings: u64,
    /// Data bytes of the transfers.
    pub bytes: u64,
    /// Transcript lines stored.
    pub lines: u32,
    /// Lines past the bounds (2 000 lines, 256 KiB) were not stored.
    pub transcript_truncated: bool,
    /// Gaps (lost bytes) in the control connection.
    pub gaps: u32,
}

fn session_info(e: FtpSessionEntry) -> FtpSessionInfo {
    let r = e.row;
    FtpSessionInfo {
        flow_id: r.flow_id.to_string(),
        client: Endpoint::new(r.client_ip, e.client),
        client_port: r.client_port,
        server: Endpoint::new(r.server_ip, e.server),
        server_port: r.server_port,
        first_ts_us: convert::us(r.first_ts),
        last_ts_us: convert::us(r.last_ts),
        banner: r.banner,
        username: r.username,
        login: match r.login.as_deref() {
            Some("accepted") => Some(FtpLogin::Accepted),
            Some("rejected") => Some(FtpLogin::Rejected),
            _ => None,
        },
        tls: r.tls,
        commands: r.commands,
        replies: r.replies,
        files: r.files,
        listings: r.listings,
        bytes: r.bytes,
        lines: r.lines,
        transcript_truncated: r.transcript_truncated,
        gaps: r.gaps,
    }
}

/// Kind of a transcript line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "lowercase")]
#[ts(export)]
pub enum FtpLineKind {
    /// Sent by the client.
    Command,
    /// Sent by the server.
    Reply,
    /// Added by the analyzer (`text`: `tls` = the rest is encrypted, `gap` = bytes missing).
    Note,
}

/// One transcript line. Display as text only.
#[derive(Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct FtpLine {
    pub seq: u32,
    pub ts_us: i64,
    pub kind: FtpLineKind,
    /// Verb of a command, or code of a reply with its separator (`230`, `211-`).
    pub head: Option<String>,
    /// Argument of the command, text of the reply, or the note.
    pub text: String,
    /// `text` is a password (`PASS`, `ACCT`): mask it by default.
    pub secret: bool,
    /// The line was longer than the 1 024 bytes kept.
    pub truncated: bool,
}

impl std::fmt::Debug for FtpLine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FtpLine")
            .field("seq", &self.seq)
            .field("kind", &self.kind)
            .field("head", &self.head)
            .field("secret", &self.secret)
            .finish_non_exhaustive()
    }
}

fn line(e: FtpLineEntry) -> FtpLine {
    FtpLine {
        seq: e.seq,
        ts_us: convert::us(e.ts),
        kind: match e.dir.as_str() {
            "c" => FtpLineKind::Command,
            "s" => FtpLineKind::Reply,
            _ => FtpLineKind::Note,
        },
        head: e.head,
        text: e.text,
        secret: e.secret,
        truncated: e.truncated,
    }
}

/// One transfer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct FtpTransferInfo {
    /// Row id (key of the list, stable within a session).
    pub id: i64,
    /// Control flow (string: may exceed 2^53).
    pub flow_id: String,
    /// Order within the session.
    pub seq: u32,
    /// Time of the command.
    pub ts_us: i64,
    pub end_ts_us: Option<i64>,
    /// Verb (`RETR`, `STOR`, `LIST`...).
    pub command: String,
    /// Argument as sent.
    pub path: Option<String>,
    pub direction: FtpDirection,
    /// `active` (`PORT` / `EPRT`) or `passive` (`PASV` / `EPSV`).
    pub mode: Option<String>,
    /// Data connection (string), absent when none was seen.
    pub data_flow_id: Option<String>,
    /// Final reply code and text.
    pub status: Option<u16>,
    pub status_text: Option<String>,
    /// Bytes carried by the data connection.
    pub bytes: u64,
    /// `REST` offset: the content does not start at 0.
    pub restart_offset: Option<u64>,
    /// Bytes are missing from the content (lost segments, size or memory bounds).
    pub truncated: bool,
    /// Stored content: key of `/objects/{sha256}` (download, thumbnail).
    pub sha256: Option<String>,
    /// Type detected from the stored content.
    pub mime: Option<String>,
    /// Start of a listing (4 KiB at most), as text.
    pub listing: Option<String>,
    pub client: Endpoint,
    pub server: Endpoint,
    pub server_port: u16,
    pub username: Option<String>,
}

fn transfer_info(e: FtpTransferEntry) -> FtpTransferInfo {
    FtpTransferInfo {
        id: e.id,
        flow_id: e.flow_id.to_string(),
        seq: e.seq,
        ts_us: convert::us(e.ts),
        end_ts_us: e.end_ts.map(convert::us),
        command: e.command,
        path: e.path,
        direction: FtpDirection::from_stored(&e.direction),
        mode: e.mode,
        data_flow_id: e.data_flow_id.map(|f| f.to_string()),
        status: e.status,
        status_text: e.status_text,
        bytes: e.bytes,
        restart_offset: e.restart_offset,
        truncated: e.truncated,
        sha256: e.sha256,
        mime: e.mime,
        listing: e.listing,
        client: Endpoint::new(e.client_ip, e.client),
        server: Endpoint::new(e.server_ip, e.server),
        server_port: e.server_port,
        username: e.username,
    }
}

/// `GET /ftp/sessions/{flow}`: a session with its transcript and transfers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct FtpSessionDetail {
    pub session: FtpSessionInfo,
    /// Transcript in order (at most 2 000 lines), secrets included and flagged.
    pub lines: Vec<FtpLine>,
    pub transfers: Vec<FtpTransferInfo>,
}

/// `GET /ftp/stats`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct FtpStats {
    /// Sessions (overlapping the range under a range).
    pub sessions: u64,
    pub servers: u64,
    pub clients: u64,
    /// Distinct user names.
    pub users: u64,
    pub logins_accepted: u64,
    pub logins_rejected: u64,
    pub tls_sessions: u64,
    /// Transfers (whose command is within the range under a range).
    pub transfers: u64,
    pub downloads: u64,
    pub uploads: u64,
    pub listings: u64,
    /// Transfers without a `2xx` final reply.
    pub failed: u64,
    /// Data bytes of the transfers.
    pub bytes: u64,
    /// Transfers whose file is stored as an object.
    pub stored: u64,
}

#[derive(Debug, Default, Deserialize)]
struct SessionsQuery {
    limit: Option<u32>,
    cursor: Option<String>,
    /// Text in the addresses, the user name or the banner.
    q: Option<String>,
    login: Option<FtpLogin>,
}

#[derive(Debug, Default, Deserialize)]
struct TransfersQuery {
    limit: Option<u32>,
    cursor: Option<String>,
    direction: Option<FtpDirection>,
    /// Text in the path.
    q: Option<String>,
    /// Control flow id.
    session: Option<i64>,
}

/// A text filter: trimmed, `None` when empty, 400 when too long.
fn text(name: &str, v: Option<String>) -> Result<Option<String>, ApiError> {
    match v.map(|s| s.trim().to_owned()).filter(|s| !s.is_empty()) {
        Some(s) if s.len() > MAX_FILTER_LEN => {
            Err(ApiError::BadRequest(format!("{name}: too long")))
        }
        other => Ok(other),
    }
}

async fn stats(
    State(state): State<Arc<AppState>>,
    UrlPath(id): UrlPath<String>,
    ApiRange(range): ApiRange,
) -> Result<Json<FtpStats>, ApiError> {
    let id = parse_id(&id)?;
    blocking(&state, move |s| {
        let (_, session) = open_ready(s, &id)?;
        let range = range.resolve(&session)?;
        let r = ftp::stats(session.conn(), range)?;
        Ok(FtpStats {
            sessions: r.sessions,
            servers: r.servers,
            clients: r.clients,
            users: r.users,
            logins_accepted: r.logins_accepted,
            logins_rejected: r.logins_rejected,
            tls_sessions: r.tls_sessions,
            transfers: r.transfers,
            downloads: r.downloads,
            uploads: r.uploads,
            listings: r.listings,
            failed: r.failed,
            bytes: r.bytes,
            stored: r.stored,
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
) -> Result<Json<Page<FtpSessionInfo>>, ApiError> {
    let id = parse_id(&id)?;
    let mut filter = FtpSessionFilter {
        q: text("q", query.q)?,
        login: query.login.map(|l| match l {
            FtpLogin::Accepted => LoginFilter::Accepted,
            FtpLogin::Rejected => LoginFilter::Rejected,
            FtpLogin::None => LoginFilter::None,
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
        let page = ftp::sessions_page(conn, &filter, &request)?;
        Ok(Page {
            items: page.items.into_iter().map(session_info).collect(),
            next_cursor: page.next_cursor,
            total_estimate: Some(ftp::count_sessions(conn, &filter)?),
        })
    })
    .await
    .map(Json)
}

async fn session(
    State(state): State<Arc<AppState>>,
    UrlPath((id, flow)): UrlPath<(String, String)>,
) -> Result<Json<FtpSessionDetail>, ApiError> {
    let id = parse_id(&id)?;
    let flow: i64 = flow.parse().map_err(|_| ApiError::NotFound)?;
    blocking(&state, move |s| {
        let (_, session) = open_ready(s, &id)?;
        let conn = session.conn();
        let entry = ftp::session(conn, flow)?.ok_or(ApiError::NotFound)?;
        Ok(FtpSessionDetail {
            session: session_info(entry),
            lines: ftp::lines(conn, flow, MAX_LINES)?
                .into_iter()
                .map(line)
                .collect(),
            transfers: ftp::session_transfers(conn, flow, MAX_TRANSFERS)?
                .into_iter()
                .map(transfer_info)
                .collect(),
        })
    })
    .await
    .map(Json)
}

async fn transfers(
    State(state): State<Arc<AppState>>,
    UrlPath(id): UrlPath<String>,
    ApiQuery(query): ApiQuery<TransfersQuery>,
    ApiRange(range): ApiRange,
) -> Result<Json<Page<FtpTransferInfo>>, ApiError> {
    let id = parse_id(&id)?;
    let mut filter = FtpTransferFilter {
        direction: query.direction.map(FtpDirection::as_str),
        q: text("q", query.q)?,
        session: query.session,
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
        let page = ftp::transfers_page(conn, &filter, &request)?;
        Ok(Page {
            items: page.items.into_iter().map(transfer_info).collect(),
            next_cursor: page.next_cursor,
            total_estimate: Some(ftp::count_transfers(conn, &filter)?),
        })
    })
    .await
    .map(Json)
}

#[cfg(test)]
mod tests;
