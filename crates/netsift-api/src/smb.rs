//! SMB view routes: NetBIOS browser announcements, OS statistics and NTLM authentication
//! sessions. Non-secret metadata only; the secret NTLM material is not served here (and is not
//! persisted: the Credentials tab, task P3.7, owns it).
//!
//! | Method | Path | Response |
//! |---|---|---|
//! | GET | `/sessions/{id}/smb/announces` | [`Page`](crate::contract::Page)`<`[`SmbAnnounceInfo`]`>` |
//! | GET | `/sessions/{id}/smb/stats` | [`SmbStats`] |
//! | GET | `/sessions/{id}/smb/auth` | [`Page`](crate::contract::Page)`<`[`SmbAuthInfo`]`>` |

use std::sync::Arc;

use axum::extract::{Path as UrlPath, State};
use axum::routing::get;
use axum::{Json, Router};
use netsift_store::PageRequest;
use netsift_store::smb::{self, SmbAnnounceEntry, SmbSessionEntry};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::contract::Page;
use crate::endpoint::Endpoint;
use crate::extract::ApiQuery;
use crate::overview::open_ready;
use crate::range::ApiRange;
use crate::sessions::parse_id;
use crate::{ApiError, AppState, blocking, convert};

/// Largest OS slice count returned by `/smb/stats`.
const OS_LIMIT: u32 = 24;

pub(crate) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/sessions/{id}/smb/announces", get(announces))
        .route("/sessions/{id}/smb/stats", get(stats))
        .route("/sessions/{id}/smb/auth", get(auth))
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct PageParams {
    limit: Option<u32>,
    cursor: Option<String>,
}

impl PageParams {
    fn request(self) -> PageRequest {
        PageRequest {
            limit: self.limit.unwrap_or(0),
            cursor: self.cursor,
        }
    }
}

/// One NetBIOS browser announcement, folded per announcing host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct SmbAnnounceInfo {
    /// Address that announced, with what the session knows about it.
    pub source: Endpoint,
    /// `host`, `local_master` or `domain`.
    pub kind: String,
    pub server_name: String,
    /// NetBIOS destination (`WORKGROUP<1D>`).
    pub dst_name: String,
    /// Readable OS label (`Windows 10 / Server 2016+`).
    pub os_label: String,
    /// Announced OS version (`10.0`).
    pub os_version: String,
    /// Announced server roles (`workstation`, `server`, `master_browser`...).
    pub roles: Vec<String>,
    pub comment: String,
    pub announce_count: u64,
    pub first_ts_us: i64,
    pub last_ts_us: i64,
}

fn announce_info(e: SmbAnnounceEntry) -> SmbAnnounceInfo {
    SmbAnnounceInfo {
        source: Endpoint::new(e.src_ip, e.source),
        kind: e.kind,
        server_name: e.server_name,
        dst_name: e.dst_name,
        os_label: e.os_label,
        os_version: format!("{}.{}", e.os_major, e.os_minor),
        roles: smb::server_roles(e.server_type)
            .into_iter()
            .map(str::to_owned)
            .collect(),
        comment: e.comment,
        announce_count: e.announce_count,
        first_ts_us: convert::us(e.first_ts),
        last_ts_us: convert::us(e.last_ts),
    }
}

/// One SMB authentication session (NTLM metadata, no secret).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct SmbAuthInfo {
    /// `flows.id`, as a string (ids can exceed 2^53).
    pub flow_id: String,
    pub first_ts_us: i64,
    pub client: Endpoint,
    pub client_port: u16,
    pub server: Endpoint,
    pub server_port: u16,
    /// `smb1` or `smb2`.
    pub protocol: String,
    pub dialect: Option<String>,
    /// `disabled`, `enabled`, `required` or `unknown`.
    pub signing: String,
    pub domain: Option<String>,
    pub account: Option<String>,
    pub workstation: Option<String>,
    /// Highest NTLM message reached (`negotiate`, `challenge`, `authenticate`).
    pub ntlm_phase: Option<String>,
}

fn auth_info(e: SmbSessionEntry) -> SmbAuthInfo {
    SmbAuthInfo {
        flow_id: e.flow_id.to_string(),
        first_ts_us: convert::us(e.first_ts),
        client: Endpoint::new(e.client_ip, e.client),
        client_port: e.client_port,
        server: Endpoint::new(e.server_ip, e.server),
        server_port: e.server_port,
        protocol: e.protocol,
        dialect: e.dialect,
        signing: e.signing,
        domain: e.domain,
        account: e.account,
        workstation: e.workstation,
        ntlm_phase: e.ntlm_phase,
    }
}

/// One slice of the OS distribution donut.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct OsSlice {
    pub label: String,
    /// Distinct announced servers with this OS.
    pub count: u64,
}

/// `GET /smb/stats`: OS distribution plus the three table counts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct SmbStats {
    pub os: Vec<OsSlice>,
    /// Distinct announcing hosts.
    pub announce_count: u64,
    pub session_count: u64,
    pub auth_count: u64,
}

async fn announces(
    State(state): State<Arc<AppState>>,
    UrlPath(id): UrlPath<String>,
    ApiQuery(query): ApiQuery<PageParams>,
    ApiRange(range): ApiRange,
) -> Result<Json<Page<SmbAnnounceInfo>>, ApiError> {
    let id = parse_id(&id)?;
    blocking(&state, move |s| {
        let (_, session) = open_ready(s, &id)?;
        let range = range.resolve(&session)?;
        let page = smb::announces_page(session.conn(), &query.request(), range)?;
        Ok(Page {
            items: page.items.into_iter().map(announce_info).collect(),
            next_cursor: page.next_cursor,
            total_estimate: Some(smb::count_announces(session.conn(), range)?),
        })
    })
    .await
    .map(Json)
}

async fn auth(
    State(state): State<Arc<AppState>>,
    UrlPath(id): UrlPath<String>,
    ApiQuery(query): ApiQuery<PageParams>,
    ApiRange(range): ApiRange,
) -> Result<Json<Page<SmbAuthInfo>>, ApiError> {
    let id = parse_id(&id)?;
    blocking(&state, move |s| {
        let (_, session) = open_ready(s, &id)?;
        let range = range.resolve(&session)?;
        let page = smb::sessions_page(session.conn(), true, &query.request(), range)?;
        Ok(Page {
            items: page.items.into_iter().map(auth_info).collect(),
            next_cursor: page.next_cursor,
            total_estimate: Some(smb::count_sessions(session.conn(), true, range)?),
        })
    })
    .await
    .map(Json)
}

async fn stats(
    State(state): State<Arc<AppState>>,
    UrlPath(id): UrlPath<String>,
    ApiRange(range): ApiRange,
) -> Result<Json<SmbStats>, ApiError> {
    let id = parse_id(&id)?;
    blocking(&state, move |s| {
        let (_, session) = open_ready(s, &id)?;
        let range = range.resolve(&session)?;
        let conn = session.conn();
        let os = smb::os_distribution(conn, OS_LIMIT, range)?
            .into_iter()
            .map(|(label, count)| OsSlice { label, count })
            .collect();
        Ok(SmbStats {
            os,
            announce_count: smb::count_announces(conn, range)?,
            session_count: smb::count_sessions(conn, false, range)?,
            auth_count: smb::count_sessions(conn, true, range)?,
        })
    })
    .await
    .map(Json)
}

#[cfg(test)]
mod tests;
