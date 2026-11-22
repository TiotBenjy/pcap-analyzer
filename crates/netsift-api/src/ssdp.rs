//! SSDP view routes (`docs/specs/ssdp.md`): `UPnP` devices, messages with their raw text, and
//! statistics. `LOCATION` URLs are served as text: the application never fetches them.
//!
//! | Method | Path | Response |
//! |---|---|---|
//! | GET | `/sessions/{id}/ssdp/stats` | [`SsdpStats`] |
//! | GET | `/sessions/{id}/ssdp/devices` | [`Page`](crate::contract::Page)`<`[`SsdpDeviceInfo`]`>` |
//! | GET | `/sessions/{id}/ssdp/messages` | [`Page`](crate::contract::Page)`<`[`SsdpMessageInfo`]`>` |
//!
//! Time range (ADR-030): messages and statistics are point records (`ts`); devices are folded
//! rows that overlap the range, with the counters of the whole session.

use std::net::IpAddr;
use std::sync::Arc;

use axum::extract::{Path as UrlPath, State};
use axum::routing::get;
use axum::{Json, Router};
use netsift_store::PageRequest;
use netsift_store::ssdp::{self, SsdpDeviceEntry, SsdpMessageEntry, SsdpMessageFilter};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::contract::Page;
use crate::endpoint::Endpoint;
use crate::extract::ApiQuery;
use crate::overview::open_ready;
use crate::range::ApiRange;
use crate::sessions::parse_id;
use crate::{ApiError, AppState, blocking, convert};

/// Entries of each ranking of `/ssdp/stats`.
const TOP_LIMIT: u32 = 10;
/// Distinct targets listed per device.
const DEVICE_TARGETS: u32 = 16;
/// Longest accepted search text or exact filter value, in bytes.
const MAX_FILTER_LEN: usize = 512;

pub(crate) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/sessions/{id}/ssdp/stats", get(stats))
        .route("/sessions/{id}/ssdp/devices", get(devices))
        .route("/sessions/{id}/ssdp/messages", get(messages))
}

/// Kind of an SSDP message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "lowercase")]
#[ts(export)]
pub enum SsdpKind {
    /// `NOTIFY` announcement.
    Notify,
    /// `M-SEARCH` search.
    Search,
    /// `HTTP/1.1` answer to a search.
    Response,
    /// Anything else on the SSDP port.
    Invalid,
}

impl SsdpKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Notify => "notify",
            Self::Search => "search",
            Self::Response => "response",
            Self::Invalid => "invalid",
        }
    }

    fn from_stored(s: &str) -> Self {
        match s {
            "notify" => Self::Notify,
            "search" => Self::Search,
            "response" => Self::Response,
            _ => Self::Invalid,
        }
    }
}

/// Notification sub-types accepted by the `nts=` filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
enum NtsFilter {
    Alive,
    Byebye,
    Update,
}

impl NtsFilter {
    fn as_str(self) -> &'static str {
        match self {
            Self::Alive => "alive",
            Self::Byebye => "byebye",
            Self::Update => "update",
        }
    }
}

/// One SSDP datagram.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct SsdpMessageInfo {
    /// Row id (key of the list, stable within a session).
    pub id: i64,
    pub ts_us: i64,
    pub source: Endpoint,
    pub src_port: u16,
    pub destination: Endpoint,
    pub dst_port: u16,
    /// The destination is a multicast group.
    pub multicast: bool,
    pub kind: SsdpKind,
    /// `NOTIFY`: `alive`, `byebye`, `update`, or the value as sent.
    pub nts: Option<String>,
    /// Response status code.
    pub status: Option<u16>,
    /// `NT` of a notification, `ST` of a search or response.
    pub target: Option<String>,
    pub usn: Option<String>,
    /// Device identifier (from the USN).
    pub uuid: Option<String>,
    pub server: Option<String>,
    pub user_agent: Option<String>,
    /// URL of the device description: text only, never fetched.
    pub location: Option<String>,
    /// `CACHE-CONTROL: max-age`, seconds.
    pub max_age: Option<u32>,
    /// `MX` of a search, seconds.
    pub mx: Option<u32>,
    /// Datagram size, bytes.
    pub size: u64,
    /// First 2048 bytes as text (LF line ends, control characters replaced). Display as text only.
    pub raw: String,
    /// The datagram is longer than `raw`.
    pub raw_truncated: bool,
}

fn message_info(e: SsdpMessageEntry) -> SsdpMessageInfo {
    SsdpMessageInfo {
        id: e.id,
        ts_us: convert::us(e.ts),
        source: Endpoint::new(e.src_ip, e.source),
        src_port: e.src_port,
        destination: Endpoint::new(e.dst_ip, e.destination),
        dst_port: e.dst_port,
        multicast: e.multicast,
        kind: SsdpKind::from_stored(&e.kind),
        nts: e.nts,
        status: e.status,
        target: e.target,
        usn: e.usn,
        uuid: e.uuid,
        server: e.server,
        user_agent: e.user_agent,
        location: e.location,
        max_age: e.max_age,
        mx: e.mx,
        size: e.size,
        raw: e.raw,
        raw_truncated: e.raw_truncated,
    }
}

/// One `UPnP` device (USN identifier at one address), folded over the session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct SsdpDeviceInfo {
    pub uuid: String,
    /// Announcing address.
    pub address: Endpoint,
    /// Latest `urn:...:device:...` type seen, empty when none.
    pub device_type: String,
    /// Latest `SERVER`, empty when none.
    pub server: String,
    /// Latest `LOCATION` (text only, never fetched), empty when none.
    pub location: String,
    /// Distinct `NT` / `ST` values, sorted, at most 16.
    pub targets: Vec<String>,
    /// Counters of the whole session (also under a time range).
    pub message_count: u64,
    pub alive_count: u64,
    pub byebye_count: u64,
    pub response_count: u64,
    pub first_ts_us: i64,
    pub last_ts_us: i64,
}

fn device_info(e: SsdpDeviceEntry, targets: Vec<String>) -> SsdpDeviceInfo {
    SsdpDeviceInfo {
        uuid: e.uuid,
        address: Endpoint::new(e.ip, e.address),
        device_type: e.device_type,
        server: e.server,
        location: e.location,
        targets,
        message_count: e.message_count,
        alive_count: e.alive_count,
        byebye_count: e.byebye_count,
        response_count: e.response_count,
        first_ts_us: convert::us(e.first_ts),
        last_ts_us: convert::us(e.last_ts),
    }
}

/// One entry of a ranking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct SsdpNameCount {
    pub name: String,
    pub count: u64,
}

/// One sender of the ranking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct SsdpSenderCount {
    pub address: Endpoint,
    pub count: u64,
}

/// `GET /ssdp/stats`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct SsdpStats {
    pub messages: u64,
    pub notify: u64,
    pub alive: u64,
    pub byebye: u64,
    pub update: u64,
    pub search: u64,
    pub response: u64,
    pub invalid: u64,
    /// Devices (overlapping the range under a range).
    pub devices: u64,
    /// Distinct sending addresses.
    pub senders: u64,
    /// Most frequent `NT` / `ST`, at most 10.
    pub targets: Vec<SsdpNameCount>,
    /// Most frequent `SERVER` (else `USER-AGENT`), at most 10.
    pub software: Vec<SsdpNameCount>,
    /// Addresses sending the most messages, at most 10.
    pub top_senders: Vec<SsdpSenderCount>,
}

#[derive(Debug, Default, Deserialize)]
struct DevicesQuery {
    limit: Option<u32>,
    cursor: Option<String>,
    /// Text in the UUID, address, type, server or location.
    q: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct MessagesQuery {
    limit: Option<u32>,
    cursor: Option<String>,
    kind: Option<SsdpKind>,
    nts: Option<NtsFilter>,
    uuid: Option<String>,
    src: Option<IpAddr>,
    target: Option<String>,
    /// Text in the target, USN, server, user agent or location.
    q: Option<String>,
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
) -> Result<Json<SsdpStats>, ApiError> {
    let id = parse_id(&id)?;
    blocking(&state, move |s| {
        let (_, session) = open_ready(s, &id)?;
        let range = range.resolve(&session)?;
        let r = ssdp::stats(session.conn(), TOP_LIMIT, range)?;
        let named = |v: Vec<(String, u64)>| {
            v.into_iter()
                .map(|(name, count)| SsdpNameCount { name, count })
                .collect()
        };
        Ok(SsdpStats {
            messages: r.messages,
            notify: r.notify,
            alive: r.alive,
            byebye: r.byebye,
            update: r.update,
            search: r.search,
            response: r.response,
            invalid: r.invalid,
            devices: r.devices,
            senders: r.senders,
            targets: named(r.targets),
            software: named(r.software),
            top_senders: r
                .senders_top
                .into_iter()
                .map(|(ip, count, info)| SsdpSenderCount {
                    address: Endpoint::new(ip, info),
                    count,
                })
                .collect(),
        })
    })
    .await
    .map(Json)
}

async fn devices(
    State(state): State<Arc<AppState>>,
    UrlPath(id): UrlPath<String>,
    ApiQuery(query): ApiQuery<DevicesQuery>,
    ApiRange(range): ApiRange,
) -> Result<Json<Page<SsdpDeviceInfo>>, ApiError> {
    let id = parse_id(&id)?;
    let q = text("q", query.q)?;
    let request = PageRequest {
        limit: query.limit.unwrap_or(0),
        cursor: query.cursor,
    };
    blocking(&state, move |s| {
        let (_, session) = open_ready(s, &id)?;
        let range = range.resolve(&session)?;
        let conn = session.conn();
        let page = ssdp::devices_page(conn, q.as_deref(), range, &request)?;
        let items = page
            .items
            .into_iter()
            .map(|e| {
                let targets = ssdp::device_targets(conn, &e.uuid, e.ip, DEVICE_TARGETS)?;
                Ok(device_info(e, targets))
            })
            .collect::<Result<Vec<_>, ApiError>>()?;
        Ok(Page {
            items,
            next_cursor: page.next_cursor,
            total_estimate: Some(ssdp::count_devices(conn, q.as_deref(), range)?),
        })
    })
    .await
    .map(Json)
}

async fn messages(
    State(state): State<Arc<AppState>>,
    UrlPath(id): UrlPath<String>,
    ApiQuery(query): ApiQuery<MessagesQuery>,
    ApiRange(range): ApiRange,
) -> Result<Json<Page<SsdpMessageInfo>>, ApiError> {
    let id = parse_id(&id)?;
    let mut filter = SsdpMessageFilter {
        kind: query.kind.map(|k| k.as_str().to_owned()),
        nts: query.nts.map(|n| n.as_str().to_owned()),
        uuid: text("uuid", query.uuid)?.map(|u| u.to_ascii_lowercase()),
        src: query.src,
        target: text("target", query.target)?,
        q: text("q", query.q)?,
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
        let page = ssdp::messages_page(conn, &filter, &request)?;
        Ok(Page {
            items: page.items.into_iter().map(message_info).collect(),
            next_cursor: page.next_cursor,
            total_estimate: Some(ssdp::count_messages(conn, &filter)?),
        })
    })
    .await
    .map(Json)
}

#[cfg(test)]
mod tests;
