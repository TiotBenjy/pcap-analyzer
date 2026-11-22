//! SIP view routes (`docs/specs/sip.md`): statistics, dialogs and calls with their RTP media,
//! messages with their raw text, and scanners.
//!
//! | Method | Path | Response |
//! |---|---|---|
//! | GET | `/sessions/{id}/sip/stats` | [`SipStats`] |
//! | GET | `/sessions/{id}/sip/dialogs` | [`Page`](crate::contract::Page)`<`[`SipDialogInfo`]`>` |
//! | GET | `/sessions/{id}/sip/messages` | [`Page`](crate::contract::Page)`<`[`SipMessageInfo`]`>` |
//! | GET | `/sessions/{id}/sip/scanners` | `Vec<`[`SipScannerInfo`]`>` |
//!
//! Time range (ADR-030): messages, their statistics and scanners are point records (`ts`);
//! dialogs are folded rows that overlap the range, with the counters of the whole session.

use std::net::IpAddr;
use std::sync::Arc;

use axum::extract::{Path as UrlPath, State};
use axum::routing::get;
use axum::{Json, Router};
use netsift_store::PageRequest;
use netsift_store::sip::{
    self, DialogType, SipDialogEntry, SipDialogFilter, SipMediaEntry, SipMessageEntry,
    SipMessageFilter, SipScannerEntry,
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

/// Entries of each ranking of `/sip/stats`.
const TOP_LIMIT: u32 = 10;
/// Scanners listed by `/sip/scanners`.
const SCANNER_LIMIT: u32 = 50;
/// Longest accepted search text or exact filter value, in bytes.
const MAX_FILTER_LEN: usize = 512;

pub(crate) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/sessions/{id}/sip/stats", get(stats))
        .route("/sessions/{id}/sip/dialogs", get(dialogs))
        .route("/sessions/{id}/sip/messages", get(messages))
        .route("/sessions/{id}/sip/scanners", get(scanners))
}

/// Request or response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "lowercase")]
#[ts(export)]
pub enum SipMessageKind {
    Request,
    Response,
}

impl SipMessageKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Response => "response",
        }
    }
}

/// Type of dialog, from its method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "lowercase")]
#[ts(export)]
pub enum SipDialogType {
    /// INVITE.
    Call,
    /// REGISTER.
    Register,
    /// Any other method.
    Other,
}

impl SipDialogType {
    fn of_method(method: &str) -> Self {
        match method {
            "INVITE" => Self::Call,
            "REGISTER" => Self::Register,
            _ => Self::Other,
        }
    }

    fn store(self) -> DialogType {
        match self {
            Self::Call => DialogType::Call,
            Self::Register => DialogType::Register,
            Self::Other => DialogType::Other,
        }
    }
}

/// Outcome of a dialog (`docs/specs/sip.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "kebab-case")]
#[ts(export)]
pub enum SipDialogState {
    /// Call answered then hung up (BYE).
    Completed,
    /// Call answered, end not seen.
    Answered,
    /// Call cancelled (CANCEL or 487).
    Cancelled,
    /// Final response >= 300.
    Rejected,
    /// No final response.
    NoAnswer,
    /// Non-INVITE dialog accepted (2xx).
    Ok,
}

impl SipDialogState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Answered => "answered",
            Self::Cancelled => "cancelled",
            Self::Rejected => "rejected",
            Self::NoAnswer => "no-answer",
            Self::Ok => "ok",
        }
    }

    fn from_stored(s: &str) -> Self {
        match s {
            "completed" => Self::Completed,
            "answered" => Self::Answered,
            "cancelled" => Self::Cancelled,
            "rejected" => Self::Rejected,
            "ok" => Self::Ok,
            _ => Self::NoAnswer,
        }
    }
}

/// One SIP message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct SipMessageInfo {
    /// Row id (key of the list, stable within a session).
    pub id: i64,
    pub ts_us: i64,
    pub source: Endpoint,
    pub src_port: u16,
    pub destination: Endpoint,
    pub dst_port: u16,
    /// `udp` or `tcp`.
    pub transport: String,
    pub kind: SipMessageKind,
    /// Method of the request, or of the `CSeq` of a response.
    pub method: Option<String>,
    pub status: Option<u16>,
    pub reason: Option<String>,
    pub request_uri: Option<String>,
    pub call_id: Option<String>,
    pub from_uri: Option<String>,
    pub to_uri: Option<String>,
    pub cseq: Option<u32>,
    /// `User-Agent`, else `Server`.
    pub user_agent: Option<String>,
    /// Scanning tool named by the user agent.
    pub scanner: Option<String>,
    /// Digest user name of an `Authorization` header.
    pub auth_user: Option<String>,
    /// Message size, bytes.
    pub size: u64,
    /// First 4096 bytes as text (LF line ends, control characters replaced). Display as text only.
    pub raw: String,
    /// The message is longer than `raw`.
    pub raw_truncated: bool,
}

fn message_info(e: SipMessageEntry) -> SipMessageInfo {
    SipMessageInfo {
        id: e.id,
        ts_us: convert::us(e.ts),
        source: Endpoint::new(e.src_ip, e.source),
        src_port: e.src_port,
        destination: Endpoint::new(e.dst_ip, e.destination),
        dst_port: e.dst_port,
        transport: e.transport,
        kind: if e.kind == "request" {
            SipMessageKind::Request
        } else {
            SipMessageKind::Response
        },
        method: e.method,
        status: e.status,
        reason: e.reason,
        request_uri: e.request_uri,
        call_id: e.call_id,
        from_uri: e.from_uri,
        to_uri: e.to_uri,
        cseq: e.cseq,
        user_agent: e.software,
        scanner: e.scanner,
        auth_user: e.auth_user,
        size: e.size,
        raw: e.raw,
        raw_truncated: e.raw_truncated,
    }
}

/// One media stream announced in the SDP of a dialog, with the UDP flows of its address and port.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct SipMediaInfo {
    /// `audio`, `video`...
    pub media: String,
    pub address: Endpoint,
    /// 0 for a refused media (never joined to flows).
    pub port: u16,
    pub proto: String,
    pub codecs: Vec<String>,
    /// `sendrecv`, `sendonly`, `recvonly`, `inactive`.
    pub direction: Option<String>,
    /// Sender of the first SDP announcing it.
    pub offered_by: String,
    pub offer_ts_us: i64,
    /// UDP flows with this address and port during the dialog.
    pub flow_count: u64,
    pub packets: u64,
    pub bytes: u64,
    /// Smallest flow id, for a link to the flow.
    pub first_flow_id: Option<u64>,
}

fn media_info(m: SipMediaEntry) -> SipMediaInfo {
    SipMediaInfo {
        media: m.media,
        address: Endpoint::new(m.ip, m.address),
        port: m.port,
        proto: m.proto,
        codecs: m.codecs,
        direction: m.direction,
        offered_by: m.offered_by.to_string(),
        offer_ts_us: convert::us(m.offer_ts),
        flow_count: m.flow_count,
        packets: m.packets,
        bytes: m.bytes,
        first_flow_id: m.first_flow_id,
    }
}

/// One dialog (Call-ID), folded over the session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct SipDialogInfo {
    /// Row id (key of the list).
    pub id: i64,
    pub call_id: String,
    pub dialog_type: SipDialogType,
    /// `INVITE`, `REGISTER`, `OPTIONS`...; `UNKNOWN` when only responses were seen.
    pub method: String,
    pub first_ts_us: i64,
    pub last_ts_us: i64,
    /// Sender of the first request.
    pub client: Endpoint,
    pub client_port: u16,
    pub server: Endpoint,
    pub server_port: u16,
    pub transport: String,
    pub from_name: Option<String>,
    pub from_uri: Option<String>,
    pub to_name: Option<String>,
    pub to_uri: Option<String>,
    pub contact: Option<String>,
    pub user_agent: Option<String>,
    pub server_agent: Option<String>,
    /// Counters of the whole session (also under a time range).
    pub requests: u64,
    pub responses: u64,
    pub invite_ts_us: Option<i64>,
    pub ringing_ts_us: Option<i64>,
    pub answer_ts_us: Option<i64>,
    pub bye_ts_us: Option<i64>,
    pub cancelled: bool,
    pub final_status: Option<u16>,
    pub final_reason: Option<String>,
    pub state: SipDialogState,
    /// Answered calls: BYE - answer (`completed`), else last message - answer (`answered`).
    pub duration_us: Option<i64>,
    pub auth_user: Option<String>,
    /// A 401 / 407 challenge was seen.
    pub challenged: bool,
    pub scanner: Option<String>,
    pub media: Vec<SipMediaInfo>,
}

fn dialog_info(e: SipDialogEntry) -> SipDialogInfo {
    let us = |v: Option<i64>| v.map(convert::us);
    SipDialogInfo {
        id: e.id,
        dialog_type: SipDialogType::of_method(&e.method),
        call_id: e.call_id,
        method: e.method,
        first_ts_us: convert::us(e.first_ts),
        last_ts_us: convert::us(e.last_ts),
        client: Endpoint::new(e.client_ip, e.client),
        client_port: e.client_port,
        server: Endpoint::new(e.server_ip, e.server),
        server_port: e.server_port,
        transport: e.transport,
        from_name: e.from_name,
        from_uri: e.from_uri,
        to_name: e.to_name,
        to_uri: e.to_uri,
        contact: e.contact,
        user_agent: e.user_agent,
        server_agent: e.server_agent,
        requests: e.requests,
        responses: e.responses,
        invite_ts_us: us(e.invite_ts),
        ringing_ts_us: us(e.ringing_ts),
        answer_ts_us: us(e.answer_ts),
        bye_ts_us: us(e.bye_ts),
        cancelled: e.cancelled,
        final_status: e.final_status,
        final_reason: e.final_reason,
        state: SipDialogState::from_stored(&e.state),
        duration_us: e.duration_ns.map(|d| d / 1000),
        auth_user: e.auth_user,
        challenged: e.challenged,
        scanner: e.scanner,
        media: e.media.into_iter().map(media_info).collect(),
    }
}

/// One entry of a ranking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct SipNameCount {
    pub name: String,
    pub count: u64,
}

/// One status code of the ranking, with its most frequent reason phrase.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct SipStatusCount {
    pub status: u16,
    pub reason: String,
    pub count: u64,
}

/// One user agent of the ranking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct SipAgentCount {
    pub name: String,
    /// Scanning tool named by this user agent.
    pub scanner: Option<String>,
    pub count: u64,
}

/// Calls in one state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct SipStateCount {
    pub state: SipDialogState,
    pub count: u64,
}

/// `GET /sip/stats`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct SipStats {
    pub messages: u64,
    pub requests: u64,
    pub responses: u64,
    /// Messages whose user agent names a scanning tool.
    pub scanner_messages: u64,
    /// Distinct sending addresses.
    pub senders: u64,
    /// Distinct user agents.
    pub user_agents: u64,
    /// Dialogs (overlapping the range under a range).
    pub dialogs: u64,
    pub calls: u64,
    /// Calls by state.
    pub call_states: Vec<SipStateCount>,
    pub registrations: u64,
    /// Total duration of the completed calls, microseconds.
    pub call_duration_us: i64,
    /// Requests per method, at most 10.
    pub methods: Vec<SipNameCount>,
    /// Most frequent response codes, at most 10.
    pub statuses: Vec<SipStatusCount>,
    /// Most frequent user agents, at most 10.
    pub top_user_agents: Vec<SipAgentCount>,
}

/// One scanning tool seen from one address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct SipScannerInfo {
    pub tool: String,
    pub address: Endpoint,
    pub messages: u64,
    /// Distinct methods sent.
    pub methods: Vec<String>,
    /// Distinct destination addresses.
    pub targets: u64,
    pub first_ts_us: i64,
    pub last_ts_us: i64,
}

fn scanner_info(e: SipScannerEntry) -> SipScannerInfo {
    SipScannerInfo {
        tool: e.tool,
        address: Endpoint::new(e.ip, e.address),
        messages: e.messages,
        methods: e.methods,
        targets: e.targets,
        first_ts_us: convert::us(e.first_ts),
        last_ts_us: convert::us(e.last_ts),
    }
}

#[derive(Debug, Default, Deserialize)]
struct DialogsQuery {
    limit: Option<u32>,
    cursor: Option<String>,
    #[serde(rename = "type")]
    dialog_type: Option<SipDialogType>,
    state: Option<SipDialogState>,
    /// Text in the Call-ID, From, To, user agents or user name.
    q: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct MessagesQuery {
    limit: Option<u32>,
    cursor: Option<String>,
    kind: Option<SipMessageKind>,
    method: Option<String>,
    call_id: Option<String>,
    src: Option<IpAddr>,
    /// Exact user agent.
    agent: Option<String>,
    /// `true`: only the messages of scanners.
    scanner: Option<bool>,
    /// Text in the Call-ID, From, To, request URI or user agent.
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
) -> Result<Json<SipStats>, ApiError> {
    let id = parse_id(&id)?;
    blocking(&state, move |s| {
        let (_, session) = open_ready(s, &id)?;
        let range = range.resolve(&session)?;
        let r = sip::stats(session.conn(), TOP_LIMIT, range)?;
        Ok(SipStats {
            messages: r.messages,
            requests: r.requests,
            responses: r.responses,
            scanner_messages: r.scanner_messages,
            senders: r.senders,
            user_agents: r.agents,
            dialogs: r.dialogs,
            calls: r.calls,
            call_states: r
                .call_states
                .into_iter()
                .map(|(state, count)| SipStateCount {
                    state: SipDialogState::from_stored(&state),
                    count,
                })
                .collect(),
            registrations: r.registrations,
            call_duration_us: r.call_duration_ns / 1000,
            methods: r
                .methods
                .into_iter()
                .map(|(name, count)| SipNameCount { name, count })
                .collect(),
            statuses: r
                .statuses
                .into_iter()
                .map(|(status, reason, count)| SipStatusCount {
                    status,
                    reason,
                    count,
                })
                .collect(),
            top_user_agents: r
                .top_agents
                .into_iter()
                .map(|(name, scanner, count)| SipAgentCount {
                    name,
                    scanner,
                    count,
                })
                .collect(),
        })
    })
    .await
    .map(Json)
}

async fn dialogs(
    State(state): State<Arc<AppState>>,
    UrlPath(id): UrlPath<String>,
    ApiQuery(query): ApiQuery<DialogsQuery>,
    ApiRange(range): ApiRange,
) -> Result<Json<Page<SipDialogInfo>>, ApiError> {
    let id = parse_id(&id)?;
    let mut filter = SipDialogFilter {
        kind: query.dialog_type.map(SipDialogType::store),
        state: query.state.map(|s| s.as_str().to_owned()),
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
        let page = sip::dialogs_page(conn, &filter, &request)?;
        Ok(Page {
            items: page.items.into_iter().map(dialog_info).collect(),
            next_cursor: page.next_cursor,
            total_estimate: Some(sip::count_dialogs(conn, &filter)?),
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
) -> Result<Json<Page<SipMessageInfo>>, ApiError> {
    let id = parse_id(&id)?;
    let mut filter = SipMessageFilter {
        kind: query.kind.map(|k| k.as_str().to_owned()),
        method: text("method", query.method)?.map(|m| m.to_ascii_uppercase()),
        call_id: text("call_id", query.call_id)?,
        src: query.src,
        software: text("agent", query.agent)?,
        scanner: query.scanner.unwrap_or(false),
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
        let page = sip::messages_page(conn, &filter, &request)?;
        Ok(Page {
            items: page.items.into_iter().map(message_info).collect(),
            next_cursor: page.next_cursor,
            total_estimate: Some(sip::count_messages(conn, &filter)?),
        })
    })
    .await
    .map(Json)
}

async fn scanners(
    State(state): State<Arc<AppState>>,
    UrlPath(id): UrlPath<String>,
    ApiRange(range): ApiRange,
) -> Result<Json<Vec<SipScannerInfo>>, ApiError> {
    let id = parse_id(&id)?;
    blocking(&state, move |s| {
        let (_, session) = open_ready(s, &id)?;
        let range = range.resolve(&session)?;
        let rows = sip::scanners(session.conn(), SCANNER_LIMIT, range)?;
        Ok(rows.into_iter().map(scanner_info).collect())
    })
    .await
    .map(Json)
}

#[cfg(test)]
mod tests;
