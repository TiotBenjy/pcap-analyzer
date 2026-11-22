//! ARP view routes (`docs/specs/arp.md`): counters, messages, IP <-> MAC bindings and the
//! addresses claimed by several MAC addresses. Every route applies the global time range
//! (ADR-030).
//!
//! | Method | Path | Response |
//! |---|---|---|
//! | GET | `/sessions/{id}/arp/stats` | [`ArpStats`] |
//! | GET | `/sessions/{id}/arp/messages` | [`Page`]`<`[`ArpMessageInfo`]`>` |
//! | GET | `/sessions/{id}/arp/bindings` | [`Page`]`<`[`ArpBindingInfo`]`>` |
//! | GET | `/sessions/{id}/arp/conflicts` | [`ArpConflicts`] |

use std::net::IpAddr;
use std::sync::Arc;

use axum::extract::{Path as UrlPath, State};
use axum::routing::get;
use axum::{Json, Router};
use netsift_store::PageRequest;
use netsift_store::arp::{
    self, ArpBindingEntry, ArpMessageEntry, BindingFilters, ConflictEntry, MessageFilters,
};
use netsift_store::connections::EndpointInfo;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::contract::Page;
use crate::endpoint::Endpoint;
use crate::extract::ApiQuery;
use crate::overview::open_ready;
use crate::range::ApiRange;
use crate::sessions::parse_id;
use crate::{ApiError, AppState, blocking, convert};

/// Senders listed by `/arp/stats`.
const TOP_SENDERS: u32 = 10;
/// Addresses listed by `/arp/conflicts`, and MAC addresses per address.
const MAX_CONFLICTS: u32 = 100;
const MAX_CONFLICT_MACS: u32 = 16;
/// Longest accepted search text.
const MAX_QUERY_LEN: usize = 64;

pub(crate) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/sessions/{id}/arp/stats", get(stats))
        .route("/sessions/{id}/arp/messages", get(messages))
        .route("/sessions/{id}/arp/bindings", get(bindings))
        .route("/sessions/{id}/arp/conflicts", get(conflicts))
}

/// Message counts per type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct ArpKindCounts {
    pub request: u64,
    pub reply: u64,
    pub gratuitous: u64,
    pub probe: u64,
    pub other: u64,
}

/// One sender of binding messages (an IP and the MAC it was announced at).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct ArpSender {
    pub ip: Endpoint,
    pub mac: String,
    pub messages: u64,
}

/// `GET /arp/stats`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct ArpStats {
    /// Every message (sum of `kinds`).
    pub messages: u64,
    pub kinds: ArpKindCounts,
    /// Replies that no recent request preceded.
    pub unsolicited: u64,
    /// Distinct (IP, MAC) pairs announced.
    pub bindings: u64,
    /// Distinct IP addresses announced.
    pub addresses: u64,
    /// IP addresses announced by several MAC addresses.
    pub conflicts: u64,
    /// Time of the first and last message (`null` without message).
    pub first_ts_us: Option<i64>,
    pub last_ts_us: Option<i64>,
    /// Most active senders of binding messages.
    pub top_senders: Vec<ArpSender>,
}

/// One ARP message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct ArpMessageInfo {
    /// Row id, as a string (unique key of the list).
    pub id: String,
    pub ts_us: i64,
    pub operation: u16,
    /// `request`, `reply`, `gratuitous`, `probe` or `other`.
    pub kind: String,
    pub sender_mac: Option<String>,
    /// Sender address (`null` unless IPv4).
    pub sender: Option<Endpoint>,
    pub target_mac: Option<String>,
    pub target: Option<Endpoint>,
    pub unsolicited: bool,
}

/// One IP <-> MAC binding. Its counters are those of the session, even under a time range.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct ArpBindingInfo {
    pub ip: Endpoint,
    pub mac: String,
    pub first_ts_us: i64,
    pub last_ts_us: i64,
    pub messages: u64,
    pub requests: u64,
    pub replies: u64,
    pub gratuitous: u64,
    pub unsolicited: u64,
    /// Another MAC address claims this IP.
    pub conflict: bool,
}

/// One MAC address of a conflict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct ArpConflictMac {
    pub mac: String,
    pub first_ts_us: i64,
    pub last_ts_us: i64,
    pub messages: u64,
    pub gratuitous: u64,
    pub unsolicited: u64,
    /// Other IP addresses this MAC address claims.
    pub other_ips: u64,
}

/// Why a conflict may be a spoofing attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum ArpSign {
    /// Two MAC addresses were active over overlapping periods.
    Simultaneous,
    /// The periods do not overlap: the address changed hands.
    Successive,
    /// One of them sent gratuitous ARP for the address.
    Gratuitous,
    /// One of them sent unsolicited replies for the address.
    Unsolicited,
    /// One of them also claims other addresses.
    MultipleIps,
}

impl ArpSign {
    fn of(label: &str) -> Option<Self> {
        Some(match label {
            "simultaneous" => Self::Simultaneous,
            "successive" => Self::Successive,
            "gratuitous" => Self::Gratuitous,
            "unsolicited" => Self::Unsolicited,
            "multiple_ips" => Self::MultipleIps,
            _ => return None,
        })
    }
}

/// An IP address claimed by several MAC addresses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct ArpConflict {
    pub ip: Endpoint,
    /// Every MAC address of the conflict (`macs` holds at most 16).
    pub mac_count: u64,
    /// By first activity.
    pub macs: Vec<ArpConflictMac>,
    pub signs: Vec<ArpSign>,
}

/// `GET /arp/conflicts`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct ArpConflicts {
    /// At most 100 addresses, most MAC addresses first.
    pub items: Vec<ArpConflict>,
    /// Every conflicting address.
    pub total: u64,
}

fn endpoint(ip: Option<IpAddr>, info: EndpointInfo) -> Option<Endpoint> {
    ip.map(|ip| Endpoint::new(ip, info))
}

fn message_info(e: ArpMessageEntry) -> ArpMessageInfo {
    ArpMessageInfo {
        id: e.id.to_string(),
        ts_us: convert::us(e.ts),
        operation: e.operation,
        kind: e.kind,
        sender_mac: e.sender_mac,
        sender: endpoint(e.sender_ip, e.sender),
        target_mac: e.target_mac,
        target: endpoint(e.target_ip, e.target),
        unsolicited: e.unsolicited,
    }
}

fn binding_info(e: ArpBindingEntry) -> ArpBindingInfo {
    ArpBindingInfo {
        ip: Endpoint::new(e.ip, e.info),
        mac: e.mac,
        first_ts_us: convert::us(e.first_ts),
        last_ts_us: convert::us(e.last_ts),
        messages: e.messages,
        requests: e.requests,
        replies: e.replies,
        gratuitous: e.gratuitous,
        unsolicited: e.unsolicited,
        conflict: e.conflict,
    }
}

fn conflict_info(e: ConflictEntry) -> ArpConflict {
    ArpConflict {
        ip: Endpoint::new(e.ip, e.info),
        mac_count: e.mac_count,
        macs: e
            .sides
            .into_iter()
            .map(|s| ArpConflictMac {
                mac: s.mac,
                first_ts_us: convert::us(s.first_ts),
                last_ts_us: convert::us(s.last_ts),
                messages: s.messages,
                gratuitous: s.gratuitous,
                unsolicited: s.unsolicited,
                other_ips: s.other_ips,
            })
            .collect(),
        signs: e.signs.iter().filter_map(|s| ArpSign::of(s)).collect(),
    }
}

#[derive(Debug, Default, Deserialize)]
struct MessageParams {
    limit: Option<u32>,
    cursor: Option<String>,
    /// Comma-separated types.
    kind: Option<String>,
    ip: Option<String>,
    mac: Option<String>,
    #[serde(default)]
    unsolicited: bool,
}

/// Normalizes a MAC address (`aa:bb:..`, `aa-bb-..`, any case) to the stored text.
fn parse_mac(raw: &str) -> Option<String> {
    let parts: Vec<&str> = raw.trim().split([':', '-']).collect();
    if parts.len() != 6 {
        return None;
    }
    let mut bytes = [0u8; 6];
    for (b, p) in bytes.iter_mut().zip(&parts) {
        if p.len() != 2 {
            return None;
        }
        *b = u8::from_str_radix(p, 16).ok()?;
    }
    Some(netsift_store::records::format_mac(bytes))
}

impl MessageParams {
    fn filters(&self) -> Result<MessageFilters, ApiError> {
        let mut kinds = Vec::new();
        for k in self
            .kind
            .as_deref()
            .unwrap_or("")
            .split(',')
            .map(str::trim)
            .filter(|k| !k.is_empty())
        {
            if !arp::KINDS.contains(&k) {
                return Err(ApiError::BadRequest("kind: unknown message type".to_owned()));
            }
            if !kinds.iter().any(|x: &String| x == k) {
                kinds.push(k.to_owned());
            }
        }
        let ip = self
            .ip
            .as_deref()
            .map(|raw| {
                raw.trim()
                    .parse::<IpAddr>()
                    .map_err(|_| ApiError::BadRequest("ip: not an IP address".to_owned()))
            })
            .transpose()?;
        let mac = self
            .mac
            .as_deref()
            .map(|raw| {
                parse_mac(raw)
                    .ok_or_else(|| ApiError::BadRequest("mac: not a MAC address".to_owned()))
            })
            .transpose()?;
        Ok(MessageFilters {
            kinds,
            ip,
            mac,
            unsolicited: self.unsolicited,
        })
    }

    fn request(&self) -> PageRequest {
        PageRequest {
            limit: self.limit.unwrap_or(0),
            cursor: self.cursor.clone(),
        }
    }
}

#[derive(Debug, Default, Deserialize)]
struct BindingParams {
    limit: Option<u32>,
    cursor: Option<String>,
    q: Option<String>,
    #[serde(default)]
    conflicts: bool,
}

impl BindingParams {
    fn filters(&self) -> Result<BindingFilters, ApiError> {
        if self.q.as_ref().is_some_and(|q| q.len() > MAX_QUERY_LEN) {
            return Err(ApiError::BadRequest("q: too long".to_owned()));
        }
        Ok(BindingFilters {
            q: self.q.clone(),
            conflicts: self.conflicts,
        })
    }
}

async fn stats(
    State(state): State<Arc<AppState>>,
    UrlPath(id): UrlPath<String>,
    ApiRange(range): ApiRange,
) -> Result<Json<ArpStats>, ApiError> {
    let id = parse_id(&id)?;
    blocking(&state, move |s| {
        let (_, session) = open_ready(s, &id)?;
        let range = range.resolve(&session)?;
        let conn = session.conn();
        let counts = arp::kind_counts(conn, range)?;
        let figures = arp::binding_figures(conn, range)?;
        let period = arp::period(conn, range)?;
        let top_senders = arp::top_senders(conn, TOP_SENDERS, range)?
            .into_iter()
            .map(|e| ArpSender {
                ip: Endpoint::new(e.ip, e.info),
                mac: e.mac,
                messages: e.messages,
            })
            .collect();
        Ok(ArpStats {
            messages: counts.total(),
            kinds: ArpKindCounts {
                request: counts.get("request"),
                reply: counts.get("reply"),
                gratuitous: counts.get("gratuitous"),
                probe: counts.get("probe"),
                other: counts.get("other"),
            },
            unsolicited: counts.unsolicited,
            bindings: figures.bindings,
            addresses: figures.addresses,
            conflicts: figures.conflicts,
            first_ts_us: period.map(|(f, _)| convert::us(f)),
            last_ts_us: period.map(|(_, l)| convert::us(l)),
            top_senders,
        })
    })
    .await
    .map(Json)
}

async fn messages(
    State(state): State<Arc<AppState>>,
    UrlPath(id): UrlPath<String>,
    ApiQuery(query): ApiQuery<MessageParams>,
    ApiRange(range): ApiRange,
) -> Result<Json<Page<ArpMessageInfo>>, ApiError> {
    let id = parse_id(&id)?;
    let filters = query.filters()?;
    let request = query.request();
    blocking(&state, move |s| {
        let (_, session) = open_ready(s, &id)?;
        let range = range.resolve(&session)?;
        let conn = session.conn();
        // Counted on the first page only: the next ones are read by the same list.
        let total = if request.cursor.is_none() {
            Some(arp::count_messages(conn, &filters, range)?)
        } else {
            None
        };
        let page = arp::messages_page(conn, &filters, &request, range)?;
        Ok(Page {
            items: page.items.into_iter().map(message_info).collect(),
            next_cursor: page.next_cursor,
            total_estimate: total,
        })
    })
    .await
    .map(Json)
}

async fn bindings(
    State(state): State<Arc<AppState>>,
    UrlPath(id): UrlPath<String>,
    ApiQuery(query): ApiQuery<BindingParams>,
    ApiRange(range): ApiRange,
) -> Result<Json<Page<ArpBindingInfo>>, ApiError> {
    let id = parse_id(&id)?;
    let filters = query.filters()?;
    let request = PageRequest {
        limit: query.limit.unwrap_or(0),
        cursor: query.cursor,
    };
    blocking(&state, move |s| {
        let (_, session) = open_ready(s, &id)?;
        let range = range.resolve(&session)?;
        let conn = session.conn();
        let total = if request.cursor.is_none() {
            Some(arp::count_bindings(conn, &filters, range)?)
        } else {
            None
        };
        let page = arp::bindings_page(conn, &filters, &request, range)?;
        Ok(Page {
            items: page.items.into_iter().map(binding_info).collect(),
            next_cursor: page.next_cursor,
            total_estimate: total,
        })
    })
    .await
    .map(Json)
}

async fn conflicts(
    State(state): State<Arc<AppState>>,
    UrlPath(id): UrlPath<String>,
    ApiRange(range): ApiRange,
) -> Result<Json<ArpConflicts>, ApiError> {
    let id = parse_id(&id)?;
    blocking(&state, move |s| {
        let (_, session) = open_ready(s, &id)?;
        let range = range.resolve(&session)?;
        let (items, total) =
            arp::conflicts(session.conn(), MAX_CONFLICTS, MAX_CONFLICT_MACS, range)?;
        Ok(ArpConflicts {
            items: items.into_iter().map(conflict_info).collect(),
            total,
        })
    })
    .await
    .map(Json)
}

#[cfg(test)]
mod tests;
