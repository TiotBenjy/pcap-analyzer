//! Connections routes: conversations between hosts, top N matrix and countries.
//!
//! | Method | Path | Response |
//! |---|---|---|
//! | GET | `/sessions/{id}/connections?limit&cursor&sort&order&from&to&protocol&category` | `Page<ConversationInfo>` |
//! | GET | `/sessions/{id}/connections/stats` | [`ConnectionStats`] |
//! | GET | `/sessions/{id}/connections/top?n&exclude_dns` | [`ConnectionMatrix`] |
//!
//! A conversation gathers the flows initiated by one host (`src`) towards another (`dst`).
//! Like the overview routes: 404 for an unknown session, 409 while importing or failed.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Path as UrlPath, State};
use axum::routing::get;
use axum::{Json, Router};
use netsift_store::connections::{
    self as store, ConversationEntry, ConversationFilter, ConversationSort, CountryTraffic,
    TrafficSide,
};
use netsift_store::{PageRequest, SessionId};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::contract::Page;
use crate::endpoint::{Endpoint, parse_categories};
use crate::extract::ApiQuery;
use crate::overview::open_ready;
use crate::sessions::{DEFAULT_LIMIT, MAX_LIMIT, parse_id};
use crate::{ApiError, AppState, blocking, convert};

/// Top N sizes accepted by `/connections/top`.
pub(crate) const TOP_SIZES: [u32; 3] = [10, 20, 50];
/// Named nodes of the chord matrix; the others are folded into one "other" node.
pub(crate) const MAX_NODES: usize = 15;
/// Longest text filter accepted.
const MAX_FILTER_LEN: usize = 256;

pub(crate) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/sessions/{id}/connections", get(list))
        .route("/sessions/{id}/connections/stats", get(stats))
        .route("/sessions/{id}/connections/top", get(top))
}

/// Row of the conversations table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct ConversationInfo {
    /// Row id as a string (pagination key, stable within a session).
    pub id: String,
    /// Initiator of the flows.
    pub src: Endpoint,
    pub dst: Endpoint,
    /// `src` -> `dst`.
    pub bytes_fwd: u64,
    /// `dst` -> `src`.
    pub bytes_rev: u64,
    pub bytes_total: u64,
    pub packets_fwd: u64,
    pub packets_rev: u64,
    pub packets_total: u64,
    pub flows: u64,
    /// Protocol labels of the flows (`dns`, `http`, `tls`, `tcp`, `udp`, `icmp`...), sorted.
    pub protocols: Vec<String>,
    pub first_ts_us: i64,
    pub last_ts_us: i64,
    pub duration_us: i64,
}

impl From<ConversationEntry> for ConversationInfo {
    fn from(e: ConversationEntry) -> Self {
        let r = e.row;
        Self {
            id: e.id.to_string(),
            src: Endpoint::new(r.src_ip, e.src),
            dst: Endpoint::new(r.dst_ip, e.dst),
            bytes_fwd: r.bytes_fwd,
            bytes_rev: r.bytes_rev,
            bytes_total: r.bytes_fwd.saturating_add(r.bytes_rev),
            packets_fwd: r.packets_fwd,
            packets_rev: r.packets_rev,
            packets_total: r.packets_fwd.saturating_add(r.packets_rev),
            flows: r.flows,
            protocols: r.protocols,
            first_ts_us: convert::us(r.first_ts),
            last_ts_us: convert::us(r.last_ts),
            duration_us: convert::us(r.last_ts.saturating_sub(r.first_ts)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SortKey {
    #[default]
    Bytes,
    Packets,
    Flows,
    FirstTs,
    LastTs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Order {
    Asc,
    #[default]
    Desc,
}

#[derive(Debug, Default, Deserialize)]
struct ListQuery {
    limit: Option<u32>,
    cursor: Option<String>,
    #[serde(default)]
    sort: SortKey,
    #[serde(default)]
    order: Order,
    /// Substring of the source IP or of one of its names.
    from: Option<String>,
    /// Substring of the destination IP or of one of its names.
    to: Option<String>,
    /// Protocol label carried by at least one flow.
    protocol: Option<String>,
    /// Comma-separated address categories; one end must match.
    category: Option<String>,
}

fn text(field: &'static str, v: Option<String>) -> Result<Option<String>, ApiError> {
    match v {
        Some(s) if s.len() > MAX_FILTER_LEN => {
            Err(ApiError::BadRequest(format!("{field}: too long")))
        }
        Some(s) if s.trim().is_empty() => Ok(None),
        other => Ok(other),
    }
}

pub(crate) fn page_request(limit: Option<u32>, cursor: Option<String>) -> PageRequest {
    PageRequest {
        limit: match limit {
            None | Some(0) => DEFAULT_LIMIT,
            Some(n) => n.min(MAX_LIMIT),
        },
        cursor,
    }
}

fn build_list(
    state: &AppState,
    id: &SessionId,
    q: ListQuery,
) -> Result<Page<ConversationInfo>, ApiError> {
    let filter = ConversationFilter {
        from: text("from", q.from)?,
        to: text("to", q.to)?,
        protocol: text("protocol", q.protocol)?.map(|p| p.trim().to_lowercase()),
        categories: parse_categories(q.category.as_deref())?,
    };
    let sort = match q.sort {
        SortKey::Bytes => ConversationSort::Bytes,
        SortKey::Packets => ConversationSort::Packets,
        SortKey::Flows => ConversationSort::Flows,
        SortKey::FirstTs => ConversationSort::FirstTs,
        SortKey::LastTs => ConversationSort::LastTs,
    };
    let first = q.cursor.is_none();
    let (_, session) = open_ready(state, id)?;
    let conn = session.conn();
    let page = store::conversations_page(
        conn,
        &filter,
        sort,
        q.order == Order::Desc,
        &page_request(q.limit, q.cursor),
    )?;
    // Counted for the first page only (the UI keeps it while loading more).
    let total = if first {
        Some(store::count_conversations(conn, &filter)?)
    } else {
        None
    };
    Ok(Page {
        items: page.items.into_iter().map(ConversationInfo::from).collect(),
        next_cursor: page.next_cursor,
        total_estimate: total,
    })
}

async fn list(
    State(state): State<Arc<AppState>>,
    UrlPath(id): UrlPath<String>,
    ApiQuery(query): ApiQuery<ListQuery>,
) -> Result<Json<Page<ConversationInfo>>, ApiError> {
    let id = parse_id(&id)?;
    blocking(&state, move |s| build_list(s, &id, query))
        .await
        .map(Json)
}

/// Traffic of the hosts of one country.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct CountryBytes {
    /// ISO 3166-1 alpha-2 code.
    pub country: String,
    pub bytes: u64,
    pub hosts: u64,
}

/// Bytes and hosts of a group without country.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, TS)]
#[ts(export)]
pub struct UnplacedBytes {
    pub bytes: u64,
    pub hosts: u64,
}

/// One side (sources or destinations) of [`ConnectionStats`].
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, TS)]
#[ts(export)]
pub struct CountrySide {
    /// Every country with traffic, largest first.
    pub countries: Vec<CountryBytes>,
    /// Public addresses whose country is unknown (no database, or not in it).
    pub unknown: UnplacedBytes,
    /// Private, local and reserved addresses (never geolocated).
    pub local: UnplacedBytes,
    pub total_bytes: u64,
}

impl CountrySide {
    fn of(rows: Vec<CountryTraffic>) -> Self {
        let mut side = Self::default();
        for r in rows {
            side.total_bytes = side.total_bytes.saturating_add(r.bytes);
            let group = match (r.country, r.public) {
                (Some(country), _) => {
                    side.countries.push(CountryBytes {
                        country,
                        bytes: r.bytes,
                        hosts: r.hosts,
                    });
                    continue;
                }
                (None, true) => &mut side.unknown,
                (None, false) => &mut side.local,
            };
            group.bytes = group.bytes.saturating_add(r.bytes);
            group.hosts = group.hosts.saturating_add(r.hosts);
        }
        side
    }
}

/// `GET /sessions/{id}/connections/stats`: bytes per country of the sending hosts (sources of
/// downloads) and of the receiving hosts (destinations).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct ConnectionStats {
    pub sources: CountrySide,
    pub destinations: CountrySide,
}

async fn stats(
    State(state): State<Arc<AppState>>,
    UrlPath(id): UrlPath<String>,
) -> Result<Json<ConnectionStats>, ApiError> {
    let id = parse_id(&id)?;
    blocking(&state, move |s| {
        let (_, session) = open_ready(s, &id)?;
        let conn = session.conn();
        Ok(ConnectionStats {
            sources: CountrySide::of(store::country_traffic(conn, TrafficSide::Sent)?),
            destinations: CountrySide::of(store::country_traffic(conn, TrafficSide::Received)?),
        })
    })
    .await
    .map(Json)
}

/// Node of [`ConnectionMatrix`]: one host, or every other host of the top conversations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct ChordNode {
    /// `null` for the "other hosts" node (always last).
    pub endpoint: Option<Endpoint>,
    /// Bytes sent and received by the node within the top conversations.
    pub bytes: u64,
}

/// `GET /sessions/{id}/connections/top`: traffic between the hosts of the top N conversations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct ConnectionMatrix {
    /// At most 15 hosts, most bytes first, plus an "other hosts" node when there are more.
    pub nodes: Vec<ChordNode>,
    /// `matrix[i][j]`: bytes sent by node `i` to node `j`.
    pub matrix: Vec<Vec<u64>>,
    /// Number of conversations taken (at most N).
    pub conversations: u32,
    /// Bytes of these conversations.
    pub total_bytes: u64,
    /// True when DNS flows were left out.
    pub exclude_dns: bool,
}

#[derive(Debug, Deserialize)]
struct TopQuery {
    n: Option<u32>,
    #[serde(default)]
    exclude_dns: bool,
}

pub(crate) fn matrix(entries: &[ConversationEntry], exclude_dns: bool) -> ConnectionMatrix {
    // Weight of each host within the top conversations.
    let mut weight: HashMap<std::net::IpAddr, u64> = HashMap::new();
    let mut infos: HashMap<std::net::IpAddr, Endpoint> = HashMap::new();
    let mut total_bytes = 0_u64;
    for e in entries {
        let bytes = e.row.bytes_fwd.saturating_add(e.row.bytes_rev);
        total_bytes = total_bytes.saturating_add(bytes);
        for (ip, info) in [(e.row.src_ip, &e.src), (e.row.dst_ip, &e.dst)] {
            let w = weight.entry(ip).or_default();
            *w = w.saturating_add(bytes);
            infos
                .entry(ip)
                .or_insert_with(|| Endpoint::new(ip, info.clone()));
        }
    }
    let mut ranked: Vec<(std::net::IpAddr, u64)> = weight.into_iter().collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let named = ranked.len().min(MAX_NODES);
    let has_other = ranked.len() > MAX_NODES;
    let index: HashMap<std::net::IpAddr, usize> = ranked
        .iter()
        .enumerate()
        .map(|(i, (ip, _))| (*ip, i.min(MAX_NODES)))
        .collect();
    let size = named + usize::from(has_other);
    let mut matrix = vec![vec![0_u64; size]; size];
    let mut node_bytes = vec![0_u64; size];
    for e in entries {
        let (Some(&s), Some(&d)) = (index.get(&e.row.src_ip), index.get(&e.row.dst_ip)) else {
            continue;
        };
        if let Some(cell) = matrix.get_mut(s).and_then(|row| row.get_mut(d)) {
            *cell = cell.saturating_add(e.row.bytes_fwd);
        }
        if let Some(cell) = matrix.get_mut(d).and_then(|row| row.get_mut(s)) {
            *cell = cell.saturating_add(e.row.bytes_rev);
        }
        let bytes = e.row.bytes_fwd.saturating_add(e.row.bytes_rev);
        let ends = [s, d];
        let ends = if s == d { &ends[..1] } else { &ends[..] };
        for &i in ends {
            if let Some(b) = node_bytes.get_mut(i) {
                *b = b.saturating_add(bytes);
            }
        }
    }
    let nodes = (0..size)
        .map(|i| ChordNode {
            endpoint: ranked
                .get(i)
                .filter(|_| i < named)
                .and_then(|(ip, _)| infos.remove(ip)),
            bytes: node_bytes.get(i).copied().unwrap_or(0),
        })
        .collect();
    ConnectionMatrix {
        nodes,
        matrix,
        conversations: u32::try_from(entries.len()).unwrap_or(u32::MAX),
        total_bytes,
        exclude_dns,
    }
}

async fn top(
    State(state): State<Arc<AppState>>,
    UrlPath(id): UrlPath<String>,
    ApiQuery(query): ApiQuery<TopQuery>,
) -> Result<Json<ConnectionMatrix>, ApiError> {
    let id = parse_id(&id)?;
    let n = query.n.unwrap_or(TOP_SIZES[0]);
    if !TOP_SIZES.contains(&n) {
        return Err(ApiError::BadRequest("n: expected 10, 20 or 50".to_owned()));
    }
    let exclude_dns = query.exclude_dns;
    blocking(&state, move |s| {
        let (_, session) = open_ready(s, &id)?;
        let entries = store::top_conversations(session.conn(), n, exclude_dns)?;
        Ok(matrix(&entries, exclude_dns))
    })
    .await
    .map(Json)
}

#[cfg(test)]
mod tests;
