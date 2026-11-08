//! Open ports routes: services seen answering, grouped by host.
//!
//! | Method | Path | Response |
//! |---|---|---|
//! | GET | `/sessions/{id}/open-ports?limit&cursor&category&port&service&q` | `Page<HostOpenPorts>` |
//! | GET | `/sessions/{id}/open-ports/stats?category&n` | [`OpenPortStats`] |
//!
//! Like the overview routes: 404 for an unknown session, 409 while importing or failed.

use std::sync::Arc;

use axum::extract::{Path as UrlPath, State};
use axum::routing::get;
use axum::{Json, Router};
use netsift_store::SessionId;
use netsift_store::ports::{self as store, HostPorts, OpenPortEntry, PortFilter};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::connections::page_request;
use crate::contract::Page;
use crate::endpoint::{Endpoint, parse_categories};
use crate::extract::ApiQuery;
use crate::overview::open_ready;
use crate::sessions::parse_id;
use crate::{ApiError, AppState, blocking, convert};

/// Default and largest number of bars of `/open-ports/stats`.
pub(crate) const DEFAULT_TOP: u32 = 15;
pub(crate) const MAX_TOP: u32 = 50;
const MAX_FILTER_LEN: usize = 256;

pub(crate) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/sessions/{id}/open-ports", get(list))
        .route("/sessions/{id}/open-ports/stats", get(stats))
}

/// Transport protocol of a port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "lowercase")]
#[ts(export)]
pub enum PortTransport {
    Tcp,
    Udp,
}

impl PortTransport {
    fn of(proto: u8) -> Self {
        if proto == 17 { Self::Udp } else { Self::Tcp }
    }
}

/// Why a port is considered open.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum PortEvidence {
    /// The host answered a SYN with a SYN-ACK.
    SynAck,
    /// The host sent data as the server of a connection whose handshake was not captured.
    ServerData,
    /// The host answered a UDP datagram from this port.
    UdpReply,
}

impl PortEvidence {
    fn of(label: &str) -> Self {
        match label {
            "server_data" => Self::ServerData,
            "udp_reply" => Self::UdpReply,
            _ => Self::SynAck,
        }
    }
}

/// One open port of a host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct OpenPortInfo {
    pub port: u16,
    pub transport: PortTransport,
    /// IANA service name of the port.
    pub service: Option<String>,
    /// Service identified from the traffic (`http`, `tls`, `ssh`, `smb`...).
    pub detected: Option<String>,
    pub evidence: PortEvidence,
    /// Distinct clients of the flows to this port.
    pub clients: u64,
    pub first_ts_us: i64,
    pub last_ts_us: i64,
    /// First line of the server greeting (SSH, FTP, SMTP...), at most 256 bytes.
    pub banner: Option<String>,
}

impl From<OpenPortEntry> for OpenPortInfo {
    fn from(e: OpenPortEntry) -> Self {
        let r = e.row;
        Self {
            port: r.port,
            transport: PortTransport::of(r.transport),
            service: r.service,
            detected: r.detected,
            evidence: PortEvidence::of(&r.evidence),
            clients: e.clients,
            first_ts_us: convert::us(r.first_ts),
            last_ts_us: convert::us(r.last_ts),
            banner: r.banner,
        }
    }
}

/// A host and its open ports (TCP then UDP, by port).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct HostOpenPorts {
    pub host: Endpoint,
    pub ports: Vec<OpenPortInfo>,
}

impl From<HostPorts> for HostOpenPorts {
    fn from(h: HostPorts) -> Self {
        Self {
            host: Endpoint::new(h.ip, h.host),
            ports: h.ports.into_iter().map(OpenPortInfo::from).collect(),
        }
    }
}

#[derive(Debug, Default, Deserialize)]
struct ListQuery {
    limit: Option<u32>,
    cursor: Option<String>,
    /// Comma-separated address categories of the host.
    category: Option<String>,
    port: Option<u16>,
    /// IANA or detected service name.
    service: Option<String>,
    /// Host IP or name, service name or port number.
    q: Option<String>,
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

fn build_list(
    state: &AppState,
    id: &SessionId,
    q: ListQuery,
) -> Result<Page<HostOpenPorts>, ApiError> {
    let filter = PortFilter {
        categories: parse_categories(q.category.as_deref())?,
        port: q.port,
        service: text("service", q.service)?,
        text: text("q", q.q)?,
    };
    let first = q.cursor.is_none();
    let (_, session) = open_ready(state, id)?;
    let conn = session.conn();
    let page = store::hosts_page(conn, &filter, &page_request(q.limit, q.cursor))?;
    let total = if first {
        Some(store::count_hosts(conn, &filter)?)
    } else {
        None
    };
    Ok(Page {
        items: page.items.into_iter().map(HostOpenPorts::from).collect(),
        next_cursor: page.next_cursor,
        total_estimate: total,
    })
}

async fn list(
    State(state): State<Arc<AppState>>,
    UrlPath(id): UrlPath<String>,
    ApiQuery(query): ApiQuery<ListQuery>,
) -> Result<Json<Page<HostOpenPorts>>, ApiError> {
    let id = parse_id(&id)?;
    blocking(&state, move |s| build_list(s, &id, query))
        .await
        .map(Json)
}

/// A port and the number of hosts where it is open.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct PortCount {
    pub port: u16,
    pub transport: PortTransport,
    pub service: Option<String>,
    pub detected: Option<String>,
    pub hosts: u64,
}

/// `GET /sessions/{id}/open-ports/stats`: ports open on the most hosts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct OpenPortStats {
    /// At most `n` ports (default 15), most hosts first.
    pub top: Vec<PortCount>,
    /// Distinct (transport, port) pairs open somewhere.
    pub distinct_ports: u64,
    /// Open ports over every host (one per host and port).
    pub open_ports: u64,
}

#[derive(Debug, Default, Deserialize)]
struct StatsQuery {
    category: Option<String>,
    n: Option<u32>,
}

async fn stats(
    State(state): State<Arc<AppState>>,
    UrlPath(id): UrlPath<String>,
    ApiQuery(query): ApiQuery<StatsQuery>,
) -> Result<Json<OpenPortStats>, ApiError> {
    let id = parse_id(&id)?;
    let n = query.n.unwrap_or(DEFAULT_TOP).clamp(1, MAX_TOP);
    let filter = PortFilter {
        categories: parse_categories(query.category.as_deref())?,
        ..PortFilter::default()
    };
    blocking(&state, move |s| {
        let (_, session) = open_ready(s, &id)?;
        let (top, distinct_ports, open_ports) = store::port_stats(session.conn(), &filter, n)?;
        Ok(OpenPortStats {
            top: top
                .into_iter()
                .map(|p| PortCount {
                    port: p.port,
                    transport: PortTransport::of(p.transport),
                    service: p.service,
                    detected: p.detected,
                    hosts: p.hosts,
                })
                .collect(),
            distinct_ports,
            open_ports,
        })
    })
    .await
    .map(Json)
}
