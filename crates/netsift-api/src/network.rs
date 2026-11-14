//! Network routes: bounded communication graph and host detail.
//!
//! | Method | Path | Response |
//! |---|---|---|
//! | GET | `/sessions/{id}/network/graph?mode&protocols&category&ipv6&include_orphans&limit&expand` | [`NetworkGraph`] |
//! | GET | `/sessions/{id}/network/node/{ip}` | [`NetworkNodeDetail`] |
//!
//! The graph is read from the tables that the end-of-import step `network` folds from the
//! conversations (`netsift_store::network`, ADR-018): at most 150 host nodes plus 15 country
//! clusters and one "other" node, at most 400 edges. Like the other analysis routes: 404 for an
//! unknown session, 409 while importing or failed.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use axum::extract::{Path as UrlPath, State};
use axum::routing::get;
use axum::{Json, Router};
use netsift_store::network::{
    self as store, GraphFilter, GraphMode, MAX_EDGES, NodeKey, ProtocolGroup,
};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::endpoint::{Endpoint, parse_categories};
use crate::extract::ApiQuery;
use crate::overview::open_ready;
use crate::ports::PortTransport;
use crate::servers::ServerRole;
use crate::sessions::parse_id;
use crate::{ApiError, AppState, blocking, convert};

/// Default number of host (or country) nodes.
pub(crate) const DEFAULT_NODES: u32 = 40;

pub(crate) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/sessions/{id}/network/graph", get(graph))
        .route("/sessions/{id}/network/node/{ip}", get(node))
}

/// Grouping of the hosts into nodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum NetworkMode {
    /// One node per host (top N), country clusters and "other".
    #[default]
    Hosts,
    /// One node per country, plus local addresses and unknown countries.
    Countries,
}

/// Protocol filter of the graph (groups of conversation labels).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum NetworkProtocol {
    Dns,
    Http,
    /// TLS conversations.
    Https,
    Ssh,
    Ftp,
    Telnet,
    Rdp,
    /// SMB and NetBIOS.
    Smb,
    /// TCP without identified protocol.
    Tcp,
    /// UDP without identified protocol.
    Udp,
    /// Every other label (ICMP, DHCP, NTP...).
    Other,
}

impl From<ProtocolGroup> for NetworkProtocol {
    fn from(g: ProtocolGroup) -> Self {
        match g {
            ProtocolGroup::Dns => Self::Dns,
            ProtocolGroup::Http => Self::Http,
            ProtocolGroup::Https => Self::Https,
            ProtocolGroup::Ssh => Self::Ssh,
            ProtocolGroup::Ftp => Self::Ftp,
            ProtocolGroup::Telnet => Self::Telnet,
            ProtocolGroup::Rdp => Self::Rdp,
            ProtocolGroup::Smb => Self::Smb,
            ProtocolGroup::Tcp => Self::Tcp,
            ProtocolGroup::Udp => Self::Udp,
            ProtocolGroup::Other => Self::Other,
        }
    }
}

/// Number of conversations carrying a protocol (whole session, counter of the filter toggles).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct NetworkProtocolCount {
    pub protocol: NetworkProtocol,
    pub conversations: u64,
}

/// What a node stands for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum NetworkNodeKind {
    Host,
    /// Public hosts of one country outside the top N (host mode).
    Cluster,
    /// Hosts of one country (country mode).
    Country,
    /// Private, local and reserved addresses (country mode).
    Local,
    /// Public addresses of unknown country (country mode).
    Unknown,
    /// Every host not drawn otherwise.
    Other,
}

/// Node of the graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct NetworkNode {
    /// Stable id within the graph (`h:<ip>`, `k:<cc>`, `c:<cc>`, `local`, `unknown`, `other`).
    pub id: String,
    pub kind: NetworkNodeKind,
    /// Host nodes only.
    pub endpoint: Option<Endpoint>,
    /// ISO 3166-1 alpha-2 code of `country` and `cluster` nodes.
    pub country: Option<String>,
    /// Hosts behind the node (1 for a host).
    pub hosts: u64,
    /// Bytes of the node within the graph (traffic inside a group counted once).
    pub bytes: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets: u64,
    /// Conversation labels (`dns`, `tls`, `tcp`...), sorted.
    pub protocols: Vec<String>,
    /// Server roles of a host (Servers view, ADR-017), in display order; empty otherwise.
    pub roles: Vec<ServerRole>,
}

impl NetworkNode {
    fn of(n: store::GraphNode, roles: &mut HashMap<IpAddr, Vec<String>>) -> Self {
        let bytes = n.bytes();
        let roles = match &n.key {
            NodeKey::Host(ip) => server_roles(roles.remove(ip)),
            _ => Vec::new(),
        };
        let (kind, endpoint, country) = match n.key {
            NodeKey::Host(ip) => (
                NetworkNodeKind::Host,
                Some(Endpoint::new(ip, n.info.unwrap_or_default())),
                None,
            ),
            NodeKey::Cluster(ref cc) => (NetworkNodeKind::Cluster, None, Some(cc.clone())),
            NodeKey::Country(ref cc) => (NetworkNodeKind::Country, None, Some(cc.clone())),
            NodeKey::Local => (NetworkNodeKind::Local, None, None),
            NodeKey::Unknown => (NetworkNodeKind::Unknown, None, None),
            NodeKey::Other => (NetworkNodeKind::Other, None, None),
        };
        Self {
            id: n.key.id(),
            kind,
            endpoint,
            country,
            hosts: n.hosts,
            bytes,
            bytes_sent: n.bytes_sent,
            bytes_received: n.bytes_received,
            packets: n.packets,
            protocols: n.protocols,
            roles,
        }
    }
}

/// Undirected edge (`source` is the smaller id).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct NetworkEdge {
    pub source: String,
    pub target: String,
    pub bytes: u64,
    /// `source` -> `target`.
    pub bytes_fwd: u64,
    /// `target` -> `source`.
    pub bytes_rev: u64,
    pub packets: u64,
    pub flows: u64,
    /// Conversations (client, server pairs) folded into the edge.
    pub conversations: u64,
    pub protocols: Vec<String>,
}

impl From<store::GraphEdge> for NetworkEdge {
    fn from(e: store::GraphEdge) -> Self {
        Self {
            bytes: e.bytes(),
            source: e.source,
            target: e.target,
            bytes_fwd: e.bytes_fwd,
            bytes_rev: e.bytes_rev,
            packets: e.packets,
            flows: e.flows,
            conversations: e.conversations,
            protocols: e.protocols,
        }
    }
}

/// `GET /sessions/{id}/network/graph`: bounded graph of the communications.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct NetworkGraph {
    pub mode: NetworkMode,
    /// Most bytes first; "other" last.
    pub nodes: Vec<NetworkNode>,
    /// Most bytes first.
    pub edges: Vec<NetworkEdge>,
    /// Hosts with traffic matching the filters.
    pub hosts: u64,
    /// Hosts drawn as their own node.
    pub hosts_shown: u64,
    /// Pairs of nodes with traffic before the edge limit (`max_edges`).
    pub edges_total: u64,
    pub max_edges: u32,
    /// Hosts of the session without traffic matching the filters.
    pub orphans: u64,
    /// Bytes of the matching conversations.
    pub total_bytes: u64,
    /// Every protocol filter with its number of conversations (whole session).
    pub protocols: Vec<NetworkProtocolCount>,
}

/// Known roles of a host, in display order (labels of a newer schema are skipped).
fn server_roles(labels: Option<Vec<String>>) -> Vec<ServerRole> {
    let mut roles: Vec<ServerRole> = labels
        .unwrap_or_default()
        .iter()
        .filter_map(|r| ServerRole::parse(r))
        .collect();
    roles.sort_unstable();
    roles.dedup();
    roles
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize)]
struct GraphQuery {
    #[serde(default)]
    mode: NetworkMode,
    /// Comma-separated protocol filters; all when absent, none when empty.
    protocols: Option<String>,
    /// Comma-separated address categories; both ends must match.
    category: Option<String>,
    #[serde(default = "default_true")]
    ipv6: bool,
    #[serde(default)]
    include_orphans: bool,
    /// Host (or country) nodes, clamped to 10..=150.
    limit: Option<u32>,
    /// Country code of a cluster whose hosts are drawn.
    expand: Option<String>,
}

fn parse_protocols(raw: Option<&str>) -> Result<Option<Vec<ProtocolGroup>>, ApiError> {
    let Some(raw) = raw else { return Ok(None) };
    raw.split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(|p| {
            ProtocolGroup::parse(&p.to_ascii_lowercase())
                .ok_or_else(|| ApiError::BadRequest("protocols: unknown protocol".to_owned()))
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Some)
}

fn parse_country(raw: Option<String>) -> Result<Option<String>, ApiError> {
    match raw {
        None => Ok(None),
        Some(s) if s.trim().is_empty() => Ok(None),
        Some(s) if s.len() == 2 && s.bytes().all(|b| b.is_ascii_alphabetic()) => {
            Ok(Some(s.to_ascii_uppercase()))
        }
        Some(_) => Err(ApiError::BadRequest(
            "expand: expected a country code".to_owned(),
        )),
    }
}

fn build_graph(
    state: &AppState,
    id: &netsift_store::SessionId,
    q: GraphQuery,
) -> Result<NetworkGraph, ApiError> {
    let filter = GraphFilter {
        protocols: parse_protocols(q.protocols.as_deref())?,
        categories: parse_categories(q.category.as_deref())?,
        ipv6: q.ipv6,
    };
    let limit = q.limit.unwrap_or(DEFAULT_NODES);
    let mode = match q.mode {
        NetworkMode::Hosts => GraphMode::Hosts {
            limit,
            expand: parse_country(q.expand)?,
            include_orphans: q.include_orphans,
        },
        NetworkMode::Countries => GraphMode::Countries { limit },
    };
    let (_, session) = open_ready(state, id)?;
    let conn = session.conn();
    let g = store::graph(conn, &filter, &mode)?;
    let hosts: Vec<IpAddr> = g
        .nodes
        .iter()
        .filter_map(|n| match n.key {
            NodeKey::Host(ip) => Some(ip),
            _ => None,
        })
        .collect();
    let mut roles = store::host_roles(conn, &hosts)?;
    let protocols = store::protocol_counts(conn)?
        .into_iter()
        .map(|(g, n)| NetworkProtocolCount {
            protocol: g.into(),
            conversations: n,
        })
        .collect();
    Ok(NetworkGraph {
        mode: q.mode,
        nodes: g
            .nodes
            .into_iter()
            .map(|n| NetworkNode::of(n, &mut roles))
            .collect(),
        edges: g.edges.into_iter().map(NetworkEdge::from).collect(),
        hosts: g.hosts,
        hosts_shown: g.hosts_shown,
        edges_total: g.edges_total,
        max_edges: u32::try_from(MAX_EDGES).unwrap_or(u32::MAX),
        orphans: g.orphans,
        total_bytes: g.total_bytes,
        protocols,
    })
}

async fn graph(
    State(state): State<Arc<AppState>>,
    UrlPath(id): UrlPath<String>,
    ApiQuery(query): ApiQuery<GraphQuery>,
) -> Result<Json<NetworkGraph>, ApiError> {
    let id = parse_id(&id)?;
    blocking(&state, move |s| build_graph(s, &id, query))
        .await
        .map(Json)
}

/// Open port of a host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct NetworkPort {
    pub port: u16,
    pub transport: PortTransport,
    /// IANA service name.
    pub service: Option<String>,
}

/// Peer of a host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct NetworkNeighbor {
    pub endpoint: Endpoint,
    /// Host -> peer.
    pub bytes_sent: u64,
    /// Peer -> host.
    pub bytes_received: u64,
    pub protocols: Vec<String>,
}

/// `GET /sessions/{id}/network/node/{ip}`: what the session knows about one host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct NetworkNodeDetail {
    pub endpoint: Endpoint,
    pub macs: Vec<String>,
    pub first_ts_us: Option<i64>,
    pub last_ts_us: Option<i64>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    /// Distinct peers.
    pub peers: u64,
    /// Every conversation label of the host, sorted.
    pub protocols: Vec<String>,
    /// At most 50, by port.
    pub open_ports: Vec<NetworkPort>,
    /// The 10 peers with the most bytes.
    pub neighbors: Vec<NetworkNeighbor>,
    /// Server roles (Servers view, ADR-017), in display order.
    pub roles: Vec<ServerRole>,
}

async fn node(
    State(state): State<Arc<AppState>>,
    UrlPath((id, ip)): UrlPath<(String, String)>,
) -> Result<Json<NetworkNodeDetail>, ApiError> {
    let id = parse_id(&id)?;
    let ip: IpAddr = ip
        .parse()
        .map_err(|_| ApiError::BadRequest("ip: invalid address".to_owned()))?;
    blocking(&state, move |s| {
        let (_, session) = open_ready(s, &id)?;
        let d = store::node_detail(session.conn(), ip)?.ok_or(ApiError::NotFound)?;
        let roles = server_roles(store::host_roles(session.conn(), &[ip])?.remove(&ip));
        Ok(NetworkNodeDetail {
            endpoint: Endpoint::new(d.ip, d.info),
            macs: d.macs,
            first_ts_us: d.first_ts.map(convert::us),
            last_ts_us: d.last_ts.map(convert::us),
            bytes_sent: d.bytes_sent,
            bytes_received: d.bytes_received,
            packets_sent: d.packets_sent,
            packets_received: d.packets_received,
            peers: d.peers,
            protocols: d.protocols,
            open_ports: d
                .open_ports
                .into_iter()
                .map(|p| NetworkPort {
                    port: p.port,
                    transport: PortTransport::of(p.transport),
                    service: p.service,
                })
                .collect(),
            neighbors: d
                .neighbors
                .into_iter()
                .map(|n| NetworkNeighbor {
                    endpoint: Endpoint::new(n.ip, n.info),
                    bytes_sent: n.bytes_sent,
                    bytes_received: n.bytes_received,
                    protocols: n.protocols,
                })
                .collect(),
            roles,
        })
    })
    .await
    .map(Json)
}

#[cfg(test)]
mod tests;
