//! Servers route: hosts playing an infrastructure role, grouped by role, with their evidence.
//!
//! | Method | Path | Response |
//! |---|---|---|
//! | GET | `/sessions/{id}/servers?role&category&limit` | [`ServersOverview`] |
//!
//! Roles are derived at read time (`netsift_store::servers`, ADR-017). Every role is listed, in
//! a fixed order, even without server; `limit` bounds the servers listed per role (strongest
//! evidence first), `total` gives how many there are. A session upgraded after its import is not
//! analyzed (`analyzed: false`, no server), ADR-013. Like the other views: 404 for an unknown
//! session, 409 while importing or failed.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

use axum::extract::{Path as UrlPath, State};
use axum::routing::get;
use axum::{Json, Router};
use netsift_store::servers::{self as store, EvidenceEntry};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::endpoint::{Endpoint, parse_categories};
use crate::extract::ApiQuery;
use crate::overview::open_ready;
use crate::sessions::parse_id;
use crate::{ApiError, AppState, blocking, convert};

/// Default and largest number of servers listed per role.
pub(crate) const DEFAULT_LIMIT: u32 = 50;
pub(crate) const MAX_LIMIT: u32 = 500;

pub(crate) fn routes() -> Router<Arc<AppState>> {
    Router::new().route("/sessions/{id}/servers", get(list))
}

/// Infrastructure role of a host, in display order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum ServerRole {
    Dns,
    Dhcp,
    Ldap,
    Ntp,
    Kerberos,
    Smb,
    Http,
}

impl ServerRole {
    pub(crate) const ALL: [Self; 7] = [
        Self::Dns,
        Self::Dhcp,
        Self::Ldap,
        Self::Ntp,
        Self::Kerberos,
        Self::Smb,
        Self::Http,
    ];

    /// Label of the `server_evidence` view.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Dns => "dns",
            Self::Dhcp => "dhcp",
            Self::Ldap => "ldap",
            Self::Ntp => "ntp",
            Self::Kerberos => "kerberos",
            Self::Smb => "smb",
            Self::Http => "http",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|r| r.as_str() == s)
    }
}

/// What was observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum EvidenceKind {
    /// Unicast DNS responses sent.
    DnsResponse,
    /// Service seen answering on a well-known port of the role (example: `389/tcp`).
    OpenPort,
    /// Named by a DNS SRV record (`_ldap._tcp`, `_gc._tcp`, `_kerberos._tcp|_udp`; example: the
    /// record owner).
    DnsSrv,
    /// DHCP OFFER / ACK / NAK sent (example: the latest address offered or leased).
    DhcpOffer,
    DhcpAck,
    DhcpNak,
    /// NTP server responses (mode 4; example: stratum and reference of the latest).
    NtpResponse,
    /// KDC replies (example: the realm).
    KdcAsRep,
    KdcTgsRep,
    KdcError,
    /// SMB sessions served (example: highest dialect).
    SmbSession,
    /// NetBIOS browser announcement of the server service (example: the announced name).
    BrowserServer,
    /// NetBIOS browser announcement of a domain controller (example: the announced name).
    BrowserDc,
    /// HTTP responses sent.
    HttpResponse,
}

impl EvidenceKind {
    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "dns_response" => Self::DnsResponse,
            "open_port" => Self::OpenPort,
            "dns_srv" => Self::DnsSrv,
            "dhcp_offer" => Self::DhcpOffer,
            "dhcp_ack" => Self::DhcpAck,
            "dhcp_nak" => Self::DhcpNak,
            "ntp_response" => Self::NtpResponse,
            "kdc_as_rep" => Self::KdcAsRep,
            "kdc_tgs_rep" => Self::KdcTgsRep,
            "kdc_error" => Self::KdcError,
            "smb_session" => Self::SmbSession,
            "browser_server" => Self::BrowserServer,
            "browser_dc" => Self::BrowserDc,
            "http_response" => Self::HttpResponse,
            _ => return None,
        })
    }
}

/// One piece of evidence of a role.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct ServerEvidence {
    pub kind: EvidenceKind,
    /// Occurrences (responses, replies, announcements, flows to the port...).
    pub count: u64,
    /// Distinct clients, when it applies.
    pub clients: Option<u64>,
    pub first_ts_us: i64,
    pub last_ts_us: i64,
    /// Representative value (see [`EvidenceKind`]).
    pub example: Option<String>,
}

/// A server of one role.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct RoleServer {
    pub endpoint: Endpoint,
    /// Sum of the evidence counts (sort key).
    pub count: u64,
    pub first_ts_us: i64,
    pub last_ts_us: i64,
    /// Strongest first.
    pub evidence: Vec<ServerEvidence>,
}

/// The servers of one role.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct RoleServers {
    pub role: ServerRole,
    /// Servers of this role (matching the category filter), listed or not.
    pub total: u64,
    /// At most `limit`, by decreasing evidence count, then address.
    pub servers: Vec<RoleServer>,
}

/// `GET /servers`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct ServersOverview {
    /// False for a session imported before this view existed (not analyzed, re-import it).
    pub analyzed: bool,
    /// Every role (or the requested one), in display order.
    pub roles: Vec<RoleServers>,
    /// The evidence of a very large session was cut: totals are lower bounds.
    pub truncated: bool,
}

#[derive(Debug, Default, Deserialize)]
struct ServersQuery {
    /// Only this role.
    role: Option<String>,
    /// Comma-separated address categories (`private,public`); all when absent.
    category: Option<String>,
    /// Servers listed per role: default 50, clamped to `1..=500`.
    limit: Option<u32>,
}

/// Address category label of a server, as `Endpoint::new` computes it.
fn category_label(ip: IpAddr, stored: Option<&str>) -> &'static str {
    stored
        .and_then(|c| netsift_geo::AddressCategory::from_str(c).ok())
        .unwrap_or_else(|| netsift_geo::AddressCategory::of(ip))
        .as_str()
}

/// Groups evidence rows by role and server; applies the category filter and the limit.
pub(crate) fn group(
    entries: Vec<EvidenceEntry>,
    roles: &[ServerRole],
    categories: Option<&[String]>,
    limit: usize,
) -> Vec<RoleServers> {
    let mut by_role: BTreeMap<ServerRole, BTreeMap<IpAddr, RoleServer>> = BTreeMap::new();
    for e in entries {
        let (Some(role), Some(kind)) = (ServerRole::parse(&e.role), EvidenceKind::parse(&e.kind))
        else {
            continue;
        };
        if !roles.contains(&role) {
            continue;
        }
        if let Some(allowed) = categories {
            let label = category_label(e.ip, e.host.category.as_deref());
            if !allowed.iter().any(|c| c == label) {
                continue;
            }
        }
        let evidence = ServerEvidence {
            kind,
            count: e.count,
            clients: e.clients,
            first_ts_us: convert::us(e.first_ts),
            last_ts_us: convert::us(e.last_ts),
            example: e.example,
        };
        let server = by_role
            .entry(role)
            .or_default()
            .entry(e.ip)
            .or_insert_with(|| RoleServer {
                endpoint: Endpoint::new(e.ip, e.host),
                count: 0,
                first_ts_us: evidence.first_ts_us,
                last_ts_us: evidence.last_ts_us,
                evidence: Vec::new(),
            });
        server.count = server.count.saturating_add(evidence.count);
        server.first_ts_us = server.first_ts_us.min(evidence.first_ts_us);
        server.last_ts_us = server.last_ts_us.max(evidence.last_ts_us);
        server.evidence.push(evidence);
    }
    roles
        .iter()
        .map(|role| {
            let mut servers: Vec<RoleServer> = by_role
                .remove(role)
                .map(|m| m.into_values().collect())
                .unwrap_or_default();
            for s in &mut servers {
                s.evidence
                    .sort_by(|a, b| b.count.cmp(&a.count).then(a.kind.cmp(&b.kind)));
            }
            // Stable sort: equal counts keep the address order of the map.
            servers.sort_by(|a, b| b.count.cmp(&a.count));
            let total = servers.len() as u64;
            servers.truncate(limit);
            RoleServers {
                role: *role,
                total,
                servers,
            }
        })
        .collect()
}

async fn list(
    State(state): State<Arc<AppState>>,
    UrlPath(id): UrlPath<String>,
    ApiQuery(query): ApiQuery<ServersQuery>,
) -> Result<Json<ServersOverview>, ApiError> {
    let id = parse_id(&id)?;
    let roles: Vec<ServerRole> = match query.role.as_deref() {
        None => ServerRole::ALL.to_vec(),
        Some(r) => vec![
            ServerRole::parse(r)
                .ok_or_else(|| ApiError::BadRequest("role: unknown server role".to_owned()))?,
        ],
    };
    let categories = parse_categories(query.category.as_deref())?;
    let limit = query.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT) as usize;
    blocking(&state, move |s| {
        let (_, session) = open_ready(s, &id)?;
        let conn = session.conn();
        if !store::analyzed(conn)? {
            return Ok(ServersOverview {
                analyzed: false,
                roles: group(Vec::new(), &roles, None, limit),
                truncated: false,
            });
        }
        let role = match roles.as_slice() {
            [only] => Some(only.as_str()),
            _ => None,
        };
        let (entries, truncated) = store::evidence(conn, role)?;
        Ok(ServersOverview {
            analyzed: true,
            roles: group(entries, &roles, categories.as_deref(), limit),
            truncated,
        })
    })
    .await
    .map(Json)
}

#[cfg(test)]
mod tests;
