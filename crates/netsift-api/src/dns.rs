//! DNS view routes (`docs/specs/dns.md`).
//!
//! | Method | Path | Response |
//! |---|---|---|
//! | GET | `/sessions/{id}/dns/stats` | [`DnsStats`] |
//! | GET | `/sessions/{id}/dns/servers?limit&cursor` | `Page<DnsServer>` |
//! | GET | `/sessions/{id}/dns/pairs?limit&cursor&protocols&errors&q` | `Page<DnsPair>` |
//! | GET | `/sessions/{id}/dns/messages?pair&limit&cursor&protocols&errors&q` | `Page<DnsMessage>` |
//!
//! - `protocols`: comma-separated subset of `dns,mdns,llmnr,nbns` (all when absent, none when
//!   empty); `errors=true`: only transactions with an error (pairs with at least one); `q`:
//!   case-insensitive substring of a name, an address or an answer.
//! - Like the overview: 404 for an unknown session, 409 while importing or failed. A session
//!   imported before the DNS module existed answers with empty results.

use std::sync::Arc;

use axum::extract::{Path as UrlPath, State};
use axum::routing::get;
use axum::{Json, Router};
use netsift_store::dns::{self as store, DnsFilter};
use netsift_store::traffic::count_rows;
use netsift_store::{PageRequest, Session, SessionId};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::contract::Page;
use crate::endpoint::Endpoint;
use crate::overview::open_ready;
use crate::sessions::{DEFAULT_LIMIT, MAX_LIMIT, parse_id};
use crate::{ApiError, AppState, blocking, convert};

pub(crate) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/sessions/{id}/dns/stats", get(stats))
        .route("/sessions/{id}/dns/servers", get(servers))
        .route("/sessions/{id}/dns/pairs", get(pairs))
        .route("/sessions/{id}/dns/messages", get(messages))
}

/// Name service protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "lowercase")]
#[ts(export)]
pub enum DnsProtocol {
    Dns,
    Mdns,
    Llmnr,
    Nbns,
}

impl DnsProtocol {
    const ALL: [Self; 4] = [Self::Dns, Self::Mdns, Self::Llmnr, Self::Nbns];

    fn id(self) -> &'static str {
        match self {
            Self::Dns => "dns",
            Self::Mdns => "mdns",
            Self::Llmnr => "llmnr",
            Self::Nbns => "nbns",
        }
    }

    fn from_id(id: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.id() == id)
    }

    /// Stored labels are written by the analyzer: an unknown one is reported as plain DNS.
    fn of_stored(label: &str) -> Self {
        Self::from_id(label).unwrap_or(Self::Dns)
    }
}

/// Transactions of one protocol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct DnsProtocolCount {
    pub protocol: DnsProtocol,
    pub count: u64,
    /// Transactions with an error (response code other than `NOERROR`, or `timeout`).
    pub errors: u64,
}

/// Transactions with one value (response code, query type).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct DnsCount {
    /// `NOERROR`, `NXDOMAIN`..., `timeout`; `null`: no response expected (mDNS queries, NBNS
    /// registrations).
    pub key: Option<String>,
    pub count: u64,
}

/// Servers of one country.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct DnsCountryCount {
    /// ISO 3166-1 alpha-2 code; `null` for local, group and unknown addresses.
    pub country: Option<String>,
    pub servers: u64,
    pub messages: u64,
}

/// `GET /sessions/{id}/dns/stats`: charts and filter counters (bounded lists).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct DnsStats {
    /// Transactions (query/response pairs, or either side alone).
    pub total: u64,
    pub errors: u64,
    /// Transactions with both a query and a response.
    pub answered: u64,
    /// Every protocol present, most transactions first.
    pub protocols: Vec<DnsProtocolCount>,
    /// The 10 most frequent outcomes; the others are summed in `rcode_other`.
    pub rcodes: Vec<DnsCount>,
    pub rcode_other: u64,
    /// The 10 most frequent query types; the others are summed in `qtype_other`.
    pub qtypes: Vec<DnsCount>,
    pub qtype_other: u64,
    /// The 10 countries with the most transactions (known countries only).
    pub countries: Vec<DnsCountryCount>,
    /// Servers without a country (private, multicast, broadcast, no GeoIP database).
    pub country_unknown: DnsCountryCount,
    pub latency_p50_us: Option<i64>,
    pub latency_p95_us: Option<i64>,
}

/// One row of the grouped table: a client, a server (query destination) and a protocol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct DnsPair {
    /// Identifier for `GET .../dns/messages?pair=`.
    pub id: String,
    pub protocol: DnsProtocol,
    pub client: Endpoint,
    pub server: Endpoint,
    pub messages: u64,
    pub errors: u64,
    /// Distinct query names.
    pub name_count: u64,
    /// The 5 most frequent names.
    pub top_names: Vec<String>,
    pub first_ts_us: i64,
    pub last_ts_us: i64,
}

/// One answer record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct DnsAnswer {
    pub name: String,
    /// Type mnemonic (`A`, `CNAME`, `NB`, `TYPE65534`...).
    #[serde(rename = "type")]
    #[ts(rename = "type")]
    pub rtype: String,
    pub value: String,
    pub ttl: u32,
}

/// One transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct DnsMessage {
    pub id: String,
    pub pair_id: Option<String>,
    /// Time of the query (of the response when there is no query).
    pub ts_us: i64,
    pub flow_id: Option<String>,
    /// `udp` or `tcp`.
    pub transport: String,
    pub protocol: DnsProtocol,
    pub client_ip: String,
    pub client_port: u16,
    pub server_ip: String,
    pub server_port: u16,
    /// Sender of the response when it is not the server (query to a group address).
    pub responder_ip: Option<String>,
    pub txid: u16,
    pub opcode: String,
    pub qname: String,
    pub qtype: String,
    /// NetBIOS name suffix (NBNS), e.g. 0x20 for a file server.
    pub nb_suffix: Option<u8>,
    pub flags: u16,
    /// `NOERROR`, `NXDOMAIN`..., `timeout`, or `null` (no response expected).
    pub rcode: Option<String>,
    pub latency_us: Option<i64>,
    pub answers: Vec<DnsAnswer>,
    pub has_query: bool,
    pub has_response: bool,
}

/// A queried server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct DnsServer {
    pub host: Endpoint,
    pub messages: u64,
    pub errors: u64,
    pub clients: u64,
    pub protocols: Vec<DnsProtocol>,
}

#[derive(Debug, Default, Deserialize)]
struct ListQuery {
    limit: Option<u32>,
    cursor: Option<String>,
    protocols: Option<String>,
    errors: Option<bool>,
    q: Option<String>,
    pair: Option<String>,
}

/// Longest accepted search text, in characters.
const MAX_SEARCH: usize = 256;

impl ListQuery {
    fn request(&self) -> PageRequest {
        PageRequest {
            limit: match self.limit {
                None | Some(0) => DEFAULT_LIMIT,
                Some(n) => n.min(MAX_LIMIT),
            },
            cursor: self.cursor.clone(),
        }
    }

    fn filter(&self) -> Result<DnsFilter, ApiError> {
        let protocols = match self.protocols.as_deref() {
            None => DnsProtocol::ALL.iter().map(|p| p.id().to_owned()).collect(),
            Some(raw) => raw
                .split(',')
                .map(str::trim)
                .filter(|p| !p.is_empty())
                .map(|p| {
                    DnsProtocol::from_id(p)
                        .map(|p| p.id().to_owned())
                        .ok_or_else(|| ApiError::BadRequest("protocols: unknown protocol".into()))
                })
                .collect::<Result<_, _>>()?,
        };
        let search = self.q.as_deref().map(str::trim).filter(|q| !q.is_empty());
        if search.is_some_and(|q| q.chars().count() > MAX_SEARCH) {
            return Err(ApiError::BadRequest("q: too long".into()));
        }
        Ok(DnsFilter {
            protocols,
            errors_only: self.errors.unwrap_or(false),
            search: search.map(str::to_owned),
        })
    }

    fn pair(&self) -> Result<Option<i64>, ApiError> {
        self.pair
            .as_deref()
            .map(|p| {
                p.parse::<i64>()
                    .map_err(|_| ApiError::BadRequest("pair: not an identifier".into()))
            })
            .transpose()
    }
}

/// The session, or `None` when it predates the DNS module (no table).
fn open(state: &AppState, id: &SessionId) -> Result<Option<Session>, ApiError> {
    let (_, session) = open_ready(state, id)?;
    Ok(count_rows(session.conn(), "dns_messages")?.map(|_| session))
}

fn country(c: store::CountryBucket) -> DnsCountryCount {
    DnsCountryCount {
        country: c.country,
        servers: c.servers,
        messages: c.messages,
    }
}

fn counts(buckets: Vec<store::Bucket>) -> Vec<DnsCount> {
    buckets
        .into_iter()
        .map(|b| DnsCount {
            key: b.key,
            count: b.count,
        })
        .collect()
}

fn build_stats(state: &AppState, id: &SessionId) -> Result<DnsStats, ApiError> {
    let s = match open(state, id)? {
        Some(session) => store::stats(session.conn())?,
        None => store::DnsStats::default(),
    };
    let errors_of = |protocol: &Option<String>| {
        s.protocol_errors
            .iter()
            .find(|b| &b.key == protocol)
            .map_or(0, |b| b.count)
    };
    let protocols = s
        .protocols
        .iter()
        .map(|b| DnsProtocolCount {
            protocol: DnsProtocol::of_stored(b.key.as_deref().unwrap_or_default()),
            count: b.count,
            errors: errors_of(&b.key),
        })
        .collect();
    Ok(DnsStats {
        total: s.total,
        errors: s.errors,
        answered: s.answered,
        protocols,
        rcodes: counts(s.rcodes),
        rcode_other: s.rcode_other,
        qtypes: counts(s.qtypes),
        qtype_other: s.qtype_other,
        countries: s.countries.into_iter().map(country).collect(),
        country_unknown: country(s.country_unknown),
        latency_p50_us: s.latency_p50_ns.map(convert::us),
        latency_p95_us: s.latency_p95_ns.map(convert::us),
    })
}

fn empty<T>() -> Page<T> {
    Page {
        items: Vec::new(),
        next_cursor: None,
        total_estimate: Some(0),
    }
}

fn build_pairs(
    state: &AppState,
    id: &SessionId,
    query: &ListQuery,
) -> Result<Page<DnsPair>, ApiError> {
    let filter = query.filter()?;
    let Some(session) = open(state, id)? else {
        return Ok(empty());
    };
    let (page, total) = store::pairs_page(session.conn(), &filter, &query.request())?;
    Ok(Page {
        items: page
            .items
            .into_iter()
            .map(|p| DnsPair {
                id: p.id.to_string(),
                protocol: DnsProtocol::of_stored(&p.proto),
                client: Endpoint::new(p.client_ip, p.client),
                server: Endpoint::new(p.server_ip, p.server),
                messages: p.messages,
                errors: p.errors,
                name_count: p.names,
                top_names: p.top_names,
                first_ts_us: convert::us(p.first_ts),
                last_ts_us: convert::us(p.last_ts),
            })
            .collect(),
        next_cursor: page.next_cursor,
        total_estimate: Some(total),
    })
}

fn message(m: store::DnsMessageRow) -> DnsMessage {
    DnsMessage {
        id: m.id.to_string(),
        pair_id: m.pair_id.map(|p| p.to_string()),
        ts_us: convert::us(m.ts),
        flow_id: m.flow_id.map(|f| f.to_string()),
        transport: if m.transport == 6 { "tcp" } else { "udp" }.to_owned(),
        protocol: DnsProtocol::of_stored(&m.proto),
        client_ip: m.client_ip,
        client_port: m.client_port,
        server_ip: m.server_ip,
        server_port: m.server_port,
        responder_ip: m.responder_ip,
        txid: m.txid,
        opcode: m.opcode,
        qname: m.qname,
        qtype: m.qtype,
        nb_suffix: m.nb_suffix,
        flags: m.flags,
        rcode: m.rcode,
        latency_us: m.latency_ns.map(convert::us),
        answers: m
            .answers
            .into_iter()
            .map(|a| DnsAnswer {
                name: a.name,
                rtype: a.rtype,
                value: a.value,
                ttl: a.ttl,
            })
            .collect(),
        has_query: m.has_query,
        has_response: m.has_response,
    }
}

fn build_messages(
    state: &AppState,
    id: &SessionId,
    query: &ListQuery,
) -> Result<Page<DnsMessage>, ApiError> {
    let filter = query.filter()?;
    let pair = query.pair()?;
    let Some(session) = open(state, id)? else {
        return Ok(empty());
    };
    let (page, total) = store::messages_page(session.conn(), pair, &filter, &query.request())?;
    Ok(Page {
        items: page.items.into_iter().map(message).collect(),
        next_cursor: page.next_cursor,
        total_estimate: Some(total),
    })
}

fn build_servers(
    state: &AppState,
    id: &SessionId,
    query: &ListQuery,
) -> Result<Page<DnsServer>, ApiError> {
    let Some(session) = open(state, id)? else {
        return Ok(empty());
    };
    let (page, total) = store::servers_page(session.conn(), &query.request())?;
    Ok(Page {
        items: page
            .items
            .into_iter()
            .map(|s| DnsServer {
                host: Endpoint::new(s.ip, s.host),
                messages: s.messages,
                errors: s.errors,
                clients: s.clients,
                protocols: s
                    .protocols
                    .iter()
                    .map(|p| DnsProtocol::of_stored(p))
                    .collect(),
            })
            .collect(),
        next_cursor: page.next_cursor,
        total_estimate: Some(total),
    })
}

async fn stats(
    State(state): State<Arc<AppState>>,
    UrlPath(id): UrlPath<String>,
) -> Result<Json<DnsStats>, ApiError> {
    let id = parse_id(&id)?;
    blocking(&state, move |s| build_stats(s, &id))
        .await
        .map(Json)
}

async fn pairs(
    State(state): State<Arc<AppState>>,
    UrlPath(id): UrlPath<String>,
    crate::extract::ApiQuery(query): crate::extract::ApiQuery<ListQuery>,
) -> Result<Json<Page<DnsPair>>, ApiError> {
    let id = parse_id(&id)?;
    blocking(&state, move |s| build_pairs(s, &id, &query))
        .await
        .map(Json)
}

async fn messages(
    State(state): State<Arc<AppState>>,
    UrlPath(id): UrlPath<String>,
    crate::extract::ApiQuery(query): crate::extract::ApiQuery<ListQuery>,
) -> Result<Json<Page<DnsMessage>>, ApiError> {
    let id = parse_id(&id)?;
    blocking(&state, move |s| build_messages(s, &id, &query))
        .await
        .map(Json)
}

async fn servers(
    State(state): State<Arc<AppState>>,
    UrlPath(id): UrlPath<String>,
    crate::extract::ApiQuery(query): crate::extract::ApiQuery<ListQuery>,
) -> Result<Json<Page<DnsServer>>, ApiError> {
    let id = parse_id(&id)?;
    blocking(&state, move |s| build_servers(s, &id, &query))
        .await
        .map(Json)
}

#[cfg(test)]
mod tests;
