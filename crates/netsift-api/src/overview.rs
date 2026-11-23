//! Overview routes: session summary and traffic time series by protocol.
//!
//! | Method | Path | Response |
//! |---|---|---|
//! | GET | `/sessions/{id}/summary?from_us&to_us` | [`OverviewSummary`] |
//! | GET | `/sessions/{id}/modules?from_us&to_us` | [`ModuleCounts`] |
//! | GET | `/sessions/{id}/timeseries?from_us&to_us&points&metric&protocols` | [`TrafficSeries`] |
//!
//! Under a time range, the counters of the aggregated views (Connections, Hosts, Network, Open
//! Ports, Servers) come from the range database (ADR-030), whose first build can take seconds:
//! `/summary` never waits for it and marks them `pending`, `/modules` waits for it and gives them.
//!
//! All answer 409 (problem+json) while the session is importing or when its import failed, and
//! 404 for an unknown session. Incomplete sessions (cancelled or interrupted imports) are served.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::{Path as UrlPath, State};
use axum::routing::get;
use axum::{Json, Router};
use netsift_store::range::ModuleRows;
use netsift_store::ranges::CancelFlag;
use netsift_store::traffic::{self, BucketPlan};
use netsift_store::{Session, SessionId, SessionInfo, SessionState as StoreState, TimeRange};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::contract::SessionState;
use crate::extract::ApiQuery;
use crate::range::{AggregateRange, ApiRange, RangeParams, range_view};
use crate::sessions::{Stats, info, parse_id, session_dir};
use crate::{ApiError, AppState, blocking, convert};

/// Default and largest number of points of a time series.
pub(crate) const DEFAULT_POINTS: u32 = 1000;
pub(crate) const MAX_POINTS: u32 = 2000;
const US_PER_S: i64 = 1_000_000;

pub(crate) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/sessions/{id}/summary", get(summary))
        .route("/sessions/{id}/modules", get(modules))
        .route("/sessions/{id}/timeseries", get(timeseries))
}

/// Module counter of the overview (one card per analysis view).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct ModuleCount {
    /// Identifier of the view (`connections`, `hosts`, `dns`...).
    pub id: String,
    pub count: u64,
    /// Under a time range: whether `count` is that of the range (same rule as the list of the
    /// view), of the whole session (module not filtered), or still to be read from `/modules`
    /// (`pending`: `count` is then that of the session). `null` without range.
    pub scope: Option<CountScope>,
}

/// `GET /sessions/{id}/modules`: the counters of the aggregated views, under the time range from
/// its range database (built first if needed), else those of the session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct ModuleCounts {
    pub modules: Vec<ModuleCount>,
}

/// What a module counter covers under a time range (ADR-030).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum CountScope {
    Range,
    Session,
    /// Counted in the range database: read it from `/modules` (aggregated views).
    Pending,
}

/// Figures of the time range of a summary (`docs/specs/time-filter.md`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct RangeSummary {
    /// The range bounded to the captured period (inclusive, microseconds); `to_us < from_us`
    /// when it does not meet the session.
    pub from_us: i64,
    pub to_us: i64,
    pub duration_us: i64,
    /// Packets and on-wire bytes of the one-second buckets that intersect the range.
    pub packets: u64,
    pub bytes: u64,
    /// Flows and hosts active in the range (their span overlaps it).
    pub flow_count: u64,
    pub host_count: u64,
}

/// `GET /sessions/{id}/summary`: figures of the overview header and module cards.
#[derive(Debug, Clone, PartialEq, Serialize, TS)]
#[ts(export)]
pub struct OverviewSummary {
    pub id: String,
    pub name: String,
    pub state: SessionState,
    /// Captured period (first and last packet), `null` when the session has no packet.
    pub first_ts_us: Option<i64>,
    pub last_ts_us: Option<i64>,
    pub duration_us: Option<i64>,
    pub packets: u64,
    /// On-wire bytes of every packet.
    pub bytes: u64,
    pub chunk_count: u32,
    /// Distinct link types of the chunks (pcap `LINKTYPE_*` values), ascending.
    pub linktypes: Vec<u32>,
    pub host_count: u64,
    pub flow_count: u64,
    pub anomaly_count: u32,
    /// Row counts of the analysis modules present in this session. A module whose table does
    /// not exist (added by a later version, or not run) is absent, not 0.
    pub modules: Vec<ModuleCount>,
    /// Figures of the time range asked for (`from_us` / `to_us`), `null` without range or when
    /// it covers the whole session.
    pub range: Option<RangeSummary>,
}

/// Series of the traffic chart, in display order. Stored protocol labels (`timeseries.proto`,
/// `netsift_analyze::classify`) are folded into these.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum TrafficProtocol {
    Dns,
    Http,
    Tls,
    Smb,
    Netbios,
    Ssh,
    Quic,
    Dhcp,
    Snmp,
    /// 802.11 management frames.
    WifiMgmt,
    OtherTcp,
    OtherUdp,
    Other,
}

impl TrafficProtocol {
    pub(crate) const ALL: [Self; 13] = [
        Self::Dns,
        Self::Http,
        Self::Tls,
        Self::Smb,
        Self::Netbios,
        Self::Ssh,
        Self::Quic,
        Self::Dhcp,
        Self::Snmp,
        Self::WifiMgmt,
        Self::OtherTcp,
        Self::OtherUdp,
        Self::Other,
    ];

    fn id(self) -> &'static str {
        match self {
            Self::Dns => "dns",
            Self::Http => "http",
            Self::Tls => "tls",
            Self::Smb => "smb",
            Self::Netbios => "netbios",
            Self::Ssh => "ssh",
            Self::Quic => "quic",
            Self::Dhcp => "dhcp",
            Self::Snmp => "snmp",
            Self::WifiMgmt => "wifi_mgmt",
            Self::OtherTcp => "other_tcp",
            Self::OtherUdp => "other_udp",
            Self::Other => "other",
        }
    }

    fn from_id(id: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.id() == id)
    }

    /// Series of a stored label. Labels of the series keep their name; the other well-known
    /// ones go to the "other" series of their usual transport (the time series does not keep
    /// the transport of a label). Unknown labels, ICMP, other IP protocols, non-IP frames and
    /// labels common on both transports (Kerberos) go to `Other`.
    pub(crate) fn of_label(label: &str) -> Self {
        match label {
            "ftp" | "imap" | "ldap" | "pop3" | "rdp" | "smtp" | "telnet" | "tcp" => Self::OtherTcp,
            "ntp" | "sip" | "ssdp" | "syslog" | "udp" => Self::OtherUdp,
            other => Self::from_id(other)
                .filter(|p| !matches!(p, Self::OtherTcp | Self::OtherUdp | Self::Other))
                .unwrap_or(Self::Other),
        }
    }
}

/// One protocol of [`TrafficSeries`]. Values are sums per bucket; the metric not asked for is
/// `null`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct ProtocolSeries {
    pub protocol: TrafficProtocol,
    pub bytes: Option<Vec<u64>>,
    pub packets: Option<Vec<u64>>,
    /// Totals over the buckets, both metrics, always: the aligned period
    /// `[start_us, start_us + points * step_us)`, which contains the requested one. They equal the
    /// sums of the bucket values.
    pub total_bytes: u64,
    pub total_packets: u64,
}

/// `GET /sessions/{id}/timeseries`: traffic per protocol, resampled on the server.
///
/// Bucket `i` covers `[start_us + i * step_us, start_us + (i + 1) * step_us)`. Buckets have a
/// round width (1 s, 2 s, 5 s... 1 min, 2 min... 1 h... days) aligned on the clock. Protocols
/// without traffic in the period are absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct TrafficSeries {
    pub start_us: i64,
    pub step_us: i64,
    /// Number of buckets (`0` when the session has no traffic and no period was asked for).
    pub points: u32,
    pub series: Vec<ProtocolSeries>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Metric {
    Bytes,
    Packets,
}

#[derive(Debug, Default, Deserialize)]
struct TrafficQuery {
    /// Start of the period (microseconds), default: first second of traffic.
    from_us: Option<i64>,
    /// End of the period (microseconds, inclusive), default: last second of traffic.
    to_us: Option<i64>,
    /// Upper bound of the number of buckets: default 1000, clamped to `1..=2000`.
    points: Option<u32>,
    /// Only this metric (`bytes` or `packets`); both when absent.
    metric: Option<Metric>,
    /// Comma-separated protocols to return; all when absent, none when empty.
    protocols: Option<String>,
}

/// Registration point: one line per analysis module, sorted by id. A module is listed in the
/// summary with the row count of its table when the table exists in the session.
const MODULES: &[(&str, &str)] = &[
    ("arp", "arp_messages"),
    ("connections", "conversations"),
    ("credentials", "credentials"),
    ("dns", "dns_messages"),
    ("ethernet", "eth_macs"),
    ("ftp", "ftp_sessions"),
    ("hosts", "hosts"),
    ("http", "http_transactions"),
    ("httpHeaders", "http_headers"),
    ("network", "network_hosts"),
    ("openPorts", "open_ports"),
    ("pictures", "pictures"),
    ("servers", "server_roles"),
    ("sip", "sip_messages"),
    ("smb", "smb_items"),
    ("ssdp", "ssdp_messages"),
    ("telnet", "telnet_sessions"),
    ("tls", "tls_sessions"),
];

/// Count over a time range of a module of [`MODULES`] read from the session; `None` for the
/// aggregated views, counted in the range database ([`aggregated`], `/modules`). Sorted by id.
fn ranged_rows(module: &str) -> Option<ModuleRows> {
    match module {
        "arp" => Some(ModuleRows::ArpMessages),
        "credentials" => Some(ModuleRows::Credentials),
        "dns" => Some(ModuleRows::DnsMessages),
        "ethernet" => Some(ModuleRows::EthernetMacs),
        "ftp" => Some(ModuleRows::FtpSessions),
        "http" => Some(ModuleRows::HttpTransactions),
        "httpHeaders" => Some(ModuleRows::HttpHeaders),
        "pictures" => Some(ModuleRows::Pictures),
        "sip" => Some(ModuleRows::Sip),
        "smb" => Some(ModuleRows::Smb),
        "ssdp" => Some(ModuleRows::Ssdp),
        "telnet" => Some(ModuleRows::Telnet),
        "tls" => Some(ModuleRows::TlsSessions),
        _ => None,
    }
}

/// Opens a session whose data can be shown: 404 when unknown, 409 while importing or failed.
/// A session created by an older build is upgraded first, except on a read-only server (ADR-013).
pub(crate) fn open_ready(
    state: &AppState,
    id: &SessionId,
) -> Result<(SessionInfo, Session), ApiError> {
    let info = info(state, id)?;
    match info.state {
        StoreState::Importing => {
            return Err(ApiError::Conflict(
                "the session is still being imported".to_owned(),
            ));
        }
        StoreState::Failed => return Err(ApiError::Conflict("the import failed".to_owned())),
        StoreState::Ready | StoreState::Incomplete => {}
    }
    let dir = session_dir(state, id);
    if !dir.join(netsift_store::session::SESSION_DB).is_file() {
        return Err(ApiError::NotFound);
    }
    let session = Session::open_finished(dir, crate::sessions::upgrade_policy(state))?;
    Ok((info, session))
}

/// Modules of the aggregated views: counted under a range in its range database (ADR-030).
fn aggregated(module: &str) -> bool {
    matches!(
        module,
        "connections" | "hosts" | "network" | "openPorts" | "servers"
    )
}

fn build_summary(
    state: &AppState,
    id: &SessionId,
    range: RangeParams,
) -> Result<OverviewSummary, ApiError> {
    let (info, session) = open_ready(state, id)?;
    let range = range.resolve(&session)?;
    let conn = session.conn();
    let stats = Stats::of(&session);
    let (bytes, ts_packets) = traffic::traffic_totals(conn)?;
    // Each table is counted once: `flows` (core schema) comes with the stats, the others are
    // counted on first use (module registry, host figure).
    let mut counts: BTreeMap<&'static str, Option<u64>> =
        BTreeMap::from([("flows", Some(stats.flows))]);
    let mut count = |table: &'static str| -> Result<Option<u64>, ApiError> {
        if let Some(n) = counts.get(table) {
            return Ok(*n);
        }
        let n = traffic::count_rows(conn, table)?;
        counts.insert(table, n);
        Ok(n)
    };
    let mut modules = Vec::with_capacity(MODULES.len());
    for (module, table) in MODULES {
        if let Some(session_count) = count(table)? {
            let (count, scope) = match (range, ranged_rows(module)) {
                (None, _) => (session_count, None),
                (Some(r), Some(rows)) => (rows.count(conn, r)?, Some(CountScope::Range)),
                // Never wait for the range database here (`/modules`).
                (Some(_), None) if aggregated(module) => (session_count, Some(CountScope::Pending)),
                (Some(_), None) => (session_count, Some(CountScope::Session)),
            };
            modules.push(ModuleCount {
                id: (*module).to_owned(),
                count,
                scope,
            });
        }
    }
    let host_count = count("hosts")?.unwrap_or(0);
    let duration_us = stats
        .first_ts
        .zip(stats.last_ts)
        .map(|(first, last)| convert::us(last.saturating_sub(first)));
    Ok(OverviewSummary {
        id: info.id.to_string(),
        name: info.name,
        state: convert::state(info.state),
        first_ts_us: stats.first_ts.map(convert::us),
        last_ts_us: stats.last_ts.map(convert::us),
        duration_us,
        // Written at the end of the import; an interrupted one may lack it.
        packets: if stats.packets == 0 {
            ts_packets
        } else {
            stats.packets
        },
        bytes,
        chunk_count: stats.chunks,
        linktypes: traffic::linktypes(conn)?,
        host_count,
        flow_count: stats.flows,
        anomaly_count: stats.anomalies,
        modules,
        range: range
            .map(|r| range_summary(&session, r, stats.first_ts, stats.last_ts))
            .transpose()?,
    })
}

fn range_summary(
    session: &Session,
    range: TimeRange,
    first: Option<i64>,
    last: Option<i64>,
) -> Result<RangeSummary, ApiError> {
    let from = first.map_or(range.from_ns(), |f| f.max(range.from_ns()));
    let to = last.map_or(range.to_ns().saturating_sub(1), |l| {
        l.min(range.to_ns().saturating_sub(1))
    });
    let conn = session.conn();
    let (bytes, packets) = traffic::traffic_totals_in(conn, range)?;
    Ok(RangeSummary {
        from_us: convert::us(from),
        to_us: convert::us(to),
        duration_us: convert::us(to.saturating_sub(from).max(0)),
        packets,
        bytes,
        flow_count: netsift_store::range::count_active_flows(conn, range)?,
        host_count: netsift_store::range::count_active_hosts(conn, range)?,
    })
}

async fn summary(
    State(state): State<Arc<AppState>>,
    UrlPath(id): UrlPath<String>,
    ApiRange(range): ApiRange,
) -> Result<Json<OverviewSummary>, ApiError> {
    let id = parse_id(&id)?;
    blocking(&state, move |s| build_summary(s, &id, range))
        .await
        .map(Json)
}

/// Counters of the aggregated views ([`aggregated`]) present in the session: under a range, from
/// its range database (the call waits for its build), else those of the session.
fn build_modules(
    state: &AppState,
    id: &SessionId,
    range: RangeParams,
    cancel: &CancelFlag,
) -> Result<ModuleCounts, ApiError> {
    let (_, session) = open_ready(state, id)?;
    let range = range.resolve(&session)?;
    let mut range_db: Option<netsift_store::ranges::RangeView> = None;
    let mut modules = Vec::new();
    for (module, table) in MODULES.iter().filter(|(m, _)| aggregated(m)) {
        let Some(session_count) = traffic::count_rows(session.conn(), table)? else {
            continue;
        };
        let (count, scope) = match range {
            None => (session_count, None),
            Some(r) => {
                let view = match range_db.take() {
                    Some(view) => view,
                    None => range_view(state, id, &session, r, cancel)?,
                };
                let n = traffic::count_rows(view.conn(), table)?.unwrap_or(0);
                range_db = Some(view);
                (n, Some(CountScope::Range))
            }
        };
        modules.push(ModuleCount {
            id: (*module).to_owned(),
            count,
            scope,
        });
    }
    Ok(ModuleCounts { modules })
}

async fn modules(
    State(state): State<Arc<AppState>>,
    UrlPath(id): UrlPath<String>,
    range: AggregateRange,
) -> Result<Json<ModuleCounts>, ApiError> {
    let id = parse_id(&id)?;
    let (params, cancel) = (range.params, range.flag());
    blocking(&state, move |s| build_modules(s, &id, params, &cancel))
        .await
        .map(Json)
}

fn parse_protocols(raw: Option<&str>) -> Result<Vec<TrafficProtocol>, ApiError> {
    let Some(raw) = raw else {
        return Ok(TrafficProtocol::ALL.to_vec());
    };
    raw.split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(|p| {
            TrafficProtocol::from_id(p)
                .ok_or_else(|| ApiError::BadRequest("protocols: unknown protocol".to_owned()))
        })
        .collect()
}

#[derive(Default)]
struct Accumulator {
    bytes: Vec<u64>,
    packets: Vec<u64>,
    total_bytes: u64,
    total_packets: u64,
}

fn build_series(
    state: &AppState,
    id: &SessionId,
    query: &TrafficQuery,
) -> Result<TrafficSeries, ApiError> {
    let wanted = parse_protocols(query.protocols.as_deref())?;
    let max_points = query.points.unwrap_or(DEFAULT_POINTS).clamp(1, MAX_POINTS);
    let (_, session) = open_ready(state, id)?;
    let conn = session.conn();

    if let (Some(from), Some(to)) = (query.from_us, query.to_us)
        && to < from
    {
        return Err(ApiError::BadRequest(
            "range: the end is before the start".to_owned(),
        ));
    }
    let to_s = |us: i64| us.div_euclid(US_PER_S);
    let bounds = traffic::traffic_bounds(conn)?;
    let (from_s, to_s) = match (query.from_us.map(to_s), query.to_us.map(to_s), bounds) {
        (Some(from), Some(to), _) => (from, to),
        (Some(from), None, b) => (from, b.map_or(from, |(_, last)| last.max(from))),
        (None, Some(to), b) => (b.map_or(to, |(first, _)| first.min(to)), to),
        (None, None, Some((first, last))) => (first, last),
        (None, None, None) => {
            return Ok(TrafficSeries {
                start_us: 0,
                step_us: US_PER_S,
                points: 0,
                series: Vec::new(),
            });
        }
    };
    let plan = BucketPlan::new(from_s, to_s, max_points)?;
    let n = usize::try_from(plan.points).unwrap_or(0);

    let mut acc: BTreeMap<TrafficProtocol, Accumulator> = BTreeMap::new();
    for row in traffic::resample(conn, &plan)? {
        let protocol = TrafficProtocol::of_label(&row.proto);
        if !wanted.contains(&protocol) {
            continue;
        }
        let a = acc.entry(protocol).or_insert_with(|| Accumulator {
            bytes: vec![0; n],
            packets: vec![0; n],
            ..Accumulator::default()
        });
        let i = usize::try_from(row.index).unwrap_or(usize::MAX);
        if let (Some(b), Some(p)) = (a.bytes.get_mut(i), a.packets.get_mut(i)) {
            *b = b.saturating_add(row.bytes);
            *p = p.saturating_add(row.packets);
        }
        a.total_bytes = a.total_bytes.saturating_add(row.bytes);
        a.total_packets = a.total_packets.saturating_add(row.packets);
    }

    let series = acc
        .into_iter()
        .filter(|(_, a)| a.total_bytes > 0 || a.total_packets > 0)
        .map(|(protocol, a)| ProtocolSeries {
            protocol,
            bytes: (query.metric != Some(Metric::Packets)).then_some(a.bytes),
            packets: (query.metric != Some(Metric::Bytes)).then_some(a.packets),
            total_bytes: a.total_bytes,
            total_packets: a.total_packets,
        })
        .collect();
    Ok(TrafficSeries {
        start_us: plan.start_s.saturating_mul(US_PER_S),
        step_us: plan.step_s.saturating_mul(US_PER_S),
        points: plan.points,
        series,
    })
}

async fn timeseries(
    State(state): State<Arc<AppState>>,
    UrlPath(id): UrlPath<String>,
    ApiQuery(query): ApiQuery<TrafficQuery>,
) -> Result<Json<TrafficSeries>, ApiError> {
    let id = parse_id(&id)?;
    blocking(&state, move |s| build_series(s, &id, &query))
        .await
        .map(Json)
}

#[cfg(test)]
mod tests;
