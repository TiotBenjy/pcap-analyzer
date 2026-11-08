//! Read queries of the Network view: a communication graph folded from the `conversations`,
//! `hosts`, `host_traffic` and `open_ports` tables (no table of its own).
//!
//! The graph is **bounded on the server**: in host mode, the `limit` hosts with the most bytes
//! get their own node, the other public hosts are folded into one cluster node per country (at
//! most [`MAX_CLUSTERS`], largest first) and everything else into one "other" node. In country
//! mode, a node is a country, the local addresses (never geolocated) or the public addresses of
//! unknown country. Edges are undirected pairs of nodes, at most [`MAX_EDGES`], largest first.
//!
//! Every query is one scan of `conversations` (hosts looked up by primary key): the table holds
//! one row per (client, server) pair, much smaller than `flows`. Sums use `total()` (no integer
//! overflow error) clamped to `i64::MAX`.

use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;

use rusqlite::{Connection, ToSql, params, params_from_iter};

use crate::connections::EndpointInfo;
use crate::error::Result;
use crate::records::conversion;

/// Smallest and largest number of host nodes in host mode (countries in country mode).
pub const MIN_NODES: u32 = 10;
pub const MAX_NODES: u32 = 150;
/// Country clusters of host mode (the remaining public hosts), largest first.
pub const MAX_CLUSTERS: usize = 15;
/// Hosts of an expanded cluster drawn as their own node, on top of the top N.
pub const EXPAND_HOSTS: u32 = 30;
/// Edges returned, largest first.
pub const MAX_EDGES: usize = 400;
/// Orphan hosts added when asked for, most traffic first.
pub const MAX_ORPHANS: u32 = 30;
/// Neighbors listed by [`node_detail`].
pub const MAX_NEIGHBORS: u32 = 10;
/// Open ports listed by [`node_detail`].
pub const MAX_NODE_PORTS: u32 = 50;

/// Protocol filters of the view: groups of conversation labels (`AppProto` labels of the
/// `connections` analyzer). "Other" is every label outside the groups.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProtocolGroup {
    Dns,
    Http,
    Https,
    Ssh,
    Ftp,
    Telnet,
    Rdp,
    Smb,
    Tcp,
    Udp,
    Other,
}

impl ProtocolGroup {
    /// Every group, in display order.
    pub const ALL: [Self; 11] = [
        Self::Dns,
        Self::Http,
        Self::Https,
        Self::Ssh,
        Self::Ftp,
        Self::Telnet,
        Self::Rdp,
        Self::Smb,
        Self::Tcp,
        Self::Udp,
        Self::Other,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Dns => "dns",
            Self::Http => "http",
            Self::Https => "https",
            Self::Ssh => "ssh",
            Self::Ftp => "ftp",
            Self::Telnet => "telnet",
            Self::Rdp => "rdp",
            Self::Smb => "smb",
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Other => "other",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|g| g.as_str() == s)
    }

    /// Conversation labels of the group (empty for `Other`).
    pub fn labels(self) -> &'static [&'static str] {
        match self {
            Self::Dns => &["dns"],
            Self::Http => &["http"],
            Self::Https => &["tls"],
            Self::Ssh => &["ssh"],
            Self::Ftp => &["ftp"],
            Self::Telnet => &["telnet"],
            Self::Rdp => &["rdp"],
            Self::Smb => &["smb", "netbios"],
            Self::Tcp => &["tcp"],
            Self::Udp => &["udp"],
            Self::Other => &[],
        }
    }

    fn known_labels() -> Vec<&'static str> {
        Self::ALL.iter().flat_map(|g| g.labels()).copied().collect()
    }
}

/// Filters of the graph; `None` = no filter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphFilter {
    /// A conversation is kept when one of its labels is in one of the groups.
    pub protocols: Option<Vec<ProtocolGroup>>,
    /// Address categories (stored labels): both ends must be in one of them.
    pub categories: Option<Vec<String>>,
    /// Keep conversations with an IPv6 end.
    pub ipv6: bool,
}

impl Default for GraphFilter {
    fn default() -> Self {
        Self {
            protocols: None,
            categories: None,
            ipv6: true,
        }
    }
}

/// How hosts are grouped into nodes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GraphMode {
    /// Top `limit` hosts, country clusters, other; the hosts of `expand` (a country code) are
    /// also drawn as their own node (at most [`EXPAND_HOSTS`]).
    Hosts {
        limit: u32,
        expand: Option<String>,
        include_orphans: bool,
    },
    /// Top `limit` countries (with the local and unknown groups), other.
    Countries { limit: u32 },
}

/// Identity of a graph node.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum NodeKey {
    Host(IpAddr),
    /// Public hosts of one country outside the top N (host mode).
    Cluster(String),
    /// Hosts of one country (country mode).
    Country(String),
    /// Private, local and reserved addresses (country mode).
    Local,
    /// Public addresses of unknown country (country mode).
    Unknown,
    /// Every host not drawn otherwise.
    Other,
}

impl NodeKey {
    /// Stable id of the node within a graph (`h:<ip>`, `k:<cc>`, `c:<cc>`, `local`, `unknown`,
    /// `other`).
    pub fn id(&self) -> String {
        match self {
            Self::Host(ip) => format!("h:{ip}"),
            Self::Cluster(cc) => format!("k:{cc}"),
            Self::Country(cc) => format!("c:{cc}"),
            Self::Local => "local".to_owned(),
            Self::Unknown => "unknown".to_owned(),
            Self::Other => "other".to_owned(),
        }
    }

    fn parse(s: &str) -> Option<Self> {
        if let Some(ip) = s.strip_prefix("h:") {
            return ip.parse().ok().map(Self::Host);
        }
        if let Some(cc) = s.strip_prefix("k:") {
            return Some(Self::Cluster(cc.to_owned()));
        }
        if let Some(cc) = s.strip_prefix("c:") {
            return Some(Self::Country(cc.to_owned()));
        }
        match s {
            "local" => Some(Self::Local),
            "unknown" => Some(Self::Unknown),
            "other" => Some(Self::Other),
            _ => None,
        }
    }
}

/// A node with its traffic within the filtered graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphNode {
    pub key: NodeKey,
    /// Hosts behind the node (1 for a host).
    pub hosts: u64,
    /// Bytes sent and received by the node; a conversation between two hosts of the same node
    /// counts once.
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets: u64,
    /// Labels of the conversations of the node, sorted.
    pub protocols: Vec<String>,
    /// What the `hosts` table knows (host nodes only).
    pub info: Option<EndpointInfo>,
}

impl GraphNode {
    pub fn bytes(&self) -> u64 {
        self.bytes_sent.saturating_add(self.bytes_received)
    }
}

/// Traffic between two nodes (undirected; `source` is the smaller id).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphEdge {
    pub source: String,
    pub target: String,
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

impl GraphEdge {
    pub fn bytes(&self) -> u64 {
        self.bytes_fwd.saturating_add(self.bytes_rev)
    }
}

/// Bounded graph of [`graph`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Graph {
    /// Most bytes first; "other" last.
    pub nodes: Vec<GraphNode>,
    /// Most bytes first, at most [`MAX_EDGES`].
    pub edges: Vec<GraphEdge>,
    /// Hosts with traffic matching the filters.
    pub hosts: u64,
    /// Hosts drawn as their own node (orphans included).
    pub hosts_shown: u64,
    /// Pairs of nodes with traffic, before the edge limit.
    pub edges_total: u64,
    /// Hosts of the session without traffic matching the filters (category and IPv6 filters
    /// applied).
    pub orphans: u64,
    /// Bytes of the matching conversations.
    pub total_bytes: u64,
}

/// Clamped sum (no integer overflow error, `i64::MAX` at most).
fn sum(expr: &str) -> String {
    format!("CAST(min(total({expr}), 9223372036854775807.0) AS INTEGER)")
}

/// Filtered conversations with the category and country of both ends. Parameters: `?1` labels
/// (JSON, NULL = no protocol filter), `?2` other labels selected, `?3` known labels (JSON),
/// `?4` categories (JSON or NULL), `?5` IPv6 kept. Queries number their own parameters from 6.
const FILTERED: &str = "f AS (SELECT c.src_ip, c.dst_ip, c.bytes_fwd, c.bytes_rev, \
    c.packets_fwd, c.packets_rev, c.flows, c.protocols, \
    hs.country AS src_country, coalesce(hs.category, '') AS src_category, \
    hd.country AS dst_country, coalesce(hd.category, '') AS dst_category \
    FROM conversations c LEFT JOIN hosts hs ON hs.ip = c.src_ip \
    LEFT JOIN hosts hd ON hd.ip = c.dst_ip \
    WHERE (?1 IS NULL OR EXISTS (SELECT 1 FROM json_each(c.protocols) j \
        WHERE j.value IN (SELECT value FROM json_each(?1)) \
        OR (?2 AND j.value NOT IN (SELECT value FROM json_each(?3))))) \
    AND (?4 IS NULL OR (coalesce(hs.category, '') IN (SELECT value FROM json_each(?4)) \
        AND coalesce(hd.category, '') IN (SELECT value FROM json_each(?4)))) \
    AND (?5 OR (instr(c.src_ip, ':') = 0 AND instr(c.dst_ip, ':') = 0)))";

/// Bound values of [`FILTERED`].
struct FilterParams {
    labels: Option<String>,
    other: bool,
    known: String,
    categories: Option<String>,
    ipv6: bool,
}

impl FilterParams {
    fn new(filter: &GraphFilter) -> Result<Self> {
        let (labels, other) = match &filter.protocols {
            None => (None, false),
            Some(groups) => {
                let labels: Vec<&str> = groups.iter().flat_map(|g| g.labels()).copied().collect();
                (
                    Some(serde_json::to_string(&labels)?),
                    groups.contains(&ProtocolGroup::Other),
                )
            }
        };
        Ok(Self {
            labels,
            other,
            known: serde_json::to_string(&ProtocolGroup::known_labels())?,
            categories: filter
                .categories
                .as_ref()
                .map(serde_json::to_string)
                .transpose()?,
            ipv6: filter.ipv6,
        })
    }

    fn with<'a>(&'a self, extra: &[&'a dyn ToSql]) -> Vec<&'a dyn ToSql> {
        let mut out: Vec<&dyn ToSql> = vec![
            &self.labels,
            &self.other,
            &self.known,
            &self.categories,
            &self.ipv6,
        ];
        out.extend_from_slice(extra);
        out
    }
}

/// Node key of an end in country mode.
fn country_key(end: &str) -> String {
    format!(
        "CASE WHEN {end}_country IS NOT NULL THEN 'c:' || {end}_country \
         WHEN {end}_category = 'public' THEN 'unknown' ELSE 'local' END"
    )
}

/// Node key of an end in host mode: `?6` hosts drawn (JSON), `?7` clusters kept (JSON).
fn host_key(end: &str) -> String {
    format!(
        "CASE WHEN {end}_ip IN (SELECT value FROM json_each(?6)) THEN 'h:' || {end}_ip \
         WHEN {end}_country IN (SELECT value FROM json_each(?7)) THEN 'k:' || {end}_country \
         ELSE 'other' END"
    )
}

/// Traffic between two node keys, as stored (directed: `a` is the client side).
struct Group {
    a: String,
    b: String,
    fwd: u64,
    rev: u64,
    packets: u64,
    flows: u64,
    conversations: u64,
    protocols: Vec<String>,
}

fn groups(conn: &Connection, sql: &str, params: &[&dyn ToSql]) -> Result<Vec<Group>> {
    let mut stmt = conn.prepare(sql)?;
    let rows = stmt.query_map(params_from_iter(params.iter()), |r| {
        let protocols: Option<String> = r.get(7)?;
        let protocols = match protocols {
            None => Vec::new(),
            // `group_concat` of JSON arrays: `["dns","udp"],["tcp"]`.
            Some(raw) => serde_json::from_str::<Vec<Vec<String>>>(&format!("[{raw}]"))
                .map_err(|e| conversion(7, e))?
                .into_iter()
                .flatten()
                .collect(),
        };
        Ok(Group {
            a: r.get(0)?,
            b: r.get(1)?,
            fwd: r.get(2)?,
            rev: r.get(3)?,
            packets: r.get(4)?,
            flows: r.get(5)?,
            conversations: r.get(6)?,
            protocols,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

fn group_sql(a: &str, b: &str) -> String {
    format!(
        "WITH {FILTERED}, m AS (SELECT {a} AS a, {b} AS b, bytes_fwd, bytes_rev, \
         packets_fwd + packets_rev AS packets, flows, protocols FROM f) \
         SELECT a, b, {}, {}, {}, {}, count(*), group_concat(DISTINCT protocols) \
         FROM m GROUP BY a, b",
        sum("bytes_fwd"),
        sum("bytes_rev"),
        sum("packets"),
        sum("flows"),
    )
}

#[derive(Default)]
struct NodeAcc {
    hosts: u64,
    sent: u64,
    received: u64,
    packets: u64,
    protocols: BTreeSet<String>,
}

#[derive(Default)]
struct EdgeAcc {
    fwd: u64,
    rev: u64,
    packets: u64,
    flows: u64,
    conversations: u64,
    protocols: BTreeSet<String>,
}

/// Folds directed groups into nodes and undirected edges; `node` maps a raw key to the key
/// of the node drawn (`None`: dropped, an invalid key).
fn fold(
    groups: Vec<Group>,
    node: impl Fn(&str) -> Option<NodeKey>,
    nodes: &mut HashMap<NodeKey, NodeAcc>,
) -> (HashMap<(NodeKey, NodeKey), EdgeAcc>, u64) {
    let mut edges: HashMap<(NodeKey, NodeKey), EdgeAcc> = HashMap::new();
    let mut total = 0_u64;
    for g in groups {
        let (Some(a), Some(b)) = (node(&g.a), node(&g.b)) else {
            continue;
        };
        total = total.saturating_add(g.fwd.saturating_add(g.rev));
        let na = nodes.entry(a.clone()).or_default();
        na.sent = na.sent.saturating_add(g.fwd);
        na.received = na.received.saturating_add(g.rev);
        na.packets = na.packets.saturating_add(g.packets);
        na.protocols.extend(g.protocols.iter().cloned());
        if a == b {
            // Traffic inside one node (cluster, other, a host talking to itself): no edge.
            continue;
        }
        let nb = nodes.entry(b.clone()).or_default();
        nb.sent = nb.sent.saturating_add(g.rev);
        nb.received = nb.received.saturating_add(g.fwd);
        nb.packets = nb.packets.saturating_add(g.packets);
        nb.protocols.extend(g.protocols.iter().cloned());
        let (key, fwd, rev) = if a.id() <= b.id() {
            ((a, b), g.fwd, g.rev)
        } else {
            ((b, a), g.rev, g.fwd)
        };
        let e = edges.entry(key).or_default();
        e.fwd = e.fwd.saturating_add(fwd);
        e.rev = e.rev.saturating_add(rev);
        e.packets = e.packets.saturating_add(g.packets);
        e.flows = e.flows.saturating_add(g.flows);
        e.conversations = e.conversations.saturating_add(g.conversations);
        e.protocols.extend(g.protocols);
    }
    (edges, total)
}

fn finish(
    nodes: HashMap<NodeKey, NodeAcc>,
    edges: HashMap<(NodeKey, NodeKey), EdgeAcc>,
    infos: &mut HashMap<IpAddr, EndpointInfo>,
) -> (Vec<GraphNode>, Vec<GraphEdge>, u64) {
    let mut nodes: Vec<GraphNode> = nodes
        .into_iter()
        .map(|(key, n)| GraphNode {
            info: match &key {
                NodeKey::Host(ip) => Some(infos.remove(ip).unwrap_or_default()),
                _ => None,
            },
            key,
            hosts: n.hosts,
            bytes_sent: n.sent,
            bytes_received: n.received,
            packets: n.packets,
            protocols: n.protocols.into_iter().collect(),
        })
        .collect();
    nodes.sort_by(|a, b| {
        (a.key == NodeKey::Other)
            .cmp(&(b.key == NodeKey::Other))
            .then_with(|| b.bytes().cmp(&a.bytes()))
            .then_with(|| a.key.cmp(&b.key))
    });
    let edges_total = u64::try_from(edges.len()).unwrap_or(u64::MAX);
    let mut edges: Vec<GraphEdge> = edges
        .into_iter()
        .map(|((a, b), e)| GraphEdge {
            source: a.id(),
            target: b.id(),
            bytes_fwd: e.fwd,
            bytes_rev: e.rev,
            packets: e.packets,
            flows: e.flows,
            conversations: e.conversations,
            protocols: e.protocols.into_iter().collect(),
        })
        .collect();
    edges.sort_by(|a, b| {
        b.bytes()
            .cmp(&a.bytes())
            .then_with(|| a.source.cmp(&b.source))
            .then_with(|| a.target.cmp(&b.target))
    });
    edges.truncate(MAX_EDGES);
    (nodes, edges, edges_total)
}

fn endpoint_infos(conn: &Connection, ips: &[String]) -> Result<HashMap<IpAddr, EndpointInfo>> {
    let mut stmt = conn.prepare(
        "SELECT ip, names, category, country FROM hosts \
         WHERE ip IN (SELECT value FROM json_each(?1))",
    )?;
    let rows = stmt.query_map([serde_json::to_string(ips)?], |r| {
        let ip: String = r.get(0)?;
        let names: String = r.get(1)?;
        Ok((
            ip.parse::<IpAddr>().map_err(|e| conversion(0, e))?,
            EndpointInfo {
                names: serde_json::from_str(&names).map_err(|e| conversion(1, e))?,
                category: r.get(2)?,
                country: r.get(3)?,
            },
        ))
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// Hosts of the session without matching traffic: their number and, when `list > 0`, the
/// `list` ones with the most traffic overall.
fn orphans(conn: &Connection, p: &FilterParams, list: u32) -> Result<(u64, Vec<String>)> {
    let base = format!(
        "WITH {FILTERED}, seen AS (SELECT src_ip AS ip FROM f UNION SELECT dst_ip FROM f) \
         SELECT h.ip FROM hosts h LEFT JOIN host_traffic t ON t.ip = h.ip \
         WHERE h.ip NOT IN (SELECT ip FROM seen) \
         AND (?4 IS NULL OR coalesce(h.category, '') IN (SELECT value FROM json_each(?4))) \
         AND (?5 OR instr(h.ip, ':') = 0)"
    );
    let count: i64 = conn.query_row(
        &format!("SELECT count(*) FROM ({base})"),
        params_from_iter(p.with(&[]).iter()),
        |r| r.get(0),
    )?;
    let mut ips = Vec::new();
    if list > 0 && count > 0 {
        let sql = format!(
            "{base} ORDER BY coalesce(t.bytes_sent, 0) + coalesce(t.bytes_received, 0) DESC, \
             h.ip LIMIT ?6"
        );
        let limit = i64::from(list);
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(params_from_iter(p.with(&[&limit]).iter()), |r| r.get(0))?;
        ips = rows.collect::<rusqlite::Result<_>>()?;
    }
    Ok((u64::try_from(count).unwrap_or(0), ips))
}

/// Host mode: ranking of the hosts, then the traffic between the nodes drawn.
fn host_graph(
    conn: &Connection,
    p: &FilterParams,
    limit: u32,
    expand: Option<&str>,
    include_orphans: bool,
) -> Result<Graph> {
    // 1. Hosts ranked by bytes: the top N (and the top hosts of the expanded country) keep
    //    their own node, the others are counted per cluster.
    let rank = format!(
        "WITH {FILTERED}, \
         e AS (SELECT src_ip AS ip, src_country AS country, bytes_fwd + bytes_rev AS b FROM f \
           UNION ALL SELECT dst_ip, dst_country, bytes_fwd + bytes_rev FROM f WHERE dst_ip <> src_ip), \
         h AS (SELECT ip, country, total(b) AS b FROM e GROUP BY ip), \
         r AS (SELECT ip, country, b, row_number() OVER (ORDER BY b DESC, ip) AS rn, \
           row_number() OVER (PARTITION BY country ORDER BY b DESC, ip) AS crn FROM h), \
         k AS (SELECT CASE WHEN rn <= ?6 OR (country = ?7 AND crn <= ?8) THEN 'h' \
           WHEN country IS NOT NULL THEN 'k' ELSE 'o' END AS kind, ip, country, b FROM r) \
         SELECT kind, CASE kind WHEN 'h' THEN ip WHEN 'k' THEN country ELSE '' END AS key, \
         count(*), total(b) FROM k GROUP BY kind, key"
    );
    let limit = i64::from(limit.clamp(MIN_NODES, MAX_NODES));
    let expand_hosts = i64::from(EXPAND_HOSTS);
    let mut stmt = conn.prepare(&rank)?;
    let rows = stmt.query_map(
        params_from_iter(p.with(&[&limit, &expand, &expand_hosts]).iter()),
        |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, u64>(2)?,
                r.get::<_, f64>(3)?,
            ))
        },
    )?;
    let mut hosts = Vec::new();
    let mut clusters: Vec<(String, u64, f64)> = Vec::new();
    let mut other_hosts = 0_u64;
    let mut total_hosts = 0_u64;
    for row in rows {
        let (kind, key, count, bytes) = row?;
        total_hosts = total_hosts.saturating_add(count);
        match kind.as_str() {
            "h" => hosts.push(key),
            "k" => clusters.push((key, count, bytes)),
            _ => other_hosts = other_hosts.saturating_add(count),
        }
    }
    drop(stmt);
    clusters.sort_by(|a, b| b.2.total_cmp(&a.2).then_with(|| a.0.cmp(&b.0)));
    for (_, count, _) in clusters.iter().skip(MAX_CLUSTERS) {
        other_hosts = other_hosts.saturating_add(*count);
    }
    clusters.truncate(MAX_CLUSTERS);

    // 2. Traffic between the nodes drawn.
    let hosts_json = serde_json::to_string(&hosts)?;
    let kept: Vec<&str> = clusters.iter().map(|c| c.0.as_str()).collect();
    let kept_json = serde_json::to_string(&kept)?;
    let sql = group_sql(&host_key("src"), &host_key("dst"));
    let raw = groups(conn, &sql, &p.with(&[&hosts_json, &kept_json]))?;
    let mut nodes: HashMap<NodeKey, NodeAcc> = HashMap::new();
    let (edges, total_bytes) = fold(raw, NodeKey::parse, &mut nodes);
    for ip in &hosts {
        if let Ok(ip) = ip.parse() {
            nodes.entry(NodeKey::Host(ip)).or_default().hosts = 1;
        }
    }
    for (cc, count, _) in &clusters {
        nodes.entry(NodeKey::Cluster(cc.clone())).or_default().hosts = *count;
    }
    if other_hosts > 0 {
        nodes.entry(NodeKey::Other).or_default().hosts = other_hosts;
    }

    // 3. Orphans: counted always, listed on demand within their own bound.
    let (orphan_count, orphan_ips) =
        orphans(conn, p, if include_orphans { MAX_ORPHANS } else { 0 })?;
    for ip in &orphan_ips {
        if let Ok(ip) = ip.parse() {
            nodes.entry(NodeKey::Host(ip)).or_default().hosts = 1;
        }
    }
    let mut all_hosts = hosts;
    all_hosts.extend(orphan_ips);
    let mut infos = endpoint_infos(conn, &all_hosts)?;
    let hosts_shown = u64::try_from(all_hosts.len()).unwrap_or(u64::MAX);
    let (nodes, edges, edges_total) = finish(nodes, edges, &mut infos);
    Ok(Graph {
        nodes,
        edges,
        hosts: total_hosts,
        hosts_shown,
        edges_total,
        orphans: orphan_count,
        total_bytes,
    })
}

/// Country mode: traffic between countries, then the top `limit` groups.
fn country_graph(conn: &Connection, p: &FilterParams, limit: u32) -> Result<Graph> {
    let sql = group_sql(&country_key("src"), &country_key("dst"));
    let raw = groups(conn, &sql, &p.with(&[]))?;

    // Hosts per group (an address always has the same country and category).
    let count_sql = format!(
        "WITH {FILTERED}, e AS (SELECT src_ip AS ip, src_country, src_category FROM f \
         UNION SELECT dst_ip, dst_country, dst_category FROM f) \
         SELECT {} AS key, count(*) FROM e GROUP BY key",
        country_key("src")
    );
    let mut stmt = conn.prepare(&count_sql)?;
    let counts: HashMap<String, u64> = stmt
        .query_map(params_from_iter(p.with(&[]).iter()), |r| {
            Ok((r.get(0)?, r.get(1)?))
        })?
        .collect::<rusqlite::Result<_>>()?;
    drop(stmt);

    // Ranking of the groups by bytes (traffic inside a group counted once).
    let mut bytes: HashMap<&str, u64> = HashMap::new();
    for g in &raw {
        let b = g.fwd.saturating_add(g.rev);
        let e = bytes.entry(g.a.as_str()).or_default();
        *e = e.saturating_add(b);
        if g.b != g.a {
            let e = bytes.entry(g.b.as_str()).or_default();
            *e = e.saturating_add(b);
        }
    }
    let mut ranked: Vec<(&str, u64)> = bytes.into_iter().collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
    let limit = usize::try_from(limit.clamp(MIN_NODES, MAX_NODES)).unwrap_or(usize::MAX);
    let kept: std::collections::HashSet<String> = ranked
        .iter()
        .take(limit)
        .map(|(k, _)| (*k).to_owned())
        .collect();
    let mut other_hosts = 0_u64;
    let total_hosts = counts.values().fold(0_u64, |a, b| a.saturating_add(*b));
    let mut nodes: HashMap<NodeKey, NodeAcc> = HashMap::new();
    for (key, count) in &counts {
        match NodeKey::parse(key) {
            Some(k) if kept.contains(key) => nodes.entry(k).or_default().hosts = *count,
            _ => other_hosts = other_hosts.saturating_add(*count),
        }
    }
    let (edges, total_bytes) = fold(
        raw,
        |k| {
            if kept.contains(k) {
                NodeKey::parse(k)
            } else {
                Some(NodeKey::Other)
            }
        },
        &mut nodes,
    );
    if let Some(other) = nodes.get_mut(&NodeKey::Other) {
        other.hosts = other_hosts;
    }
    let (orphan_count, _) = orphans(conn, p, 0)?;
    let (nodes, edges, edges_total) = finish(nodes, edges, &mut HashMap::new());
    Ok(Graph {
        nodes,
        edges,
        hosts: total_hosts,
        hosts_shown: 0,
        edges_total,
        orphans: orphan_count,
        total_bytes,
    })
}

/// Bounded communication graph of the session.
pub fn graph(conn: &Connection, filter: &GraphFilter, mode: &GraphMode) -> Result<Graph> {
    let p = FilterParams::new(filter)?;
    match mode {
        GraphMode::Hosts {
            limit,
            expand,
            include_orphans,
        } => host_graph(conn, &p, *limit, expand.as_deref(), *include_orphans),
        GraphMode::Countries { limit } => country_graph(conn, &p, *limit),
    }
}

/// Conversations carrying a label of each protocol group (whole session, no filter).
pub fn protocol_counts(conn: &Connection) -> Result<Vec<(ProtocolGroup, u64)>> {
    let mut values = Vec::new();
    for g in ProtocolGroup::ALL {
        for l in g.labels() {
            values.push(format!("('{l}', '{}')", g.as_str()));
        }
    }
    let sql = format!(
        "WITH g(label, grp) AS (VALUES {}) \
         SELECT coalesce(g.grp, 'other'), count(DISTINCT c.id) \
         FROM conversations c, json_each(c.protocols) j LEFT JOIN g ON g.label = j.value \
         GROUP BY 1",
        values.join(", ")
    );
    let mut stmt = conn.prepare(&sql)?;
    let counts: HashMap<String, u64> = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    Ok(ProtocolGroup::ALL
        .into_iter()
        .map(|g| (g, counts.get(g.as_str()).copied().unwrap_or(0)))
        .collect())
}

/// Open port of a host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodePort {
    pub port: u16,
    pub transport: u8,
    pub service: Option<String>,
}

/// A peer of a host and the traffic between them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Neighbor {
    pub ip: IpAddr,
    pub info: EndpointInfo,
    /// Host -> peer.
    pub bytes_sent: u64,
    /// Peer -> host.
    pub bytes_received: u64,
    pub protocols: Vec<String>,
}

/// Everything the session knows about one host (detail panel of the graph).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeDetail {
    pub ip: IpAddr,
    pub info: EndpointInfo,
    pub macs: Vec<String>,
    pub first_ts: Option<i64>,
    pub last_ts: Option<i64>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    /// Distinct peers (conversations in either direction).
    pub peers: u64,
    pub protocols: Vec<String>,
    /// At most [`MAX_NODE_PORTS`], by port.
    pub open_ports: Vec<NodePort>,
    /// At most [`MAX_NEIGHBORS`], most bytes first.
    pub neighbors: Vec<Neighbor>,
}

fn json_vec(raw: Option<String>, col: usize) -> rusqlite::Result<Vec<String>> {
    raw.map_or(Ok(Vec::new()), |raw| {
        serde_json::from_str(&raw).map_err(|e| conversion(col, e))
    })
}

/// Peers of a host (conversations in both directions, `UNIQUE (src_ip, dst_ip)` and `dst_ip`
/// indexes): their number and the [`MAX_NEIGHBORS`] with the most bytes.
fn neighbors(conn: &Connection, text: &str) -> Result<(u64, Vec<Neighbor>)> {
    let sql = format!(
        "WITH p AS (SELECT dst_ip AS peer, bytes_fwd AS sent, bytes_rev AS received, protocols \
           FROM conversations WHERE src_ip = ?1 \
           UNION ALL SELECT src_ip, bytes_rev, bytes_fwd, protocols \
           FROM conversations WHERE dst_ip = ?1 AND src_ip <> ?1) \
         SELECT peer, {}, {}, group_concat(DISTINCT protocols), count(*) OVER () \
         FROM p GROUP BY peer ORDER BY total(sent) + total(received) DESC, peer LIMIT ?2",
        sum("sent"),
        sum("received"),
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params![text, MAX_NEIGHBORS], |r| {
        let peer: String = r.get(0)?;
        let raw: Option<String> = r.get(3)?;
        let labels: BTreeSet<String> = match raw {
            None => BTreeSet::new(),
            Some(raw) => serde_json::from_str::<Vec<Vec<String>>>(&format!("[{raw}]"))
                .map_err(|e| conversion(3, e))?
                .into_iter()
                .flatten()
                .collect(),
        };
        Ok((
            Neighbor {
                ip: peer.parse::<IpAddr>().map_err(|e| conversion(0, e))?,
                info: EndpointInfo::default(),
                bytes_sent: r.get(1)?,
                bytes_received: r.get(2)?,
                protocols: labels.into_iter().collect(),
            },
            r.get::<_, u64>(4)?,
        ))
    })?;
    let mut count = 0;
    let mut out = Vec::new();
    for row in rows {
        let (n, total) = row?;
        count = total;
        out.push(n);
    }
    Ok((count, out))
}

/// Detail of one host; `None` when the session never saw it.
pub fn node_detail(conn: &Connection, ip: IpAddr) -> Result<Option<NodeDetail>> {
    let text = ip.to_string();
    let host = conn
        .query_row(
            "SELECT h.names, h.category, h.country, h.macs, h.first_ts, h.last_ts, \
             t.bytes_sent, t.bytes_received, t.packets_sent, t.packets_received \
             FROM hosts h LEFT JOIN host_traffic t ON t.ip = h.ip WHERE h.ip = ?1",
            [&text],
            |r| {
                Ok(NodeDetail {
                    ip,
                    info: EndpointInfo {
                        names: json_vec(r.get(0)?, 0)?,
                        category: r.get(1)?,
                        country: r.get(2)?,
                    },
                    macs: json_vec(r.get(3)?, 3)?,
                    first_ts: r.get(4)?,
                    last_ts: r.get(5)?,
                    bytes_sent: r.get::<_, Option<u64>>(6)?.unwrap_or(0),
                    bytes_received: r.get::<_, Option<u64>>(7)?.unwrap_or(0),
                    packets_sent: r.get::<_, Option<u64>>(8)?.unwrap_or(0),
                    packets_received: r.get::<_, Option<u64>>(9)?.unwrap_or(0),
                    peers: 0,
                    protocols: Vec::new(),
                    open_ports: Vec::new(),
                    neighbors: Vec::new(),
                })
            },
        )
        .map(Some)
        .or_else(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            e => Err(e),
        })?;
    let Some(mut detail) = host else {
        return Ok(None);
    };

    let mut stmt = conn.prepare(
        "SELECT port, transport, service FROM open_ports WHERE ip = ?1 \
         ORDER BY port, transport LIMIT ?2",
    )?;
    detail.open_ports = stmt
        .query_map(params![text, MAX_NODE_PORTS], |r| {
            Ok(NodePort {
                port: r.get(0)?,
                transport: r.get(1)?,
                service: r.get(2)?,
            })
        })?
        .collect::<rusqlite::Result<_>>()?;
    drop(stmt);

    let (peers, mut neighbors) = neighbors(conn, &text)?;
    detail.peers = peers;
    let mut protocols = BTreeSet::new();
    // Every label of the host (the neighbors above are only the top ones).
    let mut stmt = conn.prepare(
        "SELECT DISTINCT j.value FROM conversations c, json_each(c.protocols) j \
         WHERE c.src_ip = ?1 UNION SELECT DISTINCT j.value FROM conversations c, \
         json_each(c.protocols) j WHERE c.dst_ip = ?1",
    )?;
    for label in stmt.query_map([&text], |r| r.get::<_, String>(0))? {
        protocols.insert(label?);
    }
    drop(stmt);
    detail.protocols = protocols.into_iter().collect();
    let ips: Vec<String> = neighbors.iter().map(|n| n.ip.to_string()).collect();
    let mut infos = endpoint_infos(conn, &ips)?;
    for n in &mut neighbors {
        n.info = infos.remove(&n.ip).unwrap_or_default();
    }
    detail.neighbors = neighbors;
    Ok(Some(detail))
}

#[cfg(test)]
mod tests;
