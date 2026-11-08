//! Read queries of the Network view: a bounded communication graph (ADR-018).
//!
//! The end-of-import step `network` ([`build`], ADR-014) folds `conversations`, `hosts` and
//! `host_traffic` into the tables of `0900_network.sql`: the [`MAX_NODES`] largest hosts keep
//! their address as node key, the other public hosts are keyed by country, the rest by "other",
//! per protocol groups, categories and IPv6. A request reads these few pre-folded rows (indexed
//! or small tables) and finishes in memory: in host mode, the first `limit` matching hosts among
//! the largest get their own node, the other public hosts form one cluster node per country (at
//! most [`MAX_CLUSTERS`], largest first), everything else one "other" node; in country mode, a
//! node is a country, the local addresses or the public addresses of unknown country. Edges are
//! undirected pairs of nodes, at most [`MAX_EDGES`], largest first. Host details
//! ([`node_detail`]) are read from `conversations` by index.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::IpAddr;

use rusqlite::{Connection, ToSql, params};

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

    /// Bit of the group in the `mask` columns of `0900_network.sql` (its index in [`Self::ALL`]).
    pub fn bit(self) -> u16 {
        let index = Self::ALL.iter().position(|g| *g == self).unwrap_or(0);
        1 << index
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

/// Every protocol group.
const ALL_GROUPS: u16 = (1 << ProtocolGroup::ALL.len()) - 1;

/// Filters as bound to the queries of the derived tables.
struct Filter {
    mask: u16,
    /// JSON array of the categories, `None` = no filter.
    categories: Option<String>,
    category_set: Option<HashSet<String>>,
    ipv6: bool,
}

/// Rows of `network_edges` / `network_country_edges` / `network_expand` kept by the filters:
/// `?1` mask, `?2` categories (JSON or NULL), `?3` IPv6 kept. `{a}` and `{b}`: category columns.
fn filter_sql(a: &str, b: &str) -> String {
    format!(
        "(mask & ?1) <> 0 AND (?2 IS NULL OR ({a} IN (SELECT value FROM json_each(?2)) \
         AND {b} IN (SELECT value FROM json_each(?2)))) AND (?3 OR v6 = 0)"
    )
}

impl Filter {
    fn new(filter: &GraphFilter) -> Result<Self> {
        let mask = filter.protocols.as_ref().map_or(ALL_GROUPS, |groups| {
            groups.iter().fold(0, |m, g| m | g.bit())
        });
        Ok(Self {
            mask,
            categories: filter
                .categories
                .as_ref()
                .map(serde_json::to_string)
                .transpose()?,
            category_set: filter
                .categories
                .as_ref()
                .map(|c| c.iter().cloned().collect()),
            ipv6: filter.ipv6,
        })
    }

    /// True when a host has matching traffic and passes the category and IPv6 filters.
    fn host(&self, category: &str, v6: bool, mask: u16) -> bool {
        mask & self.mask != 0
            && self
                .category_set
                .as_ref()
                .is_none_or(|s| s.contains(category))
            && (self.ipv6 || !v6)
    }
}

/// Traffic between two node keys (directed: `a` is the client side).
#[derive(Default)]
struct Group {
    fwd: u64,
    rev: u64,
    packets: u64,
    flows: u64,
    conversations: u64,
    protocols: BTreeSet<String>,
}

impl Group {
    fn add(&mut self, g: &Group) {
        self.fwd = self.fwd.saturating_add(g.fwd);
        self.rev = self.rev.saturating_add(g.rev);
        self.packets = self.packets.saturating_add(g.packets);
        self.flows = self.flows.saturating_add(g.flows);
        self.conversations = self.conversations.saturating_add(g.conversations);
        self.protocols.extend(g.protocols.iter().cloned());
    }

    /// Removes traffic moved to other nodes (labels are kept: a union cannot be undone).
    fn sub(&mut self, g: &Group) {
        self.fwd = self.fwd.saturating_sub(g.fwd);
        self.rev = self.rev.saturating_sub(g.rev);
        self.packets = self.packets.saturating_sub(g.packets);
        self.flows = self.flows.saturating_sub(g.flows);
        self.conversations = self.conversations.saturating_sub(g.conversations);
    }

    /// Sums of columns `first..first + 5` (fwd, rev, packets, flows, conversations, labels).
    fn read(r: &rusqlite::Row<'_>, first: usize) -> rusqlite::Result<Self> {
        let raw: String = r.get(first + 5)?;
        Ok(Self {
            fwd: r.get(first)?,
            rev: r.get(first + 1)?,
            packets: r.get(first + 2)?,
            flows: r.get(first + 3)?,
            conversations: r.get(first + 4)?,
            protocols: serde_json::from_str(&raw).map_err(|e| conversion(first + 5, e))?,
        })
    }
}

type Groups = HashMap<(String, String), Group>;

/// Folded rows of `table` kept by the filters, keyed by `key(a)`, `key(b)`.
fn edge_groups(
    conn: &Connection,
    table: &str,
    f: &Filter,
    key: impl Fn(&str) -> String,
) -> Result<Groups> {
    let sql = format!(
        "SELECT a, b, bytes_fwd, bytes_rev, packets, flows, conversations, protocols \
         FROM {table} WHERE {}",
        filter_sql("cat_a", "cat_b"),
    );
    let mut stmt = conn.prepare_cached(&sql)?;
    let mut rows = stmt.query(params![f.mask, f.categories, f.ipv6])?;
    let mut out = Groups::new();
    while let Some(r) = rows.next()? {
        let a: String = r.get(0)?;
        let b: String = r.get(1)?;
        out.entry((key(&a), key(&b)))
            .or_default()
            .add(&Group::read(r, 2)?);
    }
    Ok(out)
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

/// Folds directed groups into nodes and undirected edges; `node` maps a raw key to the key of
/// the node drawn (`None`: dropped, an invalid key).
/// Nodes, undirected edges and total bytes of a fold.
type Folded = (
    HashMap<NodeKey, NodeAcc>,
    HashMap<(NodeKey, NodeKey), EdgeAcc>,
    u64,
);

fn fold(groups: &Groups, node: impl Fn(&str) -> Option<NodeKey>) -> Folded {
    let mut nodes: HashMap<NodeKey, NodeAcc> = HashMap::new();
    let mut edges: HashMap<(NodeKey, NodeKey), EdgeAcc> = HashMap::new();
    let mut total = 0_u64;
    for ((a, b), g) in groups {
        if g.conversations == 0 {
            continue;
        }
        let (Some(a), Some(b)) = (node(a), node(b)) else {
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
        e.protocols.extend(g.protocols.iter().cloned());
    }
    (nodes, edges, total)
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
    let mut stmt = conn.prepare_cached(
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

/// Host counts of `network_host_counts` passing the category and IPv6 filters:
/// (node, country node, groups) -> hosts.
fn host_counts(conn: &Connection, f: &Filter) -> Result<Vec<(String, String, u16, u64)>> {
    let mut stmt = conn.prepare_cached(&format!(
        "SELECT node, cnode, mask, {} FROM network_host_counts \
         WHERE (?1 IS NULL OR category IN (SELECT value FROM json_each(?1))) AND (?2 OR v6 = 0) \
         GROUP BY node, cnode, mask",
        sum("hosts")
    ))?;
    let rows = stmt.query_map(params![f.categories, f.ipv6], |r| {
        Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// Orphans (`?1` mask, `?2` categories, `?3` IPv6), most traffic first, `?4` at most.
const ORPHANS_SQL: &str = "SELECT ip FROM network_hosts WHERE (mask & ?1) = 0 \
    AND (?2 IS NULL OR category IN (SELECT value FROM json_each(?2))) AND (?3 OR v6 = 0) \
    ORDER BY traffic DESC, ip DESC LIMIT ?4";

/// The `list` orphans (hosts without matching traffic) with the most traffic overall.
fn orphan_ips(conn: &Connection, f: &Filter, list: u32) -> Result<Vec<String>> {
    let mut stmt = conn.prepare_cached(ORPHANS_SQL)?;
    let rows = stmt.query_map(params![f.mask, f.categories, f.ipv6, list], |r| r.get(0))?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// A host of `network_hosts` (keyed hosts and expandable hosts).
struct RankedHost {
    ip: String,
    keyed: bool,
    crank: Option<u32>,
    country: Option<String>,
    category: String,
    v6: bool,
    mask: u16,
}

impl RankedHost {
    /// Node of the host when it is not drawn individually.
    fn group(&self) -> String {
        self.country
            .as_ref()
            .map_or_else(|| "other".to_owned(), |cc| format!("k:{cc}"))
    }
}

fn ranked_hosts(conn: &Connection, sql: &str, p: &[&dyn ToSql]) -> Result<Vec<RankedHost>> {
    let mut stmt = conn.prepare_cached(sql)?;
    let rows = stmt.query_map(rusqlite::params_from_iter(p.iter()), |r| {
        Ok(RankedHost {
            ip: r.get(0)?,
            keyed: r.get(1)?,
            crank: r.get(2)?,
            country: r.get(3)?,
            category: r.get(4)?,
            v6: r.get(5)?,
            mask: r.get(6)?,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

const RANKED_COLUMNS: &str = "ip, keyed, crank, country, category, v6, mask";

/// The keyed hosts, largest first.
fn top_sql() -> String {
    format!("SELECT {RANKED_COLUMNS} FROM network_hosts WHERE keyed = 1 ORDER BY rank")
}

/// The `?2` largest hosts of country `?1`.
fn expandable_sql() -> String {
    format!(
        "SELECT {RANKED_COLUMNS} FROM network_hosts \
         WHERE country = ?1 AND crank IS NOT NULL AND crank <= ?2 ORDER BY crank"
    )
}

/// Conversations of the expandable hosts of country `?4`, after the filters.
fn expand_rows_sql() -> String {
    format!(
        "SELECT x, x_is_src, other_node, other_ip, bytes_fwd, bytes_rev, packets, flows, \
         conversations, protocols FROM network_expand WHERE country = ?4 AND {}",
        filter_sql("cat_x", "cat_other")
    )
}

/// Host mode, from the derived tables (ADR-018): the individual hosts are the first `limit`
/// matching hosts by bytes (all keyed), plus the expanded ones.
#[allow(clippy::too_many_lines)] // One pipeline: hosts, groups, expansion, clusters, counts.
fn host_graph(
    conn: &Connection,
    f: &Filter,
    limit: u32,
    expand: Option<&str>,
    include_orphans: bool,
) -> Result<Graph> {
    let limit = usize::try_from(limit.clamp(MIN_NODES, MAX_NODES)).unwrap_or(usize::MAX);
    let top = ranked_hosts(conn, &top_sql(), &[])?;
    let expandable = match expand {
        None => Vec::new(),
        Some(cc) => ranked_hosts(conn, &expandable_sql(), &[&cc, &EXPAND_HOSTS])?,
    };
    let matching = |h: &RankedHost| f.host(&h.category, h.v6, h.mask);
    let expanded_here = |h: &RankedHost| {
        expand.is_some_and(|cc| h.country.as_deref() == Some(cc))
            && h.crank.is_some_and(|c| c <= EXPAND_HOSTS)
    };
    let mut individual: HashSet<&str> = top
        .iter()
        .filter(|h| matching(h))
        .take(limit)
        .map(|h| h.ip.as_str())
        .collect();
    individual.extend(
        top.iter()
            .filter(|h| matching(h) && expanded_here(h))
            .map(|h| h.ip.as_str()),
    );
    let beyond: HashSet<&str> = expandable
        .iter()
        .filter(|h| !h.keyed && matching(h))
        .map(|h| h.ip.as_str())
        .collect();
    let by_ip: HashMap<&str, &RankedHost> = top.iter().map(|h| (h.ip.as_str(), h)).collect();
    let remap = |key: &str| -> String {
        match key.strip_prefix("h:") {
            Some(ip) if !individual.contains(ip) => by_ip
                .get(ip)
                .map_or_else(|| "other".to_owned(), |h| h.group()),
            _ => key.to_owned(),
        }
    };

    // Pre-folded traffic, with the expanded hosts moved out of their cluster.
    let mut groups = edge_groups(conn, "network_edges", f, remap)?;
    if let (Some(cc), false) = (expand, beyond.is_empty()) {
        let cluster = format!("k:{cc}");
        let mut stmt = conn.prepare_cached(&expand_rows_sql())?;
        let mut rows = stmt.query(params![f.mask, f.categories, f.ipv6, cc])?;
        while let Some(r) = rows.next()? {
            let x: String = r.get(0)?;
            if !beyond.contains(x.as_str()) {
                continue;
            }
            let x_is_src: bool = r.get(1)?;
            let other_node: String = r.get(2)?;
            let other_ip: String = r.get(3)?;
            let g = Group::read(r, 4)?;
            let other_expanded = beyond.contains(other_ip.as_str());
            if other_expanded && !x_is_src {
                continue; // Counted with the row of the client side.
            }
            let (other_old, other_new) = if other_expanded {
                (cluster.clone(), format!("h:{other_ip}"))
            } else {
                (remap(&other_node), remap(&other_node))
            };
            let x_new = format!("h:{x}");
            let (old, new) = if x_is_src {
                ((cluster.clone(), other_old), (x_new, other_new))
            } else {
                ((other_old, cluster.clone()), (other_new, x_new))
            };
            groups.entry(old).or_default().sub(&g);
            groups.entry(new).or_default().add(&g);
        }
    }

    // Country clusters: the largest ones, the others join "other".
    let (pre, _, _) = fold(&groups, NodeKey::parse);
    let mut clusters: Vec<(&NodeKey, u64)> = pre
        .iter()
        .filter(|(k, _)| matches!(k, NodeKey::Cluster(_)))
        .map(|(k, n)| (k, n.sent.saturating_add(n.received)))
        .collect();
    clusters.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
    let kept: HashSet<String> = clusters
        .iter()
        .take(MAX_CLUSTERS)
        .map(|(k, _)| k.id())
        .collect();
    let node_of = |key: &str| -> Option<NodeKey> {
        if key.starts_with("k:") && !kept.contains(key) {
            Some(NodeKey::Other)
        } else {
            NodeKey::parse(key)
        }
    };
    let (mut nodes, edges, total_bytes) = fold(&groups, node_of);

    // Hosts behind each node. A host with matching traffic whose conversations the category
    // filter removed is neither drawn nor an orphan.
    let mut orphans = 0_u64;
    let mut behind: HashMap<String, u64> = HashMap::new();
    for (node, _, mask, n) in host_counts(conn, f)? {
        if mask & f.mask == 0 {
            orphans = orphans.saturating_add(n);
            continue;
        }
        if node != "keyed" {
            *behind.entry(node).or_default() += n;
        }
    }
    for h in &top {
        if matching(h) && !individual.contains(h.ip.as_str()) {
            *behind.entry(h.group()).or_default() += 1;
        }
    }
    if let Some(cc) = expand {
        let n = behind.entry(format!("k:{cc}")).or_default();
        *n = n.saturating_sub(u64::try_from(beyond.len()).unwrap_or(0));
    }
    for (node, n) in behind {
        let key = node_of(&node).unwrap_or(NodeKey::Other);
        match nodes.get_mut(&key) {
            Some(acc) => acc.hosts = acc.hosts.saturating_add(n),
            None => {
                if let Some(other) = nodes.get_mut(&NodeKey::Other) {
                    other.hosts = other.hosts.saturating_add(n);
                }
            }
        }
    }
    let mut drawn: Vec<String> = individual
        .iter()
        .chain(beyond.iter())
        .map(|ip| (*ip).to_owned())
        .collect();
    drawn.retain(|ip| {
        ip.parse()
            .is_ok_and(|ip| nodes.contains_key(&NodeKey::Host(ip)))
    });
    for ip in &drawn {
        if let Ok(ip) = ip.parse() {
            nodes.entry(NodeKey::Host(ip)).or_default().hosts = 1;
        }
    }
    let total_hosts = nodes.values().fold(0_u64, |a, n| a.saturating_add(n.hosts));

    // Orphans, listed on demand within their own bound.
    if include_orphans {
        for ip in orphan_ips(conn, f, MAX_ORPHANS)? {
            if let Ok(addr) = ip.parse() {
                nodes.entry(NodeKey::Host(addr)).or_default().hosts = 1;
                drawn.push(ip);
            }
        }
    }
    let mut infos = endpoint_infos(conn, &drawn)?;
    let hosts_shown = u64::try_from(drawn.len()).unwrap_or(u64::MAX);
    let (nodes, edges, edges_total) = finish(nodes, edges, &mut infos);
    Ok(Graph {
        nodes,
        edges,
        hosts: total_hosts,
        hosts_shown,
        edges_total,
        orphans,
        total_bytes,
    })
}

/// Country mode: pre-folded traffic between countries, then the top `limit` groups.
fn country_graph(conn: &Connection, f: &Filter, limit: u32) -> Result<Graph> {
    let raw = edge_groups(conn, "network_country_edges", f, str::to_owned)?;
    let mut counts: HashMap<String, u64> = HashMap::new();
    let mut orphans = 0_u64;
    for (_, cnode, mask, n) in host_counts(conn, f)? {
        if mask & f.mask == 0 {
            orphans = orphans.saturating_add(n);
        } else {
            *counts.entry(cnode).or_default() += n;
        }
    }
    // Ranking of the groups by bytes (traffic inside a group counted once).
    let mut bytes: HashMap<&str, u64> = HashMap::new();
    for ((a, b), g) in &raw {
        let v = g.fwd.saturating_add(g.rev);
        let e = bytes.entry(a.as_str()).or_default();
        *e = e.saturating_add(v);
        if b != a {
            let e = bytes.entry(b.as_str()).or_default();
            *e = e.saturating_add(v);
        }
    }
    let mut ranked: Vec<(&str, u64)> = bytes.into_iter().collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
    let limit = usize::try_from(limit.clamp(MIN_NODES, MAX_NODES)).unwrap_or(usize::MAX);
    let kept: HashSet<String> = ranked
        .iter()
        .take(limit)
        .map(|(k, _)| (*k).to_owned())
        .collect();
    let (mut nodes, edges, total_bytes) = fold(&raw, |k| {
        if kept.contains(k) {
            NodeKey::parse(k)
        } else {
            Some(NodeKey::Other)
        }
    });
    for (key, n) in &counts {
        let node = if kept.contains(key) {
            NodeKey::parse(key).unwrap_or(NodeKey::Other)
        } else {
            NodeKey::Other
        };
        if let Some(acc) = nodes.get_mut(&node) {
            acc.hosts = acc.hosts.saturating_add(*n);
        }
    }
    let total_hosts = nodes.values().fold(0_u64, |a, n| a.saturating_add(n.hosts));
    let (nodes, edges, edges_total) = finish(nodes, edges, &mut HashMap::new());
    Ok(Graph {
        nodes,
        edges,
        hosts: total_hosts,
        hosts_shown: 0,
        edges_total,
        orphans,
        total_bytes,
    })
}

/// Bounded communication graph of the session, read from the tables of the `network` step.
pub fn graph(conn: &Connection, filter: &GraphFilter, mode: &GraphMode) -> Result<Graph> {
    let f = Filter::new(filter)?;
    match mode {
        GraphMode::Hosts {
            limit,
            expand,
            include_orphans,
        } => host_graph(conn, &f, *limit, expand.as_deref(), *include_orphans),
        GraphMode::Countries { limit } => country_graph(conn, &f, *limit),
    }
}

/// Conversations carrying a label of each protocol group (whole session, no filter).
pub fn protocol_counts(conn: &Connection) -> Result<Vec<(ProtocolGroup, u64)>> {
    let mut stmt = conn.prepare_cached("SELECT grp, conversations FROM network_protocols")?;
    let counts: HashMap<String, u64> = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    Ok(ProtocolGroup::ALL
        .into_iter()
        .map(|g| (g, counts.get(g.as_str()).copied().unwrap_or(0)))
        .collect())
}

/// The end-of-import step that fills the tables read by [`graph`] (ADR-014).
pub(crate) fn finalize(conn: &Connection) -> Result<()> {
    build::finalize(conn)
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
/// Peers of a host, folded (`?1` the host, `?2` the limit).
fn neighbors_sql() -> String {
    format!(
        "WITH p AS (SELECT dst_ip AS peer, bytes_fwd AS sent, bytes_rev AS received, protocols \
           FROM conversations WHERE src_ip = ?1 \
           UNION ALL SELECT src_ip, bytes_rev, bytes_fwd, protocols \
           FROM conversations WHERE dst_ip = ?1 AND src_ip <> ?1) \
         SELECT peer, {}, {}, group_concat(DISTINCT protocols), count(*) OVER () \
         FROM p GROUP BY peer ORDER BY total(sent) + total(received) DESC, peer LIMIT ?2",
        sum("sent"),
        sum("received"),
    )
}

/// Every label of the conversations of a host (`?1`).
const HOST_LABELS: &str = "SELECT DISTINCT j.value FROM conversations c, json_each(c.protocols) j \
    WHERE c.src_ip = ?1 UNION SELECT DISTINCT j.value FROM conversations c, \
    json_each(c.protocols) j WHERE c.dst_ip = ?1";

fn neighbors(conn: &Connection, text: &str) -> Result<(u64, Vec<Neighbor>)> {
    let sql = neighbors_sql();
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
    let mut stmt = conn.prepare(HOST_LABELS)?;
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

mod build;

#[cfg(test)]
mod tests;
