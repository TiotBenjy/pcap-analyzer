//! End-of-import step `network` (ADR-014, ADR-018): folds `conversations` into the derived
//! tables of `0900_network.sql`, so that a graph request reads a few thousand pre-folded rows
//! instead of every conversation.
//!
//! **Memory bounded whatever the number of hosts** (a scan or a flood with spoofed sources can
//! bring millions of addresses): per-host state lives in `network_hosts`, on disk, never in
//! memory, and no statement sorts or groups a table of hosts or conversations (an import runs
//! with `temp_store = MEMORY`: a sorter would hold every row in memory).
//! 1. Hosts: the conversations read in storage order, their ends summed per address in the
//!    scratch table `network_ends` (one upsert each); then a merge of `hosts` and
//!    `network_ends`, both in address order by index, one host at a time in memory, inserted in
//!    primary key order with its bytes, groups, country key and node key (unless keyed).
//! 2. Ranks: one pass over `network_hosts` in rank order (index `network_hosts_bytes`) with
//!    constant state (a counter per protocol group and per country); only the keyed hosts and
//!    the first hosts of each country are updated, by primary key.
//! 3. Folding: one pass over `conversations`, both ends found by primary key in
//!    `network_hosts`; in memory, only maps keyed by node keys (keyed hosts, countries,
//!    "other"), categories, groups and the expandable hosts: all bounded ([`StepStats`]).
//! 4. Host counts: one pass over `network_hosts`, counted per node key in memory (bounded).
//!
//! The result only depends on the content of the tables (ties broken by address): idempotent
//! and independent of the arrival order of the records. Time is linear in conversations and
//! hosts (ADR-018).

use std::collections::{BTreeSet, HashMap};

use rusqlite::{Connection, Rows, params};

use super::{EXPAND_HOSTS, MAX_NODES, ProtocolGroup};
use crate::error::Result;
use crate::records::{conversion, sat};

/// Sizes of the in-memory maps of the step (bounded by node keys, not by hosts).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StepStats {
    /// Countries counted by the rank pass.
    pub(crate) countries: usize,
    pub(crate) edges: usize,
    pub(crate) country_edges: usize,
    pub(crate) expand: usize,
    /// Interned strings of the folding pass.
    pub(crate) names: usize,
    pub(crate) label_sets: usize,
    /// Keys of `network_host_counts`.
    pub(crate) host_counts: usize,
}

/// Interned strings of the folding keys (node keys, categories, expandable hosts).
#[derive(Default)]
struct Names {
    ids: HashMap<String, u32>,
    names: Vec<String>,
}

impl Names {
    fn id(&mut self, name: &str) -> u32 {
        if let Some(id) = self.ids.get(name) {
            return *id;
        }
        let id = u32::try_from(self.names.len()).unwrap_or(u32::MAX);
        self.names.push(name.to_owned());
        self.ids.insert(name.to_owned(), id);
        id
    }

    fn name(&self, id: u32) -> &str {
        usize::try_from(id)
            .ok()
            .and_then(|i| self.names.get(i))
            .map_or("", String::as_str)
    }
}

/// Group of a conversation label (`Other` for labels outside the groups).
fn label_bit(label: &str) -> u16 {
    ProtocolGroup::ALL
        .iter()
        .find(|g| g.labels().contains(&label))
        .copied()
        .unwrap_or(ProtocolGroup::Other)
        .bit()
}

/// Label sets (`protocols` values) with their groups, parsed once per distinct value (bounded:
/// the labels are protocol names, at most a few per conversation).
#[derive(Default)]
struct Labels {
    cache: HashMap<String, (u16, u32)>,
    sets: Vec<Vec<String>>,
}

impl Labels {
    /// (groups, id of the label set).
    fn get(&mut self, raw: &str) -> rusqlite::Result<(u16, u32)> {
        if let Some(v) = self.cache.get(raw) {
            return Ok(*v);
        }
        let labels: Vec<String> = serde_json::from_str(raw).map_err(|e| conversion(0, e))?;
        let mask = labels.iter().fold(0, |m, l| m | label_bit(l));
        let id = u32::try_from(self.sets.len()).unwrap_or(u32::MAX);
        self.sets.push(labels);
        self.cache.insert(raw.to_owned(), (mask, id));
        Ok((mask, id))
    }
}

/// Folded sums of a set of conversations.
#[derive(Default)]
struct Sums {
    fwd: u64,
    rev: u64,
    packets: u64,
    flows: u64,
    conversations: u64,
    labels: BTreeSet<u32>,
}

impl Sums {
    fn add(&mut self, c: &Conv) {
        self.fwd = self.fwd.saturating_add(c.fwd);
        self.rev = self.rev.saturating_add(c.rev);
        self.packets = self.packets.saturating_add(c.packets);
        self.flows = self.flows.saturating_add(c.flows);
        self.conversations = self.conversations.saturating_add(1);
        self.labels.insert(c.labels);
    }

    fn protocols(&self, labels: &Labels) -> Result<String> {
        let set: BTreeSet<&str> = self
            .labels
            .iter()
            .filter_map(|id| labels.sets.get(usize::try_from(*id).ok()?))
            .flatten()
            .map(String::as_str)
            .collect();
        Ok(serde_json::to_string(&set)?)
    }
}

struct Conv {
    fwd: u64,
    rev: u64,
    packets: u64,
    flows: u64,
    labels: u32,
}

/// One end of a conversation, as folded: interned node, country node and category.
struct End {
    node: u32,
    cnode: u32,
    category: u32,
    /// Interned address and country of an expandable host.
    expandable: Option<(u32, u32)>,
}

/// Edge key: (a, b, mask, category a, category b, IPv6).
type EdgeKey = (u32, u32, u16, u32, u32, bool);
/// Expand key: (country, x, x is the client, other node, other expandable host, mask,
/// categories, IPv6).
type ExpandKey = (u32, u32, bool, u32, Option<u32>, u16, u32, u32, bool);

/// Step 1, read of the conversations: in storage order (sequential), one upsert per end into
/// the scratch table `network_ends` (a conversation with itself counts once).
const ENDS_SQL: &str = "SELECT src_ip, dst_ip, bytes_fwd, bytes_rev, protocols FROM conversations";

/// Step 1, merge: `hosts` with their traffic, and `network_ends`, both read in address order by
/// index (`ORDER BY` is never sorted, see the tests).
pub(super) const MERGE_SQL: [&str; 2] = [
    "SELECT h.ip, h.country, coalesce(h.category, ''), coalesce(t.bytes_sent, 0), \
     coalesce(t.bytes_received, 0) FROM hosts h LEFT JOIN host_traffic t ON t.ip = h.ip \
     ORDER BY h.ip",
    "SELECT ip, bytes, mask FROM network_ends ORDER BY ip",
];

/// A row of a stream of [`MERGE_SQL`], read ahead: (address, values).
type Head<T> = Option<(String, T)>;

/// Next `hosts` row: (address, (country, category, traffic)).
fn next_host(rows: &mut Rows<'_>) -> Result<Head<(Option<String>, String, u64)>> {
    let Some(r) = rows.next()? else {
        return Ok(None);
    };
    let traffic = r.get::<_, u64>(3)?.saturating_add(r.get::<_, u64>(4)?);
    Ok(Some((r.get(0)?, (r.get(1)?, r.get(2)?, traffic))))
}

/// Next `network_ends` row: (address, (bytes, groups)).
fn next_end(rows: &mut Rows<'_>) -> Result<Head<(u64, u16)>> {
    let Some(r) = rows.next()? else {
        return Ok(None);
    };
    Ok(Some((r.get(0)?, (r.get(1)?, r.get(2)?))))
}

/// Address of a read-ahead row.
fn head_ip<T>(head: Option<&(String, T)>) -> Option<&str> {
    head.map(|(ip, _)| ip.as_str())
}

/// Step 1: every host with its bytes, groups, country key and (unless keyed) node key. The
/// conversation ends are summed per address on disk (`network_ends`), then merged with `hosts`
/// in address order, one host in memory at a time, inserted in primary key order. `rank = 0`
/// marks the hosts seen in a conversation until step 2.
pub(super) fn fill_hosts(conn: &Connection) -> Result<()> {
    conn.execute("DELETE FROM network_ends", [])?;
    {
        let mut labels = Labels::default();
        let mut upsert = conn.prepare(
            "INSERT INTO network_ends (ip, bytes, mask) VALUES (?1, ?2, ?3) \
             ON CONFLICT (ip) DO UPDATE SET \
             bytes = min(bytes + excluded.bytes, 9223372036854775807), \
             mask = mask | excluded.mask",
        )?;
        let mut stmt = conn.prepare(ENDS_SQL)?;
        let mut rows = stmt.query([])?;
        while let Some(r) = rows.next()? {
            let src = r.get_ref(0)?.as_str().map_err(|e| conversion(0, e))?;
            let dst = r.get_ref(1)?.as_str().map_err(|e| conversion(1, e))?;
            let bytes = sat(r.get::<_, u64>(2)?.saturating_add(r.get::<_, u64>(3)?));
            // Borrowed: the label sets are few, the rows many.
            let raw = r.get_ref(4)?.as_str().map_err(|e| conversion(4, e))?;
            let (mask, _) = labels.get(raw)?;
            upsert.execute(params![src, bytes, mask])?;
            if dst != src {
                upsert.execute(params![dst, bytes, mask])?;
            }
        }
    }
    let [hosts_sql, ends_sql] = MERGE_SQL;
    let mut hosts_stmt = conn.prepare(hosts_sql)?;
    let mut ends_stmt = conn.prepare(ends_sql)?;
    let mut insert = conn.prepare(
        "INSERT INTO network_hosts (ip, country, category, v6, mask, bytes, traffic, rank, keyed, \
         node, cnode) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0, ?9, ?10)",
    )?;
    let mut hosts = hosts_stmt.query([])?;
    let mut ends = ends_stmt.query([])?;
    let mut host = next_host(&mut hosts)?;
    let mut end = next_end(&mut ends)?;
    // The smaller address of the two streams (text order: SQLite `BINARY` = Rust `str`).
    while let Some(ip) = [head_ip(host.as_ref()), head_ip(end.as_ref())]
        .into_iter()
        .flatten()
        .min()
        .map(str::to_owned)
    {
        let (mut country, mut category, mut traffic) = (None, String::new(), 0);
        if head_ip(host.as_ref()) == Some(ip.as_str())
            && let Some((_, h)) = host.take()
        {
            (country, category, traffic) = h;
            host = next_host(&mut hosts)?;
        }
        let (mut bytes, mut mask, mut seen) = (0, 0_u16, false);
        if head_ip(end.as_ref()) == Some(ip.as_str())
            && let Some((_, e)) = end.take()
        {
            (bytes, mask) = e;
            seen = true;
            end = next_end(&mut ends)?;
        }
        let node = country
            .as_ref()
            .map_or_else(|| "other".to_owned(), |cc| format!("k:{cc}"));
        let cnode = match (&country, category.as_str()) {
            (Some(cc), _) => format!("c:{cc}"),
            (None, "public") => "unknown".to_owned(),
            _ => "local".to_owned(),
        };
        // A stream out of order would repeat an address: the primary key rejects it.
        insert.execute(params![
            ip,
            country,
            category,
            ip.contains(':'),
            mask,
            sat(bytes),
            sat(traffic),
            seen.then_some(0),
            node,
            cnode,
        ])?;
    }
    drop(ends);
    drop(ends_stmt);
    conn.execute("DELETE FROM network_ends", [])?;
    Ok(())
}

/// Rank order of step 2 (most bytes first, then address), read by index.
pub(super) const RANK_SQL: &str = "SELECT ip, country, mask FROM network_hosts \
    WHERE rank IS NOT NULL ORDER BY bytes DESC, ip";

/// Step 2: keyed hosts, ranks and country ranks, in one pass in rank order (constant state);
/// returns the number of countries counted. Only the hosts read back by the graph are updated
/// (keyed hosts, ordered by `rank`, and the first [`EXPAND_HOSTS`] of each country, by
/// `crank`): a few thousand rows, whatever the number of hosts.
pub(super) fn rank_hosts(conn: &Connection) -> Result<usize> {
    let max = MAX_NODES;
    let mut per_group = [0_u32; ProtocolGroup::ALL.len()];
    // Bounded: one entry per country code.
    let mut per_country: HashMap<String, u32> = HashMap::new();
    let mut update = conn.prepare(
        "UPDATE network_hosts SET rank = ?2, crank = ?3, keyed = ?4, \
         node = CASE WHEN ?4 THEN 'h:' || ip ELSE node END WHERE ip = ?1",
    )?;
    let mut read = conn.prepare(RANK_SQL)?;
    let mut rows = read.query([])?;
    let mut rank = 0_u32;
    while let Some(r) = rows.next()? {
        let ip: String = r.get(0)?;
        let country: Option<String> = r.get(1)?;
        let mask: u16 = r.get(2)?;
        rank = rank.saturating_add(1);
        // Keyed: among the largest overall, or among the largest having one of its groups (the
        // first N hosts passing any protocol filter are then keyed).
        let mut keyed = rank <= max;
        for (i, g) in ProtocolGroup::ALL.iter().enumerate() {
            if mask & g.bit() != 0
                && let Some(n) = per_group.get_mut(i)
            {
                *n = n.saturating_add(1);
                keyed |= *n <= max;
            }
        }
        let crank = country
            .map(|cc| {
                let n = per_country.entry(cc).or_default();
                *n = n.saturating_add(1);
                *n
            })
            .filter(|n| *n <= EXPAND_HOSTS);
        if keyed || crank.is_some() {
            // The columns of the index being read (`bytes`, `ip`) do not change.
            update.execute(params![ip, rank, crank, keyed])?;
        }
    }
    Ok(per_country.len())
}

/// Query of step 3: every conversation with both ends (`CROSS JOIN`: `conversations` is scanned
/// once, the ends found by primary key; nothing is sorted).
pub(super) fn fold_sql() -> String {
    let end = |p: &str| {
        format!(
            "{p}.node, {p}.cnode, {p}.category, \
             CASE WHEN {p}.keyed = 0 AND {p}.crank <= {EXPAND_HOSTS} THEN {p}.ip END, \
             {p}.country, {p}.v6"
        )
    };
    format!(
        "SELECT c.bytes_fwd, c.bytes_rev, \
         CAST(min(c.packets_fwd + c.packets_rev, 9223372036854775807.0) AS INTEGER), \
         c.flows, c.protocols, {}, {} \
         FROM conversations c CROSS JOIN network_hosts s ON s.ip = c.src_ip \
         CROSS JOIN network_hosts d ON d.ip = c.dst_ip",
        end("s"),
        end("d"),
    )
}

/// Step 3: folding of the conversations by node keys.
#[allow(clippy::too_many_lines)] // One streaming pass and the inserts of its four maps.
pub(super) fn fold(conn: &Connection) -> Result<StepStats> {
    let mut names = Names::default();
    let mut labels = Labels::default();
    let mut groups = [0_u64; ProtocolGroup::ALL.len()];
    let mut edges: HashMap<EdgeKey, Sums> = HashMap::new();
    let mut country_edges: HashMap<EdgeKey, Sums> = HashMap::new();
    let mut expand: HashMap<ExpandKey, Sums> = HashMap::new();
    {
        let sql = fold_sql();
        let mut stmt = conn.prepare(&sql)?;
        let mut rows = stmt.query([])?;
        while let Some(r) = rows.next()? {
            let raw = r.get_ref(4)?.as_str().map_err(|e| conversion(4, e))?;
            let (mask, set) = labels.get(raw)?;
            let conv = Conv {
                fwd: r.get(0)?,
                rev: r.get(1)?,
                packets: r.get(2)?,
                flows: r.get(3)?,
                labels: set,
            };
            let mut read_end = |first: usize| -> rusqlite::Result<(End, bool)> {
                let node: String = r.get(first)?;
                let cnode: String = r.get(first + 1)?;
                let category: String = r.get(first + 2)?;
                let ip: Option<String> = r.get(first + 3)?;
                let country: Option<String> = r.get(first + 4)?;
                let v6: bool = r.get(first + 5)?;
                let expandable = match (ip, country) {
                    (Some(ip), Some(cc)) => Some((names.id(&ip), names.id(&cc))),
                    _ => None,
                };
                Ok((
                    End {
                        node: names.id(&node),
                        cnode: names.id(&cnode),
                        category: names.id(&category),
                        expandable,
                    },
                    v6,
                ))
            };
            let (s, s6) = read_end(5)?;
            let (d, d6) = read_end(11)?;
            let six = s6 || d6;
            for (i, g) in ProtocolGroup::ALL.iter().enumerate() {
                if mask & g.bit() != 0
                    && let Some(n) = groups.get_mut(i)
                {
                    *n += 1;
                }
            }
            edges
                .entry((s.node, d.node, mask, s.category, d.category, six))
                .or_default()
                .add(&conv);
            country_edges
                .entry((s.cnode, d.cnode, mask, s.category, d.category, six))
                .or_default()
                .add(&conv);
            let same = s.expandable.is_some() && s.expandable == d.expandable;
            for (x, other, x_is_src) in [(&s, &d, true), (&d, &s, false)] {
                let Some((ip, cc)) = x.expandable else {
                    continue;
                };
                if same && !x_is_src {
                    continue; // A host talking to itself: one row.
                }
                expand
                    .entry((
                        cc,
                        ip,
                        x_is_src,
                        other.node,
                        other.expandable.map(|(o, _)| o),
                        mask,
                        x.category,
                        other.category,
                        six,
                    ))
                    .or_default()
                    .add(&conv);
            }
        }
    }
    let stats = StepStats {
        edges: edges.len(),
        country_edges: country_edges.len(),
        expand: expand.len(),
        names: names.names.len(),
        label_sets: labels.sets.len(),
        ..StepStats::default()
    };

    for (table, map) in [
        ("network_edges", &edges),
        ("network_country_edges", &country_edges),
    ] {
        let mut stmt = conn.prepare(&format!(
            "INSERT INTO {table} (a, b, mask, cat_a, cat_b, v6, bytes_fwd, bytes_rev, packets, \
             flows, conversations, protocols) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)"
        ))?;
        for ((a, b, mask, cat_a, cat_b, six), s) in map {
            stmt.execute(params![
                names.name(*a),
                names.name(*b),
                mask,
                names.name(*cat_a),
                names.name(*cat_b),
                six,
                sat(s.fwd),
                sat(s.rev),
                sat(s.packets),
                sat(s.flows),
                sat(s.conversations),
                s.protocols(&labels)?,
            ])?;
        }
    }
    let mut stmt = conn.prepare(
        "INSERT INTO network_expand (country, x, x_is_src, other_node, other_ip, mask, cat_x, \
         cat_other, v6, bytes_fwd, bytes_rev, packets, flows, conversations, protocols) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
    )?;
    for ((cc, x, x_is_src, other_node, other_ip, mask, cat_x, cat_other, six), s) in &expand {
        stmt.execute(params![
            names.name(*cc),
            names.name(*x),
            x_is_src,
            names.name(*other_node),
            other_ip.map_or("", |o| names.name(o)),
            mask,
            names.name(*cat_x),
            names.name(*cat_other),
            six,
            sat(s.fwd),
            sat(s.rev),
            sat(s.packets),
            sat(s.flows),
            sat(s.conversations),
            s.protocols(&labels)?,
        ])?;
    }
    drop(stmt);
    let mut stmt =
        conn.prepare("INSERT INTO network_protocols (grp, conversations) VALUES (?1, ?2)")?;
    for (g, n) in ProtocolGroup::ALL.iter().zip(groups) {
        stmt.execute(params![g.as_str(), sat(n)])?;
    }
    Ok(stats)
}

/// The `network` step (see the module documentation); returns the sizes of its maps.
pub(crate) fn run(conn: &Connection) -> Result<StepStats> {
    for table in [
        "network_hosts",
        "network_edges",
        "network_country_edges",
        "network_expand",
        "network_host_counts",
        "network_protocols",
        "network_ends",
    ] {
        conn.execute(&format!("DELETE FROM {table}"), [])?;
    }
    fill_hosts(conn)?;
    let countries = rank_hosts(conn)?;
    let stats = fold(conn)?;
    let host_counts = count_hosts(conn)?;
    Ok(StepStats {
        countries,
        host_counts,
        ..stats
    })
}

/// Step 4: hosts per (node, country key, category, IPv6, groups), node `keyed` for the keyed
/// hosts. Counted in memory over a plain scan (a `GROUP BY` would sort every host): the keys
/// are bounded by countries, categories and group masks; returns their number.
pub(super) fn count_hosts(conn: &Connection) -> Result<usize> {
    type Key = (String, String, String, bool, u16);
    let mut counts: HashMap<Key, u64> = HashMap::new();
    {
        let mut stmt = conn.prepare(
            "SELECT CASE WHEN keyed = 1 THEN 'keyed' ELSE node END, cnode, category, v6, mask \
             FROM network_hosts",
        )?;
        let mut rows = stmt.query([])?;
        while let Some(r) = rows.next()? {
            let key: Key = (r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?);
            *counts.entry(key).or_default() += 1;
        }
    }
    let mut stmt = conn.prepare(
        "INSERT INTO network_host_counts (node, cnode, category, v6, mask, hosts) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    )?;
    for ((node, cnode, category, six, mask), n) in &counts {
        stmt.execute(params![node, cnode, category, six, mask, sat(*n)])?;
    }
    Ok(counts.len())
}

/// The `network` step, as registered in `SESSION_FINALIZERS`.
pub(crate) fn finalize(conn: &Connection) -> Result<()> {
    run(conn).map(|_| ())
}
