//! End-of-import step `network` (ADR-014, ADR-018): folds `conversations` into the derived
//! tables of `0900_network.sql`, so that a graph request reads a few thousand pre-folded rows
//! instead of every conversation.
//!
//! Two streaming passes over `conversations` (hosts first, then the folding), aggregation in
//! memory bounded by the number of hosts and of folded keys, then batch inserts. The result
//! only depends on the content of the tables (ties broken by address): idempotent and
//! independent of the arrival order of the records.

use std::collections::{BTreeSet, HashMap};

use rusqlite::{Connection, params};

use super::{EXPAND_HOSTS, MAX_NODES, ProtocolGroup};
use crate::error::Result;
use crate::records::{conversion, sat};

/// Bit of a conversation label (`Other` for labels outside the groups).
fn label_bit(label: &str) -> u16 {
    ProtocolGroup::ALL
        .iter()
        .find(|g| g.labels().contains(&label))
        .copied()
        .unwrap_or(ProtocolGroup::Other)
        .bit()
}

/// Groups and labels of a `protocols` JSON value, parsed once per distinct value.
#[derive(Default)]
struct Labels {
    cache: HashMap<String, (u16, u32)>,
    sets: Vec<Vec<String>>,
}

impl Labels {
    /// (mask, id of the label set).
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

#[derive(Default)]
struct Host {
    country: Option<String>,
    category: String,
    traffic: u64,
    mask: u16,
    bytes: u64,
    seen: bool,
    rank: Option<u32>,
    crank: Option<u32>,
    keyed: bool,
    node: String,
    cnode: String,
    /// Interned `node`, `cnode` and `category` (see [`Names`]).
    ids: [u32; 3],
}

/// Interned strings of the folding keys (node keys and categories).
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

impl Host {
    fn expandable(&self) -> bool {
        self.crank.is_some_and(|c| c <= EXPAND_HOSTS) && !self.keyed
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
    src: usize,
    dst: usize,
    fwd: u64,
    rev: u64,
    packets: u64,
    flows: u64,
    mask: u16,
    labels: u32,
}

/// Edge key: (a, b, mask, category a, category b, IPv6).
type EdgeKey = (u32, u32, u16, u32, u32, bool);
/// Expand key: (x, x is the client, other node, other expandable host, mask, categories, IPv6).
type ExpandKey = (usize, bool, u32, Option<usize>, u16, u32, u32, bool);

const CONVERSATIONS: &str = "SELECT src_ip, dst_ip, bytes_fwd, bytes_rev, \
    CAST(min(packets_fwd + packets_rev, 9223372036854775807.0) AS INTEGER), flows, protocols \
    FROM conversations";

/// Visits every conversation with the index of both ends (hosts added on the fly).
fn each_conversation(
    conn: &Connection,
    hosts: &mut Vec<Host>,
    index: &mut HashMap<String, usize>,
    labels: &mut Labels,
    mut f: impl FnMut(&mut Vec<Host>, &Conv),
) -> Result<()> {
    let mut stmt = conn.prepare(CONVERSATIONS)?;
    let mut rows = stmt.query([])?;
    while let Some(r) = rows.next()? {
        let mut end = |col: usize| -> rusqlite::Result<usize> {
            let ip: String = r.get(col)?;
            Ok(*index.entry(ip).or_insert_with(|| {
                hosts.push(Host::default());
                hosts.len() - 1
            }))
        };
        let src = end(0)?;
        let dst = end(1)?;
        let raw: String = r.get(6)?;
        let (mask, set) = labels.get(&raw)?;
        let conv = Conv {
            src,
            dst,
            fwd: r.get(2)?,
            rev: r.get(3)?,
            packets: r.get(4)?,
            flows: r.get(5)?,
            mask,
            labels: set,
        };
        f(hosts, &conv);
    }
    Ok(())
}

/// The `network` step (see the module documentation).
#[allow(clippy::too_many_lines)] // One linear pipeline; splitting it would scatter its state.
pub(crate) fn finalize(conn: &Connection) -> Result<()> {
    for table in [
        "network_hosts",
        "network_edges",
        "network_country_edges",
        "network_expand",
        "network_host_counts",
        "network_protocols",
    ] {
        conn.execute(&format!("DELETE FROM {table}"), [])?;
    }

    // Hosts of the session with their category, country and overall traffic.
    let mut hosts: Vec<Host> = Vec::new();
    let mut index: HashMap<String, usize> = HashMap::new();
    let mut ips: Vec<String> = Vec::new();
    {
        let mut stmt = conn.prepare(
            "SELECT h.ip, h.country, coalesce(h.category, ''), \
             coalesce(t.bytes_sent, 0), coalesce(t.bytes_received, 0) \
             FROM hosts h LEFT JOIN host_traffic t ON t.ip = h.ip",
        )?;
        let mut rows = stmt.query([])?;
        while let Some(r) = rows.next()? {
            let ip: String = r.get(0)?;
            index.insert(ip, hosts.len());
            hosts.push(Host {
                country: r.get(1)?,
                category: r.get(2)?,
                traffic: r.get::<_, u64>(3)?.saturating_add(r.get::<_, u64>(4)?),
                ..Host::default()
            });
        }
    }

    // Pass 1: bytes and groups of every host; protocol counters.
    let mut labels = Labels::default();
    let mut groups = [0_u64; ProtocolGroup::ALL.len()];
    each_conversation(conn, &mut hosts, &mut index, &mut labels, |hosts, c| {
        let bytes = c.fwd.saturating_add(c.rev);
        let ends = [c.src, c.dst];
        let ends = if c.src == c.dst {
            &ends[..1]
        } else {
            &ends[..]
        };
        for &e in ends {
            if let Some(h) = hosts.get_mut(e) {
                h.bytes = h.bytes.saturating_add(bytes);
                h.mask |= c.mask;
                h.seen = true;
            }
        }
        for (i, g) in ProtocolGroup::ALL.iter().enumerate() {
            if c.mask & g.bit() != 0
                && let Some(n) = groups.get_mut(i)
            {
                *n += 1;
            }
        }
    })?;
    ips.resize(hosts.len(), String::new());
    for (ip, &i) in &index {
        if let Some(slot) = ips.get_mut(i) {
            slot.clone_from(ip);
        }
    }

    // Ranks (most bytes first, then address), overall and within each country.
    let mut order: Vec<usize> = (0..hosts.len())
        .filter(|&i| hosts.get(i).is_some_and(|h| h.seen))
        .collect();
    order.sort_by(|&a, &b| {
        let (ha, hb) = (&hosts[a], &hosts[b]);
        hb.bytes.cmp(&ha.bytes).then_with(|| ips[a].cmp(&ips[b]))
    });
    let mut per_country: HashMap<String, u32> = HashMap::new();
    for (rank, &i) in order.iter().enumerate() {
        let h = &mut hosts[i];
        h.rank = Some(u32::try_from(rank + 1).unwrap_or(u32::MAX));
        if let Some(cc) = &h.country {
            let n = per_country.entry(cc.clone()).or_default();
            *n += 1;
            h.crank = Some(*n);
        }
    }
    // Keyed hosts: the largest overall, and the largest having each group, so that the first N
    // hosts matching any protocol filter are keyed (a host in the top N matching a filter is in
    // the top N of each of its groups).
    let max = usize::try_from(MAX_NODES).unwrap_or(usize::MAX);
    for &i in order.iter().take(max) {
        hosts[i].keyed = true;
    }
    for g in ProtocolGroup::ALL {
        let firsts: Vec<usize> = order
            .iter()
            .copied()
            .filter(|&i| hosts[i].mask & g.bit() != 0)
            .take(max)
            .collect();
        for i in firsts {
            hosts[i].keyed = true;
        }
    }
    for (i, h) in hosts.iter_mut().enumerate() {
        h.node = if h.keyed {
            format!("h:{}", ips[i])
        } else if let Some(cc) = &h.country {
            format!("k:{cc}")
        } else {
            "other".to_owned()
        };
        h.cnode = match (&h.country, h.category.as_str()) {
            (Some(cc), _) => format!("c:{cc}"),
            (None, "public") => "unknown".to_owned(),
            _ => "local".to_owned(),
        };
    }

    let mut names = Names::default();
    for h in &mut hosts {
        h.ids = [names.id(&h.node), names.id(&h.cnode), names.id(&h.category)];
    }

    // Pass 2: folding.
    let v6 = |i: usize| ips[i].contains(':');
    let mut edges: HashMap<EdgeKey, Sums> = HashMap::new();
    let mut country_edges: HashMap<EdgeKey, Sums> = HashMap::new();
    let mut expand: HashMap<ExpandKey, Sums> = HashMap::new();
    each_conversation(conn, &mut hosts, &mut index, &mut labels, |hosts, c| {
        let (s, d) = (&hosts[c.src], &hosts[c.dst]);
        let six = v6(c.src) || v6(c.dst);
        edges
            .entry((s.ids[0], d.ids[0], c.mask, s.ids[2], d.ids[2], six))
            .or_default()
            .add(c);
        country_edges
            .entry((s.ids[1], d.ids[1], c.mask, s.ids[2], d.ids[2], six))
            .or_default()
            .add(c);
        for (x, other, x_is_src) in [(c.src, c.dst, true), (c.dst, c.src, false)] {
            let (hx, ho) = (&hosts[x], &hosts[other]);
            if !hx.expandable() || (x == other && !x_is_src) {
                continue;
            }
            let other_ip = ho.expandable().then_some(other);
            expand
                .entry((
                    x, x_is_src, ho.ids[0], other_ip, c.mask, hx.ids[2], ho.ids[2], six,
                ))
                .or_default()
                .add(c);
        }
    })?;

    // Inserts.
    let mut stmt = conn.prepare(
        "INSERT INTO network_hosts (ip, country, category, v6, mask, bytes, traffic, rank, \
         crank, keyed, node, cnode) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
    )?;
    let mut counts: HashMap<(String, String, String, bool, u16), u64> = HashMap::new();
    for (i, h) in hosts.iter().enumerate() {
        stmt.execute(params![
            ips[i],
            h.country,
            h.category,
            v6(i),
            h.mask,
            sat(h.bytes),
            sat(h.traffic),
            h.rank,
            h.crank,
            h.keyed,
            h.node,
            h.cnode,
        ])?;
        let node = if h.keyed {
            "keyed".to_owned()
        } else {
            h.node.clone()
        };
        *counts
            .entry((node, h.cnode.clone(), h.category.clone(), v6(i), h.mask))
            .or_default() += 1;
    }
    drop(stmt);
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
    for ((x, x_is_src, other_node, other_ip, mask, cat_x, cat_other, six), s) in &expand {
        stmt.execute(params![
            hosts[*x].country,
            ips[*x],
            x_is_src,
            names.name(*other_node),
            other_ip.map_or("", |o| ips[o].as_str()),
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
    let mut stmt = conn.prepare(
        "INSERT INTO network_host_counts (node, cnode, category, v6, mask, hosts) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    )?;
    for ((node, cnode, category, six, mask), n) in &counts {
        stmt.execute(params![node, cnode, category, six, mask, sat(*n)])?;
    }
    drop(stmt);
    let mut stmt =
        conn.prepare("INSERT INTO network_protocols (grp, conversations) VALUES (?1, ?2)")?;
    for (g, n) in ProtocolGroup::ALL.iter().zip(groups) {
        stmt.execute(params![g.as_str(), sat(n)])?;
    }
    Ok(())
}
