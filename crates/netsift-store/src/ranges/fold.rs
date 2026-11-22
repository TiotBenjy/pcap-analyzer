//! Flows active in a range folded into the conversations, traffic per host, conversations per pair
//! of categories and clients of the open ports of a range database (rules of the `connections`
//! analyzer, of its end-of-import step and of the Open Ports view).
//!
//! One streaming read of the active flows per pass, aggregated in memory: a `GROUP BY` over the
//! flows sorted every flow of a wide range (about 8 s for 726 000 flows on the 5 GB benchmark,
//! inserts in random id order included). Memory is bounded by splitting the conversations into
//! passes by a hash of their ends ([`FLOWS_PER_PASS`] active flows per pass at most): a
//! conversation falls in exactly one pass, and it is one (port, client) and (host, client) pair
//! of the open ports it reached, so the counts of the passes add up. Traffic per host is flushed by additive upserts past
//! [`MAX_PENDING_HOSTS`] hosts.

use std::collections::HashMap;

use rusqlite::{Connection, params};

use super::ATTACHED;
use crate::connections::{HostTrafficRow, MAX_PROTOCOLS};
use crate::error::{Result, StoreError};
use crate::range::{LONG_FLOW_NS, TimeRange};
use crate::records::sat;

/// Active flows read per pass at most (bounds the conversations held in memory).
const FLOWS_PER_PASS: u64 = 1_000_000;
/// Hosts whose traffic is held in memory before an additive flush.
const MAX_PENDING_HOSTS: usize = 200_000;
/// Rows between two checks of the cancellation.
const CHECK_EVERY: u32 = 65_536;
/// Distinct flow labels supported (bits of a mask); the analyzers know about 25.
const MAX_LABELS: usize = 64;

#[derive(Default)]
struct Group {
    id: Option<i64>,
    first_ts: i64,
    last_ts: i64,
    bytes_fwd: u64,
    bytes_rev: u64,
    packets_fwd: u64,
    packets_rev: u64,
    flows: u64,
    dns_bytes_fwd: u64,
    dns_bytes_rev: u64,
    dns_flows: u64,
    labels: u64,
    /// Open ports of the server reached by the flows (indexes in [`Ports`]): the conversation is
    /// one client of each, counted once.
    ports: Vec<u32>,
}

#[derive(Default, Clone, Copy)]
struct Traffic {
    bytes_sent: u64,
    bytes_received: u64,
    packets_sent: u64,
    packets_received: u64,
}

/// Flow labels (application protocol, else transport fallback) as bits.
#[derive(Default)]
struct Labels {
    names: Vec<String>,
}

impl Labels {
    fn bit(&mut self, label: &str) -> Result<u64> {
        // A few dozen labels at most: a scan beats hashing the text of every flow.
        if let Some(b) = self.names.iter().position(|n| n == label) {
            return Ok(1 << b);
        }
        let b = u8::try_from(self.names.len())
            .ok()
            .filter(|b| usize::from(*b) < MAX_LABELS)
            .ok_or_else(|| StoreError::RangeBuild("too many flow labels".to_owned()))?;
        self.names.push(label.to_owned());
        Ok(1 << b)
    }

    /// Sorted JSON array of the labels of `mask` (at most [`MAX_PROTOCOLS`], as the store keeps).
    fn json(&self, mask: u64) -> Result<String> {
        let mut set: Vec<&str> = self
            .names
            .iter()
            .enumerate()
            .filter(|(i, _)| mask & (1 << i) != 0)
            .map(|(_, n)| n.as_str())
            .collect();
        set.sort_unstable();
        set.truncate(MAX_PROTOCOLS);
        Ok(serde_json::to_string(&set)?)
    }
}

/// Label of a flow without application protocol (`transport_fallback` of the analyzers).
fn fallback(transport: u8) -> &'static str {
    match transport {
        6 => "tcp",
        17 => "udp",
        1 | 58 => "icmp",
        _ => "ip",
    }
}

/// 64-bit FNV-1a of the two ends of a conversation: its pass.
fn pass_of(src: &str, dst: &str, passes: u64) -> u64 {
    let h = super::fnv1a(src.as_bytes());
    let h = (h ^ 0xff).wrapping_mul(0x0100_0000_01b3);
    let h = dst
        .bytes()
        .fold(h, |h, b| (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3));
    h % passes
}

/// Open ports of the range database, by address then (transport, port).
struct Ports {
    index: HashMap<Box<str>, HashMap<(u8, u16), usize>>,
    keys: Vec<(Box<str>, u8, u16)>,
    flows: Vec<u64>,
    clients: Vec<u64>,
}

impl Ports {
    fn load(conn: &Connection) -> Result<Self> {
        let mut stmt = conn.prepare("SELECT ip, transport, port FROM main.open_ports")?;
        let mut rows = stmt.query([])?;
        let (mut index, mut keys) = (HashMap::new(), Vec::new());
        while let Some(r) = rows.next()? {
            let key: (Box<str>, u8, u16) = (r.get::<_, String>(0)?.into(), r.get(1)?, r.get(2)?);
            index
                .entry(key.0.clone())
                .or_insert_with(HashMap::new)
                .insert((key.1, key.2), keys.len());
            keys.push(key);
        }
        let n = keys.len();
        Ok(Self {
            index,
            keys,
            flows: vec![0; n],
            clients: vec![0; n],
        })
    }
}

/// Conversations of one pass, by client then server.
type Groups = HashMap<Box<str>, HashMap<Box<str>, Group>>;

/// Running state of [`fold_flows`] across its passes.
struct Fold<'c> {
    conn: &'c Connection,
    ports: Ports,
    categories: HashMap<String, String>,
    /// Conversations per pair of categories of their ends.
    pairs: HashMap<(String, String), i64>,
    labels: Labels,
    hosts: HashMap<Box<str>, Traffic>,
    host_clients: HashMap<Box<str>, u64>,
    /// Last id given to a conversation absent from the session.
    next_id: i64,
    passes: u64,
    seen: u32,
}

/// Fills `conversations`, `host_traffic`, `conversation_categories`, `open_port_clients` and
/// `open_port_host_clients` of the range database from the flows active in `range` (`hosts` and
/// `open_ports` already copied). `active`: flows active in the range; `wide`: read every flow in
/// storage order rather than through the start-time index (row by row: 3 s for 726 000 flows on
/// the benchmark).
pub(super) fn fold_flows(
    conn: &Connection,
    range: TimeRange,
    active: u64,
    wide: bool,
    abandoned: &dyn Fn() -> bool,
) -> Result<()> {
    let mut fold = Fold {
        conn,
        ports: Ports::load(conn)?,
        categories: host_categories(conn)?,
        pairs: HashMap::new(),
        labels: Labels::default(),
        hosts: HashMap::new(),
        host_clients: HashMap::new(),
        next_id: conn.query_row(
            &format!("SELECT coalesce(max(id), 0) FROM {ATTACHED}.conversations"),
            [],
            |r| r.get(0),
        )?,
        passes: active.div_ceil(FLOWS_PER_PASS).max(1),
        seen: 0,
    };
    for pass in 0..fold.passes {
        let mut groups = fold.scan(range, wide, pass, abandoned)?;
        fold.assign_ids(&mut groups, pass, abandoned)?;
        fold.write(groups, abandoned)?;
        if abandoned() {
            return Err(StoreError::Cancelled);
        }
    }
    fold.finish()
}

impl Fold<'_> {
    /// Counts a row; [`StoreError::Cancelled`] every [`CHECK_EVERY`] rows once abandoned.
    fn check(&mut self, abandoned: &dyn Fn() -> bool) -> Result<()> {
        self.seen = self.seen.wrapping_add(1);
        if self.seen.is_multiple_of(CHECK_EVERY) && abandoned() {
            return Err(StoreError::Cancelled);
        }
        Ok(())
    }

    fn in_pass(&self, src: &str, dst: &str, pass: u64) -> bool {
        self.passes == 1 || pass_of(src, dst, self.passes) == pass
    }

    /// The conversations of `pass`, from one read of the active flows.
    fn scan(
        &mut self,
        range: TimeRange,
        wide: bool,
        pass: u64,
        abandoned: &dyn Fn() -> bool,
    ) -> Result<Groups> {
        let columns = "src_ip, dst_ip, dst_port, transport, first_ts, last_ts, bytes_fwd, \
                       bytes_rev, packets_fwd, packets_rev, app_proto";
        let sql = if wide {
            format!(
                "SELECT {columns} FROM {ATTACHED}.flows NOT INDEXED \
                 WHERE first_ts < ?2 AND last_ts >= ?1"
            )
        } else {
            format!(
                "SELECT {columns} FROM {ATTACHED}.flows \
                 WHERE first_ts >= ?1 - {LONG_FLOW_NS} AND first_ts < ?2 AND last_ts >= ?1 \
                 UNION ALL \
                 SELECT {columns} FROM {ATTACHED}.flows \
                 WHERE last_ts - first_ts > {LONG_FLOW_NS} AND last_ts >= ?1 \
                   AND first_ts < ?1 - {LONG_FLOW_NS}"
            )
        };
        let mut stmt = self.conn.prepare_cached(&sql)?;
        let mut rows = stmt.query(params![range.from_ns(), range.to_ns()])?;
        let mut groups = Groups::new();
        while let Some(r) = rows.next()? {
            self.check(abandoned)?;
            let src = r.get_ref(0)?.as_str().map_err(rusqlite::Error::from)?;
            let dst = r.get_ref(1)?.as_str().map_err(rusqlite::Error::from)?;
            if !self.in_pass(src, dst, pass) {
                continue;
            }
            let dst_port: u16 = r.get(2)?;
            let transport: u8 = r.get(3)?;
            let (first_ts, last_ts): (i64, i64) = (r.get(4)?, r.get(5)?);
            let (bytes_fwd, bytes_rev): (u64, u64) = (r.get(6)?, r.get(7)?);
            let (packets_fwd, packets_rev): (u64, u64) = (r.get(8)?, r.get(9)?);
            let label = match r.get_ref(10)? {
                rusqlite::types::ValueRef::Text(t) => {
                    std::str::from_utf8(t).map_err(|e| rusqlite::Error::Utf8Error(10, e))?
                }
                _ => fallback(transport),
            };
            let dns = label == "dns";
            let bit = self.labels.bit(label)?;
            let of_src = match groups.get_mut(src) {
                Some(m) => m,
                None => groups.entry(src.into()).or_default(),
            };
            let g = match of_src.get_mut(dst) {
                Some(g) => g,
                None => of_src.entry(dst.into()).or_insert_with(|| Group {
                    first_ts,
                    last_ts,
                    ..Group::default()
                }),
            };
            g.first_ts = g.first_ts.min(first_ts);
            g.last_ts = g.last_ts.max(last_ts);
            g.bytes_fwd = g.bytes_fwd.saturating_add(bytes_fwd);
            g.bytes_rev = g.bytes_rev.saturating_add(bytes_rev);
            g.packets_fwd = g.packets_fwd.saturating_add(packets_fwd);
            g.packets_rev = g.packets_rev.saturating_add(packets_rev);
            g.flows = g.flows.saturating_add(1);
            if dns {
                g.dns_bytes_fwd = g.dns_bytes_fwd.saturating_add(bytes_fwd);
                g.dns_bytes_rev = g.dns_bytes_rev.saturating_add(bytes_rev);
                g.dns_flows = g.dns_flows.saturating_add(1);
            }
            g.labels |= bit;
            if let Some(&port) = self
                .ports
                .index
                .get(dst)
                .and_then(|m| m.get(&(transport, dst_port)))
            {
                if let Some(n) = self.ports.flows.get_mut(port) {
                    *n = n.saturating_add(1);
                }
                let port = u32::try_from(port).unwrap_or(u32::MAX);
                if !g.ports.contains(&port) {
                    g.ports.push(port);
                }
            }
        }
        Ok(groups)
    }

    /// Ids of the session conversations (an index-only scan of `UNIQUE (src_ip, dst_ip)`); one
    /// absent from the session gets an id above them all.
    fn assign_ids(
        &mut self,
        groups: &mut Groups,
        pass: u64,
        abandoned: &dyn Fn() -> bool,
    ) -> Result<()> {
        let mut stmt = self.conn.prepare_cached(&format!(
            "SELECT id, src_ip, dst_ip FROM {ATTACHED}.conversations"
        ))?;
        let mut rows = stmt.query([])?;
        while let Some(r) = rows.next()? {
            self.check(abandoned)?;
            let src = r.get_ref(1)?.as_str().map_err(rusqlite::Error::from)?;
            let dst = r.get_ref(2)?.as_str().map_err(rusqlite::Error::from)?;
            if !self.in_pass(src, dst, pass) {
                continue;
            }
            if let Some(g) = groups.get_mut(src).and_then(|m| m.get_mut(dst)) {
                g.id = Some(r.get(0)?);
            }
        }
        for g in groups.values_mut().flat_map(HashMap::values_mut) {
            if g.id.is_none() {
                self.next_id = self.next_id.saturating_add(1);
                g.id = Some(self.next_id);
            }
        }
        Ok(())
    }

    /// Inserts the conversations of a pass in id order, and adds them to the traffic per host,
    /// the clients of the open ports and the counts per pair of categories.
    fn write(&mut self, groups: Groups, abandoned: &dyn Fn() -> bool) -> Result<()> {
        type Row = (Box<str>, Box<str>, Group);
        let mut out: Vec<Row> = groups
            .into_iter()
            .flat_map(|(src, m)| m.into_iter().map(move |(dst, g)| (src.clone(), dst, g)))
            .collect();
        out.sort_unstable_by_key(|(_, _, g)| g.id);
        let mut insert = self.conn.prepare_cached(
            "INSERT INTO main.conversations (id, src_ip, dst_ip, first_ts, last_ts, bytes_fwd, \
                 bytes_rev, packets_fwd, packets_rev, flows, dns_bytes_fwd, dns_bytes_rev, \
                 dns_flows, protocols) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
        )?;
        for (src, dst, g) in out {
            self.check(abandoned)?;
            insert.execute(params![
                g.id,
                &*src,
                &*dst,
                g.first_ts,
                g.last_ts,
                sat(g.bytes_fwd),
                sat(g.bytes_rev),
                sat(g.packets_fwd),
                sat(g.packets_rev),
                sat(g.flows),
                sat(g.dns_bytes_fwd),
                sat(g.dns_bytes_rev),
                sat(g.dns_flows),
                self.labels.json(g.labels)?,
            ])?;
            // A conversation is one client of every open port it reached, and of their host.
            for port in &g.ports {
                if let Some(n) = usize::try_from(*port)
                    .ok()
                    .and_then(|p| self.ports.clients.get_mut(p))
                {
                    *n = n.saturating_add(1);
                }
            }
            if !g.ports.is_empty() {
                *self.host_clients.entry(dst.clone()).or_default() += 1;
            }
            let category = |ip: &str| self.categories.get(ip).cloned().unwrap_or_default();
            let pair = (category(&src), category(&dst));
            *self.pairs.entry(pair).or_default() += 1;
            self.add_traffic(&src, &dst, &g)?;
        }
        Ok(())
    }

    /// Both ends of a conversation, as the analyzer (an address talking to itself counts twice).
    fn add_traffic(&mut self, src: &str, dst: &str, g: &Group) -> Result<()> {
        for (ip, sent, received) in [
            (
                src,
                (g.bytes_fwd, g.packets_fwd),
                (g.bytes_rev, g.packets_rev),
            ),
            (
                dst,
                (g.bytes_rev, g.packets_rev),
                (g.bytes_fwd, g.packets_fwd),
            ),
        ] {
            let t = match self.hosts.get_mut(ip) {
                Some(t) => t,
                None => self.hosts.entry(ip.into()).or_default(),
            };
            t.bytes_sent = t.bytes_sent.saturating_add(sent.0);
            t.packets_sent = t.packets_sent.saturating_add(sent.1);
            t.bytes_received = t.bytes_received.saturating_add(received.0);
            t.packets_received = t.packets_received.saturating_add(received.1);
        }
        if self.hosts.len() >= MAX_PENDING_HOSTS {
            flush_hosts(self.conn, &mut self.hosts)?;
        }
        Ok(())
    }

    /// The tables summed over the passes.
    fn finish(mut self) -> Result<()> {
        flush_hosts(self.conn, &mut self.hosts)?;
        let mut stmt = self.conn.prepare(
            "INSERT INTO main.open_port_clients (ip, transport, port, flows, clients) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )?;
        for (i, (ip, transport, port)) in self.ports.keys.iter().enumerate() {
            let flows = self.ports.flows.get(i).copied().unwrap_or(0);
            if flows > 0 {
                let clients = self.ports.clients.get(i).copied().unwrap_or(0);
                stmt.execute(params![&**ip, transport, port, sat(flows), sat(clients)])?;
            }
        }
        let mut stmt = self
            .conn
            .prepare("INSERT INTO main.open_port_host_clients (ip, clients) VALUES (?1, ?2)")?;
        for (ip, clients) in &self.host_clients {
            stmt.execute(params![&**ip, sat(*clients)])?;
        }
        // The counts of the step `connections` (`connections::finalize`), from the same passes.
        let mut stmt = self.conn.prepare(
            "INSERT INTO main.conversation_categories (src_category, dst_category, \
                 conversations) VALUES (?1, ?2, ?3)",
        )?;
        for ((src, dst), n) in &self.pairs {
            stmt.execute(params![src, dst, n])?;
        }
        Ok(())
    }
}

/// Category of every host of the range database ('' when unknown), as the step `connections`
/// reads it (an end absent from `hosts` counts as '').
fn host_categories(conn: &Connection) -> Result<HashMap<String, String>> {
    let mut stmt = conn.prepare("SELECT ip, coalesce(category, '') FROM main.hosts")?;
    let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// Adds the pending traffic per host to `host_traffic` (the additive upsert of the writer).
fn flush_hosts(conn: &Connection, hosts: &mut HashMap<Box<str>, Traffic>) -> Result<()> {
    for (ip, t) in hosts.drain() {
        let Ok(ip) = ip.parse() else {
            continue;
        };
        HostTrafficRow {
            ip,
            bytes_sent: t.bytes_sent,
            bytes_received: t.bytes_received,
            packets_sent: t.packets_sent,
            packets_received: t.packets_received,
        }
        .insert(conn)?;
    }
    Ok(())
}
