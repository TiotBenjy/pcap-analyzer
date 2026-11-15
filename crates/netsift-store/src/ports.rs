//! Table `open_ports` (migration `0400_flows.sql`): rows written by the `ports` analyzer and
//! the read queries of the Open Ports view.
//!
//! Merge rules (commutative, see `records.rs`): `first_ts` = min, `last_ts` = max;
//! `evidence`: the strongest (`syn_ack` > `udp_reply` > `server_data`); `service`, `detected`
//! and `banner`: a non-NULL value wins over NULL, the smallest one between two. Client counts are not stored: they come from `flows` at read time
//! (index `flows_service`).

use std::net::IpAddr;

use rusqlite::types::Value;
use rusqlite::{Connection, params};

use crate::connections::EndpointInfo;
use crate::error::Result;
use crate::query::{Conditions, Keyset, Page, PageRequest, keyset_page};
use crate::records::conversion;

/// Longest banner stored, in bytes (longer ones are cut on a character boundary).
pub const MAX_BANNER_LEN: usize = 256;
/// Largest top N of [`port_stats`].
pub const MAX_PORT_STATS: u32 = 100;

/// Observation of an open port (merge rules: see the module documentation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenPortRow {
    pub ip: IpAddr,
    /// IP protocol number (6 TCP, 17 UDP).
    pub transport: u8,
    pub port: u16,
    /// `syn_ack`, `server_data` or `udp_reply`.
    pub evidence: String,
    /// IANA service name of the port.
    pub service: Option<String>,
    /// Service identified by content.
    pub detected: Option<String>,
    pub banner: Option<String>,
    pub first_ts: i64,
    pub last_ts: i64,
}

fn cut(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s.get(..end).unwrap_or("")
}

impl OpenPortRow {
    pub(crate) fn insert(&self, conn: &Connection) -> Result<()> {
        let banner = self
            .banner
            .as_deref()
            .map(|b| cut(b, MAX_BANNER_LEN))
            .filter(|b| !b.is_empty());
        conn.prepare_cached(
            "INSERT INTO open_ports (ip, transport, port, evidence, service, detected, banner, \
             first_ts, last_ts) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9) \
             ON CONFLICT (ip, transport, port) DO UPDATE SET \
             evidence = CASE WHEN (CASE excluded.evidence WHEN 'syn_ack' THEN 2 \
             WHEN 'udp_reply' THEN 1 ELSE 0 END) > (CASE open_ports.evidence \
             WHEN 'syn_ack' THEN 2 WHEN 'udp_reply' THEN 1 ELSE 0 END) \
             THEN excluded.evidence ELSE open_ports.evidence END, \
             service = coalesce(min(open_ports.service, excluded.service), open_ports.service, excluded.service), \
             detected = coalesce(min(open_ports.detected, excluded.detected), open_ports.detected, excluded.detected), \
             banner = coalesce(min(open_ports.banner, excluded.banner), open_ports.banner, excluded.banner), \
             first_ts = min(open_ports.first_ts, excluded.first_ts), \
             last_ts = max(open_ports.last_ts, excluded.last_ts)",
        )?
        .execute(params![
            self.ip.to_string(),
            self.transport,
            self.port,
            self.evidence,
            self.service,
            self.detected,
            banner,
            self.first_ts,
            self.last_ts,
        ])?;
        Ok(())
    }
}

/// Filters of the open ports queries; `None` = no filter.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PortFilter {
    /// Address categories of the host.
    pub categories: Option<Vec<String>>,
    pub port: Option<u16>,
    /// IANA or detected service name (exact).
    pub service: Option<String>,
    /// Substring of the host IP, of one of its names or of a service name, or a port number.
    pub text: Option<String>,
}

/// The active filters of [`PortFilter`], on `o` (`open_ports`) only (P4.2): host categories
/// and names are looked up in `hosts` once per query, by sub-query, so no query joins `hosts`
/// for its condition and the inactive filters cost nothing.
fn conditions(filter: &PortFilter) -> Result<Conditions> {
    let mut c = Conditions::new();
    if let Some(categories) = filter
        .categories
        .as_ref()
        .map(serde_json::to_string)
        .transpose()?
    {
        c.push(
            "o.ip IN (SELECT ip FROM hosts WHERE category IN (SELECT value FROM json_each(?)))",
            [Value::Text(categories)],
        );
    }
    if let Some(port) = filter.port {
        c.push("o.port = ?", [Value::Integer(i64::from(port))]);
    }
    if let Some(service) = filter
        .service
        .as_ref()
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
    {
        c.push(
            "o.service = ? OR o.detected = ?",
            [Value::Text(service.clone()), Value::Text(service)],
        );
    }
    if let Some(text) = filter
        .text
        .as_ref()
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
    {
        c.push(
            "instr(o.ip, ?) > 0 \
             OR o.ip IN (SELECT ip FROM hosts WHERE instr(lower(names), ?) > 0) \
             OR instr(coalesce(o.service, ''), ?) > 0 OR instr(coalesce(o.detected, ''), ?) > 0 \
             OR CAST(o.port AS TEXT) = ?",
            [0, 1, 2, 3, 4].map(|_| Value::Text(text.clone())),
        );
    }
    Ok(c)
}

/// ` WHERE <conditions>`, or nothing.
fn where_clause(c: &Conditions) -> String {
    c.sql().map_or_else(String::new, |w| format!(" WHERE {w}"))
}

/// Hosts with open ports matching the filter, as a sub-query `g (ip, ports)` (grouped in the
/// order of the primary key of `open_ports`, without sort).
fn hosts_from(c: &Conditions) -> String {
    format!(
        "(SELECT o.ip AS ip, count(*) AS ports FROM open_ports o{} GROUP BY o.ip) g",
        where_clause(c)
    )
}

/// An open port with its number of distinct clients.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenPortEntry {
    pub row: OpenPortRow,
    /// Distinct client addresses of the flows to this port.
    pub clients: u64,
}

/// A host with its open ports (those matching the filter), sorted by transport then port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPorts {
    pub ip: IpAddr,
    pub host: EndpointInfo,
    /// Distinct clients of the flows to any open port of the host.
    pub clients: u64,
    pub ports: Vec<OpenPortEntry>,
}

fn ip(raw: &str, col: usize) -> rusqlite::Result<IpAddr> {
    raw.parse().map_err(|e| conversion(col, e))
}

fn json_strings(raw: Option<String>, col: usize) -> rusqlite::Result<Vec<String>> {
    match raw {
        None => Ok(Vec::new()),
        Some(raw) => serde_json::from_str(&raw).map_err(|e| conversion(col, e)),
    }
}

/// End-of-import step `ports` ([`crate::finalize::SESSION_FINALIZERS`]): the number of open
/// ports and the category of every host with open ports, into `open_port_hosts`, in the
/// transaction of the caller. Grouped in the order of the primary key of `open_ports` (no sort),
/// inserted in the order of the primary key of the table. Idempotent.
pub(crate) fn finalize(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "DELETE FROM open_port_hosts;
         INSERT INTO open_port_hosts (ip, ports, category)
             SELECT o.ip, count(*), coalesce((SELECT h.category FROM hosts h WHERE h.ip = o.ip), '')
             FROM open_ports o GROUP BY o.ip;",
    )?;
    Ok(())
}

/// True when the hosts of `filter` can be read from `open_port_hosts` (P4.8): no filter but the
/// categories, and the step `ports` done.
fn per_host_table(conn: &Connection, filter: &PortFilter) -> Result<bool> {
    let only_categories = PortFilter {
        categories: filter.categories.clone(),
        ..PortFilter::default()
    };
    Ok(*filter == only_categories && crate::finalize::step_done(conn, "ports")?)
}

/// Condition of the category filter on `open_port_hosts g`.
fn host_categories(filter: &PortFilter) -> Result<Conditions> {
    let mut c = Conditions::new();
    if let Some(categories) = filter
        .categories
        .as_ref()
        .map(serde_json::to_string)
        .transpose()?
    {
        c.push(
            "g.category IN (SELECT value FROM json_each(?))",
            [Value::Text(categories)],
        );
    }
    Ok(c)
}

/// One page of hosts with open ports: most ports first, then by address (descending).
pub fn hosts_page(
    conn: &Connection,
    filter: &PortFilter,
    request: &PageRequest,
) -> Result<Page<HostPorts>> {
    let mut cond = conditions(filter)?;
    let per_host = per_host_table(conn, filter)?;
    let page = if per_host {
        // In key order of `open_port_hosts_rank`, category covered: stops at the page size.
        let hosts = host_categories(filter)?;
        let where_sql = hosts.sql();
        let query = Keyset {
            from: "open_port_hosts g INDEXED BY open_port_hosts_rank",
            select: "g.ip",
            sort: "g.ports",
            tiebreak: "g.ip",
            descending: true,
            filter: where_sql.as_deref(),
        };
        keyset_page(conn, &query, &hosts.params(), request, |r| {
            r.get::<_, String>(0)
        })?
    } else {
        let from = hosts_from(&cond);
        let query = Keyset {
            from: &from,
            select: "g.ip",
            sort: "g.ports",
            tiebreak: "g.ip",
            descending: true,
            filter: None,
        };
        keyset_page(conn, &query, &cond.params(), request, |r| {
            r.get::<_, String>(0)
        })?
    };
    if page.items.is_empty() {
        return Ok(Page {
            items: Vec::new(),
            next_cursor: page.next_cursor,
        });
    }
    let ips = serde_json::to_string(&page.items)?;
    if per_host {
        // Only a category filter: every port of a listed host matches (no list of the hosts of
        // the categories to build for the ports of the page).
        cond = Conditions::new();
    }

    let mut hosts: Vec<HostPorts> = Vec::with_capacity(page.items.len());
    {
        let mut stmt = conn.prepare(
            "SELECT p.value, h.names, h.category, h.country, \
             (SELECT count(DISTINCT f.src_ip) FROM open_ports o JOIN flows f \
              ON f.dst_ip = o.ip AND f.dst_port = o.port AND f.transport = o.transport \
              WHERE o.ip = p.value) \
             FROM json_each(?1) p LEFT JOIN hosts h ON h.ip = p.value ORDER BY p.key",
        )?;
        let rows = stmt.query_map([&ips], |r| {
            let raw: String = r.get(0)?;
            Ok(HostPorts {
                ip: ip(&raw, 0)?,
                host: EndpointInfo {
                    names: json_strings(r.get(1)?, 1)?,
                    category: r.get(2)?,
                    country: r.get(3)?,
                },
                clients: r.get(4)?,
                ports: Vec::new(),
            })
        })?;
        for row in rows {
            hosts.push(row?);
        }
    }

    let mut ports_of = Conditions::new();
    ports_of.push(
        "o.ip IN (SELECT value FROM json_each(?))",
        [Value::Text(ips.clone())],
    );
    let sql = format!(
        "SELECT o.ip, o.transport, o.port, o.evidence, o.service, o.detected, o.banner, \
         o.first_ts, o.last_ts, \
         (SELECT count(DISTINCT f.src_ip) FROM flows f \
          WHERE f.dst_ip = o.ip AND f.dst_port = o.port AND f.transport = o.transport) \
         FROM open_ports o WHERE {}{} ORDER BY o.ip, o.transport, o.port",
        ports_of.sql().unwrap_or_default(),
        cond.sql().map_or_else(String::new, |w| format!(" AND {w}")),
    );
    let mut stmt = conn.prepare(&sql)?;
    let mut all = ports_of.params();
    all.extend(cond.params());
    let mut rows = stmt.query(all.as_slice())?;
    while let Some(r) = rows.next()? {
        let raw: String = r.get(0)?;
        let addr = ip(&raw, 0)?;
        let entry = OpenPortEntry {
            row: OpenPortRow {
                ip: addr,
                transport: r.get(1)?,
                port: r.get(2)?,
                evidence: r.get(3)?,
                service: r.get(4)?,
                detected: r.get(5)?,
                banner: r.get(6)?,
                first_ts: r.get(7)?,
                last_ts: r.get(8)?,
            },
            clients: r.get(9)?,
        };
        if let Some(host) = hosts.iter_mut().find(|h| h.ip == addr) {
            host.ports.push(entry);
        }
    }
    Ok(Page {
        items: hosts,
        next_cursor: page.next_cursor,
    })
}

/// Number of hosts with open ports matching the filter.
pub fn count_hosts(conn: &Connection, filter: &PortFilter) -> Result<u64> {
    if per_host_table(conn, filter)? {
        let hosts = host_categories(filter)?;
        let n: i64 = conn.query_row(
            &format!(
                "SELECT count(*) FROM open_port_hosts g{}",
                hosts
                    .sql()
                    .map_or_else(String::new, |w| format!(" WHERE {w}"))
            ),
            hosts.params().as_slice(),
            |r| r.get(0),
        )?;
        return Ok(u64::try_from(n).unwrap_or(0));
    }
    let cond = conditions(filter)?;
    let n: i64 = conn.query_row(
        &format!(
            "SELECT count(DISTINCT o.ip) FROM open_ports o{}",
            where_clause(&cond)
        ),
        cond.params().as_slice(),
        |r| r.get(0),
    )?;
    Ok(u64::try_from(n).unwrap_or(0))
}

/// One port of [`port_stats`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortStat {
    pub transport: u8,
    pub port: u16,
    pub service: Option<String>,
    /// Smallest service detected by content on this port.
    pub detected: Option<String>,
    /// Hosts with this port open.
    pub hosts: u64,
}

/// Ports open on the most hosts (at most `limit`, bounded by [`MAX_PORT_STATS`]), and the
/// total number of distinct open (transport, port) pairs and of open ports, for "Others".
pub fn port_stats(
    conn: &Connection,
    filter: &PortFilter,
    limit: u32,
) -> Result<(Vec<PortStat>, u64, u64)> {
    let cond = conditions(filter)?;
    let sql = format!(
        "SELECT o.transport, o.port, min(o.service), min(o.detected), count(*) AS hosts \
         FROM open_ports o{} \
         GROUP BY o.transport, o.port ORDER BY hosts DESC, o.port, o.transport LIMIT ?",
        where_clause(&cond)
    );
    let mut stmt = conn.prepare(&sql)?;
    let limit_value = i64::from(limit.min(MAX_PORT_STATS));
    let mut stats_params = cond.params();
    stats_params.push(&limit_value);
    let rows = stmt.query_map(stats_params.as_slice(), |r| {
        Ok(PortStat {
            transport: r.get(0)?,
            port: r.get(1)?,
            service: r.get(2)?,
            detected: r.get(3)?,
            hosts: r.get(4)?,
        })
    })?;
    let mut top = Vec::new();
    for row in rows {
        top.push(row?);
    }
    let (distinct, total): (i64, i64) = conn.query_row(
        &format!(
            "SELECT count(DISTINCT o.transport * 65536 + o.port), count(*) FROM open_ports o{}",
            where_clause(&cond)
        ),
        cond.params().as_slice(),
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    Ok((
        top,
        u64::try_from(distinct).unwrap_or(0),
        u64::try_from(total).unwrap_or(0),
    ))
}

#[cfg(test)]
mod tests;
