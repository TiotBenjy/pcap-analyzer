//! Servers (`0800_servers.sql`, ADR-017): rows of the `servers` analyzer (DHCP messages, NTP
//! responses, KDC replies), the end-of-import step that feeds DHCP host names into
//! `hosts.names`, and the read query of the Servers view.
//!
//! The roles are never stored: the `server_evidence` view derives them at read time from these
//! tables and from those of the DNS, ports, SMB and HTTP analyzers. A session upgraded after its
//! import lists the view in `meta.schema.tables_added_after_import` (ADR-013): [`analyzed`] is
//! then false and the view is shown as not run, not as empty.

use std::net::{IpAddr, Ipv4Addr};

use rusqlite::{Connection, OptionalExtension, params};

use crate::connections::EndpointInfo;
use crate::error::Result;
use crate::records::{MAX_HOST_NAMES, conversion, format_mac};
use crate::session::tables_added_after_import;

/// View of the derived roles.
pub const EVIDENCE_VIEW: &str = "server_evidence";

/// A row of the `servers` analyzer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerRow {
    /// New DHCP message (boxed: much larger than the others).
    Dhcp(Box<DhcpRow>),
    /// Commutative merging upsert of an NTP response.
    Ntp(NtpRow),
    /// Commutative merging upsert of a KDC reply.
    Kerberos(KerberosRow),
}

impl ServerRow {
    /// Table written, key of the writer statistics.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Dhcp(_) => "dhcp_messages",
            Self::Ntp(_) => "ntp_responses",
            Self::Kerberos(_) => "kerberos_replies",
        }
    }

    pub(crate) fn insert(&self, conn: &Connection) -> Result<()> {
        match self {
            Self::Dhcp(r) => r.insert(conn),
            Self::Ntp(r) => r.insert(conn),
            Self::Kerberos(r) => r.insert(conn),
        }
    }

    /// Approximate heap footprint, for the batch size bound of the engine.
    pub fn heap_size(&self) -> usize {
        match self {
            Self::Dhcp(d) => {
                256 + d.hostname.as_ref().map_or(0, String::len)
                    + 16 * (d.routers.len() + d.dns_servers.len())
            }
            Self::Ntp(n) => n.reference.len(),
            Self::Kerberos(k) => k.realm.as_ref().map_or(0, String::len),
        }
    }
}

fn text(ip: Option<Ipv4Addr>) -> Option<String> {
    ip.map(|a| a.to_string())
}

fn json_ips(list: &[Ipv4Addr]) -> Result<String> {
    let v: Vec<String> = list.iter().map(Ipv4Addr::to_string).collect();
    Ok(serde_json::to_string(&v)?)
}

/// One DHCP / BOOTP message (`dhcp_messages`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhcpRow {
    pub ts: i64,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub op: u8,
    pub msg_type: Option<String>,
    pub xid: u32,
    pub client_mac: Option<[u8; 6]>,
    pub ciaddr: Option<Ipv4Addr>,
    pub yiaddr: Option<Ipv4Addr>,
    pub siaddr: Option<Ipv4Addr>,
    pub giaddr: Option<Ipv4Addr>,
    pub server_id: Option<Ipv4Addr>,
    pub requested_ip: Option<Ipv4Addr>,
    pub subnet_mask: Option<Ipv4Addr>,
    pub routers: Vec<Ipv4Addr>,
    pub dns_servers: Vec<Ipv4Addr>,
    pub lease_s: Option<u32>,
    pub hostname: Option<String>,
}

impl DhcpRow {
    fn insert(&self, conn: &Connection) -> Result<()> {
        conn.prepare_cached(
            "INSERT INTO dhcp_messages (ts, src_ip, dst_ip, op, msg_type, xid, client_mac, \
             ciaddr, yiaddr, siaddr, giaddr, server_id, requested_ip, subnet_mask, routers, \
             dns_servers, lease_s, hostname) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)",
        )?
        .execute(params![
            self.ts,
            self.src_ip.to_string(),
            self.dst_ip.to_string(),
            self.op,
            self.msg_type,
            self.xid,
            self.client_mac.map(format_mac),
            text(self.ciaddr),
            text(self.yiaddr),
            text(self.siaddr),
            text(self.giaddr),
            text(self.server_id),
            text(self.requested_ip),
            text(self.subnet_mask),
            json_ips(&self.routers)?,
            json_ips(&self.dns_servers)?,
            self.lease_s,
            self.hostname,
        ])?;
        Ok(())
    }
}

/// One NTP server response (folded into `ntp_responses`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtpRow {
    pub ts: i64,
    pub server_ip: IpAddr,
    pub client_ip: IpAddr,
    pub version: u8,
    pub stratum: u8,
    pub reference: String,
}

/// The incoming response wins: more recent, or same time and greater values (deterministic).
const NTP_NEWER: &str = "(excluded.last_ts > ntp_responses.last_ts OR (excluded.last_ts = \
    ntp_responses.last_ts AND (excluded.stratum, excluded.version, excluded.reference) > \
    (ntp_responses.stratum, ntp_responses.version, ntp_responses.reference)))";

impl NtpRow {
    fn insert(&self, conn: &Connection) -> Result<()> {
        let n = NTP_NEWER;
        conn.prepare_cached(&format!(
            "INSERT INTO ntp_responses (server_ip, client_ip, responses, version, stratum, \
             reference, first_ts, last_ts) VALUES (?1, ?2, 1, ?3, ?4, ?5, ?6, ?6) \
             ON CONFLICT (server_ip, client_ip) DO UPDATE SET \
             responses = ntp_responses.responses + 1, \
             version = iif({n}, excluded.version, ntp_responses.version), \
             stratum = iif({n}, excluded.stratum, ntp_responses.stratum), \
             reference = iif({n}, excluded.reference, ntp_responses.reference), \
             first_ts = min(ntp_responses.first_ts, excluded.first_ts), \
             last_ts = max(ntp_responses.last_ts, excluded.last_ts)"
        ))?
        .execute(params![
            self.server_ip.to_string(),
            self.client_ip.to_string(),
            self.version,
            self.stratum,
            self.reference,
            self.ts,
        ])?;
        Ok(())
    }
}

/// One KDC reply (folded into `kerberos_replies`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KerberosRow {
    pub ts: i64,
    pub server_ip: IpAddr,
    pub client_ip: IpAddr,
    /// `as_rep`, `tgs_rep` or `error`.
    pub kind: String,
    pub realm: Option<String>,
    pub error_code: Option<i32>,
}

/// Same rule as [`NTP_NEWER`]; NULL realm and code compare as empty and -1.
const KRB_NEWER: &str = "(excluded.last_ts > kerberos_replies.last_ts OR (excluded.last_ts = \
    kerberos_replies.last_ts AND (coalesce(excluded.realm, ''), coalesce(excluded.error_code, -1)) \
    > (coalesce(kerberos_replies.realm, ''), coalesce(kerberos_replies.error_code, -1))))";

impl KerberosRow {
    fn insert(&self, conn: &Connection) -> Result<()> {
        let n = KRB_NEWER;
        conn.prepare_cached(&format!(
            "INSERT INTO kerberos_replies (server_ip, client_ip, kind, replies, realm, \
             error_code, first_ts, last_ts) VALUES (?1, ?2, ?3, 1, ?4, ?5, ?6, ?6) \
             ON CONFLICT (server_ip, client_ip, kind) DO UPDATE SET \
             replies = kerberos_replies.replies + 1, \
             realm = iif({n}, excluded.realm, kerberos_replies.realm), \
             error_code = iif({n}, excluded.error_code, kerberos_replies.error_code), \
             first_ts = min(kerberos_replies.first_ts, excluded.first_ts), \
             last_ts = max(kerberos_replies.last_ts, excluded.last_ts)"
        ))?
        .execute(params![
            self.server_ip.to_string(),
            self.client_ip.to_string(),
            self.kind,
            self.realm,
            self.error_code,
            self.ts,
        ])?;
        Ok(())
    }
}

// --- End of import ----------------------------------------------------------------------------

/// End-of-import step `servers` (ADR-014): adds the DHCP host names to `hosts.names`.
///
/// A name sent by a client (option 12, usually in a broadcast DISCOVER or REQUEST) is paired
/// with the address of the ACK of the same transaction (xid, client MAC): the two messages travel
/// on different flows, hence different shards. A name in the ACK itself counts too. Only hosts
/// already present get a name (as for DNS); names from other sources are kept and the DHCP ones
/// fill the room left, smallest first. Idempotent, independent of the arrival order.
pub fn finalize(conn: &Connection) -> Result<()> {
    let rows: Vec<(String, String, String)> = conn
        .prepare(
            "WITH leased AS (
                 SELECT DISTINCT a.yiaddr AS ip, coalesce(a.hostname, (
                     SELECT min(c.hostname) FROM dhcp_messages c
                     WHERE c.xid = a.xid AND c.client_mac IS a.client_mac AND c.op = 1
                       AND c.hostname IS NOT NULL)) AS name
                 FROM dhcp_messages a
                 WHERE a.op = 2 AND a.msg_type = 'ack' AND a.yiaddr IS NOT NULL)
             SELECT l.ip, h.names, json_group_array(l.name ORDER BY l.name)
             FROM leased l JOIN hosts h ON h.ip = l.ip
             WHERE l.name IS NOT NULL AND length(CAST(l.name AS BLOB)) <= 255
             GROUP BY l.ip",
        )?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
        .collect::<rusqlite::Result<_>>()?;
    let mut update = conn.prepare("UPDATE hosts SET names = ?2 WHERE ip = ?1")?;
    for (ip, existing, learned) in rows {
        let mut names: Vec<String> = serde_json::from_str(&existing)?;
        let learned: Vec<String> = serde_json::from_str(&learned)?;
        let before = names.len();
        for name in learned {
            if names.len() >= MAX_HOST_NAMES {
                break;
            }
            if !names.contains(&name) {
                names.push(name);
            }
        }
        if names.len() != before {
            names.sort_unstable();
            update.execute(params![ip, serde_json::to_string(&names)?])?;
        }
    }
    Ok(())
}

// --- Read queries -----------------------------------------------------------------------------

/// True when the roles of this session were analyzed: the view exists and was not added by an
/// upgrade after the import (its analyzers did not run).
pub fn analyzed(conn: &Connection) -> Result<bool> {
    let exists = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'view' AND name = ?1",
            [EVIDENCE_VIEW],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    Ok(exists && !tables_added_after_import(conn)?.contains(EVIDENCE_VIEW))
}

/// One piece of evidence of a role, with what `hosts` knows about the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceEntry {
    pub role: String,
    pub ip: IpAddr,
    pub kind: String,
    pub count: u64,
    pub clients: Option<u64>,
    pub first_ts: i64,
    pub last_ts: i64,
    pub example: Option<String>,
    pub host: EndpointInfo,
}

fn json_strings(raw: Option<String>, col: usize) -> rusqlite::Result<Vec<String>> {
    match raw {
        None => Ok(Vec::new()),
        Some(raw) => serde_json::from_str(&raw).map_err(|e| conversion(col, e)),
    }
}

fn unsigned(v: Option<i64>) -> Option<u64> {
    v.map(|n| u64::try_from(n).unwrap_or(0))
}

/// What [`evidence`] reads.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EvidenceQuery<'a> {
    /// Only this role (`server_evidence.role`).
    pub role: Option<&'a str>,
    /// Stored address categories (`hosts.category`); `None`: every category. A server absent from
    /// `hosts` (no stored category) always passes: the caller decides from its address.
    pub categories: Option<&'a [String]>,
    /// Servers kept per role, strongest first (clamped to `1..=MAX_SERVERS_PER_ROLE`).
    pub limit: u32,
}

/// Largest number of servers read per role.
pub const MAX_SERVERS_PER_ROLE: u32 = 1000;

/// Evidence of the strongest servers of each role, and the number of servers of each role.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RoleEvidence {
    /// Every piece of evidence of the kept servers, by role, then server rank (decreasing sum of
    /// counts, then address text), then decreasing count.
    pub entries: Vec<EvidenceEntry>,
    /// Servers per role after the category filter (kept or not), for the roles with servers.
    pub totals: Vec<(String, u64)>,
}

/// Evidence of the `limit` strongest servers of each role (or of `role` only), after the
/// category filter: the bound applies per role in SQL, so a role with many servers (an HTTP scan)
/// never hides another one. Rows whose address does not parse (never written by NetSift) are
/// skipped.
pub fn evidence(conn: &Connection, q: &EvidenceQuery<'_>) -> Result<RoleEvidence> {
    let categories = q.categories.map(serde_json::to_string).transpose()?;
    let limit = q.limit.clamp(1, MAX_SERVERS_PER_ROLE);
    let mut stmt = conn.prepare(
        "WITH e AS MATERIALIZED (
             SELECT e.role, e.ip, e.kind, e.count, e.clients, e.first_ts, e.last_ts, e.example,
                    h.names, h.category, h.country
             FROM server_evidence e LEFT JOIN hosts h ON h.ip = e.ip
             WHERE e.ip IS NOT NULL AND (?1 IS NULL OR e.role = ?1)
               AND (?2 IS NULL OR h.category IS NULL
                    OR h.category IN (SELECT value FROM json_each(?2)))),
         r AS (
             SELECT role, ip,
                    row_number() OVER (PARTITION BY role ORDER BY sum(count) DESC, ip) AS rank,
                    count(*) OVER (PARTITION BY role) AS servers
             FROM e GROUP BY role, ip)
         SELECT e.role, e.ip, e.kind, e.count, e.clients, e.first_ts, e.last_ts, e.example,
                e.names, e.category, e.country, r.servers
         FROM e JOIN r ON r.role = e.role AND r.ip = e.ip
         WHERE r.rank <= ?3
         ORDER BY e.role, r.rank, e.count DESC, e.kind",
    )?;
    let rows = stmt.query_map(params![q.role, categories, limit], |r| {
        let ip: String = r.get(1)?;
        Ok((
            ip.parse::<IpAddr>().ok(),
            unsigned(r.get(11)?).unwrap_or(0),
            EvidenceEntry {
                role: r.get(0)?,
                ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                kind: r.get(2)?,
                count: unsigned(r.get(3)?).unwrap_or(0),
                clients: unsigned(r.get(4)?),
                first_ts: r.get::<_, Option<i64>>(5)?.unwrap_or(0),
                last_ts: r.get::<_, Option<i64>>(6)?.unwrap_or(0),
                example: r.get(7)?,
                host: EndpointInfo {
                    names: json_strings(r.get(8)?, 8)?,
                    category: r.get(9)?,
                    country: r.get(10)?,
                },
            },
        ))
    })?;
    let mut out = RoleEvidence::default();
    for row in rows {
        let (ip, servers, mut entry) = row?;
        if out
            .totals
            .last()
            .is_none_or(|(role, _)| *role != entry.role)
        {
            out.totals.push((entry.role.clone(), servers));
        }
        if let Some(ip) = ip {
            entry.ip = ip;
            out.entries.push(entry);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests;
