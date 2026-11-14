//! Rows and read queries of the Credentials tab (`credentials`, migration 0600, ADR-018).
//!
//! The list queries ([`page`], [`stats`], [`paths`]) never read the secret columns: only
//! [`detail`] and [`export`] do, for the API routes that serve them on demand.

use std::fmt;
use std::net::IpAddr;

use rusqlite::types::ToSql;
use rusqlite::{Connection, OptionalExtension, params};

use crate::connections::EndpointInfo;
use crate::error::Result;
use crate::query::{Keyset, Page, PageRequest, keyset_page};
use crate::records::conversion;

/// Largest number of entries returned by one [`export`].
pub const MAX_EXPORT: u32 = 10_000;

/// One credential emitted by an analyzer, folded by `fingerprint` (merge rules: see the
/// migration). `Debug` redacts the secret and the hashcat line.
#[derive(Clone, PartialEq, Eq)]
pub struct CredentialRow {
    /// Lower-case hex SHA-256 of the identifying fields (computed by the engine).
    pub fingerprint: String,
    pub protocol: String,
    pub kind: String,
    pub secret_state: String,
    pub flow_id: Option<u64>,
    pub client_ip: Option<IpAddr>,
    pub client_port: Option<u16>,
    pub server_ip: Option<IpAddr>,
    pub server_port: Option<u16>,
    pub username: Option<String>,
    pub domain: Option<String>,
    pub workstation: Option<String>,
    pub secret: Option<String>,
    pub hashcat_mode: Option<u32>,
    pub hashcat_line: Option<String>,
    pub details: Vec<(String, String)>,
    pub ts: i64,
}

impl fmt::Debug for CredentialRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let redact = |o: &Option<String>| o.as_ref().map(|_| "<redacted>");
        f.debug_struct("CredentialRow")
            .field("fingerprint", &self.fingerprint)
            .field("protocol", &self.protocol)
            .field("kind", &self.kind)
            .field("secret_state", &self.secret_state)
            .field("flow_id", &self.flow_id)
            .field("client_ip", &self.client_ip)
            .field("server_ip", &self.server_ip)
            .field("username", &self.username)
            .field("domain", &self.domain)
            .field("secret", &redact(&self.secret))
            .field("hashcat_mode", &self.hashcat_mode)
            .field("hashcat_line", &redact(&self.hashcat_line))
            .field("ts", &self.ts)
            .finish_non_exhaustive()
    }
}

/// The incoming observation is the earliest one (deterministic tie-breaks on flow id, then
/// details), so the kept flow, ports and details do not depend on arrival order.
const EARLIER: &str = "(excluded.first_ts < credentials.first_ts OR (excluded.first_ts = \
    credentials.first_ts AND (coalesce(excluded.flow_id, -1), excluded.details) < \
    (coalesce(credentials.flow_id, -1), credentials.details)))";

impl CredentialRow {
    pub(crate) fn insert(&self, conn: &Connection) -> Result<()> {
        let details = serde_json::to_string(&self.details)?;
        let e = EARLIER;
        conn.prepare_cached(&format!(
            "INSERT INTO credentials \
             (fingerprint, protocol, kind, secret_state, flow_id, client_ip, client_port, \
              server_ip, server_port, username, domain, workstation, secret, hashcat_mode, \
              hashcat_line, details, seen_count, first_ts, last_ts) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, 1, \
                     ?17, ?17) \
             ON CONFLICT (fingerprint) DO UPDATE SET \
             seen_count = min(credentials.seen_count + 1, 9223372036854775807), \
             flow_id = iif({e}, excluded.flow_id, credentials.flow_id), \
             client_port = iif({e}, excluded.client_port, credentials.client_port), \
             workstation = iif({e}, excluded.workstation, credentials.workstation), \
             details = iif({e}, excluded.details, credentials.details), \
             first_ts = min(credentials.first_ts, excluded.first_ts), \
             last_ts = max(credentials.last_ts, excluded.last_ts)"
        ))?
        .execute(params![
            self.fingerprint,
            self.protocol,
            self.kind,
            self.secret_state,
            self.flow_id.map(|v| i64::try_from(v).unwrap_or(i64::MAX)),
            self.client_ip.map(|ip| ip.to_string()),
            self.client_port,
            self.server_ip.map(|ip| ip.to_string()),
            self.server_port,
            self.username,
            self.domain,
            self.workstation,
            self.secret,
            self.hashcat_mode,
            self.hashcat_line,
            details,
            self.ts,
        ])?;
        Ok(())
    }
}

/// One side of a credential exchange with what the session knows about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialEnd {
    pub ip: IpAddr,
    pub port: Option<u16>,
    pub info: EndpointInfo,
}

/// One list entry: everything but the secret and the hashcat line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialEntry {
    pub fingerprint: String,
    pub protocol: String,
    pub kind: String,
    pub secret_state: String,
    pub flow_id: Option<u64>,
    pub client: Option<CredentialEnd>,
    pub server: Option<CredentialEnd>,
    pub username: Option<String>,
    pub domain: Option<String>,
    pub workstation: Option<String>,
    pub has_secret: bool,
    pub hashcat_mode: Option<u32>,
    pub details: Vec<(String, String)>,
    pub seen_count: u64,
    pub first_ts: i64,
    pub last_ts: i64,
}

/// One entry with its sensitive fields ([`detail`], [`export`]). `Debug` redacts them.
#[derive(Clone, PartialEq, Eq)]
pub struct CredentialSecret {
    pub entry: CredentialEntry,
    pub secret: Option<String>,
    pub hashcat_line: Option<String>,
}

impl fmt::Debug for CredentialSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialSecret")
            .field("entry", &self.entry)
            .field("secret", &self.secret.as_ref().map(|_| "<redacted>"))
            .field(
                "hashcat_line",
                &self.hashcat_line.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

const FROM: &str = "credentials c \
    LEFT JOIN hosts hc ON hc.ip = c.client_ip LEFT JOIN hosts hs ON hs.ip = c.server_ip";
/// Columns read by [`entry`]; the secret columns are never part of it.
const SELECT: &str = "c.fingerprint, c.protocol, c.kind, c.secret_state, c.flow_id, c.client_ip, \
    c.client_port, c.server_ip, c.server_port, c.username, c.domain, c.workstation, \
    c.secret IS NOT NULL OR c.hashcat_line IS NOT NULL, c.hashcat_mode, c.details, c.seen_count, \
    c.first_ts, c.last_ts, hc.names, hc.category, hc.country, hs.names, hs.category, hs.country";
const SELECT_SECRET: &str = "c.secret, c.hashcat_line";

fn json_strings(raw: Option<String>, col: usize) -> rusqlite::Result<Vec<String>> {
    match raw {
        None => Ok(Vec::new()),
        Some(raw) => serde_json::from_str(&raw).map_err(|e| conversion(col, e)),
    }
}

fn end(
    r: &rusqlite::Row<'_>,
    ip_col: usize,
    port_col: usize,
    info_col: usize,
) -> rusqlite::Result<Option<CredentialEnd>> {
    let Some(raw) = r.get::<_, Option<String>>(ip_col)? else {
        return Ok(None);
    };
    Ok(Some(CredentialEnd {
        ip: raw.parse().map_err(|e| conversion(ip_col, e))?,
        port: r.get(port_col)?,
        info: EndpointInfo {
            names: json_strings(r.get(info_col)?, info_col)?,
            category: r.get(info_col + 1)?,
            country: r.get(info_col + 2)?,
        },
    }))
}

fn entry(r: &rusqlite::Row<'_>) -> rusqlite::Result<CredentialEntry> {
    let details: String = r.get(14)?;
    Ok(CredentialEntry {
        fingerprint: r.get(0)?,
        protocol: r.get(1)?,
        kind: r.get(2)?,
        secret_state: r.get(3)?,
        flow_id: r
            .get::<_, Option<i64>>(4)?
            .and_then(|v| u64::try_from(v).ok()),
        client: end(r, 5, 6, 18)?,
        server: end(r, 7, 8, 21)?,
        username: r.get(9)?,
        domain: r.get(10)?,
        workstation: r.get(11)?,
        has_secret: r.get(12)?,
        hashcat_mode: r.get(13)?,
        details: serde_json::from_str(&details).map_err(|e| conversion(14, e))?,
        seen_count: u64::try_from(r.get::<_, i64>(15)?).unwrap_or(0),
        first_ts: r.get(16)?,
        last_ts: r.get(17)?,
    })
}

fn secret_entry(r: &rusqlite::Row<'_>) -> rusqlite::Result<CredentialSecret> {
    Ok(CredentialSecret {
        entry: entry(r)?,
        secret: r.get(24)?,
        hashcat_line: r.get(25)?,
    })
}

/// Filters of the list and of the export.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CredentialFilter {
    /// Only this protocol (`ftp`, `http`...).
    pub protocol: Option<String>,
    /// Only this secret state (`plaintext`, `recoverable`, `metadata-only`).
    pub secret_state: Option<String>,
    /// Only this hashcat mode.
    pub hashcat_mode: Option<u32>,
}

impl CredentialFilter {
    /// Static `WHERE` text (one variant per combination, so indexes stay usable) and its values.
    fn sql(&self) -> (Option<&'static str>, Vec<Box<dyn ToSql>>) {
        let mut values: Vec<Box<dyn ToSql>> = Vec::new();
        let clause = match (&self.protocol, &self.secret_state, self.hashcat_mode) {
            (None, None, None) => None,
            (Some(p), None, None) => {
                values.push(Box::new(p.clone()));
                Some("c.protocol = ?")
            }
            (None, Some(s), None) => {
                values.push(Box::new(s.clone()));
                Some("c.secret_state = ?")
            }
            (Some(p), Some(s), None) => {
                values.push(Box::new(p.clone()));
                values.push(Box::new(s.clone()));
                Some("c.protocol = ? AND c.secret_state = ?")
            }
            (p, s, Some(m)) => {
                values.push(Box::new(m));
                let clause = match (p, s) {
                    (None, None) => "c.hashcat_mode = ?",
                    (Some(p), None) => {
                        values.push(Box::new(p.clone()));
                        "c.hashcat_mode = ? AND c.protocol = ?"
                    }
                    (None, Some(s)) => {
                        values.push(Box::new(s.clone()));
                        "c.hashcat_mode = ? AND c.secret_state = ?"
                    }
                    (Some(p), Some(s)) => {
                        values.push(Box::new(p.clone()));
                        values.push(Box::new(s.clone()));
                        "c.hashcat_mode = ? AND c.protocol = ? AND c.secret_state = ?"
                    }
                };
                Some(clause)
            }
        };
        (clause, values)
    }
}

/// One page of credentials, first seen first. No secret is read.
pub fn page(
    conn: &Connection,
    filter: &CredentialFilter,
    request: &PageRequest,
) -> Result<Page<CredentialEntry>> {
    let (clause, values) = filter.sql();
    let query = Keyset {
        from: FROM,
        select: SELECT,
        sort: "c.first_ts",
        tiebreak: "c.fingerprint",
        descending: false,
        filter: clause,
    };
    let params: Vec<&dyn ToSql> = values.iter().map(AsRef::as_ref).collect();
    keyset_page(conn, &query, &params, request, entry)
}

/// Number of entries matching `filter`.
pub fn count(conn: &Connection, filter: &CredentialFilter) -> Result<u64> {
    let (clause, values) = filter.sql();
    let sql = match clause {
        Some(c) => format!("SELECT count(*) FROM credentials c WHERE {c}"),
        None => "SELECT count(*) FROM credentials c".to_owned(),
    };
    let params: Vec<&dyn ToSql> = values.iter().map(AsRef::as_ref).collect();
    let n: i64 = conn.query_row(&sql, params.as_slice(), |r| r.get(0))?;
    Ok(u64::try_from(n).unwrap_or(0))
}

/// One entry with its secret and hashcat line, by fingerprint.
pub fn detail(conn: &Connection, fingerprint: &str) -> Result<Option<CredentialSecret>> {
    let sql = format!("SELECT {SELECT}, {SELECT_SECRET} FROM {FROM} WHERE c.fingerprint = ?1");
    Ok(conn
        .query_row(&sql, [fingerprint], secret_entry)
        .optional()?)
}

/// Entries to export with their secrets: the given fingerprints (at most [`MAX_EXPORT`]), or
/// every entry matching `filter` when `fingerprints` is empty; first seen first, bounded.
pub fn export(
    conn: &Connection,
    filter: &CredentialFilter,
    fingerprints: &[String],
) -> Result<Vec<CredentialSecret>> {
    let mut out = Vec::new();
    if fingerprints.is_empty() {
        let (clause, values) = filter.sql();
        let where_clause = clause.map(|c| format!(" WHERE {c}")).unwrap_or_default();
        let sql = format!(
            "SELECT {SELECT}, {SELECT_SECRET} FROM {FROM}{where_clause} \
             ORDER BY c.first_ts, c.fingerprint LIMIT {MAX_EXPORT}"
        );
        let params: Vec<&dyn ToSql> = values.iter().map(AsRef::as_ref).collect();
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(params.as_slice(), secret_entry)?;
        for row in rows {
            out.push(row?);
        }
    } else {
        for fp in fingerprints.iter().take(MAX_EXPORT as usize) {
            if let Some(c) = detail(conn, fp)? {
                out.push(c);
            }
        }
        out.sort_by(|a, b| {
            (a.entry.first_ts, &a.entry.fingerprint).cmp(&(b.entry.first_ts, &b.entry.fingerprint))
        });
        out.dedup_by(|a, b| a.entry.fingerprint == b.entry.fingerprint);
    }
    Ok(out)
}

/// Figures of the summary band and the filters.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CredentialStats {
    pub total: u64,
    pub plaintext: u64,
    pub recoverable: u64,
    pub metadata_only: u64,
    /// Entries carrying a hashcat line, per mode (ascending mode).
    pub hashcat_modes: Vec<(u32, u64)>,
    /// Entries per protocol (most entries first).
    pub protocols: Vec<(String, u64)>,
}

fn unsigned(n: i64) -> u64 {
    u64::try_from(n).unwrap_or(0)
}

/// Counts per state, hashcat mode and protocol (index-only scans, bounded by the few labels).
pub fn stats(conn: &Connection) -> Result<CredentialStats> {
    let mut s = CredentialStats::default();
    let mut stmt = conn.prepare("SELECT secret_state, count(*) FROM credentials GROUP BY 1")?;
    let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?;
    for row in rows {
        let (state, n) = row?;
        let n = unsigned(n);
        s.total += n;
        match state.as_str() {
            "plaintext" => s.plaintext += n,
            "recoverable" => s.recoverable += n,
            _ => s.metadata_only += n,
        }
    }
    let mut stmt = conn.prepare(
        "SELECT hashcat_mode, count(*) FROM credentials WHERE hashcat_mode IS NOT NULL \
         AND hashcat_line IS NOT NULL GROUP BY 1 ORDER BY 1 LIMIT 32",
    )?;
    let rows = stmt.query_map([], |r| Ok((r.get::<_, u32>(0)?, r.get::<_, i64>(1)?)))?;
    for row in rows {
        let (mode, n) = row?;
        s.hashcat_modes.push((mode, unsigned(n)));
    }
    let mut stmt = conn.prepare(
        "SELECT protocol, count(*) AS n FROM credentials GROUP BY 1 ORDER BY n DESC, 1 LIMIT 32",
    )?;
    let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?;
    for row in rows {
        let (p, n) = row?;
        s.protocols.push((p, unsigned(n)));
    }
    Ok(s)
}

/// One aggregated client -> protocol -> server path of the mini-graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialPath {
    pub client: Option<CredentialEnd>,
    pub protocol: String,
    pub server: Option<CredentialEnd>,
    /// Distinct credentials on this path.
    pub entries: u64,
    /// Observations (sum of `seen_count`).
    pub seen: u64,
    /// Entries with a plain-text secret.
    pub plaintext: u64,
}

/// The `limit` paths with the most entries, and the number of paths left out.
pub fn paths(conn: &Connection, limit: u32) -> Result<(Vec<CredentialPath>, u64)> {
    let total: i64 = conn.query_row(
        "SELECT count(*) FROM (SELECT 1 FROM credentials \
         GROUP BY client_ip, protocol, server_ip, server_port)",
        [],
        |r| r.get(0),
    )?;
    let mut stmt = conn.prepare(
        "SELECT p.client_ip, NULL, p.server_ip, p.server_port, p.protocol, p.n, p.seen, p.plain, \
                hc.names, hc.category, hc.country, hs.names, hs.category, hs.country \
         FROM (SELECT client_ip, protocol, server_ip, server_port, count(*) AS n, \
                      min(sum(seen_count), 9223372036854775807) AS seen, \
                      sum(secret_state = 'plaintext') AS plain \
               FROM credentials GROUP BY client_ip, protocol, server_ip, server_port) p \
         LEFT JOIN hosts hc ON hc.ip = p.client_ip LEFT JOIN hosts hs ON hs.ip = p.server_ip \
         ORDER BY p.n DESC, p.seen DESC, p.client_ip, p.protocol, p.server_ip, p.server_port \
         LIMIT ?1",
    )?;
    let rows = stmt.query_map([limit], |r| {
        Ok(CredentialPath {
            client: end(r, 0, 1, 8)?,
            server: end(r, 2, 3, 11)?,
            protocol: r.get(4)?,
            entries: unsigned(r.get(5)?),
            seen: unsigned(r.get(6)?),
            plaintext: unsigned(r.get(7)?),
        })
    })?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    let shown = out.len() as u64;
    Ok((out, unsigned(total).saturating_sub(shown)))
}

#[cfg(test)]
mod tests;
