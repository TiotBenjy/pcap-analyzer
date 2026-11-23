//! Rows and read queries of the FTP analyzer (`ftp_sessions`, `ftp_lines`, `ftp_transfers`,
//! migration `1400_ftp.sql`, `docs/specs/ftp.md`).
//!
//! # Merge rules
//!
//! Every row is written once, by the shard of its control flow (ADR-032): plain inserts that
//! ignore a replayed key (`ON CONFLICT DO NOTHING`), so the tables do not depend on the arrival
//! order nor on the number of shards. The row id of `ftp_transfers` is only the tie-breaker of its
//! keyset: it follows the arrival order and is never compared between imports.
//!
//! Under a time range (ADR-030): sessions are folded rows (overlap of `first_ts` / `last_ts`,
//! counters of the session), transfers are point records (`ts`, the transfer command).

use std::net::IpAddr;

use rusqlite::types::Value;
use rusqlite::{Connection, OptionalExtension, params};

use crate::connections::EndpointInfo;
use crate::error::Result;
use crate::query::{Conditions, Keyset, Page, PageRequest, keyset_page};
use crate::range::{PointSql, TimeRange, query_row_ranged, where_overlap};
use crate::records::conversion;

fn ip(raw: &str, col: usize) -> rusqlite::Result<IpAddr> {
    raw.parse().map_err(|e| conversion(col, e))
}

fn names(raw: Option<String>, col: usize) -> rusqlite::Result<Vec<String>> {
    match raw {
        None => Ok(Vec::new()),
        Some(raw) => serde_json::from_str(&raw).map_err(|e| conversion(col, e)),
    }
}

fn unsigned(v: i64) -> u64 {
    u64::try_from(v).unwrap_or(0)
}

fn signed(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

/// `%q%` with LIKE wildcards escaped; `None` for an empty search.
fn like_pattern(q: Option<&str>) -> Option<String> {
    let q = q.map(str::trim).filter(|q| !q.is_empty())?;
    let mut out = String::with_capacity(q.len() + 2);
    out.push('%');
    for c in q.chars() {
        if matches!(c, '%' | '_' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('%');
    Some(out)
}

// ---- rows written by the analyzer ---------------------------------------------------------------

/// A record of the FTP analyzer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FtpRow {
    Session(FtpSessionRow),
    Line(FtpLineRow),
    Transfer(FtpTransferRow),
}

impl FtpRow {
    /// Name of the table written, key of the writer statistics.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Session(_) => "ftp_sessions",
            Self::Line(_) => "ftp_lines",
            Self::Transfer(_) => "ftp_transfers",
        }
    }

    pub(crate) fn insert(&self, conn: &Connection) -> Result<()> {
        match self {
            Self::Session(r) => r.insert(conn),
            Self::Line(r) => r.insert(conn),
            Self::Transfer(r) => r.insert(conn),
        }
    }

    /// Rough heap size, for the writer's batch accounting.
    pub fn approx_size(&self) -> usize {
        let opt = |v: &Option<String>| v.as_ref().map_or(0, String::len);
        match self {
            Self::Session(r) => 160 + opt(&r.banner) + opt(&r.username),
            Self::Line(r) => 64 + r.text.len() + opt(&r.head),
            Self::Transfer(r) => {
                160 + r.command.len()
                    + opt(&r.path)
                    + opt(&r.status_text)
                    + opt(&r.sha256)
                    + opt(&r.mime)
                    + opt(&r.listing)
            }
        }
    }
}

/// One control session (`ftp_sessions`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FtpSessionRow {
    pub flow_id: i64,
    pub client_ip: IpAddr,
    pub client_port: u16,
    pub server_ip: IpAddr,
    pub server_port: u16,
    pub first_ts: i64,
    pub last_ts: i64,
    pub banner: Option<String>,
    pub username: Option<String>,
    /// `accepted`, `rejected`, or `None` when no login reply was seen.
    pub login: Option<String>,
    pub tls: bool,
    pub commands: u64,
    pub replies: u64,
    pub files: u64,
    pub listings: u64,
    pub bytes: u64,
    pub lines: u32,
    pub transcript_truncated: bool,
    pub gaps: u32,
}

impl FtpSessionRow {
    fn insert(&self, conn: &Connection) -> Result<()> {
        conn.prepare_cached(
            "INSERT INTO ftp_sessions (flow_id, client_ip, client_port, server_ip, server_port, \
             first_ts, last_ts, banner, username, login, tls, commands, replies, files, listings, \
             bytes, lines, transcript_truncated, gaps) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, \
                     ?18, ?19) ON CONFLICT (flow_id) DO NOTHING",
        )?
        .execute(params![
            self.flow_id,
            self.client_ip.to_string(),
            self.client_port,
            self.server_ip.to_string(),
            self.server_port,
            self.first_ts,
            self.last_ts,
            self.banner,
            self.username,
            self.login,
            self.tls,
            signed(self.commands),
            signed(self.replies),
            signed(self.files),
            signed(self.listings),
            signed(self.bytes),
            self.lines,
            self.transcript_truncated,
            self.gaps,
        ])?;
        Ok(())
    }
}

/// One transcript line (`ftp_lines`).
#[derive(Clone, PartialEq, Eq)]
pub struct FtpLineRow {
    pub flow_id: i64,
    pub seq: u32,
    pub ts: i64,
    /// `c` command, `s` reply, `n` note.
    pub dir: &'static str,
    pub head: Option<String>,
    pub text: String,
    /// The text is a password: never logged.
    pub secret: bool,
    pub truncated: bool,
}

impl std::fmt::Debug for FtpLineRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FtpLineRow")
            .field("flow_id", &self.flow_id)
            .field("seq", &self.seq)
            .field("ts", &self.ts)
            .field("dir", &self.dir)
            .field("head", &self.head)
            .field(
                "text",
                if self.secret {
                    &"<redacted>" as &dyn std::fmt::Debug
                } else {
                    &self.text
                },
            )
            .field("secret", &self.secret)
            .field("truncated", &self.truncated)
            .finish()
    }
}

impl FtpLineRow {
    fn insert(&self, conn: &Connection) -> Result<()> {
        conn.prepare_cached(
            "INSERT INTO ftp_lines (flow_id, seq, ts, dir, head, text, secret, truncated) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) ON CONFLICT (flow_id, seq) DO NOTHING",
        )?
        .execute(params![
            self.flow_id,
            self.seq,
            self.ts,
            self.dir,
            self.head,
            self.text,
            self.secret,
            self.truncated,
        ])?;
        Ok(())
    }
}

/// One transfer (`ftp_transfers`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FtpTransferRow {
    pub flow_id: i64,
    pub seq: u32,
    pub ts: i64,
    pub end_ts: Option<i64>,
    pub command: String,
    pub path: Option<String>,
    /// `download`, `upload` or `listing`.
    pub direction: &'static str,
    /// `active` or `passive`.
    pub mode: Option<&'static str>,
    /// `PASV`, `EPSV`, `PORT` or `EPRT`.
    pub mode_command: Option<&'static str>,
    pub data_flow_id: Option<i64>,
    pub status: Option<u16>,
    pub status_text: Option<String>,
    pub bytes: u64,
    pub restart_offset: Option<u64>,
    pub truncated: bool,
    /// Lower-case hex SHA-256 of the stored content.
    pub sha256: Option<String>,
    pub mime: Option<String>,
    pub listing: Option<String>,
}

impl FtpTransferRow {
    fn insert(&self, conn: &Connection) -> Result<()> {
        conn.prepare_cached(
            "INSERT INTO ftp_transfers (flow_id, seq, ts, end_ts, command, path, direction, mode, \
             data_flow_id, status, status_text, bytes, restart_offset, truncated, sha256, mime, \
             listing, mode_command) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, \
                     ?18) \
             ON CONFLICT (flow_id, seq) DO NOTHING",
        )?
        .execute(params![
            self.flow_id,
            self.seq,
            self.ts,
            self.end_ts,
            self.command,
            self.path,
            self.direction,
            self.mode,
            self.data_flow_id,
            self.status,
            self.status_text,
            signed(self.bytes),
            self.restart_offset.map(signed),
            self.truncated,
            self.sha256,
            self.mime,
            self.listing,
            self.mode_command,
        ])?;
        Ok(())
    }
}

// ---- sessions -----------------------------------------------------------------------------------

/// Login filter of the session list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginFilter {
    Accepted,
    Rejected,
    /// No login reply seen.
    None,
}

/// Filters of the session list (all optional, combined with AND).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FtpSessionFilter {
    /// Text in the addresses, the user name or the banner.
    pub q: Option<String>,
    pub login: Option<LoginFilter>,
    /// Sessions whose span overlaps this range.
    pub range: Option<TimeRange>,
}

/// One stored session with what the session knows about both ends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FtpSessionEntry {
    pub row: FtpSessionRow,
    pub client: EndpointInfo,
    pub server: EndpointInfo,
}

const SESSION_FROM: &str = "ftp_sessions s \
    LEFT JOIN hosts hc ON hc.ip = s.client_ip LEFT JOIN hosts hs ON hs.ip = s.server_ip";
const SESSION_SELECT: &str = "s.flow_id, s.client_ip, s.client_port, s.server_ip, s.server_port, \
    s.first_ts, s.last_ts, s.banner, s.username, s.login, s.tls, s.commands, s.replies, s.files, \
    s.listings, s.bytes, s.lines, s.transcript_truncated, s.gaps, hc.names, hc.category, \
    hc.country, hs.names, hs.category, hs.country";

fn session_entry(r: &rusqlite::Row<'_>) -> rusqlite::Result<FtpSessionEntry> {
    let client: String = r.get(1)?;
    let server: String = r.get(3)?;
    Ok(FtpSessionEntry {
        row: FtpSessionRow {
            flow_id: r.get(0)?,
            client_ip: ip(&client, 1)?,
            client_port: r.get(2)?,
            server_ip: ip(&server, 3)?,
            server_port: r.get(4)?,
            first_ts: r.get(5)?,
            last_ts: r.get(6)?,
            banner: r.get(7)?,
            username: r.get(8)?,
            login: r.get(9)?,
            tls: r.get(10)?,
            commands: unsigned(r.get(11)?),
            replies: unsigned(r.get(12)?),
            files: unsigned(r.get(13)?),
            listings: unsigned(r.get(14)?),
            bytes: unsigned(r.get(15)?),
            lines: r.get(16)?,
            transcript_truncated: r.get(17)?,
            gaps: r.get(18)?,
        },
        client: EndpointInfo {
            names: names(r.get(19)?, 19)?,
            category: r.get(20)?,
            country: r.get(21)?,
        },
        server: EndpointInfo {
            names: names(r.get(22)?, 22)?,
            category: r.get(23)?,
            country: r.get(24)?,
        },
    })
}

fn session_conditions(filter: &FtpSessionFilter) -> Conditions {
    let mut c = Conditions::new();
    if let Some(p) = like_pattern(filter.q.as_deref()) {
        c.push(
            "s.client_ip LIKE ? ESCAPE '\\' OR s.server_ip LIKE ? ESCAPE '\\' \
             OR s.username LIKE ? ESCAPE '\\' OR s.banner LIKE ? ESCAPE '\\'",
            std::iter::repeat_n(Value::Text(p), 4),
        );
    }
    match filter.login {
        Some(LoginFilter::Accepted) => c.push("s.login = 'accepted'", []),
        Some(LoginFilter::Rejected) => c.push("s.login = 'rejected'", []),
        Some(LoginFilter::None) => c.push("s.login IS NULL", []),
        None => {}
    }
    if let Some(r) = filter.range {
        r.push_overlap(&mut c, "s.first_ts", "s.last_ts");
    }
    c
}

/// One page of sessions, by start time then control flow (ascending).
pub fn sessions_page(
    conn: &Connection,
    filter: &FtpSessionFilter,
    request: &PageRequest,
) -> Result<Page<FtpSessionEntry>> {
    let c = session_conditions(filter);
    let where_sql = c.sql();
    let query = Keyset {
        from: SESSION_FROM,
        select: SESSION_SELECT,
        sort: "s.first_ts",
        tiebreak: "s.flow_id",
        descending: false,
        filter: where_sql.as_deref(),
    };
    keyset_page(conn, &query, &c.params(), request, session_entry)
}

/// Number of sessions matching `filter`.
pub fn count_sessions(conn: &Connection, filter: &FtpSessionFilter) -> Result<u64> {
    let c = session_conditions(filter);
    let sql = match c.sql() {
        Some(w) => format!("SELECT count(*) FROM ftp_sessions s WHERE {w}"),
        None => "SELECT count(*) FROM ftp_sessions s".to_owned(),
    };
    let n: i64 = conn.query_row(&sql, c.params().as_slice(), |r| r.get(0))?;
    Ok(unsigned(n))
}

/// One session by control flow.
pub fn session(conn: &Connection, flow_id: i64) -> Result<Option<FtpSessionEntry>> {
    let sql = format!("SELECT {SESSION_SELECT} FROM {SESSION_FROM} WHERE s.flow_id = ?1");
    Ok(conn.query_row(&sql, [flow_id], session_entry).optional()?)
}

/// One stored transcript line.
#[derive(Clone, PartialEq, Eq)]
pub struct FtpLineEntry {
    pub seq: u32,
    pub ts: i64,
    pub dir: String,
    pub head: Option<String>,
    pub text: String,
    pub secret: bool,
    pub truncated: bool,
}

impl std::fmt::Debug for FtpLineEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FtpLineEntry")
            .field("seq", &self.seq)
            .field("dir", &self.dir)
            .field("head", &self.head)
            .field("secret", &self.secret)
            .finish_non_exhaustive()
    }
}

/// The first `limit` transcript lines of a session, in order (secrets included).
pub fn lines(conn: &Connection, flow_id: i64, limit: u32) -> Result<Vec<FtpLineEntry>> {
    let mut stmt = conn.prepare_cached(
        "SELECT seq, ts, dir, head, text, secret, truncated FROM ftp_lines \
         WHERE flow_id = ?1 ORDER BY seq LIMIT ?2",
    )?;
    let rows = stmt
        .query_map(params![flow_id, limit], |r| {
            Ok(FtpLineEntry {
                seq: r.get(0)?,
                ts: r.get(1)?,
                dir: r.get(2)?,
                head: r.get(3)?,
                text: r.get(4)?,
                secret: r.get(5)?,
                truncated: r.get(6)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

// ---- transfers ----------------------------------------------------------------------------------

/// Filters of the transfer list (all optional, combined with AND).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FtpTransferFilter {
    /// `download`, `upload` or `listing`.
    pub direction: Option<&'static str>,
    /// Text in the path.
    pub q: Option<String>,
    /// Transfers of one control session.
    pub session: Option<i64>,
    /// Transfers whose command `ts` is within this range.
    pub range: Option<TimeRange>,
}

/// One stored transfer with its session's ends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FtpTransferEntry {
    pub id: i64,
    pub flow_id: i64,
    pub seq: u32,
    pub ts: i64,
    pub end_ts: Option<i64>,
    pub command: String,
    pub path: Option<String>,
    pub direction: String,
    pub mode: Option<String>,
    pub mode_command: Option<String>,
    pub data_flow_id: Option<i64>,
    pub status: Option<u16>,
    pub status_text: Option<String>,
    pub bytes: u64,
    pub restart_offset: Option<u64>,
    pub truncated: bool,
    pub sha256: Option<String>,
    pub mime: Option<String>,
    pub listing: Option<String>,
    pub client_ip: IpAddr,
    pub server_ip: IpAddr,
    pub server_port: u16,
    pub username: Option<String>,
    pub client: EndpointInfo,
    pub server: EndpointInfo,
}

const TRANSFER_FROM: &str = "ftp_transfers t JOIN ftp_sessions s ON s.flow_id = t.flow_id \
    LEFT JOIN hosts hc ON hc.ip = s.client_ip LEFT JOIN hosts hs ON hs.ip = s.server_ip";
const TRANSFER_SELECT: &str = "t.id, t.flow_id, t.seq, t.ts, t.end_ts, t.command, t.path, \
    t.direction, t.mode, t.data_flow_id, t.status, t.status_text, t.bytes, t.restart_offset, \
    t.truncated, t.sha256, t.mime, t.listing, s.client_ip, s.server_ip, s.server_port, \
    s.username, hc.names, hc.category, hc.country, hs.names, hs.category, hs.country, \
    t.mode_command";

fn transfer_entry(r: &rusqlite::Row<'_>) -> rusqlite::Result<FtpTransferEntry> {
    let client: String = r.get(18)?;
    let server: String = r.get(19)?;
    Ok(FtpTransferEntry {
        id: r.get(0)?,
        flow_id: r.get(1)?,
        seq: r.get(2)?,
        ts: r.get(3)?,
        end_ts: r.get(4)?,
        command: r.get(5)?,
        path: r.get(6)?,
        direction: r.get(7)?,
        mode: r.get(8)?,
        mode_command: r.get(28)?,
        data_flow_id: r.get(9)?,
        status: r.get(10)?,
        status_text: r.get(11)?,
        bytes: unsigned(r.get(12)?),
        restart_offset: r.get::<_, Option<i64>>(13)?.map(unsigned),
        truncated: r.get(14)?,
        sha256: r.get(15)?,
        mime: r.get(16)?,
        listing: r.get(17)?,
        client_ip: ip(&client, 18)?,
        server_ip: ip(&server, 19)?,
        server_port: r.get(20)?,
        username: r.get(21)?,
        client: EndpointInfo {
            names: names(r.get(22)?, 22)?,
            category: r.get(23)?,
            country: r.get(24)?,
        },
        server: EndpointInfo {
            names: names(r.get(25)?, 25)?,
            category: r.get(26)?,
            country: r.get(27)?,
        },
    })
}

fn transfer_conditions(filter: &FtpTransferFilter) -> Conditions {
    let mut c = Conditions::new();
    if let Some(d) = filter.direction {
        c.push("t.direction = ?", [Value::Text(d.to_owned())]);
    }
    if let Some(p) = like_pattern(filter.q.as_deref()) {
        c.push("t.path LIKE ? ESCAPE '\\'", [Value::Text(p)]);
    }
    if let Some(s) = filter.session {
        c.push("t.flow_id = ?", [Value::Integer(s)]);
    }
    if let Some(r) = filter.range {
        r.push_point(&mut c, "t.ts");
    }
    c
}

/// One page of transfers, by command time then row id (ascending).
pub fn transfers_page(
    conn: &Connection,
    filter: &FtpTransferFilter,
    request: &PageRequest,
) -> Result<Page<FtpTransferEntry>> {
    let c = transfer_conditions(filter);
    let where_sql = c.sql();
    let query = Keyset {
        from: TRANSFER_FROM,
        select: TRANSFER_SELECT,
        sort: "t.ts",
        tiebreak: "t.id",
        descending: false,
        filter: where_sql.as_deref(),
    };
    keyset_page(conn, &query, &c.params(), request, transfer_entry)
}

/// Number of transfers matching `filter`.
pub fn count_transfers(conn: &Connection, filter: &FtpTransferFilter) -> Result<u64> {
    let c = transfer_conditions(filter);
    let sql = match c.sql() {
        Some(w) => format!("SELECT count(*) FROM ftp_transfers t WHERE {w}"),
        None => "SELECT count(*) FROM ftp_transfers t".to_owned(),
    };
    let n: i64 = conn.query_row(&sql, c.params().as_slice(), |r| r.get(0))?;
    Ok(unsigned(n))
}

/// Every transfer of one session (at most `limit`), in order.
pub fn session_transfers(
    conn: &Connection,
    flow_id: i64,
    limit: u32,
) -> Result<Vec<FtpTransferEntry>> {
    let sql = format!(
        "SELECT {TRANSFER_SELECT} FROM {TRANSFER_FROM} WHERE t.flow_id = ?1 \
         ORDER BY t.seq LIMIT ?2"
    );
    let mut stmt = conn.prepare_cached(&sql)?;
    let rows = stmt
        .query_map(params![flow_id, limit], transfer_entry)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

// ---- statistics ---------------------------------------------------------------------------------

/// Aggregates of the FTP view.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FtpStatsRows {
    /// Sessions (overlapping the range under a range).
    pub sessions: u64,
    pub servers: u64,
    pub clients: u64,
    /// Distinct user names.
    pub users: u64,
    pub logins_accepted: u64,
    pub logins_rejected: u64,
    pub tls_sessions: u64,
    /// Transfers (whose command is within the range under a range).
    pub transfers: u64,
    pub downloads: u64,
    pub uploads: u64,
    pub listings: u64,
    /// Transfers whose final reply is not `2xx` (or missing).
    pub failed: u64,
    /// Data bytes of the transfers.
    pub bytes: u64,
    /// Transfers whose content is stored.
    pub stored: u64,
}

/// Aggregates for the view: sessions by overlap, transfers by point (ADR-030).
pub fn stats(conn: &Connection, range: Option<TimeRange>) -> Result<FtpStatsRows> {
    let o = where_overlap(range, "first_ts", "last_ts");
    let mut out = FtpStatsRows::default();
    let (sessions, servers, clients, users, accepted, rejected, tls): (
        i64,
        i64,
        i64,
        i64,
        i64,
        i64,
        i64,
    ) = query_row_ranged(
        conn,
        &format!(
            "SELECT count(*), count(DISTINCT server_ip), count(DISTINCT client_ip), \
             count(DISTINCT username), coalesce(sum(login = 'accepted'), 0), \
             coalesce(sum(login = 'rejected'), 0), coalesce(sum(tls), 0) FROM ftp_sessions{o}"
        ),
        &[],
        range,
        |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
                r.get(6)?,
            ))
        },
    )?;
    out.sessions = unsigned(sessions);
    out.servers = unsigned(servers);
    out.clients = unsigned(clients);
    out.users = unsigned(users);
    out.logins_accepted = unsigned(accepted);
    out.logins_rejected = unsigned(rejected);
    out.tls_sessions = unsigned(tls);
    let plan = PointSql::new(conn, "ftp_transfers", "ts", range)?;
    let w = plan.where_();
    let (transfers, downloads, uploads, listings, failed, bytes, stored): (
        i64,
        i64,
        i64,
        i64,
        i64,
        i64,
        i64,
    ) = query_row_ranged(
        conn,
        &format!(
            "SELECT count(*), coalesce(sum(direction = 'download'), 0), \
             coalesce(sum(direction = 'upload'), 0), coalesce(sum(direction = 'listing'), 0), \
             coalesce(sum(status IS NULL OR status < 200 OR status >= 300), 0), \
             coalesce(sum(bytes), 0), coalesce(sum(sha256 IS NOT NULL), 0) \
             FROM ftp_transfers{w}"
        ),
        &[],
        range,
        |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
                r.get(6)?,
            ))
        },
    )?;
    out.transfers = unsigned(transfers);
    out.downloads = unsigned(downloads);
    out.uploads = unsigned(uploads);
    out.listings = unsigned(listings);
    out.failed = unsigned(failed);
    out.bytes = unsigned(bytes);
    out.stored = unsigned(stored);
    Ok(out)
}

#[cfg(test)]
mod tests;
