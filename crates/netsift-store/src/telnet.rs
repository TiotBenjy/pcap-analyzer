//! Rows and read queries of the Telnet analyzer (`telnet_sessions`, `docs/specs/telnet.md`).
//!
//! The transcript is stored apart (`telnet_transcripts`) and without its secrets: a secret run is
//! the marker `["p", ""]` in `transcript`, its text is in `secrets` (same order). Only [`session_detail`] puts them back
//! together. Under a time range (ADR-030), a session is a folded row: it is listed when its span
//! overlaps the range, with the counters of the whole connection.

use std::fmt;
use std::net::IpAddr;

use rusqlite::types::Value;
use rusqlite::{Connection, OptionalExtension, params};

use crate::connections::EndpointInfo;
use crate::error::{Result, StoreError};
use crate::query::{Conditions, Keyset, Page, PageRequest, keyset_page};
use crate::range::{TimeRange, query_row_ranged, where_overlap};
use crate::records::{conversion, sat};

/// Who produced a run of a transcript.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Speaker {
    Client,
    Server,
    /// Typed at a password prompt (sensitive).
    Secret,
}

impl Speaker {
    /// Tag of the run in the stored JSON.
    const fn tag(self) -> &'static str {
        match self {
            Self::Client => "c",
            Self::Server => "s",
            Self::Secret => "p",
        }
    }

    fn from_tag(tag: &str) -> Option<Self> {
        match tag {
            "c" => Some(Self::Client),
            "s" => Some(Self::Server),
            "p" => Some(Self::Secret),
            _ => None,
        }
    }
}

/// One run of a transcript. `Debug` hides the text of a secret run.
#[derive(Clone, PartialEq, Eq)]
pub struct TelnetRun {
    pub speaker: Speaker,
    pub text: String,
}

impl fmt::Debug for TelnetRun {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text: &dyn fmt::Debug = if self.speaker == Speaker::Secret {
            &"<redacted>"
        } else {
            &self.text
        };
        f.debug_struct("TelnetRun")
            .field("speaker", &self.speaker)
            .field("text", text)
            .finish()
    }
}

/// One Telnet connection emitted by the analyzer. `Debug` hides the transcript.
#[derive(Clone, PartialEq, Eq)]
pub struct TelnetRow {
    pub flow_id: i64,
    pub first_ts: i64,
    pub last_ts: i64,
    pub client_ip: IpAddr,
    pub client_port: u16,
    pub server_ip: IpAddr,
    pub server_port: u16,
    pub client_bytes: u64,
    pub server_bytes: u64,
    pub username: Option<String>,
    pub env_user: Option<String>,
    /// `accepted` / `rejected`.
    pub login: Option<String>,
    pub login_attempts: u32,
    pub terminal: Option<String>,
    pub window: Option<(u16, u16)>,
    pub options: Vec<String>,
    /// Runs in order, secrets included (separated on insert).
    pub transcript: Vec<TelnetRun>,
    pub transcript_bytes: u64,
    pub transcript_lines: u32,
    pub truncated: bool,
}

impl fmt::Debug for TelnetRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TelnetRow")
            .field("flow_id", &self.flow_id)
            .field("client_ip", &self.client_ip)
            .field("server_ip", &self.server_ip)
            .field("login", &self.login)
            .field("runs", &self.transcript.len())
            .field("truncated", &self.truncated)
            .finish_non_exhaustive()
    }
}

/// `(transcript, secrets)` JSON of `runs`: secrets moved out of the transcript.
fn split_secrets(runs: &[TelnetRun]) -> Result<(String, String)> {
    let mut transcript: Vec<(&str, &str)> = Vec::with_capacity(runs.len());
    let mut secrets: Vec<&str> = Vec::new();
    for run in runs {
        if run.speaker == Speaker::Secret {
            secrets.push(&run.text);
            transcript.push((Speaker::Secret.tag(), ""));
        } else {
            transcript.push((run.speaker.tag(), &run.text));
        }
    }
    Ok((
        serde_json::to_string(&transcript)?,
        serde_json::to_string(&secrets)?,
    ))
}

/// Runs of a stored transcript, the secret runs filled from `secrets` (in order).
fn join_secrets(transcript: &str, secrets: &str) -> serde_json::Result<Vec<TelnetRun>> {
    let runs: Vec<(String, String)> = serde_json::from_str(transcript)?;
    let mut secrets = serde_json::from_str::<Vec<String>>(secrets)?.into_iter();
    Ok(runs
        .into_iter()
        .filter_map(|(tag, text)| {
            let speaker = Speaker::from_tag(&tag)?;
            let text = if speaker == Speaker::Secret {
                secrets.next().unwrap_or_default()
            } else {
                text
            };
            Some(TelnetRun { speaker, text })
        })
        .collect())
}

impl TelnetRow {
    pub(crate) fn insert(&self, conn: &Connection) -> Result<()> {
        let (transcript, secrets) = split_secrets(&self.transcript)?;
        let (cols, rows) = self.window.unzip();
        let inserted = conn
            .prepare_cached(
                "INSERT INTO telnet_sessions \
             (flow_id, first_ts, last_ts, client_ip, client_port, server_ip, server_port, \
              client_bytes, server_bytes, username, env_user, login, login_attempts, terminal, \
              window_cols, window_rows, options, transcript_bytes, transcript_lines, truncated) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, \
                     ?18, ?19, ?20) \
             ON CONFLICT (flow_id) DO NOTHING",
            )?
            .execute(params![
                self.flow_id,
                self.first_ts,
                self.last_ts,
                self.client_ip.to_string(),
                self.client_port,
                self.server_ip.to_string(),
                self.server_port,
                sat(self.client_bytes),
                sat(self.server_bytes),
                self.username,
                self.env_user,
                self.login,
                self.login_attempts,
                self.terminal,
                cols,
                rows,
                serde_json::to_string(&self.options)?,
                sat(self.transcript_bytes),
                self.transcript_lines,
                self.truncated,
            ])?;
        if inserted > 0 {
            conn.prepare_cached(
                "INSERT INTO telnet_transcripts (flow_id, transcript, secrets) VALUES (?1, ?2, ?3) \
                 ON CONFLICT (flow_id) DO NOTHING",
            )?
            .execute(params![self.flow_id, transcript, secrets])?;
        }
        Ok(())
    }

    /// Rough heap size, for the writer's batch accounting.
    pub fn approx_size(&self) -> usize {
        let opt = |v: &Option<String>| v.as_ref().map_or(0, String::len);
        256 + opt(&self.username)
            + opt(&self.env_user)
            + opt(&self.terminal)
            + self.options.iter().map(|o| o.len() + 24).sum::<usize>()
            + self
                .transcript
                .iter()
                .map(|r| r.text.len() + 32)
                .sum::<usize>()
    }
}

// ---- list --------------------------------------------------------------------------------------

/// Login filter of the list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginFilter {
    Accepted,
    Rejected,
    /// A password was typed but nothing told whether it was accepted.
    Unknown,
    /// No password typed.
    None,
}

/// Filters of the session list (all optional, combined with AND).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TelnetFilter {
    /// Text in the addresses, user names, terminal or transcript (never the secrets).
    pub q: Option<String>,
    pub login: Option<LoginFilter>,
    /// Sessions whose span overlaps this range.
    pub range: Option<TimeRange>,
}

/// One stored session (without its transcript) with what the session knows about both ends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelnetEntry {
    pub flow_id: i64,
    pub first_ts: i64,
    pub last_ts: i64,
    pub client_ip: IpAddr,
    pub client_port: u16,
    pub server_ip: IpAddr,
    pub server_port: u16,
    pub client_bytes: u64,
    pub server_bytes: u64,
    pub username: Option<String>,
    pub env_user: Option<String>,
    pub login: Option<String>,
    pub login_attempts: u32,
    pub terminal: Option<String>,
    pub window: Option<(u16, u16)>,
    pub options: Vec<String>,
    pub transcript_bytes: u64,
    pub transcript_lines: u32,
    pub truncated: bool,
    pub client: EndpointInfo,
    pub server: EndpointInfo,
}

const FROM: &str = "telnet_sessions t \
    LEFT JOIN hosts hc ON hc.ip = t.client_ip LEFT JOIN hosts hs ON hs.ip = t.server_ip";
const SELECT: &str = "t.flow_id, t.first_ts, t.last_ts, t.client_ip, t.client_port, t.server_ip, \
    t.server_port, t.client_bytes, t.server_bytes, t.username, t.env_user, t.login, \
    t.login_attempts, t.terminal, t.window_cols, t.window_rows, t.options, t.transcript_bytes, \
    t.transcript_lines, t.truncated, hc.names, hc.category, hc.country, hs.names, hs.category, \
    hs.country";

fn ip(raw: &str, col: usize) -> rusqlite::Result<IpAddr> {
    raw.parse().map_err(|e| conversion(col, e))
}

fn json_strings(raw: Option<String>, col: usize) -> rusqlite::Result<Vec<String>> {
    match raw {
        None => Ok(Vec::new()),
        Some(raw) => serde_json::from_str(&raw).map_err(|e| conversion(col, e)),
    }
}

fn unsigned(v: i64) -> u64 {
    u64::try_from(v).unwrap_or(0)
}

fn entry(r: &rusqlite::Row<'_>) -> rusqlite::Result<TelnetEntry> {
    let client: String = r.get(3)?;
    let server: String = r.get(5)?;
    let cols: Option<u16> = r.get(14)?;
    let rows: Option<u16> = r.get(15)?;
    Ok(TelnetEntry {
        flow_id: r.get(0)?,
        first_ts: r.get(1)?,
        last_ts: r.get(2)?,
        client_ip: ip(&client, 3)?,
        client_port: r.get(4)?,
        server_ip: ip(&server, 5)?,
        server_port: r.get(6)?,
        client_bytes: unsigned(r.get(7)?),
        server_bytes: unsigned(r.get(8)?),
        username: r.get(9)?,
        env_user: r.get(10)?,
        login: r.get(11)?,
        login_attempts: r.get(12)?,
        terminal: r.get(13)?,
        window: cols.zip(rows),
        options: json_strings(r.get(16)?, 16)?,
        transcript_bytes: unsigned(r.get(17)?),
        transcript_lines: r.get(18)?,
        truncated: r.get(19)?,
        client: EndpointInfo {
            names: json_strings(r.get(20)?, 20)?,
            category: r.get(21)?,
            country: r.get(22)?,
        },
        server: EndpointInfo {
            names: json_strings(r.get(23)?, 23)?,
            category: r.get(24)?,
            country: r.get(25)?,
        },
    })
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

/// LIKE pattern of `q` as written inside a JSON string (`"` -> `\"`, `\` -> `\\`...).
fn json_pattern(q: Option<&str>) -> Option<String> {
    let q = q.map(str::trim).filter(|q| !q.is_empty())?;
    let quoted = serde_json::to_string(q).ok()?;
    let inner = quoted.get(1..quoted.len().saturating_sub(1))?;
    like_pattern(Some(inner))
}

fn conditions(filter: &TelnetFilter) -> Conditions {
    let mut c = Conditions::new();
    if let Some(p) = like_pattern(filter.q.as_deref()) {
        // The transcript is JSON: the search text is matched in its JSON form (`"` and `\`
        // escaped). It holds no secret (they are in `secrets`, never searched).
        let json = json_pattern(filter.q.as_deref()).unwrap_or_else(|| p.clone());
        c.push(
            "t.client_ip LIKE ? ESCAPE '\\' OR t.server_ip LIKE ? ESCAPE '\\' \
             OR t.username LIKE ? ESCAPE '\\' OR t.env_user LIKE ? ESCAPE '\\' \
             OR t.terminal LIKE ? ESCAPE '\\' OR EXISTS (SELECT 1 FROM telnet_transcripts x \
             WHERE x.flow_id = t.flow_id AND x.transcript LIKE ? ESCAPE '\\')",
            std::iter::repeat_n(Value::Text(p), 5).chain([Value::Text(json)]),
        );
    }
    match filter.login {
        Some(LoginFilter::Accepted) => c.push("t.login = 'accepted'", []),
        Some(LoginFilter::Rejected) => c.push("t.login = 'rejected'", []),
        Some(LoginFilter::Unknown) => c.push("t.login IS NULL AND t.login_attempts > 0", []),
        Some(LoginFilter::None) => c.push("t.login_attempts = 0", []),
        None => {}
    }
    if let Some(r) = filter.range {
        r.push_overlap(&mut c, "t.first_ts", "t.last_ts");
    }
    c
}

/// One page of sessions, by start time then flow id (ascending).
pub fn sessions_page(
    conn: &Connection,
    filter: &TelnetFilter,
    request: &PageRequest,
) -> Result<Page<TelnetEntry>> {
    let c = conditions(filter);
    let where_sql = c.sql();
    let query = Keyset {
        from: FROM,
        select: SELECT,
        sort: "t.first_ts",
        tiebreak: "t.flow_id",
        descending: false,
        filter: where_sql.as_deref(),
    };
    keyset_page(conn, &query, &c.params(), request, entry)
}

/// Number of sessions matching `filter`.
pub fn count_sessions(conn: &Connection, filter: &TelnetFilter) -> Result<u64> {
    let c = conditions(filter);
    let sql = match c.sql() {
        Some(w) => format!("SELECT count(*) FROM telnet_sessions t WHERE {w}"),
        None => "SELECT count(*) FROM telnet_sessions t".to_owned(),
    };
    let n: i64 = conn.query_row(&sql, c.params().as_slice(), |r| r.get(0))?;
    Ok(unsigned(n))
}

/// A session with its transcript, secrets put back (sensitive: detail route only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelnetDetail {
    pub entry: TelnetEntry,
    pub transcript: Vec<TelnetRun>,
}

/// The session of flow `flow_id`, `None` when unknown.
pub fn session_detail(conn: &Connection, flow_id: i64) -> Result<Option<TelnetDetail>> {
    let sql = format!(
        "SELECT {SELECT}, coalesce(x.transcript, '[]'), coalesce(x.secrets, '[]') FROM {FROM} \
         LEFT JOIN telnet_transcripts x ON x.flow_id = t.flow_id WHERE t.flow_id = ?1"
    );
    let row = conn
        .query_row(&sql, params![flow_id], |r| {
            let transcript: String = r.get(26)?;
            let secrets: String = r.get(27)?;
            Ok((entry(r)?, transcript, secrets))
        })
        .optional()?;
    let Some((entry, transcript, secrets)) = row else {
        return Ok(None);
    };
    let transcript = join_secrets(&transcript, &secrets).map_err(StoreError::from)?;
    Ok(Some(TelnetDetail { entry, transcript }))
}

// ---- statistics --------------------------------------------------------------------------------

/// Counters of the Telnet view (of the sessions overlapping `range` when set).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TelnetStatsRow {
    pub sessions: u64,
    pub clients: u64,
    pub servers: u64,
    /// Sessions where a password was typed.
    pub logins: u64,
    pub accepted: u64,
    pub rejected: u64,
    pub truncated: u64,
}

/// Counters for the view.
pub fn stats(conn: &Connection, range: Option<TimeRange>) -> Result<TelnetStatsRow> {
    let w = where_overlap(range, "first_ts", "last_ts");
    let sql = format!(
        "SELECT count(*), count(DISTINCT client_ip), count(DISTINCT server_ip), \
         coalesce(sum(login_attempts > 0), 0), coalesce(sum(login = 'accepted'), 0), \
         coalesce(sum(login = 'rejected'), 0), coalesce(sum(truncated), 0) \
         FROM telnet_sessions{w}"
    );
    let map = |r: &rusqlite::Row<'_>| {
        Ok(TelnetStatsRow {
            sessions: unsigned(r.get(0)?),
            clients: unsigned(r.get(1)?),
            servers: unsigned(r.get(2)?),
            logins: unsigned(r.get(3)?),
            accepted: unsigned(r.get(4)?),
            rejected: unsigned(r.get(5)?),
            truncated: unsigned(r.get(6)?),
        })
    };
    query_row_ranged(conn, &sql, &[], range, map)
}

#[cfg(test)]
mod tests;
