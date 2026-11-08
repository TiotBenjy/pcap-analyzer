//! TLS tables (migration `0300_tls.sql`): one row per TLS session (TCP flow) with its decoded
//! hellos and certificate chain, certificates deduplicated by SHA-256.
//!
//! # Merge rules
//!
//! A flow is analyzed by exactly one shard, so a session arrives once: its rows are plain
//! inserts (`ON CONFLICT DO NOTHING` guards against a replay). Certificate rows are derived from
//! the DER alone, so whichever session inserts a certificate first writes the same values;
//! `stored` keeps the maximum (a blob written by any shard). Cipher suite names are static.

use std::net::IpAddr;

use rusqlite::types::Value;
use rusqlite::{Connection, OptionalExtension, Row, ToSql, params};

use crate::error::Result;
use crate::query::{Keyset, Page, PageRequest, keyset_page};
use crate::records::{conversion, id_i64};

/// Bits of `tls_sessions.cert_issues` (set over the whole chain).
pub mod cert_issue {
    /// A certificate had expired at the time of the session.
    pub const EXPIRED: u32 = 1;
    /// A certificate was not valid yet at the time of the session.
    pub const NOT_YET_VALID: u32 = 2;
    /// A certificate is self-signed (issuer = subject, outside a CA chain).
    pub const SELF_SIGNED: u32 = 4;
    /// A public key is too short (RSA/DSA below 2048 bits, EC below 224 bits).
    pub const WEAK_KEY: u32 = 8;
}

/// How the handshake ended, as far as the capture shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsOutcome {
    /// Both sides switched to encrypted traffic.
    Complete,
    /// Anything less (no `ServerHello`, alert, capture cut).
    Partial,
}

impl TlsOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Partial => "partial",
        }
    }
}

/// Visibility of the server certificates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertStatus {
    /// Certificates seen in clear (TLS 1.2 and earlier).
    Present,
    /// TLS 1.3: certificates are encrypted, not visible.
    Encrypted,
    /// No certificate message (resumption, anonymous suite, capture cut).
    None,
}

impl CertStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Present => "present",
            Self::Encrypted => "encrypted",
            Self::None => "none",
        }
    }
}

/// First plaintext alert of a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlsAlertRow {
    pub level: u8,
    pub description: u8,
    /// Sent by the server (otherwise by the client).
    pub from_server: bool,
}

/// Decoded `ClientHello` (lists in wire order, GREASE included).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientHelloRow {
    pub legacy_version: u16,
    /// Hex.
    pub random: String,
    /// Hex.
    pub legacy_session_id: String,
    /// A non-empty session ticket was offered (resumption attempt).
    pub session_ticket: bool,
    pub cipher_suites: Vec<u16>,
    pub compressions: Vec<u8>,
    pub extensions: Vec<u16>,
    pub groups: Vec<u16>,
    pub point_formats: Vec<u8>,
    pub signature_algs: Vec<u16>,
    pub supported_versions: Vec<u16>,
    pub key_share_groups: Vec<u16>,
}

/// Decoded `ServerHello`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServerHelloRow {
    pub legacy_version: u16,
    /// Hex.
    pub random: String,
    /// Hex.
    pub legacy_session_id: String,
    pub cipher_suite: u16,
    pub compression: u8,
    pub extensions: Vec<u16>,
    /// `supported_versions` extension (TLS 1.3).
    pub selected_version: Option<u16>,
}

/// An X.509 certificate (every field derived from its DER).
#[allow(clippy::struct_excessive_bools)] // flags of the certificate, stored as columns
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CertificateRow {
    /// Hex SHA-256 of the DER: primary key and blob name.
    pub sha256: String,
    /// Hex SHA-1 of the DER.
    pub sha1: String,
    pub size: u64,
    /// The DER blob was written to `blobs/`.
    pub stored: bool,
    /// The DER parsed as a certificate (otherwise only digests and size are known).
    pub parsed: bool,
    pub subject: Option<String>,
    pub subject_cn: Option<String>,
    pub issuer: Option<String>,
    pub issuer_cn: Option<String>,
    /// Hex.
    pub serial: Option<String>,
    pub not_before: Option<i64>,
    pub not_after: Option<i64>,
    /// Subject alternative names (`DNS:`, `IP:`, `email:`, `URI:` prefixed).
    pub san: Vec<String>,
    pub key_algorithm: Option<String>,
    pub key_bits: Option<u32>,
    pub signature_algorithm: Option<String>,
    pub self_signed: bool,
    pub is_ca: bool,
}

/// Display name of a cipher suite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CipherNameRow {
    pub id: u16,
    pub name: String,
    pub weak: Option<String>,
}

/// One TLS session with everything decoded from its handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsSessionRow {
    /// Flow id (`flows.id`).
    pub id: u64,
    pub ts: i64,
    pub client_ip: IpAddr,
    pub client_port: u16,
    pub server_ip: IpAddr,
    pub server_port: u16,
    pub sni: Option<String>,
    pub offered_version: Option<u16>,
    pub version: Option<u16>,
    pub cipher_suite: Option<u16>,
    pub cipher_name: Option<String>,
    pub cipher_weak: Option<String>,
    pub alpn_offered: Vec<String>,
    pub alpn: Option<String>,
    pub ja3: Option<String>,
    pub ja3_hash: Option<String>,
    pub ja4: Option<String>,
    pub compression: Option<u8>,
    pub resumed: bool,
    pub outcome: TlsOutcome,
    pub alert: Option<TlsAlertRow>,
    pub cert_status: CertStatus,
    /// Bits of [`cert_issue`].
    pub cert_issues: u32,
    pub client_hello: Option<ClientHelloRow>,
    pub server_hello: Option<ServerHelloRow>,
    /// Chain, leaf first.
    pub certificates: Vec<CertificateRow>,
    /// Names of the suites of this session not sent before by the same shard.
    pub cipher_names: Vec<CipherNameRow>,
}

/// JSON text of a list (the store has no direct `serde` dependency, hence the macro).
macro_rules! json {
    ($v:expr) => {
        serde_json::to_string($v)?
    };
}

impl TlsSessionRow {
    /// Approximate heap footprint (writer batch bounds).
    pub fn approx_size(&self) -> usize {
        let cert: usize = self
            .certificates
            .iter()
            .map(|c| {
                256 + c.subject.as_ref().map_or(0, String::len)
                    + c.issuer.as_ref().map_or(0, String::len)
                    + c.san.iter().map(String::len).sum::<usize>()
            })
            .sum();
        1024 + cert + 64 * self.cipher_names.len()
    }

    /// Writes every row of the session, all or nothing (a savepoint inside the writer's
    /// transaction), so that a rejected record leaves no partial session behind.
    pub(crate) fn insert(&self, conn: &Connection) -> Result<()> {
        conn.execute_batch("SAVEPOINT tls_session")?;
        match self.insert_rows(conn) {
            Ok(()) => {
                conn.execute_batch("RELEASE tls_session")?;
                Ok(())
            }
            Err(e) => {
                conn.execute_batch("ROLLBACK TO tls_session; RELEASE tls_session")?;
                Err(e)
            }
        }
    }

    fn insert_rows(&self, conn: &Connection) -> Result<()> {
        let id = id_i64(self.id, "tls_sessions.id")?;
        let leaf = self.certificates.first().map(|c| c.sha256.as_str());
        let inserted = conn
            .prepare_cached(
                "INSERT INTO tls_sessions (id, ts, client_ip, client_port, server_ip, server_port, \
                 sni, offered_version, version, cipher_suite, cipher_name, cipher_weak, \
                 alpn_offered, alpn, ja3, ja3_hash, ja4, compression, resumed, outcome, \
                 alert_level, alert_desc, alert_from, cert_status, cert_count, leaf_sha256, \
                 cert_issues) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, \
                 ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27) \
                 ON CONFLICT (id) DO NOTHING",
            )?
            .execute(params![
                id,
                self.ts,
                self.client_ip.to_string(),
                self.client_port,
                self.server_ip.to_string(),
                self.server_port,
                self.sni,
                self.offered_version,
                self.version,
                self.cipher_suite,
                self.cipher_name,
                self.cipher_weak,
                json!(&self.alpn_offered),
                self.alpn,
                self.ja3,
                self.ja3_hash,
                self.ja4,
                self.compression,
                self.resumed,
                self.outcome.as_str(),
                self.alert.map(|a| a.level),
                self.alert.map(|a| a.description),
                self.alert
                    .map(|a| if a.from_server { "server" } else { "client" }),
                self.cert_status.as_str(),
                i64::try_from(self.certificates.len()).unwrap_or(i64::MAX),
                leaf,
                self.cert_issues,
            ])?;
        if inserted == 0 {
            return Ok(()); // replayed session: everything below is already there
        }
        if let Some(ch) = &self.client_hello {
            ch.insert(conn, id)?;
        }
        if let Some(sh) = &self.server_hello {
            sh.insert(conn, id)?;
        }
        for (position, c) in self.certificates.iter().enumerate() {
            c.insert(conn)?;
            conn.prepare_cached(
                "INSERT OR IGNORE INTO tls_session_certificates (session_id, position, sha256) \
                 VALUES (?1, ?2, ?3)",
            )?
            .execute(params![
                id,
                i64::try_from(position).unwrap_or(i64::MAX),
                c.sha256
            ])?;
        }
        for n in &self.cipher_names {
            conn.prepare_cached(
                "INSERT INTO tls_cipher_suites (id, name, weak) VALUES (?1, ?2, ?3) \
                 ON CONFLICT (id) DO NOTHING",
            )?
            .execute(params![n.id, n.name, n.weak])?;
        }
        Ok(())
    }
}

impl ClientHelloRow {
    fn insert(&self, conn: &Connection, id: i64) -> Result<()> {
        let ch = self;
        conn.prepare_cached(
            "INSERT OR IGNORE INTO tls_client_hellos (session_id, legacy_version, random, \
             session_ticket, legacy_session_id, cipher_suites, compressions, extensions, \
             groups, point_formats, signature_algs, supported_versions, key_share_groups) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        )?
        .execute(params![
            id,
            ch.legacy_version,
            ch.random,
            ch.session_ticket,
            ch.legacy_session_id,
            json!(&ch.cipher_suites),
            json!(&ch.compressions),
            json!(&ch.extensions),
            json!(&ch.groups),
            json!(&ch.point_formats),
            json!(&ch.signature_algs),
            json!(&ch.supported_versions),
            json!(&ch.key_share_groups),
        ])?;
        Ok(())
    }
}

impl ServerHelloRow {
    fn insert(&self, conn: &Connection, id: i64) -> Result<()> {
        let sh = self;
        conn.prepare_cached(
            "INSERT OR IGNORE INTO tls_server_hellos (session_id, legacy_version, random, \
             legacy_session_id, cipher_suite, compression, extensions, selected_version) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        )?
        .execute(params![
            id,
            sh.legacy_version,
            sh.random,
            sh.legacy_session_id,
            sh.cipher_suite,
            sh.compression,
            json!(&sh.extensions),
            sh.selected_version,
        ])?;
        Ok(())
    }
}

impl CertificateRow {
    fn insert(&self, conn: &Connection) -> Result<()> {
        conn.prepare_cached(
            "INSERT INTO tls_certificates (sha256, sha1, size, stored, parsed, subject, \
             subject_cn, issuer, issuer_cn, serial, not_before, not_after, san, key_algorithm, \
             key_bits, signature_algorithm, self_signed, is_ca) VALUES (?1, ?2, ?3, ?4, ?5, ?6, \
             ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18) \
             ON CONFLICT (sha256) DO UPDATE SET stored = max(stored, excluded.stored)",
        )?
        .execute(params![
            self.sha256,
            self.sha1,
            i64::try_from(self.size).unwrap_or(i64::MAX),
            self.stored,
            self.parsed,
            self.subject,
            self.subject_cn,
            self.issuer,
            self.issuer_cn,
            self.serial,
            self.not_before,
            self.not_after,
            json!(&self.san),
            self.key_algorithm,
            self.key_bits,
            self.signature_algorithm,
            self.self_signed,
            self.is_ca,
        ])?;
        Ok(())
    }

    fn from_row(r: &Row<'_>, at: usize) -> rusqlite::Result<Self> {
        let san: String = r.get(at + 12)?;
        Ok(Self {
            sha256: r.get(at)?,
            sha1: r.get(at + 1)?,
            size: r.get(at + 2)?,
            stored: r.get(at + 3)?,
            parsed: r.get(at + 4)?,
            subject: r.get(at + 5)?,
            subject_cn: r.get(at + 6)?,
            issuer: r.get(at + 7)?,
            issuer_cn: r.get(at + 8)?,
            serial: r.get(at + 9)?,
            not_before: r.get(at + 10)?,
            not_after: r.get(at + 11)?,
            san: serde_json::from_str(&san).map_err(|e| conversion(at + 12, e))?,
            key_algorithm: r.get(at + 13)?,
            key_bits: r.get(at + 14)?,
            signature_algorithm: r.get(at + 15)?,
            self_signed: r.get(at + 16)?,
            is_ca: r.get(at + 17)?,
        })
    }
}

/// Columns of `tls_certificates` (alias `c`) in the order of [`CertificateRow::from_row`].
const CERT_COLUMNS: &str = "c.sha256, c.sha1, c.size, c.stored, c.parsed, c.subject, \
    c.subject_cn, c.issuer, c.issuer_cn, c.serial, c.not_before, c.not_after, c.san, \
    c.key_algorithm, c.key_bits, c.signature_algorithm, c.self_signed, c.is_ca";

// ------------------------------------------------------------------------------------------
// Read side
// ------------------------------------------------------------------------------------------

/// A row of the sessions list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsSessionEntry {
    pub id: i64,
    pub ts: i64,
    pub client_ip: String,
    pub client_port: u16,
    pub server_ip: String,
    pub server_port: u16,
    pub sni: Option<String>,
    pub offered_version: Option<u16>,
    pub version: Option<u16>,
    pub cipher_suite: Option<u16>,
    pub cipher_name: Option<String>,
    pub cipher_weak: Option<String>,
    pub alpn_offered: Vec<String>,
    pub alpn: Option<String>,
    pub ja3: Option<String>,
    pub ja3_hash: Option<String>,
    pub ja4: Option<String>,
    pub compression: Option<u8>,
    pub resumed: bool,
    pub outcome: String,
    pub alert: Option<TlsAlertRow>,
    pub cert_status: String,
    pub cert_count: u32,
    pub leaf_sha256: Option<String>,
    pub leaf_subject_cn: Option<String>,
    pub cert_issues: u32,
}

const SESSION_COLUMNS: &str = "s.id, s.ts, s.client_ip, s.client_port, s.server_ip, \
    s.server_port, s.sni, s.offered_version, s.version, s.cipher_suite, s.cipher_name, \
    s.cipher_weak, s.alpn_offered, s.alpn, s.ja3, s.ja3_hash, s.ja4, s.compression, s.resumed, \
    s.outcome, s.alert_level, s.alert_desc, s.alert_from, s.cert_status, s.cert_count, \
    s.leaf_sha256, c.subject_cn, s.cert_issues";

const SESSION_FROM: &str =
    "tls_sessions AS s LEFT JOIN tls_certificates AS c ON c.sha256 = s.leaf_sha256";

impl TlsSessionEntry {
    fn from_row(r: &Row<'_>) -> rusqlite::Result<Self> {
        let alpn: String = r.get(12)?;
        let level: Option<u8> = r.get(20)?;
        let desc: Option<u8> = r.get(21)?;
        let from: Option<String> = r.get(22)?;
        Ok(Self {
            id: r.get(0)?,
            ts: r.get(1)?,
            client_ip: r.get(2)?,
            client_port: r.get(3)?,
            server_ip: r.get(4)?,
            server_port: r.get(5)?,
            sni: r.get(6)?,
            offered_version: r.get(7)?,
            version: r.get(8)?,
            cipher_suite: r.get(9)?,
            cipher_name: r.get(10)?,
            cipher_weak: r.get(11)?,
            alpn_offered: serde_json::from_str(&alpn).map_err(|e| conversion(12, e))?,
            alpn: r.get(13)?,
            ja3: r.get(14)?,
            ja3_hash: r.get(15)?,
            ja4: r.get(16)?,
            compression: r.get(17)?,
            resumed: r.get(18)?,
            outcome: r.get(19)?,
            alert: level.zip(desc).map(|(level, description)| TlsAlertRow {
                level,
                description,
                from_server: from.as_deref() == Some("server"),
            }),
            cert_status: r.get(23)?,
            cert_count: r.get(24)?,
            leaf_sha256: r.get(25)?,
            leaf_subject_cn: r.get(26)?,
            cert_issues: r.get(27)?,
        })
    }
}

/// Filters of the sessions list (all optional, combined with AND).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TlsSessionFilter {
    /// Negotiated version.
    pub version: Option<u16>,
    /// Negotiated cipher suite.
    pub suite: Option<u16>,
    /// Substring of the SNI or of the server address (case-insensitive for ASCII).
    pub q: Option<String>,
    /// Only sessions with a weak negotiated suite.
    pub weak_only: bool,
    /// Only sessions whose chain has an issue (expired, self-signed...).
    pub cert_issues_only: bool,
}

/// One static condition with NULL-able parameters, so that the SQL text never depends on input.
const SESSION_FILTER: &str = "(?1 IS NULL OR s.version = ?1) \
    AND (?2 IS NULL OR s.cipher_suite = ?2) \
    AND (?3 IS NULL OR s.sni LIKE ?3 ESCAPE '\\' OR s.server_ip LIKE ?3 ESCAPE '\\') \
    AND (?4 = 0 OR s.cipher_weak IS NOT NULL) \
    AND (?5 = 0 OR s.cert_issues != 0)";

/// `%q%` with LIKE wildcards escaped.
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

fn filter_params(f: &TlsSessionFilter) -> [Value; 5] {
    [
        f.version
            .map_or(Value::Null, |v| Value::Integer(i64::from(v))),
        f.suite
            .map_or(Value::Null, |v| Value::Integer(i64::from(v))),
        like_pattern(f.q.as_deref()).map_or(Value::Null, Value::Text),
        Value::Integer(i64::from(f.weak_only)),
        Value::Integer(i64::from(f.cert_issues_only)),
    ]
}

/// One page of sessions by time (`descending`: newest first).
pub fn sessions_page(
    conn: &Connection,
    filter: &TlsSessionFilter,
    descending: bool,
    request: &PageRequest,
) -> Result<Page<TlsSessionEntry>> {
    let query = Keyset {
        from: SESSION_FROM,
        select: SESSION_COLUMNS,
        sort: "s.ts",
        tiebreak: "s.id",
        descending,
        filter: Some(SESSION_FILTER),
    };
    let values = filter_params(filter);
    let params: Vec<&dyn ToSql> = values.iter().map(|v| v as &dyn ToSql).collect();
    keyset_page(conn, &query, &params, request, TlsSessionEntry::from_row)
}

/// Number of sessions matching `filter`.
pub fn count_sessions(conn: &Connection, filter: &TlsSessionFilter) -> Result<u64> {
    let values = filter_params(filter);
    let sql = format!("SELECT count(*) FROM tls_sessions AS s WHERE {SESSION_FILTER}");
    let n: i64 = conn.query_row(&sql, rusqlite::params_from_iter(values.iter()), |r| {
        r.get(0)
    })?;
    Ok(u64::try_from(n).unwrap_or(0))
}

/// Count of one value of a grouped column.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuiteCount {
    pub suite: u16,
    pub name: Option<String>,
    pub weak: Option<String>,
    pub count: u64,
}

/// Aggregates of the TLS view.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TlsStatsRows {
    pub sessions: u64,
    pub weak_sessions: u64,
    pub cert_issue_sessions: u64,
    pub encrypted_cert_sessions: u64,
    pub certificates: u64,
    /// `(negotiated version or NULL, count)`, most frequent first.
    pub versions: Vec<(Option<u16>, u64)>,
    /// Negotiated suites, most frequent first (sessions without `ServerHello` excluded).
    pub suites: Vec<SuiteCount>,
    /// `(version, suite, count)` for every pair (sessions without `ServerHello` excluded).
    pub pairs: Vec<(Option<u16>, u16, u64)>,
    /// `(sni, count)`, most frequent first, at most `top` rows.
    pub sni: Vec<(String, u64)>,
}

fn unsigned(v: i64) -> u64 {
    u64::try_from(v).unwrap_or(0)
}

/// Aggregates for the charts: grouped in SQL (the result is bounded by the distinct values).
pub fn stats(conn: &Connection, top_sni: u32) -> Result<TlsStatsRows> {
    let (sessions, weak, issues, encrypted): (i64, i64, i64, i64) = conn.query_row(
        "SELECT count(*), coalesce(sum(cipher_weak IS NOT NULL), 0), \
         coalesce(sum(cert_issues != 0), 0), coalesce(sum(cert_status = 'encrypted'), 0) \
         FROM tls_sessions",
        [],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
    )?;
    let certificates: i64 =
        conn.query_row("SELECT count(*) FROM tls_certificates", [], |r| r.get(0))?;

    let mut stmt = conn.prepare(
        "SELECT version, count(*) AS n FROM tls_sessions GROUP BY version \
         ORDER BY n DESC, version",
    )?;
    let versions = stmt
        .query_map([], |r| Ok((r.get(0)?, unsigned(r.get(1)?))))?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    let mut stmt = conn.prepare(
        "SELECT cipher_suite, max(cipher_name), max(cipher_weak), count(*) AS n FROM tls_sessions \
         WHERE cipher_suite IS NOT NULL GROUP BY cipher_suite ORDER BY n DESC, cipher_suite",
    )?;
    let suites = stmt
        .query_map([], |r| {
            Ok(SuiteCount {
                suite: r.get(0)?,
                name: r.get(1)?,
                weak: r.get(2)?,
                count: unsigned(r.get(3)?),
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    let mut stmt = conn.prepare(
        "SELECT version, cipher_suite, count(*) FROM tls_sessions \
         WHERE cipher_suite IS NOT NULL GROUP BY version, cipher_suite",
    )?;
    let pairs = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, unsigned(r.get(2)?))))?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    let mut stmt = conn.prepare(
        "SELECT sni, count(*) AS n FROM tls_sessions WHERE sni IS NOT NULL \
         GROUP BY sni ORDER BY n DESC, sni LIMIT ?1",
    )?;
    let sni = stmt
        .query_map([top_sni], |r| Ok((r.get(0)?, unsigned(r.get(1)?))))?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    Ok(TlsStatsRows {
        sessions: unsigned(sessions),
        weak_sessions: unsigned(weak),
        cert_issue_sessions: unsigned(issues),
        encrypted_cert_sessions: unsigned(encrypted),
        certificates: unsigned(certificates),
        versions,
        suites,
        pairs,
        sni,
    })
}

/// A session with its decoded hellos and chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsSessionDetail {
    pub session: TlsSessionEntry,
    pub client_hello: Option<ClientHelloRow>,
    pub server_hello: Option<ServerHelloRow>,
    /// Chain, leaf first.
    pub certificates: Vec<CertificateRow>,
    /// Names of the suites offered or selected (only those known).
    pub cipher_names: Vec<CipherNameRow>,
}

/// JSON list column.
macro_rules! json_col {
    ($r:expr, $i:expr) => {{
        let s: String = $r.get($i)?;
        serde_json::from_str(&s).map_err(|e| conversion($i, e))?
    }};
}

/// Everything about one session, `None` when unknown.
pub fn session_detail(conn: &Connection, id: i64) -> Result<Option<TlsSessionDetail>> {
    let sql = format!("SELECT {SESSION_COLUMNS} FROM {SESSION_FROM} WHERE s.id = ?1");
    let Some(session) = conn
        .query_row(&sql, [id], TlsSessionEntry::from_row)
        .optional()?
    else {
        return Ok(None);
    };
    let client_hello = conn
        .query_row(
            "SELECT legacy_version, random, legacy_session_id, session_ticket, cipher_suites, \
             compressions, extensions, groups, point_formats, signature_algs, \
             supported_versions, key_share_groups FROM tls_client_hellos WHERE session_id = ?1",
            [id],
            |r| {
                Ok(ClientHelloRow {
                    legacy_version: r.get(0)?,
                    random: r.get(1)?,
                    legacy_session_id: r.get(2)?,
                    session_ticket: r.get(3)?,
                    cipher_suites: json_col!(r, 4),
                    compressions: json_col!(r, 5),
                    extensions: json_col!(r, 6),
                    groups: json_col!(r, 7),
                    point_formats: json_col!(r, 8),
                    signature_algs: json_col!(r, 9),
                    supported_versions: json_col!(r, 10),
                    key_share_groups: json_col!(r, 11),
                })
            },
        )
        .optional()?;
    let server_hello = conn
        .query_row(
            "SELECT legacy_version, random, legacy_session_id, cipher_suite, compression, \
             extensions, selected_version FROM tls_server_hellos WHERE session_id = ?1",
            [id],
            |r| {
                Ok(ServerHelloRow {
                    legacy_version: r.get(0)?,
                    random: r.get(1)?,
                    legacy_session_id: r.get(2)?,
                    cipher_suite: r.get(3)?,
                    compression: r.get(4)?,
                    extensions: json_col!(r, 5),
                    selected_version: r.get(6)?,
                })
            },
        )
        .optional()?;
    let sql = format!(
        "SELECT {CERT_COLUMNS} FROM tls_session_certificates AS sc \
         JOIN tls_certificates AS c ON c.sha256 = sc.sha256 \
         WHERE sc.session_id = ?1 ORDER BY sc.position"
    );
    let mut stmt = conn.prepare(&sql)?;
    let certificates = stmt
        .query_map([id], |r| CertificateRow::from_row(r, 0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    let mut ids: Vec<u16> = client_hello
        .as_ref()
        .map(|c| c.cipher_suites.clone())
        .unwrap_or_default();
    ids.extend(session.cipher_suite);
    ids.sort_unstable();
    ids.dedup();
    let mut stmt = conn.prepare_cached("SELECT name, weak FROM tls_cipher_suites WHERE id = ?1")?;
    let mut cipher_names = Vec::new();
    for suite in ids {
        if let Some((name, weak)) = stmt
            .query_row([suite], |r| Ok((r.get(0)?, r.get(1)?)))
            .optional()?
        {
            cipher_names.push(CipherNameRow {
                id: suite,
                name,
                weak,
            });
        }
    }
    Ok(Some(TlsSessionDetail {
        session,
        client_hello,
        server_hello,
        certificates,
        cipher_names,
    }))
}

/// A row of the deduplicated certificates list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateEntry {
    pub certificate: CertificateRow,
    /// Sessions whose chain contains it.
    pub sessions: u64,
}

/// Filters of the certificates list.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CertificateFilter {
    /// Substring of the subject, issuer or SAN.
    pub q: Option<String>,
    /// Only expired (at `capture_end`), not yet valid (at `capture_start`) or self-signed ones
    /// (CA roots excluded).
    pub problems_only: bool,
    /// Capture period (ns) used by `problems_only`.
    pub capture_start: Option<i64>,
    pub capture_end: Option<i64>,
}

const CERT_FILTER: &str = "(?1 IS NULL OR c.subject LIKE ?1 ESCAPE '\\' \
    OR c.issuer LIKE ?1 ESCAPE '\\' OR c.san LIKE ?1 ESCAPE '\\') \
    AND (?2 = 0 OR (c.self_signed = 1 AND c.is_ca = 0) OR c.not_after < ?3 OR c.not_before > ?4)";

/// One page of certificates by subject CN (case-insensitive for ASCII).
pub fn certificates_page(
    conn: &Connection,
    filter: &CertificateFilter,
    request: &PageRequest,
) -> Result<Page<CertificateEntry>> {
    let query = Keyset {
        from: "tls_certificates AS c",
        select: "c.sha256, c.sha1, c.size, c.stored, c.parsed, c.subject, c.subject_cn, \
                 c.issuer, c.issuer_cn, c.serial, c.not_before, c.not_after, c.san, \
                 c.key_algorithm, c.key_bits, c.signature_algorithm, c.self_signed, c.is_ca, \
                 (SELECT count(*) FROM tls_session_certificates AS sc WHERE sc.sha256 = c.sha256)",
        sort: "lower(coalesce(c.subject_cn, ''))",
        tiebreak: "c.sha256",
        descending: false,
        filter: Some(CERT_FILTER),
    };
    let values = cert_params(filter);
    let params: Vec<&dyn ToSql> = values.iter().map(|v| v as &dyn ToSql).collect();
    keyset_page(conn, &query, &params, request, |r| {
        Ok(CertificateEntry {
            certificate: CertificateRow::from_row(r, 0)?,
            sessions: unsigned(r.get(18)?),
        })
    })
}

fn cert_params(f: &CertificateFilter) -> [Value; 4] {
    [
        like_pattern(f.q.as_deref()).map_or(Value::Null, Value::Text),
        Value::Integer(i64::from(f.problems_only)),
        Value::Integer(f.capture_end.unwrap_or(i64::MIN)),
        Value::Integer(f.capture_start.unwrap_or(i64::MAX)),
    ]
}

/// Number of certificates matching `filter`.
pub fn count_certificates(conn: &Connection, filter: &CertificateFilter) -> Result<u64> {
    let values = cert_params(filter);
    let sql = format!("SELECT count(*) FROM tls_certificates AS c WHERE {CERT_FILTER}");
    let n: i64 = conn.query_row(&sql, rusqlite::params_from_iter(values.iter()), |r| {
        r.get(0)
    })?;
    Ok(unsigned(n))
}

/// One certificate by hex SHA-256.
pub fn certificate(conn: &Connection, sha256: &str) -> Result<Option<CertificateRow>> {
    let sql = format!("SELECT {CERT_COLUMNS} FROM tls_certificates AS c WHERE c.sha256 = ?1");
    Ok(conn
        .query_row(&sql, [sha256], |r| CertificateRow::from_row(r, 0))
        .optional()?)
}

#[cfg(test)]
mod tests;
