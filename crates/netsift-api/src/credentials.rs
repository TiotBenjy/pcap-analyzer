//! Credentials view routes (ADR-019). The list, the statistics and the paths never carry a
//! secret; the secret and the hashcat line of an entry are served by its detail route, and in
//! bulk by the export route, both on explicit user action. Nothing here is logged.
//!
//! | Method | Path | Response |
//! |---|---|---|
//! | GET | `/sessions/{id}/credentials` | [`Page`](crate::contract::Page)`<`[`CredentialInfo`]`>` |
//! | GET | `/sessions/{id}/credentials/stats` | [`CredentialStats`] |
//! | GET | `/sessions/{id}/credentials/paths` | [`CredentialPaths`] |
//! | GET | `/sessions/{id}/credentials/export` | CSV or hashcat file (attachment) |
//! | GET | `/sessions/{id}/credentials/{entry}` | [`CredentialDetail`] |
//!
//! Filters (list and export): `protocol=`, `state=` (`plaintext`, `recoverable`,
//! `metadata-only`), `mode=` (hashcat mode). Export: `format=csv|hashcat` (hashcat needs
//! `mode`), optional `ids=` (comma-separated entry ids, at most [`MAX_IDS`]); without `ids`,
//! every entry matching the filters. An export is never truncated: above
//! `netsift_store::credentials::MAX_EXPORT` matching entries it is refused (400).
//! Entry ids are random (they never derive from the secret, ADR-019).
//! A session upgraded after its import is not analyzed (`analyzed: false`), ADR-013.

use std::fmt::Write as _;
use std::sync::Arc;

use axum::extract::{Path as UrlPath, State};
use axum::http::{HeaderValue, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use netsift_store::PageRequest;
use netsift_store::credentials::{
    self as store, CredentialEnd, CredentialEntry, CredentialFilter, CredentialSecret,
};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::contract::Page;
use crate::endpoint::Endpoint;
use crate::extract::ApiQuery;
use crate::overview::open_ready;
use crate::sessions::parse_id;
use crate::{ApiError, AppState, blocking, convert};

/// Most entry ids accepted by one export (`ids=`).
pub const MAX_IDS: usize = 500;
/// Most paths returned by `/credentials/paths` (default 12).
const MAX_PATHS: u32 = 50;
const DEFAULT_PATHS: u32 = 12;

pub(crate) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/sessions/{id}/credentials", get(list))
        .route("/sessions/{id}/credentials/stats", get(stats))
        .route("/sessions/{id}/credentials/paths", get(paths))
        .route("/sessions/{id}/credentials/export", get(export))
        .route("/sessions/{id}/credentials/{entry}", get(detail))
}

/// One side of a credential exchange.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct CredentialEndpoint {
    pub endpoint: Endpoint,
    pub port: Option<u16>,
}

fn endpoint(e: Option<CredentialEnd>) -> Option<CredentialEndpoint> {
    e.map(|e| CredentialEndpoint {
        endpoint: Endpoint::new(e.ip, e.info),
        port: e.port,
    })
}

/// One non-secret key/value of an entry (mechanism, result, SMB dialect...).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct CredentialDetailItem {
    pub key: String,
    pub value: String,
}

/// One credential, without its secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct CredentialInfo {
    /// Entry identifier: 32 random hex digits, never derived from the secret.
    pub id: String,
    /// `smb`, `http`, `ftp`, `smtp`, `pop3`, `imap`, `ldap`, `snmp`.
    pub protocol: String,
    /// `ntlmv1`, `ntlmv2`, `ntlm`, `http-basic`, `http-form`, `ftp`, `mail`, `ldap`, `snmp`.
    pub kind: String,
    /// `plaintext`, `recoverable` or `metadata-only`.
    pub secret_state: String,
    /// `flows.id` of the first observation, as a string (ids can exceed 2^53).
    pub flow_id: Option<String>,
    pub client: Option<CredentialEndpoint>,
    pub server: Option<CredentialEndpoint>,
    pub username: Option<String>,
    pub domain: Option<String>,
    pub workstation: Option<String>,
    /// A secret or a hashcat line is available from the detail route.
    pub has_secret: bool,
    pub hashcat_mode: Option<u32>,
    pub details: Vec<CredentialDetailItem>,
    /// Observations folded into this entry.
    pub seen_count: u64,
    pub first_ts_us: i64,
    pub last_ts_us: i64,
}

fn info(e: CredentialEntry) -> CredentialInfo {
    CredentialInfo {
        id: e.id,
        protocol: e.protocol,
        kind: e.kind,
        secret_state: e.secret_state,
        flow_id: e.flow_id.map(|f| f.to_string()),
        client: endpoint(e.client),
        server: endpoint(e.server),
        username: e.username,
        domain: e.domain,
        workstation: e.workstation,
        has_secret: e.has_secret,
        hashcat_mode: e.hashcat_mode,
        details: e
            .details
            .into_iter()
            .map(|(key, value)| CredentialDetailItem { key, value })
            .collect(),
        seen_count: e.seen_count,
        first_ts_us: convert::us(e.first_ts),
        last_ts_us: convert::us(e.last_ts),
    }
}

/// `GET /credentials/{entry}`: one entry with its sensitive fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct CredentialDetail {
    pub info: CredentialInfo,
    /// Plain-text secret (sensitive: masked by default in the UI).
    pub secret: Option<String>,
    /// Offline-recovery line for `hashcat_mode` (sensitive: masked by default in the UI).
    pub hashcat_line: Option<String>,
}

/// Entries carrying a hashcat line for one mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct HashcatModeCount {
    pub mode: u32,
    pub count: u64,
}

/// Entries of one protocol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct ProtocolCount {
    pub protocol: String,
    pub count: u64,
}

/// `GET /credentials/stats`: figures of the summary band and of the filters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct CredentialStats {
    /// False for a session imported before this view existed (not analyzed, re-import it).
    pub analyzed: bool,
    pub total: u64,
    pub plaintext: u64,
    pub recoverable: u64,
    pub metadata_only: u64,
    /// Exportable handshake captures (Wi-Fi EAPOL, phase 5): always 0 for now.
    pub handshakes: u64,
    pub hashcat_modes: Vec<HashcatModeCount>,
    pub protocols: Vec<ProtocolCount>,
}

/// One aggregated client -> protocol -> server path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct CredentialPath {
    pub client: Option<CredentialEndpoint>,
    pub protocol: String,
    pub server: Option<CredentialEndpoint>,
    /// Distinct credentials.
    pub entries: u64,
    /// Observations.
    pub seen: u64,
    /// Entries with a plain-text secret.
    pub plaintext: u64,
}

/// `GET /credentials/paths`: the paths with the most entries, and how many are left out.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct CredentialPaths {
    pub paths: Vec<CredentialPath>,
    pub others: u64,
}

#[derive(Debug, Default, Deserialize)]
struct ListQuery {
    limit: Option<u32>,
    cursor: Option<String>,
    protocol: Option<String>,
    state: Option<String>,
    mode: Option<u32>,
}

#[derive(Debug, Default, Deserialize)]
struct PathsQuery {
    limit: Option<u32>,
}

#[derive(Debug, Default, Deserialize)]
struct ExportQuery {
    format: Option<String>,
    protocol: Option<String>,
    state: Option<String>,
    mode: Option<u32>,
    ids: Option<String>,
}

const STATES: [&str; 3] = ["plaintext", "recoverable", "metadata-only"];

fn filter(
    protocol: Option<String>,
    state: Option<String>,
    mode: Option<u32>,
) -> Result<CredentialFilter, ApiError> {
    if let Some(s) = &state
        && !STATES.contains(&s.as_str())
    {
        return Err(ApiError::BadRequest(format!("unknown state {s:?}")));
    }
    if let Some(p) = &protocol
        && (p.is_empty()
            || p.len() > 16
            || !p
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()))
    {
        return Err(ApiError::BadRequest("invalid protocol".to_owned()));
    }
    Ok(CredentialFilter {
        protocol,
        secret_state: state,
        hashcat_mode: mode,
    })
}

/// An entry id: 32 lower-case hex digits.
fn is_entry_id(s: &str) -> bool {
    s.len() == 32
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

async fn list(
    State(state): State<Arc<AppState>>,
    UrlPath(id): UrlPath<String>,
    ApiQuery(query): ApiQuery<ListQuery>,
) -> Result<Json<Page<CredentialInfo>>, ApiError> {
    let id = parse_id(&id)?;
    let f = filter(query.protocol, query.state, query.mode)?;
    let request = PageRequest {
        limit: query.limit.unwrap_or(0),
        cursor: query.cursor,
    };
    blocking(&state, move |s| {
        let (_, session) = open_ready(s, &id)?;
        let conn = session.conn();
        let page = store::page(conn, &f, &request)?;
        Ok(Page {
            items: page.items.into_iter().map(info).collect(),
            next_cursor: page.next_cursor,
            total_estimate: Some(store::count(conn, &f)?),
        })
    })
    .await
    .map(Json)
}

async fn stats(
    State(state): State<Arc<AppState>>,
    UrlPath(id): UrlPath<String>,
) -> Result<Json<CredentialStats>, ApiError> {
    let id = parse_id(&id)?;
    blocking(&state, move |s| {
        let (_, session) = open_ready(s, &id)?;
        let conn = session.conn();
        let analyzed = netsift_store::traffic::count_rows(conn, "credentials")?.is_some();
        let st = store::stats(conn)?;
        Ok(CredentialStats {
            analyzed,
            total: st.total,
            plaintext: st.plaintext,
            recoverable: st.recoverable,
            metadata_only: st.metadata_only,
            handshakes: 0,
            hashcat_modes: st
                .hashcat_modes
                .into_iter()
                .map(|(mode, count)| HashcatModeCount { mode, count })
                .collect(),
            protocols: st
                .protocols
                .into_iter()
                .map(|(protocol, count)| ProtocolCount { protocol, count })
                .collect(),
        })
    })
    .await
    .map(Json)
}

async fn paths(
    State(state): State<Arc<AppState>>,
    UrlPath(id): UrlPath<String>,
    ApiQuery(query): ApiQuery<PathsQuery>,
) -> Result<Json<CredentialPaths>, ApiError> {
    let id = parse_id(&id)?;
    let limit = query.limit.unwrap_or(DEFAULT_PATHS).clamp(1, MAX_PATHS);
    blocking(&state, move |s| {
        let (_, session) = open_ready(s, &id)?;
        let (found, others) = store::paths(session.conn(), limit)?;
        Ok(CredentialPaths {
            paths: found
                .into_iter()
                .map(|p| CredentialPath {
                    client: endpoint(p.client),
                    protocol: p.protocol,
                    server: endpoint(p.server),
                    entries: p.entries,
                    seen: p.seen,
                    plaintext: p.plaintext,
                })
                .collect(),
            others,
        })
    })
    .await
    .map(Json)
}

async fn detail(
    State(state): State<Arc<AppState>>,
    UrlPath((id, entry)): UrlPath<(String, String)>,
) -> Result<Json<CredentialDetail>, ApiError> {
    let id = parse_id(&id)?;
    if !is_entry_id(&entry) {
        return Err(ApiError::NotFound);
    }
    blocking(&state, move |s| {
        let (_, session) = open_ready(s, &id)?;
        let found = store::detail(session.conn(), &entry)?.ok_or(ApiError::NotFound)?;
        Ok(secret_detail(found))
    })
    .await
    .map(Json)
}

fn secret_detail(c: CredentialSecret) -> CredentialDetail {
    CredentialDetail {
        info: info(c.entry),
        secret: c.secret,
        hashcat_line: c.hashcat_line,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Format {
    Csv,
    Hashcat,
}

async fn export(
    State(state): State<Arc<AppState>>,
    UrlPath(id): UrlPath<String>,
    ApiQuery(query): ApiQuery<ExportQuery>,
) -> Result<Response, ApiError> {
    let id = parse_id(&id)?;
    let format = match query.format.as_deref() {
        None | Some("csv") => Format::Csv,
        Some("hashcat") => Format::Hashcat,
        Some(other) => return Err(ApiError::BadRequest(format!("unknown format {other:?}"))),
    };
    if format == Format::Hashcat && query.mode.is_none() {
        return Err(ApiError::BadRequest(
            "a hashcat export needs a mode (one mode per file)".to_owned(),
        ));
    }
    let ids: Vec<String> = query
        .ids
        .as_deref()
        .map(|raw| {
            raw.split(',')
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    if ids.len() > MAX_IDS {
        return Err(ApiError::BadRequest(format!("at most {MAX_IDS} ids")));
    }
    if !ids.iter().all(|i| is_entry_id(i)) {
        return Err(ApiError::BadRequest("invalid id".to_owned()));
    }
    let f = filter(query.protocol, query.state, query.mode)?;
    let (body, name) = blocking(&state, move |s| {
        let (_, session) = open_ready(s, &id)?;
        if ids.is_empty() && store::count(session.conn(), &f)? > u64::from(store::MAX_EXPORT) {
            return Err(ApiError::BadRequest(format!(
                "more than {} entries match: narrow the filters",
                store::MAX_EXPORT
            )));
        }
        let rows = store::export(session.conn(), &f, &ids)?;
        let short = id.to_string().chars().take(8).collect::<String>();
        Ok(match format {
            Format::Csv => (csv(&rows), format!("credentials-{short}.csv")),
            Format::Hashcat => {
                let mode = f.hashcat_mode.unwrap_or_default();
                (
                    hashcat(&rows, mode),
                    format!("credentials-{short}-hashcat-{mode}.txt"),
                )
            }
        })
    })
    .await?;
    let content_type = match format {
        Format::Csv => "text/csv; charset=utf-8",
        Format::Hashcat => "text/plain; charset=utf-8",
    };
    Ok(attachment(body, content_type, &name))
}

/// A sensitive download: never cached, never rendered by the webview.
fn attachment(body: String, content_type: &'static str, name: &str) -> Response {
    let mut res = body.into_response();
    let headers = res.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    if let Ok(v) = HeaderValue::from_str(&format!("attachment; filename=\"{name}\"")) {
        headers.insert(header::CONTENT_DISPOSITION, v);
    }
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("sandbox"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res
}

/// One hashcat line per entry of `mode` (entries without a line are skipped).
fn hashcat(rows: &[CredentialSecret], mode: u32) -> String {
    let mut out = String::new();
    for r in rows {
        if r.entry.hashcat_mode == Some(mode)
            && let Some(line) = &r.hashcat_line
        {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

/// A CSV cell (RFC 4180 quoting). A cell starting with `=`, `+`, `-`, `@`, tab or carriage
/// return gets a leading `'`, so that a spreadsheet never evaluates text taken from a capture.
fn cell(value: &str) -> String {
    let guarded = if value.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{value}")
    } else {
        value.to_owned()
    };
    if guarded.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", guarded.replace('"', "\"\""))
    } else {
        guarded
    }
}

fn end_text(e: Option<&CredentialEnd>) -> String {
    e.map_or_else(String::new, |e| match (e.ip, e.port) {
        (std::net::IpAddr::V6(ip), Some(port)) => format!("[{ip}]:{port}"),
        (ip, Some(port)) => format!("{ip}:{port}"),
        (ip, None) => ip.to_string(),
    })
}

fn csv(rows: &[CredentialSecret]) -> String {
    let mut out = String::from(
        "first_seen,last_seen,protocol,kind,client,server,username,domain,workstation,\
         secret_state,secret,hashcat_mode,hashcat_line,seen_count,details\r\n",
    );
    for r in rows {
        let e = &r.entry;
        let opt = |o: &Option<String>| o.clone().unwrap_or_default();
        let details: Vec<String> = e.details.iter().map(|(k, v)| format!("{k}={v}")).collect();
        let cells = [
            rfc3339(e.first_ts),
            rfc3339(e.last_ts),
            e.protocol.clone(),
            e.kind.clone(),
            end_text(e.client.as_ref()),
            end_text(e.server.as_ref()),
            opt(&e.username),
            opt(&e.domain),
            opt(&e.workstation),
            e.secret_state.clone(),
            opt(&r.secret),
            e.hashcat_mode.map(|m| m.to_string()).unwrap_or_default(),
            opt(&r.hashcat_line),
            e.seen_count.to_string(),
            details.join("; "),
        ];
        let line: Vec<String> = cells.iter().map(|c| cell(c)).collect();
        let _ = write!(out, "{}\r\n", line.join(","));
    }
    out
}

/// UTC date and time of a nanosecond timestamp (`2023-11-14T22:13:20.000000Z`).
fn rfc3339(ns: i64) -> String {
    let secs = ns.div_euclid(1_000_000_000);
    let micros = ns.rem_euclid(1_000_000_000) / 1_000;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // Civil date from days since 1970-01-01 (H. Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{micros:06}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests;
