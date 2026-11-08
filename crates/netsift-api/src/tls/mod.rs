//! TLS routes (`docs/specs/tls.md`).
//!
//! | Method | Path | Response |
//! |---|---|---|
//! | GET | `/sessions/{id}/tls/stats` | [`TlsStats`] |
//! | GET | `/sessions/{id}/tls/sessions?limit&cursor&order&version&suite&q&weak&cert_issues` | `Page<TlsSessionItem>` |
//! | GET | `/sessions/{id}/tls/sessions/{flow}` | [`TlsSessionDetail`] |
//! | GET | `/sessions/{id}/tls/certificates?limit&cursor&q&problems` | `Page<TlsCertificateItem>` |
//! | GET | `/sessions/{id}/tls/certificates/{sha256}` | [`TlsCertificateInfo`] |
//! | GET | `/sessions/{id}/tls/certificates/{sha256}/der` | DER file (download) |
//! | GET | `/sessions/{id}/tls/certificates/{sha256}/pem` | PEM file (download) |
//!
//! Like the overview, they answer 409 while the session is importing or failed. Certificate
//! files are always attachments with `Content-Security-Policy: sandbox` and `nosniff`: the
//! webview never renders them.

mod names;

use std::sync::Arc;

use axum::extract::{Path as UrlPath, State};
use axum::http::{HeaderValue, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use netsift_store::tls::{
    self as store, CertificateFilter, CertificateRow, ClientHelloRow, ServerHelloRow,
    TlsSessionEntry, TlsSessionFilter,
};
use netsift_store::{PageRequest, Session};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::contract::Page;
use crate::convert::us;
use crate::extract::ApiQuery;
use crate::overview::open_ready;
use crate::sessions::{DEFAULT_LIMIT, MAX_LIMIT, Stats, parse_id};
use crate::{ApiError, AppState, blocking};

/// Suites shown individually by the charts; the others are summed.
pub(crate) const TOP_SUITES: usize = 15;
/// Server names listed by the statistics.
const TOP_SNI: u32 = 15;
/// Versions listed by the statistics (others summed): real versions are few, but the field is
/// a free 16-bit value in hostile traffic.
const TOP_VERSIONS: u32 = 8;
/// Longest accepted search text.
const MAX_QUERY_LEN: usize = 256;

pub(crate) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/sessions/{id}/tls/stats", get(stats))
        .route("/sessions/{id}/tls/sessions", get(sessions))
        .route("/sessions/{id}/tls/sessions/{flow}", get(session))
        .route("/sessions/{id}/tls/certificates", get(certificates))
        .route("/sessions/{id}/tls/certificates/{sha256}", get(certificate))
        .route("/sessions/{id}/tls/certificates/{sha256}/der", get(der))
        .route("/sessions/{id}/tls/certificates/{sha256}/pem", get(pem))
}

// ------------------------------------------------------------------------------------------
// DTOs
// ------------------------------------------------------------------------------------------

/// Sessions of one negotiated version (`null`: no `ServerHello` seen). Versions beyond the top 8
/// are summed in [`TlsStats::other_versions`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct TlsVersionCount {
    pub version: Option<u16>,
    pub count: u64,
}

/// Sessions of one negotiated suite; `suite` is `null` for the sum of the others.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct TlsSuiteCount {
    pub suite: Option<u16>,
    /// IANA name, `null` when unknown.
    pub name: Option<String>,
    /// Weakness (`rc4`, `3des`, `null`, `export`, `anon`, `des`, `rc2`, `md5`, `cbc_sha1`).
    pub weak: Option<String>,
    pub count: u64,
}

/// One cell of the version x suite matrix (`version` `null`: the versions outside the top 8;
/// `suite` `null`: the suites outside the top 15).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct TlsMatrixCell {
    pub version: Option<u16>,
    pub suite: Option<u16>,
    pub count: u64,
}

/// Sessions of one server name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct TlsSniCount {
    pub sni: String,
    pub count: u64,
}

/// `GET /sessions/{id}/tls/stats`: figures and chart data of the TLS view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct TlsStats {
    pub sessions: u64,
    /// Sessions with a weak negotiated suite.
    pub weak_sessions: u64,
    /// Sessions whose certificate chain has an issue.
    pub cert_issue_sessions: u64,
    /// TLS 1.3 sessions (certificates encrypted, not visible).
    pub encrypted_cert_sessions: u64,
    /// Distinct certificates.
    pub certificates: u64,
    /// Top 8, most frequent first.
    pub versions: Vec<TlsVersionCount>,
    /// Sessions of the other versions.
    pub other_versions: u64,
    /// Top 15 negotiated suites, most frequent first, then the others summed (`suite` `null`).
    pub suites: Vec<TlsSuiteCount>,
    /// Version x suite counts, folded like `versions` and `suites` (non-zero cells only).
    pub matrix: Vec<TlsMatrixCell>,
    /// Top 15 server names.
    pub sni: Vec<TlsSniCount>,
}

/// First plaintext alert of a session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct TlsAlertInfo {
    /// 1 warning, 2 fatal.
    pub level: u8,
    /// RFC 8446 6.2 alert description.
    pub description: u8,
    /// `client` or `server`.
    pub from: String,
}

/// Row of the TLS sessions table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct TlsSessionItem {
    /// Flow id (string: may exceed 2^53).
    pub id: String,
    pub ts_us: i64,
    pub client_ip: String,
    pub client_port: u16,
    pub server_ip: String,
    pub server_port: u16,
    pub sni: Option<String>,
    /// Highest version offered by the client (IANA value, 771 = TLS 1.2).
    pub offered_version: Option<u16>,
    /// Negotiated version, `null` without `ServerHello`.
    pub version: Option<u16>,
    pub cipher_suite: Option<u16>,
    pub cipher_name: Option<String>,
    pub cipher_weak: Option<String>,
    pub alpn_offered: Vec<String>,
    pub alpn: Option<String>,
    pub ja3: Option<String>,
    pub ja3_hash: Option<String>,
    pub ja4: Option<String>,
    pub resumed: bool,
    /// `complete` or `partial`.
    pub outcome: String,
    pub alert: Option<TlsAlertInfo>,
    /// `present`, `encrypted` (TLS 1.3) or `none`.
    pub cert_status: String,
    pub cert_count: u32,
    pub leaf_sha256: Option<String>,
    pub leaf_subject_cn: Option<String>,
    /// `expired`, `not_yet_valid`, `self_signed`, `weak_key` (at the time of the session).
    pub cert_issues: Vec<String>,
}

/// A code point with its registry name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct TlsNamedValue {
    pub value: u16,
    pub name: Option<String>,
    pub grease: bool,
    /// Weakness of a cipher suite.
    pub weak: Option<String>,
}

/// Decoded `ClientHello`, lists in wire order with GREASE values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct TlsClientHelloInfo {
    pub legacy_version: u16,
    /// Hex.
    pub random: String,
    /// Hex.
    pub session_id: String,
    pub session_ticket: bool,
    pub cipher_suites: Vec<TlsNamedValue>,
    pub compressions: Vec<u8>,
    pub extensions: Vec<TlsNamedValue>,
    pub groups: Vec<TlsNamedValue>,
    pub point_formats: Vec<u8>,
    pub signature_algorithms: Vec<TlsNamedValue>,
    pub supported_versions: Vec<TlsNamedValue>,
    pub key_share_groups: Vec<TlsNamedValue>,
}

/// Decoded `ServerHello`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct TlsServerHelloInfo {
    pub legacy_version: u16,
    /// Hex.
    pub random: String,
    /// Hex.
    pub session_id: String,
    pub cipher_suite: TlsNamedValue,
    pub compression: u8,
    pub extensions: Vec<TlsNamedValue>,
    pub selected_version: Option<u16>,
}

/// An X.509 certificate.
#[allow(clippy::struct_excessive_bools)] // certificate flags
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct TlsCertificateInfo {
    /// Hex SHA-256 of the DER (download key).
    pub sha256: String,
    pub sha1: String,
    pub size: u64,
    /// The DER can be downloaded.
    pub downloadable: bool,
    /// The DER parsed as a certificate; the other fields are `null` otherwise.
    pub parsed: bool,
    pub subject: Option<String>,
    pub subject_cn: Option<String>,
    pub issuer: Option<String>,
    pub issuer_cn: Option<String>,
    /// Hex.
    pub serial: Option<String>,
    pub not_before_us: Option<i64>,
    pub not_after_us: Option<i64>,
    pub san: Vec<String>,
    pub key_algorithm: Option<String>,
    pub key_bits: Option<u32>,
    pub signature_algorithm: Option<String>,
    pub self_signed: bool,
    pub is_ca: bool,
    /// Expired at the reference time (the session, or the end of the capture in lists).
    pub expired: bool,
    /// Not valid yet at the reference time (the session, or the start of the capture).
    pub not_yet_valid: bool,
}

/// Row of the deduplicated certificates list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct TlsCertificateItem {
    pub certificate: TlsCertificateInfo,
    /// Sessions whose chain contains it.
    pub sessions: u64,
}

/// `GET /sessions/{id}/tls/sessions/{flow}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct TlsSessionDetail {
    pub session: TlsSessionItem,
    pub client_hello: Option<TlsClientHelloInfo>,
    pub server_hello: Option<TlsServerHelloInfo>,
    /// Chain, leaf first.
    pub certificates: Vec<TlsCertificateInfo>,
}

// ------------------------------------------------------------------------------------------
// Conversions
// ------------------------------------------------------------------------------------------

fn issue_names(bits: u32) -> Vec<String> {
    [
        (store::cert_issue::EXPIRED, "expired"),
        (store::cert_issue::NOT_YET_VALID, "not_yet_valid"),
        (store::cert_issue::SELF_SIGNED, "self_signed"),
        (store::cert_issue::WEAK_KEY, "weak_key"),
    ]
    .into_iter()
    .filter(|(bit, _)| bits & bit != 0)
    .map(|(_, name)| name.to_owned())
    .collect()
}

fn session_item(s: TlsSessionEntry) -> TlsSessionItem {
    TlsSessionItem {
        id: s.id.to_string(),
        ts_us: us(s.ts),
        client_ip: s.client_ip,
        client_port: s.client_port,
        server_ip: s.server_ip,
        server_port: s.server_port,
        sni: s.sni,
        offered_version: s.offered_version,
        version: s.version,
        cipher_suite: s.cipher_suite,
        cipher_name: s.cipher_name,
        cipher_weak: s.cipher_weak,
        alpn_offered: s.alpn_offered,
        alpn: s.alpn,
        ja3: s.ja3,
        ja3_hash: s.ja3_hash,
        ja4: s.ja4,
        resumed: s.resumed,
        outcome: s.outcome,
        alert: s.alert.map(|a| TlsAlertInfo {
            level: a.level,
            description: a.description,
            from: if a.from_server { "server" } else { "client" }.to_owned(),
        }),
        cert_status: s.cert_status,
        cert_count: s.cert_count,
        leaf_sha256: s.leaf_sha256,
        leaf_subject_cn: s.leaf_subject_cn,
        cert_issues: issue_names(s.cert_issues),
    }
}

/// `expired` at `end`, `not_yet_valid` at `start` (nanoseconds).
fn certificate_info(c: CertificateRow, start: Option<i64>, end: Option<i64>) -> TlsCertificateInfo {
    TlsCertificateInfo {
        expired: matches!((c.not_after, end), (Some(a), Some(e)) if a < e),
        not_yet_valid: matches!((c.not_before, start), (Some(b), Some(s)) if b > s),
        sha256: c.sha256,
        sha1: c.sha1,
        size: c.size,
        downloadable: c.stored,
        parsed: c.parsed,
        subject: c.subject,
        subject_cn: c.subject_cn,
        issuer: c.issuer,
        issuer_cn: c.issuer_cn,
        serial: c.serial,
        not_before_us: c.not_before.map(us),
        not_after_us: c.not_after.map(us),
        san: c.san,
        key_algorithm: c.key_algorithm,
        key_bits: c.key_bits,
        signature_algorithm: c.signature_algorithm,
        self_signed: c.self_signed,
        is_ca: c.is_ca,
    }
}

fn named(values: &[u16], name: impl Fn(u16) -> Option<&'static str>) -> Vec<TlsNamedValue> {
    values
        .iter()
        .map(|&value| TlsNamedValue {
            value,
            name: name(value).map(str::to_owned),
            grease: names::is_grease(value),
            weak: None,
        })
        .collect()
}

/// Names of the suites of a session.
struct Suites(Vec<store::CipherNameRow>);

impl Suites {
    fn value(&self, value: u16) -> TlsNamedValue {
        let known = self.0.iter().find(|c| c.id == value);
        TlsNamedValue {
            value,
            name: known.map(|c| c.name.clone()),
            grease: names::is_grease(value),
            weak: known.and_then(|c| c.weak.clone()),
        }
    }
}

fn client_hello(ch: ClientHelloRow, suites: &Suites) -> TlsClientHelloInfo {
    TlsClientHelloInfo {
        legacy_version: ch.legacy_version,
        random: ch.random,
        session_id: ch.legacy_session_id,
        session_ticket: ch.session_ticket,
        cipher_suites: ch.cipher_suites.iter().map(|s| suites.value(*s)).collect(),
        compressions: ch.compressions,
        extensions: named(&ch.extensions, names::extension),
        groups: named(&ch.groups, names::group),
        point_formats: ch.point_formats,
        signature_algorithms: named(&ch.signature_algs, names::signature_scheme),
        supported_versions: named(&ch.supported_versions, names::version),
        key_share_groups: named(&ch.key_share_groups, names::group),
    }
}

fn server_hello(sh: ServerHelloRow, suites: &Suites) -> TlsServerHelloInfo {
    TlsServerHelloInfo {
        legacy_version: sh.legacy_version,
        random: sh.random,
        session_id: sh.legacy_session_id,
        cipher_suite: suites.value(sh.cipher_suite),
        compression: sh.compression,
        extensions: named(&sh.extensions, names::extension),
        selected_version: sh.selected_version,
    }
}

// ------------------------------------------------------------------------------------------
// Handlers
// ------------------------------------------------------------------------------------------

fn build_stats(session: &Session) -> Result<TlsStats, ApiError> {
    let rows = store::stats(
        session.conn(),
        store::StatsLimits {
            versions: TOP_VERSIONS,
            suites: u32::try_from(TOP_SUITES).unwrap_or(u32::MAX),
            sni: TOP_SNI,
        },
    )?;
    let mut suites: Vec<TlsSuiteCount> = rows
        .suites
        .into_iter()
        .map(|s| TlsSuiteCount {
            suite: Some(s.suite),
            name: s.name,
            weak: s.weak,
            count: s.count,
        })
        .collect();
    if rows.other_suites > 0 {
        suites.push(TlsSuiteCount {
            suite: None,
            name: None,
            weak: None,
            count: rows.other_suites,
        });
    }
    // Already folded and bounded by the store: one cell per row.
    let mut matrix: Vec<TlsMatrixCell> = rows
        .pairs
        .into_iter()
        .map(|(version, suite, count)| TlsMatrixCell {
            version,
            suite,
            count,
        })
        .collect();
    matrix.sort_by_key(|c| (c.version, c.suite));
    Ok(TlsStats {
        sessions: rows.sessions,
        weak_sessions: rows.weak_sessions,
        cert_issue_sessions: rows.cert_issue_sessions,
        encrypted_cert_sessions: rows.encrypted_cert_sessions,
        certificates: rows.certificates,
        versions: rows
            .versions
            .into_iter()
            .map(|(version, count)| TlsVersionCount { version, count })
            .collect(),
        other_versions: rows.other_versions,
        suites,
        matrix,
        sni: rows
            .sni
            .into_iter()
            .map(|(sni, count)| TlsSniCount { sni, count })
            .collect(),
    })
}

async fn stats(
    State(state): State<Arc<AppState>>,
    UrlPath(id): UrlPath<String>,
) -> Result<Json<TlsStats>, ApiError> {
    let id = parse_id(&id)?;
    blocking(&state, move |s| build_stats(&open_ready(s, &id)?.1))
        .await
        .map(Json)
}

fn page_request(limit: Option<u32>, cursor: Option<String>) -> PageRequest {
    PageRequest {
        limit: match limit {
            None | Some(0) => DEFAULT_LIMIT,
            Some(n) => n.min(MAX_LIMIT),
        },
        cursor,
    }
}

fn search(q: Option<String>) -> Result<Option<String>, ApiError> {
    match q {
        Some(q) if q.len() > MAX_QUERY_LEN => Err(ApiError::BadRequest("q: too long".to_owned())),
        q => Ok(q.filter(|q| !q.trim().is_empty())),
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Order {
    Asc,
    #[default]
    Desc,
}

#[derive(Debug, Default, Deserialize)]
struct SessionsQuery {
    limit: Option<u32>,
    cursor: Option<String>,
    /// By time: `desc` (default, newest first) or `asc`.
    #[serde(default)]
    order: Order,
    version: Option<u16>,
    suite: Option<u16>,
    /// Substring of the SNI or of the server address.
    q: Option<String>,
    /// Only weak negotiated suites.
    #[serde(default)]
    weak: bool,
    /// Only chains with an issue.
    #[serde(default)]
    cert_issues: bool,
}

async fn sessions(
    State(state): State<Arc<AppState>>,
    UrlPath(id): UrlPath<String>,
    ApiQuery(query): ApiQuery<SessionsQuery>,
) -> Result<Json<Page<TlsSessionItem>>, ApiError> {
    let id = parse_id(&id)?;
    blocking(&state, move |s| {
        let (_, session) = open_ready(s, &id)?;
        let filter = TlsSessionFilter {
            version: query.version,
            suite: query.suite,
            q: search(query.q)?,
            weak_only: query.weak,
            cert_issues_only: query.cert_issues,
        };
        let conn = session.conn();
        let page = store::sessions_page(
            conn,
            &filter,
            query.order == Order::Desc,
            &page_request(query.limit, query.cursor),
        )?;
        Ok(Page {
            items: page.items.into_iter().map(session_item).collect(),
            next_cursor: page.next_cursor,
            total_estimate: Some(store::count_sessions(conn, &filter)?),
        })
    })
    .await
    .map(Json)
}

fn build_detail(session: &Session, flow: i64) -> Result<TlsSessionDetail, ApiError> {
    let d = store::session_detail(session.conn(), flow)?.ok_or(ApiError::NotFound)?;
    let at = Some(d.session.ts);
    let suites = Suites(d.cipher_names);
    Ok(TlsSessionDetail {
        client_hello: d.client_hello.map(|ch| client_hello(ch, &suites)),
        server_hello: d.server_hello.map(|sh| server_hello(sh, &suites)),
        certificates: d
            .certificates
            .into_iter()
            .map(|c| certificate_info(c, at, at))
            .collect(),
        session: session_item(d.session),
    })
}

async fn session(
    State(state): State<Arc<AppState>>,
    UrlPath((id, flow)): UrlPath<(String, String)>,
) -> Result<Json<TlsSessionDetail>, ApiError> {
    let id = parse_id(&id)?;
    let flow: i64 = flow.parse().map_err(|_| ApiError::NotFound)?;
    blocking(&state, move |s| build_detail(&open_ready(s, &id)?.1, flow))
        .await
        .map(Json)
}

#[derive(Debug, Default, Deserialize)]
struct CertificatesQuery {
    limit: Option<u32>,
    cursor: Option<String>,
    /// Substring of the subject, issuer or SAN.
    q: Option<String>,
    /// Only expired, not yet valid or self-signed certificates (over the capture period).
    #[serde(default)]
    problems: bool,
}

async fn certificates(
    State(state): State<Arc<AppState>>,
    UrlPath(id): UrlPath<String>,
    ApiQuery(query): ApiQuery<CertificatesQuery>,
) -> Result<Json<Page<TlsCertificateItem>>, ApiError> {
    let id = parse_id(&id)?;
    blocking(&state, move |s| {
        let (_, session) = open_ready(s, &id)?;
        let period = Stats::of(&session);
        let filter = CertificateFilter {
            q: search(query.q)?,
            problems_only: query.problems,
            capture_start: period.first_ts,
            capture_end: period.last_ts,
        };
        let conn = session.conn();
        let page =
            store::certificates_page(conn, &filter, &page_request(query.limit, query.cursor))?;
        Ok(Page {
            items: page
                .items
                .into_iter()
                .map(|e| TlsCertificateItem {
                    certificate: certificate_info(e.certificate, period.first_ts, period.last_ts),
                    sessions: e.sessions,
                })
                .collect(),
            next_cursor: page.next_cursor,
            total_estimate: Some(store::count_certificates(conn, &filter)?),
        })
    })
    .await
    .map(Json)
}

/// A certificate row, 404 for an unknown or malformed digest.
fn find_certificate(session: &Session, sha256: &str) -> Result<CertificateRow, ApiError> {
    netsift_store::session::blob_relpath(sha256).ok_or(ApiError::NotFound)?;
    store::certificate(session.conn(), sha256)?.ok_or(ApiError::NotFound)
}

async fn certificate(
    State(state): State<Arc<AppState>>,
    UrlPath((id, sha256)): UrlPath<(String, String)>,
) -> Result<Json<TlsCertificateInfo>, ApiError> {
    let id = parse_id(&id)?;
    blocking(&state, move |s| {
        let (_, session) = open_ready(s, &id)?;
        let period = Stats::of(&session);
        let row = find_certificate(&session, &sha256)?;
        Ok(certificate_info(row, period.first_ts, period.last_ts))
    })
    .await
    .map(Json)
}

/// File name of a downloaded certificate: common name (letters, digits, `.-_` only) and the
/// first 12 hex digits of the digest.
fn file_name(row: &CertificateRow, extension: &str) -> String {
    let stem: String = row
        .subject_cn
        .as_deref()
        .unwrap_or("certificate")
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .take(64)
        .collect();
    let stem = stem.trim_matches('.');
    let stem = if stem.is_empty() { "certificate" } else { stem };
    let short = row.sha256.get(..12).unwrap_or_default();
    format!("{stem}-{short}.{extension}")
}

/// The DER bytes of a stored certificate, with its row.
fn read_der(
    state: &AppState,
    id: &str,
    sha256: &str,
) -> Result<(CertificateRow, Vec<u8>), ApiError> {
    let id = parse_id(id)?;
    let (_, session) = open_ready(state, &id)?;
    let row = find_certificate(&session, sha256)?;
    let path = session.blob_path(&row.sha256).ok_or(ApiError::NotFound)?;
    let bytes = std::fs::read(&path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            ApiError::NotFound
        } else {
            tracing::error!("cannot read a certificate blob: {e}");
            ApiError::Internal
        }
    })?;
    // A blob cut short (interrupted write, damaged disk) is never served as a certificate.
    if u64::try_from(bytes.len()).ok() != Some(row.size) {
        tracing::warn!("a certificate blob does not have its recorded size");
        return Err(ApiError::Conflict(
            "the stored certificate file is incomplete".to_owned(),
        ));
    }
    Ok((row, bytes))
}

/// An attachment that the webview must never render.
fn attachment(bytes: Vec<u8>, content_type: &'static str, name: &str) -> Response {
    let mut res = bytes.into_response();
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

async fn der(
    State(state): State<Arc<AppState>>,
    UrlPath((id, sha256)): UrlPath<(String, String)>,
) -> Result<Response, ApiError> {
    let (row, bytes) = blocking(&state, move |s| read_der(s, &id, &sha256)).await?;
    Ok(attachment(
        bytes,
        "application/pkix-cert",
        &file_name(&row, "der"),
    ))
}

async fn pem(
    State(state): State<Arc<AppState>>,
    UrlPath((id, sha256)): UrlPath<(String, String)>,
) -> Result<Response, ApiError> {
    let (row, bytes) = blocking(&state, move |s| read_der(s, &id, &sha256)).await?;
    Ok(attachment(
        to_pem(&bytes).into_bytes(),
        "application/x-pem-file",
        &file_name(&row, "pem"),
    ))
}

/// PEM encoding (RFC 7468): base64 in lines of 64 characters.
fn to_pem(der: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut b64 = String::with_capacity(der.len().div_ceil(3) * 4);
    for chunk in der.chunks(3) {
        let b = [
            chunk.first().copied().unwrap_or(0),
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        let take = chunk.len() + 1;
        for i in 0..4 {
            if i < take {
                let index = usize::try_from((n >> (18 - 6 * i)) & 0x3f).unwrap_or(0);
                b64.push(char::from(ALPHABET.get(index).copied().unwrap_or(b'A')));
            } else {
                b64.push('=');
            }
        }
    }
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    for line in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).unwrap_or_default());
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}

#[cfg(test)]
mod tests;
