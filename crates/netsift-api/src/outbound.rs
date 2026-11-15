//! Outbound HTTPS client shared by the few features allowed to reach the network: the GeoIP
//! download (ADR-015) and the online checks enabled by the user (ADR-025). No other code of the
//! application sends a request outside the machine.
//!
//! Every request goes through [`Outbound`], built from a [`Policy`] given by the caller:
//!
//! - HTTPS only (rustls with the `ring` provider, certificates checked against the trust store of
//!   the operating system), default port only, host names only (no IP literal), no credentials
//!   in the URL;
//! - hosts restricted to the caller's allow list, checked before the first request and again at
//!   every redirection, with at most [`MAX_REDIRECTS`] redirections by default;
//! - generic `User-Agent` (`NetSift/<version>`), no cookie, no identifier, nothing else sent;
//!   proxy of the environment variables honoured;
//! - connection, read and total timeouts (`Policy::with_*`); body size bounded by the caller while it is received;
//! - downloads written to a temporary file of their own next to the target
//!   (`<name>.<pid>-<n>.part`, created exclusively, never through a link, the next `n` when a
//!   crashed run left that name), hashed (SHA-256) on
//!   the fly, renamed to the target once complete and checked, removed on any failure or
//!   cancellation; an existing `.part` file is never opened nor removed.
//!
//! Errors never carry a response body (not even in the logs).
//!
//! Tests reach a local plain-HTTP server through [`Policy::local_http_for_tests`], which only
//! exists in test builds: a release binary cannot leave HTTPS.

#[cfg(test)]
mod tests;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use reqwest::header::{ACCEPT, CONTENT_LENGTH, HeaderMap};
use reqwest::{Client, Response, StatusCode, Url, redirect};
use serde::de::DeserializeOwned;
use sha2::{Digest as _, Sha256};
use tokio::io::AsyncWriteExt as _;

use crate::ApiError;

/// Redirections followed at most, by default.
pub(crate) const MAX_REDIRECTS: usize = 3;
/// `User-Agent` of every request: the application name and version, nothing else.
pub(crate) const USER_AGENT: &str = concat!("NetSift/", env!("CARGO_PKG_VERSION"));
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const READ_TIMEOUT: Duration = Duration::from_secs(30);
const TOTAL_TIMEOUT: Duration = Duration::from_secs(300);
const HTTPS_PORT: u16 = 443;

/// What a client may reach, and how long it may wait. Built by each feature with its own allow
/// list (DB-IP on one side, GitHub on the other).
#[derive(Debug, Clone)]
pub(crate) struct Policy {
    /// Host names (exact, ASCII case-insensitive) of the first request and of every redirection.
    allowed_hosts: Arc<[String]>,
    /// Redirections followed at most.
    max_redirects: usize,
    connect_timeout: Duration,
    /// Longest wait between two reads (headers, then each part of the body).
    read_timeout: Duration,
    /// Longest duration of a whole request, body included.
    total_timeout: Duration,
    /// Plain HTTP to any port of the allowed hosts, without proxy.
    #[cfg(test)]
    local_http: bool,
}

impl Policy {
    /// HTTPS to `allowed_hosts` only, with the default bounds (15 s to connect, 30 s between
    /// reads, 300 s in total, [`MAX_REDIRECTS`] redirections).
    pub(crate) fn new(allowed_hosts: &[&str]) -> Self {
        Self {
            allowed_hosts: allowed_hosts
                .iter()
                .map(|h| h.to_ascii_lowercase())
                .collect(),
            max_redirects: MAX_REDIRECTS,
            connect_timeout: CONNECT_TIMEOUT,
            read_timeout: READ_TIMEOUT,
            total_timeout: TOTAL_TIMEOUT,
            #[cfg(test)]
            local_http: false,
        }
    }

    /// Longest wait for the connection (default 15 s).
    pub(crate) fn with_connect_timeout(mut self, d: Duration) -> Self {
        self.connect_timeout = d;
        self
    }

    /// Longest wait between two reads: headers, then each part of the body (default 30 s).
    pub(crate) fn with_read_timeout(mut self, d: Duration) -> Self {
        self.read_timeout = d;
        self
    }

    /// Longest duration of a whole request, body included (default 300 s): raise it for large
    /// files.
    pub(crate) fn with_total_timeout(mut self, d: Duration) -> Self {
        self.total_timeout = d;
        self
    }

    /// Tests only: also accept plain HTTP on any port (a local server), without proxy.
    #[cfg(test)]
    pub(crate) fn local_http_for_tests(mut self) -> Self {
        self.local_http = true;
        self
    }

    #[cfg(test)]
    fn local_http(&self) -> bool {
        self.local_http
    }

    #[cfg(not(test))]
    #[expect(clippy::unused_self, reason = "same signature as the test build")]
    fn local_http(&self) -> bool {
        false
    }

    /// The URL may be requested: allowed scheme, port and host name (never an IP literal), no
    /// credentials.
    fn check(&self, url: &Url) -> Result<(), Refusal> {
        let local = self.local_http();
        let scheme_ok = url.scheme() == "https" || (local && url.scheme() == "http");
        let port_ok = local || url.port_or_known_default() == Some(HTTPS_PORT);
        let named = local || url.domain().is_some();
        if !scheme_ok
            || !port_ok
            || !named
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err(Refusal::Url);
        }
        let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
        if self.allowed_hosts.contains(&host) {
            Ok(())
        } else {
            Err(Refusal::Host(host))
        }
    }
}

/// Why a URL or a redirection was refused (carried through reqwest's redirect error).
#[derive(Debug, thiserror::Error)]
enum Refusal {
    #[error("URL refused: scheme, port, IP literal or credentials")]
    Url,
    #[error("host not allowed: {0}")]
    Host(String),
    #[error("too many redirections")]
    TooManyRedirects,
}

/// Failure of an outbound request. Never contains a response body.
#[derive(Debug, thiserror::Error)]
pub(crate) enum OutboundError {
    #[error("cannot set up the HTTP client: {0}")]
    Client(String),
    /// Unparsable URL, scheme other than HTTPS, other port, IP literal, credentials in the URL.
    #[error("URL refused")]
    UrlRefused,
    /// First request or redirection to a host outside the allow list.
    #[error("host not allowed: {0}")]
    HostNotAllowed(String),
    #[error("too many redirections")]
    TooManyRedirects,
    #[error("request timed out")]
    Timeout,
    /// Transport failure, without the URL of the request (see `from_reqwest`).
    #[error("request failed: {0}")]
    Network(reqwest::Error),
    #[error("unexpected HTTP status {0}")]
    Status(StatusCode),
    /// Announced or received body larger than the bound of the caller.
    #[error("the response is larger than allowed")]
    TooLarge,
    /// Body that is not the expected JSON (position only, never the contents).
    #[error("unexpected JSON response at line {line}, column {column}")]
    Json { line: usize, column: usize },
    /// Expected SHA-256 that is not 64 hexadecimal digits.
    #[error("invalid expected SHA-256")]
    InvalidChecksum,
    /// Downloaded file whose SHA-256 differs from the expected one (file removed).
    #[error("SHA-256 mismatch")]
    ChecksumMismatch,
    /// Destination without file name, or file system error (the message names no path).
    #[error("cannot write the downloaded file: {0}")]
    Io(#[from] std::io::Error),
}

impl OutboundError {
    fn from_reqwest(e: reqwest::Error) -> Self {
        let mut source: Option<&(dyn std::error::Error + 'static)> = Some(&e);
        while let Some(err) = source {
            if let Some(refusal) = err.downcast_ref::<Refusal>() {
                return match refusal {
                    Refusal::Url => Self::UrlRefused,
                    Refusal::Host(h) => Self::HostNotAllowed(h.clone()),
                    Refusal::TooManyRedirects => Self::TooManyRedirects,
                };
            }
            source = err.source();
        }
        if e.is_timeout() {
            Self::Timeout
        } else {
            // Without its URL: a redirection target may carry a signed query (asset storage),
            // which must never reach the logs.
            Self::Network(e.without_url())
        }
    }
}

impl OutboundError {
    /// API problem of a failed request, for the routes of an online feature: problem type
    /// `urn:netsift:problem:<kind>` and `title` chosen by the feature, status 504 on timeout,
    /// 500 for local failures (client set-up, file system), 502 otherwise. The error itself is
    /// logged (never a response body), the client only sees the kind.
    pub(crate) fn into_problem(self, kind: &'static str, title: &'static str) -> ApiError {
        let status = match &self {
            Self::Timeout => StatusCode::GATEWAY_TIMEOUT,
            Self::Client(_) | Self::Io(_) => StatusCode::INTERNAL_SERVER_ERROR,
            _ => StatusCode::BAD_GATEWAY,
        };
        tracing::warn!(kind, "outbound request failed: {self}");
        ApiError::Feature {
            status,
            kind,
            title,
        }
    }
}

impl From<Refusal> for OutboundError {
    fn from(r: Refusal) -> Self {
        match r {
            Refusal::Url => Self::UrlRefused,
            Refusal::Host(h) => Self::HostNotAllowed(h),
            Refusal::TooManyRedirects => Self::TooManyRedirects,
        }
    }
}

/// Answer to a `HEAD` request (any status: the caller interprets it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HeadInfo {
    pub(crate) status: StatusCode,
    /// `Content-Length` announced by the server.
    pub(crate) content_length: Option<u64>,
}

/// File written by [`Outbound::download_to`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Downloaded {
    pub(crate) bytes: u64,
    /// SHA-256 of the file, lowercase hexadecimal.
    pub(crate) sha256: String,
}

/// HTTPS client bound to a [`Policy`]. Cheap to build: one per operation is fine.
#[derive(Debug, Clone)]
pub(crate) struct Outbound {
    client: Client,
    policy: Policy,
}

impl Outbound {
    pub(crate) fn new(policy: Policy) -> Result<Self, OutboundError> {
        let mut builder = Client::builder()
            .user_agent(USER_AGENT)
            .connect_timeout(policy.connect_timeout)
            .read_timeout(policy.read_timeout)
            .timeout(policy.total_timeout)
            .redirect(redirect_policy(&policy))
            .https_only(!policy.local_http())
            .tls_backend_preconfigured(tls_config()?);
        if policy.local_http() {
            builder = builder.no_proxy();
        }
        let client = builder
            .build()
            .map_err(|e| OutboundError::Client(e.to_string()))?;
        Ok(Self { client, policy })
    }

    /// `HEAD url`: status and announced size, whatever the status.
    pub(crate) async fn head(&self, url: &str) -> Result<HeadInfo, OutboundError> {
        let url = self.url(url)?;
        let response = self
            .client
            .head(url)
            .send()
            .await
            .map_err(OutboundError::from_reqwest)?;
        Ok(HeadInfo {
            status: response.status(),
            content_length: announced_length(response.headers()),
        })
    }

    /// `GET url` with `Accept: accept`, body of at most `max_bytes` parsed as JSON. Any status
    /// other than 2xx is [`OutboundError::Status`].
    pub(crate) async fn get_json<T: DeserializeOwned>(
        &self,
        url: &str,
        accept: &'static str,
        max_bytes: u64,
    ) -> Result<T, OutboundError> {
        let url = self.url(url)?;
        let response = self
            .client
            .get(url)
            .header(ACCEPT, accept)
            .send()
            .await
            .map_err(OutboundError::from_reqwest)?;
        let body = read_body(success(response)?, max_bytes, |_, _| {}).await?;
        serde_json::from_slice(&body).map_err(|e| OutboundError::Json {
            line: e.line(),
            column: e.column(),
        })
    }

    /// `GET url`, body of at most `max_bytes` kept in memory. `progress(received, total)` is
    /// called once the status is known, then as the body arrives. Any status other than 2xx is
    /// [`OutboundError::Status`] (the caller may handle 404).
    pub(crate) async fn get_bytes(
        &self,
        url: &str,
        max_bytes: u64,
        progress: impl FnMut(u64, Option<u64>),
    ) -> Result<Vec<u8>, OutboundError> {
        let url = self.url(url)?;
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(OutboundError::from_reqwest)?;
        read_body(success(response)?, max_bytes, progress).await
    }

    /// `GET url` streamed to a temporary file next to `dest`, then renamed to `dest` (replacing
    /// it) once the body is complete, flushed to disk and, when `expected_sha256` is given
    /// (hexadecimal), checked. The temporary file has a name of its own
    /// (`<name>.<pid>-<n>.part`), created exclusively (never an existing file, never through a
    /// symbolic link) once the response is accepted: concurrent downloads to the same `dest`
    /// never share it, and the result is one of them, whole and checked. On any failure, and if
    /// the future is dropped, that file is removed and `dest` is left untouched. The parent
    /// directory of `dest` must exist.
    pub(crate) async fn download_to(
        &self,
        url: &str,
        dest: &Path,
        max_bytes: u64,
        expected_sha256: Option<&str>,
        mut progress: impl FnMut(u64, Option<u64>),
    ) -> Result<Downloaded, OutboundError> {
        let expected = expected_sha256
            .map(|h| parse_sha256(h).ok_or(OutboundError::InvalidChecksum))
            .transpose()?;
        // No file name: refused before any request.
        dest_name(dest)?;
        let url = self.url(url)?;
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(OutboundError::from_reqwest)?;
        let mut response = success(response)?;
        let total = checked_length(&response, max_bytes)?;
        progress(0, total);

        let (mut file, part) = PartFile::create_unique(dest).await?;
        let mut hasher = Sha256::new();
        let mut received: u64 = 0;
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(OutboundError::from_reqwest)?
        {
            received = received.saturating_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX));
            if received > max_bytes {
                return Err(OutboundError::TooLarge);
            }
            hasher.update(&chunk);
            file.write_all(&chunk).await?;
            progress(received, total);
        }
        file.flush().await?;
        file.sync_all().await?;
        drop(file);

        let digest: [u8; 32] = hasher.finalize().into();
        if expected.is_some_and(|e| e != digest) {
            return Err(OutboundError::ChecksumMismatch);
        }
        tokio::fs::rename(&part.path, dest).await?;
        part.keep();
        Ok(Downloaded {
            bytes: received,
            sha256: to_hex(&digest),
        })
    }

    fn url(&self, url: &str) -> Result<Url, OutboundError> {
        let url = Url::parse(url).map_err(|_| OutboundError::UrlRefused)?;
        self.policy.check(&url)?;
        Ok(url)
    }
}

/// TLS settings: rustls with `ring`, safe default protocol versions, certificates checked by
/// the platform verifier (system trust store).
fn tls_config() -> Result<rustls::ClientConfig, OutboundError> {
    use rustls_platform_verifier::BuilderVerifierExt as _;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| OutboundError::Client(e.to_string()))?
        .with_platform_verifier()
        .map_err(|e| OutboundError::Client(e.to_string()))?
        .with_no_client_auth();
    Ok(config)
}

/// Redirections: at most `policy.max_redirects`, each target checked against the policy.
fn redirect_policy(policy: &Policy) -> redirect::Policy {
    let policy = policy.clone();
    redirect::Policy::custom(move |attempt| {
        if attempt.previous().len() > policy.max_redirects {
            return attempt.error(Refusal::TooManyRedirects);
        }
        match policy.check(attempt.url()) {
            Ok(()) => attempt.follow(),
            Err(refusal) => attempt.error(refusal),
        }
    })
}

fn success(response: Response) -> Result<Response, OutboundError> {
    let status = response.status();
    if status.is_success() {
        Ok(response)
    } else {
        Err(OutboundError::Status(status))
    }
}

fn announced_length(headers: &HeaderMap) -> Option<u64> {
    headers.get(CONTENT_LENGTH)?.to_str().ok()?.parse().ok()
}

/// Announced size of the body, refused above `max_bytes`.
fn checked_length(response: &Response, max_bytes: u64) -> Result<Option<u64>, OutboundError> {
    let total = response.content_length();
    if total.is_some_and(|t| t > max_bytes) {
        return Err(OutboundError::TooLarge);
    }
    Ok(total)
}

async fn read_body(
    mut response: Response,
    max_bytes: u64,
    mut progress: impl FnMut(u64, Option<u64>),
) -> Result<Vec<u8>, OutboundError> {
    let total = checked_length(&response, max_bytes)?;
    progress(0, total);
    // Announced size, already checked against the bound: one allocation in the usual case.
    let mut body =
        Vec::with_capacity(usize::try_from(total.unwrap_or(0).min(max_bytes)).unwrap_or(0));
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(OutboundError::from_reqwest)?
    {
        let received = u64::try_from(body.len().saturating_add(chunk.len())).unwrap_or(u64::MAX);
        if received > max_bytes {
            return Err(OutboundError::TooLarge);
        }
        body.extend_from_slice(&chunk);
        progress(received, total);
    }
    Ok(body)
}

/// Downloads started by this process, for unique temporary names.
static PART_COUNTER: AtomicU64 = AtomicU64::new(0);
/// Temporary names tried at most by one download: a `.part` file left by a crashed run whose
/// PID was the same (PID reuse) takes a name, the next one is tried.
const PART_ATTEMPTS: usize = 16;

/// `<name>.<pid>-<n>.part`, next to `dest`, unique within this process.
fn part_path(dest: &Path) -> Result<PathBuf, OutboundError> {
    let name = dest_name(dest)?;
    let n = PART_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut name = name.to_os_string();
    name.push(format!(".{}-{n}.part", std::process::id()));
    Ok(dest.with_file_name(name))
}

fn dest_name(dest: &Path) -> Result<&std::ffi::OsStr, OutboundError> {
    dest.file_name().ok_or_else(|| {
        OutboundError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "the destination has no file name",
        ))
    })
}

/// Partial download created by this download, removed on drop unless kept.
struct PartFile {
    path: PathBuf,
    keep: bool,
}

impl PartFile {
    /// Creates `path` exclusively (`O_CREAT | O_EXCL`: fails on any existing file or link).
    /// Only a file created here is ever removed.
    async fn create(path: PathBuf) -> Result<(tokio::fs::File, Self), OutboundError> {
        let file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .await?;
        Ok((file, Self { path, keep: false }))
    }

    /// Creates the next free `<name>.<pid>-<n>.part` next to `dest`: an existing name (left by
    /// a crashed run, or a link) is skipped and left alone, up to [`PART_ATTEMPTS`] names.
    async fn create_unique(dest: &Path) -> Result<(tokio::fs::File, Self), OutboundError> {
        let mut attempt = 1;
        loop {
            match Self::create(part_path(dest)?).await {
                Err(OutboundError::Io(e))
                    if e.kind() == std::io::ErrorKind::AlreadyExists && attempt < PART_ATTEMPTS =>
                {
                    attempt += 1;
                }
                other => return other,
            }
        }
    }

    fn keep(mut self) {
        self.keep = true;
    }
}

impl Drop for PartFile {
    fn drop(&mut self) {
        if !self.keep {
            // Missing file (failure before its creation): nothing to do.
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// 32 bytes from 64 hexadecimal digits (either case).
pub(crate) fn parse_sha256(hex: &str) -> Option<[u8; 32]> {
    let bytes = hex.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut out = [0_u8; 32];
    let (pairs, _) = bytes.as_chunks::<2>();
    for (byte, [hi, lo]) in out.iter_mut().zip(pairs) {
        *byte = (hex_digit(*hi)? << 4) | hex_digit(*lo)?;
    }
    Some(out)
}

fn hex_digit(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::with_capacity(64), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}
