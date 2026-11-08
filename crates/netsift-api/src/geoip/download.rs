//! Download of the DB-IP IP-to-Country Lite database: the only outbound network request of the
//! application (ADR-015), sent only when the user asks for it.
//!
//! - HTTPS only (rustls with the `ring` provider, certificates checked against the trust store of
//!   the operating system), at most [`MAX_REDIRECTS`] redirections and only to the same origin;
//! - generic `User-Agent` (`NetSift/<version>`), no cookie, no identifier, nothing else sent;
//! - connection, read and total timeouts; body bounded by `netsift_geo::MAX_COMPRESSED_BYTES`
//!   while it is received.
//!
//! Same logic as `scripts/ci/geoip.sh`: the file of the current month (UTC), or the one of the
//! previous month when the current one is not published yet (404).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use reqwest::{Client, StatusCode, redirect};

/// Base URL of the published files.
pub(crate) const DB_IP_BASE: &str = "https://download.db-ip.com/free/";
/// Redirections followed at most (same origin only).
pub(crate) const MAX_REDIRECTS: usize = 3;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const READ_TIMEOUT: Duration = Duration::from_secs(30);
const TOTAL_TIMEOUT: Duration = Duration::from_secs(300);
const USER_AGENT: &str = concat!("NetSift/", env!("CARGO_PKG_VERSION"));

/// Where the files are downloaded from.
#[derive(Debug, Clone)]
pub(crate) struct Source {
    /// Prefix of the file URLs, ending with `/`.
    pub(crate) base: String,
    /// Tests only: plain HTTP to a local server, without proxy.
    pub(crate) allow_http: bool,
}

impl Default for Source {
    fn default() -> Self {
        Self {
            base: DB_IP_BASE.to_owned(),
            allow_http: false,
        }
    }
}

/// Failure of a download. Logged by the caller; the UI only sees its problem type.
#[derive(Debug, thiserror::Error)]
pub(crate) enum DownloadError {
    #[error("cannot set up the HTTP client: {0}")]
    Client(String),
    #[error("request failed: {0}")]
    Network(#[from] reqwest::Error),
    #[error("unexpected HTTP status {0}")]
    Status(StatusCode),
    #[error("no database published for {0} or {1}")]
    NotPublished(String, String),
    #[error("the database is larger than allowed")]
    TooLarge,
}

/// Year and month (UTC) of `now`, and of the month before.
pub(crate) fn months(now: SystemTime) -> [(i64, u32); 2] {
    let secs = now
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
    let (year, month) = year_month(secs.div_euclid(86_400));
    let previous = if month == 1 {
        (year - 1, 12)
    } else {
        (year, month - 1)
    };
    [(year, month), previous]
}

/// Civil year and month of a day count since 1970-01-01 (proleptic Gregorian calendar,
/// algorithm of H. Hinnant's `civil_from_days`).
fn year_month(days: i64) -> (i64, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, u32::try_from(month).unwrap_or(1))
}

/// File name published for a month.
pub(crate) fn file_name((year, month): (i64, u32)) -> String {
    format!("dbip-country-lite-{year:04}-{month:02}.mmdb.gz")
}

/// TLS settings: rustls with `ring`, safe default protocol versions, certificates checked by
/// the platform verifier (system trust store).
fn tls_config() -> Result<rustls::ClientConfig, DownloadError> {
    use rustls_platform_verifier::BuilderVerifierExt as _;
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| DownloadError::Client(e.to_string()))?
        .with_platform_verifier()
        .map_err(|e| DownloadError::Client(e.to_string()))?
        .with_no_client_auth();
    Ok(config)
}

/// Redirections: at most [`MAX_REDIRECTS`], same scheme, host and port as the first request.
fn redirect_policy() -> redirect::Policy {
    redirect::Policy::custom(|attempt| {
        let same_origin = attempt.previous().first().is_some_and(|first| {
            let next = attempt.url();
            first.scheme() == next.scheme()
                && first.host_str() == next.host_str()
                && first.port_or_known_default() == next.port_or_known_default()
        });
        if attempt.previous().len() > MAX_REDIRECTS {
            attempt.error("too many redirections")
        } else if same_origin {
            attempt.follow()
        } else {
            attempt.error("redirection to another origin refused")
        }
    })
}

pub(crate) fn client(source: &Source) -> Result<Client, DownloadError> {
    let mut builder = Client::builder()
        .user_agent(USER_AGENT)
        .connect_timeout(CONNECT_TIMEOUT)
        .read_timeout(READ_TIMEOUT)
        .timeout(TOTAL_TIMEOUT)
        .redirect(redirect_policy())
        .https_only(!source.allow_http)
        .tls_backend_preconfigured(tls_config()?);
    if source.allow_http {
        builder = builder.no_proxy();
    }
    builder
        .build()
        .map_err(|e| DownloadError::Client(e.to_string()))
}

/// Downloads the compressed database of the current month, or of the previous one when the
/// current one answers 404. `progress(received, total)` is called as the body arrives.
pub(crate) async fn fetch(
    source: &Source,
    now: SystemTime,
    max_bytes: u64,
    mut progress: impl FnMut(u64, Option<u64>),
) -> Result<Vec<u8>, DownloadError> {
    let client = client(source)?;
    let [current, previous] = months(now);
    for month in [current, previous] {
        let url = format!("{}{}", source.base, file_name(month));
        let mut response = client.get(&url).send().await?;
        let status = response.status();
        if status == StatusCode::NOT_FOUND {
            tracing::info!(%url, "GeoIP database not published yet");
            continue;
        }
        if !status.is_success() {
            return Err(DownloadError::Status(status));
        }
        let total = response.content_length();
        if total.is_some_and(|t| t > max_bytes) {
            return Err(DownloadError::TooLarge);
        }
        progress(0, total);
        // Announced size, already checked against the bound: one allocation in the usual case.
        let mut body =
            Vec::with_capacity(usize::try_from(total.unwrap_or(0).min(max_bytes)).unwrap_or(0));
        while let Some(chunk) = response.chunk().await? {
            let received =
                u64::try_from(body.len().saturating_add(chunk.len())).unwrap_or(u64::MAX);
            if received > max_bytes {
                return Err(DownloadError::TooLarge);
            }
            body.extend_from_slice(&chunk);
            progress(received, total);
        }
        tracing::info!(%url, bytes = body.len(), "GeoIP database downloaded");
        return Ok(body);
    }
    Err(DownloadError::NotPublished(
        file_name(current),
        file_name(previous),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    #[test]
    fn months_are_utc_and_wrap_at_new_year() {
        assert_eq!(months(at(0)), [(1970, 1), (1969, 12)]);
        // 2026-11-08T12:00Z.
        assert_eq!(months(at(1_794_139_200)), [(2026, 11), (2026, 10)]);
        // 2024-02-29T23:59:59Z, then 2024-03-01T00:00Z.
        assert_eq!(months(at(1_709_251_199)), [(2024, 2), (2024, 1)]);
        assert_eq!(months(at(1_709_251_200)), [(2024, 3), (2024, 2)]);
        // 2027-01-01T00:00Z.
        assert_eq!(months(at(1_798_761_600)), [(2027, 1), (2026, 12)]);
        // Before the epoch: clamped to it.
        assert_eq!(
            months(UNIX_EPOCH - Duration::from_secs(10)),
            [(1970, 1), (1969, 12)]
        );
    }

    #[test]
    fn file_names_follow_db_ip() {
        assert_eq!(file_name((2026, 3)), "dbip-country-lite-2026-03.mmdb.gz");
        assert!(DB_IP_BASE.starts_with("https://download.db-ip.com/"));
        assert!(USER_AGENT.starts_with("NetSift/"));
    }

    #[test]
    fn the_https_client_builds_without_network() {
        client(&Source::default()).unwrap();
    }
}
