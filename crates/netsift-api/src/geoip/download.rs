//! Download of the DB-IP IP-to-Country Lite database (ADR-015), sent only when the user asks
//! for it, through the shared outbound client (`crate::outbound`): HTTPS only, allow list
//! reduced to the DB-IP download host (checked at each of at most
//! [`outbound::MAX_REDIRECTS`](crate::outbound::MAX_REDIRECTS) redirections), generic
//! `User-Agent`, connection, read and total timeouts, body bounded by
//! `netsift_geo::MAX_COMPRESSED_BYTES` while it is received.
//!
//! Same logic as `scripts/ci/geoip.sh`: the file of the current month (UTC), or the one of the
//! previous month when the current one is not published yet (404).

use std::time::{SystemTime, UNIX_EPOCH};

use reqwest::StatusCode;

use crate::outbound::{Outbound, OutboundError, Policy};

/// Host of the published files: the only one the download may reach.
pub(crate) const DB_IP_HOST: &str = "download.db-ip.com";
/// Base URL of the published files.
pub(crate) const DB_IP_BASE: &str = "https://download.db-ip.com/free/";

/// Where the files are downloaded from.
#[derive(Debug, Clone)]
pub(crate) struct Source {
    /// Prefix of the file URLs, ending with `/`.
    pub(crate) base: String,
    /// Hosts and bounds of the requests.
    pub(crate) policy: Policy,
}

impl Default for Source {
    fn default() -> Self {
        Self {
            base: DB_IP_BASE.to_owned(),
            policy: Policy::new(&[DB_IP_HOST]),
        }
    }
}

/// Failure of a download. Logged by the caller; the UI only sees its problem type.
#[derive(Debug, thiserror::Error)]
pub(crate) enum DownloadError {
    #[error(transparent)]
    Outbound(OutboundError),
    #[error("no database published for {0} or {1}")]
    NotPublished(String, String),
    #[error("the database is larger than allowed")]
    TooLarge,
}

impl From<OutboundError> for DownloadError {
    fn from(e: OutboundError) -> Self {
        match e {
            OutboundError::TooLarge => Self::TooLarge,
            other => Self::Outbound(other),
        }
    }
}

/// Year and month (UTC) of `now`, and of the month before.
pub(crate) fn months(now: SystemTime) -> [(i64, u32); 2] {
    let secs = now
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
    let (year, month) = month_of(secs);
    let previous = if month == 1 {
        (year - 1, 12)
    } else {
        (year, month - 1)
    };
    [(year, month), previous]
}

/// Year and month (UTC) of a time in seconds since the Unix epoch.
pub(crate) fn month_of(secs: i64) -> (i64, u32) {
    year_month(secs.div_euclid(86_400))
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

/// Downloads the compressed database of the current month, or of the previous one when the
/// current one answers 404. `progress(received, total)` is called as the body arrives.
pub(crate) async fn fetch(
    source: &Source,
    now: SystemTime,
    max_bytes: u64,
    mut progress: impl FnMut(u64, Option<u64>),
) -> Result<Vec<u8>, DownloadError> {
    let client = Outbound::new(source.policy.clone())?;
    let [current, previous] = months(now);
    for month in [current, previous] {
        let url = format!("{}{}", source.base, file_name(month));
        match client.get_bytes(&url, max_bytes, &mut progress).await {
            Ok(body) => {
                tracing::info!(%url, bytes = body.len(), "GeoIP database downloaded");
                return Ok(body);
            }
            Err(OutboundError::Status(StatusCode::NOT_FOUND)) => {
                tracing::info!(%url, "GeoIP database not published yet");
            }
            Err(e) => return Err(e.into()),
        }
    }
    Err(DownloadError::NotPublished(
        file_name(current),
        file_name(previous),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::Duration;

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
        assert!(DB_IP_BASE.contains(DB_IP_HOST));
    }

    #[test]
    fn the_https_client_builds_without_network() {
        Outbound::new(Source::default().policy).unwrap();
    }
}
