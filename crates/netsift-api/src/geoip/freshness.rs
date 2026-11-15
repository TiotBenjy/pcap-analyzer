//! Is the country database of this month? (`GET /geoip/status`, P4.9, ADR-025.)
//!
//! - Local check, without network: the month (UTC) of the `build_epoch` of the database in use
//!   (user copy, else bundled one) compared to the current month. No usable database is
//!   `missing`, an older month is `outdated`.
//! - Online check, only when the user enabled `geoip_check` (off by default) and the local
//!   check is not `current`: at startup, one `HEAD` request for the file of the current month on
//!   download.db-ip.com, then one for the previous month when the current one answers 404 (the
//!   months the download of ADR-015 tries). It decides whether a newer database can be offered;
//!   any failure is silent (a log line) and the offer falls back to the local check.
//! - The offer (`download` or `update`) feeds the notice of the UI, dismissed until the month
//!   changes; a read-only server offers nothing (its database cannot be replaced).

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::{Json, Router};
use futures_util::future::BoxFuture;
use reqwest::StatusCode;
use serde::Serialize;
use ts_rs::TS;

use super::download::{self, Source};
use super::lock;
use crate::outbound::{Outbound, OutboundError};
use crate::{ApiError, AppState, blocking};

/// Longest duration of each `HEAD` request (connection included).
const HEAD_TIMEOUT: Duration = Duration::from_secs(20);
const HEAD_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Year and month (UTC).
type Month = (i64, u32);

pub(super) fn routes() -> Router<Arc<AppState>> {
    Router::new().route("/geoip/status", axum::routing::get(status))
}

/// Local check of the database in use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum GeoipFreshnessState {
    /// Built this month (or later).
    Current,
    /// Built before the current month.
    Outdated,
    /// No usable database (absent or unreadable).
    Missing,
}

/// Online check of this start.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum GeoipOnlineCheck {
    /// Not run: setting off, read-only server, or database already current at startup.
    Off,
    /// Running: no offer until it ends.
    Pending,
    /// A database is published, for `published_month`.
    Published,
    /// Neither the current month nor the previous one is published.
    NotPublished,
    /// Network or server failure: the offer follows the local check.
    Failed,
}

/// What the notice offers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum GeoipOffer {
    /// No usable database: download one.
    Download,
    /// The database is older than the one that can be downloaded.
    Update,
}

/// `GET /api/v1/geoip/status`: freshness of the country database in use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct GeoipFreshness {
    pub state: GeoipFreshnessState,
    /// Month the database in use was built (`YYYY-MM`, UTC), when there is one.
    pub built_month: Option<String>,
    /// Current month (`YYYY-MM`, UTC): the key a dismissed notice is hidden for.
    pub current_month: String,
    pub online: GeoipOnlineCheck,
    /// Newest published month found by the online check (`YYYY-MM`).
    pub published_month: Option<String>,
    /// What to offer, if anything (never on a read-only server, nor while the online check runs).
    pub offer: Option<GeoipOffer>,
}

/// Result of the online check, kept for the whole run of the server (`AppState::online`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum CheckState {
    #[default]
    Off,
    Pending,
    Published(Month),
    NotPublished,
    Failed,
}

/// State of the online check (`state.online.get::<OnlineCheck>()`).
#[derive(Default)]
pub(crate) struct OnlineCheck(Mutex<CheckState>);

impl OnlineCheck {
    fn get(&self) -> CheckState {
        *lock(&self.0)
    }

    fn set(&self, state: CheckState) {
        *lock(&self.0) = state;
    }
}

/// Startup check (`online::STARTUP_CHECKS`, run only when `geoip_check` is on and the server is
/// not read-only). Marked as running before the server answers its first request, so that the
/// UI never offers on the local check alone what the online check may withdraw.
pub(crate) fn run(state: Arc<AppState>) -> BoxFuture<'static, ()> {
    let check = state.online.get::<OnlineCheck>();
    check.set(CheckState::Pending);
    Box::pin(async move {
        let now = SystemTime::now();
        let built = blocking(&state, |s| Ok(built_month(s))).await;
        let result = match built {
            Ok(built) if local_state(built, month_of(now)) == GeoipFreshnessState::Current => {
                tracing::debug!("GeoIP database current: no online check");
                CheckState::Off
            }
            Ok(_) => check_published(&state.geoip.source(), now).await,
            Err(_) => CheckState::Failed,
        };
        check.set(result);
    })
}

/// `GET /geoip/status`.
async fn status(State(state): State<Arc<AppState>>) -> Result<Json<GeoipFreshness>, ApiError> {
    let built = blocking(&state, |s| Ok(built_month(s))).await?;
    let online = state.online.get::<OnlineCheck>().get();
    Ok(Json(assess(
        built,
        month_of(SystemTime::now()),
        online,
        state.config.read_only,
    )))
}

/// Month the database in use was built, `None` when no database is usable.
fn built_month(state: &AppState) -> Option<Month> {
    let (db, _) = state.geoip.current();
    let epoch = i64::try_from(db?.build_epoch()).unwrap_or(i64::MAX);
    Some(download::month_of(epoch))
}

fn month_of(t: SystemTime) -> Month {
    let secs = t
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
    download::month_of(secs)
}

fn month_text((year, month): Month) -> String {
    format!("{year:04}-{month:02}")
}

/// Local check: a database built in `now` or later is current (a clock behind the publisher's
/// must not offer an older file).
fn local_state(built: Option<Month>, now: Month) -> GeoipFreshnessState {
    match built {
        None => GeoipFreshnessState::Missing,
        Some(built) if built >= now => GeoipFreshnessState::Current,
        Some(_) => GeoipFreshnessState::Outdated,
    }
}

/// Status reported to the UI.
fn assess(built: Option<Month>, now: Month, online: CheckState, read_only: bool) -> GeoipFreshness {
    let state = local_state(built, now);
    let local_offer = match state {
        GeoipFreshnessState::Current => None,
        GeoipFreshnessState::Outdated => Some(GeoipOffer::Update),
        GeoipFreshnessState::Missing => Some(GeoipOffer::Download),
    };
    let (online, published, offer) = match online {
        CheckState::Off => (GeoipOnlineCheck::Off, None, local_offer),
        CheckState::Failed => (GeoipOnlineCheck::Failed, None, local_offer),
        CheckState::Pending => (GeoipOnlineCheck::Pending, None, None),
        CheckState::NotPublished => (GeoipOnlineCheck::NotPublished, None, None),
        CheckState::Published(month) => {
            // The download fetches this month: offer it only if it is newer than the database.
            let offer = match built {
                None => Some(GeoipOffer::Download),
                Some(built) if built < month => local_offer,
                Some(_) => None,
            };
            (GeoipOnlineCheck::Published, Some(month), offer)
        }
    };
    GeoipFreshness {
        state,
        built_month: built.map(month_text),
        current_month: month_text(now),
        online,
        published_month: published.map(month_text),
        offer: if read_only { None } else { offer },
    }
}

/// Asks the server whether the database of the current month, else of the previous one, is
/// published (`HEAD`, same files as the download). Never fails: errors become
/// [`CheckState::Failed`], logged without any response body.
async fn check_published(source: &Source, now: SystemTime) -> CheckState {
    let policy = source
        .policy
        .clone()
        .with_connect_timeout(HEAD_CONNECT_TIMEOUT)
        .with_read_timeout(HEAD_TIMEOUT)
        .with_total_timeout(HEAD_TIMEOUT);
    let client = match Outbound::new(policy) {
        Ok(client) => client,
        Err(e) => {
            tracing::info!("GeoIP online check not run: {e}");
            return CheckState::Failed;
        }
    };
    for month in download::months(now) {
        let file = download::file_name(month);
        let url = format!("{}{file}", source.base);
        match client.head(&url).await {
            Ok(head) if head.status.is_success() => {
                tracing::info!(file, "GeoIP online check: database published");
                return CheckState::Published(month);
            }
            Ok(head) if head.status == StatusCode::NOT_FOUND => {
                tracing::debug!(file, "GeoIP online check: not published yet");
            }
            Ok(head) => {
                tracing::info!(file, status = %head.status, "GeoIP online check: unexpected answer");
                return CheckState::Failed;
            }
            Err(e) => {
                tracing::info!(file, "GeoIP online check failed: {}", describe(e));
                return CheckState::Failed;
            }
        }
    }
    CheckState::NotPublished
}

/// Error text for the logs, without the URL kept by reqwest.
fn describe(e: OutboundError) -> String {
    match e {
        OutboundError::Network(e) => format!("request failed: {}", e.without_url()),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOV: Month = (2026, 11);

    /// `YYYY-MM-DDTHH:MM:SSZ` in seconds since the epoch (days from H. Hinnant's
    /// `days_from_civil`).
    fn utc(year: i64, month: i64, day: i64, hour: i64, minute: i64, second: i64) -> i64 {
        let year = if month <= 2 { year - 1 } else { year };
        let era = year.div_euclid(400);
        let yoe = year - era * 400;
        let mp = (month + 9) % 12;
        let doy = (153 * mp + 2) / 5 + day - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        let days = era * 146_097 + doe - 719_468;
        days * 86_400 + hour * 3_600 + minute * 60 + second
    }

    fn state_at(built: Option<i64>, now: i64) -> GeoipFreshnessState {
        local_state(built.map(download::month_of), download::month_of(now))
    }

    #[test]
    fn the_month_is_compared_in_utc_at_its_boundaries() {
        use GeoipFreshnessState::{Current, Missing, Outdated};
        let first_nov = utc(2026, 11, 1, 0, 0, 0);
        assert_eq!(first_nov, 1_793_491_200);
        // Built the last second of October, read at the first second of November.
        assert_eq!(state_at(Some(first_nov - 1), first_nov), Outdated);
        assert_eq!(state_at(Some(first_nov), first_nov), Current);
        assert_eq!(
            state_at(Some(first_nov), utc(2026, 11, 30, 23, 59, 59)),
            Current
        );
        assert_eq!(
            state_at(Some(first_nov), utc(2026, 12, 1, 0, 0, 0)),
            Outdated
        );
        // New year: December is older than January.
        let jan = utc(2027, 1, 1, 0, 0, 0);
        assert_eq!(state_at(Some(jan - 1), jan), Outdated);
        assert_eq!(state_at(Some(utc(2026, 1, 15, 0, 0, 0)), jan - 1), Outdated);
        // Leap day.
        assert_eq!(
            state_at(Some(utc(2028, 2, 29, 23, 59, 59)), utc(2028, 3, 1, 0, 0, 0)),
            Outdated
        );
        // A database from a later month (clock behind) is current.
        assert_eq!(
            state_at(Some(utc(2026, 12, 1, 0, 0, 0)), first_nov),
            Current
        );
        assert_eq!(state_at(Some(i64::MAX), first_nov), Current);
        // Epoch 0 (no real build date) is very old.
        assert_eq!(state_at(Some(0), first_nov), Outdated);
        assert_eq!(state_at(None, first_nov), Missing);
    }

    #[test]
    fn the_local_check_decides_while_the_online_one_is_off_or_failed() {
        for online in [CheckState::Off, CheckState::Failed] {
            let s = assess(Some((2026, 10)), NOV, online, false);
            assert_eq!(s.state, GeoipFreshnessState::Outdated);
            assert_eq!(s.offer, Some(GeoipOffer::Update));
            assert_eq!(s.built_month.as_deref(), Some("2026-10"));
            assert_eq!(s.current_month, "2026-11");
            assert_eq!(s.published_month, None);

            let s = assess(None, NOV, online, false);
            assert_eq!(s.state, GeoipFreshnessState::Missing);
            assert_eq!(s.offer, Some(GeoipOffer::Download));
            assert_eq!(s.built_month, None);

            assert_eq!(assess(Some(NOV), NOV, online, false).offer, None);
        }
        assert_eq!(
            assess(Some(NOV), NOV, CheckState::Off, false).state,
            GeoipFreshnessState::Current
        );
    }

    #[test]
    fn the_online_check_confirms_or_withdraws_the_offer() {
        // Running: nothing yet.
        assert_eq!(assess(None, NOV, CheckState::Pending, false).offer, None);
        // Current month published.
        let s = assess(Some((2026, 10)), NOV, CheckState::Published(NOV), false);
        assert_eq!(
            (s.online, s.offer),
            (GeoipOnlineCheck::Published, Some(GeoipOffer::Update))
        );
        assert_eq!(s.published_month.as_deref(), Some("2026-11"));
        // Only the previous month published: newer than a September database, not than October's.
        let oct = CheckState::Published((2026, 10));
        assert_eq!(
            assess(Some((2026, 9)), NOV, oct, false).offer,
            Some(GeoipOffer::Update)
        );
        assert_eq!(assess(Some((2026, 10)), NOV, oct, false).offer, None);
        assert_eq!(
            assess(None, NOV, oct, false).offer,
            Some(GeoipOffer::Download)
        );
        // Nothing published: the download would fail.
        let s = assess(None, NOV, CheckState::NotPublished, false);
        assert_eq!((s.online, s.offer), (GeoipOnlineCheck::NotPublished, None));
    }

    #[test]
    fn a_read_only_server_offers_nothing() {
        for online in [
            CheckState::Off,
            CheckState::Failed,
            CheckState::Published(NOV),
        ] {
            let s = assess(None, NOV, online, true);
            assert_eq!(s.state, GeoipFreshnessState::Missing);
            assert_eq!(s.offer, None);
        }
    }

    #[test]
    fn months_are_dismissal_keys() {
        assert_eq!(month_text((2026, 3)), "2026-03");
        assert_eq!(month_text((987, 12)), "0987-12");
    }
}
