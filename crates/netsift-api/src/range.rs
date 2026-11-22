//! Global time filter (P5.2, ADR-030, `docs/specs/time-filter.md`): the `from_us` / `to_us`
//! parameters of every filtered route, read, validated and normalized here only.
//!
//! Both bounds are microseconds since the Unix epoch, inclusive, each optional (a missing bound
//! is the start or the end of the session). The store receives the half-open range
//! `[from_us * 1000, (to_us + 1) * 1000)` in nanoseconds. A range that covers the whole session
//! is dropped, so that the route answers from its precomputed tables exactly as without filter.
//!
//! The aggregated views (Connections, Open Ports, Servers, Network, and their module counts in
//! `/summary`) read the tables of a range from a range database (`netsift_store::ranges`), built at
//! the first request of the range: [`AggregateRange`] and [`open_view`]. The request waits for the
//! build (ADR-030); the build stops when every request waiting for it is gone (client disconnected).
//! A read-only server writes these databases in a temporary directory of the process, never in the
//! data directory.

use std::path::PathBuf;

use axum::extract::{FromRequestParts, Query};
use axum::http::request::Parts;
use netsift_store::query::get_meta;
use netsift_store::ranges::{CancelFlag, RangeView};
use netsift_store::{Connection, Session, SessionId, SessionInfo, TimeRange};
use serde::Deserialize;

use crate::overview::open_ready;
use crate::{ApiError, AppState};

/// Largest absolute bound accepted, in microseconds: its nanoseconds, plus one microsecond,
/// fit an `i64`.
const MAX_ABS_US: i64 = i64::MAX / 1000 - 1;

/// The two parameters as sent.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
pub(crate) struct RangeParams {
    pub(crate) from_us: Option<i64>,
    pub(crate) to_us: Option<i64>,
}

/// Validated range parameters of a request (400 problem document when invalid). Resolve them
/// against the opened session with [`RangeParams::resolve`].
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct ApiRange(pub(crate) RangeParams);

impl<S: Send + Sync> FromRequestParts<S> for ApiRange {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, ApiError> {
        let Query(params) = Query::<RangeParams>::from_request_parts(parts, state)
            .await
            .map_err(|e| ApiError::BadRequest(e.body_text()))?;
        params.validate()?;
        Ok(Self(params))
    }
}

/// Range parameters of an aggregated view, with the cancellation flag of the request: set when the
/// handler is dropped (client gone), which stops a range build nobody waits for any more.
#[derive(Debug, Default)]
pub(crate) struct AggregateRange {
    pub(crate) params: RangeParams,
    guard: CancelOnDrop,
}

impl AggregateRange {
    /// The flag to give to [`open_view`] (from the blocking task).
    pub(crate) fn flag(&self) -> CancelFlag {
        self.guard.0.clone()
    }
}

#[derive(Debug, Default)]
struct CancelOnDrop(CancelFlag);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

impl<S: Send + Sync> FromRequestParts<S> for AggregateRange {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, ApiError> {
        let ApiRange(params) = ApiRange::from_request_parts(parts, state).await?;
        Ok(Self {
            params,
            guard: CancelOnDrop::default(),
        })
    }
}

/// What an aggregated view reads: the session, or the range database of its range.
pub(crate) enum View {
    Session(Session),
    Range {
        view: RangeView,
        /// Kept open: the session the range database attaches.
        _session: Session,
    },
}

impl View {
    pub(crate) fn conn(&self) -> &Connection {
        match self {
            Self::Session(s) => s.conn(),
            Self::Range { view, .. } => view.conn(),
        }
    }
}

/// Opens a session for an aggregated view ([`open_ready`]) and, under a range that does not cover
/// it, its range database (built first if needed: the call lasts as long as the build).
pub(crate) fn open_view(
    state: &AppState,
    id: &SessionId,
    params: RangeParams,
    cancel: &CancelFlag,
) -> Result<(SessionInfo, View), ApiError> {
    let (info, session) = open_ready(state, id)?;
    let Some(range) = params.resolve(&session)? else {
        return Ok((info, View::Session(session)));
    };
    let view = range_view(state, id, &session, range, cancel)?;
    Ok((
        info,
        View::Range {
            view,
            _session: session,
        },
    ))
}

/// The range database of `range` over `session`.
pub(crate) fn range_view(
    state: &AppState,
    id: &SessionId,
    session: &Session,
    range: TimeRange,
    cancel: &CancelFlag,
) -> Result<RangeView, ApiError> {
    let dir = ranges_dir(state, id, session)?;
    Ok(state.ranges.open(session, &dir, range, cancel)?)
}

/// Directory of the range databases of a session: `sessions/<id>/ranges/` (removed with the
/// session), or a directory of the process for a read-only server.
fn ranges_dir(state: &AppState, id: &SessionId, session: &Session) -> Result<PathBuf, ApiError> {
    if !state.config.read_only {
        return Ok(session.dir().join(RANGES_DIR));
    }
    let scratch = state
        .range_scratch
        .get_or_init(
            || match tempfile::Builder::new().prefix("netsift-ranges-").tempdir() {
                Ok(dir) => Some(dir),
                Err(e) => {
                    tracing::error!("cannot create the directory of the time ranges: {e}");
                    None
                }
            },
        )
        .as_ref()
        .ok_or(ApiError::Internal)?;
    Ok(scratch.path().join(id.as_str()))
}

/// Name of the directory of the range databases inside a session directory.
pub(crate) const RANGES_DIR: &str = "ranges";

impl RangeParams {
    fn validate(self) -> Result<(), ApiError> {
        for v in [self.from_us, self.to_us].into_iter().flatten() {
            if v.checked_abs().is_none_or(|a| a > MAX_ABS_US) {
                return Err(ApiError::BadRequest("range: out of bounds".to_owned()));
            }
        }
        if let (Some(from), Some(to)) = (self.from_us, self.to_us)
            && to < from
        {
            return Err(ApiError::BadRequest(
                "range: the end is before the start".to_owned(),
            ));
        }
        Ok(())
    }

    /// True when no bound was sent.
    pub(crate) fn is_empty(self) -> bool {
        self.from_us.is_none() && self.to_us.is_none()
    }

    /// The range in nanoseconds, before normalization (`None` without bound).
    pub(crate) fn raw(self) -> Option<TimeRange> {
        if self.is_empty() {
            return None;
        }
        // Validated: no overflow.
        let from = self.from_us.map_or(i64::MIN, |us| us.saturating_mul(1000));
        let to = self
            .to_us
            .map_or(i64::MAX, |us| us.saturating_add(1).saturating_mul(1000));
        TimeRange::new(from, to)
    }

    /// The range to apply to `session`: `None` without bound, or when it covers the captured
    /// period of the session (end-of-import statistics in `meta`; a session without them is
    /// never normalized).
    pub(crate) fn resolve(self, session: &Session) -> Result<Option<TimeRange>, ApiError> {
        let Some(range) = self.raw() else {
            return Ok(None);
        };
        let conn = session.conn();
        let bound = |key: &str| -> Result<Option<i64>, ApiError> {
            Ok(get_meta(conn, key)?.and_then(|v| v.parse::<i64>().ok()))
        };
        if let (Some(first), Some(last)) = (bound("stats.first_ts")?, bound("stats.last_ts")?)
            && range.covers(first, last)
        {
            return Ok(None);
        }
        Ok(Some(range))
    }
}

#[cfg(test)]
mod aggregate_tests;
#[cfg(test)]
mod equivalence_tests;
#[cfg(test)]
mod tests;
