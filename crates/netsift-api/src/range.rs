//! Global time filter (P5.2, ADR-030, `docs/specs/time-filter.md`): the `from_us` / `to_us`
//! parameters of every filtered route, read, validated and normalized here only.
//!
//! Both bounds are microseconds since the Unix epoch, inclusive, each optional (a missing bound
//! is the start or the end of the session). The store receives the half-open range
//! `[from_us * 1000, (to_us + 1) * 1000)` in nanoseconds. A range that covers the whole session
//! is dropped, so that the route answers from its precomputed tables exactly as without filter.

use axum::extract::{FromRequestParts, Query};
use axum::http::request::Parts;
use netsift_store::query::get_meta;
use netsift_store::{Session, TimeRange};
use serde::Deserialize;

use crate::ApiError;

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
mod tests;
