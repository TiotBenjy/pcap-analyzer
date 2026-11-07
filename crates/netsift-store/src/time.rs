//! Wall-clock helpers (catalog dates only: packet data never uses the wall clock).

use std::time::{SystemTime, UNIX_EPOCH};

/// Current wall-clock time in nanoseconds since the Unix epoch (UTC), saturating.
pub(crate) fn now_ns() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_nanos()).unwrap_or(i64::MAX))
}
