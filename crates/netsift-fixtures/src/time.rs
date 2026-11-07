//! Calendar helpers (UTC only, proleptic Gregorian), without a date-time dependency.

/// Nanoseconds per second.
pub const NS_PER_SEC: i64 = 1_000_000_000;
/// Nanoseconds per millisecond.
pub const NS_PER_MS: i64 = 1_000_000;
/// Nanoseconds per microsecond.
pub const NS_PER_US: i64 = 1_000;

/// Broken-down UTC time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UtcTime {
    pub year: i64,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
}

/// Converts seconds since the Unix epoch to a UTC calendar time.
pub fn utc_from_unix(secs: i64) -> UtcTime {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // Howard Hinnant's `civil_from_days`.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    UtcTime {
        year,
        month: small(month),
        day: small(day),
        hour: small(rem / 3600),
        minute: small(rem % 3600 / 60),
        second: small(rem % 60),
    }
}

/// Converts a UTC calendar time to seconds since the Unix epoch.
pub fn unix_from_utc(t: UtcTime) -> i64 {
    // Howard Hinnant's `days_from_civil`.
    let month = i64::from(t.month);
    let year = t.year - i64::from(month <= 2);
    let era = year.div_euclid(400);
    let yoe = year.rem_euclid(400);
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + i64::from(t.day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    days * 86_400 + i64::from(t.hour) * 3600 + i64::from(t.minute) * 60 + i64::from(t.second)
}

/// `YYYYmmddHHMMSS` (UTC) for a nanosecond timestamp, as used in dumpcap/editcap file names.
pub fn compact_timestamp(ts_ns: i64) -> String {
    let t = utc_from_unix(ts_ns.div_euclid(NS_PER_SEC));
    format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}",
        t.year, t.month, t.day, t.hour, t.minute, t.second
    )
}

fn small(v: i64) -> u8 {
    u8::try_from(v).expect("calendar field fits in u8")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_and_known_dates() {
        assert_eq!(compact_timestamp(0), "19700101000000");
        // 2023-11-14T22:13:20Z
        assert_eq!(
            compact_timestamp(1_700_000_000 * NS_PER_SEC + 999),
            "20231114221320"
        );
        // Leap day.
        let t = UtcTime {
            year: 2024,
            month: 2,
            day: 29,
            hour: 23,
            minute: 59,
            second: 59,
        };
        assert_eq!(utc_from_unix(unix_from_utc(t)), t);
        assert_eq!(unix_from_utc(t), 1_709_251_199);
    }

    #[test]
    fn round_trip_over_a_wide_range() {
        let mut s = -2_208_988_800; // 1900-01-01
        while s < 4_102_444_800 {
            // 2100-01-01
            assert_eq!(unix_from_utc(utc_from_unix(s)), s);
            s += 86_400 * 37 + 3_671;
        }
    }
}
