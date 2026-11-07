//! Session identifiers: ULIDs (48-bit millisecond timestamp + 80 random bits, Crockford base32).
//!
//! Lexicographic order of the text form equals creation order (to the millisecond). The id is
//! also a directory name, so parsing is strict: exactly 26 upper-case Crockford characters,
//! which rules out any path traversal.

use std::fmt;
use std::hash::{BuildHasher, RandomState};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::StoreError;

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const LEN: usize = 26;

/// Identifier of a session, also the name of its directory under `sessions/`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SessionId(String);

impl SessionId {
    /// Generates a new identifier from the wall clock and process-local randomness.
    pub fn generate() -> Self {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        Self::from_parts(now_ms, random_u128())
    }

    /// Builds an id from a millisecond timestamp (low 48 bits) and randomness (low 80 bits).
    pub fn from_parts(timestamp_ms: u64, random: u128) -> Self {
        let value =
            (u128::from(timestamp_ms & 0xFFFF_FFFF_FFFF) << 80) | (random & ((1u128 << 80) - 1));
        let mut out = String::with_capacity(LEN);
        for i in (0..LEN).rev() {
            // 26 x 5 bits = 130 bits: the two top bits are always zero.
            let digit = (value >> (i * 5)) & 0x1F;
            out.push(char::from(ALPHABET[usize::try_from(digit).unwrap_or(0)]));
        }
        Self(out)
    }

    /// Text form (26 characters).
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for SessionId {
    type Err = StoreError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let valid = s.len() == LEN
            && s.bytes().all(|b| ALPHABET.contains(&b))
            // The first character carries only 3 bits (48-bit timestamp, 130-bit text form).
            && s.as_bytes().first().is_some_and(|b| *b <= b'7');
        if valid {
            Ok(Self(s.to_owned()))
        } else {
            Err(StoreError::InvalidSessionId)
        }
    }
}

/// 128 bits from the standard library's randomly keyed `SipHash` (OS-seeded per process).
/// Not cryptographic, which is fine for identifiers whose uniqueness is enforced by the
/// catalog's primary key.
fn random_u128() -> u128 {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    let hi = RandomState::new().hash_one((n, nanos, 0u8));
    let lo = RandomState::new().hash_one((n, nanos, 1u8));
    (u128::from(hi) << 64) | u128::from(lo)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_ids_parse_and_are_unique() {
        let ids: Vec<SessionId> = (0..1000).map(|_| SessionId::generate()).collect();
        let mut set = std::collections::HashSet::new();
        for id in &ids {
            assert_eq!(id.as_str().parse::<SessionId>().unwrap(), *id);
            assert!(set.insert(id.clone()));
        }
    }

    #[test]
    fn ids_sort_by_timestamp() {
        let a = SessionId::from_parts(1_000, u128::MAX);
        let b = SessionId::from_parts(1_001, 0);
        assert!(a < b);
        assert!(a.as_str() < b.as_str());
        assert_eq!(
            SessionId::from_parts(0, 0).as_str(),
            "00000000000000000000000000"
        );
        assert_eq!(
            SessionId::from_parts(u64::MAX, u128::MAX).as_str(),
            "7ZZZZZZZZZZZZZZZZZZZZZZZZZ"
        );
    }

    #[test]
    fn rejects_hostile_ids() {
        for bad in [
            "",
            "..",
            "../../etc/passwd",
            "01ARZ3NDEKTSV4RRFFQ69G5FA",   // 25 chars
            "01ARZ3NDEKTSV4RRFFQ69G5FAVV", // 27 chars
            "01arz3ndektsv4rrffq69g5fav",  // lower case
            "01ARZ3NDEKTSV4RRFFQ69G5FI0",  // I is not Crockford
            "81ARZ3NDEKTSV4RRFFQ69G5FAV",  // overflows 128 bits
            "01ARZ3NDEKTSV4RRFFQ69G5F/V",
        ] {
            assert!(bad.parse::<SessionId>().is_err(), "{bad}");
        }
        assert!("01ARZ3NDEKTSV4RRFFQ69G5FAV".parse::<SessionId>().is_ok());
    }
}
