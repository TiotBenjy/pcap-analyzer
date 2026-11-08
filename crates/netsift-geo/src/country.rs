//! ISO 3166-1 alpha-2 country codes.

use std::fmt;

/// An ISO 3166-1 alpha-2 country code: two upper-case ASCII letters (`"FR"`).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CountryCode([u8; 2]);

impl CountryCode {
    /// Parses two ASCII letters (any case, stored upper case). Anything else is `None`.
    pub fn new(code: &str) -> Option<Self> {
        match code.as_bytes() {
            &[a, b] if a.is_ascii_alphabetic() && b.is_ascii_alphabetic() => {
                Some(Self([a.to_ascii_uppercase(), b.to_ascii_uppercase()]))
            }
            _ => None,
        }
    }

    /// The code, e.g. `"FR"`.
    pub fn as_str(&self) -> &str {
        // Always two ASCII letters by construction.
        std::str::from_utf8(&self.0).unwrap_or("")
    }
}

impl fmt::Display for CountryCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Debug for CountryCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CountryCode({})", self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_two_letters_only() {
        assert_eq!(
            CountryCode::new("FR").map(|c| c.to_string()),
            Some("FR".into())
        );
        assert_eq!(
            CountryCode::new("de").map(|c| c.to_string()),
            Some("DE".into())
        );
        for bad in ["", "F", "FRA", "F1", "  ", "é"] {
            assert_eq!(CountryCode::new(bad), None, "{bad:?}");
        }
        assert_eq!(
            format!("{:?}", CountryCode::new("us").unwrap()),
            "CountryCode(US)"
        );
    }
}
