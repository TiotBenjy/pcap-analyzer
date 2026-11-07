//! File-name patterns of chunked captures (pure string functions, no I/O).
//!
//! Patterns, by priority (see `docs/CHUNKED_CAPTURES.md`):
//! 1. dumpcap default: `prefix_NNNNN_YYYYmmddHHMMSS.ext[.gz]`;
//! 2. dumpcap `-b nametimenum:2`: `prefix_YYYYmmddHHMMSS_NNNNN.ext[.gz]`;
//! 3. tcpdump `-C`: `name`, `name1`, `name2`, ... (optionally `.gz`);
//! 4. fallback: common prefix, i.e. the name up to its first digit.

/// Length of a dumpcap `YYYYmmddHHMMSS` timestamp.
const TS_DIGITS: usize = 14;
/// Minimum width of a dumpcap sequence number (wider when it exceeds 99 999).
const MIN_SEQ_DIGITS: usize = 5;

/// A file name recognized as a dumpcap chunk (patterns 1 and 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DumpcapName {
    pub(crate) prefix: String,
    pub(crate) seq: u64,
}

/// Strips a trailing `.gz` (any case), when something remains before it.
fn strip_gz(name: &str) -> Option<&str> {
    let cut = name.len().checked_sub(3)?;
    let (head, tail) = (name.get(..cut)?, name.get(cut..)?);
    (tail.eq_ignore_ascii_case(".gz") && !head.is_empty()).then_some(head)
}

fn all_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// Parses a decimal sequence number; `None` when not all digits or too large for `u64`.
fn parse_seq(s: &str) -> Option<u64> {
    if all_digits(s) { s.parse().ok() } else { None }
}

/// Candidate stems (name without its last extension), with and without a `.gz` suffix, mirroring
/// `\.(?P<ext>[^.]+)(\.gz)?$`.
fn stems(name: &str) -> impl Iterator<Item = &str> {
    let gz = strip_gz(name);
    gz.into_iter().chain(std::iter::once(name)).filter_map(|n| {
        let (stem, ext) = n.rsplit_once('.')?;
        (!ext.is_empty() && !stem.is_empty()).then_some(stem)
    })
}

/// Pattern 1: `prefix_NNNNN_YYYYmmddHHMMSS.ext[.gz]`.
pub(crate) fn parse_dumpcap(name: &str) -> Option<DumpcapName> {
    stems(name).find_map(|stem| {
        let (rest, ts) = stem.rsplit_once('_')?;
        let (prefix, num) = rest.rsplit_once('_')?;
        if prefix.is_empty() || ts.len() != TS_DIGITS || !all_digits(ts) {
            return None;
        }
        if num.len() < MIN_SEQ_DIGITS {
            return None;
        }
        Some(DumpcapName {
            prefix: prefix.to_owned(),
            seq: parse_seq(num)?,
        })
    })
}

/// Pattern 2: `prefix_YYYYmmddHHMMSS_NNNNN.ext[.gz]`.
pub(crate) fn parse_nametimenum(name: &str) -> Option<DumpcapName> {
    stems(name).find_map(|stem| {
        let (rest, num) = stem.rsplit_once('_')?;
        let (prefix, ts) = rest.rsplit_once('_')?;
        if prefix.is_empty() || ts.len() != TS_DIGITS || !all_digits(ts) {
            return None;
        }
        if num.len() < MIN_SEQ_DIGITS {
            return None;
        }
        Some(DumpcapName {
            prefix: prefix.to_owned(),
            seq: parse_seq(num)?,
        })
    })
}

/// Pattern 3 (tcpdump `-C`): splits `name` into its base and trailing number.
///
/// `cap.pcap3` -> (`cap.pcap`, Some(3)); `cap.pcap` -> (`cap.pcap`, None). A `.gz` suffix is
/// ignored. Returns `None` when the trailing number does not fit in `u64`.
pub(crate) fn split_rotation(name: &str) -> Option<(&str, Option<u64>)> {
    let name = strip_gz(name).unwrap_or(name);
    let base = name.trim_end_matches(|c: char| c.is_ascii_digit());
    if base.is_empty() {
        return None;
    }
    let digits = name.get(base.len()..)?;
    if digits.is_empty() {
        Some((base, None))
    } else {
        Some((base, Some(parse_seq(digits)?)))
    }
}

/// Fallback grouping key: the name without extension, cut at its first digit, trailing
/// separators trimmed (`cap-20240101-1200.pcap` -> `cap`, `trace7.pcapng.gz` -> `trace`).
pub(crate) fn common_prefix_key(name: &str) -> &str {
    let name = strip_gz(name).unwrap_or(name);
    let stem = match name.rsplit_once('.') {
        Some((stem, _)) if !stem.is_empty() => stem,
        _ => name,
    };
    let cut = stem
        .find(|c: char| c.is_ascii_digit())
        .unwrap_or(stem.len());
    stem.get(..cut)
        .unwrap_or(stem)
        .trim_end_matches(['-', '_', '.', ' '])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(clippy::unnecessary_wraps)]
    fn dc(prefix: &str, seq: u64) -> Option<DumpcapName> {
        Some(DumpcapName {
            prefix: prefix.into(),
            seq,
        })
    }

    #[test]
    fn dumpcap_default_names() {
        assert_eq!(
            parse_dumpcap("cap_00001_20240101120000.pcapng"),
            dc("cap", 1)
        );
        assert_eq!(
            parse_dumpcap("my_cap_file_00042_20240101120000.pcap.gz"),
            dc("my_cap_file", 42)
        );
        assert_eq!(
            parse_dumpcap("cap_123456_20240101120000.pcapng"),
            dc("cap", 123_456)
        );
        // `.gz` alone is the extension.
        assert_eq!(parse_dumpcap("cap_00007_20240101120000.gz"), dc("cap", 7));
        assert_eq!(parse_dumpcap("cap_0001_20240101120000.pcapng"), None);
        assert_eq!(parse_dumpcap("cap_00001_2024010112000.pcapng"), None);
        assert_eq!(parse_dumpcap("cap_00001_20240101120000"), None);
        assert_eq!(parse_dumpcap("_00001_20240101120000.pcap"), None);
        assert_eq!(parse_dumpcap("cap_20240101120000_00001.pcap"), None);
        // Sequence number too large for u64: not a match.
        assert_eq!(
            parse_dumpcap("cap_123456789012345678901234_20240101120000.pcap"),
            None
        );
    }

    #[test]
    fn dumpcap_nametimenum_names() {
        assert_eq!(
            parse_nametimenum("cap_20240101120000_00001.pcapng"),
            dc("cap", 1)
        );
        assert_eq!(
            parse_nametimenum("a_b_20240101120000_100000.pcapng.GZ"),
            dc("a_b", 100_000)
        );
        assert_eq!(parse_nametimenum("cap_00001_20240101120000.pcapng"), None);
    }

    #[test]
    fn tcpdump_rotation_names() {
        assert_eq!(split_rotation("cap.pcap"), Some(("cap.pcap", None)));
        assert_eq!(split_rotation("cap.pcap12"), Some(("cap.pcap", Some(12))));
        assert_eq!(split_rotation("cap.pcap03.gz"), Some(("cap.pcap", Some(3))));
        assert_eq!(split_rotation("trace"), Some(("trace", None)));
        assert_eq!(split_rotation("12345"), None);
        assert_eq!(split_rotation("x99999999999999999999999"), None);
    }

    #[test]
    fn prefix_keys() {
        assert_eq!(common_prefix_key("cap-20240101-1200.pcap"), "cap");
        assert_eq!(common_prefix_key("trace7.pcapng.gz"), "trace");
        assert_eq!(common_prefix_key("eth0.pcap"), "eth");
        assert_eq!(common_prefix_key("20240101.pcap"), "");
        assert_eq!(common_prefix_key("plain.pcap"), "plain");
        assert_eq!(common_prefix_key("noext"), "noext");
        assert_eq!(common_prefix_key(".hidden"), ".hidden");
    }

    #[test]
    fn strip_gz_keeps_bare_gz() {
        assert_eq!(strip_gz(".gz"), None);
        assert_eq!(strip_gz("a.gz"), Some("a"));
        assert_eq!(strip_gz("a.pcap"), None);
        // Multi-byte names never split inside a character.
        assert_eq!(strip_gz("é"), None);
        assert_eq!(split_rotation("éé1"), Some(("éé", Some(1))));
    }
}
