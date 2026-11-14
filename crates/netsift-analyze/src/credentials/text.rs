//! Shared helpers of the credential emitters: bounded line splitting, bounded strings, base64.
//!
//! Captures are hostile input: lines and values are bounded, nothing is sized from a length
//! read on the wire, and every decoding failure yields `None` rather than a guess.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

/// Longest command or reply line kept (RFC 4954 allows 12 288 bytes for a SASL response; real
/// authentication lines are far shorter). Longer lines are skipped up to their end.
pub(crate) const MAX_LINE: usize = 4096;
/// Longest identity (user, domain, DN) kept, in characters.
pub(crate) const MAX_IDENTITY: usize = 256;
/// Longest secret kept, in characters.
pub(crate) const MAX_SECRET: usize = 512;

/// Splits a byte stream into lines (`\n`, optional `\r`), bounded by [`MAX_LINE`].
#[derive(Debug, Default)]
pub(crate) struct LineBuf {
    buf: Vec<u8>,
    /// The current line overflowed: its bytes are dropped up to the next `\n`.
    skipping: bool,
}

impl LineBuf {
    /// Appends `data` and returns the lines it completes, without their terminator.
    pub(crate) fn push(&mut self, mut data: &[u8]) -> Vec<Vec<u8>> {
        let mut lines = Vec::new();
        while !data.is_empty() {
            let (piece, rest, ends) = match data.iter().position(|&b| b == b'\n') {
                Some(i) => (
                    data.get(..i).unwrap_or_default(),
                    data.get(i + 1..).unwrap_or_default(),
                    true,
                ),
                None => (data, &[][..], false),
            };
            data = rest;
            if !self.skipping {
                if self.buf.len() + piece.len() > MAX_LINE {
                    self.buf.clear();
                    self.skipping = true;
                } else {
                    self.buf.extend_from_slice(piece);
                }
            }
            if ends {
                if !self.skipping {
                    let mut line = std::mem::take(&mut self.buf);
                    if line.last() == Some(&b'\r') {
                        line.pop();
                    }
                    lines.push(line);
                }
                self.buf.clear();
                self.skipping = false;
            }
        }
        lines
    }

    /// Bytes are missing before the next data: the partial line is dropped.
    pub(crate) fn reset(&mut self) {
        self.buf.clear();
        self.skipping = true;
    }
}

/// UTF-8 (lossy) text of `bytes`, cut to `max` characters.
pub(crate) fn bounded(bytes: &[u8], max: usize) -> String {
    String::from_utf8_lossy(bytes).chars().take(max).collect()
}

/// `s` cut to `max` characters.
pub(crate) fn clip(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

/// Standard base64 (padding optional, surrounding whitespace ignored), bounded input.
pub(crate) fn base64(text: &str) -> Option<Vec<u8>> {
    let text = text.trim();
    if text.is_empty() || text.len() > MAX_LINE * 2 {
        return None;
    }
    STANDARD.decode(text).ok().or_else(|| {
        // Some clients omit the padding.
        let padded = format!("{text}{}", "=".repeat((4 - text.len() % 4) % 4));
        STANDARD.decode(padded).ok()
    })
}

/// Splits `s` at the first ASCII whitespace: (first word, trimmed rest).
pub(crate) fn split_word(s: &str) -> (&str, &str) {
    match s.find(|c: char| c.is_ascii_whitespace()) {
        Some(i) => (
            s.get(..i).unwrap_or_default(),
            s.get(i..).unwrap_or_default().trim(),
        ),
        None => (s, ""),
    }
}

/// Lower-case hexadecimal.
pub(crate) fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_are_split_and_bounded() {
        let mut lb = LineBuf::default();
        assert_eq!(lb.push(b"USER al"), Vec::<Vec<u8>>::new());
        assert_eq!(
            lb.push(b"ice\r\nPASS x\nQU"),
            vec![b"USER alice".to_vec(), b"PASS x".to_vec()]
        );
        assert_eq!(lb.push(b"IT\r\n"), vec![b"QUIT".to_vec()]);
        // An overlong line is skipped entirely, the next one is kept.
        let long = vec![b'a'; MAX_LINE + 10];
        assert_eq!(lb.push(&long), Vec::<Vec<u8>>::new());
        assert_eq!(lb.push(b"tail\r\nNOOP\r\n"), vec![b"NOOP".to_vec()]);
        // After a gap the partial line is dropped.
        assert_eq!(lb.push(b"PAS"), Vec::<Vec<u8>>::new());
        lb.reset();
        assert_eq!(lb.push(b"S y\r\nNOOP\r\n"), vec![b"NOOP".to_vec()]);
    }

    #[test]
    fn base64_tolerates_missing_padding() {
        assert_eq!(base64("ZGVtbzpkZW1vLW9ubHk=").unwrap(), b"demo:demo-only");
        assert_eq!(base64("YQ").unwrap(), b"a");
        assert!(base64("***").is_none());
        assert!(base64("").is_none());
    }

    #[test]
    fn words_and_clipping() {
        assert_eq!(split_word("AUTH  PLAIN abc"), ("AUTH", "PLAIN abc"));
        assert_eq!(split_word("QUIT"), ("QUIT", ""));
        assert_eq!(clip("élodie", 3), "élo");
        assert_eq!(bounded(b"a\xffb", 10), "a\u{fffd}b");
    }
}
