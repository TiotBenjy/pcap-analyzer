//! Line splitting and sanitizing of the FTP control connection.
//!
//! Lines end with `\n` (an optional `\r` is removed). Only the first [`MAX_LINE`] bytes of a line
//! are kept; the rest is dropped up to the end of the line, which is then marked truncated.
//! `Debug` of [`Lines`] never shows the buffered bytes (they may hold a password).

/// Bytes kept per line.
pub const MAX_LINE: usize = 1024;

/// Splits a byte stream into bounded lines.
#[derive(Default)]
pub struct Lines {
    buf: Vec<u8>,
    /// The current line is longer than [`MAX_LINE`].
    truncated: bool,
}

impl std::fmt::Debug for Lines {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Lines")
            .field("buffered", &self.buf.len())
            .field("truncated", &self.truncated)
            .finish()
    }
}

impl Lines {
    /// Appends `data` and calls `line(bytes, truncated)` for each line it completes.
    pub fn push(&mut self, mut data: &[u8], line: &mut dyn FnMut(&[u8], bool)) {
        while !data.is_empty() {
            let (piece, rest, ends) = match data.iter().position(|&b| b == b'\n') {
                Some(i) => (
                    data.get(..i).unwrap_or_default(),
                    data.get(i.saturating_add(1)..).unwrap_or_default(),
                    true,
                ),
                None => (data, &[][..], false),
            };
            data = rest;
            let room = MAX_LINE.saturating_sub(self.buf.len());
            if piece.len() > room {
                self.buf
                    .extend_from_slice(piece.get(..room).unwrap_or_default());
                self.truncated = true;
            } else {
                self.buf.extend_from_slice(piece);
            }
            if ends {
                self.emit(line);
            }
        }
    }

    /// Calls `line` for a last line without terminator (end of the connection), if any.
    pub fn flush(&mut self, line: &mut dyn FnMut(&[u8], bool)) {
        if !self.buf.is_empty() || self.truncated {
            self.emit(line);
        }
    }

    /// Bytes are missing before the next data: the partial line is dropped.
    pub fn reset(&mut self) {
        self.buf.clear();
        self.truncated = false;
    }

    fn emit(&mut self, line: &mut dyn FnMut(&[u8], bool)) {
        if !self.truncated && self.buf.last() == Some(&b'\r') {
            self.buf.pop();
        }
        line(&self.buf, self.truncated);
        self.buf.clear();
        self.truncated = false;
    }
}

/// Invisible or bidirectional formatting characters, replaced like control characters so that a
/// stored text cannot reorder or hide what the UI shows.
fn is_format(c: char) -> bool {
    matches!(
        c,
        '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{FEFF}'
    )
}

/// Lossy UTF-8 text of `bytes` with control and formatting characters (except tab) replaced by
/// U+FFFD, cut to `max` characters; the flag tells whether it was cut.
pub fn clean(bytes: &[u8], max: usize) -> (String, bool) {
    let text = String::from_utf8_lossy(bytes);
    let mut out = String::with_capacity(text.len().min(max.saturating_mul(4)));
    let mut cut = false;
    for (n, c) in text.chars().enumerate() {
        if n >= max {
            cut = true;
            break;
        }
        out.push(if (c.is_control() && c != '\t') || is_format(c) {
            char::REPLACEMENT_CHARACTER
        } else {
            c
        });
    }
    (out, cut)
}

/// [`clean`] of a multi-line text (listings): line ends are kept as `\n`, `\r` removed.
pub fn clean_block(bytes: &[u8], max: usize) -> String {
    let text = String::from_utf8_lossy(bytes);
    text.chars()
        .filter(|c| *c != '\r')
        .take(max)
        .map(|c| {
            if (c.is_control() && c != '\t' && c != '\n') || is_format(c) {
                char::REPLACEMENT_CHARACTER
            } else {
                c
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(chunks: &[&[u8]]) -> Vec<(String, bool)> {
        let mut l = Lines::default();
        let mut out = Vec::new();
        for c in chunks {
            l.push(c, &mut |b, t| {
                out.push((String::from_utf8_lossy(b).into_owned(), t));
            });
        }
        l.flush(&mut |b, t| out.push((String::from_utf8_lossy(b).into_owned(), t)));
        out
    }

    #[test]
    fn splits_across_chunks_and_bounds_lines() {
        assert_eq!(
            lines(&[b"USER al", b"ice\r\nPASS x\r", b"\nQUIT"]),
            vec![
                ("USER alice".to_owned(), false),
                ("PASS x".to_owned(), false),
                ("QUIT".to_owned(), false)
            ]
        );
        let long = vec![b'a'; MAX_LINE + 10];
        let got = lines(&[&long, b"bbb\nnext\n"]);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].0.len(), MAX_LINE);
        assert!(got[0].1);
        assert_eq!(got[1], ("next".to_owned(), false));
        assert_eq!(lines(&[b"\n"]), vec![(String::new(), false)]);
    }

    #[test]
    fn reset_drops_the_partial_line() {
        let mut l = Lines::default();
        let mut out = Vec::new();
        l.push(b"PASS sec", &mut |b, _| out.push(b.to_vec()));
        assert!(!format!("{l:?}").contains("sec"));
        l.reset();
        l.push(b"ret\nNOOP\n", &mut |b, _| out.push(b.to_vec()));
        assert_eq!(out, vec![b"ret".to_vec(), b"NOOP".to_vec()]);
    }

    #[test]
    fn cleaning_replaces_controls_and_bidi() {
        let (s, cut) = clean(b"a\x00b\x1b[31m\tc\xe2\x80\xaed\xff", 100);
        assert_eq!(s, "a\u{FFFD}b\u{FFFD}[31m\tc\u{FFFD}d\u{FFFD}");
        assert!(!cut);
        assert_eq!(
            clean("\u{e9}t\u{e9}".as_bytes(), 2),
            ("\u{e9}t".to_owned(), true)
        );
        assert_eq!(clean_block(b"a\r\nb\x07\n", 10), "a\nb\u{FFFD}\n");
    }
}
