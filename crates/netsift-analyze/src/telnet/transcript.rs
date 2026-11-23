//! Display transcript of a Telnet session: NVT normalization of each direction, server echoes
//! merged with the client's typing, bounded text.
//!
//! - [`Nvt`] turns the data bytes of one direction (after the `IAC` layer) into [`Token`]s: line
//!   ends normalized, ANSI/VT escape sequences removed, erase keys recognized, other control
//!   characters rendered in caret notation (client) or dropped (server).
//! - [`Echo`] remembers what the client typed until the server echoes it, so the echo is
//!   absorbed instead of being shown twice.
//! - [`Transcript`] keeps the text as runs of one [`Speaker`], bounded by [`MAX_BYTES`],
//!   [`MAX_LINES`] and [`MAX_RUNS`].

use std::collections::VecDeque;

use super::{Speaker, TranscriptRun};

/// Longest transcript kept per session, in bytes.
pub const MAX_BYTES: usize = 64 * 1024;
/// Most lines kept per session.
pub const MAX_LINES: u32 = 2000;
/// Most runs (changes of speaker) kept per session.
pub const MAX_RUNS: usize = 8192;
/// Most typed elements waiting for their echo.
pub const MAX_ECHO: usize = 512;
/// An escape sequence longer than this is abandoned (its bytes are dropped).
const MAX_ESCAPE: u16 = 256;

/// One display element of a direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Token {
    /// A byte to show (printable ASCII, tab, or part of a UTF-8 sequence).
    Char(u8),
    Newline,
    /// Erase the previous character (`BS`, `DEL`, `IAC EC`).
    Erase,
    /// Erase the client's input on the current line (`^U`, `IAC EL`).
    EraseLine,
    /// Erase the client's last typed word (`^W`).
    EraseWord,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Escape {
    #[default]
    None,
    /// After `ESC` (and possibly intermediate bytes).
    Esc,
    /// Control sequence `ESC [`, up to its final byte.
    Csi,
    /// String (`OSC`, `DCS`, `PM`, `APC`, `SOS`), up to `BEL` or `ESC \`.
    Str,
    /// `ESC` inside a string.
    StrEsc,
}

/// NVT normalization of one direction (see the module documentation).
#[derive(Debug, Clone, Default)]
pub(crate) struct Nvt {
    /// The previous byte was a `CR` (a following `LF`, `NUL` or `CR` adds no line).
    cr: bool,
    escape: Escape,
    escape_len: u16,
}

impl Nvt {
    /// Bytes are missing: escape and line-end state are dropped.
    pub(crate) fn reset(&mut self) {
        *self = Self::default();
    }

    /// Normalizes one data byte; `client` selects the rules of the client's direction.
    pub(crate) fn push(&mut self, byte: u8, client: bool, out: &mut impl FnMut(Token)) {
        if self.escape != Escape::None {
            self.escape_byte(byte);
            return;
        }
        if self.cr {
            if matches!(byte, b'\n' | 0 | b'\r') {
                // `CR LF`, `CR NUL` and `CR CR LF` are one line end; `NUL` ends the pair.
                self.cr = byte == b'\r';
                return;
            }
            self.cr = false;
        }
        match byte {
            0x1b => {
                self.escape = Escape::Esc;
                self.escape_len = 0;
            }
            b'\r' => {
                self.cr = true;
                out(Token::Newline);
            }
            b'\n' => out(Token::Newline),
            b'\t' => out(Token::Char(b'\t')),
            0x08 | 0x7f => out(Token::Erase),
            0x15 if client => out(Token::EraseLine),
            0x17 if client => out(Token::EraseWord),
            0x00..=0x1f => {
                if client {
                    out(Token::Char(b'^'));
                    out(Token::Char(byte | 0x40));
                }
            }
            _ => out(Token::Char(byte)),
        }
    }

    fn escape_byte(&mut self, byte: u8) {
        self.escape_len = self.escape_len.saturating_add(1);
        self.escape = match (self.escape, byte) {
            _ if self.escape_len > MAX_ESCAPE => Escape::None,
            (Escape::Esc, b'[') => Escape::Csi,
            // Intermediate bytes (`ESC ( B`...) precede the final byte.
            (Escape::Esc, 0x20..=0x2f) => Escape::Esc,
            (Escape::Csi, 0x40..=0x7e) | (Escape::Str, 0x07) | (Escape::StrEsc, b'\\') => {
                Escape::None
            }
            (Escape::Str, 0x1b) => Escape::StrEsc,
            (Escape::Esc, b']' | b'P' | b'X' | b'^' | b'_') | (Escape::StrEsc, _) => Escape::Str,
            (Escape::Csi | Escape::Str, _) => self.escape,
            (Escape::Esc | Escape::None, _) => Escape::None,
        };
    }
}

/// What the server is expected to echo next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expect {
    /// A character, typed at a password prompt when `secret` (its echo is rarely sent).
    Char {
        byte: u8,
        secret: bool,
    },
    Newline,
    Erase,
}

/// Echo matching (see the module documentation). `Debug` shows the queue length only: it may
/// hold a password being typed.
#[derive(Default)]
pub(crate) struct Echo {
    queue: VecDeque<Expect>,
    /// Progress in the `BS SP BS` echo of an erase: 1 after the first `BS`, 2 after the space.
    erase_tail: u8,
}

impl std::fmt::Debug for Echo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Echo")
            .field("pending", &self.queue.len())
            .finish_non_exhaustive()
    }
}

impl Echo {
    /// The client typed `token` (at a password prompt when `secret`).
    pub(crate) fn typed(&mut self, token: Token, secret: bool) {
        let expect = match token {
            Token::Char(byte) => Expect::Char { byte, secret },
            Token::Newline => Expect::Newline,
            Token::Erase => Expect::Erase,
            Token::EraseLine | Token::EraseWord => {
                // Their echo depends on the line discipline: not predicted.
                self.clear();
                return;
            }
        };
        if self.queue.len() >= MAX_ECHO {
            self.queue.pop_front();
        }
        self.queue.push_back(expect);
    }

    /// The server sent `token`: `true` when it is the echo of the client's typing (absorbed).
    pub(crate) fn absorbs(&mut self, token: Token) -> bool {
        match (self.erase_tail, token) {
            (1, Token::Char(b' ')) => {
                self.erase_tail = 2;
                return true;
            }
            (2, Token::Erase) => {
                self.erase_tail = 0;
                return true;
            }
            _ => self.erase_tail = 0,
        }
        // A password is usually not echoed: its characters are skipped when the server sends
        // something else (typically the line end).
        while let Some(Expect::Char { byte, secret: true }) = self.queue.front()
            && token != Token::Char(*byte)
        {
            self.queue.pop_front();
        }
        let matched = match (self.queue.front(), token) {
            (Some(Expect::Char { byte, .. }), Token::Char(b)) => *byte == b,
            (Some(Expect::Newline), Token::Newline) => true,
            (Some(Expect::Erase), Token::Erase) => {
                self.erase_tail = 1;
                true
            }
            (None, _) => return false,
            _ => false,
        };
        if matched {
            self.queue.pop_front();
        } else {
            // The server does not echo (or shows something else): stop expecting.
            self.clear();
        }
        matched
    }

    pub(crate) fn clear(&mut self) {
        self.queue.clear();
        self.erase_tail = 0;
    }

    /// The characters still expected belong to a password (their echo is rarely sent).
    pub(crate) fn secret_pending(&mut self) {
        for e in &mut self.queue {
            if let Expect::Char { secret, .. } = e {
                *secret = true;
            }
        }
    }
}

/// The bounded transcript of a session. `Debug` shows sizes only.
#[derive(Default)]
pub(crate) struct Transcript {
    text: Vec<u8>,
    /// `(start offset in text, speaker)`, in order; a run ends where the next one starts.
    runs: Vec<(usize, Speaker)>,
    /// Offset of the first byte of the current line.
    line_start: usize,
    lines: u32,
    truncated: bool,
    /// Largest size the text reached (at most [`MAX_BYTES`]), charged to the shard budget: text
    /// typed again after an erase costs nothing more.
    pub(crate) charged: usize,
}

impl std::fmt::Debug for Transcript {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Transcript")
            .field("bytes", &self.text.len())
            .field("runs", &self.runs.len())
            .field("lines", &self.lines)
            .field("truncated", &self.truncated)
            .finish_non_exhaustive()
    }
}

/// Characters never kept in the text: C1 controls and bidirectional overrides and isolates
/// (they would reorder the displayed text).
fn hidden(c: char) -> bool {
    matches!(c, '\u{80}'..='\u{9f}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

impl Transcript {
    pub(crate) fn truncated(&self) -> bool {
        self.truncated
    }

    pub(crate) fn len(&self) -> usize {
        self.text.len()
    }

    /// The client's text in `from..to` is a password: its client runs become secret.
    pub(crate) fn relabel_secret(&mut self, from: usize, to: usize) {
        let to = to.min(self.text.len());
        if from >= to {
            return;
        }
        self.split_run(to);
        self.split_run(from);
        for (start, speaker) in &mut self.runs {
            if *start >= from && *start < to && *speaker == Speaker::Client {
                *speaker = Speaker::Secret;
            }
        }
    }

    /// Makes a run start at `pos` (inside the text), splitting the run that covers it.
    fn split_run(&mut self, pos: usize) {
        if pos >= self.text.len() {
            return;
        }
        let Some(idx) = self.runs.iter().rposition(|(start, _)| *start <= pos) else {
            return;
        };
        if let Some(&(start, speaker)) = self.runs.get(idx)
            && start < pos
        {
            self.runs.insert(idx.saturating_add(1), (pos, speaker));
        }
    }

    /// Lines started so far (a last line without line end counts).
    pub(crate) fn lines(&self) -> u32 {
        if self.text.len() > self.line_start {
            self.lines.saturating_add(1)
        } else {
            self.lines
        }
    }

    /// Applies one token of `speaker`; `budget` is what the shard still allows to append.
    pub(crate) fn apply(&mut self, speaker: Speaker, token: Token, budget: &mut usize) {
        if self.truncated {
            return;
        }
        match token {
            Token::Char(c) => self.append(speaker, c, budget),
            Token::Newline => {
                if self.lines.saturating_add(1) >= MAX_LINES {
                    self.truncated = true;
                    return;
                }
                // A line end typed after a secret belongs to the client.
                let who = if speaker == Speaker::Secret {
                    Speaker::Client
                } else {
                    speaker
                };
                self.append(who, b'\n', budget);
                if !self.truncated {
                    self.lines = self.lines.saturating_add(1);
                    self.line_start = self.text.len();
                }
            }
            Token::Erase => {
                self.erase_char();
            }
            Token::EraseLine => while self.erase_typed() {},
            Token::EraseWord => {
                while self.last_typed().is_some_and(|b| b == b' ' || b == b'\t') {
                    self.erase_typed();
                }
                while self.last_typed().is_some_and(|b| b != b' ' && b != b'\t') {
                    self.erase_typed();
                }
            }
        }
    }

    fn append(&mut self, speaker: Speaker, byte: u8, budget: &mut usize) {
        let grows = self.text.len() >= self.charged;
        if self.text.len() >= MAX_BYTES || (grows && *budget == 0) {
            self.truncated = true;
            return;
        }
        if self.runs.last().is_none_or(|(_, s)| *s != speaker) {
            if self.runs.len() >= MAX_RUNS {
                self.truncated = true;
                return;
            }
            self.runs.push((self.text.len(), speaker));
        }
        self.text.push(byte);
        if self.text.len() > self.charged {
            self.charged = self.text.len();
            *budget = budget.saturating_sub(1);
        }
    }

    /// Removes the last byte of the current line (a whole UTF-8 sequence); `false` at the start
    /// of the line.
    fn erase_char(&mut self) -> bool {
        if self.text.len() <= self.line_start {
            return false;
        }
        while let Some(b) = self.text.pop() {
            // Stop after the first byte of a UTF-8 sequence (or an ASCII byte).
            if b & 0xc0 != 0x80 || self.text.len() <= self.line_start {
                break;
            }
        }
        while self
            .runs
            .last()
            .is_some_and(|(start, _)| *start >= self.text.len() && *start > 0)
        {
            self.runs.pop();
        }
        if self.text.is_empty() {
            self.runs.clear();
        }
        true
    }

    /// Last byte of the current line when the client typed it.
    fn last_typed(&self) -> Option<u8> {
        let (_, speaker) = self.runs.last()?;
        if *speaker == Speaker::Server || self.text.len() <= self.line_start {
            return None;
        }
        self.text.last().copied()
    }

    /// Erases the last character of the current line when the client typed it.
    fn erase_typed(&mut self) -> bool {
        self.last_typed().is_some() && self.erase_char()
    }

    /// The runs as text; secret runs keep their value (the store separates them).
    pub(crate) fn into_runs(self) -> Vec<TranscriptRun> {
        let mut out = Vec::with_capacity(self.runs.len());
        let mut iter = self.runs.iter().peekable();
        while let Some(&(start, speaker)) = iter.next() {
            let end = iter.peek().map_or(self.text.len(), |(next, _)| *next);
            let bytes = self.text.get(start..end).unwrap_or_default();
            let text: String = String::from_utf8_lossy(bytes)
                .chars()
                .filter(|c| !hidden(*c))
                .collect();
            if text.is_empty() {
                continue;
            }
            match out.last_mut() {
                Some(TranscriptRun {
                    speaker: s,
                    text: t,
                }) if *s == speaker => t.push_str(&text),
                _ => out.push(TranscriptRun { speaker, text }),
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tokens(bytes: &[u8], client: bool) -> Vec<Token> {
        let mut nvt = Nvt::default();
        let mut out = Vec::new();
        for &b in bytes {
            nvt.push(b, client, &mut |t| out.push(t));
        }
        out
    }

    fn render(t: Transcript) -> String {
        use std::fmt::Write as _;
        t.into_runs().iter().fold(String::new(), |mut out, r| {
            let tag = match r.speaker {
                Speaker::Client => "C",
                Speaker::Server => "S",
                Speaker::Secret => "P",
            };
            let _ = write!(out, "[{tag}:{}]", r.text);
            out
        })
    }

    #[test]
    fn line_ends_escapes_and_controls() {
        use Token::{Char, Erase, EraseLine, Newline};
        assert_eq!(
            tokens(b"a\r\nb\r\0c\rd\ne\r\r\nf", false),
            vec![
                Char(b'a'),
                Newline,
                Char(b'b'),
                Newline,
                Char(b'c'),
                Newline,
                Char(b'd'),
                Newline,
                Char(b'e'),
                Newline,
                Char(b'f')
            ]
        );
        // ANSI colour, cursor movement, title (OSC), charset designation: all removed.
        assert_eq!(
            tokens(
                b"\x1b[1;31mX\x1b[0m\x1b]0;title\x07Y\x1b(BZ\x1b]2;t\x1b\\W",
                false
            ),
            vec![Char(b'X'), Char(b'Y'), Char(b'Z'), Char(b'W')]
        );
        // Server bell and NUL dropped; client controls in caret notation; erase keys.
        assert_eq!(tokens(b"\x07\x00a\x08", false), vec![Char(b'a'), Erase]);
        assert_eq!(
            tokens(b"\x03\x7f\x15", true),
            vec![Char(b'^'), Char(b'C'), Erase, EraseLine]
        );
        // An endless escape sequence gives up.
        let mut long = vec![0x1b, b'['];
        long.extend(std::iter::repeat_n(b'1', 300));
        long.extend(b"ok");
        let out = tokens(&long, false);
        assert!(
            out.len() < 300 && out.ends_with(&[Char(b'o'), Char(b'k')]),
            "{out:?}"
        );
    }

    #[test]
    fn echo_is_absorbed_and_mismatch_stops_expecting() {
        let mut echo = Echo::default();
        echo.typed(Token::Char(b'l'), false);
        echo.typed(Token::Erase, false);
        echo.typed(Token::Newline, false);
        assert!(echo.absorbs(Token::Char(b'l')));
        assert!(echo.absorbs(Token::Erase));
        assert!(echo.absorbs(Token::Char(b' ')));
        assert!(echo.absorbs(Token::Erase));
        assert!(echo.absorbs(Token::Newline));
        assert!(!echo.absorbs(Token::Char(b'x')));
        echo.typed(Token::Char(b'a'), false);
        echo.typed(Token::Char(b'b'), false);
        assert!(!echo.absorbs(Token::Char(b'z')));
        // Cleared: the following `a` is server output.
        assert!(!echo.absorbs(Token::Char(b'a')));
        // A password without echo: the line end matches after its characters.
        echo.typed(Token::Char(b'p'), true);
        echo.typed(Token::Char(b'w'), true);
        echo.typed(Token::Newline, false);
        assert!(echo.absorbs(Token::Newline));
        // An echoed password is absorbed too.
        echo.typed(Token::Char(b'p'), true);
        assert!(echo.absorbs(Token::Char(b'p')));
    }

    #[test]
    fn erases_stay_on_the_line_and_runs_merge() {
        let mut t = Transcript::default();
        let mut budget = usize::MAX;
        for &b in b"$ " {
            t.apply(Speaker::Server, Token::Char(b), &mut budget);
        }
        for &b in b"lsx" {
            t.apply(Speaker::Client, Token::Char(b), &mut budget);
        }
        t.apply(Speaker::Client, Token::Erase, &mut budget);
        t.apply(Speaker::Client, Token::Newline, &mut budget);
        // At the start of a line an erase does nothing.
        t.apply(Speaker::Server, Token::Erase, &mut budget);
        for &b in b"a b" {
            t.apply(Speaker::Client, Token::Char(b), &mut budget);
        }
        t.apply(Speaker::Client, Token::EraseWord, &mut budget);
        t.apply(Speaker::Client, Token::Char(b'c'), &mut budget);
        t.apply(Speaker::Server, Token::Char(b'>'), &mut budget);
        t.apply(Speaker::Client, Token::Char(b'z'), &mut budget);
        // The line erase stops at the server's text.
        t.apply(Speaker::Client, Token::EraseLine, &mut budget);
        assert_eq!(t.lines(), 2);
        assert_eq!(render(t), "[S:$ ][C:ls\na c][S:>]");
    }

    #[test]
    fn bounds_truncate() {
        let mut t = Transcript::default();
        let mut budget = usize::MAX;
        for _ in 0..(MAX_LINES + 10) {
            t.apply(Speaker::Server, Token::Char(b'x'), &mut budget);
            t.apply(Speaker::Server, Token::Newline, &mut budget);
        }
        assert!(t.truncated());
        assert_eq!(t.lines(), MAX_LINES);
        let mut t = Transcript::default();
        let mut budget = 10;
        for _ in 0..20 {
            t.apply(Speaker::Server, Token::Char(b'y'), &mut budget);
        }
        assert!(t.truncated());
        assert_eq!((t.len(), budget, t.charged), (10, 0, 10));
        // Alternating speakers: bounded number of runs.
        let mut t = Transcript::default();
        let mut budget = usize::MAX;
        for i in 0..(MAX_RUNS + 5) {
            let who = if i % 2 == 0 {
                Speaker::Server
            } else {
                Speaker::Client
            };
            t.apply(who, Token::Char(b'r'), &mut budget);
        }
        assert!(t.truncated());
        assert_eq!(t.len(), MAX_RUNS);
    }

    #[test]
    fn repeated_erases_charge_the_largest_size_only() {
        // A spinner (`|`, `/`, `-`, `\` each erased) forever: the budget pays for one byte.
        let mut t = Transcript::default();
        let mut budget = 100;
        t.apply(Speaker::Server, Token::Char(b'['), &mut budget);
        for i in 0..200_000_usize {
            let c = b"|/-\\"[i % 4];
            t.apply(Speaker::Server, Token::Char(c), &mut budget);
            t.apply(Speaker::Server, Token::Erase, &mut budget);
        }
        assert!(!t.truncated());
        assert_eq!((t.charged, budget), (2, 98));
        assert!(t.charged <= MAX_BYTES);
        // An empty budget still allows text below the size already paid for.
        let mut empty = 0;
        t.apply(Speaker::Server, Token::Char(b'x'), &mut empty);
        assert!(!t.truncated());
        t.apply(Speaker::Server, Token::Char(b'y'), &mut empty);
        assert!(t.truncated());
    }

    #[test]
    fn relabel_turns_the_typed_line_secret() {
        let mut t = Transcript::default();
        let mut budget = usize::MAX;
        for &b in b"Code: " {
            t.apply(Speaker::Server, Token::Char(b), &mut budget);
        }
        t.apply(Speaker::Client, Token::Char(b'a'), &mut budget);
        let start = t.len();
        for &b in b"bc" {
            t.apply(Speaker::Client, Token::Char(b), &mut budget);
        }
        t.apply(Speaker::Client, Token::Newline, &mut budget);
        let end = t.len() - 1;
        t.relabel_secret(start, end);
        assert_eq!(render(t), "[S:Code: ][C:a][P:bc][C:\n]");
    }

    #[test]
    fn hidden_characters_are_removed() {
        let mut t = Transcript::default();
        let mut budget = usize::MAX;
        for &b in "a\u{202e}b\u{85}c".as_bytes() {
            t.apply(Speaker::Server, Token::Char(b), &mut budget);
        }
        assert_eq!(render(t), "[S:abc]");
    }
}
