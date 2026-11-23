//! Telnet command layer (RFC 854, RFC 855) and the sub-negotiations of common options.
//!
//! [`Decoder`] removes the `IAC` sequences from one direction of a Telnet connection,
//! incrementally: a sequence may be split anywhere between two calls to [`Decoder::feed`]. It
//! reports data, option negotiations, sub-negotiations and the other commands as [`Event`]s, in
//! stream order. Memory is bounded: a sub-negotiation keeps at most [`MAX_SUBNEG`] bytes, and one
//! that never ends is abandoned after [`MAX_SUBNEG_SCAN`] bytes (its bytes become data again, so a
//! broken stream cannot hide the rest of a session).
//!
//! Option payloads: [`parse_ttype`] (RFC 1091), [`parse_naws`] (RFC 1073), [`parse_environ`]
//! (RFC 1572). Names of the common options: [`option_name`].

/// Interpret As Command.
pub const IAC: u8 = 255;
pub const DONT: u8 = 254;
pub const DO: u8 = 253;
pub const WONT: u8 = 252;
pub const WILL: u8 = 251;
/// Start of a sub-negotiation.
pub const SB: u8 = 250;
pub const GA: u8 = 249;
/// Erase line.
pub const EL: u8 = 248;
/// Erase character.
pub const EC: u8 = 247;
pub const AYT: u8 = 246;
pub const AO: u8 = 245;
pub const IP: u8 = 244;
pub const BRK: u8 = 243;
pub const DM: u8 = 242;
pub const NOP: u8 = 241;
/// End of a sub-negotiation.
pub const SE: u8 = 240;
pub const EOR: u8 = 239;

/// Option codes (IANA "Telnet Options" registry).
pub mod opt {
    pub const BINARY: u8 = 0;
    pub const ECHO: u8 = 1;
    pub const SGA: u8 = 3;
    pub const STATUS: u8 = 5;
    pub const TIMING_MARK: u8 = 6;
    pub const TTYPE: u8 = 24;
    pub const EOR: u8 = 25;
    pub const NAWS: u8 = 31;
    pub const TSPEED: u8 = 32;
    pub const LFLOW: u8 = 33;
    pub const LINEMODE: u8 = 34;
    pub const XDISPLOC: u8 = 35;
    pub const ENVIRON: u8 = 36;
    pub const AUTHENTICATION: u8 = 37;
    pub const ENCRYPT: u8 = 38;
    pub const NEW_ENVIRON: u8 = 39;
}

/// Largest sub-negotiation payload kept, in bytes (longer ones are flagged `truncated`).
pub const MAX_SUBNEG: usize = 512;
/// A sub-negotiation without `IAC SE` is abandoned after this many bytes.
pub const MAX_SUBNEG_SCAN: usize = 4096;
/// Longest terminal type kept, in characters.
pub const MAX_TTYPE: usize = 64;
/// Most environment variables decoded from one message.
pub const MAX_ENV_VARS: usize = 32;
/// Longest environment variable name or value kept, in characters.
pub const MAX_ENV_TEXT: usize = 128;

/// Name of a common option, `None` for the others.
pub const fn option_name(code: u8) -> Option<&'static str> {
    Some(match code {
        opt::BINARY => "BINARY",
        opt::ECHO => "ECHO",
        opt::SGA => "SGA",
        opt::STATUS => "STATUS",
        opt::TIMING_MARK => "TIMING-MARK",
        opt::TTYPE => "TTYPE",
        opt::EOR => "EOR",
        opt::NAWS => "NAWS",
        opt::TSPEED => "TSPEED",
        opt::LFLOW => "LFLOW",
        opt::LINEMODE => "LINEMODE",
        opt::XDISPLOC => "XDISPLOC",
        opt::ENVIRON => "ENVIRON",
        opt::AUTHENTICATION => "AUTHENTICATION",
        opt::ENCRYPT => "ENCRYPT",
        opt::NEW_ENVIRON => "NEW-ENVIRON",
        _ => return None,
    })
}

/// Option negotiation verb.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Verb {
    Will,
    Wont,
    Do,
    Dont,
}

impl Verb {
    const fn of(byte: u8) -> Option<Self> {
        match byte {
            WILL => Some(Self::Will),
            WONT => Some(Self::Wont),
            DO => Some(Self::Do),
            DONT => Some(Self::Dont),
            _ => None,
        }
    }
}

/// One element of the decoded stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event<'a> {
    /// Data bytes (no `IAC` left; `IAC IAC` yields `[0xFF]`).
    Data(&'a [u8]),
    /// `IAC WILL|WONT|DO|DONT <option>`.
    Negotiation { verb: Verb, option: u8 },
    /// `IAC SB <option> <data> IAC SE`, `data` unescaped and at most [`MAX_SUBNEG`] bytes.
    Subnegotiation {
        option: u8,
        data: &'a [u8],
        /// The payload was longer than [`MAX_SUBNEG`], or the sub-negotiation never ended.
        truncated: bool,
    },
    /// Any other `IAC <command>` (`EC`, `EL`, `AYT`, `GA`, `NOP`, a stray `SE`...).
    Command(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum State {
    #[default]
    Data,
    Iac,
    Verb(Verb),
    /// After `IAC SB`, waiting for the option code.
    SbOption,
    SbData,
    /// `IAC` inside a sub-negotiation.
    SbIac,
}

/// Incremental decoder of one direction (see the module documentation). `Debug` shows the size
/// of a sub-negotiation in progress, never its bytes (`NEW-ENVIRON` may carry a user name).
#[derive(Clone, Default)]
pub struct Decoder {
    state: State,
    sb_option: u8,
    sb_buf: Vec<u8>,
    sb_truncated: bool,
    /// Bytes of the current sub-negotiation, kept or not.
    sb_scanned: usize,
}

impl std::fmt::Debug for Decoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Decoder")
            .field("state", &self.state)
            .field("sb_option", &self.sb_option)
            .field("sb_len", &self.sb_buf.len())
            .field("sb_truncated", &self.sb_truncated)
            .finish_non_exhaustive()
    }
}

const ESCAPED_IAC: [u8; 1] = [IAC];

impl Decoder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Bytes are missing before the next data (reassembly gap): any sequence in progress is
    /// dropped and decoding resumes as data.
    pub fn reset(&mut self) {
        self.state = State::Data;
        self.sb_buf.clear();
        self.sb_truncated = false;
        self.sb_scanned = 0;
    }

    /// The decoder is inside a command or sub-negotiation.
    pub fn in_sequence(&self) -> bool {
        self.state != State::Data
    }

    /// Decodes `data`, reporting each element to `on_event` in stream order.
    pub fn feed(&mut self, mut data: &[u8], on_event: &mut dyn FnMut(Event<'_>)) {
        while !data.is_empty() {
            if self.state == State::Data {
                let (text, rest) = match data.iter().position(|&b| b == IAC) {
                    Some(i) => {
                        let (text, rest) = data.split_at(i);
                        (text, rest.get(1..).unwrap_or_default())
                    }
                    None => (data, &[][..]),
                };
                if !text.is_empty() {
                    on_event(Event::Data(text));
                }
                if text.len() < data.len() {
                    self.state = State::Iac;
                }
                data = rest;
                continue;
            }
            let Some((&byte, rest)) = data.split_first() else {
                break;
            };
            data = rest;
            self.step(byte, on_event);
        }
    }

    /// One byte outside the data state.
    fn step(&mut self, byte: u8, on_event: &mut dyn FnMut(Event<'_>)) {
        match self.state {
            State::Data => {}
            State::Iac => self.after_iac(byte, on_event),
            State::Verb(verb) => {
                on_event(Event::Negotiation { verb, option: byte });
                self.state = State::Data;
            }
            State::SbOption => {
                self.sb_option = byte;
                self.sb_buf.clear();
                self.sb_truncated = false;
                self.sb_scanned = 0;
                self.state = State::SbData;
            }
            State::SbData => {
                if byte == IAC {
                    self.state = State::SbIac;
                } else {
                    self.sb_push(byte, on_event);
                }
            }
            State::SbIac => match byte {
                IAC => {
                    self.state = State::SbData;
                    self.sb_push(IAC, on_event);
                }
                SE => {
                    self.emit_subneg(on_event);
                    self.state = State::Data;
                }
                other => {
                    // RFC 855 violation: the sub-negotiation ends here and `IAC <other>` is read
                    // as a command.
                    self.emit_subneg(on_event);
                    self.after_iac(other, on_event);
                }
            },
        }
    }

    fn after_iac(&mut self, byte: u8, on_event: &mut dyn FnMut(Event<'_>)) {
        self.state = State::Data;
        match byte {
            IAC => on_event(Event::Data(&ESCAPED_IAC)),
            SB => self.state = State::SbOption,
            other => match Verb::of(other) {
                Some(verb) => self.state = State::Verb(verb),
                None => on_event(Event::Command(other)),
            },
        }
    }

    fn sb_push(&mut self, byte: u8, on_event: &mut dyn FnMut(Event<'_>)) {
        self.sb_scanned = self.sb_scanned.saturating_add(1);
        if self.sb_buf.len() < MAX_SUBNEG {
            self.sb_buf.push(byte);
        } else {
            self.sb_truncated = true;
        }
        if self.sb_scanned >= MAX_SUBNEG_SCAN {
            // Never ended: report what was kept and read the rest as data.
            self.sb_truncated = true;
            self.emit_subneg(on_event);
            self.state = State::Data;
        }
    }

    fn emit_subneg(&mut self, on_event: &mut dyn FnMut(Event<'_>)) {
        on_event(Event::Subnegotiation {
            option: self.sb_option,
            data: &self.sb_buf,
            truncated: self.sb_truncated,
        });
        self.sb_buf.clear();
        self.sb_truncated = false;
        self.sb_scanned = 0;
    }
}

/// `TTYPE` sub-negotiation commands.
const IS: u8 = 0;
const SEND: u8 = 1;
/// `NEW-ENVIRON` `INFO`.
const INFO: u8 = 2;

/// A `TTYPE` message (RFC 1091).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ttype {
    /// `IS <name>` (client), name bounded to [`MAX_TTYPE`] printable ASCII characters.
    Is(String),
    /// `SEND` (server).
    Send,
}

/// Printable ASCII of `bytes` (other bytes dropped), at most `max` characters.
fn printable(bytes: &[u8], max: usize) -> String {
    bytes
        .iter()
        .filter(|b| b.is_ascii_graphic() || **b == b' ')
        .take(max)
        .map(|&b| char::from(b))
        .collect()
}

/// Decodes a `TTYPE` payload.
pub fn parse_ttype(data: &[u8]) -> Option<Ttype> {
    match data.split_first()? {
        (&IS, name) => Some(Ttype::Is(printable(name, MAX_TTYPE))),
        (&SEND, _) => Some(Ttype::Send),
        _ => None,
    }
}

/// Decodes a `NAWS` payload: `(width, height)` in characters (RFC 1073).
pub fn parse_naws(data: &[u8]) -> Option<(u16, u16)> {
    match data {
        [w0, w1, h0, h1] => Some((
            u16::from_be_bytes([*w0, *w1]),
            u16::from_be_bytes([*h0, *h1]),
        )),
        _ => None,
    }
}

/// Kind of a `NEW-ENVIRON` message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvKind {
    /// `IS` (answer to `SEND`).
    Is,
    /// `SEND` (request).
    Send,
    /// `INFO` (unsolicited update).
    Info,
}

/// One variable of a `NEW-ENVIRON` message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvVar {
    /// `USERVAR` rather than a well-known `VAR`.
    pub user_var: bool,
    pub name: String,
    /// `None` when the variable has no `VALUE` (undefined, or a `SEND` request).
    pub value: Option<String>,
}

/// A `NEW-ENVIRON` message (RFC 1572).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Environ {
    pub kind: EnvKind,
    /// At most [`MAX_ENV_VARS`].
    pub vars: Vec<EnvVar>,
}

const ENV_VAR: u8 = 0;
const ENV_VALUE: u8 = 1;
const ENV_ESC: u8 = 2;
const ENV_USERVAR: u8 = 3;

/// Decodes a `NEW-ENVIRON` payload (`ESC` honoured, names and values bounded to
/// [`MAX_ENV_TEXT`] characters of printable ASCII).
pub fn parse_environ(data: &[u8]) -> Option<Environ> {
    let (&cmd, mut rest) = data.split_first()?;
    let kind = match cmd {
        IS => EnvKind::Is,
        SEND => EnvKind::Send,
        INFO => EnvKind::Info,
        _ => return None,
    };
    let mut vars = Vec::new();
    // Current variable: (user_var, name bytes, value bytes, reading the value).
    let mut current: Option<(bool, Vec<u8>, Option<Vec<u8>>)> = None;
    let finish = |c: Option<(bool, Vec<u8>, Option<Vec<u8>>)>, vars: &mut Vec<EnvVar>| {
        if let Some((user_var, name, value)) = c
            && vars.len() < MAX_ENV_VARS
        {
            vars.push(EnvVar {
                user_var,
                name: printable(&name, MAX_ENV_TEXT),
                value: value.map(|v| printable(&v, MAX_ENV_TEXT)),
            });
        }
    };
    while let Some((&b, tail)) = rest.split_first() {
        rest = tail;
        match b {
            ENV_VAR | ENV_USERVAR => {
                finish(current.take(), &mut vars);
                current = Some((b == ENV_USERVAR, Vec::new(), None));
            }
            ENV_VALUE => {
                if let Some((_, _, value)) = current.as_mut() {
                    *value = Some(Vec::new());
                }
            }
            other => {
                let byte = if other == ENV_ESC {
                    let Some((&escaped, tail)) = rest.split_first() else {
                        break;
                    };
                    rest = tail;
                    escaped
                } else {
                    other
                };
                if let Some((_, name, value)) = current.as_mut() {
                    let target = value.as_mut().unwrap_or(name);
                    if target.len() < MAX_ENV_TEXT {
                        target.push(byte);
                    }
                }
            }
        }
    }
    finish(current, &mut vars);
    Some(Environ { kind, vars })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Eq)]
    enum Owned {
        Data(Vec<u8>),
        Neg(Verb, u8),
        Sub(u8, Vec<u8>, bool),
        Cmd(u8),
    }

    /// Decodes `chunks` in order, merging adjacent data.
    fn decode(chunks: &[&[u8]]) -> Vec<Owned> {
        let mut d = Decoder::new();
        let mut out: Vec<Owned> = Vec::new();
        for chunk in chunks {
            d.feed(chunk, &mut |e| match e {
                Event::Data(bytes) => {
                    if let Some(Owned::Data(prev)) = out.last_mut() {
                        prev.extend_from_slice(bytes);
                    } else {
                        out.push(Owned::Data(bytes.to_vec()));
                    }
                }
                Event::Negotiation { verb, option } => out.push(Owned::Neg(verb, option)),
                Event::Subnegotiation {
                    option,
                    data,
                    truncated,
                } => out.push(Owned::Sub(option, data.to_vec(), truncated)),
                Event::Command(c) => out.push(Owned::Cmd(c)),
            });
        }
        out
    }

    const SAMPLE: &[u8] = &[
        b'h',
        b'i',
        IAC,
        DO,
        opt::TTYPE,
        IAC,
        WILL,
        opt::ECHO,
        b'a',
        IAC,
        IAC,
        b'b',
        IAC,
        SB,
        opt::NAWS,
        0,
        80,
        IAC,
        IAC,
        24,
        IAC,
        SE,
        IAC,
        EC,
        b'z',
    ];

    fn sample_events() -> Vec<Owned> {
        vec![
            Owned::Data(b"hi".to_vec()),
            Owned::Neg(Verb::Do, opt::TTYPE),
            Owned::Neg(Verb::Will, opt::ECHO),
            Owned::Data(vec![b'a', IAC, b'b']),
            Owned::Sub(opt::NAWS, vec![0, 80, IAC, 24], false),
            Owned::Cmd(EC),
            Owned::Data(b"z".to_vec()),
        ]
    }

    #[test]
    fn decodes_commands_data_and_subnegotiations() {
        assert_eq!(decode(&[SAMPLE]), sample_events());
    }

    #[test]
    fn every_split_point_gives_the_same_events() {
        for i in 0..=SAMPLE.len() {
            let (a, b) = SAMPLE.split_at(i);
            assert_eq!(decode(&[a, b]), sample_events(), "split at {i}");
        }
        // One byte at a time.
        let bytes: Vec<&[u8]> = SAMPLE.chunks(1).collect();
        assert_eq!(decode(&bytes), sample_events());
    }

    #[test]
    fn long_subnegotiation_is_truncated_then_ended() {
        let mut input = vec![IAC, SB, opt::TTYPE, IS];
        input.extend(std::iter::repeat_n(b'x', MAX_SUBNEG + 10));
        input.extend([IAC, SE, b'k']);
        let events = decode(&[&input]);
        let Owned::Sub(option, data, truncated) = &events[0] else {
            panic!("{events:?}")
        };
        assert_eq!(
            (*option, data.len(), *truncated),
            (opt::TTYPE, MAX_SUBNEG, true)
        );
        assert_eq!(events[1], Owned::Data(b"k".to_vec()));
    }

    #[test]
    fn endless_subnegotiation_is_abandoned() {
        let mut input = vec![IAC, SB, 99];
        input.extend(std::iter::repeat_n(b'y', MAX_SUBNEG_SCAN + 5));
        let events = decode(&[&input]);
        assert!(matches!(&events[0], Owned::Sub(99, d, true) if d.len() == MAX_SUBNEG));
        assert_eq!(events[1], Owned::Data(vec![b'y'; 5]));
    }

    #[test]
    fn stray_iac_ends_a_subnegotiation_and_reset_drops_sequences() {
        let events = decode(&[&[IAC, SB, 5, 1, IAC, NOP, b'q']]);
        assert_eq!(
            events,
            vec![
                Owned::Sub(5, vec![1], false),
                Owned::Cmd(NOP),
                Owned::Data(b"q".to_vec())
            ]
        );
        let mut d = Decoder::new();
        d.feed(&[IAC, SB, 24, 0, b'v'], &mut |_| {});
        assert!(d.in_sequence());
        d.reset();
        let mut seen = Vec::new();
        d.feed(b"ok", &mut |e| {
            if let Event::Data(b) = e {
                seen.extend_from_slice(b);
            }
        });
        assert_eq!(seen, b"ok");
    }

    #[test]
    fn option_payloads() {
        assert_eq!(
            parse_ttype(b"\0XTERM-256COLOR\x07"),
            Some(Ttype::Is("XTERM-256COLOR".to_owned()))
        );
        assert_eq!(parse_ttype(&[SEND]), Some(Ttype::Send));
        assert_eq!(parse_ttype(&[9]), None);
        assert_eq!(parse_ttype(&[]), None);
        assert_eq!(parse_naws(&[0, 132, 0, 43]), Some((132, 43)));
        assert_eq!(parse_naws(&[0, 132, 0]), None);
        assert_eq!(option_name(opt::NEW_ENVIRON), Some("NEW-ENVIRON"));
        assert_eq!(option_name(200), None);
    }

    #[test]
    fn environ_variables() {
        let msg = [
            IS,
            ENV_VAR,
            b'U',
            b'S',
            b'E',
            b'R',
            ENV_VALUE,
            b'j',
            b'd',
            ENV_ESC,
            ENV_VAR,
            b'e',
            ENV_USERVAR,
            b'X',
            ENV_VAR,
            b'D',
            b'I',
            b'S',
            b'P',
            b'L',
            b'A',
            b'Y',
        ];
        let env = parse_environ(&msg).unwrap();
        assert_eq!(env.kind, EnvKind::Is);
        assert_eq!(
            env.vars,
            vec![
                EnvVar {
                    user_var: false,
                    name: "USER".to_owned(),
                    // `ESC VAR` is a literal 0 byte, dropped as non-printable.
                    value: Some("jde".to_owned()),
                },
                EnvVar {
                    user_var: true,
                    name: "X".to_owned(),
                    value: None
                },
                EnvVar {
                    user_var: false,
                    name: "DISPLAY".to_owned(),
                    value: None
                },
            ]
        );
        assert_eq!(parse_environ(&[SEND]).unwrap().vars, vec![]);
        assert_eq!(parse_environ(&[7]), None);
        // Bounded number of variables and lengths.
        let mut big = vec![INFO];
        for _ in 0..(MAX_ENV_VARS + 5) {
            big.push(ENV_VAR);
            big.extend(std::iter::repeat_n(b'n', MAX_ENV_TEXT + 3));
        }
        let env = parse_environ(&big).unwrap();
        assert_eq!(env.vars.len(), MAX_ENV_VARS);
        assert!(env.vars.iter().all(|v| v.name.len() == MAX_ENV_TEXT));
    }

    #[test]
    fn hostile_bytes_never_panic() {
        let mut state = 0x1234_5678_u32;
        let mut d = Decoder::new();
        for _ in 0..2000 {
            let mut chunk = Vec::new();
            for _ in 0..64 {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                // Bias towards command bytes.
                let b = (state & 0xff) as u8;
                chunk.push(if b < 64 { IAC } else { b | 0xf0 });
            }
            d.feed(&chunk, &mut |e| {
                if let Event::Subnegotiation { data, .. } = e {
                    assert!(data.len() <= MAX_SUBNEG);
                    let _ = parse_environ(data);
                    let _ = parse_ttype(data);
                    let _ = parse_naws(data);
                }
            });
        }
    }
}
