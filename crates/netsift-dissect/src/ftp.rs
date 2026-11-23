//! FTP control lines (RFC 959), extended data addresses (RFC 2428).
//!
//! Pure functions over one line of the control connection, without its terminator: a command sent
//! by the client ([`parse_command`]), a reply line sent by the server ([`parse_reply`]), and the
//! data-channel addresses carried by `PORT`, `EPRT` and the `227` / `229` replies. Nothing here
//! allocates in proportion to the input; malformed input yields `None`, never a guess.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Longest command verb accepted (RFC 959 verbs have 3 or 4 letters; extensions stay short).
pub const MAX_VERB: usize = 8;

/// A command line: verb (upper case) and argument (the rest after one space, may be empty).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Command<'a> {
    /// The verb as sent; compare with [`Command::is`].
    pub verb: &'a str,
    pub arg: &'a str,
}

impl Command<'_> {
    /// Case-insensitive verb comparison.
    pub fn is(&self, verb: &str) -> bool {
        self.verb.eq_ignore_ascii_case(verb)
    }
}

/// Parses a command line: 1 to [`MAX_VERB`] ASCII letters or digits starting with a letter, then
/// optionally a space and the argument. `None` when the line does not start with such a verb.
pub fn parse_command(line: &str) -> Option<Command<'_>> {
    let line = line.trim_start();
    let (verb, arg) = match line.find([' ', '\t']) {
        Some(i) => (
            line.get(..i)?,
            line.get(i..)?.trim_start_matches([' ', '\t']),
        ),
        None => (line, ""),
    };
    let valid = !verb.is_empty()
        && verb.len() <= MAX_VERB
        && verb.bytes().next().is_some_and(|b| b.is_ascii_alphabetic())
        && verb.bytes().all(|b| b.is_ascii_alphanumeric());
    valid.then_some(Command {
        verb,
        arg: arg.trim_end(),
    })
}

/// One reply line that starts with a code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reply<'a> {
    /// Three-digit code, 100 to 599.
    pub code: u16,
    /// `true` for `NNN-`: first line of a multi-line reply (RFC 959 4.2).
    pub more: bool,
    /// Text after the code and its separator.
    pub text: &'a str,
}

/// Parses a reply line `NNN text` or `NNN-text` (a bare `NNN` is a last line with no text).
/// `None` when the line does not start with a code (continuation line of a multi-line reply).
pub fn parse_reply(line: &str) -> Option<Reply<'_>> {
    let bytes = line.as_bytes();
    let digits = bytes.get(..3)?;
    if !digits.iter().all(u8::is_ascii_digit) || !(b'1'..=b'5').contains(digits.first()?) {
        return None;
    }
    let code = digits.iter().try_fold(0u16, |acc, d| {
        acc.checked_mul(10)?
            .checked_add(u16::from(d.checked_sub(b'0')?))
    })?;
    let (more, text) = match bytes.get(3) {
        None => (false, ""),
        Some(b' ') => (false, line.get(4..)?),
        Some(b'-') => (true, line.get(4..)?),
        Some(_) => return None,
    };
    Some(Reply { code, more, text })
}

/// A byte value written in decimal (`0`-`255`), at most three digits.
fn octet(s: &str) -> Option<u8> {
    let s = s.trim();
    if s.is_empty() || s.len() > 3 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

/// A TCP port in decimal, 1 to 65535.
fn port(s: &str) -> Option<u16> {
    let s = s.trim();
    if s.is_empty() || s.len() > 5 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok().filter(|p| *p != 0)
}

/// `h1,h2,h3,h4,p1,p2` (RFC 959 `PORT` argument and `227` address).
fn host_port(text: &str) -> Option<(IpAddr, u16)> {
    let mut fields = text.split(',');
    let mut bytes = [0u8; 6];
    for slot in &mut bytes {
        *slot = octet(fields.next()?)?;
    }
    if fields.next().is_some() {
        return None;
    }
    let [h1, h2, h3, h4, p1, p2] = bytes;
    let port = u16::from_be_bytes([p1, p2]);
    (port != 0).then_some((IpAddr::V4(Ipv4Addr::new(h1, h2, h3, h4)), port))
}

/// Address of a `PORT h1,h2,h3,h4,p1,p2` argument.
pub fn parse_port_arg(arg: &str) -> Option<(IpAddr, u16)> {
    host_port(arg.trim())
}

/// Address of a `227` reply: the first run of six comma-separated numbers in the text, with or
/// without parentheses (RFC 959 leaves the text free, RFC 1123 4.1.2.6 asks clients to scan it).
pub fn parse_pasv_reply(text: &str) -> Option<(IpAddr, u16)> {
    let bytes = text.as_bytes();
    let mut start = 0usize;
    while start < bytes.len() {
        if bytes.get(start).is_some_and(u8::is_ascii_digit) {
            let len = bytes
                .get(start..)?
                .iter()
                .take_while(|b| b.is_ascii_digit() || **b == b',' || **b == b' ')
                .count();
            let end = start.checked_add(len)?;
            let run = text.get(start..end)?.trim_end_matches([',', ' ']);
            if let Some(found) = host_port(run) {
                return Some(found);
            }
            start = end;
        } else {
            start = start.checked_add(1)?;
        }
    }
    None
}

/// Address of an `EPRT |af|addr|port|` argument (RFC 2428 2): `af` 1 is IPv4, 2 is IPv6; the
/// delimiter is any printable ASCII character but a digit or a dot.
pub fn parse_eprt_arg(arg: &str) -> Option<(IpAddr, u16)> {
    let arg = arg.trim();
    let delim = arg.chars().next()?;
    if !(delim.is_ascii_graphic()) || delim.is_ascii_digit() || delim == '.' {
        return None;
    }
    let mut parts = arg.split(delim);
    // Leading empty field, af, address, port, trailing empty field.
    if !parts.next()?.is_empty() {
        return None;
    }
    let af = parts.next()?;
    let addr = parts.next()?;
    let p = port(parts.next()?)?;
    if !parts.next()?.is_empty() || parts.next().is_some() {
        return None;
    }
    let ip = match af {
        "1" => IpAddr::V4(addr.parse::<Ipv4Addr>().ok()?),
        "2" => IpAddr::V6(addr.parse::<Ipv6Addr>().ok()?),
        _ => return None,
    };
    Some((ip, p))
}

/// Port of a `229 Entering Extended Passive Mode (|||port|)` reply (RFC 2428 3): the text in
/// parentheses, made of three delimiters, the port and a fourth delimiter.
pub fn parse_epsv_reply(text: &str) -> Option<u16> {
    let open = text.find('(')?;
    let inner = text.get(open.checked_add(1)?..)?;
    let close = inner.find(')')?;
    let inner = inner.get(..close)?;
    let delim = inner.chars().next()?;
    if !delim.is_ascii_graphic() || delim.is_ascii_digit() {
        return None;
    }
    let mut parts = inner.split(delim);
    for _ in 0..3 {
        if !parts.next()?.is_empty() {
            return None;
        }
    }
    let p = port(parts.next()?)?;
    if !parts.next()?.is_empty() || parts.next().is_some() {
        return None;
    }
    Some(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commands() {
        assert_eq!(
            parse_command("USER alice"),
            Some(Command {
                verb: "USER",
                arg: "alice"
            })
        );
        let c = parse_command("retr  my file.txt ").unwrap();
        assert!(c.is("RETR"));
        assert_eq!(c.arg, "my file.txt");
        assert_eq!(parse_command("PASV").unwrap().arg, "");
        assert_eq!(parse_command("XMKD dir").unwrap().verb, "XMKD");
        for bad in [
            "",
            "   ",
            "1USER x",
            "US-ER x",
            "TOOLONGVERB x",
            "\u{e9}t\u{e9} x",
        ] {
            assert_eq!(parse_command(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn replies() {
        assert_eq!(
            parse_reply("220 FTP server ready"),
            Some(Reply {
                code: 220,
                more: false,
                text: "FTP server ready"
            })
        );
        let r = parse_reply("211-Features:").unwrap();
        assert!(r.more);
        assert_eq!(r.code, 211);
        assert_eq!(parse_reply("226").unwrap().text, "");
        for bad in [" 220 x", "22", "220x", "620 x", "099 x", "abc def", " MDTM"] {
            assert_eq!(parse_reply(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn port_and_pasv() {
        let want = Some(("192.168.1.21".parse().unwrap(), 195 * 256 + 80));
        assert_eq!(parse_port_arg("192,168,1,21,195,80"), want);
        assert_eq!(parse_port_arg(" 192, 168, 1, 21, 195, 80 "), want);
        assert_eq!(
            parse_pasv_reply("Entering Passive Mode (192,168,1,21,195,80)."),
            want
        );
        assert_eq!(parse_pasv_reply("=192,168,1,21,195,80"), want);
        // A number before the address is skipped.
        assert_eq!(parse_pasv_reply("Mode 1 (192,168,1,21,195,80)"), want);
        for bad in [
            "192,168,1,21,195",
            "192,168,1,21,195,80,1",
            "256,168,1,21,195,80",
            "192,168,1,21,0,0",
            "1921,168,1,21,195,80",
            "",
        ] {
            assert_eq!(parse_port_arg(bad), None, "{bad:?}");
        }
        assert_eq!(parse_pasv_reply("Entering Passive Mode"), None);
        assert_eq!(parse_pasv_reply("(1,2,3)"), None);
    }

    #[test]
    fn eprt_and_epsv() {
        assert_eq!(
            parse_eprt_arg("|1|132.235.1.2|6275|"),
            Some(("132.235.1.2".parse().unwrap(), 6275))
        );
        assert_eq!(
            parse_eprt_arg("!2!2001:db8::21!5282!"),
            Some(("2001:db8::21".parse().unwrap(), 5282))
        );
        for bad in [
            "|3|1.2.3.4|21|",
            "|1|1.2.3.4|0|",
            "|1|1.2.3.4|70000|",
            "|1|::1|21|",
            "|2|1.2.3.4|21|",
            "|1|1.2.3.4|21",
            "|1|1.2.3.4|21|x",
            "1|1.2.3.4|21|",
            "",
        ] {
            assert_eq!(parse_eprt_arg(bad), None, "{bad:?}");
        }
        assert_eq!(
            parse_epsv_reply("Entering Extended Passive Mode (|||6446|)"),
            Some(6446)
        );
        assert_eq!(parse_epsv_reply("(!!!21!)"), Some(21));
        for bad in [
            "Entering Extended Passive Mode",
            "(|||0|)",
            "(||6446|)",
            "(|||6446)",
            "(|1|1|6446|)",
            "(|||6446||)",
        ] {
            assert_eq!(parse_epsv_reply(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn hostile_input_never_panics() {
        let samples = [
            "\u{0}\u{1}\u{2}",
            "999-",
            "1",
            "(((((",
            "|",
            "||||||||",
            ",,,,,,",
            "9,9,9,9,9,9,9,9,9,9,9,9,9",
        ];
        for s in samples {
            let _ = parse_command(s);
            let _ = parse_reply(s);
            let _ = parse_port_arg(s);
            let _ = parse_pasv_reply(s);
            let _ = parse_eprt_arg(s);
            let _ = parse_epsv_reply(s);
        }
    }
}
