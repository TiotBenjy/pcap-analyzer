//! SIP message parser (RFC 3261), with the SDP body read by [`crate::sdp`].
//!
//! A SIP message is text: a request line (`INVITE sip:bob@example.com SIP/2.0`) or a status line
//! (`SIP/2.0 180 Ringing`), header lines, an empty line and a body. What devices send is read
//! tolerantly: LF-only line ends, folded header lines (continuation lines starting with a space or
//! a tab, RFC 3261 section 7.3.1), the compact header names of section 7.3.3 and any case.
//!
//! Captures are hostile input: at most [`MAX_PARSE`] bytes are read, at most [`MAX_HEADERS`]
//! headers kept, every extracted field cut to [`MAX_FIELD`] bytes (the Call-ID to
//! [`MAX_CALL_ID`]) and the raw text kept for display to [`MAX_RAW`] bytes, with control and
//! invisible formatting characters replaced. [`parse`] returns `None` when the first line is
//! neither a SIP request nor a SIP status line.
//!
//! Over TCP, [`message_len`] frames the stream: end of the headers, then `Content-Length`
//! (RFC 3261 section 18.3), bounded by [`MAX_MESSAGE`].

use crate::sdp::{self, Sdp};

/// Bytes of a message read by the parser (head and SDP body).
pub const MAX_PARSE: usize = 16 * 1024;
/// Largest message accepted when framing a TCP stream (head and body).
pub const MAX_MESSAGE: usize = 64 * 1024;
/// Headers kept from one message; the following ones are ignored (`headers_truncated`).
pub const MAX_HEADERS: usize = 64;
/// Longest extracted field value, in bytes (cut on a character boundary).
pub const MAX_FIELD: usize = 512;
/// Longest Call-ID kept, in bytes.
pub const MAX_CALL_ID: usize = 256;
/// Bytes of the message kept as raw text for display.
pub const MAX_RAW: usize = 4096;
/// Longest method name (a token in RFC 3261; real ones are at most 9 characters).
const MAX_METHOD: usize = 32;
/// Authentication parameters read from one header.
const MAX_AUTH_PARAMS: usize = 32;

/// First line of a SIP message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartLine {
    /// `<method> <request-uri> SIP/2.0`; the method is upper-cased.
    Request { method: String, uri: String },
    /// `SIP/2.0 <code> <reason>`.
    Response { status: u16, reason: String },
}

/// A `From` / `To` value: optional display name, URI and `tag` parameter.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NameAddr {
    pub name: Option<String>,
    pub uri: Option<String>,
    pub tag: Option<String>,
}

/// Header that carried the credentials of a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthHeader {
    Authorization,
    ProxyAuthorization,
}

impl AuthHeader {
    /// Header name as written in RFC 3261.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Authorization => "Authorization",
            Self::ProxyAuthorization => "Proxy-Authorization",
        }
    }
}

/// Non-secret parameters of a `Digest` authorization header (RFC 3261 section 22.4, RFC 2617).
/// The nonce and the response are never kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DigestAuth {
    pub header: AuthHeader,
    pub username: Option<String>,
    pub realm: Option<String>,
    pub uri: Option<String>,
    pub algorithm: Option<String>,
    pub qop: Option<String>,
}

/// A decoded SIP message. Text fields are bounded and free of control characters.
///
/// `Debug` shows the size of the raw text, never the text itself.
#[derive(Clone, PartialEq, Eq)]
pub struct SipMessage {
    pub start: StartLine,
    /// `Call-ID` (`i`), cut to [`MAX_CALL_ID`] bytes.
    pub call_id: Option<String>,
    /// `From` (`f`).
    pub from: NameAddr,
    /// `To` (`t`).
    pub to: NameAddr,
    /// Sequence number of `CSeq`.
    pub cseq: Option<u32>,
    /// Method of `CSeq` (upper case): the method a response answers.
    pub cseq_method: Option<String>,
    pub user_agent: Option<String>,
    pub server: Option<String>,
    /// URI of the first `Contact` (`m`), or `*`.
    pub contact: Option<String>,
    /// First `Via` (`v`) without its parameters (`SIP/2.0/UDP host:port`).
    pub via: Option<String>,
    /// `Expires`, seconds.
    pub expires: Option<u32>,
    /// `Content-Type` (`c`) without parameters, lower case.
    pub content_type: Option<String>,
    /// `Content-Length` (`l`).
    pub content_length: Option<u32>,
    /// `Reason` header (RFC 3326).
    pub reason_header: Option<String>,
    /// `realm` of a `WWW-Authenticate` / `Proxy-Authenticate` challenge.
    pub challenge_realm: Option<String>,
    /// `Authorization` / `Proxy-Authorization` of scheme `Digest`.
    pub auth: Option<DigestAuth>,
    /// SDP body, when the content type is `application/sdp`.
    pub sdp: Option<Sdp>,
    /// More than [`MAX_HEADERS`] headers: the following ones were ignored.
    pub headers_truncated: bool,
    /// Size of the message, in bytes.
    pub size: usize,
    /// The first [`MAX_RAW`] bytes as text: UTF-8 with replacement, LF line ends, control and
    /// invisible formatting characters other than tab and LF replaced by U+FFFD, and the values of
    /// the authentication headers masked ([`redact_auth`]).
    pub raw: String,
    /// True when the message is longer than [`MAX_RAW`].
    pub raw_truncated: bool,
}

impl std::fmt::Debug for SipMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SipMessage")
            .field("start", &self.start)
            .field("call_id", &self.call_id)
            .field("from", &self.from)
            .field("to", &self.to)
            .field("cseq", &self.cseq)
            .field("cseq_method", &self.cseq_method)
            .field("user_agent", &self.user_agent)
            .field("server", &self.server)
            .field("contact", &self.contact)
            .field("via", &self.via)
            .field("expires", &self.expires)
            .field("content_type", &self.content_type)
            .field("content_length", &self.content_length)
            .field("reason_header", &self.reason_header)
            .field("challenge_realm", &self.challenge_realm)
            .field("auth", &self.auth)
            .field("sdp", &self.sdp)
            .field("headers_truncated", &self.headers_truncated)
            .field("size", &self.size)
            .field("raw", &format_args!("<{} bytes>", self.raw.len()))
            .field("raw_truncated", &self.raw_truncated)
            .finish()
    }
}

impl SipMessage {
    pub fn is_request(&self) -> bool {
        matches!(self.start, StartLine::Request { .. })
    }

    /// Method of a request, else the `CSeq` method of a response.
    pub fn method(&self) -> Option<&str> {
        match &self.start {
            StartLine::Request { method, .. } => Some(method),
            StartLine::Response { .. } => self.cseq_method.as_deref(),
        }
    }

    /// Status code of a response.
    pub fn status(&self) -> Option<u16> {
        match self.start {
            StartLine::Response { status, .. } => Some(status),
            StartLine::Request { .. } => None,
        }
    }

    /// `User-Agent`, else `Server`.
    pub fn software(&self) -> Option<&str> {
        self.user_agent.as_deref().or(self.server.as_deref())
    }
}

/// Why a TCP stream cannot be framed as SIP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// The first line is not a SIP request or status line.
    NotSip,
    /// The head or the whole message exceeds the bounds.
    TooLarge,
    /// `Content-Length` is not a number.
    BadLength,
}

/// Length of the SIP message at the start of `data` (a TCP stream): `Ok(None)` when more bytes
/// are needed. Leading keep-alive line ends (RFC 5626) are not part of a message: skip them with
/// [`keepalive_len`] first.
pub fn message_len(data: &[u8]) -> Result<Option<usize>, FrameError> {
    let window = data.get(..data.len().min(MAX_PARSE)).unwrap_or(data);
    // Judge the first line as soon as it is complete (or long enough to be judged).
    match window.iter().position(|b| *b == b'\n') {
        Some(end) => {
            let line = trim_cr(window.get(..end).unwrap_or_default());
            if start_line(line).is_none() {
                return Err(FrameError::NotSip);
            }
        }
        None if window.len() >= MAX_PARSE => return Err(FrameError::TooLarge),
        None => {
            return if plausible_prefix(window) {
                Ok(None)
            } else {
                Err(FrameError::NotSip)
            };
        }
    }
    let Some(head) = split_head(window) else {
        return if window.len() >= MAX_PARSE {
            Err(FrameError::TooLarge)
        } else {
            Ok(None)
        };
    };
    let mut length = 0usize;
    for line in head.header_lines(window) {
        // A folded continuation line belongs to the previous header (as in `collect_headers`).
        if line.first().is_some_and(|b| *b == b' ' || *b == b'\t') {
            continue;
        }
        if let Some((name, value)) = split_header(line)
            && (name.eq_ignore_ascii_case(b"content-length") || name.eq_ignore_ascii_case(b"l"))
        {
            length = number(value).ok_or(FrameError::BadLength)? as usize;
            break;
        }
    }
    let total = head
        .body_start
        .checked_add(length)
        .filter(|t| *t <= MAX_MESSAGE)
        .ok_or(FrameError::TooLarge)?;
    Ok((data.len() >= total).then_some(total))
}

/// Number of keep-alive line end bytes (`CR` / `LF`) at the start of a stream.
pub fn keepalive_len(data: &[u8]) -> usize {
    data.iter()
        .take_while(|b| **b == b'\r' || **b == b'\n')
        .count()
}

/// Decodes one SIP message (a UDP datagram, or a message framed by [`message_len`]). `None` when
/// the first line is not SIP.
pub fn parse(data: &[u8]) -> Option<SipMessage> {
    let window = data.get(..data.len().min(MAX_PARSE)).unwrap_or(data);
    let first_end = window
        .iter()
        .position(|b| *b == b'\n')
        .unwrap_or(window.len());
    let start = start_line(trim_cr(window.get(..first_end)?))?;
    let (raw, raw_truncated) = raw_text(data, MAX_RAW);
    let raw = redact_auth(&raw);
    // URI passwords of the head (start line and headers), never of the body.
    let raw = match raw.find("\n\n") {
        Some(end) => {
            let (head, body) = raw.split_at(end);
            format!("{}{body}", mask_uri_passwords(head))
        }
        None => mask_uri_passwords(&raw),
    };
    let mut msg = SipMessage {
        start,
        call_id: None,
        from: NameAddr::default(),
        to: NameAddr::default(),
        cseq: None,
        cseq_method: None,
        user_agent: None,
        server: None,
        contact: None,
        via: None,
        expires: None,
        content_type: None,
        content_length: None,
        reason_header: None,
        challenge_realm: None,
        auth: None,
        sdp: None,
        headers_truncated: false,
        size: data.len(),
        raw,
        raw_truncated,
    };
    // A head without its final empty line (cut datagram) is read up to its end.
    let head = split_head(window).unwrap_or(Head {
        first_end,
        headers_end: window.len(),
        body_start: window.len(),
    });
    let headers = collect_headers(head.header_lines(window), &mut msg.headers_truncated);
    for (name, value) in &headers {
        apply_header(&mut msg, name, value);
    }
    // A password in a SIP URI (`sip:user:password@host`, RFC 3261 section 19.1.1) is masked in
    // every extracted URI.
    for uri in [
        msg.from.uri.as_mut(),
        msg.to.uri.as_mut(),
        msg.contact.as_mut(),
        msg.auth.as_mut().and_then(|a| a.uri.as_mut()),
    ]
    .into_iter()
    .flatten()
    {
        *uri = mask_uri_passwords(uri);
    }
    if let StartLine::Request { uri, .. } = &mut msg.start {
        *uri = mask_uri_passwords(uri);
    }
    let body = window.get(head.body_start..).unwrap_or_default();
    let body = match msg.content_length {
        Some(n) => body.get(..body.len().min(n as usize)).unwrap_or(body),
        None => body,
    };
    if msg.content_type.as_deref() == Some("application/sdp") && !body.is_empty() {
        msg.sdp = sdp::parse(body);
    }
    Some(msg)
}

/// Positions of the head of a message within the parsed window.
#[derive(Debug, Clone, Copy)]
struct Head {
    /// End of the first line (index of its `\n`, or of the end of the window).
    first_end: usize,
    /// End of the header lines (start of the empty line).
    headers_end: usize,
    /// First byte of the body (after the empty line).
    body_start: usize,
}

impl Head {
    /// The header lines, without their line ends (folded lines not joined yet).
    fn header_lines<'a>(&self, data: &'a [u8]) -> impl Iterator<Item = &'a [u8]> {
        let from = self.first_end.saturating_add(1);
        data.get(from.min(self.headers_end)..self.headers_end)
            .unwrap_or_default()
            .split(|b| *b == b'\n')
            .map(trim_cr)
            .filter(|l| !l.is_empty())
    }
}

/// Finds the empty line that ends the head (`CRLF CRLF`, `LF LF` or a mix). `None` when the
/// window ends inside the head.
fn split_head(data: &[u8]) -> Option<Head> {
    let first_end = data.iter().position(|b| *b == b'\n')?;
    let mut pos = first_end.checked_add(1)?;
    loop {
        let rest = data.get(pos..)?;
        let len = rest.iter().position(|b| *b == b'\n')?;
        let line = trim_cr(rest.get(..len)?);
        let next = pos.checked_add(len)?.checked_add(1)?;
        if line.is_empty() {
            return Some(Head {
                first_end,
                headers_end: pos,
                body_start: next,
            });
        }
        pos = next;
    }
}

/// Joins folded lines and keeps at most [`MAX_HEADERS`] `(lower-case name, value)` pairs, each
/// value cut a little beyond [`MAX_FIELD`].
fn collect_headers<'a>(
    lines: impl Iterator<Item = &'a [u8]>,
    truncated: &mut bool,
) -> Vec<(String, Vec<u8>)> {
    let mut out: Vec<(String, Vec<u8>)> = Vec::new();
    let mut skipping = false;
    for line in lines {
        if line.first().is_some_and(|b| *b == b' ' || *b == b'\t') {
            if skipping {
                continue;
            }
            if let Some((_, value)) = out.last_mut() {
                let room = (MAX_FIELD + 4).saturating_sub(value.len());
                if room > 1 {
                    value.push(b' ');
                    let more = line.trim_ascii();
                    value.extend_from_slice(
                        more.get(..more.len().min(room.saturating_sub(1)))
                            .unwrap_or(more),
                    );
                }
            }
            continue;
        }
        let Some((name, value)) = split_header(line) else {
            skipping = true;
            continue;
        };
        if out.len() >= MAX_HEADERS {
            *truncated = true;
            break;
        }
        skipping = false;
        let name = String::from_utf8_lossy(name).to_ascii_lowercase();
        let value = value
            .get(..value.len().min(MAX_FIELD + 4))
            .unwrap_or_default()
            .to_vec();
        out.push((name, value));
    }
    out
}

/// `name: value` of a header line (name trimmed, value trimmed). `None` without a colon or with
/// an empty or blank-containing name.
fn split_header(line: &[u8]) -> Option<(&[u8], &[u8])> {
    let colon = line.iter().position(|b| *b == b':')?;
    let name = line.get(..colon)?.trim_ascii();
    let value = line.get(colon.checked_add(1)?..)?.trim_ascii();
    if name.is_empty() || name.iter().any(|b| !is_token_char(*b)) {
        return None;
    }
    Some((name, value))
}

/// Applies one header to the message. The first occurrence of a header wins.
fn apply_header(msg: &mut SipMessage, name: &str, value: &[u8]) {
    let text = || field(value, MAX_FIELD);
    match name {
        "call-id" | "i" => {
            if msg.call_id.is_none() {
                msg.call_id = field(value, MAX_CALL_ID);
            }
        }
        "from" | "f" => {
            if msg.from.uri.is_none() && msg.from.name.is_none() {
                msg.from = name_addr(value);
            }
        }
        "to" | "t" => {
            if msg.to.uri.is_none() && msg.to.name.is_none() {
                msg.to = name_addr(value);
            }
        }
        "cseq" => {
            if msg.cseq.is_none() {
                let text = String::from_utf8_lossy(value);
                let mut parts = text.split_ascii_whitespace();
                msg.cseq = parts.next().and_then(|n| number(n.as_bytes()));
                msg.cseq_method = parts.next().and_then(method_token);
            }
        }
        "user-agent" => msg.user_agent = msg.user_agent.take().or_else(text),
        "server" => msg.server = msg.server.take().or_else(text),
        "contact" | "m" => {
            if msg.contact.is_none() {
                msg.contact = if value.trim_ascii() == b"*" {
                    Some("*".to_owned())
                } else {
                    name_addr(value).uri
                };
            }
        }
        "via" | "v" => {
            if msg.via.is_none() {
                let first = value.split(|b| *b == b',').next().unwrap_or_default();
                let sent_by = first.split(|b| *b == b';').next().unwrap_or_default();
                msg.via = field(sent_by, MAX_FIELD);
            }
        }
        "expires" => msg.expires = msg.expires.or_else(|| number(value)),
        "content-type" | "c" => {
            if msg.content_type.is_none() {
                let media = value.split(|b| *b == b';').next().unwrap_or_default();
                msg.content_type = field(media, MAX_FIELD).map(|t| t.to_ascii_lowercase());
            }
        }
        "content-length" | "l" => msg.content_length = msg.content_length.or_else(|| number(value)),
        "reason" => msg.reason_header = msg.reason_header.take().or_else(text),
        "www-authenticate" | "proxy-authenticate" => {
            if msg.challenge_realm.is_none() {
                msg.challenge_realm = digest_params(value).and_then(|p| p.realm);
            }
        }
        "authorization" | "proxy-authorization" => {
            if msg.auth.is_none()
                && let Some(p) = digest_params(value)
            {
                msg.auth = Some(DigestAuth {
                    header: if name == "authorization" {
                        AuthHeader::Authorization
                    } else {
                        AuthHeader::ProxyAuthorization
                    },
                    username: p.username,
                    realm: p.realm,
                    uri: p.uri,
                    algorithm: p.algorithm,
                    qop: p.qop,
                });
            }
        }
        _ => {}
    }
}

/// Request or status line. `None` when it is not SIP/2.0.
fn start_line(line: &[u8]) -> Option<StartLine> {
    let text = std::str::from_utf8(line.get(..line.len().min(MAX_FIELD * 4))?).ok()?;
    let mut parts = text.split_ascii_whitespace();
    let first = parts.next()?;
    if first.eq_ignore_ascii_case("SIP/2.0") {
        let code = parts.next()?;
        if code.len() != 3 || !code.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let status: u16 = code.parse().ok()?;
        if !(100..=699).contains(&status) {
            return None;
        }
        // The reason phrase is the rest of the line, spaces included.
        let reason = text
            .trim_start()
            .get(first.len()..)
            .map(str::trim_start)
            .and_then(|r| r.get(code.len()..))
            .unwrap_or_default();
        return Some(StartLine::Response {
            status,
            reason: field(reason.as_bytes(), MAX_FIELD).unwrap_or_default(),
        });
    }
    let method = method_token(first)?;
    let uri = parts.next()?;
    let version = parts.next()?;
    if !version.eq_ignore_ascii_case("SIP/2.0") || parts.next().is_some() {
        return None;
    }
    Some(StartLine::Request {
        method,
        uri: field(uri.as_bytes(), MAX_FIELD)?,
    })
}

/// A method token (RFC 3261 section 25.1), upper-cased.
fn method_token(s: &str) -> Option<String> {
    (!s.is_empty() && s.len() <= MAX_METHOD && s.bytes().all(is_token_char))
        .then(|| s.to_ascii_uppercase())
}

/// Could `data` (no line end yet) be the beginning of a SIP first line?
fn plausible_prefix(data: &[u8]) -> bool {
    let word_end = data.iter().position(|b| *b == b' ').unwrap_or(data.len());
    let word = data.get(..word_end).unwrap_or_default();
    word.len() <= MAX_METHOD
        && word.iter().all(|b| is_token_char(*b) || *b == b'/')
        && data
            .iter()
            .all(|b| !b.is_ascii_control() || *b == b'\r' || *b == b'\t')
}

/// RFC 3261 `token` characters.
fn is_token_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"-.!%*_+`'~".contains(&b)
}

/// `From` / `To` / `Contact` value: `"Name" <uri>;tag=x`, `Name <uri>;tag=x` or `uri;tag=x`.
fn name_addr(value: &[u8]) -> NameAddr {
    let text = String::from_utf8_lossy(value);
    let text = text.trim();
    let (name, rest) = if let Some(quoted) = text.strip_prefix('"') {
        let end = closing_quote(quoted);
        (
            Some(unescape(quoted.get(..end).unwrap_or(quoted))),
            quoted.get(end.saturating_add(1)..).unwrap_or_default(),
        )
    } else {
        (None, text)
    };
    let (name, uri, params) = match (rest.find('<'), rest.find('>')) {
        (Some(open), Some(close)) if open < close => {
            let display = rest.get(..open).unwrap_or_default().trim();
            let name = name.or_else(|| (!display.is_empty()).then(|| display.to_owned()));
            (
                name,
                rest.get(open.saturating_add(1)..close).unwrap_or_default(),
                rest.get(close.saturating_add(1)..).unwrap_or_default(),
            )
        }
        _ => {
            let rest = rest.trim();
            let cut = rest.find(';').unwrap_or(rest.len());
            (
                name,
                rest.get(..cut).unwrap_or_default(),
                rest.get(cut..).unwrap_or_default(),
            )
        }
    };
    let tag = params.split(';').find_map(|p| {
        let (k, v) = p.split_once('=')?;
        k.trim().eq_ignore_ascii_case("tag").then(|| v.trim())
    });
    NameAddr {
        name: name.and_then(|n| field(n.as_bytes(), MAX_FIELD)),
        uri: field(uri.trim().as_bytes(), MAX_FIELD),
        tag: tag.and_then(|t| field(t.as_bytes(), MAX_FIELD)),
    }
}

/// Index of the closing double quote of a quoted string (after the opening one), escapes
/// skipped; the length of `s` when unterminated.
fn closing_quote(s: &str) -> usize {
    let mut escaped = false;
    for (i, c) in s.char_indices() {
        match c {
            _ if escaped => escaped = false,
            '\\' => escaped = true,
            '"' => return i,
            _ => {}
        }
    }
    s.len()
}

/// Removes the backslash escapes of a quoted string.
fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut escaped = false;
    for c in s.chars() {
        if escaped || c != '\\' {
            out.push(c);
            escaped = false;
        } else {
            escaped = true;
        }
    }
    out
}

/// Parameters of interest of a `Digest` challenge or authorization.
#[derive(Debug, Default)]
struct DigestParams {
    username: Option<String>,
    realm: Option<String>,
    uri: Option<String>,
    algorithm: Option<String>,
    qop: Option<String>,
}

/// One `key=value` parameter of an authentication header: lower-case key, unescaped value, and
/// whether the value was quoted.
struct AuthParam {
    key: String,
    value: String,
    quoted: bool,
}

/// Scheme and parameters of an authentication header value (`Digest k=v, k="v", ...`), at most
/// [`MAX_AUTH_PARAMS`]; the flag is set when more were left unread.
fn auth_params(text: &str) -> (&str, Vec<AuthParam>, bool) {
    let text = text.trim_start();
    let scheme_end = text
        .find(|c: char| c.is_ascii_whitespace())
        .unwrap_or(text.len());
    let scheme = text.get(..scheme_end).unwrap_or_default();
    let mut rest = text.get(scheme_end..).unwrap_or_default();
    let mut out = Vec::new();
    loop {
        rest = rest.trim_start_matches(|c: char| c == ',' || c.is_ascii_whitespace());
        let Some(eq) = rest.find('=') else { break };
        if out.len() >= MAX_AUTH_PARAMS {
            return (scheme, out, true);
        }
        let key = rest
            .get(..eq)
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        rest = rest
            .get(eq.saturating_add(1)..)
            .unwrap_or_default()
            .trim_start();
        let (value, quoted) = if let Some(quoted) = rest.strip_prefix('"') {
            let end = closing_quote(quoted);
            rest = quoted.get(end.saturating_add(1)..).unwrap_or_default();
            (unescape(quoted.get(..end).unwrap_or(quoted)), true)
        } else {
            // A token ends at a comma or a blank: `username=alice response=abc` is two parameters.
            let end = rest
                .find(|c: char| c == ',' || c.is_ascii_whitespace())
                .unwrap_or(rest.len());
            let v = rest.get(..end).unwrap_or_default().to_owned();
            rest = rest.get(end..).unwrap_or_default();
            (v, false)
        };
        out.push(AuthParam { key, value, quoted });
    }
    (scheme, out, false)
}

/// `Digest k=v, k="v", ...`; `None` for another scheme.
fn digest_params(value: &[u8]) -> Option<DigestParams> {
    let text = String::from_utf8_lossy(value);
    let (scheme, params, _) = auth_params(&text);
    if !scheme.eq_ignore_ascii_case("digest") {
        return None;
    }
    let mut out = DigestParams::default();
    for p in params {
        let slot = match p.key.as_str() {
            "username" => &mut out.username,
            "realm" => &mut out.realm,
            "uri" => &mut out.uri,
            "algorithm" => &mut out.algorithm,
            "qop" => &mut out.qop,
            _ => continue,
        };
        if slot.is_none() {
            *slot = field(p.value.as_bytes(), MAX_FIELD);
        }
    }
    Some(out)
}

/// Decimal number (surrounding spaces allowed), saturated to `u32::MAX`.
fn number(value: &[u8]) -> Option<u32> {
    let text = std::str::from_utf8(value.get(..value.len().min(32))?)
        .ok()?
        .trim();
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(
        text.parse::<u64>()
            .map_or(u32::MAX, |n| u32::try_from(n).unwrap_or(u32::MAX)),
    )
}

fn trim_cr(line: &[u8]) -> &[u8] {
    line.strip_suffix(b"\r").unwrap_or(line)
}

/// Invisible or bidirectional formatting characters, replaced in displayed text.
pub(crate) fn is_invisible(c: char) -> bool {
    matches!(c, '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{FEFF}')
}

/// Value as bounded, trimmed text without control or invisible characters; `None` when empty.
pub(crate) fn field(value: &[u8], max: usize) -> Option<String> {
    let head = value.get(..value.len().min(max.saturating_add(4)))?;
    let text: String = String::from_utf8_lossy(head)
        .chars()
        .map(|c| match c {
            '\t' => ' ',
            c if c.is_control() || is_invisible(c) => char::REPLACEMENT_CHARACTER,
            c => c,
        })
        .collect();
    let text = cut(text.trim(), max).trim_end();
    (!text.is_empty()).then(|| text.to_owned())
}

/// The longest prefix of `s` of at most `max` bytes ending on a character boundary.
pub(crate) fn cut(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    s.get(..end).unwrap_or_default()
}

/// Displayable raw text of the first `max` bytes of a message (see [`SipMessage::raw`]) and
/// whether it was cut.
pub fn raw_text(data: &[u8], max: usize) -> (String, bool) {
    let truncated = data.len() > max;
    let head = data.get(..data.len().min(max)).unwrap_or(data);
    let text = String::from_utf8_lossy(head);
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            // A lone CR is not a line end for the parser: never one in the text either (an
            // authentication header must not pass for body text, see `redact_auth`).
            '\r' => {
                if chars.peek() != Some(&'\n') {
                    out.push(char::REPLACEMENT_CHARACTER);
                }
            }
            '\n' | '\t' => out.push(c),
            c if c.is_control() || is_invisible(c) => out.push(char::REPLACEMENT_CHARACTER),
            c => out.push(c),
        }
    }
    (out, truncated)
}

/// `text` with the password of every `sip:` / `sips:` URI masked: `sip:alice:secret@host`
/// becomes `sip:alice:<masked>@host`. The user part ends at `@`; a URI without `@` before its
/// end (`;`, `?`, `>`, `,`, a quote or a blank) has no user part.
pub fn mask_uri_passwords(text: &str) -> String {
    let lower = text.to_ascii_lowercase();
    let mut out = String::with_capacity(text.len());
    let mut done = 0usize;
    let mut search = 0usize;
    while let Some(found) = lower.get(search..).and_then(|t| t.find("sip")) {
        let at = search.saturating_add(found);
        let after = lower.get(at..).unwrap_or_default();
        let scheme = if after.starts_with("sips:") {
            5
        } else if after.starts_with("sip:") {
            4
        } else {
            search = at.saturating_add(3);
            continue;
        };
        let user_start = at.saturating_add(scheme);
        let rest = text.get(user_start..).unwrap_or_default();
        let end = rest
            .find(|c: char| {
                matches!(c, '@' | ';' | '?' | '>' | ',' | '"' | '<') || c.is_whitespace()
            })
            .unwrap_or(rest.len());
        search = user_start.saturating_add(end);
        if !rest.get(end..).unwrap_or_default().starts_with('@') {
            continue;
        }
        let Some(colon) = rest.get(..end).and_then(|u| u.find(':')) else {
            continue;
        };
        let pass_start = user_start.saturating_add(colon).saturating_add(1);
        out.push_str(text.get(done..pass_start).unwrap_or_default());
        out.push_str(MASK);
        done = user_start.saturating_add(end);
    }
    out.push_str(text.get(done..).unwrap_or_default());
    out
}

/// What replaces a secret in the raw text.
pub const MASK: &str = "<masked>";
/// Digest parameters kept in clear in the raw text: identity and context, never the proof
/// (`response`, `nonce`, `cnonce`, `opaque`, `nc`, `nextnonce`, `rspauth`... are masked).
const KEPT_AUTH_PARAMS: &[&str] = &[
    "username",
    "realm",
    "uri",
    "algorithm",
    "qop",
    "stale",
    "domain",
];

/// Headers whose value carries authentication material (RFC 3261 section 20; none has a compact
/// form).
fn is_auth_header(name: &str) -> bool {
    [
        "authorization",
        "proxy-authorization",
        "www-authenticate",
        "proxy-authenticate",
        "authentication-info",
    ]
    .iter()
    .any(|h| name.eq_ignore_ascii_case(h))
}

/// The value of an authentication header with its secrets masked: for `Digest`, the parameters of
/// [`KEPT_AUTH_PARAMS`] in clear and every other value replaced by [`MASK`]; for any other scheme
/// (`Basic`, unknown) and for `Authentication-Info`, the whole value.
fn redact_auth_value(name: &str, value: &str) -> String {
    if name.eq_ignore_ascii_case("authentication-info") {
        return MASK.to_owned();
    }
    let (scheme, params, more) = auth_params(value);
    if !scheme.eq_ignore_ascii_case("digest") {
        return MASK.to_owned();
    }
    let mut parts: Vec<String> = params
        .iter()
        .map(|p| {
            if !KEPT_AUTH_PARAMS.contains(&p.key.as_str()) {
                format!("{}={MASK}", p.key)
            } else if p.quoted {
                format!(
                    "{}=\"{}\"",
                    p.key,
                    p.value.replace('\\', "\\\\").replace('"', "\\\"")
                )
            } else {
                format!("{}={}", p.key, p.value)
            }
        })
        .collect();
    if more {
        parts.push(MASK.to_owned());
    }
    format!("{scheme} {}", parts.join(", "))
}

/// Raw text (LF line ends) with the values of the authentication headers of its head masked
/// ([`redact_auth_value`]), folded continuation lines included (joined to their header). The
/// start line and the body are kept as they are.
pub fn redact_auth(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    // An authentication header being read: its name and value (continuation lines appended).
    let mut pending: Option<(String, String)> = None;
    let flush = |out: &mut String, pending: &mut Option<(String, String)>| {
        if let Some((name, value)) = pending.take() {
            out.push_str(&name);
            out.push_str(": ");
            out.push_str(&redact_auth_value(&name, &value));
            out.push('\n');
        }
    };
    let mut in_head = true;
    let mut lines = raw.split_inclusive('\n').enumerate();
    for (i, line) in lines.by_ref() {
        let content = line.strip_suffix('\n').unwrap_or(line);
        let folded = content.starts_with([' ', '\t']);
        if folded && let Some((_, value)) = pending.as_mut() {
            value.push(' ');
            value.push_str(content.trim());
            continue;
        }
        flush(&mut out, &mut pending);
        if i == 0 {
            out.push_str(line);
            continue;
        }
        if content.is_empty() {
            in_head = false;
            out.push_str(line);
            break;
        }
        match content.split_once(':') {
            Some((name, value)) if is_auth_header(name.trim()) => {
                pending = Some((name.trim().to_owned(), value.trim().to_owned()));
            }
            _ => out.push_str(line),
        }
    }
    flush(&mut out, &mut pending);
    if !in_head {
        for (_, line) in lines {
            out.push_str(line);
        }
    }
    // A raw text without final line end keeps none.
    if !raw.ends_with('\n') && out.ends_with('\n') {
        out.pop();
    }
    out
}

#[cfg(test)]
mod tests;
