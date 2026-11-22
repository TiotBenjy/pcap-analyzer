//! SSDP message parser (`UPnP` Device Architecture 1.1 / 2.0, section 1: discovery).
//!
//! SSDP is HTTP/1.1 over UDP ("HTTPU"): `NOTIFY * HTTP/1.1` announcements (`ssdp:alive`,
//! `ssdp:byebye`, `ssdp:update`), `M-SEARCH * HTTP/1.1` searches and `HTTP/1.1 200 OK` answers.
//! The head is read with `httparse`, tolerant of what devices actually send: LF-only line ends, a
//! missing final empty line (truncated datagram), spaces after a header name and invalid header
//! lines (skipped).
//!
//! Captures are hostile input: at most [`MAX_PARSE`] bytes are parsed and [`MAX_HEADERS`] headers
//! read, every extracted field is cut to [`MAX_FIELD`] bytes and the raw text kept for display to
//! [`MAX_RAW`] bytes, control characters replaced. [`parse`] never fails: what is not a valid
//! SSDP message is [`SsdpKind::Invalid`], with its raw text.

/// Bytes of a datagram given to the HTTP parser (SSDP messages are far smaller).
pub const MAX_PARSE: usize = 8 * 1024;
/// Headers read from one message; more makes the message invalid.
pub const MAX_HEADERS: usize = 64;
/// Longest extracted field value, in bytes (cut on a character boundary).
pub const MAX_FIELD: usize = 512;
/// Bytes of the datagram kept as raw text for display.
pub const MAX_RAW: usize = 2048;
/// Longest device identifier taken from a USN.
const MAX_UUID: usize = 128;

/// Kind of an SSDP message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SsdpKind {
    /// `NOTIFY * HTTP/1.1` (announcement).
    Notify,
    /// `M-SEARCH * HTTP/1.1` (search).
    Search,
    /// `HTTP/1.1 <code>` (answer to a search).
    Response,
    /// Anything else on the SSDP port (other method, binary, unreadable first line).
    Invalid,
}

impl SsdpKind {
    /// Stable label stored in the database.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Notify => "notify",
            Self::Search => "search",
            Self::Response => "response",
            Self::Invalid => "invalid",
        }
    }
}

/// A decoded SSDP message. Text fields are bounded and free of control characters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsdpMessage {
    pub kind: SsdpKind,
    /// Notification sub-type of a `NOTIFY`: `alive`, `byebye`, `update`, or the (bounded) value
    /// as sent when it is not one of these.
    pub nts: Option<String>,
    /// Status code of a response.
    pub status: Option<u16>,
    /// `NT` of a notification, `ST` of a search or response.
    pub target: Option<String>,
    pub usn: Option<String>,
    /// Device identifier (lower case, without `uuid:`) from the USN, else from a `uuid:` target.
    pub uuid: Option<String>,
    /// `SERVER` header (notification, response).
    pub server: Option<String>,
    /// `USER-AGENT` header (search).
    pub user_agent: Option<String>,
    /// `LOCATION` header: URL of the device description. Extracted text, never fetched.
    pub location: Option<String>,
    /// `max-age` of `CACHE-CONTROL`, in seconds.
    pub max_age: Option<u32>,
    /// `MX` of a search, in seconds.
    pub mx: Option<u32>,
    /// Size of the datagram, in bytes.
    pub size: usize,
    /// The first [`MAX_RAW`] bytes as text: UTF-8 with replacement, LF line ends, control
    /// characters other than tab and LF replaced by U+FFFD. Displayed, never interpreted.
    pub raw: String,
    /// True when the datagram is longer than [`MAX_RAW`].
    pub raw_truncated: bool,
}

impl SsdpMessage {
    fn invalid(payload: &[u8]) -> Self {
        let (raw, raw_truncated) = raw_text(payload);
        Self {
            kind: SsdpKind::Invalid,
            nts: None,
            status: None,
            target: None,
            usn: None,
            uuid: None,
            server: None,
            user_agent: None,
            location: None,
            max_age: None,
            mx: None,
            size: payload.len(),
            raw,
            raw_truncated,
        }
    }

    /// Device type announced or searched (`urn:<domain>:device:<type>:<version>`), if any.
    pub fn device_type(&self) -> Option<&str> {
        self.target.as_deref().filter(|t| is_device_type(t))
    }
}

/// True for a `urn:<domain>:device:<type>:<version>` target.
pub fn is_device_type(target: &str) -> bool {
    let lower = target
        .get(..4)
        .is_some_and(|p| p.eq_ignore_ascii_case("urn:"));
    lower && target.to_ascii_lowercase().contains(":device:")
}

/// Head of the datagram read by `httparse`.
enum Head {
    Request { method: String },
    Response { status: u16 },
}

/// One header, name and value copied (the value cut a little beyond [`MAX_FIELD`]).
struct OwnedHeader {
    name: String,
    value: Vec<u8>,
}

/// Decodes one SSDP datagram. Never fails: see [`SsdpKind::Invalid`].
pub fn parse(payload: &[u8]) -> SsdpMessage {
    let mut msg = SsdpMessage::invalid(payload);
    let data = payload
        .get(..payload.len().min(MAX_PARSE))
        .unwrap_or(payload);
    let Some((head, headers)) = parse_head(data) else {
        return msg;
    };
    match head {
        Head::Request { method } => {
            if method.eq_ignore_ascii_case("NOTIFY") {
                msg.kind = SsdpKind::Notify;
            } else if method.eq_ignore_ascii_case("M-SEARCH") {
                msg.kind = SsdpKind::Search;
            } else {
                return msg;
            }
        }
        Head::Response { status } => {
            msg.kind = SsdpKind::Response;
            msg.status = Some(status);
        }
    }
    let mut nt = None;
    let mut st = None;
    // The first occurrence of a header wins.
    for h in &headers {
        let name = h.name.as_str();
        let value = || field(&h.value);
        if name.eq_ignore_ascii_case("NT") {
            nt = nt.or_else(value);
        } else if name.eq_ignore_ascii_case("ST") {
            st = st.or_else(value);
        } else if name.eq_ignore_ascii_case("NTS") {
            msg.nts = msg.nts.take().or_else(|| value().map(|v| nts_label(&v)));
        } else if name.eq_ignore_ascii_case("USN") {
            msg.usn = msg.usn.take().or_else(value);
        } else if name.eq_ignore_ascii_case("SERVER") {
            msg.server = msg.server.take().or_else(value);
        } else if name.eq_ignore_ascii_case("USER-AGENT") {
            msg.user_agent = msg.user_agent.take().or_else(value);
        } else if name.eq_ignore_ascii_case("LOCATION") {
            msg.location = msg.location.take().or_else(value);
        } else if name.eq_ignore_ascii_case("CACHE-CONTROL") {
            msg.max_age = msg.max_age.or_else(|| max_age(&h.value));
        } else if name.eq_ignore_ascii_case("MX") {
            msg.mx = msg.mx.or_else(|| number(&h.value));
        }
    }
    if msg.kind != SsdpKind::Notify {
        msg.nts = None;
    }
    msg.target = match msg.kind {
        SsdpKind::Notify => nt,
        _ => st,
    };
    msg.uuid = msg
        .usn
        .as_deref()
        .and_then(uuid_of)
        .or_else(|| msg.target.as_deref().and_then(uuid_of));
    msg
}

/// Parses the head as a response (`HTTP/...`) or a request. A datagram that ends inside the head
/// (no final empty line, or cut) is read again up to its last complete line, followed by an
/// empty line. `None` when it is not HTTP.
fn parse_head(data: &[u8]) -> Option<(Head, Vec<OwnedHeader>)> {
    let is_response = data.starts_with(b"HTTP/");
    match try_head(data, is_response) {
        Attempt::Done(head, headers) => Some((head, headers)),
        Attempt::Invalid => None,
        Attempt::Partial => {
            let end = data.iter().rposition(|b| *b == b'\n')?;
            let mut buf = Vec::with_capacity(end + 3);
            buf.extend_from_slice(data.get(..=end)?);
            buf.extend_from_slice(b"\r\n");
            match try_head(&buf, is_response) {
                Attempt::Done(head, headers) => Some((head, headers)),
                Attempt::Partial | Attempt::Invalid => None,
            }
        }
    }
}

enum Attempt {
    Done(Head, Vec<OwnedHeader>),
    Partial,
    Invalid,
}

fn config() -> httparse::ParserConfig {
    let mut c = httparse::ParserConfig::default();
    c.allow_spaces_after_header_name_in_responses(true)
        .allow_multiple_spaces_in_request_line_delimiters(true)
        .allow_multiple_spaces_in_response_status_delimiters(true)
        .ignore_invalid_headers_in_requests(true)
        .ignore_invalid_headers_in_responses(true);
    c
}

fn owned(headers: &[httparse::Header<'_>]) -> Vec<OwnedHeader> {
    headers
        .iter()
        .map(|h| OwnedHeader {
            name: h.name.to_owned(),
            value: h
                .value
                .get(..h.value.len().min(MAX_FIELD + 4))
                .unwrap_or_default()
                .to_vec(),
        })
        .collect()
}

fn try_head(data: &[u8], is_response: bool) -> Attempt {
    let cfg = config();
    let mut storage = [httparse::EMPTY_HEADER; MAX_HEADERS];
    if is_response {
        let mut res = httparse::Response::new(&mut storage);
        match cfg.parse_response(&mut res, data) {
            Ok(httparse::Status::Complete(_)) => match res.code {
                Some(status) => Attempt::Done(Head::Response { status }, owned(res.headers)),
                None => Attempt::Invalid,
            },
            Ok(httparse::Status::Partial) => Attempt::Partial,
            Err(_) => Attempt::Invalid,
        }
    } else {
        let mut req = httparse::Request::new(&mut storage);
        match cfg.parse_request(&mut req, data) {
            Ok(httparse::Status::Complete(_)) => match req.method {
                Some(m) => Attempt::Done(
                    Head::Request {
                        method: m.to_owned(),
                    },
                    owned(req.headers),
                ),
                None => Attempt::Invalid,
            },
            Ok(httparse::Status::Partial) => Attempt::Partial,
            Err(_) => Attempt::Invalid,
        }
    }
}

/// `alive` / `byebye` / `update` for the `ssdp:` sub-types, else the value itself.
fn nts_label(value: &str) -> String {
    let lower = value.to_ascii_lowercase();
    match lower.as_str() {
        "ssdp:alive" => "alive".to_owned(),
        "ssdp:byebye" => "byebye".to_owned(),
        "ssdp:update" => "update".to_owned(),
        _ => value.to_owned(),
    }
}

/// Device identifier of a USN or target: the text after `uuid:` up to `::`, lower case.
fn uuid_of(value: &str) -> Option<String> {
    let rest = value
        .get(..5)
        .filter(|p| p.eq_ignore_ascii_case("uuid:"))
        .and_then(|_| value.get(5..))?;
    let id = rest.split("::").next().unwrap_or_default().trim();
    if id.is_empty() {
        return None;
    }
    Some(cut(&id.to_ascii_lowercase(), MAX_UUID).to_owned())
}

/// `max-age=<seconds>` of a `CACHE-CONTROL` value (directives separated by commas).
fn max_age(value: &[u8]) -> Option<u32> {
    let text = String::from_utf8_lossy(value.get(..value.len().min(MAX_FIELD))?);
    text.split(',').find_map(|d| {
        let (name, v) = d.split_once('=')?;
        name.trim()
            .eq_ignore_ascii_case("max-age")
            .then(|| number(v.trim().trim_matches('"').as_bytes()))
            .flatten()
    })
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

/// Header value as bounded, trimmed text without control characters; `None` when empty.
fn field(value: &[u8]) -> Option<String> {
    let head = value.get(..value.len().min(MAX_FIELD + 4))?;
    let text: String = String::from_utf8_lossy(head)
        .chars()
        .map(|c| match c {
            '\t' => ' ',
            c if c.is_control() => char::REPLACEMENT_CHARACTER,
            c => c,
        })
        .collect();
    let text = cut(text.trim(), MAX_FIELD).trim_end();
    (!text.is_empty()).then(|| text.to_owned())
}

/// The longest prefix of `s` of at most `max` bytes ending on a character boundary.
fn cut(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s.get(..end).unwrap_or_default()
}

/// Displayable raw text of a datagram (see [`SsdpMessage::raw`]) and whether it was cut.
pub fn raw_text(payload: &[u8]) -> (String, bool) {
    let truncated = payload.len() > MAX_RAW;
    let head = payload.get(..payload.len().min(MAX_RAW)).unwrap_or(payload);
    let text = String::from_utf8_lossy(head);
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\r' => {
                if chars.peek() != Some(&'\n') {
                    out.push('\n');
                }
            }
            '\n' | '\t' => out.push(c),
            c if c.is_control() => out.push(char::REPLACEMENT_CHARACTER),
            c => out.push(c),
        }
    }
    (out, truncated)
}
