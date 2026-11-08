//! Start lines and headers (`httparse`), message detection and body framing rules.

use super::body::Framing;
use super::types::HttpHeader;

/// Longest head (start line and headers) accepted; past it the direction is abandoned.
pub(crate) const MAX_HEAD: usize = 64 * 1024;
/// Most headers parsed in one message.
const MAX_HEADERS: usize = 128;
/// Longest method token.
const MAX_METHOD: usize = 24;

/// A parsed request head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RequestHead {
    pub(crate) method: String,
    pub(crate) target: String,
    pub(crate) minor_version: u8,
    pub(crate) headers: Vec<HttpHeader>,
}

/// A parsed response head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResponseHead {
    pub(crate) minor_version: u8,
    pub(crate) status: u16,
    pub(crate) reason: String,
    pub(crate) headers: Vec<HttpHeader>,
}

/// Index just past the blank line ending a head, searching from `from` (bytes before it were
/// already searched). Accepts CRLF and bare LF line ends.
pub(crate) fn head_end(buf: &[u8], from: usize) -> Option<usize> {
    let mut i = from.saturating_sub(3);
    while let Some(off) = buf.get(i..)?.iter().position(|&b| b == b'\n') {
        let nl = i + off;
        let prev = nl.checked_sub(1).and_then(|p| buf.get(p));
        let prev2 = nl.checked_sub(2).and_then(|p| buf.get(p));
        if prev == Some(&b'\n') || (prev == Some(&b'\r') && prev2 == Some(&b'\n')) {
            return Some(nl + 1);
        }
        i = nl + 1;
    }
    None
}

fn config() -> httparse::ParserConfig {
    let mut c = httparse::ParserConfig::default();
    c.allow_spaces_after_header_name_in_responses(true)
        .allow_obsolete_multiline_headers_in_responses(true)
        .allow_multiple_spaces_in_request_line_delimiters(true)
        .allow_multiple_spaces_in_response_status_delimiters(true)
        .ignore_invalid_headers_in_responses(true)
        .ignore_invalid_headers_in_requests(true);
    c
}

fn headers(raw: &[httparse::Header<'_>]) -> Vec<HttpHeader> {
    raw.iter()
        .map(|h| HttpHeader {
            name: h.name.to_owned(),
            value: String::from_utf8_lossy(h.value).trim().to_owned(),
        })
        .collect()
}

/// Parses a complete request head (`buf` ends with the blank line).
pub(crate) fn parse_request(buf: &[u8]) -> Option<RequestHead> {
    let mut raw = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut req = httparse::Request::new(&mut raw);
    match config().parse_request(&mut req, buf) {
        Ok(httparse::Status::Complete(_)) => {}
        _ => return None,
    }
    Some(RequestHead {
        method: req.method?.to_owned(),
        target: req.path?.to_owned(),
        minor_version: req.version?,
        headers: headers(req.headers),
    })
}

/// Parses a complete response head.
pub(crate) fn parse_response(buf: &[u8]) -> Option<ResponseHead> {
    let mut raw = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut resp = httparse::Response::new(&mut raw);
    match config().parse_response(&mut resp, buf) {
        Ok(httparse::Status::Complete(_)) => {}
        _ => return None,
    }
    Some(ResponseHead {
        minor_version: resp.version?,
        status: resp.code?,
        reason: resp.reason.unwrap_or_default().to_owned(),
        headers: headers(resp.headers),
    })
}

/// True when `data` may start a request: a method token, a space, and, if the first line is
/// complete, ` HTTP/1.x` at its end.
pub(crate) fn starts_request(data: &[u8]) -> bool {
    let token = data
        .iter()
        .take_while(|b| b.is_ascii_uppercase() || matches!(b, b'-' | b'_'))
        .count();
    if token == 0 || token > MAX_METHOD {
        return false;
    }
    match data.get(token) {
        None => return true,
        Some(b' ') => {}
        Some(_) => return false,
    }
    let window = data.get(..MAX_HEAD.min(data.len())).unwrap_or_default();
    match window.iter().position(|&b| b == b'\n') {
        Some(nl) => {
            let line = window.get(..nl).unwrap_or_default();
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            line.len() >= 8 && line.get(line.len() - 8..line.len() - 1) == Some(b"HTTP/1.")
        }
        None => window.len() < MAX_HEAD,
    }
}

/// True when `data` may start a response (`HTTP/1.`, or a prefix of it).
pub(crate) fn starts_response(data: &[u8]) -> bool {
    const PREFIX: &[u8] = b"HTTP/1.";
    let n = data.len().min(PREFIX.len());
    n > 0 && data.get(..n) == PREFIX.get(..n)
}

/// Body framing of a request; `None` when its framing is invalid.
pub(crate) fn request_framing(headers: &[HttpHeader]) -> Option<Framing> {
    if let Some(te) = transfer_encoding(headers) {
        // A request with a transfer coding other than chunked last cannot be delimited.
        return is_chunked_last(&te).then_some(Framing::Chunked);
    }
    match content_length(headers) {
        Length::Valid(n) => Some(Framing::Length(n)),
        Length::Absent => Some(Framing::Length(0)),
        Length::Invalid => None,
    }
}

/// What follows a response head.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ResponseNext {
    /// Interim response (1xx other than 101): no body, the final response follows.
    Interim,
    /// The connection stops being HTTP (101 Switching Protocols, 2xx to CONNECT).
    Tunnel,
    Body(Framing),
}

/// Body framing of a response to `method` (`None` when the request is unknown).
pub(crate) fn response_next(
    status: u16,
    method: Option<&str>,
    headers: &[HttpHeader],
) -> Option<ResponseNext> {
    let connect = method.is_some_and(|m| m.eq_ignore_ascii_case("CONNECT"));
    if status == 101 || (connect && (200..300).contains(&status)) {
        return Some(ResponseNext::Tunnel);
    }
    if (100..200).contains(&status) {
        return Some(ResponseNext::Interim);
    }
    let head = method.is_some_and(|m| m.eq_ignore_ascii_case("HEAD"));
    if head || status == 204 || status == 304 {
        return Some(ResponseNext::Body(Framing::Length(0)));
    }
    if let Some(te) = transfer_encoding(headers) {
        return Some(ResponseNext::Body(if is_chunked_last(&te) {
            Framing::Chunked
        } else {
            Framing::UntilClose
        }));
    }
    match content_length(headers) {
        Length::Valid(n) => Some(ResponseNext::Body(Framing::Length(n))),
        Length::Absent => Some(ResponseNext::Body(Framing::UntilClose)),
        Length::Invalid => None,
    }
}

fn transfer_encoding(headers: &[HttpHeader]) -> Option<String> {
    let mut all = headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case("transfer-encoding"))
        .map(|h| h.value.as_str())
        .peekable();
    all.peek()?;
    Some(all.collect::<Vec<_>>().join(","))
}

fn is_chunked_last(te: &str) -> bool {
    te.split(',')
        .map(str::trim)
        .rfind(|c| !c.is_empty())
        .is_some_and(|c| c.eq_ignore_ascii_case("chunked"))
}

enum Length {
    Absent,
    Valid(u64),
    Invalid,
}

/// `Content-Length`, possibly repeated or listed with identical values (RFC 9110, 8.6).
fn content_length(headers: &[HttpHeader]) -> Length {
    let mut found: Option<u64> = None;
    for h in headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case("content-length"))
    {
        for part in h.value.split(',') {
            let part = part.trim();
            if part.is_empty() || part.len() > 19 || !part.bytes().all(|b| b.is_ascii_digit()) {
                return Length::Invalid;
            }
            let Ok(n) = part.parse::<u64>() else {
                return Length::Invalid;
            };
            match found {
                Some(prev) if prev != n => return Length::Invalid,
                _ => found = Some(n),
            }
        }
    }
    found.map_or(Length::Absent, Length::Valid)
}

/// The content coding of a message, lower case (`Content-Encoding`).
pub(crate) fn content_encoding(headers: &[HttpHeader]) -> Option<String> {
    let value = headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case("content-encoding"))
        .map(|h| h.value.trim().to_ascii_lowercase())
        .filter(|v| !v.is_empty())
        .collect::<Vec<_>>()
        .join(", ");
    (!value.is_empty()).then_some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(name: &str, value: &str) -> HttpHeader {
        HttpHeader {
            name: name.to_owned(),
            value: value.to_owned(),
        }
    }

    #[test]
    fn head_end_finds_crlf_and_lf_terminators() {
        assert_eq!(head_end(b"GET / HTTP/1.1\r\nA: b\r\n\r\nbody", 0), Some(24));
        assert_eq!(head_end(b"GET / HTTP/1.1\nA: b\n\nbody", 0), Some(21));
        assert_eq!(head_end(b"GET / HTTP/1.1\r\nA: b\r\n", 0), None);
        // Resuming a search that stopped in the middle of the terminator.
        let buf = b"GET / HTTP/1.1\r\nA: b\r\n\r\n";
        assert_eq!(head_end(buf, 23), Some(24));
        assert_eq!(head_end(b"", 0), None);
        assert_eq!(head_end(b"\n", 5), None);
    }

    #[test]
    fn parses_heads() {
        let req =
            parse_request(b"POST /login?x=1 HTTP/1.0\r\nHost: a.test\r\nX-Folded:  v \r\n\r\n")
                .unwrap();
        assert_eq!(req.method, "POST");
        assert_eq!(req.target, "/login?x=1");
        assert_eq!(req.minor_version, 0);
        assert_eq!(req.headers, vec![h("Host", "a.test"), h("X-Folded", "v")]);
        let resp = parse_response(b"HTTP/1.1 404 Not Found\r\nServer: x\r\n\r\n").unwrap();
        assert_eq!((resp.status, resp.reason.as_str()), (404, "Not Found"));
        assert!(parse_response(b"HTTP/2 200\r\n\r\n").is_none());
        assert!(parse_request(b"\x16\x03\x01 garbage\r\n\r\n").is_none());
        let mut many = b"GET / HTTP/1.1\r\n".to_vec();
        for i in 0..200 {
            many.extend_from_slice(format!("H{i}: v\r\n").as_bytes());
        }
        many.extend_from_slice(b"\r\n");
        assert!(parse_request(&many).is_none(), "too many headers");
    }

    #[test]
    fn detects_message_starts() {
        assert!(starts_request(b"GET /index.html HTTP/1.1\r\nHost: x\r\n"));
        assert!(starts_request(b"PROPFIND /dav HTTP/1.1\r\n"));
        assert!(starts_request(b"GE"));
        assert!(starts_request(b"GET /very-long-path-without-line-end"));
        assert!(!starts_request(b"GET / SMTP/1.0\r\n"));
        assert!(!starts_request(b"get / HTTP/1.1\r\n"));
        assert!(!starts_request(b"\x16\x03\x01\x02\x00"));
        assert!(!starts_request(b"SSH-2.0-OpenSSH\r\n"));
        assert!(!starts_request(b""));
        assert!(starts_response(b"HTTP/1.1 200 OK"));
        assert!(starts_response(b"HTT"));
        assert!(!starts_response(b"HTTP/2"));
        assert!(!starts_response(b""));
    }

    #[test]
    fn framing_rules() {
        use ResponseNext::{Body, Interim, Tunnel};
        assert_eq!(request_framing(&[]), Some(Framing::Length(0)));
        assert_eq!(
            request_framing(&[h("Content-Length", "12")]),
            Some(Framing::Length(12))
        );
        assert_eq!(
            request_framing(&[h("Content-Length", "12, 12"), h("content-length", "12")]),
            Some(Framing::Length(12))
        );
        assert_eq!(request_framing(&[h("Content-Length", "1, 2")]), None);
        assert_eq!(request_framing(&[h("Content-Length", "-1")]), None);
        assert_eq!(
            request_framing(&[h("Content-Length", "99999999999999999999")]),
            None
        );
        assert_eq!(
            request_framing(&[
                h("Transfer-Encoding", "gzip, chunked"),
                h("Content-Length", "3")
            ]),
            Some(Framing::Chunked)
        );
        assert_eq!(request_framing(&[h("Transfer-Encoding", "gzip")]), None);

        assert_eq!(response_next(100, Some("GET"), &[]), Some(Interim));
        assert_eq!(response_next(101, Some("GET"), &[]), Some(Tunnel));
        assert_eq!(response_next(200, Some("CONNECT"), &[]), Some(Tunnel));
        assert_eq!(
            response_next(407, Some("CONNECT"), &[h("Content-Length", "0")]),
            Some(Body(Framing::Length(0)))
        );
        assert_eq!(
            response_next(200, Some("HEAD"), &[h("Content-Length", "50")]),
            Some(Body(Framing::Length(0)))
        );
        assert_eq!(
            response_next(304, None, &[]),
            Some(Body(Framing::Length(0)))
        );
        assert_eq!(
            response_next(200, None, &[]),
            Some(Body(Framing::UntilClose))
        );
        assert_eq!(
            response_next(200, None, &[h("Transfer-Encoding", "chunked")]),
            Some(Body(Framing::Chunked))
        );
        assert_eq!(
            response_next(200, None, &[h("Transfer-Encoding", "gzip")]),
            Some(Body(Framing::UntilClose))
        );
    }

    #[test]
    fn content_encoding_is_normalized() {
        assert_eq!(
            content_encoding(&[h("Content-Encoding", " GZIP ")]).as_deref(),
            Some("gzip")
        );
        assert_eq!(content_encoding(&[]), None);
    }
}
