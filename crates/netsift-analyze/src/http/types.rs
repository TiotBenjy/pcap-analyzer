//! Public types of the `http` analyzer: settings and the transactions it emits.

use netsift_flow::{Endpoint, FlowId};

use crate::analyzer::BlobRef;

/// Settings of the `http` analyzer (`AnalyzerConfig::http`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpConfig {
    /// Largest decoded body (after de-chunking and content decoding) of one message, in bytes:
    /// decoding stops there and the body is marked `truncated` (`docs/specs/http.md`: 64 MiB).
    pub max_body_bytes: u64,
    /// Decoded body bytes kept in memory by one analyzer instance (one shard) at a time, all
    /// messages together. Past it, bodies are still decoded and counted but not kept (no
    /// object, no preview beyond what was kept). The bound is **per shard**: the engine runs
    /// one instance per shard, so the total is this value times the number of shards (a
    /// budget shared by every shard is a follow-up of task P4.2).
    pub max_retained_bytes: usize,
    /// Store selected bodies as objects ([`crate::RecordSink::put_blob`], task P3.6, ADR-016).
    /// On by default. Selection ([`super::objects::selected`]): **response** bodies only,
    /// read and decoded completely (not a `206` partial response), whose **content** is an image
    /// by magic number ([`super::objects::IMAGE_TYPES`]: PNG, JPEG, GIF, WebP, BMP, ICO, SVG;
    /// the declared `Content-Type` is ignored), between [`Self::object_min_bytes`] and
    /// [`Self::object_max_bytes`]. Pages, scripts, forms, uploads and every request body never
    /// reach the disk. The engine adds a budget for the whole session (all blobs, TLS
    /// certificates included: `IngestOptions::max_blob_bytes`); past it, bodies are no longer
    /// stored (the transaction keeps its metadata). While off, only the start of each body is
    /// kept in memory (preview and MIME sniffing), and nothing is written to disk.
    pub store_bodies: bool,
    /// Smallest body stored as an object, in bytes (smaller ones cannot be a useful picture).
    pub object_min_bytes: u64,
    /// Largest body stored as an object, in bytes (also bounds the thumbnail decoding).
    pub object_max_bytes: u64,
    /// Content decoding stops (`bomb`) when the decoded size exceeds this many times the
    /// encoded size, once at least [`RATIO_CHECK_MIN`] bytes were decoded.
    pub max_decompression_ratio: u64,
    /// Requests waiting for their response, per connection (pipelining). Past it, the oldest
    /// one is emitted without response.
    pub max_pending: usize,
    /// Content decoders (gzip, deflate, brotli) alive at a time per shard. Past it, new
    /// compressed bodies are counted but not decoded (`not_decoded`).
    pub max_decoders: usize,
    /// Brotli decoders alive at a time per shard, within `max_decoders`: the window of one
    /// stream may take 16 MiB (`WBITS` 24) as soon as its header is read, before any output,
    /// so the ratio check cannot protect against many idle streams.
    pub max_brotli_decoders: usize,
    /// Size of the text preview kept for textual bodies, in bytes.
    pub preview_bytes: usize,
}

/// Decoded size from which the decompression ratio is checked (small bodies of zeros are fine).
pub const RATIO_CHECK_MIN: u64 = 1024 * 1024;

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            max_body_bytes: 64 * 1024 * 1024,
            max_retained_bytes: 32 * 1024 * 1024,
            store_bodies: true,
            object_min_bytes: 32,
            object_max_bytes: 16 * 1024 * 1024,
            max_decompression_ratio: 250,
            max_pending: 64,
            max_decoders: 64,
            max_brotli_decoders: 4,
            preview_bytes: 4096,
        }
    }
}

/// One header line, as sent (name case kept, value decoded as lossy UTF-8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpHeader {
    pub name: String,
    pub value: String,
}

/// Outcome of reading and decoding a message body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum BodyState {
    /// The message has no body (or an empty one).
    None,
    /// Read and decoded completely.
    Complete,
    /// Bytes are missing: capture gap, or the connection ended before the end of the body.
    Incomplete,
    /// Decoding stopped at [`HttpConfig::max_body_bytes`].
    Truncated,
    /// Decoding stopped by the decompression ratio limit (decompression bomb).
    Bomb,
    /// The content coding is corrupt.
    DecodeError,
    /// Content coding not supported (or no decoder available): the body is kept encoded.
    NotDecoded,
    /// Invalid framing (chunked encoding, length): the rest of the connection is skipped.
    Malformed,
}

impl BodyState {
    /// Stable label stored in the database.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Complete => "complete",
            Self::Incomplete => "incomplete",
            Self::Truncated => "truncated",
            Self::Bomb => "bomb",
            Self::DecodeError => "decode_error",
            Self::NotDecoded => "not_decoded",
            Self::Malformed => "malformed",
        }
    }
}

/// Body of a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpBody {
    /// Bytes of the body on the wire, chunked framing included.
    pub wire_len: u64,
    /// Bytes after de-chunking and content decoding (raw bytes when not decoded).
    pub decoded_len: u64,
    /// `Transfer-Encoding: chunked`.
    pub chunked: bool,
    /// `Content-Encoding` as sent (lower case), `None` when absent.
    pub content_encoding: Option<String>,
    pub state: BodyState,
    /// MIME type sniffed from the first decoded bytes (magic numbers), independent of the
    /// `Content-Type` header.
    pub mime_magic: Option<&'static str>,
    /// Start of a textual body (at most [`HttpConfig::preview_bytes`], cut on a character).
    pub preview: Option<String>,
    /// Extracted object, when the sink stores blobs and the body is complete.
    pub blob: Option<BlobRef>,
}

/// What requests and responses have in common.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpMessage {
    /// Packet time of the first byte of the message.
    pub ts_ns: i64,
    /// Packet time of the last byte read.
    pub end_ts_ns: i64,
    /// Frame of the first byte (provenance, PCAP export).
    pub frame: u64,
    /// Length of the start line and headers, blank line included.
    pub head_len: u64,
    pub headers: Vec<HttpHeader>,
    pub body: HttpBody,
}

impl HttpMessage {
    /// Value of the first header named `name` (ASCII case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| h.value.as_str())
    }
}

/// A request message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    pub method: String,
    /// Request target as sent (origin, absolute, authority or asterisk form).
    pub target: String,
    /// `0` for HTTP/1.0, `1` for HTTP/1.1.
    pub minor_version: u8,
    pub message: HttpMessage,
}

/// A response message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub minor_version: u8,
    pub status: u16,
    pub reason: String,
    pub message: HttpMessage,
}

/// A request and its response, or one of them alone (request without response, response whose
/// request was not captured).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpTransaction {
    pub flow: FlowId,
    pub client: Endpoint,
    pub server: Endpoint,
    /// Order of the transaction in its connection (0-based).
    pub seq: u32,
    pub request: Option<HttpRequest>,
    pub response: Option<HttpResponse>,
}

/// Longest derived text (host, media type) kept, in bytes.
const MAX_DERIVED: usize = 1024;

impl HttpTransaction {
    /// Time of the transaction: its request, else its response.
    pub fn ts_ns(&self) -> i64 {
        self.request
            .as_ref()
            .map(|r| r.message.ts_ns)
            .or_else(|| self.response.as_ref().map(|r| r.message.ts_ns))
            .unwrap_or(0)
    }

    /// Time of the last byte of the transaction.
    pub fn end_ts_ns(&self) -> i64 {
        let req = self.request.as_ref().map(|r| r.message.end_ts_ns);
        let resp = self.response.as_ref().map(|r| r.message.end_ts_ns);
        req.into_iter().chain(resp).max().unwrap_or(0)
    }

    /// Host asked for: authority of an absolute or authority-form target, else the `Host`
    /// header; lower case, user information removed.
    pub fn host(&self) -> Option<String> {
        let req = self.request.as_ref()?;
        let authority = target_parts(&req.method, &req.target)
            .authority
            .or_else(|| req.message.header("host"))?;
        let authority = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
        let host = authority.trim();
        (!host.is_empty()).then(|| bounded(&host.to_ascii_lowercase()))
    }

    /// Path of the target (without query nor fragment), `None` for the authority form.
    pub fn path(&self) -> Option<String> {
        let req = self.request.as_ref()?;
        target_parts(&req.method, &req.target)
            .path
            .map(ToOwned::to_owned)
    }

    /// Query of the target (after `?`, without fragment).
    pub fn query(&self) -> Option<String> {
        let req = self.request.as_ref()?;
        target_parts(&req.method, &req.target)
            .query
            .map(ToOwned::to_owned)
    }

    pub fn user_agent(&self) -> Option<&str> {
        self.request.as_ref()?.message.header("user-agent")
    }

    pub fn referer(&self) -> Option<&str> {
        self.request.as_ref()?.message.header("referer")
    }

    /// Media type of the response (`Content-Type` without parameters, lower case).
    pub fn content_type(&self) -> Option<String> {
        media_type(self.response.as_ref()?.message.header("content-type")?)
    }

    /// Media type of the request body.
    pub fn request_content_type(&self) -> Option<String> {
        media_type(self.request.as_ref()?.message.header("content-type")?)
    }
}

/// `type/subtype` of a `Content-Type` value, lower case, `None` when empty.
pub fn media_type(value: &str) -> Option<String> {
    let essence = value.split(';').next().unwrap_or_default().trim();
    (!essence.is_empty()).then(|| bounded(&essence.to_ascii_lowercase()))
}

fn bounded(s: &str) -> String {
    if s.len() <= MAX_DERIVED {
        return s.to_owned();
    }
    let mut end = MAX_DERIVED;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s.get(..end).unwrap_or_default().to_owned()
}

#[derive(Debug, Default, PartialEq, Eq)]
struct TargetParts<'a> {
    authority: Option<&'a str>,
    path: Option<&'a str>,
    query: Option<&'a str>,
}

/// Splits a request target (RFC 9112, section 3.2).
fn target_parts<'a>(method: &str, target: &'a str) -> TargetParts<'a> {
    if method.eq_ignore_ascii_case("CONNECT") {
        return TargetParts {
            authority: Some(target),
            ..TargetParts::default()
        };
    }
    let (authority, rest) = match target.split_once("://") {
        Some((scheme, after))
            if !scheme.is_empty() && scheme.bytes().all(|b| b.is_ascii_alphanumeric()) =>
        {
            let end = after.find(['/', '?', '#']).unwrap_or(after.len());
            let (auth, rest) = after.split_at_checked(end).unwrap_or((after, ""));
            (Some(auth), rest)
        }
        _ => (None, target),
    };
    let rest = rest.split('#').next().unwrap_or_default();
    let (path, query) = match rest.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (rest, None),
    };
    let path = if path.is_empty() && authority.is_some() {
        "/"
    } else {
        path
    };
    TargetParts {
        authority,
        path: (!path.is_empty()).then_some(path),
        query,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_forms() {
        assert_eq!(
            target_parts("GET", "/a/b?x=1&y=2#frag"),
            TargetParts {
                authority: None,
                path: Some("/a/b"),
                query: Some("x=1&y=2"),
            }
        );
        assert_eq!(
            target_parts("GET", "http://Example.test:8080?q"),
            TargetParts {
                authority: Some("Example.test:8080"),
                path: Some("/"),
                query: Some("q"),
            }
        );
        assert_eq!(
            target_parts("CONNECT", "example.test:443"),
            TargetParts {
                authority: Some("example.test:443"),
                path: None,
                query: None,
            }
        );
        assert_eq!(target_parts("OPTIONS", "*").path, Some("*"));
    }

    #[test]
    fn media_types() {
        assert_eq!(
            media_type("Text/HTML; charset=utf-8").as_deref(),
            Some("text/html")
        );
        assert_eq!(media_type(" ; x").as_deref(), None);
        let long = "a".repeat(5000);
        assert_eq!(media_type(&long).map(|s| s.len()), Some(MAX_DERIVED));
    }
}
