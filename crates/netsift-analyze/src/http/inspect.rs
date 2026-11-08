//! What is derived from a finished message: MIME type by content, text preview, extracted
//! object. [`inspect_message`] is the extension point of the analyzer (see the module
//! documentation of `http`).

use netsift_flow::{FlowId, FlowKey};

use super::types::{BodyState, HttpBody, HttpConfig, HttpHeader, media_type};
use crate::analyzer::RecordSink;

/// Direction of a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    Request,
    Response,
}

/// A finished message, as seen by [`inspect_message`].
#[derive(Debug, Clone, Copy)]
pub struct MessageView<'a> {
    pub flow: FlowId,
    /// Connection (`client` sent the requests).
    pub key: &'a FlowKey,
    pub role: Role,
    /// Packet time and frame of the first byte of the message.
    pub ts_ns: i64,
    pub frame: u64,
    /// Request method and target (requests only).
    pub method: Option<&'a str>,
    pub target: Option<&'a str>,
    /// Status code (responses only).
    pub status: Option<u16>,
    pub headers: &'a [HttpHeader],
    pub state: BodyState,
    /// Decoded body bytes kept in memory: the whole body when `body_complete`, otherwise a
    /// prefix (possibly empty: retention budget exhausted, or nothing decoded).
    pub body: &'a [u8],
    /// `body` holds the whole decoded body.
    pub body_complete: bool,
}

impl MessageView<'_> {
    /// Value of the first header named `name` (ASCII case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| h.value.as_str())
    }
}

/// Extension point, called once per finished message: fills the derived figures of `body`
/// (sniffed MIME type, preview, object). Complete bodies are offered to the sink as objects
/// ([`RecordSink::put_blob`], stored by the engine from P3.6). Credentials found in the
/// message (P3.7) are to be emitted here through `out`.
pub fn inspect_message(
    view: &MessageView<'_>,
    body: &mut HttpBody,
    config: &HttpConfig,
    out: &mut dyn RecordSink,
) {
    if view.body.is_empty() {
        return;
    }
    let decoded = view.state != BodyState::NotDecoded;
    body.mime_magic = decoded.then(|| sniff_mime(view.body)).flatten();
    if decoded {
        body.preview = preview(
            view.header("content-type"),
            body.mime_magic,
            view.body,
            config.preview_bytes,
        );
    }
    if view.body_complete {
        body.blob = out.put_blob(view.body);
    }
}

/// MIME type sniffed from the first bytes of a body (magic numbers). Only unambiguous
/// signatures: `None` rather than a guess.
pub fn sniff_mime(data: &[u8]) -> Option<&'static str> {
    const SIGNATURES: &[(&[u8], &str)] = &[
        (b"\x89PNG\r\n\x1a\n", "image/png"),
        (b"\xff\xd8\xff", "image/jpeg"),
        (b"GIF87a", "image/gif"),
        (b"GIF89a", "image/gif"),
        (b"BM", "image/bmp"),
        (b"\x00\x00\x01\x00", "image/x-icon"),
        (b"II*\x00", "image/tiff"),
        (b"MM\x00*", "image/tiff"),
        (b"%PDF-", "application/pdf"),
        (b"PK\x03\x04", "application/zip"),
        (b"\x1f\x8b", "application/gzip"),
        (b"7z\xbc\xaf\x27\x1c", "application/x-7z-compressed"),
        (b"Rar!\x1a\x07", "application/vnd.rar"),
        (b"MZ", "application/vnd.microsoft.portable-executable"),
        (b"\x7fELF", "application/x-elf"),
        (b"\x00asm", "application/wasm"),
        (b"wOFF", "font/woff"),
        (b"wOF2", "font/woff2"),
        (b"OggS", "application/ogg"),
        (b"ID3", "audio/mpeg"),
        (
            b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
            "application/x-ole-storage",
        ),
    ];
    if let Some((_, mime)) = SIGNATURES.iter().find(|(magic, _)| data.starts_with(magic)) {
        return Some(mime);
    }
    if data.len() >= 12 && data.starts_with(b"RIFF") && data.get(8..12) == Some(b"WEBP") {
        return Some("image/webp");
    }
    if data.get(4..8) == Some(b"ftyp") {
        return Some("video/mp4");
    }
    sniff_markup(data)
}

/// HTML, SVG and XML documents, after optional whitespace and byte order mark.
fn sniff_markup(data: &[u8]) -> Option<&'static str> {
    let head = data.get(..data.len().min(512)).unwrap_or_default();
    let head = head.strip_prefix(b"\xef\xbb\xbf").unwrap_or(head);
    let start = head.iter().position(|b| !b.is_ascii_whitespace())?;
    let text = head.get(start..)?.to_ascii_lowercase();
    if text.starts_with(b"<!doctype html") || text.starts_with(b"<html") {
        return Some("text/html");
    }
    if text.starts_with(b"<svg") || (text.starts_with(b"<?xml") && contains(&text, b"<svg")) {
        return Some("image/svg+xml");
    }
    text.starts_with(b"<?xml").then_some("application/xml")
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// True for media types whose content is text.
fn is_textual(media: &str) -> bool {
    media.starts_with("text/")
        || media.ends_with("+json")
        || media.ends_with("+xml")
        || matches!(
            media,
            "application/json"
                | "application/xml"
                | "application/javascript"
                | "application/ecmascript"
                | "application/x-www-form-urlencoded"
                | "application/graphql"
        )
}

/// Start of a textual body, at most `limit` bytes cut on a character boundary. A body is
/// textual when its `Content-Type` (or sniffed type) says so, or, without type, when its
/// start is valid UTF-8 without control characters.
pub fn preview(
    content_type: Option<&str>,
    sniffed: Option<&str>,
    data: &[u8],
    limit: usize,
) -> Option<String> {
    if data.is_empty() || limit == 0 {
        return None;
    }
    let declared = content_type.and_then(media_type);
    let textual = match (declared.as_deref(), sniffed) {
        (_, Some(s)) if s.starts_with("image/") && s != "image/svg+xml" => false,
        (Some(m), _) => is_textual(m) || sniffed.is_some_and(is_textual),
        (None, Some(s)) => is_textual(s),
        (None, None) => looks_like_text(data.get(..data.len().min(limit)).unwrap_or_default()),
    };
    if !textual {
        return None;
    }
    let cut = data.get(..data.len().min(limit)).unwrap_or_default();
    let valid = match std::str::from_utf8(cut) {
        Ok(s) => s,
        // A character cut at the end is dropped; invalid bytes elsewhere are replaced.
        Err(e) if e.error_len().is_none() => {
            std::str::from_utf8(cut.get(..e.valid_up_to()).unwrap_or_default()).unwrap_or_default()
        }
        Err(_) => return Some(String::from_utf8_lossy(cut).into_owned()),
    };
    Some(valid.to_owned())
}

fn looks_like_text(data: &[u8]) -> bool {
    let valid = match std::str::from_utf8(data) {
        Ok(_) => true,
        Err(e) => e.error_len().is_none(),
    };
    valid
        && data
            .iter()
            .all(|&b| b >= 0x20 || matches!(b, b'\t' | b'\n' | b'\r'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sniffs_common_types() {
        assert_eq!(sniff_mime(b"\x89PNG\r\n\x1a\n...."), Some("image/png"));
        assert_eq!(sniff_mime(b"RIFF\0\0\0\0WEBPVP8 "), Some("image/webp"));
        assert_eq!(sniff_mime(b"  <!DOCTYPE html><html>"), Some("text/html"));
        assert_eq!(
            sniff_mime(b"<?xml version=\"1.0\"?><svg xmlns="),
            Some("image/svg+xml")
        );
        assert_eq!(
            sniff_mime(b"<?xml version=\"1.0\"?><feed>"),
            Some("application/xml")
        );
        assert_eq!(sniff_mime(b"{\"a\": 1}"), None);
        assert_eq!(sniff_mime(b""), None);
    }

    #[test]
    fn previews_text_only() {
        assert_eq!(
            preview(Some("text/html; charset=utf-8"), None, b"<p>hi</p>", 100).as_deref(),
            Some("<p>hi</p>")
        );
        assert_eq!(
            preview(Some("image/png"), Some("image/png"), b"\x89PNG", 100),
            None
        );
        assert_eq!(
            preview(None, None, b"user=a&pass=b", 100).as_deref(),
            Some("user=a&pass=b")
        );
        assert_eq!(preview(None, None, b"\x00\x01binary", 100), None);
        // Cut on a character boundary.
        let text = "aé".repeat(10);
        let p = preview(Some("text/plain"), None, text.as_bytes(), 5).unwrap();
        assert_eq!(p, "aéa");
        assert!(preview(Some("text/plain"), None, b"", 4).is_none());
    }
}
