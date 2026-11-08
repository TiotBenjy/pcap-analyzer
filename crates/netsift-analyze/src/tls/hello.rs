//! `ClientHello` and `ServerHello` decoding (RFC 8446 4.1.2-4.1.3, RFC 5246 7.4.1).
//!
//! The fixed part of a hello is parsed by `tls-parser`; the extension block is walked here so
//! that every extension type is kept in wire order (fingerprints need the raw list, GREASE
//! included) and so that one malformed extension does not lose the others: a bad extension body
//! is skipped, a bad extension header ends the walk.

use tls_parser::{parse_tls_handshake_client_hello, parse_tls_handshake_server_hello};

/// Extension types used here (IANA registry of TLS extension types).
pub mod ext {
    pub const SERVER_NAME: u16 = 0;
    pub const SUPPORTED_GROUPS: u16 = 10;
    pub const EC_POINT_FORMATS: u16 = 11;
    pub const SIGNATURE_ALGORITHMS: u16 = 13;
    pub const ALPN: u16 = 16;
    pub const SESSION_TICKET: u16 = 35;
    pub const PRE_SHARED_KEY: u16 = 41;
    pub const SUPPORTED_VERSIONS: u16 = 43;
    pub const KEY_SHARE: u16 = 51;
}

/// Bounds of the decoded lists (a hello is at most one handshake message, already bounded).
/// Scanners offer several hundred suites: the lists must stay complete for the fingerprints.
const MAX_LIST: usize = 4096;
/// Longest kept SNI / ALPN value, in bytes.
const MAX_NAME: usize = 255;

/// `random` of a `ServerHello` that is in fact a `HelloRetryRequest` (RFC 8446 4.1.3).
pub const HELLO_RETRY_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

/// GREASE values (RFC 8701): `0x?a?a` with both bytes equal.
pub fn is_grease(v: u16) -> bool {
    v & 0x0f0f == 0x0a0a && v >> 8 == v & 0xff
}

/// Decoded `ClientHello`. Lists are in wire order, GREASE included.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientHello {
    pub legacy_version: u16,
    pub random: Vec<u8>,
    pub session_id: Vec<u8>,
    pub cipher_suites: Vec<u16>,
    pub compressions: Vec<u8>,
    pub extensions: Vec<u16>,
    pub sni: Option<String>,
    pub alpn: Vec<String>,
    /// Raw bytes of the first ALPN value (JA4 works on bytes, not on the sanitized text).
    pub alpn_first: Option<Vec<u8>>,
    pub groups: Vec<u16>,
    pub point_formats: Vec<u8>,
    pub signature_algs: Vec<u16>,
    pub supported_versions: Vec<u16>,
    pub key_share_groups: Vec<u16>,
    /// A non-empty session ticket was offered.
    pub session_ticket: bool,
    /// A pre-shared key was offered (TLS 1.3 resumption).
    pub psk: bool,
}

impl ClientHello {
    /// Approximate heap size (shard memory bound).
    pub fn approx_size(&self) -> usize {
        std::mem::size_of::<Self>()
            + self.random.len()
            + self.session_id.len()
            + 2 * (self.cipher_suites.len()
                + self.extensions.len()
                + self.groups.len()
                + self.signature_algs.len()
                + self.supported_versions.len()
                + self.key_share_groups.len())
            + self.compressions.len()
            + self.point_formats.len()
            + self.sni.as_ref().map_or(0, String::len)
            + self.alpn.iter().map(|a| a.len() + 24).sum::<usize>()
            + self.alpn_first.as_ref().map_or(0, Vec::len)
    }

    /// Highest version offered: `supported_versions` (GREASE excluded) when present, else the
    /// legacy version.
    pub fn offered_version(&self) -> u16 {
        self.supported_versions
            .iter()
            .copied()
            .filter(|v| !is_grease(*v))
            .max()
            .unwrap_or(self.legacy_version)
    }
}

/// Decoded `ServerHello`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServerHello {
    pub legacy_version: u16,
    pub random: Vec<u8>,
    pub session_id: Vec<u8>,
    pub cipher_suite: u16,
    pub compression: u8,
    pub extensions: Vec<u16>,
    /// `supported_versions` (TLS 1.3).
    pub selected_version: Option<u16>,
    pub alpn: Option<String>,
    /// The server accepted a pre-shared key (TLS 1.3 resumption).
    pub psk: bool,
    /// This is a `HelloRetryRequest`.
    pub retry: bool,
}

impl ServerHello {
    /// Approximate heap size (shard memory bound).
    pub fn approx_size(&self) -> usize {
        std::mem::size_of::<Self>()
            + self.random.len()
            + self.session_id.len()
            + 2 * self.extensions.len()
            + self.alpn.as_ref().map_or(0, String::len)
    }

    /// Negotiated version.
    pub fn version(&self) -> u16 {
        self.selected_version.unwrap_or(self.legacy_version)
    }
}

/// Big-endian reader over a byte slice; every read is checked.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Reader<'a>(pub(crate) &'a [u8]);

impl<'a> Reader<'a> {
    pub(crate) fn u8(&mut self) -> Option<u8> {
        let (&b, rest) = self.0.split_first()?;
        self.0 = rest;
        Some(b)
    }

    pub(crate) fn u16(&mut self) -> Option<u16> {
        let (head, rest) = self.0.split_first_chunk::<2>()?;
        self.0 = rest;
        Some(u16::from_be_bytes(*head))
    }

    pub(crate) fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (head, rest) = self.0.split_at_checked(n)?;
        self.0 = rest;
        Some(head)
    }

    /// Body of a vector with a 1-byte length.
    fn vec8(&mut self) -> Option<&'a [u8]> {
        let n = self.u8()?;
        self.take(usize::from(n))
    }

    /// Body of a vector with a 2-byte length.
    pub(crate) fn vec16(&mut self) -> Option<&'a [u8]> {
        let n = self.u16()?;
        self.take(usize::from(n))
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// `u16` list (ignores a trailing odd byte), at most [`MAX_LIST`] values.
fn u16_list(data: &[u8]) -> Vec<u16> {
    data.as_chunks::<2>()
        .0
        .iter()
        .take(MAX_LIST)
        .map(|b| u16::from_be_bytes(*b))
        .collect()
}

/// Lossy UTF-8 text bounded to [`MAX_NAME`] bytes, control characters replaced.
pub(crate) fn text(bytes: &[u8]) -> String {
    let bytes = bytes.get(..MAX_NAME).unwrap_or(bytes);
    String::from_utf8_lossy(bytes)
        .chars()
        .map(|c| if c.is_control() { '\u{fffd}' } else { c })
        .collect()
}

/// `(type, body)` of each extension, in order. Stops at the first truncated header or body.
fn extensions(block: &[u8]) -> Vec<(u16, &[u8])> {
    let mut r = Reader(block);
    let mut out = Vec::new();
    while !r.is_empty() && out.len() < MAX_LIST {
        let Some(kind) = r.u16() else { break };
        let Some(body) = r.vec16() else { break };
        out.push((kind, body));
    }
    out
}

/// First `host_name` of a `server_name` extension (RFC 6066 3).
fn sni(body: &[u8]) -> Option<String> {
    let mut list = Reader(Reader(body).vec16()?);
    while !list.is_empty() {
        let kind = list.u8()?;
        let name = list.vec16()?;
        if kind == 0 && !name.is_empty() {
            return Some(text(name));
        }
    }
    None
}

/// Raw protocol names of an ALPN extension (RFC 7301 3.1), empty names skipped.
fn alpn_raw(body: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let Some(list) = Reader(body).vec16() else {
        return out;
    };
    let mut list = Reader(list);
    while !list.is_empty() && out.len() < MAX_LIST {
        match list.vec8() {
            Some(name) if !name.is_empty() => out.push(name),
            Some(_) => {}
            None => break,
        }
    }
    out
}

/// Protocol names of an ALPN extension, as display text.
fn alpn(body: &[u8]) -> Vec<String> {
    alpn_raw(body).into_iter().map(text).collect()
}

/// Groups of a `ClientHello` `key_share` extension (RFC 8446 4.2.8).
fn key_share_groups(body: &[u8]) -> Vec<u16> {
    let mut out = Vec::new();
    let Some(list) = Reader(body).vec16() else {
        return out;
    };
    let mut list = Reader(list);
    while !list.is_empty() && out.len() < MAX_LIST {
        let Some(group) = list.u16() else { break };
        if list.vec16().is_none() {
            break;
        }
        out.push(group);
    }
    out
}

/// Decodes a `ClientHello` handshake body (after the 4-byte handshake header).
pub fn parse_client_hello(body: &[u8]) -> Option<ClientHello> {
    let (_, ch) = parse_tls_handshake_client_hello(body).ok()?;
    let mut out = ClientHello {
        legacy_version: ch.version.0,
        random: ch.random.to_vec(),
        session_id: ch.session_id.unwrap_or_default().to_vec(),
        cipher_suites: ch.ciphers.iter().take(MAX_LIST).map(|c| c.0).collect(),
        compressions: ch.comp.iter().take(MAX_LIST).map(|c| c.0).collect(),
        ..ClientHello::default()
    };
    for (kind, body) in extensions(ch.ext.unwrap_or_default()) {
        out.extensions.push(kind);
        match kind {
            ext::SERVER_NAME => out.sni = sni(body),
            ext::ALPN => {
                let names = alpn_raw(body);
                out.alpn_first = names.first().map(|n| n.to_vec());
                out.alpn = names.into_iter().map(text).collect();
            }
            ext::SUPPORTED_GROUPS => {
                out.groups = Reader(body).vec16().map(u16_list).unwrap_or_default();
            }
            ext::EC_POINT_FORMATS => {
                out.point_formats = Reader(body)
                    .vec8()
                    .map(|p| p.iter().take(MAX_LIST).copied().collect())
                    .unwrap_or_default();
            }
            ext::SIGNATURE_ALGORITHMS => {
                out.signature_algs = Reader(body).vec16().map(u16_list).unwrap_or_default();
            }
            ext::SUPPORTED_VERSIONS => {
                out.supported_versions = Reader(body).vec8().map(u16_list).unwrap_or_default();
            }
            ext::KEY_SHARE => out.key_share_groups = key_share_groups(body),
            ext::SESSION_TICKET => out.session_ticket = !body.is_empty(),
            ext::PRE_SHARED_KEY => out.psk = true,
            _ => {}
        }
    }
    Some(out)
}

/// Decodes a `ServerHello` handshake body (after the 4-byte handshake header).
pub fn parse_server_hello(body: &[u8]) -> Option<ServerHello> {
    let (_, sh) = parse_tls_handshake_server_hello(body).ok()?;
    let mut out = ServerHello {
        legacy_version: sh.version.0,
        random: sh.random.to_vec(),
        session_id: sh.session_id.unwrap_or_default().to_vec(),
        cipher_suite: sh.cipher.0,
        compression: sh.compression.0,
        retry: sh.random == HELLO_RETRY_RANDOM,
        ..ServerHello::default()
    };
    for (kind, body) in extensions(sh.ext.unwrap_or_default()) {
        out.extensions.push(kind);
        match kind {
            ext::SUPPORTED_VERSIONS => out.selected_version = Reader(body).u16(),
            ext::ALPN => out.alpn = alpn(body).into_iter().next(),
            ext::PRE_SHARED_KEY => out.psk = true,
            _ => {}
        }
    }
    Some(out)
}
