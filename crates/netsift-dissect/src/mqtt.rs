//! MQTT control packets (OASIS MQTT 3.1.1 and 5.0, MQTT V3.1 `MQIsdp`), pure and bounded.
//!
//! - [`fixed_header`]: packet type, flags and remaining length (variable byte integer, at most
//!   four bytes), with "incomplete" kept apart from "invalid";
//! - [`parse_packet`]: the variable header and payload of one packet, from a **prefix** of its
//!   body: a PUBLISH of several MiB is decoded on its first [`MAX_PACKET_PREFIX`] bytes (topic,
//!   properties, beginning of the payload), its size comes from the fixed header. Every inner
//!   length (strings, properties, filter lists) is checked against the remaining length; reading
//!   past the prefix but within the remaining length is "truncated", past the remaining length
//!   "malformed".
//!
//! Strings are UTF-8 (invalid, or holding U+0000: malformed, as the specifications require) and
//! bounded when kept ([`MAX_ID`], [`MAX_TOPIC`]...): a longer value is cut on a character
//! boundary and flagged. The payload is never interpreted: an excerpt of [`MAX_EXCERPT`] bytes
//! and its length. Authentication data (5.0) is never kept, only its length.

use std::fmt;

/// Largest remaining length (four bytes of variable byte integer).
pub const MAX_REMAINING: u32 = 268_435_455;
/// Bytes of a packet body decoded; the rest of a larger packet is only counted.
pub const MAX_PACKET_PREFIX: usize = 64 * 1024;
/// Longest client identifier and user name kept, in bytes.
pub const MAX_ID: usize = 256;
/// Longest password kept, in bytes.
pub const MAX_PASSWORD: usize = 1024;
/// Longest topic name or filter kept, in bytes.
pub const MAX_TOPIC: usize = 1024;
/// Longest short text property kept (content type, reason string, method...), in bytes.
pub const MAX_TEXT: usize = 256;
/// Bytes of payload kept (PUBLISH, will message).
pub const MAX_EXCERPT: usize = 512;
/// User properties kept per packet.
pub const MAX_USER_PROPS: usize = 16;
/// Filters (or codes) kept per SUBSCRIBE, UNSUBSCRIBE, SUBACK, UNSUBACK.
pub const MAX_FILTERS: usize = 64;
/// Subscription identifiers kept per PUBLISH.
pub const MAX_SUB_IDS: usize = 8;
/// Bytes of correlation data kept (shown in hexadecimal).
pub const MAX_CORRELATION: usize = 32;

/// Control packet type (4 high bits of the first byte).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PacketType {
    Connect = 1,
    Connack = 2,
    Publish = 3,
    Puback = 4,
    Pubrec = 5,
    Pubrel = 6,
    Pubcomp = 7,
    Subscribe = 8,
    Suback = 9,
    Unsubscribe = 10,
    Unsuback = 11,
    Pingreq = 12,
    Pingresp = 13,
    Disconnect = 14,
    /// 5.0 only (reserved in 3.1.1).
    Auth = 15,
}

impl PacketType {
    /// Type of the 4-bit code, `None` for the reserved 0.
    pub const fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            1 => Self::Connect,
            2 => Self::Connack,
            3 => Self::Publish,
            4 => Self::Puback,
            5 => Self::Pubrec,
            6 => Self::Pubrel,
            7 => Self::Pubcomp,
            8 => Self::Subscribe,
            9 => Self::Suback,
            10 => Self::Unsubscribe,
            11 => Self::Unsuback,
            12 => Self::Pingreq,
            13 => Self::Pingresp,
            14 => Self::Disconnect,
            15 => Self::Auth,
            _ => return None,
        })
    }

    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Specification name (`CONNECT`, `PUBLISH`...).
    pub const fn name(self) -> &'static str {
        match self {
            Self::Connect => "CONNECT",
            Self::Connack => "CONNACK",
            Self::Publish => "PUBLISH",
            Self::Puback => "PUBACK",
            Self::Pubrec => "PUBREC",
            Self::Pubrel => "PUBREL",
            Self::Pubcomp => "PUBCOMP",
            Self::Subscribe => "SUBSCRIBE",
            Self::Suback => "SUBACK",
            Self::Unsubscribe => "UNSUBSCRIBE",
            Self::Unsuback => "UNSUBACK",
            Self::Pingreq => "PINGREQ",
            Self::Pingresp => "PINGRESP",
            Self::Disconnect => "DISCONNECT",
            Self::Auth => "AUTH",
        }
    }

    /// True when a client may send this type.
    pub const fn from_client(self) -> bool {
        matches!(
            self,
            Self::Connect
                | Self::Publish
                | Self::Puback
                | Self::Pubrec
                | Self::Pubrel
                | Self::Pubcomp
                | Self::Subscribe
                | Self::Unsubscribe
                | Self::Pingreq
                | Self::Disconnect
                | Self::Auth
        )
    }

    /// True when a server may send this type.
    pub const fn from_server(self) -> bool {
        matches!(
            self,
            Self::Connack
                | Self::Publish
                | Self::Puback
                | Self::Pubrec
                | Self::Pubrel
                | Self::Pubcomp
                | Self::Suback
                | Self::Unsuback
                | Self::Pingresp
                | Self::Disconnect
                | Self::Auth
        )
    }

    /// True when `flags` are the ones the specifications impose for this type (PUBLISH: any
    /// DUP and RETAIN, `QoS` 0 to 2).
    pub const fn flags_valid(self, flags: u8) -> bool {
        match self {
            Self::Publish => (flags >> 1) & 3 != 3,
            Self::Pubrel | Self::Subscribe | Self::Unsubscribe => flags == 0b0010,
            _ => flags == 0,
        }
    }
}

impl fmt::Display for PacketType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Protocol version (CONNECT protocol name and level).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Version {
    /// `MQIsdp`, level 3.
    V31,
    /// `MQTT`, level 4.
    V311,
    /// `MQTT`, level 5.
    V5,
}

impl Version {
    /// Protocol level (3, 4, 5).
    pub const fn level(self) -> u8 {
        match self {
            Self::V31 => 3,
            Self::V311 => 4,
            Self::V5 => 5,
        }
    }

    pub const fn from_level(level: u8) -> Option<Self> {
        match level {
            3 => Some(Self::V31),
            4 => Some(Self::V311),
            5 => Some(Self::V5),
            _ => None,
        }
    }

    /// Display label (`3.1`, `3.1.1`, `5.0`).
    pub const fn label(self) -> &'static str {
        match self {
            Self::V31 => "3.1",
            Self::V311 => "3.1.1",
            Self::V5 => "5.0",
        }
    }

    const fn has_properties(self) -> bool {
        matches!(self, Self::V5)
    }
}

/// Decoded fixed header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixedHeader {
    pub ptype: PacketType,
    pub flags: u8,
    /// Bytes of the packet after the fixed header.
    pub remaining: u32,
    /// Bytes of the fixed header (2 to 5).
    pub header_len: u8,
}

impl FixedHeader {
    /// Size of the whole packet, in bytes.
    pub fn size(&self) -> u64 {
        u64::from(self.remaining).saturating_add(u64::from(self.header_len))
    }

    pub const fn qos(&self) -> u8 {
        (self.flags >> 1) & 3
    }

    pub const fn retain(&self) -> bool {
        self.flags & 1 != 0
    }

    pub const fn dup(&self) -> bool {
        self.flags & 8 != 0
    }
}

/// Outcome of [`fixed_header`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderStatus {
    /// More bytes are needed to decide.
    Incomplete,
    /// Not an MQTT fixed header (reserved type, imposed flags wrong, length too long).
    Invalid,
    Valid(FixedHeader),
}

/// Bit offsets of the four groups of a variable byte integer.
const VARINT_SHIFTS: [u32; 4] = [0, 7, 14, 21];

/// Fixed header at the start of `buf`.
pub fn fixed_header(buf: &[u8]) -> HeaderStatus {
    let Some(&first) = buf.first() else {
        return HeaderStatus::Incomplete;
    };
    let Some(ptype) = PacketType::from_code(first >> 4) else {
        return HeaderStatus::Invalid;
    };
    let flags = first & 0x0F;
    if !ptype.flags_valid(flags) {
        return HeaderStatus::Invalid;
    }
    let mut value: u32 = 0;
    for (i, shift) in (0..4u8).zip(VARINT_SHIFTS) {
        let Some(&b) = buf.get(usize::from(i).saturating_add(1)) else {
            return HeaderStatus::Incomplete;
        };
        value |= u32::from(b & 0x7F).wrapping_shl(shift);
        if b & 0x80 == 0 {
            return HeaderStatus::Valid(FixedHeader {
                ptype,
                flags,
                remaining: value,
                header_len: i.saturating_add(2),
            });
        }
    }
    HeaderStatus::Invalid
}

/// Why a packet could not be decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// A length runs past the remaining length, an invalid string, a reserved value: the
    /// specifications make it a fatal error.
    Malformed,
    /// Not decodable with this version (AUTH before 5.0, unknown protocol name or level).
    Unsupported,
}

/// Read failure inside a body prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Short {
    /// Past the prefix, within the remaining length: the rest is not available.
    Truncated,
    Malformed,
}

impl From<Short> for ParseError {
    fn from(_: Short) -> Self {
        Self::Malformed
    }
}

/// Cursor over a body prefix whose full length is `limit`.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
    limit: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8], limit: usize) -> Self {
        Self {
            buf,
            pos: 0,
            limit: limit.max(buf.len()),
        }
    }

    /// Bytes left before the end of the packet (prefix or not).
    fn left(&self) -> usize {
        self.limit.saturating_sub(self.pos)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], Short> {
        let end = self.pos.checked_add(n).ok_or(Short::Malformed)?;
        if end > self.limit {
            return Err(Short::Malformed);
        }
        let Some(slice) = self.buf.get(self.pos..end) else {
            return Err(Short::Truncated);
        };
        self.pos = end;
        Ok(slice)
    }

    /// Skips `n` bytes that may run past the prefix (within the packet).
    fn skip(&mut self, n: usize) -> Result<(), Short> {
        let end = self.pos.checked_add(n).ok_or(Short::Malformed)?;
        if end > self.limit {
            return Err(Short::Malformed);
        }
        self.pos = end;
        Ok(())
    }

    fn u8(&mut self) -> Result<u8, Short> {
        self.take(1)?.first().copied().ok_or(Short::Truncated)
    }

    fn u16(&mut self) -> Result<u16, Short> {
        match self.take(2)? {
            [a, b] => Ok(u16::from_be_bytes([*a, *b])),
            _ => Err(Short::Truncated),
        }
    }

    fn u32(&mut self) -> Result<u32, Short> {
        match self.take(4)? {
            [a, b, c, d] => Ok(u32::from_be_bytes([*a, *b, *c, *d])),
            _ => Err(Short::Truncated),
        }
    }

    fn varint(&mut self) -> Result<u32, Short> {
        let mut value: u32 = 0;
        for shift in VARINT_SHIFTS {
            let b = self.u8()?;
            value |= u32::from(b & 0x7F).wrapping_shl(shift);
            if b & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(Short::Malformed)
    }

    /// Two-byte length, then that many bytes; the bytes past the prefix are skipped, those
    /// kept are at most `max` (flag set when fewer than announced are returned).
    fn binary(&mut self, max: usize) -> Result<Bounded<'a>, Short> {
        let len = usize::from(self.u16()?);
        let end = self.pos.checked_add(len).ok_or(Short::Malformed)?;
        if end > self.limit {
            return Err(Short::Malformed);
        }
        let available = self.buf.len().saturating_sub(self.pos).min(len);
        let kept = available.min(max);
        let bytes = self
            .buf
            .get(self.pos..self.pos.saturating_add(kept))
            .unwrap_or_default();
        self.pos = end;
        Ok(Bounded {
            bytes,
            len,
            complete: available == len,
        })
    }

    /// UTF-8 string of at most `max` bytes kept. A string cut by the prefix is checked on what
    /// is available (a character cut at the end is dropped).
    fn string(&mut self, max: usize) -> Result<Text, Short> {
        let b = self.binary(usize::MAX)?;
        let valid = match std::str::from_utf8(b.bytes) {
            Ok(s) => s,
            Err(e) if !b.complete && e.error_len().is_none() => {
                // Cut inside a character by the prefix: keep what precedes it.
                std::str::from_utf8(b.bytes.get(..e.valid_up_to()).unwrap_or_default())
                    .map_err(|_| Short::Malformed)?
            }
            Err(_) => return Err(Short::Malformed),
        };
        if valid.contains('\0') {
            return Err(Short::Malformed);
        }
        let (value, cut) = cut_str(valid, max);
        Ok(Text {
            value: value.to_owned(),
            truncated: cut || !b.complete,
        })
    }

    fn at_end(&self) -> bool {
        self.pos >= self.limit
    }

    /// True when the reader stopped before the end of the prefix.
    fn in_prefix(&self) -> bool {
        self.pos < self.buf.len()
    }
}

/// Bytes of a length-prefixed field, as much as is available and kept.
struct Bounded<'a> {
    bytes: &'a [u8],
    len: usize,
    complete: bool,
}

/// Longest prefix of `s` of at most `max` bytes ending on a character boundary.
fn cut_str(s: &str, max: usize) -> (&str, bool) {
    if s.len() <= max {
        return (s, false);
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    (s.get(..end).unwrap_or_default(), true)
}

/// A bounded string value.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Text {
    pub value: String,
    /// Longer than kept, or cut by the end of the decoded prefix.
    pub truncated: bool,
}

/// An excerpt of binary data (payload, will message, correlation data).
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Excerpt {
    /// At most [`MAX_EXCERPT`] (or [`MAX_CORRELATION`]) first bytes.
    pub bytes: Vec<u8>,
    /// Full length announced.
    pub len: u64,
}

impl fmt::Debug for Excerpt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Excerpt")
            .field("kept", &self.bytes.len())
            .field("len", &self.len)
            .finish()
    }
}

/// MQTT 5.0 properties (only the ones displayed; the others are skipped by their type).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Properties {
    pub payload_format: Option<u8>,
    pub message_expiry: Option<u32>,
    pub content_type: Option<String>,
    pub response_topic: Option<String>,
    pub correlation_data: Option<Excerpt>,
    pub subscription_ids: Vec<u32>,
    pub session_expiry: Option<u32>,
    pub assigned_client_id: Option<String>,
    pub server_keep_alive: Option<u16>,
    pub auth_method: Option<String>,
    /// Length of the authentication data (never its content).
    pub auth_data_len: Option<u32>,
    pub request_problem_info: Option<u8>,
    pub will_delay: Option<u32>,
    pub request_response_info: Option<u8>,
    pub response_info: Option<String>,
    pub server_reference: Option<String>,
    pub reason_string: Option<String>,
    pub receive_maximum: Option<u16>,
    pub topic_alias_maximum: Option<u16>,
    pub topic_alias: Option<u16>,
    pub maximum_qos: Option<u8>,
    pub retain_available: Option<u8>,
    pub user_properties: Vec<(String, String)>,
    /// User properties beyond [`MAX_USER_PROPS`].
    pub user_properties_dropped: u32,
    pub maximum_packet_size: Option<u32>,
    pub wildcard_available: Option<u8>,
    pub sub_id_available: Option<u8>,
    pub shared_available: Option<u8>,
    /// An unknown identifier stopped the decoding of the properties (the rest was skipped).
    pub error: bool,
    /// The property list was cut by the end of the decoded prefix.
    pub truncated: bool,
}

/// Reads a property block (length, then properties) when the version has them.
fn properties(r: &mut Reader<'_>, version: Version) -> Result<Properties, Short> {
    let mut p = Properties::default();
    if !version.has_properties() {
        return Ok(p);
    }
    let len = usize::try_from(r.varint()?).map_err(|_| Short::Malformed)?;
    if len > r.left() {
        return Err(Short::Malformed);
    }
    let end = r.pos.saturating_add(len);
    let mut inner = Reader {
        buf: r.buf.get(..end.min(r.buf.len())).unwrap_or_default(),
        pos: r.pos,
        limit: end,
    };
    match property_list(&mut inner, &mut p) {
        Ok(()) => {}
        Err(Short::Truncated) => p.truncated = true,
        Err(Short::Malformed) => return Err(Short::Malformed),
    }
    r.skip(len)?;
    Ok(p)
}

fn text_prop(r: &mut Reader<'_>, max: usize) -> Result<String, Short> {
    Ok(r.string(max)?.value)
}

fn property_list(r: &mut Reader<'_>, p: &mut Properties) -> Result<(), Short> {
    while !r.at_end() {
        let id = r.varint()?;
        match id {
            0x01 => p.payload_format = Some(r.u8()?),
            0x02 => p.message_expiry = Some(r.u32()?),
            0x03 => p.content_type = Some(text_prop(r, MAX_TEXT)?),
            0x08 => p.response_topic = Some(text_prop(r, MAX_TOPIC)?),
            0x09 => {
                let b = r.binary(MAX_CORRELATION)?;
                p.correlation_data = Some(Excerpt {
                    bytes: b.bytes.to_vec(),
                    len: u64::try_from(b.len).unwrap_or(u64::MAX),
                });
            }
            0x0B => {
                let v = r.varint()?;
                if p.subscription_ids.len() < MAX_SUB_IDS {
                    p.subscription_ids.push(v);
                }
            }
            0x11 => p.session_expiry = Some(r.u32()?),
            0x12 => p.assigned_client_id = Some(text_prop(r, MAX_ID)?),
            0x13 => p.server_keep_alive = Some(r.u16()?),
            0x15 => p.auth_method = Some(text_prop(r, MAX_TEXT)?),
            0x16 => {
                let b = r.binary(0)?;
                p.auth_data_len = Some(u32::try_from(b.len).unwrap_or(u32::MAX));
            }
            0x17 => p.request_problem_info = Some(r.u8()?),
            0x18 => p.will_delay = Some(r.u32()?),
            0x19 => p.request_response_info = Some(r.u8()?),
            0x1A => p.response_info = Some(text_prop(r, MAX_TEXT)?),
            0x1C => p.server_reference = Some(text_prop(r, MAX_TEXT)?),
            0x1F => p.reason_string = Some(text_prop(r, MAX_TEXT)?),
            0x21 => p.receive_maximum = Some(r.u16()?),
            0x22 => p.topic_alias_maximum = Some(r.u16()?),
            0x23 => p.topic_alias = Some(r.u16()?),
            0x24 => p.maximum_qos = Some(r.u8()?),
            0x25 => p.retain_available = Some(r.u8()?),
            0x26 => {
                let name = text_prop(r, MAX_TEXT)?;
                let value = text_prop(r, MAX_TEXT)?;
                if p.user_properties.len() < MAX_USER_PROPS {
                    p.user_properties.push((name, value));
                } else {
                    p.user_properties_dropped = p.user_properties_dropped.saturating_add(1);
                }
            }
            0x27 => p.maximum_packet_size = Some(r.u32()?),
            0x28 => p.wildcard_available = Some(r.u8()?),
            0x29 => p.sub_id_available = Some(r.u8()?),
            0x2A => p.shared_available = Some(r.u8()?),
            _ => {
                // Unknown identifier: its type, hence its length, is unknown.
                p.error = true;
                return Ok(());
            }
        }
    }
    Ok(())
}

/// Will message of a CONNECT.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Will {
    pub properties: Properties,
    pub topic: Text,
    pub qos: u8,
    pub retain: bool,
    pub payload: Excerpt,
}

/// A CONNECT packet. `Debug` hides the password.
#[allow(clippy::struct_excessive_bools)] // Independent flags of the packet.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Connect {
    /// `MQTT` or `MQIsdp`.
    pub protocol_name: String,
    /// Protocol level as sent (bit 7 included).
    pub level: u8,
    pub version: Option<Version>,
    /// Bit 7 of the level set (bridge convention).
    pub bridge: bool,
    pub clean_start: bool,
    pub keep_alive: u16,
    pub properties: Properties,
    pub client_id: Text,
    pub will: Option<Will>,
    pub username: Option<Text>,
    /// At most [`MAX_PASSWORD`] bytes (binary data in 3.1.1 and 5.0).
    pub password: Option<Vec<u8>>,
    pub password_len: u32,
    /// Password without user name in 3.x, empty client id with Clean Session 0 in 3.1.1...
    pub protocol_error: bool,
    /// Fields past the decoded prefix were not read.
    pub truncated: bool,
    /// Every byte of the remaining length was read, no more (the strict test of detection).
    pub exact: bool,
}

impl fmt::Debug for Connect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Connect")
            .field("protocol_name", &self.protocol_name)
            .field("level", &self.level)
            .field("clean_start", &self.clean_start)
            .field("keep_alive", &self.keep_alive)
            .field("client_id", &self.client_id)
            .field("will", &self.will.is_some())
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("password_len", &self.password_len)
            .finish_non_exhaustive()
    }
}

/// A CONNACK packet.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Connack {
    pub session_present: bool,
    /// Return code (3.x) or reason code (5.0).
    pub code: u8,
    pub properties: Properties,
}

/// A PUBLISH packet.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Publish {
    pub topic: Text,
    pub packet_id: Option<u16>,
    pub properties: Properties,
    pub payload: Excerpt,
}

/// PUBACK, PUBREC, PUBREL or PUBCOMP.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ack {
    pub packet_id: u16,
    /// 5.0 reason code (absent: 0x00 success).
    pub reason: Option<u8>,
    pub properties: Properties,
}

/// One filter of a SUBSCRIBE.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Subscription {
    pub filter: Text,
    /// Options byte: `QoS` (bits 1-0), and in 5.0 No Local (2), Retain As Published (3), Retain
    /// Handling (5-4).
    pub options: u8,
}

impl Subscription {
    pub const fn qos(&self) -> u8 {
        self.options & 3
    }
}

/// SUBSCRIBE (filters with options) or UNSUBSCRIBE (filters only, options 0).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Subscribe {
    pub packet_id: u16,
    pub properties: Properties,
    pub filters: Vec<Subscription>,
    /// Filters beyond [`MAX_FILTERS`], or not decoded (prefix).
    pub dropped: u32,
    pub protocol_error: bool,
}

/// SUBACK or UNSUBACK.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Suback {
    pub packet_id: u16,
    pub properties: Properties,
    /// One code per filter (granted `QoS`, or 0x80 and above: refused); empty for a 3.x UNSUBACK.
    pub codes: Vec<u8>,
}

/// DISCONNECT or AUTH (5.0 reason code and properties; empty in 3.x).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Reasoned {
    /// Absent: 0x00 (normal disconnection, success).
    pub reason: Option<u8>,
    pub properties: Properties,
}

/// A decoded control packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Packet {
    Connect(Box<Connect>),
    Connack(Connack),
    Publish(Box<Publish>),
    Puback(Ack),
    Pubrec(Ack),
    Pubrel(Ack),
    Pubcomp(Ack),
    Subscribe(Subscribe),
    Suback(Suback),
    Unsubscribe(Subscribe),
    Unsuback(Suback),
    Pingreq,
    Pingresp,
    Disconnect(Reasoned),
    Auth(Reasoned),
}

/// Decodes one packet from `body`, a prefix of its body (`header.remaining` bytes in full). A
/// CONNECT is decoded with the version it announces; every other packet with `version`.
pub fn parse_packet(
    header: FixedHeader,
    body: &[u8],
    version: Version,
) -> Result<Packet, ParseError> {
    let limit = usize::try_from(header.remaining).unwrap_or(usize::MAX);
    let body = body.get(..limit.min(body.len())).unwrap_or_default();
    let mut r = Reader::new(body, limit);
    let packet = match header.ptype {
        PacketType::Connect => Packet::Connect(Box::new(connect(&mut r)?)),
        PacketType::Connack => Packet::Connack(connack(&mut r, version)?),
        PacketType::Publish => Packet::Publish(Box::new(publish(&mut r, header, version)?)),
        PacketType::Puback => Packet::Puback(ack(&mut r, version)?),
        PacketType::Pubrec => Packet::Pubrec(ack(&mut r, version)?),
        PacketType::Pubrel => Packet::Pubrel(ack(&mut r, version)?),
        PacketType::Pubcomp => Packet::Pubcomp(ack(&mut r, version)?),
        PacketType::Subscribe => Packet::Subscribe(subscribe(&mut r, version, true)?),
        PacketType::Suback => Packet::Suback(suback(&mut r, version, true)?),
        PacketType::Unsubscribe => Packet::Unsubscribe(subscribe(&mut r, version, false)?),
        PacketType::Unsuback => Packet::Unsuback(suback(&mut r, version, false)?),
        PacketType::Pingreq => Packet::Pingreq,
        PacketType::Pingresp => Packet::Pingresp,
        PacketType::Disconnect => Packet::Disconnect(reasoned(&mut r, version)?),
        PacketType::Auth => {
            if version != Version::V5 {
                return Err(ParseError::Unsupported);
            }
            Packet::Auth(reasoned(&mut r, version)?)
        }
    };
    Ok(packet)
}

/// Maps a truncated read to "stop here" (`Ok(false)`), keeping malformed as an error.
fn soft(r: Result<(), Short>) -> Result<bool, ParseError> {
    match r {
        Ok(()) => Ok(true),
        Err(Short::Truncated) => Ok(false),
        Err(Short::Malformed) => Err(ParseError::Malformed),
    }
}

fn connect(r: &mut Reader<'_>) -> Result<Connect, ParseError> {
    let mut c = Connect::default();
    let name = r.string(16)?;
    c.protocol_name = name.value;
    c.level = r.u8()?;
    c.bridge = c.level & 0x80 != 0;
    let version = Version::from_level(c.level & 0x7F).ok_or(ParseError::Unsupported)?;
    match (c.protocol_name.as_str(), version) {
        ("MQTT", Version::V311 | Version::V5) | ("MQIsdp", Version::V31) => {}
        _ => return Err(ParseError::Unsupported),
    }
    c.version = Some(version);
    let flags = r.u8()?;
    if flags & 1 != 0 {
        return Err(ParseError::Malformed);
    }
    c.clean_start = flags & 0x02 != 0;
    let will_flag = flags & 0x04 != 0;
    let will_qos = (flags >> 3) & 3;
    let will_retain = flags & 0x20 != 0;
    let password_flag = flags & 0x40 != 0;
    let username_flag = flags & 0x80 != 0;
    if will_qos == 3 || (!will_flag && (will_qos != 0 || will_retain)) {
        return Err(ParseError::Malformed);
    }
    if password_flag && !username_flag && version != Version::V5 {
        c.protocol_error = true;
    }
    c.keep_alive = r.u16()?;
    let complete = soft((|| -> Result<(), Short> {
        c.properties = properties(r, version)?;
        if c.properties.truncated {
            return Err(Short::Truncated);
        }
        c.client_id = r.string(MAX_ID)?;
        if will_flag {
            let properties = properties(r, version)?;
            let topic = r.string(MAX_TOPIC)?;
            let payload = r.binary(MAX_EXCERPT)?;
            c.will = Some(Will {
                properties,
                topic,
                qos: will_qos,
                retain: will_retain,
                payload: Excerpt {
                    bytes: payload.bytes.to_vec(),
                    len: u64::try_from(payload.len).unwrap_or(u64::MAX),
                },
            });
        }
        if username_flag {
            c.username = Some(r.string(MAX_ID)?);
        }
        if password_flag {
            let p = r.binary(MAX_PASSWORD)?;
            if !p.complete && p.bytes.len() < MAX_PASSWORD {
                return Err(Short::Truncated);
            }
            c.password_len = u32::try_from(p.len).unwrap_or(u32::MAX);
            c.password = Some(p.bytes.to_vec());
        }
        Ok(())
    })())?;
    c.truncated = !complete || r.pos > r.buf.len();
    c.exact = complete && r.at_end() && !c.truncated;
    Ok(c)
}

fn connack(r: &mut Reader<'_>, version: Version) -> Result<Connack, ParseError> {
    let flags = r.u8()?;
    if flags & 0xFE != 0 {
        return Err(ParseError::Malformed);
    }
    let code = r.u8()?;
    let mut c = Connack {
        session_present: flags & 1 != 0,
        code,
        properties: Properties::default(),
    };
    if version.has_properties() && !r.at_end() {
        c.properties = properties(r, version)?;
    }
    Ok(c)
}

fn publish(
    r: &mut Reader<'_>,
    header: FixedHeader,
    version: Version,
) -> Result<Publish, ParseError> {
    let mut p = Publish {
        topic: r.string(MAX_TOPIC)?,
        ..Publish::default()
    };
    if p.topic.value.contains(['+', '#']) {
        return Err(ParseError::Malformed);
    }
    if header.qos() > 0 {
        let id = r.u16()?;
        if id == 0 {
            return Err(ParseError::Malformed);
        }
        p.packet_id = Some(id);
    }
    p.properties = properties(r, version)?;
    let len = r.left();
    let kept = r.buf.len().saturating_sub(r.pos).min(MAX_EXCERPT).min(len);
    p.payload = Excerpt {
        bytes: r
            .buf
            .get(r.pos..r.pos.saturating_add(kept))
            .unwrap_or_default()
            .to_vec(),
        len: u64::try_from(len).unwrap_or(u64::MAX),
    };
    Ok(p)
}

fn ack(r: &mut Reader<'_>, version: Version) -> Result<Ack, ParseError> {
    let mut a = Ack {
        packet_id: r.u16()?,
        ..Ack::default()
    };
    if version.has_properties() {
        if !r.at_end() {
            a.reason = Some(r.u8()?);
        }
        if !r.at_end() {
            a.properties = properties(r, version)?;
        }
    }
    Ok(a)
}

fn subscribe(r: &mut Reader<'_>, version: Version, options: bool) -> Result<Subscribe, ParseError> {
    let mut s = Subscribe {
        packet_id: r.u16()?,
        ..Subscribe::default()
    };
    s.properties = properties(r, version)?;
    while !r.at_end() {
        if !r.in_prefix() {
            s.dropped = s.dropped.saturating_add(1);
            break;
        }
        let filter = match r.string(MAX_TOPIC) {
            Ok(f) => f,
            Err(Short::Truncated) => {
                s.dropped = s.dropped.saturating_add(1);
                break;
            }
            Err(Short::Malformed) => return Err(ParseError::Malformed),
        };
        if filter.value.is_empty() {
            return Err(ParseError::Malformed);
        }
        let opts = if options {
            match r.u8() {
                Ok(o) => o,
                Err(Short::Truncated) => {
                    s.dropped = s.dropped.saturating_add(1);
                    break;
                }
                Err(Short::Malformed) => return Err(ParseError::Malformed),
            }
        } else {
            0
        };
        let reserved = if version.has_properties() { 0xC0 } else { 0xFC };
        if opts & reserved != 0 || opts & 3 == 3 || (opts >> 4) & 3 == 3 {
            return Err(ParseError::Malformed);
        }
        if s.filters.len() < MAX_FILTERS {
            s.filters.push(Subscription {
                filter,
                options: opts,
            });
        } else {
            s.dropped = s.dropped.saturating_add(1);
        }
    }
    if s.filters.is_empty() && s.dropped == 0 {
        s.protocol_error = true;
    }
    Ok(s)
}

fn suback(r: &mut Reader<'_>, version: Version, sub: bool) -> Result<Suback, ParseError> {
    let mut s = Suback {
        packet_id: r.u16()?,
        ..Suback::default()
    };
    if !sub && !version.has_properties() {
        return Ok(s);
    }
    s.properties = properties(r, version)?;
    while !r.at_end() && s.codes.len() < MAX_FILTERS {
        match r.u8() {
            Ok(c) => s.codes.push(c),
            Err(_) => break,
        }
    }
    Ok(s)
}

fn reasoned(r: &mut Reader<'_>, version: Version) -> Result<Reasoned, ParseError> {
    let mut d = Reasoned::default();
    if !version.has_properties() {
        return Ok(d);
    }
    if !r.at_end() {
        d.reason = Some(r.u8()?);
    }
    if !r.at_end() {
        d.properties = properties(r, version)?;
    }
    Ok(d)
}

/// True when `buf` starts with a valid and complete CONNECT that fills its remaining length
/// exactly (the detection rule on any port), or with a CONNECT longer than
/// [`MAX_PACKET_PREFIX`] whose fields up to the user name are valid. `None` while more bytes
/// are needed to decide.
pub fn starts_connect(buf: &[u8]) -> Option<bool> {
    if buf.first().is_some_and(|&b| b != 0x10) {
        return Some(false);
    }
    let header = match fixed_header(buf) {
        HeaderStatus::Incomplete => return None,
        HeaderStatus::Invalid => return Some(false),
        HeaderStatus::Valid(h) => h,
    };
    let start = usize::from(header.header_len);
    let total = usize::try_from(header.remaining).unwrap_or(usize::MAX);
    let want = total.min(MAX_PACKET_PREFIX);
    let available = buf.len().saturating_sub(start);
    if available < want {
        return None;
    }
    let body = buf
        .get(start..start.saturating_add(want))
        .unwrap_or_default();
    match parse_packet(header, body, Version::V311) {
        // A CONNECT longer than the prefix (a large will message) is judged on what was read.
        Ok(Packet::Connect(c)) => Some(if total <= MAX_PACKET_PREFIX {
            c.exact
        } else {
            true
        }),
        _ => Some(false),
    }
}

#[cfg(test)]
mod tests;
