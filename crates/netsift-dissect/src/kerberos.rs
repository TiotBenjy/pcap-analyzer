//! Minimal Kerberos V5 message recognition (RFC 4120), without an ASN.1 library.
//!
//! Only the outer structure is read: the application tag gives the message type (AS-REQ,
//! AS-REP, TGS-REQ, TGS-REP, AP-REQ, AP-REP, KRB-ERROR), checked against the `pvno` (5) and
//! `msg-type` fields, so random bytes on port 88 are not taken for Kerberos. The realm and, for
//! KRB-ERROR, the error code are extracted when they lie inside the bytes available: a message
//! may be cut (only the head of a large TCP record is kept), which is not an error.
//!
//! The DER walk is bounded: definite lengths only, at most 4 length bytes, low tag numbers only,
//! a single pass over at most [`MAX_FIELDS`] fields per level, two levels deep. Nothing is
//! allocated but the realm, cut at [`MAX_REALM_LEN`] bytes.

use crate::bytes::be32;

/// Fields walked per SEQUENCE.
pub const MAX_FIELDS: usize = 16;
/// Longest realm kept, in bytes.
pub const MAX_REALM_LEN: usize = 255;

/// Kerberos message type (application tag number).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageKind {
    AsReq,
    AsRep,
    TgsReq,
    TgsRep,
    ApReq,
    ApRep,
    KrbError,
}

impl MessageKind {
    fn from_application(n: u8) -> Option<Self> {
        Some(match n {
            10 => Self::AsReq,
            11 => Self::AsRep,
            12 => Self::TgsReq,
            13 => Self::TgsRep,
            14 => Self::ApReq,
            15 => Self::ApRep,
            30 => Self::KrbError,
            _ => return None,
        })
    }

    /// Application tag number (also the `msg-type` value).
    pub const fn number(self) -> u8 {
        match self {
            Self::AsReq => 10,
            Self::AsRep => 11,
            Self::TgsReq => 12,
            Self::TgsRep => 13,
            Self::ApReq => 14,
            Self::ApRep => 15,
            Self::KrbError => 30,
        }
    }

    /// Stable lower-case label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AsReq => "as_req",
            Self::AsRep => "as_rep",
            Self::TgsReq => "tgs_req",
            Self::TgsRep => "tgs_rep",
            Self::ApReq => "ap_req",
            Self::ApRep => "ap_rep",
            Self::KrbError => "error",
        }
    }

    /// True for the messages a KDC sends (AS-REP, TGS-REP, KRB-ERROR).
    pub const fn is_kdc_reply(self) -> bool {
        matches!(self, Self::AsRep | Self::TgsRep | Self::KrbError)
    }

    /// KDC-REQ numbers its fields from 1 (`pvno [1]`), every other message from 0.
    const fn first_field(self) -> u8 {
        match self {
            Self::AsReq | Self::TgsReq => 1,
            _ => 0,
        }
    }
}

/// A recognized Kerberos message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub kind: MessageKind,
    /// Client realm (KDC-REP `crealm`), request realm (KDC-REQ body) or server realm
    /// (KRB-ERROR), when present in the available bytes.
    pub realm: Option<String>,
    /// KRB-ERROR `error-code` (25: pre-authentication required, 6: unknown client...).
    pub error_code: Option<i32>,
    /// The message is longer than the bytes available.
    pub truncated: bool,
}

/// One TLV: tag, available content, and whether all of it is present.
struct Tlv<'a> {
    tag: u8,
    content: &'a [u8],
    complete: bool,
}

/// Reads one TLV at the start of `data`; returns it and the bytes after it (empty when the TLV
/// is cut). `None` for high tag numbers, indefinite or oversized lengths, or a cut header.
fn read_tlv(data: &[u8]) -> Option<(Tlv<'_>, &[u8])> {
    let (&tag, rest) = data.split_first()?;
    if tag & 0x1f == 0x1f {
        return None;
    }
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 {
            return None;
        }
        let (bytes, rest) = rest.split_at_checked(n)?;
        let len = bytes
            .iter()
            .fold(0_usize, |acc, b| acc.wrapping_shl(8) | usize::from(*b));
        (len, rest)
    };
    match rest.split_at_checked(len) {
        Some((content, after)) => Some((
            Tlv {
                tag,
                content,
                complete: true,
            },
            after,
        )),
        None => Some((
            Tlv {
                tag,
                content: rest,
                complete: false,
            },
            rest.get(rest.len()..).unwrap_or_default(),
        )),
    }
}

/// Context-tagged fields `[n] value` of a SEQUENCE content, in order, each with its inner TLV.
/// Stops at the first field whose header is unreadable, or after [`MAX_FIELDS`].
fn fields(mut seq: &[u8], mut visit: impl FnMut(u8, &Tlv<'_>, Option<&Tlv<'_>>) -> bool) {
    for _ in 0..MAX_FIELDS {
        if seq.is_empty() {
            return;
        }
        let Some((field, rest)) = read_tlv(seq) else {
            return;
        };
        // Context-specific, constructed: 0b101x_xxxx.
        if field.tag & 0xe0 != 0xa0 {
            return;
        }
        let inner = read_tlv(field.content).map(|(t, _)| t);
        if !visit(field.tag & 0x1f, &field, inner.as_ref()) || !field.complete {
            return;
        }
        seq = rest;
    }
}

/// Signed INTEGER of at most 4 bytes, when complete.
fn integer(tlv: &Tlv<'_>) -> Option<i64> {
    if tlv.tag != 0x02 || !tlv.complete || tlv.content.is_empty() || tlv.content.len() > 4 {
        return None;
    }
    let negative = tlv.content.first().is_some_and(|b| b & 0x80 != 0);
    let start: i64 = if negative { -1 } else { 0 };
    Some(
        tlv.content
            .iter()
            .fold(start, |acc, b| acc.wrapping_shl(8) | i64::from(*b)),
    )
}

/// `GeneralString` realm, printable ASCII only, when complete and not empty.
fn realm(tlv: &Tlv<'_>) -> Option<String> {
    if tlv.tag != 0x1b || !tlv.complete {
        return None;
    }
    let s: String = tlv
        .content
        .iter()
        .take(MAX_REALM_LEN)
        .filter(|b| b.is_ascii_graphic())
        .map(|b| char::from(*b))
        .collect();
    (!s.is_empty()).then_some(s)
}

/// Recognizes one message (a UDP payload, or a TCP record without its length prefix, possibly
/// cut). `None` when it is not a Kerberos message.
pub fn parse(data: &[u8]) -> Option<Message> {
    let (outer, _) = read_tlv(data)?;
    // Application class, constructed: 0b011x_xxxx.
    if outer.tag & 0xe0 != 0x60 {
        return None;
    }
    let kind = MessageKind::from_application(outer.tag & 0x1f)?;
    let (seq, _) = read_tlv(outer.content)?;
    if seq.tag != 0x30 {
        return None;
    }
    let first = kind.first_field();
    let (pvno_tag, type_tag) = (first, first.saturating_add(1));
    let mut msg = Message {
        kind,
        realm: None,
        error_code: None,
        truncated: !outer.complete,
    };
    let (mut pvno, mut msg_type) = (None, None);
    fields(seq.content, |n, field, inner| {
        match (n, inner) {
            (n, Some(v)) if n == pvno_tag => pvno = integer(v),
            (n, Some(v)) if n == type_tag => msg_type = integer(v),
            // KDC-REP `crealm [3]`, KRB-ERROR `realm [9]`, `error-code [6]`.
            (3, Some(v)) if matches!(kind, MessageKind::AsRep | MessageKind::TgsRep) => {
                msg.realm = realm(v);
            }
            (9, Some(v)) if kind == MessageKind::KrbError => msg.realm = realm(v),
            (6, Some(v)) if kind == MessageKind::KrbError => {
                msg.error_code = integer(v).and_then(|c| i32::try_from(c).ok());
            }
            // KDC-REQ `req-body [4]`: realm at `[2]` of the body.
            (4, Some(body))
                if matches!(kind, MessageKind::AsReq | MessageKind::TgsReq) && body.tag == 0x30 =>
            {
                fields(body.content, |m, _, v| {
                    if let (2, Some(v)) = (m, v) {
                        msg.realm = realm(v);
                        return false;
                    }
                    m < 2
                });
            }
            _ => {}
        }
        // `pvno` and `msg-type` come first: give up early on anything else.
        !(n > type_tag && (pvno.is_none() || msg_type.is_none())) && field.complete
    });
    if pvno != Some(5) || msg_type != Some(i64::from(kind.number())) {
        return None;
    }
    Some(msg)
}

/// Length of a TCP record from its 4-byte prefix (RFC 4120 7.2.2). `None` when the prefix is
/// short or has the reserved high bit set (extension negotiation, not a message).
pub fn tcp_record_len(prefix: &[u8]) -> Option<u32> {
    let len = be32(prefix, 0)?;
    (len & 0x8000_0000 == 0).then_some(len)
}
