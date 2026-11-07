//! DNS message encoder (RFC 1035, RFC 3596). Answers whose owner name equals the question
//! name are compressed with a pointer to offset 12; other names are written in full.

use std::net::{Ipv4Addr, Ipv6Addr};

/// Query / record type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsType {
    A,
    Ns,
    Cname,
    Ptr,
    Mx,
    Txt,
    Aaaa,
    Srv,
    Any,
    Other(u16),
}

impl DnsType {
    pub fn code(self) -> u16 {
        match self {
            Self::A => 1,
            Self::Ns => 2,
            Self::Cname => 5,
            Self::Ptr => 12,
            Self::Mx => 15,
            Self::Txt => 16,
            Self::Aaaa => 28,
            Self::Srv => 33,
            Self::Any => 255,
            Self::Other(code) => code,
        }
    }
}

/// Resource record data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(String),
    Ns(String),
    Ptr(String),
    Mx {
        preference: u16,
        exchange: String,
    },
    Txt(String),
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
}

impl DnsData {
    pub fn rtype(&self) -> DnsType {
        match self {
            Self::A(_) => DnsType::A,
            Self::Aaaa(_) => DnsType::Aaaa,
            Self::Cname(_) => DnsType::Cname,
            Self::Ns(_) => DnsType::Ns,
            Self::Ptr(_) => DnsType::Ptr,
            Self::Mx { .. } => DnsType::Mx,
            Self::Txt(_) => DnsType::Txt,
            Self::Srv { .. } => DnsType::Srv,
        }
    }
}

/// One answer record (class IN).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsAnswer {
    pub name: String,
    pub ttl: u32,
    pub data: DnsData,
}

impl DnsAnswer {
    pub fn new(name: impl Into<String>, ttl: u32, data: DnsData) -> Self {
        Self {
            name: name.into(),
            ttl,
            data,
        }
    }
}

/// Response code `NXDOMAIN`.
pub const RCODE_NXDOMAIN: u8 = 3;

const CLASS_IN: u16 = 1;

/// Standard recursive query for `name`.
pub fn encode_query(id: u16, name: &str, qtype: DnsType) -> Vec<u8> {
    let mut out = header(id, 0x0100, 1, 0);
    push_question(&mut out, name, qtype);
    out
}

/// Response to [`encode_query`] carrying `answers` and the given response code.
pub fn encode_response(
    id: u16,
    name: &str,
    qtype: DnsType,
    rcode: u8,
    answers: &[DnsAnswer],
) -> Vec<u8> {
    // QR, RD, RA + rcode.
    let flags = 0x8180 | u16::from(rcode & 0x0f);
    let count = u16::try_from(answers.len()).expect("answer count fits in u16");
    let mut out = header(id, flags, 1, count);
    push_question(&mut out, name, qtype);
    for answer in answers {
        if answer.name.eq_ignore_ascii_case(name) {
            out.extend_from_slice(&[0xc0, 0x0c]);
        } else {
            push_name(&mut out, &answer.name);
        }
        out.extend_from_slice(&answer.data.rtype().code().to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        out.extend_from_slice(&answer.ttl.to_be_bytes());
        let rdata = rdata(&answer.data);
        let rdlen = u16::try_from(rdata.len()).expect("rdata fits in u16");
        out.extend_from_slice(&rdlen.to_be_bytes());
        out.extend_from_slice(&rdata);
    }
    out
}

fn header(id: u16, flags: u16, qd: u16, an: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(512);
    for v in [id, flags, qd, an, 0, 0] {
        out.extend_from_slice(&v.to_be_bytes());
    }
    out
}

fn push_question(out: &mut Vec<u8>, name: &str, qtype: DnsType) {
    push_name(out, name);
    out.extend_from_slice(&qtype.code().to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
}

/// Uncompressed wire-format name.
///
/// # Panics
/// If a label is longer than 63 bytes.
pub fn push_name(out: &mut Vec<u8>, name: &str) {
    for label in name
        .trim_end_matches('.')
        .split('.')
        .filter(|l| !l.is_empty())
    {
        let len = u8::try_from(label.len())
            .ok()
            .filter(|l| *l <= 63)
            .expect("DNS label of at most 63 bytes");
        out.push(len);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
}

fn rdata(data: &DnsData) -> Vec<u8> {
    let mut out = Vec::new();
    match data {
        DnsData::A(ip) => out.extend_from_slice(&ip.octets()),
        DnsData::Aaaa(ip) => out.extend_from_slice(&ip.octets()),
        DnsData::Cname(n) | DnsData::Ns(n) | DnsData::Ptr(n) => push_name(&mut out, n),
        DnsData::Mx {
            preference,
            exchange,
        } => {
            out.extend_from_slice(&preference.to_be_bytes());
            push_name(&mut out, exchange);
        }
        DnsData::Txt(text) => {
            for piece in text.as_bytes().chunks(255) {
                out.push(u8::try_from(piece.len()).expect("at most 255"));
                out.extend_from_slice(piece);
            }
            if text.is_empty() {
                out.push(0);
            }
        }
        DnsData::Srv {
            priority,
            weight,
            port,
            target,
        } => {
            for v in [priority, weight, port] {
                out.extend_from_slice(&v.to_be_bytes());
            }
            push_name(&mut out, target);
        }
    }
    out
}
