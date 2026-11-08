//! DNS message parser (RFC 1035 wire format), shared by DNS, mDNS (RFC 6762), LLMNR (RFC 4795)
//! and the NetBIOS name service (NBNS, RFC 1002), which reuses the DNS layout with encoded names
//! and its own record types (`NB`, `NBSTAT`).
//!
//! Captures are hostile input, so the parser is defensive and bounded:
//! - names: compression pointers must point strictly backwards (no loop), at most
//!   [`MAX_POINTER_JUMPS`] of them per name, at most [`MAX_LABELS`] labels and
//!   [`MAX_NAME_LEN`] wire bytes (a longer name is malformed); the presentation form is cut at
//!   [`MAX_NAME_LEN`] bytes (escapes make it longer than the wire form);
//! - the names of one message cost at most [`MAX_NAME_STEPS`] labels and jumps in total, so that
//!   chains of pointers between thousands of questions stay linear;
//! - names inside record data must end inside the record data (`RDLENGTH`);
//! - at most [`MAX_QUESTIONS`] questions and [`MAX_RECORDS`] resource records are decoded (the
//!   header counts are kept as they are); allocations never depend on an unchecked length field;
//! - text values are cut at [`MAX_TEXT_LEN`] bytes.
//!
//! A message whose header is complete is always returned: what follows a malformed or truncated
//! part is dropped and [`Message::malformed`] is set.

use std::fmt::Write as _;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Fixed DNS header length.
pub const HEADER_LEN: usize = 12;
/// Largest name, in wire bytes (longer: malformed); presentation names are cut at this length.
pub const MAX_NAME_LEN: usize = 255;
/// Compression pointers followed per name.
pub const MAX_POINTER_JUMPS: usize = 32;
/// Labels and pointer jumps read for all the names of one message.
pub const MAX_NAME_STEPS: usize = 16_384;
/// Largest number of labels in one name.
pub const MAX_LABELS: usize = 128;
/// Questions decoded per message.
pub const MAX_QUESTIONS: usize = 16;
/// Resource records decoded per message (all sections together).
pub const MAX_RECORDS: usize = 64;
/// Largest text value (TXT, HINFO...) kept, in bytes.
pub const MAX_TEXT_LEN: usize = 255;
/// NetBIOS names listed per `NBSTAT` record.
pub const MAX_NBSTAT_NAMES: usize = 32;
/// Addresses listed per `NB` record.
pub const MAX_NB_ADDRESSES: usize = 16;

/// Name encoding of a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Flavor {
    /// DNS, mDNS, LLMNR: plain labels.
    Dns,
    /// NBNS: the first label of a name is a level-one encoded NetBIOS name (RFC 1001 14.1).
    Nbns,
}

/// Record types used by name.
pub mod rtype {
    pub const A: u16 = 1;
    pub const NS: u16 = 2;
    pub const CNAME: u16 = 5;
    pub const SOA: u16 = 6;
    pub const NULL: u16 = 10;
    pub const PTR: u16 = 12;
    pub const HINFO: u16 = 13;
    pub const MX: u16 = 15;
    pub const TXT: u16 = 16;
    pub const AAAA: u16 = 28;
    pub const SRV: u16 = 33;
    pub const DNAME: u16 = 39;
    pub const OPT: u16 = 41;
    pub const SPF: u16 = 99;
    pub const ANY: u16 = 255;
    /// NetBIOS general name service resource record (shares the value 32 with DNS `NIMLOC`).
    pub const NB: u16 = 32;
    /// NetBIOS node status (shares the value 33 with DNS `SRV`).
    pub const NBSTAT: u16 = 33;
}

/// Mnemonic of a record type (`TYPE<n>` when unknown, RFC 3597).
pub fn type_name(flavor: Flavor, code: u16) -> String {
    let known = match (flavor, code) {
        (Flavor::Nbns, rtype::NB) => "NB",
        (Flavor::Nbns, rtype::NBSTAT) => "NBSTAT",
        (Flavor::Nbns, rtype::A) => "A",
        (Flavor::Nbns, rtype::NS) => "NS",
        (Flavor::Nbns, rtype::NULL) => "NULL",
        (Flavor::Nbns, _) => "",
        (Flavor::Dns, c) => dns_type_name(c),
    };
    if known.is_empty() {
        format!("TYPE{code}")
    } else {
        known.to_owned()
    }
}

fn dns_type_name(code: u16) -> &'static str {
    match code {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        10 => "NULL",
        12 => "PTR",
        13 => "HINFO",
        15 => "MX",
        16 => "TXT",
        17 => "RP",
        18 => "AFSDB",
        24 => "SIG",
        25 => "KEY",
        28 => "AAAA",
        29 => "LOC",
        33 => "SRV",
        35 => "NAPTR",
        36 => "KX",
        37 => "CERT",
        39 => "DNAME",
        41 => "OPT",
        42 => "APL",
        43 => "DS",
        44 => "SSHFP",
        45 => "IPSECKEY",
        46 => "RRSIG",
        47 => "NSEC",
        48 => "DNSKEY",
        49 => "DHCID",
        50 => "NSEC3",
        51 => "NSEC3PARAM",
        52 => "TLSA",
        53 => "SMIMEA",
        55 => "HIP",
        59 => "CDS",
        60 => "CDNSKEY",
        61 => "OPENPGPKEY",
        62 => "CSYNC",
        63 => "ZONEMD",
        64 => "SVCB",
        65 => "HTTPS",
        99 => "SPF",
        249 => "TKEY",
        250 => "TSIG",
        251 => "IXFR",
        252 => "AXFR",
        255 => "ANY",
        256 => "URI",
        257 => "CAA",
        _ => "",
    }
}

/// Name of a DNS opcode (`OPCODE<n>` when unknown).
pub fn opcode_name(flavor: Flavor, code: u8) -> String {
    let known = match (flavor, code) {
        (Flavor::Dns | Flavor::Nbns, 0) => "QUERY",
        (Flavor::Dns, 1) => "IQUERY",
        (Flavor::Dns, 2) => "STATUS",
        (Flavor::Dns, 4) => "NOTIFY",
        (Flavor::Dns, 5) => "UPDATE",
        (Flavor::Dns, 6) => "DSO",
        (Flavor::Nbns, 5) => "REGISTRATION",
        (Flavor::Nbns, 6) => "RELEASE",
        (Flavor::Nbns, 7) => "WACK",
        (Flavor::Nbns, 8 | 9) => "REFRESH",
        (Flavor::Nbns, 15) => "MULTIHOMED",
        _ => "",
    };
    if known.is_empty() {
        format!("OPCODE{code}")
    } else {
        known.to_owned()
    }
}

/// Name of a response code (`RCODE<n>` when unknown). NBNS codes 1-5 share the DNS meaning;
/// 6 and 7 are `ACT_ERR` (name active) and `CFT_ERR` (name conflict).
pub fn rcode_name(flavor: Flavor, code: u8) -> String {
    let known = match (flavor, code) {
        (_, 0) => "NOERROR",
        (_, 1) => "FORMERR",
        (_, 2) => "SERVFAIL",
        (_, 3) => "NXDOMAIN",
        (_, 4) => "NOTIMP",
        (_, 5) => "REFUSED",
        (Flavor::Dns, 6) => "YXDOMAIN",
        (Flavor::Dns, 7) => "YXRRSET",
        (Flavor::Dns, 8) => "NXRRSET",
        (Flavor::Dns, 9) => "NOTAUTH",
        (Flavor::Dns, 10) => "NOTZONE",
        (Flavor::Nbns, 6) => "ACT_ERR",
        (Flavor::Nbns, 7) => "CFT_ERR",
        _ => "",
    };
    if known.is_empty() {
        format!("RCODE{code}")
    } else {
        known.to_owned()
    }
}

/// Fixed header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub id: u16,
    pub flags: u16,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

impl Header {
    /// QR bit: response.
    pub fn is_response(&self) -> bool {
        self.flags & 0x8000 != 0
    }

    pub fn opcode(&self) -> u8 {
        u8::try_from((self.flags >> 11) & 0x0f).unwrap_or(0)
    }

    /// Low 4 bits of the response code (extended codes of EDNS are not combined).
    pub fn rcode(&self) -> u8 {
        u8::try_from(self.flags & 0x0f).unwrap_or(0)
    }

    /// TC bit: the message was truncated by the sender.
    pub fn truncated(&self) -> bool {
        self.flags & 0x0200 != 0
    }
}

/// A decoded name. For NBNS, `suffix` is the 16th byte of the NetBIOS name (service type) and
/// `name` the first 15 characters, trailing spaces removed, followed by the scope if any.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Name {
    pub name: String,
    pub suffix: Option<u8>,
}

/// One question.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub name: Name,
    pub qtype: u16,
    /// Class without the mDNS "unicast response" bit.
    pub qclass: u16,
    /// mDNS QU bit (top bit of the class).
    pub unicast_response: bool,
}

/// Section of a resource record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Section {
    Answer,
    Authority,
    Additional,
}

/// An address of an NBNS `NB` record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NbAddress {
    pub group: bool,
    /// Owner node type: 0 B, 1 P, 2 M, 3 H.
    pub node_type: u8,
    pub addr: Ipv4Addr,
}

/// A name of an NBNS `NBSTAT` record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NbStatName {
    pub name: String,
    pub suffix: u8,
    pub group: bool,
}

/// Decoded record data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    /// CNAME, NS, PTR, DNAME.
    Name(String),
    Mx {
        preference: u16,
        exchange: String,
    },
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    Soa {
        mname: String,
        rname: String,
        serial: u32,
    },
    /// TXT, HINFO and other character strings, joined by spaces and cut at [`MAX_TEXT_LEN`].
    Text(String),
    Nb(Vec<NbAddress>),
    NbStat(Vec<NbStatName>),
    /// Not decoded: only its length is kept.
    Other(usize),
}

/// One resource record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub section: Section,
    pub name: Name,
    pub rtype: u16,
    /// Class without the mDNS "cache flush" bit (for `OPT`, the UDP payload size).
    pub class: u16,
    pub ttl: u32,
    pub data: RData,
}

/// A decoded message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub header: Header,
    pub questions: Vec<Question>,
    pub records: Vec<Record>,
    /// Something could not be decoded (truncated, bad pointer, name too long...): the parts
    /// after it are missing.
    pub malformed: bool,
}

impl Message {
    /// Records of the answer section.
    pub fn answers(&self) -> impl Iterator<Item = &Record> {
        self.records.iter().filter(|r| r.section == Section::Answer)
    }
}

/// Why a buffer is not a DNS message at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DnsError {
    #[error("shorter than a DNS header ({0} bytes)")]
    TooShort(usize),
    #[error("implausible section counts")]
    Implausible,
}

/// Parses one message (UDP payload, or one message of a TCP stream without its length prefix).
pub fn parse(data: &[u8], flavor: Flavor) -> Result<Message, DnsError> {
    let header = parse_header(data).ok_or(DnsError::TooShort(data.len()))?;
    // Every question takes at least 5 bytes and every record 11: counts that cannot fit are
    // not a DNS message (random UDP traffic on a DNS port).
    let min_len = usize::from(header.qdcount)
        .saturating_mul(5)
        .saturating_add(
            (usize::from(header.ancount))
                .saturating_add(usize::from(header.nscount))
                .saturating_add(usize::from(header.arcount))
                .saturating_mul(11),
        );
    if min_len > data.len().saturating_sub(HEADER_LEN).saturating_add(1024) {
        return Err(DnsError::Implausible);
    }
    let mut msg = Message {
        header,
        questions: Vec::new(),
        records: Vec::new(),
        malformed: false,
    };
    let mut pos = HEADER_LEN;
    let mut budget = MAX_NAME_STEPS;
    for _ in 0..header.qdcount {
        let Some((q, next)) = parse_question(data, pos, flavor, &mut budget) else {
            msg.malformed = true;
            return Ok(msg);
        };
        pos = next;
        if msg.questions.len() < MAX_QUESTIONS {
            msg.questions.push(q);
        }
    }
    let sections = [
        (Section::Answer, header.ancount),
        (Section::Authority, header.nscount),
        (Section::Additional, header.arcount),
    ];
    for (section, count) in sections {
        for _ in 0..count {
            if msg.records.len() >= MAX_RECORDS {
                return Ok(msg);
            }
            let Some((r, next)) = parse_record(data, pos, section, flavor, &mut budget) else {
                msg.malformed = true;
                return Ok(msg);
            };
            pos = next;
            msg.records.push(r);
        }
    }
    Ok(msg)
}

fn be16(data: &[u8], off: usize) -> Option<u16> {
    crate::bytes::be16(data, off)
}

fn be32(data: &[u8], off: usize) -> Option<u32> {
    crate::bytes::be32(data, off)
}

fn parse_header(data: &[u8]) -> Option<Header> {
    Some(Header {
        id: be16(data, 0)?,
        flags: be16(data, 2)?,
        qdcount: be16(data, 4)?,
        ancount: be16(data, 6)?,
        nscount: be16(data, 8)?,
        arcount: be16(data, 10)?,
    })
}

fn parse_question(
    data: &[u8],
    pos: usize,
    flavor: Flavor,
    budget: &mut usize,
) -> Option<(Question, usize)> {
    let (name, pos) = read_name(data, pos, flavor, budget)?;
    let qtype = be16(data, pos)?;
    let class = be16(data, pos.checked_add(2)?)?;
    Some((
        Question {
            name,
            qtype,
            qclass: class & 0x7fff,
            unicast_response: class & 0x8000 != 0,
        },
        pos.checked_add(4)?,
    ))
}

fn parse_record(
    data: &[u8],
    pos: usize,
    section: Section,
    flavor: Flavor,
    budget: &mut usize,
) -> Option<(Record, usize)> {
    let (name, pos) = read_name(data, pos, flavor, budget)?;
    let rtype = be16(data, pos)?;
    let class = be16(data, pos.checked_add(2)?)?;
    let ttl = be32(data, pos.checked_add(4)?)?;
    let rdlen = usize::from(be16(data, pos.checked_add(8)?)?);
    let start = pos.checked_add(10)?;
    let end = start.checked_add(rdlen)?;
    let rdata = data.get(start..end)?;
    let class = if rtype == rtype::OPT {
        class
    } else {
        class & 0x7fff
    };
    let data_value = parse_rdata(data, start, rdata, rtype, flavor, budget);
    Some((
        Record {
            section,
            name,
            rtype,
            class,
            ttl,
            data: data_value,
        },
        end,
    ))
}

fn parse_rdata(
    msg: &[u8],
    start: usize,
    rdata: &[u8],
    rtype: u16,
    flavor: Flavor,
    budget: &mut usize,
) -> RData {
    let other = RData::Other(rdata.len());
    let limit = start.saturating_add(rdata.len());
    // Names inside record data are plain DNS names, even in NBNS, and end inside the data.
    let mut name_at = |off: usize| -> Option<String> {
        name_in(msg, start.checked_add(off)?, limit, budget).map(|(n, _)| n)
    };
    let decoded = match (flavor, rtype) {
        (Flavor::Nbns, rtype::NB) => Some(RData::Nb(nb_addresses(rdata))),
        (Flavor::Nbns, rtype::NBSTAT) => Some(RData::NbStat(nbstat_names(rdata))),
        (Flavor::Nbns | Flavor::Dns, rtype::A) => {
            <[u8; 4]>::try_from(rdata).ok().map(|b| RData::A(b.into()))
        }
        (Flavor::Dns, rtype::AAAA) => <[u8; 16]>::try_from(rdata)
            .ok()
            .map(|b| RData::Aaaa(b.into())),
        (Flavor::Dns, rtype::CNAME | rtype::NS | rtype::PTR | rtype::DNAME) => {
            name_at(0).map(RData::Name)
        }
        (Flavor::Dns, rtype::MX) => Some(RData::Mx {
            preference: be16(rdata, 0).unwrap_or(0),
            exchange: name_at(2).unwrap_or_default(),
        }),
        (Flavor::Dns, rtype::SRV) => Some(RData::Srv {
            priority: be16(rdata, 0).unwrap_or(0),
            weight: be16(rdata, 2).unwrap_or(0),
            port: be16(rdata, 4).unwrap_or(0),
            target: name_at(6).unwrap_or_default(),
        }),
        (Flavor::Dns, rtype::SOA) => soa(msg, start, limit, budget),
        (Flavor::Dns, rtype::TXT | rtype::HINFO | rtype::SPF) => {
            Some(RData::Text(char_strings(rdata)))
        }
        _ => None,
    };
    decoded.unwrap_or(other)
}

fn soa(msg: &[u8], start: usize, limit: usize, budget: &mut usize) -> Option<RData> {
    let (mname, next) = name_in(msg, start, limit, budget)?;
    let (rname, next) = name_in(msg, next, limit, budget)?;
    let serial_end = next.checked_add(4)?;
    if serial_end > limit {
        return None;
    }
    Some(RData::Soa {
        mname,
        rname,
        serial: be32(msg, next)?,
    })
}

/// A plain DNS name starting at `pos` whose own bytes (before any pointer) end by `limit`.
fn name_in(msg: &[u8], pos: usize, limit: usize, budget: &mut usize) -> Option<(String, usize)> {
    let (name, next) = read_name(msg, pos, Flavor::Dns, budget)?;
    (next <= limit).then_some((name.name, next))
}

/// Takes one step of the per-message budget of [`read_name`].
fn spend(budget: &mut usize) -> Option<()> {
    *budget = budget.checked_sub(1)?;
    Some(())
}

fn nb_addresses(rdata: &[u8]) -> Vec<NbAddress> {
    rdata
        .as_chunks::<6>()
        .0
        .iter()
        .take(MAX_NB_ADDRESSES)
        .map(|&[f0, f1, a, b, c, d]| {
            let flags = u16::from_be_bytes([f0, f1]);
            NbAddress {
                group: flags & 0x8000 != 0,
                node_type: u8::try_from((flags >> 13) & 0x3).unwrap_or(0),
                addr: Ipv4Addr::new(a, b, c, d),
            }
        })
        .collect()
}

fn nbstat_names(rdata: &[u8]) -> Vec<NbStatName> {
    let Some((&count, rest)) = rdata.split_first() else {
        return Vec::new();
    };
    rest.as_chunks::<18>()
        .0
        .iter()
        .take(usize::from(count).min(MAX_NBSTAT_NAMES))
        .filter_map(|entry| {
            let raw = entry.get(..15)?;
            let suffix = *entry.get(15)?;
            let flags = be16(entry, 16)?;
            Some(NbStatName {
                name: netbios_text(raw),
                suffix,
                group: flags & 0x8000 != 0,
            })
        })
        .collect()
}

/// Character strings joined by a space, cut at [`MAX_TEXT_LEN`] bytes.
fn char_strings(rdata: &[u8]) -> String {
    let mut out = String::new();
    let mut rest = rdata;
    while let Some((&len, tail)) = rest.split_first() {
        let Some((piece, next)) = tail.split_at_checked(usize::from(len)) else {
            break;
        };
        if !out.is_empty() {
            out.push(' ');
        }
        push_text(&mut out, piece);
        if out.len() >= MAX_TEXT_LEN {
            break;
        }
        rest = next;
    }
    truncate_utf8(&mut out, MAX_TEXT_LEN);
    out
}

/// Appends bytes as text: valid UTF-8 is kept, control characters and invalid bytes are
/// escaped as `\DDD` (RFC 1035 presentation format).
fn push_text(out: &mut String, bytes: &[u8]) {
    for chunk in bytes.utf8_chunks() {
        for c in chunk.valid().chars() {
            if c.is_control() {
                for b in c.to_string().bytes() {
                    let _ = write!(out, "\\{b:03}");
                }
            } else {
                out.push(c);
            }
        }
        for b in chunk.invalid() {
            let _ = write!(out, "\\{b:03}");
        }
    }
}

fn truncate_utf8(s: &mut String, max: usize) {
    if s.len() > max {
        let mut cut = max;
        while cut > 0 && !s.is_char_boundary(cut) {
            cut = cut.saturating_sub(1);
        }
        s.truncate(cut);
    }
}

/// Reads a possibly compressed name at `pos`; returns it and the position after it (after the
/// first pointer when the name is compressed).
fn read_name(data: &[u8], pos: usize, flavor: Flavor, budget: &mut usize) -> Option<(Name, usize)> {
    let mut labels: Vec<&[u8]> = Vec::new();
    let mut cursor = pos;
    let mut end: Option<usize> = None;
    // Pointers must go strictly backwards (no loop is possible) and are capped per name.
    let mut lowest = pos;
    let mut jumps: usize = 0;
    let mut wire_len: usize = 0;
    loop {
        spend(budget)?;
        let len = *data.get(cursor)?;
        match len & 0xc0 {
            0x00 => {
                let start = cursor.checked_add(1)?;
                if len == 0 {
                    end.get_or_insert(start);
                    break;
                }
                let stop = start.checked_add(usize::from(len))?;
                labels.push(data.get(start..stop)?);
                wire_len = wire_len.checked_add(usize::from(len))?.checked_add(1)?;
                if labels.len() > MAX_LABELS || wire_len > MAX_NAME_LEN {
                    return None;
                }
                cursor = stop;
            }
            0xc0 => {
                let low = *data.get(cursor.checked_add(1)?)?;
                let target = usize::from(len & 0x3f) << 8 | usize::from(low);
                jumps = jumps.checked_add(1)?;
                if target >= lowest || jumps > MAX_POINTER_JUMPS {
                    return None;
                }
                end.get_or_insert(cursor.checked_add(2)?);
                lowest = target;
                cursor = target;
            }
            // 0x40 (extended label types, obsolete) and 0x80 (reserved).
            _ => return None,
        }
    }
    let next = end?;
    Some((present(&labels, flavor), next))
}

/// Presentation form: labels joined by dots, special characters escaped.
fn present(labels: &[&[u8]], flavor: Flavor) -> Name {
    let mut out = String::new();
    let mut suffix = None;
    let mut rest = labels;
    if flavor == Flavor::Nbns
        && let Some((first, tail)) = labels.split_first()
        && let Some((name, sfx)) = decode_netbios(first)
    {
        out.push_str(&name);
        suffix = Some(sfx);
        rest = tail;
    }
    for label in rest {
        if !out.is_empty() {
            out.push('.');
        }
        for chunk in label.utf8_chunks() {
            for c in chunk.valid().chars() {
                match c {
                    '.' | '\\' => {
                        out.push('\\');
                        out.push(c);
                    }
                    c if c.is_control() || c == ' ' => {
                        for b in c.to_string().bytes() {
                            let _ = write!(out, "\\{b:03}");
                        }
                    }
                    c => out.push(c),
                }
            }
            for b in chunk.invalid() {
                let _ = write!(out, "\\{b:03}");
            }
        }
    }
    truncate_utf8(&mut out, MAX_NAME_LEN);
    Name { name: out, suffix }
}

/// Level-one decoding of a 32-byte NetBIOS label (`'A' + nibble`); `None` if it is not one.
fn decode_netbios(label: &[u8]) -> Option<(String, u8)> {
    if label.len() != 32 {
        return None;
    }
    let mut raw = [0u8; 16];
    for (slot, &[h, l]) in raw.iter_mut().zip(label.as_chunks::<2>().0) {
        let hi = h.checked_sub(b'A').filter(|v| *v < 16)?;
        let lo = l.checked_sub(b'A').filter(|v| *v < 16)?;
        *slot = hi << 4 | lo;
    }
    let (name, suffix) = raw.split_at(15);
    Some((netbios_text(name), *suffix.first()?))
}

/// The 15 name bytes of a NetBIOS name: trailing spaces and NULs removed, other unprintable
/// bytes escaped (`*` wildcard queries keep their `*`).
fn netbios_text(raw: &[u8]) -> String {
    let trimmed = raw
        .iter()
        .rposition(|b| *b != b' ' && *b != 0)
        .and_then(|last| raw.get(..=last))
        .unwrap_or_default();
    let mut out = String::new();
    for &b in trimmed {
        if b.is_ascii_graphic() || b == b' ' {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "\\{b:03}");
        }
    }
    out
}

/// Text of a record value for display (empty for undecoded data).
pub fn rdata_text(data: &RData) -> String {
    match data {
        RData::A(ip) => ip.to_string(),
        RData::Aaaa(ip) => ip.to_string(),
        RData::Name(n) | RData::Text(n) => n.clone(),
        RData::Mx {
            preference,
            exchange,
        } => format!("{preference} {exchange}"),
        RData::Srv {
            priority,
            weight,
            port,
            target,
        } => format!("{priority} {weight} {port} {target}"),
        RData::Soa {
            mname,
            rname,
            serial,
        } => format!("{mname} {rname} {serial}"),
        RData::Nb(addrs) => addrs
            .iter()
            .map(|a| a.addr.to_string())
            .collect::<Vec<_>>()
            .join(" "),
        RData::NbStat(names) => names
            .iter()
            .map(|n| format!("{}<{:02X}>", n.name, n.suffix))
            .collect::<Vec<_>>()
            .join(" "),
        RData::Other(_) => String::new(),
    }
}
