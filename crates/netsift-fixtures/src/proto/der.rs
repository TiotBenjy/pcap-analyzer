//! Minimal DER/BER encoder (definite lengths only), enough for X.509 and SNMP.

/// Universal and context tags used by the encoders.
pub mod tag {
    pub const BOOLEAN: u8 = 0x01;
    pub const INTEGER: u8 = 0x02;
    pub const BIT_STRING: u8 = 0x03;
    pub const OCTET_STRING: u8 = 0x04;
    pub const NULL: u8 = 0x05;
    pub const OID: u8 = 0x06;
    pub const UTF8_STRING: u8 = 0x0c;
    pub const PRINTABLE_STRING: u8 = 0x13;
    pub const IA5_STRING: u8 = 0x16;
    pub const UTC_TIME: u8 = 0x17;
    pub const GENERALIZED_TIME: u8 = 0x18;
    pub const SEQUENCE: u8 = 0x30;
    pub const SET: u8 = 0x31;
}

/// Encodes a tag-length-value triple.
pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 6);
    out.push(tag);
    push_len(&mut out, content.len());
    out.extend_from_slice(content);
    out
}

fn push_len(out: &mut Vec<u8>, len: usize) {
    if let Ok(short) = u8::try_from(len)
        && short < 0x80
    {
        out.push(short);
        return;
    }
    let bytes = (len as u64).to_be_bytes();
    let skip = bytes.iter().take_while(|b| **b == 0).count();
    let significant = bytes.get(skip..).unwrap_or_default();
    out.push(0x80 | u8::try_from(significant.len()).expect("at most 8 length bytes"));
    out.extend_from_slice(significant);
}

/// Constructed SEQUENCE of already encoded elements.
pub fn sequence(parts: &[&[u8]]) -> Vec<u8> {
    tlv(tag::SEQUENCE, &parts.concat())
}

/// Constructed SET of already encoded elements (caller keeps DER order).
pub fn set(parts: &[&[u8]]) -> Vec<u8> {
    tlv(tag::SET, &parts.concat())
}

/// Context-specific constructed tag `[n]` (explicit tagging).
pub fn explicit(n: u8, inner: &[u8]) -> Vec<u8> {
    tlv(0xa0 | n, inner)
}

/// Signed INTEGER, minimal two's complement.
pub fn integer_i64(v: i64) -> Vec<u8> {
    let bytes = v.to_be_bytes();
    let mut start = 0;
    while start < 7 {
        let (Some(&cur), Some(&next)) = (bytes.get(start), bytes.get(start + 1)) else {
            break;
        };
        let redundant = (cur == 0x00 && next & 0x80 == 0) || (cur == 0xff && next & 0x80 != 0);
        if !redundant {
            break;
        }
        start += 1;
    }
    tlv(tag::INTEGER, bytes.get(start..).unwrap_or_default())
}

/// Non-negative INTEGER from big-endian magnitude bytes.
pub fn integer_unsigned(magnitude: &[u8]) -> Vec<u8> {
    let skip = magnitude.iter().take_while(|b| **b == 0).count();
    let trimmed = magnitude.get(skip..).unwrap_or_default();
    let mut content = Vec::with_capacity(trimmed.len() + 1);
    if trimmed.first().is_none_or(|b| b & 0x80 != 0) {
        content.push(0);
    }
    content.extend_from_slice(trimmed);
    tlv(tag::INTEGER, &content)
}

pub fn boolean(v: bool) -> Vec<u8> {
    tlv(tag::BOOLEAN, &[if v { 0xff } else { 0x00 }])
}

pub fn null() -> Vec<u8> {
    tlv(tag::NULL, &[])
}

pub fn octet_string(v: &[u8]) -> Vec<u8> {
    tlv(tag::OCTET_STRING, v)
}

/// BIT STRING with no unused bits.
pub fn bit_string(v: &[u8]) -> Vec<u8> {
    let mut content = Vec::with_capacity(v.len() + 1);
    content.push(0);
    content.extend_from_slice(v);
    tlv(tag::BIT_STRING, &content)
}

/// OBJECT IDENTIFIER from its arcs (at least two).
pub fn oid(arcs: &[u32]) -> Vec<u8> {
    assert!(arcs.len() >= 2, "an OID has at least two arcs");
    let mut content = Vec::new();
    let mut it = arcs.iter();
    let first = it.next().copied().unwrap_or_default();
    let second = it.next().copied().unwrap_or_default();
    push_base128(&mut content, first * 40 + second);
    for &arc in it {
        push_base128(&mut content, arc);
    }
    tlv(tag::OID, &content)
}

fn push_base128(out: &mut Vec<u8>, mut v: u32) {
    let mut tmp = [0u8; 5];
    let mut n = 0;
    loop {
        if let Some(slot) = tmp.get_mut(n) {
            *slot = u8::try_from(v & 0x7f).expect("7 bits");
        }
        n += 1;
        v >>= 7;
        if v == 0 {
            break;
        }
    }
    for i in (0..n).rev() {
        let b = tmp.get(i).copied().unwrap_or_default();
        out.push(if i == 0 { b } else { b | 0x80 });
    }
}

/// Parses a dotted OID (`"1.3.6.1.2.1.1.1.0"`).
///
/// # Panics
/// On a malformed OID string (fixture input is trusted).
pub fn parse_oid(dotted: &str) -> Vec<u32> {
    dotted
        .split('.')
        .map(|arc| arc.parse().expect("numeric OID arc"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers() {
        assert_eq!(integer_i64(0), [2, 1, 0]);
        assert_eq!(integer_i64(127), [2, 1, 0x7f]);
        assert_eq!(integer_i64(128), [2, 2, 0, 0x80]);
        assert_eq!(integer_i64(-1), [2, 1, 0xff]);
        assert_eq!(integer_i64(-129), [2, 2, 0xff, 0x7f]);
        assert_eq!(integer_unsigned(&[0, 0, 0x80]), [2, 2, 0, 0x80]);
        assert_eq!(integer_unsigned(&[]), [2, 1, 0]);
    }

    #[test]
    fn oids_and_lengths() {
        // sysDescr.0
        assert_eq!(
            oid(&parse_oid("1.3.6.1.2.1.1.1.0")),
            [6, 8, 0x2b, 6, 1, 2, 1, 1, 1, 0]
        );
        // ecdsa-with-SHA256: 1.2.840.10045.4.3.2
        assert_eq!(
            oid(&[1, 2, 840, 10045, 4, 3, 2]),
            [6, 8, 0x2a, 0x86, 0x48, 0xce, 0x3d, 4, 3, 2]
        );
        let long = tlv(tag::OCTET_STRING, &[0u8; 300]);
        assert_eq!(long.get(..4), Some(&[4u8, 0x82, 0x01, 0x2c][..]));
        assert_eq!(long.len(), 304);
    }
}
