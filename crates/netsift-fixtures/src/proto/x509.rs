//! Self-signed X.509 v3 certificates built with the in-crate DER encoder.
//!
//! The issuer equals the subject, the public key is the P-256 base point (a valid curve
//! point) and the ECDSA signature is a well-formed `Ecdsa-Sig-Value` filled with seeded
//! pseudo-random bytes: the certificate parses like a real one but its signature does not
//! verify. Analyzers only parse certificates, they never validate chains.

use super::der::{self, tag};
use crate::rng::SplitMix64;
use crate::time::utc_from_unix;

const OID_ECDSA_SHA256: &[u32] = &[1, 2, 840, 10_045, 4, 3, 2];
const OID_EC_PUBLIC_KEY: &[u32] = &[1, 2, 840, 10_045, 2, 1];
const OID_PRIME256V1: &[u32] = &[1, 2, 840, 10_045, 3, 1, 7];
const OID_COUNTRY: &[u32] = &[2, 5, 4, 6];
const OID_ORGANIZATION: &[u32] = &[2, 5, 4, 10];
const OID_COMMON_NAME: &[u32] = &[2, 5, 4, 3];
const OID_BASIC_CONSTRAINTS: &[u32] = &[2, 5, 29, 19];
const OID_SUBJECT_ALT_NAME: &[u32] = &[2, 5, 29, 17];

/// Uncompressed P-256 generator point `04 || Gx || Gy`.
const P256_GENERATOR: [u8; 65] = [
    0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40,
    0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2,
    0x96, 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e,
    0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51,
    0xf5,
];

/// Content of a self-signed certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertSpec {
    pub common_name: String,
    pub organization: Option<String>,
    /// Two-letter country code.
    pub country: Option<String>,
    /// `subjectAltName` DNS names (omitted when empty).
    pub dns_names: Vec<String>,
    pub serial: u64,
    /// Validity start, seconds since the Unix epoch.
    pub not_before: i64,
    /// Validity end, seconds since the Unix epoch.
    pub not_after: i64,
}

impl CertSpec {
    /// Certificate for `common_name`, valid 2023-01-01 to 2033-01-01, SAN = CN.
    pub fn new(common_name: impl Into<String>) -> Self {
        let common_name = common_name.into();
        Self {
            dns_names: vec![common_name.clone()],
            common_name,
            organization: Some("NetSift Fixtures".to_owned()),
            country: Some("FR".to_owned()),
            serial: 0x1001,
            not_before: 1_672_531_200,
            not_after: 1_988_150_400,
        }
    }
}

/// DER encoding of a self-signed certificate (issuer = subject).
pub fn self_signed_certificate(spec: &CertSpec) -> Vec<u8> {
    let algorithm = der::sequence(&[&der::oid(OID_ECDSA_SHA256)]);
    let name = distinguished_name(spec);
    let validity = der::sequence(&[&time(spec.not_before), &time(spec.not_after)]);
    let spki = der::sequence(&[
        &der::sequence(&[&der::oid(OID_EC_PUBLIC_KEY), &der::oid(OID_PRIME256V1)]),
        &der::bit_string(&P256_GENERATOR),
    ]);

    let mut extensions = vec![der::sequence(&[
        &der::oid(OID_BASIC_CONSTRAINTS),
        &der::boolean(true),
        &der::octet_string(&der::sequence(&[])),
    ])];
    if !spec.dns_names.is_empty() {
        let names: Vec<u8> = spec
            .dns_names
            .iter()
            .flat_map(|n| der::tlv(0x82, n.as_bytes()))
            .collect();
        extensions.push(der::sequence(&[
            &der::oid(OID_SUBJECT_ALT_NAME),
            &der::octet_string(&der::tlv(tag::SEQUENCE, &names)),
        ]));
    }
    let ext_refs: Vec<&[u8]> = extensions.iter().map(Vec::as_slice).collect();

    let tbs = der::sequence(&[
        &der::explicit(0, &der::integer_i64(2)),
        &der::integer_unsigned(&spec.serial.to_be_bytes()),
        &algorithm,
        &name,
        &validity,
        &name,
        &spki,
        &der::explicit(3, &der::sequence(&ext_refs)),
    ]);

    let mut rng = SplitMix64::new(spec.serial ^ 0x5eed_ce87);
    let r: [u8; 32] = rng.bytes();
    let s: [u8; 32] = rng.bytes();
    let signature = der::sequence(&[&der::integer_unsigned(&r), &der::integer_unsigned(&s)]);

    der::sequence(&[&tbs, &algorithm, &der::bit_string(&signature)])
}

fn distinguished_name(spec: &CertSpec) -> Vec<u8> {
    let mut rdns = Vec::new();
    if let Some(c) = &spec.country {
        rdns.push(attribute(OID_COUNTRY, tag::PRINTABLE_STRING, c));
    }
    if let Some(o) = &spec.organization {
        rdns.push(attribute(OID_ORGANIZATION, tag::UTF8_STRING, o));
    }
    rdns.push(attribute(
        OID_COMMON_NAME,
        tag::UTF8_STRING,
        &spec.common_name,
    ));
    let refs: Vec<&[u8]> = rdns.iter().map(Vec::as_slice).collect();
    der::sequence(&refs)
}

fn attribute(oid: &[u32], string_tag: u8, value: &str) -> Vec<u8> {
    der::set(&[&der::sequence(&[
        &der::oid(oid),
        &der::tlv(string_tag, value.as_bytes()),
    ])])
}

/// `UTCTime` for 1950..=2049, `GeneralizedTime` otherwise (RFC 5280, 4.1.2.5).
fn time(unix: i64) -> Vec<u8> {
    let t = utc_from_unix(unix);
    let tail = format!(
        "{:02}{:02}{:02}{:02}{:02}Z",
        t.month, t.day, t.hour, t.minute, t.second
    );
    if (1950..2050).contains(&t.year) {
        let text = format!("{:02}{tail}", t.year % 100);
        der::tlv(tag::UTC_TIME, text.as_bytes())
    } else {
        let text = format!("{:04}{tail}", t.year);
        der::tlv(tag::GENERALIZED_TIME, text.as_bytes())
    }
}
