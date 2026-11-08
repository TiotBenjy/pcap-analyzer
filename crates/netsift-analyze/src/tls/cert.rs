//! X.509 certificate decoding (RFC 5280) with `x509-parser`: only parsing, never validation.

use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use sha1::Sha1;
use sha2::{Digest as _, Sha256};
use x509_parser::extensions::GeneralName;
use x509_parser::objects::{oid_registry, oid2sn};
use x509_parser::prelude::{FromDer as _, X509Certificate};
use x509_parser::public_key::PublicKey;
use x509_parser::x509::X509Name;

const NS_PER_SEC: i64 = 1_000_000_000;
/// Longest kept distinguished name, in characters.
const MAX_NAME: usize = 1024;
/// Subject alternative names kept per certificate.
const MAX_SAN: usize = 100;
/// Longest kept alternative name, in characters.
const MAX_SAN_LEN: usize = 255;

/// Fields of a parsed certificate.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CertInfo {
    pub subject: String,
    pub subject_cn: Option<String>,
    pub issuer: String,
    pub issuer_cn: Option<String>,
    /// Hex.
    pub serial: String,
    /// Nanoseconds since the Unix epoch.
    pub not_before_ns: i64,
    pub not_after_ns: i64,
    /// `DNS:`, `IP:`, `email:`, `URI:` prefixed names.
    pub san: Vec<String>,
    /// `RSA`, `EC`, `DSA`, `Ed25519`, `Ed448` or the OID short name.
    pub key_algorithm: String,
    /// Key size in bits, when known.
    pub key_bits: Option<u32>,
    pub signature_algorithm: String,
    /// Issuer equals subject.
    pub self_signed: bool,
    /// Basic constraints `cA`.
    pub is_ca: bool,
}

impl CertInfo {
    /// RSA/DSA keys below 2048 bits and EC keys below 224 bits.
    pub fn weak_key(&self) -> bool {
        match (self.key_algorithm.as_str(), self.key_bits) {
            ("RSA" | "DSA", Some(bits)) => bits < 2048,
            ("EC", Some(bits)) => bits < 224,
            _ => false,
        }
    }
}

/// A certificate of a chain: digests of the DER, and its fields when it parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    pub sha256: [u8; 32],
    pub sha1: [u8; 20],
    pub size: u64,
    /// The DER was stored as a blob of the session.
    pub stored: bool,
    pub info: Option<CertInfo>,
}

impl Certificate {
    /// Digests and fields of a DER certificate (`stored` left false).
    pub fn from_der(der: &[u8]) -> Self {
        Self {
            sha256: Sha256::digest(der).into(),
            sha1: Sha1::digest(der).into(),
            size: u64::try_from(der.len()).unwrap_or(u64::MAX),
            stored: false,
            info: parse(der),
        }
    }
}

/// Lower-case hex.
pub fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

fn bounded(s: &str, max: usize) -> String {
    s.chars()
        .take(max)
        .map(|c| if c.is_control() { '\u{fffd}' } else { c })
        .collect()
}

fn common_name(name: &X509Name<'_>) -> Option<String> {
    name.iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(|cn| bounded(cn, MAX_SAN_LEN))
}

fn general_name(name: &GeneralName<'_>) -> Option<String> {
    let text = match name {
        GeneralName::DNSName(s) => format!("DNS:{s}"),
        GeneralName::RFC822Name(s) => format!("email:{s}"),
        GeneralName::URI(s) => format!("URI:{s}"),
        GeneralName::IPAddress(bytes) => {
            let ip = if let Ok(v4) = <[u8; 4]>::try_from(*bytes) {
                IpAddr::V4(Ipv4Addr::from(v4))
            } else {
                IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(*bytes).ok()?))
            };
            format!("IP:{ip}")
        }
        _ => return None,
    };
    Some(bounded(&text, MAX_SAN_LEN))
}

/// Bits of an unsigned big-endian integer.
fn bit_length(bytes: &[u8]) -> Option<u32> {
    let start = bytes.iter().position(|b| *b != 0)?;
    let significant = bytes.get(start..)?;
    let first = significant.first()?;
    let len = u32::try_from(significant.len()).ok()?;
    Some((len - 1) * 8 + (8 - first.leading_zeros()))
}

fn oid_name(oid: &x509_parser::der_parser::oid::Oid<'_>) -> String {
    oid2sn(oid, oid_registry()).map_or_else(|_| oid.to_id_string(), str::to_owned)
}

/// Fields of a DER certificate, `None` when it does not parse.
pub fn parse(der: &[u8]) -> Option<CertInfo> {
    let (_, cert) = X509Certificate::from_der(der).ok()?;
    let spki = cert.public_key();
    let (key_algorithm, key_bits) = match spki.parsed() {
        Ok(PublicKey::RSA(rsa)) => ("RSA".to_owned(), bit_length(rsa.modulus)),
        Ok(PublicKey::EC(ec)) => (
            "EC".to_owned(),
            u32::try_from(ec.key_size()).ok().filter(|b| *b > 0),
        ),
        Ok(PublicKey::DSA(y)) => ("DSA".to_owned(), bit_length(y)),
        _ => {
            let name = oid_name(&spki.algorithm.algorithm);
            let bits = match name.as_str() {
                "ED25519" | "Ed25519" => Some(256),
                "ED448" | "Ed448" => Some(456),
                _ => None,
            };
            let name = match name.as_str() {
                "ED25519" => "Ed25519".to_owned(),
                "ED448" => "Ed448".to_owned(),
                _ => name,
            };
            (name, bits)
        }
    };
    let san = match cert.subject_alternative_name() {
        Ok(Some(ext)) => ext
            .value
            .general_names
            .iter()
            .filter_map(general_name)
            .take(MAX_SAN)
            .collect(),
        _ => Vec::new(),
    };
    let is_ca = matches!(cert.basic_constraints(), Ok(Some(bc)) if bc.value.ca);
    Some(CertInfo {
        subject: bounded(&cert.subject().to_string(), MAX_NAME),
        subject_cn: common_name(cert.subject()),
        issuer: bounded(&cert.issuer().to_string(), MAX_NAME),
        issuer_cn: common_name(cert.issuer()),
        serial: hex(cert.raw_serial()),
        not_before_ns: cert
            .validity()
            .not_before
            .timestamp()
            .saturating_mul(NS_PER_SEC),
        not_after_ns: cert
            .validity()
            .not_after
            .timestamp()
            .saturating_mul(NS_PER_SEC),
        san,
        key_algorithm,
        key_bits,
        signature_algorithm: oid_name(&cert.signature_algorithm.algorithm),
        self_signed: cert.subject().as_raw() == cert.issuer().as_raw(),
        is_ca,
    })
}

#[cfg(test)]
mod tests {
    use netsift_fixtures::proto::x509::{CertSpec, self_signed_certificate};

    use super::*;

    #[test]
    fn parses_a_fixture_certificate() {
        let mut spec = CertSpec::new("secure.example.test");
        spec.dns_names.push("www.example.test".to_owned());
        let der = self_signed_certificate(&spec);
        let c = Certificate::from_der(&der);
        assert_eq!(c.size, der.len() as u64);
        let info = c.info.unwrap();
        assert_eq!(info.subject_cn.as_deref(), Some("secure.example.test"));
        assert_eq!(
            info.subject,
            "C=FR, O=NetSift Fixtures, CN=secure.example.test"
        );
        assert_eq!(info.issuer, info.subject);
        assert!(info.self_signed);
        assert!(!info.is_ca);
        assert_eq!(info.serial, "1001");
        assert_eq!(info.not_before_ns, 1_672_531_200 * NS_PER_SEC);
        assert_eq!(info.not_after_ns, 1_988_150_400 * NS_PER_SEC);
        assert_eq!(
            info.san,
            vec!["DNS:secure.example.test", "DNS:www.example.test"]
        );
        assert_eq!(info.key_algorithm, "EC");
        assert_eq!(info.key_bits, Some(256));
        assert_eq!(info.signature_algorithm, "ecdsa-with-SHA256");
        assert!(!info.weak_key());
    }

    #[test]
    fn garbage_and_truncated_der_do_not_parse() {
        let der = self_signed_certificate(&CertSpec::new("x.example.test"));
        for cut in [0, 1, 10, der.len() / 2, der.len() - 1] {
            assert!(parse(&der[..cut]).is_none(), "cut at {cut}");
        }
        assert!(parse(&[0x30, 0x84, 0xff, 0xff, 0xff, 0xff]).is_none());
        let c = Certificate::from_der(b"not a certificate");
        assert!(c.info.is_none());
        assert_eq!(hex(&c.sha256).len(), 64);
    }

    #[test]
    fn bit_lengths() {
        assert_eq!(bit_length(&[0x00, 0x80, 0x00]), Some(16));
        assert_eq!(bit_length(&[0x01]), Some(1));
        assert_eq!(bit_length(&[0x00, 0x00]), None);
        assert_eq!(bit_length(&[]), None);
        let weak = CertInfo {
            key_algorithm: "RSA".to_owned(),
            key_bits: Some(1024),
            ..CertInfo::default()
        };
        assert!(weak.weak_key());
    }
}
