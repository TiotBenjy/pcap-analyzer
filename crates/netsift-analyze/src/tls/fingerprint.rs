//! Client fingerprints computed from a `ClientHello`.
//!
//! - **`JA3`** (Salesforce, public definition): `SSLVersion,Ciphers,Extensions,EllipticCurves,
//!   EllipticCurvePointFormats`, decimal values joined by `-`, GREASE values removed, and the MD5
//!   of that string.
//! - **`JA4`** (`FoxIO`, public specification, TLS client part only): `a_b_c` where `a` is
//!   `t<version><d|i><ciphers:02><extensions:02><alpn>`, `b` the first 12 hex digits of the SHA-256
//!   of the sorted cipher list, `c` the same for the sorted extension list (SNI and ALPN removed)
//!   followed by `_` and the signature algorithms in wire order. GREASE values are ignored
//!   everywhere.

use std::fmt::Write as _;

use md5::{Digest as _, Md5};
use sha2::Sha256;

use super::hello::{ClientHello, ext, is_grease};

/// JA3 string and its MD5 (lower-case hex).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ja3 {
    pub text: String,
    pub hash: String,
}

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

fn decimal_list(values: impl Iterator<Item = u16>) -> String {
    values.map(|v| v.to_string()).collect::<Vec<_>>().join("-")
}

/// JA3 of a `ClientHello`.
pub fn ja3(ch: &ClientHello) -> Ja3 {
    let keep = |v: &u16| !is_grease(*v);
    let text = format!(
        "{},{},{},{},{}",
        ch.legacy_version,
        decimal_list(ch.cipher_suites.iter().copied().filter(keep)),
        decimal_list(ch.extensions.iter().copied().filter(keep)),
        decimal_list(ch.groups.iter().copied().filter(keep)),
        decimal_list(ch.point_formats.iter().map(|p| u16::from(*p))),
    );
    Ja3 {
        hash: md5_hex(text.as_bytes()),
        text,
    }
}

/// Lower-case hex MD5.
pub fn md5_hex(data: &[u8]) -> String {
    hex(&Md5::digest(data))
}

/// First 12 hex digits of the SHA-256 of `text`, `000000000000` for an empty text.
fn truncated_sha256(text: &str) -> String {
    if text.is_empty() {
        return "000000000000".to_owned();
    }
    let mut h = hex(&Sha256::digest(text.as_bytes()));
    h.truncate(12);
    h
}

/// Two-character JA4 version label.
fn version_label(v: u16) -> &'static str {
    match v {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        0x0002 => "s2",
        0xfeff => "d1",
        0xfefd => "d2",
        0xfefc => "d3",
        _ => "00",
    }
}

/// First and last characters of the raw first ALPN value; the first and last digits of its hex
/// form when either byte is not ASCII alphanumeric; `00` without ALPN.
fn alpn_label(alpn: Option<&[u8]>) -> String {
    let Some(bytes) = alpn.filter(|a| !a.is_empty()) else {
        return "00".to_owned();
    };
    match (bytes.first(), bytes.last()) {
        (Some(&f), Some(&l)) if f.is_ascii_alphanumeric() && l.is_ascii_alphanumeric() => {
            format!("{}{}", char::from(f), char::from(l))
        }
        _ => {
            let h = hex(bytes);
            let first = h.chars().next().unwrap_or('0');
            let last = h.chars().last().unwrap_or('0');
            format!("{first}{last}")
        }
    }
}

fn hex_list(values: &[u16]) -> String {
    values
        .iter()
        .map(|v| format!("{v:04x}"))
        .collect::<Vec<_>>()
        .join(",")
}

/// JA4 of a `ClientHello` seen over TCP.
pub fn ja4(ch: &ClientHello) -> String {
    let mut ciphers: Vec<u16> = ch
        .cipher_suites
        .iter()
        .copied()
        .filter(|c| !is_grease(*c))
        .collect();
    let exts: Vec<u16> = ch
        .extensions
        .iter()
        .copied()
        .filter(|e| !is_grease(*e))
        .collect();
    let sni = if ch.extensions.contains(&ext::SERVER_NAME) {
        'd'
    } else {
        'i'
    };
    let a = format!(
        "t{}{sni}{:02}{:02}{}",
        version_label(ch.offered_version()),
        ciphers.len().min(99),
        exts.len().min(99),
        alpn_label(ch.alpn_first.as_deref()),
    );

    ciphers.sort_unstable();
    let b = truncated_sha256(&hex_list(&ciphers));

    let mut sorted_exts: Vec<u16> = exts
        .into_iter()
        .filter(|e| *e != ext::SERVER_NAME && *e != ext::ALPN)
        .collect();
    sorted_exts.sort_unstable();
    let sigalgs: Vec<u16> = ch
        .signature_algs
        .iter()
        .copied()
        .filter(|s| !is_grease(*s))
        .collect();
    let c = if sorted_exts.is_empty() {
        "000000000000".to_owned()
    } else if sigalgs.is_empty() {
        truncated_sha256(&hex_list(&sorted_exts))
    } else {
        truncated_sha256(&format!(
            "{}_{}",
            hex_list(&sorted_exts),
            hex_list(&sigalgs)
        ))
    };
    format!("{a}_{b}_{c}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md5_matches_the_ja3_reference_example() {
        // Example of the JA3 README (Salesforce).
        assert_eq!(
            md5_hex(b"769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0"),
            "ada70206e40642a3e4461f35503241d5"
        );
    }

    #[test]
    fn ja4_hashes_match_the_specification_example() {
        // Example of the JA4 technical details (FoxIO): Chrome, JA4 t13d1516h2_8daaf6152771_e5627efa2ab1.
        assert_eq!(
            truncated_sha256(
                "002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9"
            ),
            "8daaf6152771"
        );
        assert_eq!(
            truncated_sha256(
                "0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01_\
                 0403,0804,0401,0503,0805,0501,0806,0601"
            ),
            "e5627efa2ab1"
        );
    }

    /// The Chrome hello of the JA4 example, rebuilt from its published lists (GREASE added).
    fn chrome() -> ClientHello {
        ClientHello {
            legacy_version: 0x0303,
            cipher_suites: vec![
                0x8a8a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8,
                0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
            ],
            extensions: vec![
                0x3a3a, 0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0023, 0x0010, 0x0005, 0x000d,
                0x0012, 0x0033, 0x002d, 0x002b, 0x001b, 0x0015, 0x4469, 0x1a1a,
            ],
            sni: Some("example.com".to_owned()),
            alpn: vec!["h2".to_owned(), "http/1.1".to_owned()],
            alpn_first: Some(b"h2".to_vec()),
            groups: vec![0x2a2a, 0x001d, 0x0017, 0x0018],
            point_formats: vec![0],
            signature_algs: vec![
                0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
            ],
            supported_versions: vec![0x7a7a, 0x0304, 0x0303],
            ..ClientHello::default()
        }
    }

    #[test]
    fn ja4_of_the_specification_example() {
        assert_eq!(ja4(&chrome()), "t13d1516h2_8daaf6152771_e5627efa2ab1");
    }

    #[test]
    fn ja3_excludes_grease() {
        let j = ja3(&chrome());
        assert_eq!(
            j.text,
            "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,\
             0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21-17513,29-23-24,0"
        );
        assert_eq!(j.hash, md5_hex(j.text.as_bytes()));
        assert_eq!(j.hash.len(), 32);
    }

    #[test]
    fn ja4_edge_cases() {
        let mut ch = ClientHello {
            legacy_version: 0x0301,
            ..ClientHello::default()
        };
        assert_eq!(ja4(&ch), "t10i000000_000000000000_000000000000");
        ch.alpn_first = Some(b"\x01x".to_vec());
        ch.extensions = vec![ext::ALPN];
        // Non alphanumeric first byte: first and last hex digits of "0178".
        assert!(ja4(&ch).starts_with("t10i000108_"), "{}", ja4(&ch));
        // Raw bytes, not the sanitized text (an invalid UTF-8 byte would become U+FFFD).
        ch.alpn_first = Some(vec![0xff, b'a']);
        assert!(ja4(&ch).starts_with("t10i0001f1_"), "{}", ja4(&ch));
        ch.legacy_version = 0x0300;
        ch.alpn_first = Some(b"h".to_vec());
        assert!(ja4(&ch).starts_with("ts3i0001hh_"), "{}", ja4(&ch));
        ch.cipher_suites = (0..150).collect();
        assert!(ja4(&ch).starts_with("ts3i9901hh_"), "{}", ja4(&ch));
        assert_eq!(alpn_label(Some(b"http/1.1")), "h1");
        assert_eq!(alpn_label(Some(b"")), "00");
        assert_eq!(alpn_label(Some(b"\x01x")), "08");
        assert_eq!(version_label(0x9999), "00");
    }

    #[test]
    fn grease_values() {
        for v in [0x0a0a, 0x1a1a, 0xfafa, 0x8a8a, 0xaaaa] {
            assert!(is_grease(v), "{v:#x}");
        }
        for v in [0x0a1a, 0x1301, 0x0000, 0xabab] {
            assert!(!is_grease(v), "{v:#x}");
        }
    }
}
