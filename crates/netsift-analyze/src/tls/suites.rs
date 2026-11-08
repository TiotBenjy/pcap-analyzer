//! Cipher suite names (IANA registry, through `tls-parser`) and weakness classification.

use tls_parser::{TlsCipherEnc, TlsCipherEncMode, TlsCipherKx, TlsCipherMac, TlsCipherSuite};

/// Signaling values that are not real suites (never weak).
const SCSV: [u16; 2] = [0x00ff, 0x5600];

/// IANA name and weakness of a cipher suite, `None` when unknown.
///
/// Weakness labels, by priority: `null` (no encryption), `export`, `anon` (no
/// authentication), `rc4`, `des`, `3des`, `rc2`, `md5`, `cbc_sha1` (CBC with HMAC-SHA1).
pub fn describe(id: u16) -> Option<(&'static str, Option<&'static str>)> {
    let suite = TlsCipherSuite::from_id(id)?;
    if SCSV.contains(&id) {
        return Some((suite.name, None));
    }
    Some((suite.name, weakness(suite)))
}

fn weakness(s: &TlsCipherSuite) -> Option<&'static str> {
    if s.enc == TlsCipherEnc::Null {
        return Some("null");
    }
    if s.name.contains("_EXPORT") {
        return Some("export");
    }
    if s.name.contains("_anon_") || matches!(s.kx, TlsCipherKx::Aecdh) {
        return Some("anon");
    }
    match s.enc {
        TlsCipherEnc::Rc4 => return Some("rc4"),
        TlsCipherEnc::Des => return Some("des"),
        TlsCipherEnc::TripleDes => return Some("3des"),
        TlsCipherEnc::Rc2 => return Some("rc2"),
        _ => {}
    }
    match (s.mac, s.enc_mode) {
        (TlsCipherMac::HmacMd5, _) => Some("md5"),
        (TlsCipherMac::HmacSha1, TlsCipherEncMode::Cbc) => Some("cbc_sha1"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_weaknesses() {
        assert_eq!(describe(0x1301), Some(("TLS_AES_128_GCM_SHA256", None)));
        assert_eq!(
            describe(0xc02b),
            Some(("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", None))
        );
        let weak = |id| describe(id).and_then(|(_, w)| w);
        assert_eq!(weak(0x0005), Some("rc4")); // TLS_RSA_WITH_RC4_128_SHA
        assert_eq!(weak(0x000a), Some("3des")); // TLS_RSA_WITH_3DES_EDE_CBC_SHA
        assert_eq!(weak(0x0002), Some("null")); // TLS_RSA_WITH_NULL_SHA
        assert_eq!(weak(0x0003), Some("export")); // TLS_RSA_EXPORT_WITH_RC4_40_MD5
        assert_eq!(weak(0x0018), Some("anon")); // TLS_DH_anon_WITH_RC4_128_MD5
        assert_eq!(weak(0x002f), Some("cbc_sha1")); // TLS_RSA_WITH_AES_128_CBC_SHA
        assert_eq!(weak(0xc013), Some("cbc_sha1")); // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
        assert_eq!(weak(0x00ff), None);
        assert_eq!(describe(0xfafa), None);
    }
}
