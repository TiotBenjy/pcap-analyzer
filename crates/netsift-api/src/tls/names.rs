//! Display names of TLS code points (IANA registries): extensions, named groups, signature
//! schemes and versions. Cipher suite names come from the session (`tls_cipher_suites`).

/// GREASE values (RFC 8701).
pub(crate) fn is_grease(v: u16) -> bool {
    v & 0x0f0f == 0x0a0a && v >> 8 == v & 0xff
}

pub(crate) fn extension(v: u16) -> Option<&'static str> {
    Some(match v {
        0 => "server_name",
        1 => "max_fragment_length",
        5 => "status_request",
        10 => "supported_groups",
        11 => "ec_point_formats",
        13 => "signature_algorithms",
        14 => "use_srtp",
        15 => "heartbeat",
        16 => "application_layer_protocol_negotiation",
        17 => "status_request_v2",
        18 => "signed_certificate_timestamp",
        21 => "padding",
        22 => "encrypt_then_mac",
        23 => "extended_master_secret",
        27 => "compress_certificate",
        28 => "record_size_limit",
        34 => "delegated_credentials",
        35 => "session_ticket",
        41 => "pre_shared_key",
        42 => "early_data",
        43 => "supported_versions",
        44 => "cookie",
        45 => "psk_key_exchange_modes",
        47 => "certificate_authorities",
        49 => "post_handshake_auth",
        50 => "signature_algorithms_cert",
        51 => "key_share",
        57 => "quic_transport_parameters",
        13172 => "next_protocol_negotiation",
        17513 => "application_settings",
        17613 => "application_settings_new",
        65037 => "encrypted_client_hello",
        65281 => "renegotiation_info",
        _ => return None,
    })
}

pub(crate) fn group(v: u16) -> Option<&'static str> {
    Some(match v {
        23 => "secp256r1",
        24 => "secp384r1",
        25 => "secp521r1",
        29 => "x25519",
        30 => "x448",
        256 => "ffdhe2048",
        257 => "ffdhe3072",
        258 => "ffdhe4096",
        259 => "ffdhe6144",
        260 => "ffdhe8192",
        512 => "MLKEM512",
        513 => "MLKEM768",
        514 => "MLKEM1024",
        4587 => "SecP256r1MLKEM768",
        4588 => "X25519MLKEM768",
        25497 => "X25519Kyber768Draft00",
        _ => return None,
    })
}

pub(crate) fn signature_scheme(v: u16) -> Option<&'static str> {
    Some(match v {
        0x0201 => "rsa_pkcs1_sha1",
        0x0203 => "ecdsa_sha1",
        0x0401 => "rsa_pkcs1_sha256",
        0x0403 => "ecdsa_secp256r1_sha256",
        0x0501 => "rsa_pkcs1_sha384",
        0x0503 => "ecdsa_secp384r1_sha384",
        0x0601 => "rsa_pkcs1_sha512",
        0x0603 => "ecdsa_secp521r1_sha512",
        0x0804 => "rsa_pss_rsae_sha256",
        0x0805 => "rsa_pss_rsae_sha384",
        0x0806 => "rsa_pss_rsae_sha512",
        0x0807 => "ed25519",
        0x0808 => "ed448",
        0x0809 => "rsa_pss_pss_sha256",
        0x080a => "rsa_pss_pss_sha384",
        0x080b => "rsa_pss_pss_sha512",
        _ => return None,
    })
}

pub(crate) fn version(v: u16) -> Option<&'static str> {
    Some(match v {
        0x0002 => "SSL 2.0",
        0x0300 => "SSL 3.0",
        0x0301 => "TLS 1.0",
        0x0302 => "TLS 1.1",
        0x0303 => "TLS 1.2",
        0x0304 => "TLS 1.3",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_and_unknown_values() {
        assert_eq!(extension(0), Some("server_name"));
        assert_eq!(extension(0xfafa), None);
        assert_eq!(group(29), Some("x25519"));
        assert_eq!(signature_scheme(0x0403), Some("ecdsa_secp256r1_sha256"));
        assert_eq!(version(0x0304), Some("TLS 1.3"));
        assert!(is_grease(0x2a2a) && !is_grease(0x0303));
    }
}
