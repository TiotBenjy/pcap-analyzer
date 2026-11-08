//! TLS handshake records (RFC 5246, RFC 8446, RFC 6066 SNI, RFC 7301 ALPN, RFC 8701 GREASE):
//! `ClientHello`, `ServerHello`, `Certificate`, `ServerKeyExchange`, `ServerHelloDone`, plus
//! `ChangeCipherSpec`, alert and opaque application data records. Each handshake message is
//! wrapped in its own record. TLS 1.3 extensions (`supported_versions`, `key_share`) and GREASE
//! values are opt-in: without them the bytes are those of a plain TLS 1.2 handshake.

/// `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`.
pub const TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: u16 = 0xc02f;
/// `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`.
pub const TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: u16 = 0xc02b;

/// Default client cipher-suite offer.
pub const DEFAULT_CIPHER_SUITES: &[u16] = &[
    0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
];

const CONTENT_CHANGE_CIPHER_SPEC: u8 = 20;
const CONTENT_ALERT: u8 = 21;
const CONTENT_HANDSHAKE: u8 = 22;
const CONTENT_APPLICATION_DATA: u8 = 23;
const RECORD_VERSION: u16 = 0x0303;
const LEGACY_HELLO_RECORD_VERSION: u16 = 0x0301;

const HS_CLIENT_HELLO: u8 = 1;
const HS_SERVER_HELLO: u8 = 2;
const HS_CERTIFICATE: u8 = 11;
const HS_SERVER_KEY_EXCHANGE: u8 = 12;
const HS_SERVER_HELLO_DONE: u8 = 14;

const EXT_SERVER_NAME: u16 = 0;
const EXT_SUPPORTED_GROUPS: u16 = 10;
const EXT_EC_POINT_FORMATS: u16 = 11;
const EXT_SIGNATURE_ALGORITHMS: u16 = 13;
const EXT_ALPN: u16 = 16;
const EXT_EXTENDED_MASTER_SECRET: u16 = 23;
const EXT_SUPPORTED_VERSIONS: u16 = 43;
const EXT_KEY_SHARE: u16 = 51;
const EXT_RENEGOTIATION_INFO: u16 = 0xff01;

/// X25519 named group.
pub const GROUP_X25519: u16 = 0x001d;

/// Parameters of a `ClientHello`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHello {
    /// `legacy_version` (0x0303 for TLS 1.2 and 1.3).
    pub version: u16,
    pub random: [u8; 32],
    pub session_id: Vec<u8>,
    pub cipher_suites: Vec<u16>,
    pub sni: Option<String>,
    pub alpn: Vec<String>,
    /// `supported_versions` extension, omitted when empty.
    pub supported_versions: Vec<u16>,
    /// Groups of a `key_share` extension (32-byte keys), omitted when empty.
    pub key_share_groups: Vec<u16>,
    /// GREASE value added (RFC 8701) as first suite, first and last extension, first group and
    /// first supported version.
    pub grease: Option<u16>,
}

/// Parameters of a `ServerHello`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerHello {
    /// `legacy_version`.
    pub version: u16,
    pub random: [u8; 32],
    pub session_id: Vec<u8>,
    pub cipher_suite: u16,
    pub alpn: Option<String>,
    /// TLS 1.3: `supported_versions` and `key_share` (x25519) only, instead of the TLS 1.2
    /// extensions.
    pub selected_version: Option<u16>,
}

/// `ClientHello` record.
pub fn client_hello_record(hello: &ClientHello) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&hello.version.to_be_bytes());
    body.extend_from_slice(&hello.random);
    push_u8_vec(&mut body, &hello.session_id);
    let suites: Vec<u8> = hello
        .grease
        .iter()
        .chain(&hello.cipher_suites)
        .flat_map(|s| s.to_be_bytes())
        .collect();
    push_u16_vec(&mut body, &suites);
    push_u8_vec(&mut body, &[0]); // compression: null

    let mut ext = Vec::new();
    if let Some(g) = hello.grease {
        push_extension(&mut ext, g, &[]);
    }
    if let Some(sni) = &hello.sni {
        let mut entry = vec![0u8]; // host_name
        push_u16_vec(&mut entry, sni.as_bytes());
        let mut list = Vec::new();
        push_u16_vec(&mut list, &entry);
        push_extension(&mut ext, EXT_SERVER_NAME, &list);
    }
    push_extension(&mut ext, EXT_EXTENDED_MASTER_SECRET, &[]);
    push_extension(&mut ext, EXT_RENEGOTIATION_INFO, &[0]);
    let mut groups = Vec::new();
    let group_list: Vec<u8> = hello
        .grease
        .iter()
        .chain(&[GROUP_X25519, 0x0017, 0x0018])
        .flat_map(|g| g.to_be_bytes())
        .collect();
    push_u16_vec(&mut groups, &group_list);
    push_extension(&mut ext, EXT_SUPPORTED_GROUPS, &groups);
    push_extension(&mut ext, EXT_EC_POINT_FORMATS, &[1, 0]);
    let mut sig = Vec::new();
    push_u16_vec(&mut sig, &[4, 3, 8, 4, 4, 1, 5, 3, 8, 5, 5, 1, 8, 6, 6, 1]);
    push_extension(&mut ext, EXT_SIGNATURE_ALGORITHMS, &sig);
    if !hello.alpn.is_empty() {
        push_extension(&mut ext, EXT_ALPN, &alpn_list(&hello.alpn));
    }
    if !hello.supported_versions.is_empty() {
        let versions: Vec<u8> = hello
            .grease
            .iter()
            .chain(&hello.supported_versions)
            .flat_map(|v| v.to_be_bytes())
            .collect();
        let mut data = Vec::new();
        push_u8_vec(&mut data, &versions);
        push_extension(&mut ext, EXT_SUPPORTED_VERSIONS, &data);
    }
    if !hello.key_share_groups.is_empty() {
        let mut shares = Vec::new();
        for g in &hello.key_share_groups {
            shares.extend_from_slice(&g.to_be_bytes());
            push_u16_vec(&mut shares, &[0x42; 32]);
        }
        let mut data = Vec::new();
        push_u16_vec(&mut data, &shares);
        push_extension(&mut ext, EXT_KEY_SHARE, &data);
    }
    if let Some(g) = hello.grease {
        push_extension(&mut ext, g ^ 0x1010, &[0]);
    }
    push_u16_vec(&mut body, &ext);

    record(
        LEGACY_HELLO_RECORD_VERSION,
        &handshake(HS_CLIENT_HELLO, &body),
    )
}

/// `ServerHello` record.
pub fn server_hello_record(hello: &ServerHello) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&hello.version.to_be_bytes());
    body.extend_from_slice(&hello.random);
    push_u8_vec(&mut body, &hello.session_id);
    body.extend_from_slice(&hello.cipher_suite.to_be_bytes());
    body.push(0);

    let mut ext = Vec::new();
    if let Some(version) = hello.selected_version {
        push_extension(&mut ext, EXT_SUPPORTED_VERSIONS, &version.to_be_bytes());
        let mut share = GROUP_X25519.to_be_bytes().to_vec();
        push_u16_vec(&mut share, &[0x24; 32]);
        push_extension(&mut ext, EXT_KEY_SHARE, &share);
    } else {
        push_extension(&mut ext, EXT_RENEGOTIATION_INFO, &[0]);
        push_extension(&mut ext, EXT_EXTENDED_MASTER_SECRET, &[]);
        push_extension(&mut ext, EXT_EC_POINT_FORMATS, &[1, 0]);
    }
    if let Some(proto) = &hello.alpn {
        push_extension(&mut ext, EXT_ALPN, &alpn_list(std::slice::from_ref(proto)));
    }
    push_u16_vec(&mut body, &ext);
    record(RECORD_VERSION, &handshake(HS_SERVER_HELLO, &body))
}

/// `Certificate` record carrying a DER certificate chain (leaf first).
pub fn certificate_record(chain: &[Vec<u8>]) -> Vec<u8> {
    let mut list = Vec::new();
    for cert in chain {
        push_u24_vec(&mut list, cert);
    }
    let mut body = Vec::new();
    push_u24_vec(&mut body, &list);
    record(RECORD_VERSION, &handshake(HS_CERTIFICATE, &body))
}

/// `ServerKeyExchange` record of an ECDHE suite: named curve x25519, a 32-byte public point
/// and a `ecdsa_secp256r1_sha256` signature of filler bytes (RFC 8422 5.4).
pub fn server_key_exchange_record() -> Vec<u8> {
    let mut body = vec![3]; // named_curve
    body.extend_from_slice(&GROUP_X25519.to_be_bytes());
    push_u8_vec(&mut body, &[0x09; 32]);
    body.extend_from_slice(&[4, 3]);
    push_u16_vec(&mut body, &[0x5a; 70]);
    record(RECORD_VERSION, &handshake(HS_SERVER_KEY_EXCHANGE, &body))
}

/// `ChangeCipherSpec` record.
pub fn change_cipher_spec_record() -> Vec<u8> {
    let mut out = vec![CONTENT_CHANGE_CIPHER_SPEC];
    out.extend_from_slice(&RECORD_VERSION.to_be_bytes());
    push_u16_vec(&mut out, &[1]);
    out
}

/// Plaintext alert record (`level` 1 warning, 2 fatal).
pub fn alert_record(level: u8, description: u8) -> Vec<u8> {
    let mut out = vec![CONTENT_ALERT];
    out.extend_from_slice(&RECORD_VERSION.to_be_bytes());
    push_u16_vec(&mut out, &[level, description]);
    out
}

/// Application data record of `len` opaque bytes (encrypted traffic, or a TLS 1.3 encrypted
/// handshake flight).
pub fn application_data_record(len: usize, fill: u8) -> Vec<u8> {
    let mut out = vec![CONTENT_APPLICATION_DATA];
    out.extend_from_slice(&RECORD_VERSION.to_be_bytes());
    push_u16_vec(&mut out, &vec![fill; len.min(16_384)]);
    out
}

/// Encrypted handshake record (TLS 1.2 `Finished` after `ChangeCipherSpec`): opaque bytes in
/// a handshake record.
pub fn encrypted_handshake_record(len: usize) -> Vec<u8> {
    let mut out = vec![CONTENT_HANDSHAKE];
    out.extend_from_slice(&RECORD_VERSION.to_be_bytes());
    push_u16_vec(&mut out, &vec![0x77; len.min(16_384)]);
    out
}

/// `ServerHelloDone` record.
pub fn server_hello_done_record() -> Vec<u8> {
    record(RECORD_VERSION, &handshake(HS_SERVER_HELLO_DONE, &[]))
}

fn alpn_list(protocols: &[String]) -> Vec<u8> {
    let mut names = Vec::new();
    for p in protocols {
        push_u8_vec(&mut names, p.as_bytes());
    }
    let mut out = Vec::new();
    push_u16_vec(&mut out, &names);
    out
}

fn handshake(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![kind];
    push_u24_vec(&mut out, body);
    out
}

fn record(version: u16, fragment: &[u8]) -> Vec<u8> {
    assert!(fragment.len() <= 16_384, "TLS record fragment too large");
    let mut out = vec![CONTENT_HANDSHAKE];
    out.extend_from_slice(&version.to_be_bytes());
    push_u16_vec(&mut out, fragment);
    out
}

fn push_extension(out: &mut Vec<u8>, kind: u16, data: &[u8]) {
    out.extend_from_slice(&kind.to_be_bytes());
    push_u16_vec(out, data);
}

fn push_u8_vec(out: &mut Vec<u8>, data: &[u8]) {
    out.push(u8::try_from(data.len()).expect("vector fits in u8 length"));
    out.extend_from_slice(data);
}

fn push_u16_vec(out: &mut Vec<u8>, data: &[u8]) {
    let len = u16::try_from(data.len()).expect("vector fits in u16 length");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(data);
}

fn push_u24_vec(out: &mut Vec<u8>, data: &[u8]) {
    let len = u32::try_from(data.len())
        .ok()
        .filter(|l| *l < 1 << 24)
        .expect("vector fits in u24 length");
    out.extend_from_slice(len.to_be_bytes().get(1..).unwrap_or_default());
    out.extend_from_slice(data);
}
