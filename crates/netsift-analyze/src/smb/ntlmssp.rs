//! NTLMSSP messages (MS-NLMP) and the hashcat lines derived from a captured challenge/response.
//!
//! The three message types are located by their `NTLMSSP\0` signature inside the security blob
//! (SPNEGO/GSS-API wrapping is skipped by searching for the signature). Every field is read
//! through a bounds-checked security-buffer accessor; nothing is ever sized from an unchecked
//! length. NetSift only *formats* the observed material for offline tools: it computes no hash
//! and performs no recovery.

use std::fmt;

use super::bytes::{array, decode_string, find, le16, le32, slice, to_hex};

/// `NTLMSSP\0` signature.
const SIGNATURE: &[u8; 8] = b"NTLMSSP\0";
/// Longest blob we scan for the signature.
const MAX_SCAN: usize = 4096;
/// `NTLMSSP_NEGOTIATE_UNICODE`.
const NEGOTIATE_UNICODE: u32 = 0x0000_0001;
/// `NTLMSSP_NEGOTIATE_ANONYMOUS`.
const NEGOTIATE_ANONYMOUS: u32 = 0x0000_0800;
/// Upper bound on a response field we copy (defensive: real responses are far smaller).
const MAX_RESPONSE: usize = 4096;

/// A parsed NTLMSSP message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NtlmMessage {
    Negotiate,
    Challenge { server_challenge: [u8; 8] },
    Authenticate(NtlmAuth),
}

/// The non-cryptographic fields of an AUTHENTICATE message plus its response blobs.
///
/// The response blobs are offline-recoverable material: [`fmt::Debug`] shows only their length,
/// never their bytes, so a credential can never leak through logs.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct NtlmAuth {
    pub domain: Option<String>,
    pub user: Option<String>,
    pub workstation: Option<String>,
    pub lm_response: Vec<u8>,
    pub nt_response: Vec<u8>,
    /// Anonymous logon (ANONYMOUS flag, or no user and no NT response): carries no credential.
    pub anonymous: bool,
}

impl fmt::Debug for NtlmAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NtlmAuth")
            .field("domain", &self.domain)
            .field("user", &self.user)
            .field("workstation", &self.workstation)
            .field(
                "lm_response",
                &format_args!("{} bytes", self.lm_response.len()),
            )
            .field(
                "nt_response",
                &format_args!("{} bytes", self.nt_response.len()),
            )
            .field("anonymous", &self.anonymous)
            .finish()
    }
}

/// A ready-to-crack hashcat line and its mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashcatLine {
    /// 5500 (`NetNTLMv1`) or 5600 (`NetNTLMv2`).
    pub mode: u32,
    /// `ntlmv1` or `ntlmv2`.
    pub kind: &'static str,
    pub line: String,
}

/// Reads a security buffer (`len`, `maxlen`, `offset`) at `field_off` and returns the bytes it
/// points to, within `msg`.
fn security_buffer(msg: &[u8], field_off: usize) -> Option<&[u8]> {
    let len = usize::from(le16(msg, field_off)?);
    let offset = usize::try_from(le32(msg, field_off + 4)?).ok()?;
    if len > MAX_RESPONSE {
        return None;
    }
    slice(msg, offset, len)
}

/// Locates the NTLMSSP message inside `blob` (skipping any SPNEGO/GSS wrapping) and parses it.
pub fn parse(blob: &[u8]) -> Option<NtlmMessage> {
    let start = find(blob, SIGNATURE, MAX_SCAN)?;
    let msg = blob.get(start..)?;
    parse_message(msg)
}

/// Parses a message that starts exactly at the `NTLMSSP\0` signature.
fn parse_message(msg: &[u8]) -> Option<NtlmMessage> {
    if slice(msg, 0, 8)? != SIGNATURE {
        return None;
    }
    match le32(msg, 8)? {
        1 => Some(NtlmMessage::Negotiate),
        2 => {
            let server_challenge = array(msg, 24)?;
            Some(NtlmMessage::Challenge { server_challenge })
        }
        3 => Some(NtlmMessage::Authenticate(parse_authenticate(msg)?)),
        _ => None,
    }
}

fn parse_authenticate(msg: &[u8]) -> Option<NtlmAuth> {
    let flags = le32(msg, 60).unwrap_or(0);
    let unicode = flags & NEGOTIATE_UNICODE != 0;
    let text = |off: usize| security_buffer(msg, off).map(|b| decode_string(b, unicode));
    let lm_response = security_buffer(msg, 12)?.to_vec();
    let nt_response = security_buffer(msg, 20)?.to_vec();
    let user = text(36).filter(|s| !s.is_empty());
    let anonymous = flags & NEGOTIATE_ANONYMOUS != 0 || (user.is_none() && nt_response.is_empty());
    Some(NtlmAuth {
        domain: text(28).filter(|s| !s.is_empty()),
        user,
        workstation: text(44).filter(|s| !s.is_empty()),
        lm_response,
        nt_response,
        anonymous,
    })
}

/// A hashcat field (`user`, `domain`) is safe when it cannot break the `:`-separated line.
fn safe_field(s: &str) -> bool {
    !s.bytes().any(|b| b == b':' || b == b'\n' || b == b'\r')
}

/// Builds the hashcat line pairing a server challenge with an AUTHENTICATE response, or `None`
/// when the response carries no crackable material, or when the identity cannot be put in the
/// line without corrupting it (a `:` or newline in the user or domain).
pub fn hashcat(server_challenge: [u8; 8], auth: &NtlmAuth) -> Option<HashcatLine> {
    let user = auth.user.clone().unwrap_or_default();
    let domain = auth.domain.clone().unwrap_or_default();
    if !safe_field(&user) || !safe_field(&domain) {
        return None;
    }
    let challenge = to_hex(&server_challenge);
    match auth.nt_response.len() {
        // NetNTLMv1: 24-byte NT response. hashcat 5500:
        // user::domain:LMresp(48):NTresp(48):serverChallenge(16).
        // ESS / NTLM2 session: the LM field is the 8-byte client challenge followed by 16 zero
        // bytes; hashcat 5500 detects that shape and applies the session-hash transform itself, so
        // emitting the real LM response (not a substitute) is enough.
        24 => {
            let lm = if auth.lm_response.len() == 24 {
                &auth.lm_response
            } else {
                // No usable LM response: reuse the NT response (hashcat cracks the NT part).
                &auth.nt_response
            };
            Some(HashcatLine {
                mode: 5500,
                kind: "ntlmv1",
                line: format!(
                    "{user}::{domain}:{}:{}:{challenge}",
                    to_hex(lm),
                    to_hex(&auth.nt_response),
                ),
            })
        }
        // NetNTLMv2: NT response = NTProofStr(16) + blob. hashcat 5600:
        // user::domain:serverChallenge(16):NTProofStr(32):blob
        n if n > 24 => {
            let proof = auth.nt_response.get(..16)?;
            let rest = auth.nt_response.get(16..)?;
            Some(HashcatLine {
                mode: 5600,
                kind: "ntlmv2",
                line: format!(
                    "{user}::{domain}:{challenge}:{}:{}",
                    to_hex(proof),
                    to_hex(rest),
                ),
            })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netsift_fixtures::proto::smb::{
        ntlmssp_authenticate, ntlmssp_challenge, ntlmssp_negotiate,
    };

    #[test]
    fn parses_the_three_message_types() {
        assert_eq!(parse(&ntlmssp_negotiate()), Some(NtlmMessage::Negotiate));
        let chal = [1, 2, 3, 4, 5, 6, 7, 8];
        assert_eq!(
            parse(&ntlmssp_challenge(chal, "CORP")),
            Some(NtlmMessage::Challenge {
                server_challenge: chal
            }),
        );
        let msg = ntlmssp_authenticate("CORP", "alice", "WS01", &[0x11; 24], &[0x22; 24]);
        let Some(NtlmMessage::Authenticate(auth)) = parse(&msg) else {
            panic!("not an authenticate message");
        };
        assert_eq!(auth.domain.as_deref(), Some("CORP"));
        assert_eq!(auth.user.as_deref(), Some("alice"));
        assert_eq!(auth.workstation.as_deref(), Some("WS01"));
        assert_eq!(auth.nt_response, vec![0x22; 24]);
    }

    #[test]
    fn hashcat_v1_line() {
        let auth = NtlmAuth {
            domain: Some("CORP".to_owned()),
            user: Some("alice".to_owned()),
            lm_response: vec![0xaa; 24],
            nt_response: vec![0xbb; 24],
            ..NtlmAuth::default()
        };
        let line = hashcat([0xcb, 0x80, 0x86, 0x04, 0x9e, 0xc4, 0x73, 0x6c], &auth).unwrap();
        assert_eq!(line.mode, 5500);
        assert_eq!(
            line.line,
            format!(
                "alice::CORP:{}:{}:cb8086049ec4736c",
                "aa".repeat(24),
                "bb".repeat(24)
            )
        );
    }

    #[test]
    fn hashcat_v2_line() {
        // NT response = 16-byte proof + variable blob.
        let mut nt = vec![0x01; 16];
        nt.extend_from_slice(&[0x02; 40]);
        let auth = NtlmAuth {
            domain: Some("CORP".to_owned()),
            user: Some("bob".to_owned()),
            lm_response: vec![0; 24],
            nt_response: nt,
            ..NtlmAuth::default()
        };
        let line = hashcat([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88], &auth).unwrap();
        assert_eq!(line.mode, 5600);
        assert_eq!(
            line.line,
            format!(
                "bob::CORP:1122334455667788:{}:{}",
                "01".repeat(16),
                "02".repeat(40)
            ),
        );
    }

    #[test]
    fn empty_response_has_no_line() {
        let auth = NtlmAuth {
            user: Some("anon".to_owned()),
            ..NtlmAuth::default()
        };
        assert!(hashcat([0; 8], &auth).is_none());
    }

    #[test]
    fn non_ascii_unicode_user_is_decoded() {
        let msg = ntlmssp_authenticate("ACME", "élodie", "PÇ-01", &[0; 24], &[9; 24]);
        let Some(NtlmMessage::Authenticate(auth)) = parse(&msg) else {
            panic!("not authenticate");
        };
        assert_eq!(auth.user.as_deref(), Some("élodie"));
        assert_eq!(auth.workstation.as_deref(), Some("PÇ-01"));
    }

    #[test]
    fn anonymous_is_flagged() {
        // No user and no NT response: anonymous logon.
        let msg = ntlmssp_authenticate("", "", "", &[0], &[]);
        let Some(NtlmMessage::Authenticate(auth)) = parse(&msg) else {
            panic!("not authenticate");
        };
        assert!(auth.anonymous);
    }

    #[test]
    fn a_colon_in_the_identity_rejects_the_line() {
        // A ':' would split the hashcat fields; the line is refused (metadata only upstream).
        let auth = NtlmAuth {
            domain: Some("CO:RP".to_owned()),
            user: Some("al:ice".to_owned()),
            lm_response: vec![0xaa; 24],
            nt_response: vec![0xbb; 24],
            ..NtlmAuth::default()
        };
        assert!(hashcat([0; 8], &auth).is_none());
    }

    #[test]
    fn ess_ntlm2_session_uses_the_real_lm_for_mode_5500() {
        // ESS: LM = 8-byte client challenge followed by 16 zero bytes; hashcat 5500 detects it.
        let mut lm = vec![0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04];
        lm.extend_from_slice(&[0u8; 16]);
        let auth = NtlmAuth {
            domain: Some("CORP".to_owned()),
            user: Some("carol".to_owned()),
            lm_response: lm.clone(),
            nt_response: vec![0x77; 24],
            ..NtlmAuth::default()
        };
        let line = hashcat([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef], &auth).unwrap();
        assert_eq!(line.mode, 5500);
        assert_eq!(
            line.line,
            format!(
                "carol::CORP:{}:{}:0123456789abcdef",
                to_hex(&lm),
                "77".repeat(24)
            ),
        );
    }

    #[test]
    fn ms_nlmp_v1_vector() {
        // MS-NLMP 4.2.2: ServerChallenge, LM and NT responses of the documented NTLMv1 example.
        let server_challenge = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        let lm = hex("98def7b87f88aa5dbb6d4e6d2e6b0b0b0b0b0b0b0b0b0b0b");
        let nt = hex("67c43011f30298a2ad35ece64f16331c44bdbed927841f94");
        let auth = NtlmAuth {
            domain: Some("Domain".to_owned()),
            user: Some("User".to_owned()),
            lm_response: lm,
            nt_response: nt,
            ..NtlmAuth::default()
        };
        let line = hashcat(server_challenge, &auth).unwrap();
        assert_eq!(line.mode, 5500);
        assert_eq!(
            line.line,
            "User::Domain:98def7b87f88aa5dbb6d4e6d2e6b0b0b0b0b0b0b0b0b0b0b:\
             67c43011f30298a2ad35ece64f16331c44bdbed927841f94:0123456789abcdef"
        );
    }

    fn hex(s: &str) -> Vec<u8> {
        s.as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
            .collect()
    }

    #[test]
    fn hostile_blobs_never_panic() {
        for len in 0..200usize {
            let data: Vec<u8> = (0..len)
                .map(|i| u8::try_from(i % 256).unwrap_or(0))
                .collect();
            let _ = parse(&data);
        }
        // A signature with an out-of-range field offset must not slice out of bounds.
        let mut msg = SIGNATURE.to_vec();
        msg.extend_from_slice(&3u32.to_le_bytes());
        msg.resize(64, 0);
        let _ = parse(&msg);
    }
}
