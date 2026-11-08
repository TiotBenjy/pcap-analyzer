//! SMB1 and SMB2/3 message recognition over TCP (NetBIOS session service framing on 139/445).
//!
//! Only what the SMB view needs is decoded: the SMB2 `NEGOTIATE` response (dialect, signing
//! posture, server GUID) and the NTLMSSP token carried by the security buffer of a `SESSION_SETUP`
//! (SMB2 command `0x0001`, SMB1 `SMB_COM_SESSION_SETUP_ANDX` `0x73`). NTLMSSP is searched **only**
//! inside that security buffer, never in arbitrary payload, so a `READ`/`WRITE` carrying the bytes
//! `NTLMSSP\0` cannot fabricate a credential. Parsing only, fully bounds-checked.

use super::bytes::{array, be24, le16, le32, le64, slice, u8_at};
use super::ntlmssp::{self, NtlmMessage};
use crate::record::{Signing, SmbProtocol};

/// SMB1 header magic (`\xffSMB`).
const SMB1_MAGIC: [u8; 4] = *b"\xffSMB";
/// SMB2/3 header magic (`\xfeSMB`).
const SMB2_MAGIC: [u8; 4] = *b"\xfeSMB";
/// SMB3 transform (encrypted) header magic (`\xfdSMB`): nothing to extract.
const SMB3_ENC_MAGIC: [u8; 4] = *b"\xfdSMB";

const SMB2_NEGOTIATE: u16 = 0x0000;
const SMB2_SESSION_SETUP: u16 = 0x0001;
const SMB2_FLAG_RESPONSE: u32 = 0x0000_0001;
const SMB1_COM_NEGOTIATE: u8 = 0x72;
const SMB1_COM_SESSION_SETUP_ANDX: u8 = 0x73;
/// SMB1 `flags` bit 7: the message is a response.
const SMB1_FLAGS_RESPONSE: u8 = 0x80;

/// NetBIOS session service message types (RFC 1002 4.3.1) we recognize.
pub const NBSS_SESSION_MESSAGE: u8 = 0x00;
pub const NBSS_POSITIVE_RESPONSE: u8 = 0x82;
pub const NBSS_SESSION_KEEPALIVE: u8 = 0x85;

/// What a single SMB PDU tells us.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SmbEvent {
    /// SMB dialect family recognized from the PDU magic (no negotiation details).
    Magic(SmbProtocol),
    /// Parsed SMB2 `NEGOTIATE` response.
    Negotiate {
        protocol: SmbProtocol,
        dialect: Option<String>,
        signing: Signing,
        server_guid: Option<[u8; 16]>,
    },
    /// A `SESSION_SETUP` and the NTLMSSP message found in its security buffer, if any.
    SessionSetup {
        protocol: SmbProtocol,
        /// SMB2 `SessionId` (0 for SMB1): the challenge and its response share it.
        session_id: u64,
        ntlm: Option<NtlmMessage>,
    },
}

/// NetBIOS session service header: `(nbss_type, declared_length, total_pdu_len)`. `None` when the
/// 4-byte header is not fully present yet.
pub fn nbss_header(buf: &[u8]) -> Option<(u8, usize, usize)> {
    let nbss_type = u8_at(buf, 0)?;
    let len = usize::try_from(be24(buf, 1)?).ok()?;
    Some((nbss_type, len, len.checked_add(4)?))
}

/// Parses one SMB PDU (the bytes after the 4-byte NBSS header).
pub fn parse_pdu(pdu: &[u8]) -> Option<SmbEvent> {
    let magic: [u8; 4] = array(pdu, 0)?;
    if magic == SMB2_MAGIC {
        return Some(parse_smb2(pdu));
    }
    if magic == SMB1_MAGIC {
        return Some(parse_smb1(pdu));
    }
    if magic == SMB3_ENC_MAGIC {
        return Some(SmbEvent::Magic(SmbProtocol::Smb2));
    }
    None
}

fn parse_smb2(pdu: &[u8]) -> SmbEvent {
    let Some(command) = le16(pdu, 12) else {
        return SmbEvent::Magic(SmbProtocol::Smb2);
    };
    let flags = le32(pdu, 16).unwrap_or(0);
    let is_response = flags & SMB2_FLAG_RESPONSE != 0;
    if command == SMB2_NEGOTIATE
        && is_response
        && let Some(ev) = parse_smb2_negotiate_response(pdu)
    {
        return ev;
    }
    if command == SMB2_SESSION_SETUP {
        let session_id = le64(pdu, 40).unwrap_or(0);
        let blob = smb2_session_setup_blob(pdu, is_response);
        return SmbEvent::SessionSetup {
            protocol: SmbProtocol::Smb2,
            session_id,
            ntlm: blob.and_then(ntlmssp::parse),
        };
    }
    SmbEvent::Magic(SmbProtocol::Smb2)
}

/// Security buffer of an SMB2 `SESSION_SETUP` (offsets from the SMB2 header start, i.e. `pdu`).
fn smb2_session_setup_blob(pdu: &[u8], is_response: bool) -> Option<&[u8]> {
    // Fields hold an offset counted from the SMB2 header start (= `pdu`).
    // Request body (StructureSize 25): SecurityBufferOffset at header+12, Length at +14.
    // Response body (StructureSize 9): SecurityBufferOffset at header+4, Length at +6.
    let (off_field, len_field) = if is_response { (68, 70) } else { (76, 78) };
    let offset = usize::from(le16(pdu, off_field)?);
    let len = usize::from(le16(pdu, len_field)?);
    slice(pdu, offset, len)
}

/// SMB2 `NEGOTIATE` response body starts right after the 64-byte header.
fn parse_smb2_negotiate_response(pdu: &[u8]) -> Option<SmbEvent> {
    const BODY: usize = 64;
    let security_mode = le16(pdu, BODY + 2)?;
    let dialect = le16(pdu, BODY + 4)?;
    let server_guid = array::<16>(pdu, BODY + 8);
    Some(SmbEvent::Negotiate {
        protocol: SmbProtocol::Smb2,
        dialect: Some(dialect_label(dialect)),
        signing: signing_of(security_mode),
        server_guid,
    })
}

fn parse_smb1(pdu: &[u8]) -> SmbEvent {
    let command = u8_at(pdu, 4).unwrap_or(0xff);
    if command == SMB1_COM_NEGOTIATE {
        return SmbEvent::Negotiate {
            protocol: SmbProtocol::Smb1,
            dialect: None,
            signing: Signing::Unknown,
            server_guid: None,
        };
    }
    if command == SMB1_COM_SESSION_SETUP_ANDX {
        return SmbEvent::SessionSetup {
            protocol: SmbProtocol::Smb1,
            session_id: 0,
            ntlm: smb1_session_setup_blob(pdu).and_then(ntlmssp::parse),
        };
    }
    SmbEvent::Magic(SmbProtocol::Smb1)
}

/// Security blob of an SMB1 `SESSION_SETUP_ANDX` with extended security (`WordCount` 12 request /
/// 4 response). Non-extended variants carry no NTLMSSP and return `None`.
fn smb1_session_setup_blob(pdu: &[u8]) -> Option<&[u8]> {
    let flags = u8_at(pdu, 9)?;
    let word_count = u8_at(pdu, 32)?;
    let is_response = flags & SMB1_FLAGS_RESPONSE != 0;
    // SecurityBlobLength word, then ByteCount right after the parameter words, then the blob.
    let (blob_len_off, data_off) = match (is_response, word_count) {
        (false, 12) => (47, 59),
        (true, 4) => (39, 43),
        _ => return None,
    };
    let blob_len = usize::from(le16(pdu, blob_len_off)?);
    slice(pdu, data_off, blob_len)
}

/// SMB2 `SecurityMode` bits to a [`Signing`] posture.
fn signing_of(security_mode: u16) -> Signing {
    const ENABLED: u16 = 0x0001;
    const REQUIRED: u16 = 0x0002;
    if security_mode & REQUIRED != 0 {
        Signing::Required
    } else if security_mode & ENABLED != 0 {
        Signing::Enabled
    } else {
        Signing::Disabled
    }
}

/// Readable label for an SMB2/3 dialect revision.
fn dialect_label(revision: u16) -> String {
    match revision {
        0x0202 => "SMB 2.0.2".to_owned(),
        0x0210 => "SMB 2.1".to_owned(),
        0x0300 => "SMB 3.0".to_owned(),
        0x0302 => "SMB 3.0.2".to_owned(),
        0x0311 => "SMB 3.1.1".to_owned(),
        0x02ff => "SMB 2.x".to_owned(),
        other => format!("SMB2 0x{other:04x}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netsift_fixtures::proto::smb;

    #[test]
    fn reads_smb2_negotiate_response() {
        let guid = [7u8; 16];
        let pdu = smb::smb2_negotiate_response(0x0311, 0x0002, guid);
        let SmbEvent::Negotiate {
            protocol,
            dialect,
            signing,
            server_guid,
        } = parse_pdu(&pdu).unwrap()
        else {
            panic!("not a negotiate");
        };
        assert_eq!(protocol, SmbProtocol::Smb2);
        assert_eq!(dialect.as_deref(), Some("SMB 3.1.1"));
        assert_eq!(signing, Signing::Required);
        assert_eq!(server_guid, Some(guid));
    }

    #[test]
    fn finds_ntlm_only_in_the_session_setup_security_buffer() {
        let blob = smb::ntlmssp_challenge([9; 8], "CORP");
        let pdu = smb::smb2_session_setup_response(0, &blob);
        assert!(matches!(
            parse_pdu(&pdu),
            Some(SmbEvent::SessionSetup {
                ntlm: Some(NtlmMessage::Challenge { .. }),
                ..
            })
        ));
    }

    #[test]
    fn ntlmssp_bytes_in_a_write_are_ignored() {
        // An SMB2 WRITE (command 0x0009) whose payload contains a full AUTHENTICATE token.
        let auth = smb::ntlmssp_authenticate("CORP", "eve", "WS", &[0; 24], &[1; 24]);
        let mut pdu = vec![0u8; 64];
        pdu[0..4].copy_from_slice(b"\xfeSMB");
        pdu[12..14].copy_from_slice(&0x0009u16.to_le_bytes()); // WRITE
        pdu.extend_from_slice(&auth);
        // Recognized as SMB2 but no SESSION_SETUP, hence no NTLM.
        assert_eq!(parse_pdu(&pdu), Some(SmbEvent::Magic(SmbProtocol::Smb2)));
    }

    #[test]
    fn reads_smb1_negotiate_and_session_setup() {
        assert!(matches!(
            parse_pdu(&smb::smb1_negotiate_response()),
            Some(SmbEvent::Negotiate {
                protocol: SmbProtocol::Smb1,
                ..
            })
        ));
        let blob = smb::ntlmssp_authenticate("CORP", "dave", "WS", &[0; 24], &[3; 24]);
        let pdu = smb::smb1_session_setup_andx_request(&blob);
        assert!(matches!(
            parse_pdu(&pdu),
            Some(SmbEvent::SessionSetup {
                protocol: SmbProtocol::Smb1,
                ntlm: Some(NtlmMessage::Authenticate(_)),
                ..
            })
        ));
    }

    #[test]
    fn unknown_or_short_pdus_do_not_panic() {
        assert_eq!(parse_pdu(&[]), None);
        assert_eq!(parse_pdu(b"junk"), None);
        for n in 0..90 {
            let pdu = smb::smb2_negotiate_response(0x0210, 1, [0; 16]);
            let _ = parse_pdu(&pdu[..n.min(pdu.len())]);
        }
    }
}
