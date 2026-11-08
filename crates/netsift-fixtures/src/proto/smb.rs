//! SMB2/3 messages and NTLMSSP tokens (MS-SMB2, MS-NLMP) for the SMB analyzer tests.
//!
//! These build byte-exact wire messages: an SMB2 header, a `NEGOTIATE` response, `SESSION_SETUP`
//! request/response carrying a security blob, and the three NTLMSSP messages. Strings in
//! NTLMSSP are UTF-16LE with the unicode negotiate flag set.

const NTLMSSP_SIGNATURE: &[u8; 8] = b"NTLMSSP\0";
const NEGOTIATE_UNICODE: u32 = 0x0000_0001;

fn utf16(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

/// Appends a security buffer field (`len`, `maxlen`, `offset`) pointing at `payload`, growing it.
fn push_field(fields: &mut Vec<u8>, payload: &mut Vec<u8>, base: usize, data: &[u8]) {
    let len = u16::try_from(data.len()).expect("field fits in u16");
    let offset = u32::try_from(base + payload.len()).expect("offset fits in u32");
    fields.extend_from_slice(&len.to_le_bytes());
    fields.extend_from_slice(&len.to_le_bytes());
    fields.extend_from_slice(&offset.to_le_bytes());
    payload.extend_from_slice(data);
}

/// NTLMSSP `NEGOTIATE` (type 1). The analyzer only checks the signature and type.
pub fn ntlmssp_negotiate() -> Vec<u8> {
    let mut out = NTLMSSP_SIGNATURE.to_vec();
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&NEGOTIATE_UNICODE.to_le_bytes());
    out.extend_from_slice(&[0u8; 8]); // domain fields
    out.extend_from_slice(&[0u8; 8]); // workstation fields
    out
}

/// NTLMSSP CHALLENGE (type 2) with the given 8-byte server challenge and target name.
pub fn ntlmssp_challenge(server_challenge: [u8; 8], target: &str) -> Vec<u8> {
    const HEADER: usize = 48;
    let mut header = Vec::with_capacity(HEADER);
    let mut payload = Vec::new();
    header.extend_from_slice(NTLMSSP_SIGNATURE);
    header.extend_from_slice(&2u32.to_le_bytes());
    // TargetName fields (8) at offset 12.
    let mut fields = Vec::new();
    push_field(&mut fields, &mut payload, HEADER, &utf16(target));
    header.extend_from_slice(&fields);
    header.extend_from_slice(&NEGOTIATE_UNICODE.to_le_bytes()); // flags at 20
    header.extend_from_slice(&server_challenge); // at 24
    header.extend_from_slice(&[0u8; 8]); // reserved at 32
    header.extend_from_slice(&[0u8; 8]); // TargetInfo fields at 40
    debug_assert_eq!(header.len(), HEADER);
    header.extend_from_slice(&payload);
    header
}

/// NTLMSSP AUTHENTICATE (type 3) with the given identity and response blobs.
pub fn ntlmssp_authenticate(
    domain: &str,
    user: &str,
    workstation: &str,
    lm_response: &[u8],
    nt_response: &[u8],
) -> Vec<u8> {
    const HEADER: usize = 64;
    let mut header = Vec::with_capacity(HEADER);
    let mut payload = Vec::new();
    let mut fields = Vec::new();
    header.extend_from_slice(NTLMSSP_SIGNATURE);
    header.extend_from_slice(&3u32.to_le_bytes());
    // Order in the header: LM(12), NT(20), Domain(28), User(36), Workstation(44), SessionKey(52).
    push_field(&mut fields, &mut payload, HEADER, lm_response);
    push_field(&mut fields, &mut payload, HEADER, nt_response);
    push_field(&mut fields, &mut payload, HEADER, &utf16(domain));
    push_field(&mut fields, &mut payload, HEADER, &utf16(user));
    push_field(&mut fields, &mut payload, HEADER, &utf16(workstation));
    push_field(&mut fields, &mut payload, HEADER, &[]); // encrypted session key
    header.extend_from_slice(&fields);
    header.extend_from_slice(&NEGOTIATE_UNICODE.to_le_bytes()); // flags at 60
    debug_assert_eq!(header.len(), HEADER);
    header.extend_from_slice(&payload);
    header
}

/// A 64-byte SMB2 header.
fn smb2_header(command: u16, flags: u32, status: u32) -> Vec<u8> {
    let mut h = Vec::with_capacity(64);
    h.extend_from_slice(b"\xfeSMB");
    h.extend_from_slice(&64u16.to_le_bytes()); // StructureSize
    h.extend_from_slice(&0u16.to_le_bytes()); // CreditCharge
    h.extend_from_slice(&status.to_le_bytes()); // Status
    h.extend_from_slice(&command.to_le_bytes());
    h.extend_from_slice(&1u16.to_le_bytes()); // CreditReqResp
    h.extend_from_slice(&flags.to_le_bytes());
    h.extend_from_slice(&0u32.to_le_bytes()); // NextCommand
    h.extend_from_slice(&0u64.to_le_bytes()); // MessageId
    h.extend_from_slice(&0u32.to_le_bytes()); // Reserved
    h.extend_from_slice(&0u32.to_le_bytes()); // TreeId
    h.extend_from_slice(&0u64.to_le_bytes()); // SessionId
    h.extend_from_slice(&[0u8; 16]); // Signature
    debug_assert_eq!(h.len(), 64);
    h
}

const FLAG_RESPONSE: u32 = 0x0000_0001;

/// SMB2 `NEGOTIATE` request (minimal; ignored by the analyzer but completes the exchange).
pub fn smb2_negotiate_request() -> Vec<u8> {
    let mut m = smb2_header(0x0000, 0, 0);
    m.extend_from_slice(&36u16.to_le_bytes()); // StructureSize
    m.extend_from_slice(&[0u8; 34]); // remaining fixed body
    m
}

/// SMB2 `NEGOTIATE` response advertising `dialect`, `security_mode` and `server_guid`.
pub fn smb2_negotiate_response(dialect: u16, security_mode: u16, server_guid: [u8; 16]) -> Vec<u8> {
    let mut m = smb2_header(0x0000, FLAG_RESPONSE, 0);
    m.extend_from_slice(&65u16.to_le_bytes()); // StructureSize
    m.extend_from_slice(&security_mode.to_le_bytes());
    m.extend_from_slice(&dialect.to_le_bytes());
    m.extend_from_slice(&0u16.to_le_bytes()); // NegotiateContextCount
    m.extend_from_slice(&server_guid);
    m.extend_from_slice(&[0u8; 40]); // capabilities, sizes, times, security buffer fields
    m
}

/// SMB2 `SESSION_SETUP` request carrying `blob` (the GSS/NTLMSSP security token).
pub fn smb2_session_setup_request(blob: &[u8]) -> Vec<u8> {
    let mut m = smb2_header(0x0001, 0, 0);
    let base = m.len();
    let sec_offset = u16::try_from(base + 24).expect("offset fits");
    let sec_len = u16::try_from(blob.len()).expect("blob fits");
    m.extend_from_slice(&25u16.to_le_bytes()); // StructureSize
    m.push(0); // Flags
    m.push(0); // SecurityMode
    m.extend_from_slice(&0u32.to_le_bytes()); // Capabilities
    m.extend_from_slice(&0u32.to_le_bytes()); // Channel
    m.extend_from_slice(&sec_offset.to_le_bytes());
    m.extend_from_slice(&sec_len.to_le_bytes());
    m.extend_from_slice(&0u64.to_le_bytes()); // PreviousSessionId
    m.extend_from_slice(blob);
    m
}

/// SMB2 `SESSION_SETUP` response with `status` carrying `blob`.
pub fn smb2_session_setup_response(status: u32, blob: &[u8]) -> Vec<u8> {
    let mut m = smb2_header(0x0001, FLAG_RESPONSE, status);
    let base = m.len();
    let sec_offset = u16::try_from(base + 8).expect("offset fits");
    let sec_len = u16::try_from(blob.len()).expect("blob fits");
    m.extend_from_slice(&9u16.to_le_bytes()); // StructureSize
    m.extend_from_slice(&0u16.to_le_bytes()); // SessionFlags
    m.extend_from_slice(&sec_offset.to_le_bytes());
    m.extend_from_slice(&sec_len.to_le_bytes());
    m.extend_from_slice(blob);
    m
}

/// A 32-byte SMB1 header for `command` (response flag set when `response`).
fn smb1_header(command: u8, response: bool) -> Vec<u8> {
    let mut h = Vec::with_capacity(32);
    h.extend_from_slice(b"\xffSMB");
    h.push(command);
    h.extend_from_slice(&0u32.to_le_bytes()); // status
    h.push(if response { 0x80 } else { 0x00 }); // flags
    h.extend_from_slice(&0u16.to_le_bytes()); // flags2
    h.extend_from_slice(&0u16.to_le_bytes()); // pid high
    h.extend_from_slice(&[0u8; 8]); // security features
    h.extend_from_slice(&0u16.to_le_bytes()); // reserved
    h.extend_from_slice(&0u16.to_le_bytes()); // tid
    h.extend_from_slice(&0u16.to_le_bytes()); // pid low
    h.extend_from_slice(&0u16.to_le_bytes()); // uid
    h.extend_from_slice(&0u16.to_le_bytes()); // mid
    debug_assert_eq!(h.len(), 32);
    h
}

/// Minimal SMB1 `SMB_COM_NEGOTIATE` response (the analyzer only keys on the command).
pub fn smb1_negotiate_response() -> Vec<u8> {
    let mut m = smb1_header(0x72, true);
    m.push(1); // word count
    m.extend_from_slice(&0u16.to_le_bytes()); // one word
    m.extend_from_slice(&0u16.to_le_bytes()); // byte count
    m
}

/// SMB1 `SMB_COM_SESSION_SETUP_ANDX` request with extended security carrying `blob` (`WordCount` 12).
pub fn smb1_session_setup_andx_request(blob: &[u8]) -> Vec<u8> {
    let mut m = smb1_header(0x73, false);
    m.push(12); // word count
    m.extend_from_slice(&[0xff, 0x00]); // AndXCommand, AndXReserved
    m.extend_from_slice(&0u16.to_le_bytes()); // AndXOffset
    m.extend_from_slice(&4356u16.to_le_bytes()); // MaxBufferSize
    m.extend_from_slice(&50u16.to_le_bytes()); // MaxMpxCount
    m.extend_from_slice(&0u16.to_le_bytes()); // VcNumber
    m.extend_from_slice(&0u32.to_le_bytes()); // SessionKey
    let blob_len = u16::try_from(blob.len()).expect("blob fits");
    m.extend_from_slice(&blob_len.to_le_bytes()); // SecurityBlobLength
    m.extend_from_slice(&0u32.to_le_bytes()); // Reserved
    m.extend_from_slice(&0u32.to_le_bytes()); // Capabilities
    let byte_count = u16::try_from(blob.len()).expect("byte count fits");
    m.extend_from_slice(&byte_count.to_le_bytes());
    m.extend_from_slice(blob);
    m
}

/// Wraps an SMB message in a NetBIOS session service header (4 bytes: type 0 + 24-bit length).
pub fn nbss(message: &[u8]) -> Vec<u8> {
    let len = u32::try_from(message.len()).expect("SMB message fits in 24 bits");
    let mut out = Vec::with_capacity(message.len() + 4);
    out.push(0);
    out.extend_from_slice(&len.to_be_bytes()[1..]);
    out.extend_from_slice(message);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_round_trips_offsets() {
        let m = ntlmssp_challenge([1, 2, 3, 4, 5, 6, 7, 8], "CORP");
        assert_eq!(&m[0..8], NTLMSSP_SIGNATURE);
        assert_eq!(u32::from_le_bytes([m[8], m[9], m[10], m[11]]), 2);
        assert_eq!(&m[24..32], &[1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn nbss_prefix_is_a_24_bit_length() {
        let framed = nbss(&[0xaa; 5]);
        assert_eq!(&framed[0..4], &[0, 0, 0, 5]);
        assert_eq!(&framed[4..], &[0xaa; 5]);
    }
}
