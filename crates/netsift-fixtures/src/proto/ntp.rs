//! NTP packet encoder (RFC 5905 header, no extension fields).

/// NTP modes used by the scenarios.
pub const MODE_CLIENT: u8 = 3;
pub const MODE_SERVER: u8 = 4;

/// 48-byte NTP header. `reference_id` is the raw 4-byte field: ASCII for stratum 1 (`GPS\0`),
/// an IPv4 address for a secondary server.
pub fn encode(
    mode: u8,
    version: u8,
    stratum: u8,
    reference_id: [u8; 4],
    transmit_s: u32,
) -> Vec<u8> {
    let mut out = vec![0_u8; 48];
    out[0] = ((version & 0x07) << 3) | (mode & 0x07);
    out[1] = stratum;
    out[2] = 6; // poll: 64 s
    out[3] = 0xec; // precision: about 2^-20 s
    out[12..16].copy_from_slice(&reference_id);
    out[40..44].copy_from_slice(&transmit_s.to_be_bytes());
    out
}

/// Client request (mode 3, version 4, stratum 0).
pub fn request(transmit_s: u32) -> Vec<u8> {
    encode(MODE_CLIENT, 4, 0, [0; 4], transmit_s)
}

/// Server response (mode 4, version 4).
pub fn response(stratum: u8, reference_id: [u8; 4], transmit_s: u32) -> Vec<u8> {
    encode(MODE_SERVER, 4, stratum, reference_id, transmit_s)
}
