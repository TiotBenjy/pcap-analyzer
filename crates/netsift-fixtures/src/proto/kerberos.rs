//! Kerberos V5 message encoder (RFC 4120), enough for the KDC exchanges of the scenarios:
//! AS-REQ, AS-REP, TGS-REP and KRB-ERROR with structurally valid DER and dummy cipher text.

use super::der::{self, explicit, integer_i64, octet_string, sequence, tlv};

/// `GeneralString` (Realm, `KerberosString`).
const GENERAL_STRING: u8 = 0x1b;
/// `GeneralizedTime` (`KerberosTime`).
const GENERALIZED_TIME: u8 = der::tag::GENERALIZED_TIME;

/// Application tag numbers of the message types.
pub const AS_REQ: u8 = 10;
pub const AS_REP: u8 = 11;
pub const TGS_REQ: u8 = 12;
pub const TGS_REP: u8 = 13;
pub const KRB_ERROR: u8 = 30;

/// `KDC_ERR_PREAUTH_REQUIRED`.
pub const ERR_PREAUTH_REQUIRED: i64 = 25;

fn application(n: u8, inner: &[u8]) -> Vec<u8> {
    tlv(0x60 | n, inner)
}

fn string(s: &str) -> Vec<u8> {
    tlv(GENERAL_STRING, s.as_bytes())
}

fn principal(name_type: i64, parts: &[&str]) -> Vec<u8> {
    let names: Vec<Vec<u8>> = parts.iter().map(|p| string(p)).collect();
    let refs: Vec<&[u8]> = names.iter().map(Vec::as_slice).collect();
    sequence(&[
        &explicit(0, &integer_i64(name_type)),
        &explicit(1, &sequence(&refs)),
    ])
}

fn encrypted(etype: i64, len: usize) -> Vec<u8> {
    let cipher: Vec<u8> = (0..len)
        .map(|i| u8::try_from(i * 37 % 251).unwrap_or(0))
        .collect();
    sequence(&[
        &explicit(0, &integer_i64(etype)),
        &explicit(1, &integer_i64(2)),
        &explicit(2, &octet_string(&cipher)),
    ])
}

fn time() -> Vec<u8> {
    tlv(GENERALIZED_TIME, b"20261108120000Z")
}

/// AS-REQ (`tgs = false`) or TGS-REQ (`tgs = true`) for `user@realm` (KDC-REQ: pvno at `[1]`,
/// realm inside the request body `[4]`).
pub fn kdc_req(tgs: bool, realm: &str, user: &str) -> Vec<u8> {
    let msg_type = if tgs { TGS_REQ } else { AS_REQ };
    let body = sequence(&[
        &explicit(0, &der::bit_string(&[0x40, 0x81, 0x00, 0x10])),
        &explicit(1, &principal(1, &[user])),
        &explicit(2, &string(realm)),
        &explicit(3, &principal(2, &["krbtgt", realm])),
        &explicit(5, &time()),
        &explicit(7, &integer_i64(0x1234_5678)),
        &explicit(8, &sequence(&[&integer_i64(18), &integer_i64(17)])),
    ]);
    application(
        msg_type,
        &sequence(&[
            &explicit(1, &integer_i64(5)),
            &explicit(2, &integer_i64(i64::from(msg_type))),
            &explicit(4, &body),
        ]),
    )
}

/// AS-REP (`tgs = false`) or TGS-REP (`tgs = true`) for `user@realm`, with a pre-auth hint
/// before the client realm (the field order of KDC-REP).
pub fn kdc_rep(tgs: bool, realm: &str, user: &str) -> Vec<u8> {
    let msg_type = if tgs { TGS_REP } else { AS_REP };
    let padata = sequence(&[&sequence(&[
        &explicit(1, &integer_i64(19)),
        &explicit(2, &octet_string(&[0x30, 0x00])),
    ])]);
    let ticket = application(
        1,
        &sequence(&[
            &explicit(0, &integer_i64(5)),
            &explicit(1, &string(realm)),
            &explicit(2, &principal(2, &["krbtgt", realm])),
            &explicit(3, &encrypted(18, 240)),
        ]),
    );
    application(
        msg_type,
        &sequence(&[
            &explicit(0, &integer_i64(5)),
            &explicit(1, &integer_i64(i64::from(msg_type))),
            &explicit(2, &padata),
            &explicit(3, &string(realm)),
            &explicit(4, &principal(1, &[user])),
            &explicit(5, &ticket),
            &explicit(6, &encrypted(18, 180)),
        ]),
    )
}

/// KRB-ERROR with `error_code`, server realm `realm`.
pub fn krb_error(error_code: i64, realm: &str) -> Vec<u8> {
    application(
        KRB_ERROR,
        &sequence(&[
            &explicit(0, &integer_i64(5)),
            &explicit(1, &integer_i64(i64::from(KRB_ERROR))),
            &explicit(4, &time()),
            &explicit(5, &integer_i64(0)),
            &explicit(6, &integer_i64(error_code)),
            &explicit(9, &string(realm)),
            &explicit(10, &principal(2, &["krbtgt", realm])),
        ]),
    )
}

/// TCP framing (RFC 4120 7.2.2): 4-byte big-endian length, then the message.
pub fn tcp_record(message: &[u8]) -> Vec<u8> {
    let mut out = u32::try_from(message.len())
        .expect("Kerberos message fits in a TCP record")
        .to_be_bytes()
        .to_vec();
    out.extend_from_slice(message);
    out
}
