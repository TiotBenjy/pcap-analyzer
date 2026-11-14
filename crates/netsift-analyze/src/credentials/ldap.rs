//! LDAP simple binds (RFC 4511 4.2), parsed with `ldap-parser`.
//!
//! The client stream is cut into BER messages (`LDAPMessage` SEQUENCE, length read from the
//! header and bounded); a `BindRequest` with simple authentication and a non-empty password is a
//! plain-text credential (DN and password). The server stream gives the `BindResponse` result
//! code, matched by message id. Anonymous and unauthenticated binds (empty password) and SASL
//! binds carry no password and are ignored. A stream that stops looking like LDAP (`StartTLS`,
//! garbage) is abandoned.

use ldap_parser::FromBer as _;
use ldap_parser::ldap::{AuthenticationChoice, LdapMessage, ProtocolOp};
use netsift_flow::{FlowId, FlowKey};

use super::text::{MAX_IDENTITY, MAX_SECRET, bounded, clip};
use super::{MAX_PER_FLOW, base_credential};
use crate::analyzer::RecordSink;
use crate::record::{Credential, Record, SecretState};

/// LDAP and Global Catalog ports.
pub(crate) const PORTS: [u16; 2] = [389, 3268];
/// Largest message buffered whole (binds are tiny; bigger messages are skipped unparsed).
const MAX_MESSAGE: usize = 64 * 1024;
/// Binds waiting for their response, per flow.
const MAX_PENDING: usize = 8;
/// `invalidCredentials` result code.
const INVALID_CREDENTIALS: u32 = 49;

/// Splits a byte stream into BER `SEQUENCE` messages.
#[derive(Debug, Default)]
struct BerStream {
    buf: Vec<u8>,
    /// Bytes of an oversized message still to skip.
    skip: usize,
    broken: bool,
}

/// Total length (header + content) of the BER `SEQUENCE` at the start of `buf`: `Ok(None)`
/// when more bytes are needed, `Err` when it is not a `SEQUENCE` with a definite length.
fn message_len(buf: &[u8]) -> Result<Option<usize>, ()> {
    let Some(&tag) = buf.first() else {
        return Ok(None);
    };
    if tag != 0x30 {
        return Err(());
    }
    let Some(&first) = buf.get(1) else {
        return Ok(None);
    };
    if first < 0x80 {
        return Ok(Some(2 + usize::from(first)));
    }
    let n = usize::from(first & 0x7f);
    if n == 0 || n > 4 {
        return Err(()); // Indefinite length (forbidden in LDAP) or absurd.
    }
    let Some(bytes) = buf.get(2..2 + n) else {
        return Ok(None);
    };
    let len = bytes
        .iter()
        .fold(0usize, |acc, &b| (acc << 8) | usize::from(b));
    Ok(Some(2 + n + len))
}

impl BerStream {
    /// Appends `data` and calls `f` on every complete message small enough to parse.
    fn push(&mut self, mut data: &[u8], mut f: impl FnMut(&[u8])) {
        while !data.is_empty() && !self.broken {
            if self.skip > 0 {
                let n = self.skip.min(data.len());
                self.skip -= n;
                data = data.get(n..).unwrap_or_default();
                continue;
            }
            // Never buffer more than one header plus a bounded message.
            let room = (MAX_MESSAGE + 8).saturating_sub(self.buf.len());
            let take = room.min(data.len());
            self.buf
                .extend_from_slice(data.get(..take).unwrap_or_default());
            data = data.get(take..).unwrap_or_default();
            loop {
                match message_len(&self.buf) {
                    Err(()) => {
                        self.broken = true;
                        self.buf.clear();
                        return;
                    }
                    Ok(None) => break,
                    Ok(Some(total)) if total > MAX_MESSAGE => {
                        // Oversized: drop what is buffered and skip the rest of it.
                        let have = self.buf.len().min(total);
                        self.buf.drain(..have);
                        self.skip = total - have;
                        if self.skip > 0 {
                            break;
                        }
                    }
                    Ok(Some(total)) => {
                        let Some(msg) = self.buf.get(..total) else {
                            break; // Incomplete.
                        };
                        f(msg);
                        self.buf.drain(..total);
                    }
                }
            }
        }
    }

    fn reset(&mut self) {
        // Message boundaries are lost after a gap.
        self.buf.clear();
        self.broken = true;
    }
}

/// State of one LDAP connection.
#[derive(Debug)]
pub(crate) struct LdapFlow {
    id: FlowId,
    key: FlowKey,
    client: BerStream,
    server: BerStream,
    pending: Vec<(u32, Credential)>,
    emitted: usize,
}

/// What one client message holds.
enum Bind {
    Simple {
        id: u32,
        version: u8,
        dn: String,
        password: String,
    },
    Other,
}

fn parse_client(msg: &[u8]) -> Bind {
    let Ok((_, m)) = LdapMessage::from_ber(msg) else {
        return Bind::Other;
    };
    match m.protocol_op {
        ProtocolOp::BindRequest(req) => match req.authentication {
            AuthenticationChoice::Simple(pw) if !pw.is_empty() => Bind::Simple {
                id: m.message_id.0,
                version: req.version,
                dn: clip(&req.name.0, MAX_IDENTITY),
                password: bounded(&pw, MAX_SECRET),
            },
            _ => Bind::Other,
        },
        _ => Bind::Other,
    }
}

/// `(message id, result code)` of a `BindResponse`.
fn parse_server(msg: &[u8]) -> Option<(u32, u32)> {
    let (_, m) = LdapMessage::from_ber(msg).ok()?;
    match m.protocol_op {
        ProtocolOp::BindResponse(resp) => Some((m.message_id.0, resp.result.result_code.0)),
        _ => None,
    }
}

impl LdapFlow {
    pub(crate) fn new(id: FlowId, key: FlowKey) -> Self {
        Self {
            id,
            key,
            client: BerStream::default(),
            server: BerStream::default(),
            pending: Vec::new(),
            emitted: 0,
        }
    }

    pub(crate) fn client_data(
        &mut self,
        data: &[u8],
        gap: bool,
        ts: i64,
        out: &mut dyn RecordSink,
    ) {
        if gap {
            self.client.reset();
        }
        let mut binds = Vec::new();
        self.client.push(data, |msg| {
            if let Bind::Simple {
                id,
                version,
                dn,
                password,
            } = parse_client(msg)
            {
                binds.push((id, version, dn, password));
            }
        });
        for (id, version, dn, password) in binds {
            let mut cred = base_credential(
                "ldap",
                "ldap",
                self.id,
                &self.key,
                ts,
                SecretState::Plaintext,
            );
            cred.username = Some(dn).filter(|d| !d.is_empty());
            cred.secret = Some(password);
            cred.details
                .push(("version".to_owned(), version.to_string()));
            if self.pending.len() >= MAX_PENDING {
                let (_, old) = self.pending.remove(0);
                self.emit(old, out);
            }
            self.pending.push((id, cred));
        }
    }

    pub(crate) fn server_data(&mut self, data: &[u8], gap: bool, out: &mut dyn RecordSink) {
        if gap {
            self.server.reset();
        }
        let mut results = Vec::new();
        self.server.push(data, |msg| {
            if let Some(r) = parse_server(msg) {
                results.push(r);
            }
        });
        for (id, code) in results {
            if let Some(i) = self.pending.iter().position(|(p, _)| *p == id) {
                let (_, mut cred) = self.pending.remove(i);
                let result = if code == 0 { "accepted" } else { "rejected" };
                cred.details.push(("result".to_owned(), result.to_owned()));
                if code != 0 {
                    let label = if code == INVALID_CREDENTIALS {
                        format!("{code} (invalidCredentials)")
                    } else {
                        code.to_string()
                    };
                    cred.details.push(("result_code".to_owned(), label));
                }
                self.emit(cred, out);
            }
        }
    }

    pub(crate) fn end(&mut self, out: &mut dyn RecordSink) {
        for (_, cred) in std::mem::take(&mut self.pending) {
            self.emit(cred, out);
        }
    }

    fn emit(&mut self, cred: Credential, out: &mut dyn RecordSink) {
        if self.emitted < MAX_PER_FLOW {
            self.emitted += 1;
            out.emit(Record::Credential(cred));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_lengths() {
        assert_eq!(message_len(&[]), Ok(None));
        assert_eq!(message_len(&[0x30]), Ok(None));
        assert_eq!(message_len(&[0x30, 0x05]), Ok(Some(7)));
        assert_eq!(message_len(&[0x30, 0x82, 0x01]), Ok(None));
        assert_eq!(message_len(&[0x30, 0x82, 0x01, 0x00]), Ok(Some(260)));
        assert_eq!(message_len(&[0x30, 0x80]), Err(()));
        assert_eq!(message_len(&[0x04, 0x01]), Err(()));
    }

    #[test]
    fn oversized_messages_are_skipped_without_buffering() {
        let mut s = BerStream::default();
        let mut seen = Vec::new();
        // A 70 000-byte message, then a small one, fed in pieces.
        let big_len = 70_000usize;
        let mut big = vec![0x30, 0x83];
        big.extend_from_slice(&u32::try_from(big_len).unwrap().to_be_bytes()[1..]);
        big.extend(std::iter::repeat_n(0u8, big_len));
        let small = [0x30, 0x03, 0x02, 0x01, 0x07];
        let mut all = big.clone();
        all.extend_from_slice(&small);
        for piece in all.chunks(1000) {
            s.push(piece, |m| seen.push(m.to_vec()));
            assert!(s.buf.len() <= MAX_MESSAGE + 8);
        }
        assert_eq!(seen, vec![small.to_vec()]);
    }

    #[test]
    fn garbage_breaks_the_stream() {
        let mut s = BerStream::default();
        let mut n = 0;
        s.push(b"\x16\x03\x01 TLS", |_| n += 1);
        assert!(s.broken);
        s.push(&[0x30, 0x00], |_| n += 1);
        assert_eq!(n, 0);
    }
}
