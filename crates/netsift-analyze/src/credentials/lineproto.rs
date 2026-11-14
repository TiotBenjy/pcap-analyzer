//! Line-based protocols that carry passwords: FTP (RFC 959), SMTP AUTH (RFC 4954), POP3
//! (RFC 1939, RFC 5034) and IMAP (RFC 9051).
//!
//! Recognized authentications:
//! - FTP `USER` / `PASS`; POP3 `USER` / `PASS` and `APOP`; IMAP `LOGIN`;
//! - SASL in SMTP `AUTH`, POP3 `AUTH` and IMAP `AUTHENTICATE`: `PLAIN` (RFC 4616), `LOGIN`
//!   and `CRAM-MD5` (RFC 2195, offline-recoverable: hashcat mode 16400).
//!
//! A credential waits for the server's reply to the command that completed it, which gives
//! its `result` (`accepted` / `rejected`); it is emitted without result at the end of the flow
//! when no reply was seen.

use std::fmt;

use netsift_flow::{FlowId, FlowKey};

use super::text::{MAX_IDENTITY, MAX_SECRET, base64, bounded, clip, split_word};
use super::{MAX_PER_FLOW, base_credential};
use crate::analyzer::RecordSink;
use crate::record::{Credential, Record, SecretState};

/// hashcat mode of a CRAM-MD5 challenge/response.
pub const HASHCAT_CRAM_MD5: u32 = 16400;

/// A line-based protocol, chosen by the server port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LineProto {
    Ftp,
    Smtp,
    Pop3,
    Imap,
}

impl LineProto {
    /// Protocol served on a well-known port.
    pub(crate) fn of_port(port: u16) -> Option<Self> {
        match port {
            21 => Some(Self::Ftp),
            25 | 587 | 2525 => Some(Self::Smtp),
            110 => Some(Self::Pop3),
            143 => Some(Self::Imap),
            _ => None,
        }
    }

    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Ftp => "ftp",
            Self::Smtp => "smtp",
            Self::Pop3 => "pop3",
            Self::Imap => "imap",
        }
    }

    /// Credential type (`docs/specs/credentials.md`): `ftp`, or `mail` for the others.
    const fn kind(self) -> &'static str {
        match self {
            Self::Ftp => "ftp",
            Self::Smtp | Self::Pop3 | Self::Imap => "mail",
        }
    }
}

/// SASL mechanism being exchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mech {
    Plain,
    Login,
    CramMd5,
}

impl Mech {
    fn parse(name: &str) -> Option<Self> {
        match name.to_ascii_uppercase().as_str() {
            "PLAIN" => Some(Self::Plain),
            "LOGIN" => Some(Self::Login),
            "CRAM-MD5" => Some(Self::CramMd5),
            _ => None,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Plain => "PLAIN",
            Self::Login => "LOGIN",
            Self::CramMd5 => "CRAM-MD5",
        }
    }
}

/// A SASL exchange in progress. `Debug` shows the mechanism only.
struct Sasl {
    mech: Mech,
    /// IMAP tag of the `AUTHENTICATE` command.
    tag: Option<String>,
    /// `LOGIN`: user name already received.
    user: Option<String>,
    /// `CRAM-MD5`: base64 challenge sent by the server.
    challenge: Option<String>,
}

/// State of one connection. `Debug` shows no identity nor secret.
pub(crate) struct LineFlow {
    proto: LineProto,
    id: FlowId,
    key: FlowKey,
    /// FTP / POP3 `USER` argument.
    user: Option<String>,
    sasl: Option<Sasl>,
    /// Credential waiting for the server's reply, and the IMAP tag of its command.
    pending: Option<(Credential, Option<String>)>,
    emitted: usize,
}

impl fmt::Debug for Sasl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sasl")
            .field("mech", &self.mech)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for LineFlow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LineFlow")
            .field("proto", &self.proto)
            .field("id", &self.id)
            .field("sasl", &self.sasl)
            .field("pending", &self.pending.is_some())
            .field("emitted", &self.emitted)
            .finish_non_exhaustive()
    }
}

impl LineFlow {
    pub(crate) fn new(proto: LineProto, id: FlowId, key: FlowKey) -> Self {
        Self {
            proto,
            id,
            key,
            user: None,
            sasl: None,
            pending: None,
            emitted: 0,
        }
    }

    /// One complete line sent by the client.
    pub(crate) fn client_line(&mut self, line: &[u8], ts: i64, out: &mut dyn RecordSink) {
        let text = bounded(line, super::text::MAX_LINE);
        let text = text.trim();
        if let Some(sasl) = self.sasl.take() {
            self.sasl_response(sasl, text, ts, out);
            return;
        }
        match self.proto {
            LineProto::Ftp => self.ftp_command(text, ts, out),
            LineProto::Smtp => self.smtp_command(text, ts, out),
            LineProto::Pop3 => self.pop3_command(text, ts, out),
            LineProto::Imap => self.imap_command(text, ts, out),
        }
    }

    /// One complete line sent by the server.
    pub(crate) fn server_line(&mut self, line: &[u8], out: &mut dyn RecordSink) {
        let text = bounded(line, super::text::MAX_LINE);
        let text = text.trim_end();
        if self.sasl.is_some() {
            if let Some(challenge) = self.challenge(text) {
                // Only a well-formed base64 challenge goes into a hashcat line.
                if let Some(sasl) = self.sasl.as_mut()
                    && sasl.mech == Mech::CramMd5
                    && challenge.len() <= MAX_SECRET
                    && base64(challenge).is_some()
                {
                    sasl.challenge = Some(challenge.to_owned());
                }
                return;
            }
            let tag = self.sasl.as_ref().and_then(|s| s.tag.clone());
            if self.outcome(text, tag.as_deref()).is_some() {
                // The exchange ended before the client sent its secret (refused mechanism...).
                self.sasl = None;
            }
            return;
        }
        let Some((_, tag)) = &self.pending else {
            return;
        };
        if let Some(accepted) = self.outcome(text, tag.as_deref())
            && let Some((mut cred, _)) = self.pending.take()
        {
            let result = if accepted { "accepted" } else { "rejected" };
            cred.details.push(("result".to_owned(), result.to_owned()));
            self.emit(cred, out);
        }
    }

    /// End of the flow: a credential still waiting for its reply goes without result.
    pub(crate) fn end(&mut self, out: &mut dyn RecordSink) {
        if let Some((cred, _)) = self.pending.take() {
            self.emit(cred, out);
        }
    }

    fn emit(&mut self, cred: Credential, out: &mut dyn RecordSink) {
        if self.emitted < MAX_PER_FLOW {
            self.emitted += 1;
            out.emit(Record::Credential(cred));
        }
    }

    /// Queues a new credential; one still waiting (no reply seen) is emitted first.
    fn hold(&mut self, cred: Credential, tag: Option<String>, out: &mut dyn RecordSink) {
        if let Some((old, _)) = self.pending.take() {
            self.emit(old, out);
        }
        self.pending = Some((cred, tag));
    }

    fn credential(&self, ts: i64, state: SecretState) -> Credential {
        base_credential(
            self.proto.name(),
            self.proto.kind(),
            self.id,
            &self.key,
            ts,
            state,
        )
    }

    /// A plain-text credential (`secret` in clear), with its mechanism for mail protocols.
    fn plaintext(&self, ts: i64, user: Option<String>, secret: &str, mech: &str) -> Credential {
        let mut cred = self.credential(ts, SecretState::Plaintext);
        cred.username = user.filter(|u| !u.is_empty());
        cred.secret = Some(clip(secret, MAX_SECRET));
        if self.proto != LineProto::Ftp {
            cred.details.push(("mechanism".to_owned(), mech.to_owned()));
        }
        cred
    }

    fn ftp_command(&mut self, text: &str, ts: i64, out: &mut dyn RecordSink) {
        let (verb, arg) = split_word(text);
        if verb.eq_ignore_ascii_case("USER") {
            self.user = Some(clip(arg, MAX_IDENTITY));
        } else if verb.eq_ignore_ascii_case("PASS") {
            let user = self.user.clone();
            let anonymous = user.as_deref().is_some_and(|u| {
                u.eq_ignore_ascii_case("anonymous") || u.eq_ignore_ascii_case("ftp")
            });
            let mut cred = self.plaintext(ts, user, arg, "USER/PASS");
            if anonymous {
                cred.details
                    .push(("anonymous".to_owned(), "true".to_owned()));
            }
            self.hold(cred, None, out);
        }
    }

    fn smtp_command(&mut self, text: &str, ts: i64, out: &mut dyn RecordSink) {
        let (verb, arg) = split_word(text);
        if verb.eq_ignore_ascii_case("AUTH") {
            self.start_sasl(arg, None, ts, out);
        }
    }

    fn pop3_command(&mut self, text: &str, ts: i64, out: &mut dyn RecordSink) {
        let (verb, arg) = split_word(text);
        if verb.eq_ignore_ascii_case("USER") {
            self.user = Some(clip(arg, MAX_IDENTITY));
        } else if verb.eq_ignore_ascii_case("PASS") {
            let cred = self.plaintext(ts, self.user.clone(), arg, "USER/PASS");
            self.hold(cred, None, out);
        } else if verb.eq_ignore_ascii_case("APOP") {
            // `APOP name digest`: MD5 of the server timestamp and the password.
            let (name, digest) = split_word(arg);
            if !name.is_empty() && !digest.is_empty() {
                let mut cred = self.credential(ts, SecretState::Recoverable);
                cred.username = Some(clip(name, MAX_IDENTITY));
                cred.details
                    .push(("mechanism".to_owned(), "APOP".to_owned()));
                self.hold(cred, None, out);
            }
        } else if verb.eq_ignore_ascii_case("AUTH") {
            self.start_sasl(arg, None, ts, out);
        }
    }

    fn imap_command(&mut self, text: &str, ts: i64, out: &mut dyn RecordSink) {
        let (tag, rest) = split_word(text);
        let (verb, arg) = split_word(rest);
        if tag.is_empty() {
            return;
        }
        if verb.eq_ignore_ascii_case("LOGIN") {
            let mut args = imap_strings(arg);
            if let (Some(user), Some(pass)) = (args.next(), args.next()) {
                let cred = self.plaintext(ts, Some(clip(&user, MAX_IDENTITY)), &pass, "LOGIN");
                self.hold(cred, Some(clip(tag, 64)), out);
            }
        } else if verb.eq_ignore_ascii_case("AUTHENTICATE") {
            self.start_sasl(arg, Some(clip(tag, 64)), ts, out);
        }
    }

    /// `AUTH <mechanism> [initial-response]`.
    fn start_sasl(&mut self, arg: &str, tag: Option<String>, ts: i64, out: &mut dyn RecordSink) {
        let (name, initial) = split_word(arg);
        let Some(mech) = Mech::parse(name) else {
            return;
        };
        let sasl = Sasl {
            mech,
            tag,
            user: None,
            challenge: None,
        };
        // `=` is an empty initial response (RFC 4954).
        if initial.is_empty() || initial == "=" || mech == Mech::CramMd5 {
            self.sasl = Some(sasl);
        } else {
            self.sasl_response(sasl, initial, ts, out);
        }
    }

    /// One client response of a SASL exchange.
    fn sasl_response(&mut self, mut sasl: Sasl, text: &str, ts: i64, out: &mut dyn RecordSink) {
        if text == "*" {
            return; // Cancelled by the client.
        }
        let Some(decoded) = base64(text) else {
            return;
        };
        match sasl.mech {
            Mech::Plain => {
                // authzid NUL authcid NUL passwd
                let mut parts = decoded.splitn(3, |&b| b == 0);
                let (Some(authzid), Some(authcid), Some(passwd)) =
                    (parts.next(), parts.next(), parts.next())
                else {
                    return;
                };
                let secret = bounded(passwd, MAX_SECRET);
                let mut cred = self.plaintext(
                    ts,
                    Some(bounded(authcid, MAX_IDENTITY)),
                    &secret,
                    sasl.mech.label(),
                );
                if !authzid.is_empty() {
                    cred.details
                        .push(("authzid".to_owned(), bounded(authzid, MAX_IDENTITY)));
                }
                self.hold(cred, sasl.tag, out);
            }
            Mech::Login => {
                if sasl.user.is_none() {
                    sasl.user = Some(bounded(&decoded, MAX_IDENTITY));
                    self.sasl = Some(sasl);
                } else {
                    let secret = bounded(&decoded, MAX_SECRET);
                    let cred = self.plaintext(ts, sasl.user.take(), &secret, sasl.mech.label());
                    self.hold(cred, sasl.tag, out);
                }
            }
            Mech::CramMd5 => {
                // `user SP hex-digest`, keyed with the password over the challenge.
                // Without the separator the response is malformed: no user name is taken from it
                // (it would hold the digest).
                let response = bounded(&decoded, MAX_IDENTITY + 64);
                let user = response.rsplit_once(' ').map(|(u, _)| u);
                let mut cred = self.credential(ts, SecretState::Recoverable);
                cred.username = user
                    .map(|u| clip(u, MAX_IDENTITY))
                    .filter(|u| !u.is_empty());
                cred.details
                    .push(("mechanism".to_owned(), sasl.mech.label().to_owned()));
                if let Some(challenge) = &sasl.challenge {
                    cred.hashcat_mode = Some(HASHCAT_CRAM_MD5);
                    cred.hashcat_line = Some(format!("$cram_md5${challenge}${}", text.trim()));
                }
                self.hold(cred, sasl.tag, out);
            }
        }
    }

    /// The text of a SASL server challenge line, if `text` is one.
    fn challenge<'t>(&self, text: &'t str) -> Option<&'t str> {
        match self.proto {
            LineProto::Smtp => text
                .strip_prefix("334")
                .filter(|r| r.is_empty() || r.starts_with(' '))
                .map(str::trim),
            LineProto::Pop3 | LineProto::Imap => text
                .strip_prefix('+')
                .filter(|r| r.is_empty() || r.starts_with(' '))
                .map(str::trim),
            LineProto::Ftp => None,
        }
    }

    /// `Some(accepted)` when `text` is the final reply to an authentication command.
    fn outcome(&self, text: &str, tag: Option<&str>) -> Option<bool> {
        match self.proto {
            LineProto::Ftp | LineProto::Smtp => {
                let code = text.get(..3)?;
                if !code.bytes().all(|b| b.is_ascii_digit())
                    || text.as_bytes().get(3) == Some(&b'-')
                {
                    return None; // Not a reply, or a continuation line.
                }
                match code.as_bytes().first()? {
                    b'2' => Some(true),
                    b'4' | b'5' => Some(false),
                    _ => None,
                }
            }
            LineProto::Pop3 => {
                if text.starts_with("+OK") {
                    Some(true)
                } else if text.starts_with("-ERR") {
                    Some(false)
                } else {
                    None
                }
            }
            LineProto::Imap => {
                let (t, rest) = split_word(text);
                if tag.is_none_or(|tag| t != tag) {
                    return None;
                }
                let (status, _) = split_word(rest);
                match status.to_ascii_uppercase().as_str() {
                    "OK" => Some(true),
                    "NO" | "BAD" => Some(false),
                    _ => None,
                }
            }
        }
    }
}

/// IMAP `astring` arguments: atoms or quoted strings (`\` escapes). Literals (`{n}`) are not
/// followed: they end the iteration.
fn imap_strings(text: &str) -> impl Iterator<Item = String> + '_ {
    let mut rest = text.trim_start();
    std::iter::from_fn(move || {
        if rest.is_empty() || rest.starts_with('{') {
            return None;
        }
        let mut value = String::new();
        if let Some(quoted) = rest.strip_prefix('"') {
            let mut chars = quoted.char_indices();
            let mut end = None;
            while let Some((i, c)) = chars.next() {
                match c {
                    '\\' => {
                        if let Some((_, escaped)) = chars.next() {
                            value.push(escaped);
                        }
                    }
                    '"' => {
                        end = Some(i + 1);
                        break;
                    }
                    c => value.push(c),
                }
            }
            rest = quoted.get(end?..).unwrap_or_default().trim_start();
        } else {
            let (word, tail) = split_word(rest);
            value.push_str(word);
            rest = tail;
        }
        Some(value)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imap_arguments() {
        let v: Vec<String> = imap_strings(r#""al ice" "p\"w\\d" extra"#).collect();
        assert_eq!(v, vec!["al ice", "p\"w\\d", "extra"]);
        let v: Vec<String> = imap_strings("bob secret").collect();
        assert_eq!(v, vec!["bob", "secret"]);
        assert_eq!(imap_strings("{5}").count(), 0);
        assert_eq!(imap_strings(r#""unterminated"#).count(), 0);
    }
}
