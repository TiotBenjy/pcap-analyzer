//! Credentials carried by HTTP messages (emitted as [`Record::Credential`] for the Credentials
//! tab):
//!
//! - `Authorization` / `Proxy-Authorization: Basic` (RFC 7617): user and password in clear;
//! - `Authorization` / `Proxy-Authorization: NTLM` or `Negotiate` with an NTLMSSP AUTHENTICATE,
//!   paired with the CHALLENGE of the previous `WWW-Authenticate` / `Proxy-Authenticate` on the
//!   same connection: hashcat 5500 / 5600 line, as for SMB;
//! - login forms: `application/x-www-form-urlencoded` request bodies, and query strings, holding
//!   a password-like field (and usually a user-like one).
//!
//! The secrets are never logged ([`crate::Credential`]'s `Debug` redacts them).

use super::inspect::{MessageView, Role};
use crate::analyzer::RecordSink;
use crate::credentials::text::{
    MAX_IDENTITY, MAX_SECRET, base64, bounded, clip, split_word, to_hex,
};
use crate::record::{Credential, Record, SecretState};
use crate::smb::ntlmssp::{self, NtlmMessage};

/// Most credentials emitted for one connection.
const MAX_PER_CONN: usize = crate::credentials::MAX_PER_FLOW;
/// Most form fields looked at.
const MAX_FIELDS: usize = 64;

/// Authentication state of one connection.
#[derive(Debug, Default)]
pub(crate) struct AuthState {
    /// Server challenge of the last NTLM CHALLENGE, consumed by the next AUTHENTICATE.
    ntlm_challenge: Option<[u8; 8]>,
    emitted: usize,
}

impl AuthState {
    fn emit(&mut self, cred: Credential, out: &mut dyn RecordSink) {
        if self.emitted < MAX_PER_CONN {
            self.emitted += 1;
            out.emit(Record::Credential(cred));
        }
    }
}

/// Looks for credentials in a finished message.
pub(crate) fn inspect(view: &MessageView<'_>, state: &mut AuthState, out: &mut dyn RecordSink) {
    match view.role {
        Role::Response => {
            for h in view.headers {
                let name = h.name.as_str();
                let challenge_header = name.eq_ignore_ascii_case("www-authenticate")
                    || name.eq_ignore_ascii_case("proxy-authenticate");
                if challenge_header
                    && let Some(NtlmMessage::Challenge { server_challenge }) = ntlm_token(&h.value)
                {
                    state.ntlm_challenge = Some(server_challenge);
                }
            }
        }
        Role::Request => {
            for h in view.headers {
                let header = if h.name.eq_ignore_ascii_case("authorization") {
                    "Authorization"
                } else if h.name.eq_ignore_ascii_case("proxy-authorization") {
                    "Proxy-Authorization"
                } else {
                    continue;
                };
                if let Some(cred) = authorization(view, state, header, &h.value) {
                    state.emit(cred, out);
                }
            }
            for cred in forms(view) {
                state.emit(cred, out);
            }
        }
    }
}

fn base(view: &MessageView<'_>, kind: &'static str, state: SecretState) -> Credential {
    Credential {
        source_protocol: "http",
        kind,
        flow_id: Some(view.flow),
        client: Some(view.key.client),
        server: Some(view.key.server),
        ts: view.ts_ns,
        username: None,
        domain: None,
        workstation: None,
        secret_state: state,
        secret: None,
        hashcat_mode: None,
        hashcat_line: None,
        details: Vec::new(),
    }
}

/// Request context: method, host and path (the query is left out: it may hold secrets).
fn request_details(view: &MessageView<'_>) -> Vec<(String, String)> {
    let mut d = Vec::new();
    if let Some(m) = view.method {
        d.push(("method".to_owned(), clip(m, 16)));
    }
    if let Some(host) = view.header("host") {
        d.push(("host".to_owned(), clip(host, MAX_IDENTITY)));
    }
    if let Some(target) = view.target {
        let path = target.split(['?', '#']).next().unwrap_or_default();
        d.push(("path".to_owned(), clip(path, 512)));
    }
    d
}

/// NTLMSSP message of an `NTLM <token>` / `Negotiate <token>` header value.
fn ntlm_token(value: &str) -> Option<NtlmMessage> {
    let (scheme, token) = split_word(value.trim());
    if !scheme.eq_ignore_ascii_case("ntlm") && !scheme.eq_ignore_ascii_case("negotiate") {
        return None;
    }
    let token = token.split([',', ' ']).next().unwrap_or_default();
    ntlmssp::parse(&base64(token)?)
}

fn authorization(
    view: &MessageView<'_>,
    state: &mut AuthState,
    header: &str,
    value: &str,
) -> Option<Credential> {
    let (scheme, token) = split_word(value.trim());
    if scheme.eq_ignore_ascii_case("basic") {
        let decoded = base64(token)?;
        let text = bounded(&decoded, MAX_IDENTITY + MAX_SECRET + 1);
        let (user, password) = text.split_once(':')?;
        if user.is_empty() && password.is_empty() {
            return None;
        }
        let mut cred = base(view, "http-basic", SecretState::Plaintext);
        cred.username = Some(clip(user, MAX_IDENTITY)).filter(|u| !u.is_empty());
        cred.secret = Some(clip(password, MAX_SECRET));
        cred.details.push(("header".to_owned(), header.to_owned()));
        cred.details.extend(request_details(view));
        return Some(cred);
    }
    let NtlmMessage::Authenticate(auth) = ntlm_token(value)? else {
        return None;
    };
    if auth.anonymous {
        return None;
    }
    let challenge = state.ntlm_challenge.take();
    let line = challenge.and_then(|c| ntlmssp::hashcat(c, &auth));
    let mut cred = match &line {
        Some(l) => {
            let mut c = base(view, l.kind, SecretState::Recoverable);
            c.hashcat_mode = Some(l.mode);
            c.hashcat_line = Some(l.line.clone());
            c
        }
        None => base(view, "ntlm", SecretState::MetadataOnly),
    };
    cred.username = auth.user.as_deref().map(|u| clip(u, MAX_IDENTITY));
    cred.domain = auth.domain.as_deref().map(|d| clip(d, MAX_IDENTITY));
    cred.workstation = auth.workstation.as_deref().map(|w| clip(w, MAX_IDENTITY));
    cred.details.push(("header".to_owned(), header.to_owned()));
    cred.details.extend(request_details(view));
    if let Some(c) = challenge {
        cred.details
            .push(("server_challenge".to_owned(), to_hex(&c)));
    }
    Some(cred)
}

/// Login form credentials of a request: its urlencoded body, then its query string.
fn forms(view: &MessageView<'_>) -> Vec<Credential> {
    let mut found = Vec::new();
    let urlencoded = view.header("content-type").is_some_and(|ct| {
        ct.split(';').next().is_some_and(|m| {
            m.trim()
                .eq_ignore_ascii_case("application/x-www-form-urlencoded")
        })
    });
    if urlencoded && !view.body.is_empty() {
        let body = String::from_utf8_lossy(view.body);
        if let Some(c) = form_credential(view, &body, "body") {
            found.push(c);
        }
    }
    if let Some((_, query)) = view.target.and_then(|t| t.split_once('?')) {
        let query = query.split('#').next().unwrap_or_default();
        if let Some(c) = form_credential(view, query, "query") {
            found.push(c);
        }
    }
    found
}

fn form_credential(view: &MessageView<'_>, encoded: &str, source: &str) -> Option<Credential> {
    let fields: Vec<(String, String)> = encoded
        .split('&')
        .take(MAX_FIELDS)
        .filter_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            Some((url_decode(k, 128), url_decode(v, MAX_SECRET)))
        })
        .collect();
    let (secret_field, secret) = fields
        .iter()
        .find(|(k, v)| !v.is_empty() && is_secret_field(k))?;
    let user = fields
        .iter()
        .find(|(k, v)| !v.is_empty() && k != secret_field && is_user_field(k));
    let mut cred = base(view, "http-form", SecretState::Plaintext);
    cred.username = user.map(|(_, v)| clip(v, MAX_IDENTITY));
    cred.secret = Some(secret.clone());
    cred.details.push(("source".to_owned(), source.to_owned()));
    if let Some((k, _)) = user {
        cred.details.push(("user_field".to_owned(), k.clone()));
    }
    cred.details
        .push(("secret_field".to_owned(), secret_field.clone()));
    cred.details.extend(request_details(view));
    Some(cred)
}

/// Field names holding a password.
fn is_secret_field(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.contains("password")
        || n.contains("passwd")
        || n.contains("passwort")
        || n.contains("motdepasse")
        || n.contains("mot_de_passe")
        || matches!(
            n.as_str(),
            "pass" | "pwd" | "pw" | "pword" | "secret" | "passphrase" | "pin"
        )
}

/// Field names holding a user name.
fn is_user_field(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.contains("user")
        || n.contains("login")
        || n.contains("email")
        || matches!(
            n.as_str(),
            "uname"
                | "usr"
                | "account"
                | "log"
                | "name"
                | "uid"
                | "id"
                | "mail"
                | "identifiant"
                | "nickname"
        )
}

/// `application/x-www-form-urlencoded` decoding (`+` is a space, `%XX` a byte), bounded.
fn url_decode(s: &str, max: usize) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len().min(max * 4));
    let mut i = 0;
    while i < bytes.len() && out.len() < max * 4 {
        match bytes.get(i) {
            Some(b'+') => out.push(b' '),
            Some(b'%') => {
                let hex = bytes
                    .get(i + 1..i + 3)
                    .and_then(|h| std::str::from_utf8(h).ok())
                    .and_then(|h| u8::from_str_radix(h, 16).ok());
                if let Some(b) = hex {
                    out.push(b);
                    i += 2;
                } else {
                    out.push(b'%');
                }
            }
            Some(&b) => out.push(b),
            None => break,
        }
        i += 1;
    }
    bounded(&out, max)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_names() {
        for n in [
            "password",
            "user[password]",
            "Passwd",
            "pwd",
            "j_password",
            "login_password",
        ] {
            assert!(is_secret_field(n), "{n}");
        }
        for n in ["bypass", "passenger", "q", "username"] {
            assert!(!is_secret_field(n), "{n}");
        }
        for n in ["username", "login", "Email", "j_username", "uname"] {
            assert!(is_user_field(n), "{n}");
        }
    }

    #[test]
    fn url_decoding() {
        assert_eq!(url_decode("a+b%40c%2", 100), "a b@c%2");
        assert_eq!(url_decode("%C3%A9t%C3%A9", 100), "été");
        assert_eq!(url_decode("abcdef", 3), "abc");
    }
}
