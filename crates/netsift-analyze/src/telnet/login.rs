//! Login detection of a Telnet session: user name and password typed at the server's prompts,
//! emitted as [`Credential`]s once the following output tells whether they were accepted.
//!
//! The prompt is the server's current (unfinished) line when the client starts typing a line.
//! The tracker sees the tokens of the transcript after echo merging, so an absorbed echo never
//! reaches the server line.

use std::fmt;

use netsift_flow::{FlowId, FlowKey};

use super::transcript::Token;
use crate::analyzer::RecordSink;
use crate::credentials::text::{MAX_IDENTITY, MAX_SECRET};
use crate::credentials::{MAX_PER_FLOW, base_credential};
use crate::record::{Credential, Record, SecretState};

/// Server line kept for prompt detection (its end only), in bytes.
const MAX_SERVER_LINE: usize = 256;

/// Outcome of a login attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginResult {
    Accepted,
    Rejected,
}

impl LoginResult {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
        }
    }
}

/// What the client is typing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Field {
    /// Not at a login prompt.
    Other,
    User,
    Password,
}

/// Kind of a server prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Prompt {
    User,
    Password,
    Shell,
    Other,
}

/// Endings of a user name prompt (lower case).
const USER_PROMPTS: [&str; 5] = ["login:", "username:", "user name:", "user:", "login as:"];
/// Words of a server line that rejects a login (lower case).
const REJECTED: [&str; 6] = [
    "incorrect",
    "failed",
    "failure",
    "invalid",
    "denied",
    "bad password",
];

/// Classifies the server's current line, read as a prompt.
fn prompt(line: &[u8]) -> Prompt {
    let text = String::from_utf8_lossy(line).to_ascii_lowercase();
    let text = text.trim_end();
    if USER_PROMPTS.iter().any(|p| text.ends_with(p)) {
        return Prompt::User;
    }
    if text.ends_with(':')
        && ["password", "passwd", "passcode"]
            .iter()
            .any(|p| text.contains(p))
    {
        return Prompt::Password;
    }
    if text.ends_with(['$', '#', '>', '%']) {
        return Prompt::Shell;
    }
    Prompt::Other
}

/// Result announced by a complete server line, if any.
fn outcome(line: &[u8]) -> Option<LoginResult> {
    let text = String::from_utf8_lossy(line).to_ascii_lowercase();
    if REJECTED.iter().any(|w| text.contains(w)) {
        return Some(LoginResult::Rejected);
    }
    if text.contains("last login") || text.contains("welcome") {
        return Some(LoginResult::Accepted);
    }
    None
}

/// Login state of one session. `Debug` shows no input, name nor secret.
pub(crate) struct Login {
    id: FlowId,
    /// Oriented key (client first).
    key: FlowKey,
    server_line: Vec<u8>,
    field: Field,
    /// The client started typing the current line.
    typing: bool,
    input: Vec<u8>,
    user: Option<String>,
    pending: Option<Credential>,
    emitted: usize,
    /// Passwords typed.
    pub(crate) attempts: u32,
    pub(crate) accepted_user: Option<String>,
    /// User name of the last attempt.
    pub(crate) last_user: Option<String>,
    pub(crate) any_accepted: bool,
    pub(crate) any_rejected: bool,
}

impl fmt::Debug for Login {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Login")
            .field("id", &self.id)
            .field("field", &self.field)
            .field("pending", &self.pending.is_some())
            .field("attempts", &self.attempts)
            .finish_non_exhaustive()
    }
}

impl Login {
    pub(crate) fn new(id: FlowId, key: FlowKey) -> Self {
        Self {
            id,
            key,
            server_line: Vec::new(),
            field: Field::Other,
            typing: false,
            input: Vec::new(),
            user: None,
            pending: None,
            emitted: 0,
            attempts: 0,
            accepted_user: None,
            last_user: None,
            any_accepted: false,
            any_rejected: false,
        }
    }

    /// Bytes are missing: the line being typed is dropped.
    pub(crate) fn reset(&mut self) {
        self.server_line.clear();
        self.field = Field::Other;
        self.typing = false;
        self.input.clear();
    }

    /// The client typed `token`; returns `true` when it belongs to a password (secret).
    pub(crate) fn client(
        &mut self,
        token: Token,
        ts: i64,
        env_user: Option<&str>,
        out: &mut dyn RecordSink,
    ) -> bool {
        if !self.typing {
            self.typing = true;
            let p = prompt(&self.server_line);
            if self.pending.is_some() {
                match p {
                    Prompt::User | Prompt::Password => self.resolve(LoginResult::Rejected, out),
                    Prompt::Shell => self.resolve(LoginResult::Accepted, out),
                    Prompt::Other => {}
                }
            }
            self.field = match p {
                Prompt::User => Field::User,
                Prompt::Password => Field::Password,
                Prompt::Shell | Prompt::Other => Field::Other,
            };
        }
        let secret = self.field == Field::Password;
        match token {
            Token::Char(c) => {
                let max = if secret { MAX_SECRET } else { MAX_IDENTITY };
                if self.field != Field::Other && self.input.len() < max {
                    self.input.push(c);
                }
                secret
            }
            Token::Erase => {
                self.input.pop();
                false
            }
            Token::EraseLine | Token::EraseWord => {
                self.input.clear();
                false
            }
            Token::Newline => {
                self.end_of_input(ts, env_user, out);
                false
            }
        }
    }

    /// The server sent `token` (not an absorbed echo).
    pub(crate) fn server(&mut self, token: Token, out: &mut dyn RecordSink) {
        match token {
            Token::Char(c) => {
                if self.server_line.len() >= MAX_SERVER_LINE {
                    self.server_line.drain(..MAX_SERVER_LINE / 2);
                }
                self.server_line.push(c);
            }
            Token::Erase => {
                self.server_line.pop();
            }
            Token::EraseLine | Token::EraseWord => {}
            Token::Newline => {
                if self.pending.is_some()
                    && let Some(result) = outcome(&self.server_line)
                {
                    self.resolve(result, out);
                }
                self.server_line.clear();
            }
        }
    }

    fn end_of_input(&mut self, ts: i64, env_user: Option<&str>, out: &mut dyn RecordSink) {
        let value = String::from_utf8_lossy(&self.input).into_owned();
        match self.field {
            Field::User => {
                let name = value.trim();
                self.user = (!name.is_empty()).then(|| name.to_owned());
            }
            Field::Password if !value.is_empty() => {
                self.attempts = self.attempts.saturating_add(1);
                let mut cred = base_credential(
                    "telnet",
                    "telnet",
                    self.id,
                    &self.key,
                    ts,
                    SecretState::Plaintext,
                );
                cred.username = self.user.take().or_else(|| env_user.map(str::to_owned));
                cred.secret = Some(value);
                self.last_user.clone_from(&cred.username);
                if let Some(old) = self.pending.replace(cred) {
                    self.emit(old, out);
                }
            }
            Field::Password | Field::Other => {}
        }
        self.input.clear();
        self.typing = false;
        self.field = Field::Other;
        // The server's next output starts a new prompt.
        self.server_line.clear();
    }

    fn resolve(&mut self, result: LoginResult, out: &mut dyn RecordSink) {
        let Some(mut cred) = self.pending.take() else {
            return;
        };
        match result {
            LoginResult::Accepted => {
                self.any_accepted = true;
                if self.accepted_user.is_none() {
                    self.accepted_user.clone_from(&cred.username);
                }
            }
            LoginResult::Rejected => self.any_rejected = true,
        }
        cred.details
            .push(("result".to_owned(), result.as_str().to_owned()));
        self.emit(cred, out);
    }

    fn emit(&mut self, cred: Credential, out: &mut dyn RecordSink) {
        if self.emitted < MAX_PER_FLOW {
            self.emitted += 1;
            out.emit(Record::Credential(cred));
        }
    }

    /// End of the flow: an attempt without result goes as is.
    pub(crate) fn end(&mut self, out: &mut dyn RecordSink) {
        if let Some(cred) = self.pending.take() {
            self.emit(cred, out);
        }
    }

    /// Overall result: accepted if one attempt was, else rejected if one was.
    pub(crate) fn result(&self) -> Option<LoginResult> {
        if self.any_accepted {
            Some(LoginResult::Accepted)
        } else if self.any_rejected {
            Some(LoginResult::Rejected)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prompts() {
        assert_eq!(prompt(b"login: "), Prompt::User);
        assert_eq!(prompt(b"OpenBSD (oof)\nUsername:"), Prompt::User);
        assert_eq!(prompt(b"Password:"), Prompt::Password);
        assert_eq!(prompt(b"jdoe@host's password: "), Prompt::Password);
        assert_eq!(prompt(b"Enter PASSCODE:"), Prompt::Password);
        assert_eq!(prompt(b"[jdoe@host ~]$ "), Prompt::Shell);
        assert_eq!(prompt(b"Router#"), Prompt::Shell);
        assert_eq!(prompt(b"Press any key"), Prompt::Other);
        assert_eq!(prompt(b""), Prompt::Other);
    }

    #[test]
    fn outcomes() {
        assert_eq!(outcome(b"Login incorrect"), Some(LoginResult::Rejected));
        assert_eq!(
            outcome(b"% Authentication failed"),
            Some(LoginResult::Rejected)
        );
        assert_eq!(
            outcome(b"Last login: Sat Nov 27 20:11:43"),
            Some(LoginResult::Accepted)
        );
        assert_eq!(outcome(b"Welcome to OpenBSD"), Some(LoginResult::Accepted));
        assert_eq!(outcome(b"OpenBSD 2.6"), None);
    }
}
