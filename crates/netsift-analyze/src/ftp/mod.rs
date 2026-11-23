//! The `ftp` analyzer (`docs/specs/ftp.md`, ADR-032): FTP control sessions on TCP port 21 as a
//! bounded transcript, the data connections announced by `PORT` / `EPRT` / `227` / `229`, and the
//! files they carry, stored as objects.
//!
//! - [`analyzer`]: the [`Analyzer`](crate::Analyzer) implementation;
//! - [`text`]: line splitting and sanitizing of the control connection.
//!
//! The data connection of a control session links the same two addresses in the common case, and
//! the engine routes flows by their unordered address pair, ports ignored (`shard_hash`): both are
//! seen by the same shard, in capture order, which lets the analyzer pair them in its own state.
//! Credentials (`USER` / `PASS`) are emitted by the `credentials` analyzer; this one keeps the
//! user name and the result of the login for the session, and the password argument of the
//! transcript flagged as secret (masked by the UI, redacted from `Debug`).

mod analyzer;
pub mod text;

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use netsift_flow::{Endpoint, FlowId};

pub use analyzer::FtpAnalyzer;

use crate::analyzer::BlobRef;

/// FTP control port (RFC 959).
pub const FTP_PORT: u16 = 21;

/// Bytes of data connections held in memory by every shard together, shared by the analyzer
/// instances of one import (the engine gives each import a fresh one, see
/// [`FtpConfig::with_fresh_budget`]).
#[derive(Debug)]
pub struct RetentionBudget {
    remaining: AtomicUsize,
}

impl RetentionBudget {
    pub fn new(bytes: usize) -> Self {
        Self {
            remaining: AtomicUsize::new(bytes),
        }
    }

    /// Takes `n` bytes; false (nothing taken) when fewer remain.
    pub fn take(&self, n: usize) -> bool {
        self.remaining
            .try_update(Ordering::AcqRel, Ordering::Acquire, |r| r.checked_sub(n))
            .is_ok()
    }

    pub fn give_back(&self, n: usize) {
        self.remaining.fetch_add(n, Ordering::AcqRel);
    }

    /// Bytes still available.
    pub fn remaining(&self) -> usize {
        self.remaining.load(Ordering::Acquire)
    }
}

/// Settings of the `ftp` analyzer.
#[derive(Debug, Clone)]
pub struct FtpConfig {
    /// Data bytes held in memory at a time, all shards together (128 MiB). Past it, transfers are
    /// counted without content (`truncated`).
    pub max_retained_bytes: usize,
    /// Largest file stored as an object (64 MiB, `docs/ARCHITECTURE.md`).
    pub object_max_bytes: usize,
    /// Control sessions followed at a time; new ones are ignored beyond. One analyzer instance
    /// applies it as is; the engine gives each shard its share (at least 16), so the memory of
    /// these states (a few tens of KiB each at worst) does not grow with the number of cores.
    pub max_controls: usize,
    /// Data connections followed at a time (shared by the shards like [`Self::max_controls`]);
    /// new ones are not paired beyond.
    pub max_data_flows: usize,
    /// Budget of [`Self::max_retained_bytes`] shared by the shards.
    pub budget: Arc<RetentionBudget>,
}

impl Default for FtpConfig {
    fn default() -> Self {
        let max_retained_bytes = 128 * 1024 * 1024;
        Self {
            max_retained_bytes,
            object_max_bytes: 64 * 1024 * 1024,
            max_controls: 4096,
            max_data_flows: 1024,
            budget: Arc::new(RetentionBudget::new(max_retained_bytes)),
        }
    }
}

impl FtpConfig {
    /// The same settings with a new budget of [`Self::max_retained_bytes`] (one per import).
    #[must_use]
    pub fn with_fresh_budget(mut self) -> Self {
        self.budget = Arc::new(RetentionBudget::new(self.max_retained_bytes));
        self
    }
}

/// A record of the `ftp` analyzer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FtpRecord {
    /// One line of a transcript (`ftp_lines`), emitted as it is read.
    Line(FtpLine),
    /// One transfer (`ftp_transfers`), emitted when its reply and its data connection are done.
    Transfer(Box<FtpTransfer>),
    /// One control session (`ftp_sessions`), emitted after its last transfer.
    Session(Box<FtpSession>),
}

/// Kind of a transcript line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineKind {
    /// Sent by the client.
    Command,
    /// Sent by the server.
    Reply,
    /// Added by the analyzer: [`NOTE_TLS`] or [`NOTE_GAP`] in the text.
    Note,
}

impl LineKind {
    /// Stored value (`ftp_lines.dir`).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Command => "c",
            Self::Reply => "s",
            Self::Note => "n",
        }
    }
}

/// Note: `AUTH TLS` accepted, the rest of the session is encrypted.
pub const NOTE_TLS: &str = "tls";
/// Note: bytes of the control connection are missing (lost segments, buffer bound).
pub const NOTE_GAP: &str = "gap";

/// One transcript line. `Debug` redacts the text of a secret line.
#[derive(Clone, PartialEq, Eq)]
pub struct FtpLine {
    /// Control flow.
    pub flow_id: FlowId,
    /// Order within the session, from 0.
    pub seq: u32,
    pub ts: i64,
    pub kind: LineKind,
    /// Command verb (upper case), or reply code with its separator (`230`, `211-`); `None` for a
    /// line without verb or code (continuation of a multi-line reply) and for notes.
    pub head: Option<String>,
    /// Argument of the command, text of the reply, or the note.
    pub text: String,
    /// The text is a password (`PASS`, `ACCT`): masked by the UI, never logged.
    pub secret: bool,
    /// The line was longer than what is kept.
    pub truncated: bool,
}

impl fmt::Debug for FtpLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FtpLine")
            .field("flow_id", &self.flow_id)
            .field("seq", &self.seq)
            .field("ts", &self.ts)
            .field("kind", &self.kind)
            .field("head", &self.head)
            .field(
                "text",
                if self.secret {
                    &"<redacted>" as &dyn fmt::Debug
                } else {
                    &self.text
                },
            )
            .field("secret", &self.secret)
            .field("truncated", &self.truncated)
            .finish()
    }
}

/// What a transfer moves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferDirection {
    /// `RETR`: from the server to the client.
    Download,
    /// `STOR`, `STOU`, `APPE`: from the client to the server.
    Upload,
    /// `LIST`, `NLST`, `MLSD`: directory listing from the server.
    Listing,
}

impl TransferDirection {
    /// Direction of a transfer command, `None` for any other verb.
    pub fn of_verb(verb: &str) -> Option<Self> {
        const VERBS: [(&str, TransferDirection); 7] = [
            ("RETR", TransferDirection::Download),
            ("STOR", TransferDirection::Upload),
            ("STOU", TransferDirection::Upload),
            ("APPE", TransferDirection::Upload),
            ("LIST", TransferDirection::Listing),
            ("NLST", TransferDirection::Listing),
            ("MLSD", TransferDirection::Listing),
        ];
        VERBS
            .iter()
            .find(|(v, _)| verb.eq_ignore_ascii_case(v))
            .map(|(_, d)| *d)
    }

    /// Stored value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Download => "download",
            Self::Upload => "upload",
            Self::Listing => "listing",
        }
    }
}

/// Who opens the data connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataMode {
    /// `PORT` / `EPRT`: the server connects to the client.
    Active,
    /// `PASV` / `EPSV`: the client connects to the server.
    Passive,
}

impl DataMode {
    /// Stored value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Passive => "passive",
        }
    }
}

/// One transfer command and what its data connection carried.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FtpTransfer {
    /// Control flow.
    pub flow_id: FlowId,
    /// Order within the session, from 0.
    pub seq: u32,
    /// Time of the command.
    pub ts: i64,
    /// Time of the final reply, or of the end of the data connection when later.
    pub end_ts: Option<i64>,
    /// Verb, upper case.
    pub command: String,
    /// Argument as sent (bounded), `None` when empty.
    pub path: Option<String>,
    pub direction: TransferDirection,
    pub mode: Option<DataMode>,
    /// Command that set the data connection up: `PASV`, `EPSV`, `PORT` or `EPRT`.
    pub mode_command: Option<&'static str>,
    /// Data connection, when one was paired.
    pub data_flow: Option<FlowId>,
    /// Final reply (`226`, `426`, `550`...), when seen.
    pub status: Option<u16>,
    pub status_text: Option<String>,
    /// Bytes carried by the data connection in the transfer direction.
    pub bytes: u64,
    /// `REST` offset accepted before the command (the content does not start at 0).
    pub restart_offset: Option<u64>,
    /// Bytes are missing from the content: lost segments, or beyond the size or memory bounds.
    pub truncated: bool,
    /// Stored content (complete file transfers only).
    pub object: Option<BlobRef>,
    /// Type detected from the stored content.
    pub mime: Option<String>,
    /// Start of a listing as sanitized text.
    pub listing: Option<String>,
}

/// One control session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FtpSession {
    /// Control flow.
    pub flow_id: FlowId,
    /// FTP client and server (whatever the orientation of the flow key).
    pub client: Endpoint,
    pub server: Endpoint,
    pub first_ts: i64,
    pub last_ts: i64,
    /// Text of the first `220` reply.
    pub banner: Option<String>,
    /// Last `USER` argument.
    pub username: Option<String>,
    /// `Some(true)` once a login is accepted (`230`), `Some(false)` when refused.
    pub login: Option<bool>,
    /// `AUTH TLS` / `AUTH SSL` accepted: the rest is encrypted.
    pub tls: bool,
    /// Lines sent by the client.
    pub commands: u64,
    /// Complete replies sent by the server.
    pub replies: u64,
    /// File transfer commands (downloads and uploads).
    pub files: u64,
    /// Listing commands.
    pub listings: u64,
    /// Data bytes of the transfers.
    pub bytes: u64,
    /// Transcript lines stored.
    pub lines: u32,
    /// Lines were dropped past the transcript bounds.
    pub transcript_truncated: bool,
    /// Gaps in the control connection.
    pub gaps: u32,
}

#[cfg(test)]
mod tests;
