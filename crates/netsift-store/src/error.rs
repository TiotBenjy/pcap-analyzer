//! Error type of the crate.

use std::path::PathBuf;

/// Errors returned by the store.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("I/O error on {}: {source}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error(
        "database schema contains migration {version}, unknown to this build \
         (created by a newer NetSift?)"
    )]
    SchemaTooNew { version: u32 },
    #[error(
        "database schema is out of date (migration {version} pending); open it read-write or \
         upgrading first"
    )]
    SchemaOutdated { version: u32 },
    #[error("migration {version} ({name}) failed: {source}")]
    Migration {
        version: u32,
        name: &'static str,
        #[source]
        source: rusqlite::Error,
    },
    #[error("could not upgrade the session schema: {0}")]
    UpgradeFailed(#[source] Box<StoreError>),
    #[error("not a NetSift {expected} database")]
    ForeignDatabase { expected: &'static str },
    #[error("session not found: {0}")]
    SessionNotFound(String),
    #[error("session files are missing: {}", path.display())]
    SessionFilesMissing { path: PathBuf },
    #[error("session already contains imported data; import into a new session")]
    SessionNotEmpty,
    #[error("invalid session id")]
    InvalidSessionId,
    #[error("invalid pagination cursor")]
    InvalidCursor,
    #[error("invalid value for {field}: {reason}")]
    InvalidValue {
        field: &'static str,
        reason: &'static str,
    },
    #[error("the writer thread has stopped")]
    WriterClosed,
    #[error("the writer thread panicked")]
    WriterPanicked,
}

impl StoreError {
    pub(crate) fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }
}

/// Result alias of the crate.
pub type Result<T, E = StoreError> = std::result::Result<T, E>;
