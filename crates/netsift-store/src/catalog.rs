//! The catalog (`catalog.db` at the root of the data directory) lists the sessions.
//!
//! Layout of the data directory:
//!
//! ```text
//! <data_dir>/catalog.db
//! <data_dir>/sessions/<session_id>/{session.db, blobs/, thumbs/}
//! ```

use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use rusqlite::{Connection, OptionalExtension, Row, params};

use crate::error::{Result, StoreError};
use crate::id::SessionId;
use crate::migrate::migrate;
use crate::schema::CATALOG_SCHEMA;
use crate::session::{OpenMode, SESSION_DB, Session, configure_writable};
use crate::time::now_ns;

/// Catalog database file name.
pub const CATALOG_DB: &str = "catalog.db";
/// Directory holding one sub-directory per session.
pub const SESSIONS_DIR: &str = "sessions";
/// Directory under `sessions/` where deleted sessions are moved before removal.
pub const TRASH_DIR: &str = ".trash";
/// Maximum length of a session name, in bytes.
pub const MAX_NAME_LEN: usize = 256;

/// Lifecycle state of a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SessionState {
    /// Import in progress (or interrupted by a crash).
    Importing,
    /// Import finished successfully.
    Ready,
    /// Import cancelled: what was analyzed remains browsable.
    Incomplete,
    /// Import failed.
    Failed,
}

impl SessionState {
    /// Text stored in the database.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Importing => "importing",
            Self::Ready => "ready",
            Self::Incomplete => "incomplete",
            Self::Failed => "failed",
        }
    }
}

impl fmt::Display for SessionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SessionState {
    type Err = StoreError;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "importing" => Ok(Self::Importing),
            "ready" => Ok(Self::Ready),
            "incomplete" => Ok(Self::Incomplete),
            "failed" => Ok(Self::Failed),
            _ => Err(StoreError::InvalidValue {
                field: "state",
                reason: "unknown session state",
            }),
        }
    }
}

/// One catalog entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionInfo {
    pub id: SessionId,
    pub name: String,
    /// Source capture files or folders (never copied, referenced only).
    pub sources: Vec<PathBuf>,
    pub state: SessionState,
    /// Free text attached to the state (error message of a failed import, ...).
    pub state_detail: Option<String>,
    /// Wall-clock creation date, ns since the Unix epoch.
    pub created_ns: i64,
    /// Wall-clock date of the last change, ns since the Unix epoch.
    pub updated_ns: i64,
    /// Total size of the source files, in bytes.
    pub source_bytes: u64,
    /// Disk usage of the session directory, in bytes.
    pub session_bytes: u64,
}

/// Handle on the catalog. Not `Sync`: share it behind a mutex.
#[derive(Debug)]
pub struct Catalog {
    root: PathBuf,
    conn: Connection,
}

const SELECT: &str = "SELECT id, name, sources, state, state_detail, created_ns, updated_ns, \
                      source_bytes, session_bytes FROM sessions";

impl Catalog {
    /// Opens (creating if needed) the catalog of `data_dir`.
    pub fn open(data_dir: impl Into<PathBuf>) -> Result<Self> {
        let root = data_dir.into();
        let sessions = root.join(SESSIONS_DIR);
        std::fs::create_dir_all(&sessions).map_err(|e| StoreError::io(&sessions, e))?;
        let mut conn = Connection::open(root.join(CATALOG_DB))?;
        configure_writable(&conn, 4096)?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        migrate(&mut conn, &CATALOG_SCHEMA)?;
        let catalog = Self { root, conn };
        catalog.empty_trash();
        Ok(catalog)
    }

    /// Removes what an interrupted [`Catalog::delete`] left in `sessions/.trash/`
    /// (best effort: a failure is retried at the next opening).
    fn empty_trash(&self) {
        let trash = self.root.join(SESSIONS_DIR).join(TRASH_DIR);
        if let Ok(entries) = std::fs::read_dir(&trash) {
            for entry in entries.flatten() {
                let _ = std::fs::remove_dir_all(entry.path());
            }
        }
    }

    /// Root of the data directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Directory of a session (it may not exist yet).
    pub fn session_dir(&self, id: &SessionId) -> PathBuf {
        self.root.join(SESSIONS_DIR).join(id.as_str())
    }

    /// Registers a new session in state `importing` and creates its directory and empty,
    /// migrated database.
    pub fn create(
        &self,
        name: &str,
        sources: &[PathBuf],
        source_bytes: u64,
    ) -> Result<SessionInfo> {
        let name = validate_name(name)?;
        let sources_json = serde_json::to_string(sources)?;
        let now = now_ns();
        // A collision is astronomically unlikely; retry a few times rather than fail.
        for _ in 0..4 {
            let id = SessionId::generate();
            let inserted = self.conn.execute(
                "INSERT INTO sessions \
                 (id, name, sources, state, created_ns, updated_ns, source_bytes) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?6) ON CONFLICT (id) DO NOTHING",
                params![
                    id.as_str(),
                    name,
                    sources_json,
                    SessionState::Importing.as_str(),
                    now,
                    sat(source_bytes)
                ],
            )?;
            if inserted == 1 {
                if let Err(e) = Session::open(self.session_dir(&id), OpenMode::ReadWrite) {
                    // Roll back the registration; the directory is removed best effort.
                    let _ = std::fs::remove_dir_all(self.session_dir(&id));
                    self.conn
                        .execute("DELETE FROM sessions WHERE id = ?1", [id.as_str()])?;
                    return Err(e);
                }
                return self
                    .get(&id)?
                    .ok_or_else(|| StoreError::SessionNotFound(id.to_string()));
            }
        }
        Err(StoreError::InvalidValue {
            field: "id",
            reason: "could not generate a unique session id",
        })
    }

    /// Looks a session up.
    pub fn get(&self, id: &SessionId) -> Result<Option<SessionInfo>> {
        let sql = format!("{SELECT} WHERE id = ?1");
        let raw = self
            .conn
            .query_row(&sql, [id.as_str()], RawInfo::from_row)
            .optional()?;
        raw.map(RawInfo::into_info).transpose()
    }

    /// All sessions, newest first.
    pub fn list(&self) -> Result<Vec<SessionInfo>> {
        let sql = format!("{SELECT} ORDER BY created_ns DESC, id DESC");
        let mut stmt = self.conn.prepare(&sql)?;
        let raws = stmt
            .query_map([], RawInfo::from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        raws.into_iter().map(RawInfo::into_info).collect()
    }

    /// Renames a session.
    pub fn rename(&self, id: &SessionId, name: &str) -> Result<()> {
        let name = validate_name(name)?;
        self.update(
            id,
            "UPDATE sessions SET name = ?2, updated_ns = ?3 WHERE id = ?1",
            params![id.as_str(), name, now_ns()],
        )
    }

    /// Changes the state of a session, replacing its detail text.
    pub fn set_state(
        &self,
        id: &SessionId,
        state: SessionState,
        detail: Option<&str>,
    ) -> Result<()> {
        self.update(
            id,
            "UPDATE sessions SET state = ?2, state_detail = ?3, updated_ns = ?4 WHERE id = ?1",
            params![id.as_str(), state.as_str(), detail, now_ns()],
        )
    }

    /// Records the sizes of a session (sources, and the session directory on disk).
    pub fn set_sizes(&self, id: &SessionId, source_bytes: u64, session_bytes: u64) -> Result<()> {
        self.update(
            id,
            "UPDATE sessions SET source_bytes = ?2, session_bytes = ?3, updated_ns = ?4 \
             WHERE id = ?1",
            params![id.as_str(), sat(source_bytes), sat(session_bytes), now_ns()],
        )
    }

    /// Deletes a session. Its directory is first moved atomically to `sessions/.trash/<id>`
    /// (a failure leaves everything in place for a retry), then the catalog entry is removed,
    /// then the moved directory (whatever remains is cleaned at the next opening).
    /// The caller must have closed every connection to the session.
    pub fn delete(&self, id: &SessionId) -> Result<()> {
        if self.get(id)?.is_none() {
            return Err(StoreError::SessionNotFound(id.to_string()));
        }
        let dir = self.session_dir(id);
        let trash = self.root.join(SESSIONS_DIR).join(TRASH_DIR);
        std::fs::create_dir_all(&trash).map_err(|e| StoreError::io(&trash, e))?;
        let trashed = trash.join(id.as_str());
        match std::fs::rename(&dir, &trashed) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(StoreError::io(dir, e)),
        }
        self.conn
            .execute("DELETE FROM sessions WHERE id = ?1", [id.as_str()])?;
        let _ = std::fs::remove_dir_all(&trashed);
        Ok(())
    }

    /// Opens the session database of a catalog entry. Fails with
    /// [`StoreError::SessionFilesMissing`] if its directory or database has disappeared,
    /// rather than silently recreating an empty session.
    pub fn open_session(&self, id: &SessionId, mode: OpenMode) -> Result<Session> {
        if self.get(id)?.is_none() {
            return Err(StoreError::SessionNotFound(id.to_string()));
        }
        let dir = self.session_dir(id);
        let db = dir.join(SESSION_DB);
        if !db.is_file() {
            return Err(StoreError::SessionFilesMissing { path: db });
        }
        Session::open(dir, mode)
    }

    fn update(&self, id: &SessionId, sql: &str, params: &[&dyn rusqlite::ToSql]) -> Result<()> {
        match self.conn.execute(sql, params)? {
            0 => Err(StoreError::SessionNotFound(id.to_string())),
            _ => Ok(()),
        }
    }
}

/// Saturating conversion for sizes.
fn sat(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

fn validate_name(name: &str) -> Result<&str> {
    let name = name.trim();
    if name.is_empty() {
        return Err(StoreError::InvalidValue {
            field: "name",
            reason: "must not be empty",
        });
    }
    if name.len() > MAX_NAME_LEN {
        return Err(StoreError::InvalidValue {
            field: "name",
            reason: "too long",
        });
    }
    if name.chars().any(char::is_control) {
        return Err(StoreError::InvalidValue {
            field: "name",
            reason: "must not contain control characters",
        });
    }
    Ok(name)
}

/// Row as read from SQLite, before validation of the text fields.
struct RawInfo {
    id: String,
    name: String,
    sources: String,
    state: String,
    state_detail: Option<String>,
    created_ns: i64,
    updated_ns: i64,
    source_bytes: u64,
    session_bytes: u64,
}

impl RawInfo {
    fn from_row(r: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: r.get(0)?,
            name: r.get(1)?,
            sources: r.get(2)?,
            state: r.get(3)?,
            state_detail: r.get(4)?,
            created_ns: r.get(5)?,
            updated_ns: r.get(6)?,
            source_bytes: r.get(7)?,
            session_bytes: r.get(8)?,
        })
    }

    fn into_info(self) -> Result<SessionInfo> {
        Ok(SessionInfo {
            id: self.id.parse()?,
            name: self.name,
            sources: serde_json::from_str(&self.sources)?,
            state: self.state.parse()?,
            state_detail: self.state_detail,
            created_ns: self.created_ns,
            updated_ns: self.updated_ns,
            source_bytes: self.source_bytes,
            session_bytes: self.session_bytes,
        })
    }
}
