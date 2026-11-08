//! A session directory: `session.db` (SQLite, WAL) plus `blobs/` and `thumbs/`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use rusqlite::{Connection, OpenFlags, Transaction, params};

use crate::error::{Result, StoreError};
use crate::migrate::{MigrationSet, check_current, migrate, migrate_with};
use crate::query::get_meta;
use crate::schema::SESSION_SCHEMA;

/// Database file name inside a session directory.
pub const SESSION_DB: &str = "session.db";
/// Directory of extracted objects (SHA-256 addressed).
pub const BLOBS_DIR: &str = "blobs";
/// Directory of generated thumbnails.
pub const THUMBS_DIR: &str = "thumbs";
/// Page size of session databases, fixed before the first table is created.
pub const PAGE_SIZE: u32 = 8192;
/// How long a connection waits on a lock before returning `SQLITE_BUSY`.
pub const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
/// How long the upgrade of an older session waits for the write lock (another opening upgrading
/// it, or a long transaction) before giving up with [`StoreError::SessionBusy`].
pub const UPGRADE_BUSY_TIMEOUT: Duration = Duration::from_secs(30);
/// `meta` key listing the tables created by migrations applied after the import (sorted,
/// comma-separated): they exist but their analyzer never ran on this session (ADR-013).
pub const TABLES_ADDED_AFTER_IMPORT: &str = "schema.tables_added_after_import";

/// How a session database is opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenMode {
    /// Bulk import by the single writer: creates the directory if needed, migrates,
    /// `synchronous=NORMAL` and a larger page cache. Refused with
    /// [`StoreError::SessionNotEmpty`] when the session already holds imported data, since
    /// additive upserts would count it twice.
    Import,
    /// Read-write outside import (rename metadata, upgrades): migrates, `synchronous=FULL`.
    ReadWrite,
    /// Read-only access: never writes, requires an up-to-date schema. The API uses
    /// [`Session::open_upgrading`] for finished sessions, which yields this mode too.
    ReadOnly,
}

/// Whether opening a finished session may write to it ([`Session::open_finished`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Upgrade {
    /// Apply what the session lacks (pending migrations), then open it read-only.
    Apply,
    /// Never write: a session that needs it is refused with [`StoreError::UpgradeNeeded`]
    /// (read-only server).
    Refuse,
}

/// An opened session.
#[derive(Debug)]
pub struct Session {
    dir: PathBuf,
    conn: Connection,
    mode: OpenMode,
}

impl Session {
    /// Opens (and in write modes creates and migrates) the session stored in `dir`.
    pub fn open(dir: impl Into<PathBuf>, mode: OpenMode) -> Result<Self> {
        let dir = dir.into();
        let db_path = dir.join(SESSION_DB);
        let conn = match mode {
            OpenMode::Import | OpenMode::ReadWrite => {
                for sub in [dir.clone(), dir.join(BLOBS_DIR), dir.join(THUMBS_DIR)] {
                    std::fs::create_dir_all(&sub).map_err(|e| StoreError::io(&sub, e))?;
                }
                let mut conn = Connection::open(&db_path)?;
                configure_writable(&conn, PAGE_SIZE)?;
                let sync = if mode == OpenMode::Import {
                    "NORMAL"
                } else {
                    "FULL"
                };
                conn.pragma_update(None, "synchronous", sync)?;
                if mode == OpenMode::Import {
                    // Negative value = KiB: 64 MiB of page cache for the writer.
                    conn.pragma_update(None, "cache_size", -65_536)?;
                    conn.pragma_update(None, "temp_store", "MEMORY")?;
                }
                migrate_session(&mut conn, &SESSION_SCHEMA)?;
                if mode == OpenMode::Import {
                    if has_imported_data(&conn)? {
                        return Err(StoreError::SessionNotEmpty);
                    }
                    // The import about to run fills every table of the current schema.
                    conn.execute(
                        "DELETE FROM meta WHERE key = ?1",
                        [TABLES_ADDED_AFTER_IMPORT],
                    )?;
                }
                conn
            }
            OpenMode::ReadOnly => {
                if !db_path.is_file() {
                    return Err(StoreError::io(
                        &db_path,
                        std::io::Error::from(std::io::ErrorKind::NotFound),
                    ));
                }
                let conn = open_read_only(&db_path)?;
                check_current(&conn, &SESSION_SCHEMA)?;
                conn
            }
        };
        Ok(Self { dir, conn, mode })
    }

    /// Opens a finished session (`ready` or `incomplete`) read-only, first applying the
    /// migrations it lacks when it was created by an older build (ADR-013). Same as
    /// [`Session::open_finished`] with [`Upgrade::Apply`].
    pub fn open_upgrading(dir: impl Into<PathBuf>) -> Result<Self> {
        Self::open_finished(dir, Upgrade::Apply)
    }

    /// Opens a finished session (`ready` or `incomplete`) read-only. When it needs writing first
    /// (see `write_needed`: today, migrations added since its import), `upgrade` decides: apply
    /// them, recording the tables they create under [`TABLES_ADDED_AFTER_IMPORT`], or refuse with
    /// [`StoreError::UpgradeNeeded`].
    ///
    /// The upgrade is serialized (one `BEGIN IMMEDIATE` transaction per migration) and
    /// idempotent, so concurrent openings are safe. A schema newer than this build is refused
    /// with [`StoreError::SchemaTooNew`]; a write lock not obtained within
    /// [`UPGRADE_BUSY_TIMEOUT`] gives [`StoreError::SessionBusy`]; any other failure of the
    /// upgrade is [`StoreError::UpgradeFailed`]. Never call it on a session being imported.
    pub fn open_finished(dir: impl Into<PathBuf>, upgrade: Upgrade) -> Result<Self> {
        Self::open_finished_with(dir.into(), &SESSION_SCHEMA, upgrade)
    }

    fn open_finished_with(dir: PathBuf, set: &MigrationSet, policy: Upgrade) -> Result<Self> {
        let db_path = dir.join(SESSION_DB);
        if !db_path.is_file() {
            return Err(StoreError::io(
                &db_path,
                std::io::Error::from(std::io::ErrorKind::NotFound),
            ));
        }
        let conn = open_read_only(&db_path)?;
        let needed = write_needed(&conn, set)?;
        // A read-only server never writes: pending end-of-import steps wait (the session is
        // readable without them, ADR-014); only a pending migration makes it unreadable.
        if !needed.any() || (policy == Upgrade::Refuse && !needed.migrations) {
            return Ok(Self {
                dir,
                conn,
                mode: OpenMode::ReadOnly,
            });
        }
        drop(conn);
        if policy == Upgrade::Refuse {
            return Err(StoreError::UpgradeNeeded);
        }
        upgrade(&db_path, set).map_err(|e| match e {
            e @ StoreError::SchemaTooNew { .. } => e,
            e if is_busy(&e) => StoreError::SessionBusy,
            other => StoreError::UpgradeFailed(Box::new(other)),
        })?;
        let conn = open_read_only(&db_path)?;
        check_current(&conn, set)?;
        Ok(Self {
            dir,
            conn,
            mode: OpenMode::ReadOnly,
        })
    }

    /// Session directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Path of `session.db`.
    pub fn db_path(&self) -> PathBuf {
        self.dir.join(SESSION_DB)
    }

    /// Directory of extracted objects.
    pub fn blobs_dir(&self) -> PathBuf {
        self.dir.join(BLOBS_DIR)
    }

    /// Path of the blob whose SHA-256 is `sha256_hex` (see [`blob_relpath`]), `None` when the
    /// digest is malformed. The file may not exist.
    pub fn blob_path(&self, sha256_hex: &str) -> Option<PathBuf> {
        blob_relpath(sha256_hex).map(|rel| self.blobs_dir().join(rel))
    }

    /// Directory of thumbnails.
    pub fn thumbs_dir(&self) -> PathBuf {
        self.dir.join(THUMBS_DIR)
    }

    /// Mode the session was opened with.
    pub fn mode(&self) -> OpenMode {
        self.mode
    }

    /// Underlying connection, for queries (see [`crate::query`]).
    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    /// Mutable connection, for explicit transactions.
    pub fn conn_mut(&mut self) -> &mut Connection {
        &mut self.conn
    }

    /// Consumes the session and returns its connection (used by the writer thread).
    pub fn into_conn(self) -> Connection {
        self.conn
    }
}

/// Location of a blob inside `blobs/`: `<first two hex digits>/<64 hex digits>`. `None` unless
/// `sha256_hex` is exactly 64 lower-case hexadecimal digits (never a path traversal).
pub fn blob_relpath(sha256_hex: &str) -> Option<PathBuf> {
    let valid = sha256_hex.len() == 64
        && sha256_hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    let prefix = sha256_hex.get(..2).filter(|_| valid)?;
    Some(Path::new(prefix).join(sha256_hex))
}

/// Tables created after the import ([`TABLES_ADDED_AFTER_IMPORT`]): empty because their
/// analyzer did not run, not because it found nothing.
pub fn tables_added_after_import(conn: &Connection) -> Result<BTreeSet<String>> {
    Ok(get_meta(conn, TABLES_ADDED_AFTER_IMPORT)?
        .map(|v| {
            v.split(',')
                .filter(|t| !t.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default())
}

/// Applies the pending migrations of a session database. On a database that already had a
/// schema (an existing session), the tables they create are recorded as added after the import.
fn migrate_session(conn: &mut Connection, set: &MigrationSet) -> Result<Vec<u32>> {
    if has_schema(conn)? {
        migrate_with(conn, set, record_added_tables)
    } else {
        migrate(conn, set)
    }
}

/// What a finished session needs written ([`write_needed`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WriteNeeded {
    /// Migrations added since its import: unreadable until applied.
    migrations: bool,
    /// End-of-import steps not recorded as done (interrupted import, failed step, new step or
    /// new version of a step, ADR-014): readable, but incomplete.
    finalizers: bool,
}

impl WriteNeeded {
    fn any(self) -> bool {
        self.migrations || self.finalizers
    }
}

/// Whether a finished session must be written. Checked read-only on every opening (fast
/// path); [`upgrade`] does the corresponding work.
fn write_needed(conn: &Connection, set: &MigrationSet) -> Result<WriteNeeded> {
    let migrations = match check_current(conn, set) {
        Ok(()) => false,
        Err(StoreError::SchemaOutdated { .. }) => true,
        Err(e) => return Err(e),
    };
    let finalizers = !crate::finalize::finalizers_complete(conn)?;
    Ok(WriteNeeded {
        migrations,
        finalizers,
    })
}

/// Does what [`write_needed`] reports, through a read-write connection that cannot create the
/// file.
fn upgrade(path: &Path, set: &MigrationSet) -> Result<()> {
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::SQLITE_OPEN_URI;
    let mut conn = Connection::open_with_flags(path, flags)?;
    configure_writable(&conn, PAGE_SIZE)?;
    conn.busy_timeout(UPGRADE_BUSY_TIMEOUT)?;
    conn.pragma_update(None, "synchronous", "FULL")?;
    migrate_session(&mut conn, set)?;
    // End-of-import steps missing from the marker, on the same write connection, after the
    // migrations (ADR-014). A failed step is not an upgrade failure: the session stays
    // readable, the step is retried at the next opening.
    crate::finalize::run_finalizers(&conn)?;
    Ok(())
}

/// True when `e` comes from a lock that could not be obtained in time.
fn is_busy(e: &StoreError) -> bool {
    let (StoreError::Sqlite(sqlite) | StoreError::Migration { source: sqlite, .. }) = e else {
        return false;
    };
    matches!(
        sqlite.sqlite_error_code(),
        Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked)
    )
}

/// True when at least one migration has already been applied.
fn has_schema(conn: &Connection) -> Result<bool> {
    let has_table: bool = conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations')",
        [],
        |r| r.get(0),
    )?;
    if !has_table {
        return Ok(false);
    }
    Ok(
        conn.query_row("SELECT EXISTS (SELECT 1 FROM schema_migrations)", [], |r| {
            r.get(0)
        })?,
    )
}

/// Adds `created` to [`TABLES_ADDED_AFTER_IMPORT`], in the transaction of the migration.
fn record_added_tables(tx: &Transaction<'_>, created: &[String]) -> Result<()> {
    if created.is_empty() {
        return Ok(());
    }
    let mut tables = tables_added_after_import(tx)?;
    tables.extend(created.iter().cloned());
    let value = tables.into_iter().collect::<Vec<_>>().join(",");
    tx.execute(
        "INSERT INTO meta (key, value) VALUES (?1, ?2) \
         ON CONFLICT (key) DO UPDATE SET value = excluded.value",
        params![TABLES_ADDED_AFTER_IMPORT, value],
    )?;
    Ok(())
}

/// True when a core data table (anything but `meta`) already has rows.
fn has_imported_data(conn: &Connection) -> Result<bool> {
    Ok(conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM chunks) OR EXISTS (SELECT 1 FROM flows) \
         OR EXISTS (SELECT 1 FROM timeseries) OR EXISTS (SELECT 1 FROM hosts) \
         OR EXISTS (SELECT 1 FROM anomalies)",
        [],
        |r| r.get(0),
    )?)
}

/// Pragmas of a read-write connection. `page_size` only takes effect on an empty file and
/// must precede the switch to WAL, hence the order.
pub(crate) fn configure_writable(conn: &Connection, page_size: u32) -> Result<()> {
    conn.busy_timeout(BUSY_TIMEOUT)?;
    conn.pragma_update(None, "page_size", page_size)?;
    let mode: String = conn.pragma_update_and_check(None, "journal_mode", "WAL", |r| r.get(0))?;
    if !mode.eq_ignore_ascii_case("wal") {
        return Err(StoreError::InvalidValue {
            field: "journal_mode",
            reason: "WAL is not supported by this file system",
        });
    }
    conn.pragma_update(None, "foreign_keys", true)?;
    Ok(())
}

/// Read-only connection: cannot create the file nor write to it (`query_only` as a second
/// guard), but still reads the WAL so it sees committed batches of a running import.
pub(crate) fn open_read_only(path: &Path) -> Result<Connection> {
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::SQLITE_OPEN_URI;
    let conn = Connection::open_with_flags(path, flags)?;
    conn.busy_timeout(BUSY_TIMEOUT)?;
    conn.pragma_update(None, "query_only", true)?;
    conn.pragma_update(None, "foreign_keys", true)?;
    Ok(conn)
}

#[cfg(test)]
mod tests;
