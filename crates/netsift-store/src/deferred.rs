//! Secondary indexes built once, at the end of the import (P4.2, ADR-023).
//!
//! Maintaining every secondary index row by row was most of the writer's time on large captures
//! (the flows table alone has ten, filled in random order): an import session drops them when it
//! opens ([`defer`], [`crate::OpenMode::Import`]), after recording their definitions in `meta`,
//! and the first end-of-import step (`indexes`, [`finalize`]) creates them again, each with one
//! sort, before the other steps read them. Unique indexes and the indexes of primary keys and
//! `UNIQUE` constraints stay: the upserts need them.
//!
//! An interrupted import leaves the definitions in `meta` and the step unmarked: the next opening
//! of the session runs it (ADR-014), like any pending step. Until then the session is complete
//! but its queries are slow.

use rusqlite::{Connection, OptionalExtension, params};

use crate::error::{Result, StoreError};

/// `meta` key of the definitions of the dropped indexes (JSON array of `[name, sql]`).
pub const META_KEY: &str = "import.deferred_indexes";

/// Drops every non-unique secondary index of an empty session and records its definition, in one
/// transaction. Returns the number of indexes dropped.
pub(crate) fn defer(conn: &Connection) -> Result<usize> {
    let defs: Vec<(String, String)> = conn
        .prepare(
            "SELECT name, sql FROM sqlite_master WHERE type = 'index' AND sql IS NOT NULL \
             AND sql NOT LIKE 'CREATE UNIQUE %' ORDER BY name",
        )?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    if defs.is_empty() {
        return Ok(0);
    }
    conn.execute_batch("BEGIN IMMEDIATE")?;
    let result = (|| -> Result<()> {
        conn.execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2) \
             ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            params![META_KEY, serde_json::to_string(&defs)?],
        )?;
        for (name, _) in &defs {
            conn.execute_batch(&format!("DROP INDEX {}", quote(name)))?;
        }
        Ok(())
    })();
    match result {
        Ok(()) => {
            conn.execute_batch("COMMIT")?;
            Ok(defs.len())
        }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            Err(e)
        }
    }
}

/// End-of-import step `indexes` ([`crate::finalize::SESSION_FINALIZERS`], first): creates the
/// recorded indexes that do not exist, then forgets them, in the transaction of the caller.
/// Idempotent; nothing to do on a session imported without deferred indexes.
pub(crate) fn finalize(conn: &Connection) -> Result<()> {
    let Some(raw) = conn
        .query_row("SELECT value FROM meta WHERE key = ?1", [META_KEY], |r| {
            r.get::<_, String>(0)
        })
        .optional()?
    else {
        return Ok(());
    };
    let defs: Vec<(String, String)> = serde_json::from_str(&raw)?;
    for (name, sql) in defs {
        let exists = conn
            .query_row(
                "SELECT 1 FROM sqlite_master WHERE type = 'index' AND name = ?1",
                [&name],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if exists {
            continue;
        }
        // Only a plain index definition is ever executed (one statement, `prepare` refuses a
        // tail), whatever the content of `meta`.
        if !sql.starts_with("CREATE INDEX ") {
            return Err(StoreError::InvalidValue {
                field: META_KEY,
                reason: "not an index definition",
            });
        }
        conn.prepare(&sql)?.execute([])?;
    }
    conn.execute("DELETE FROM meta WHERE key = ?1", [META_KEY])?;
    Ok(())
}

/// SQL identifier quoting.
fn quote(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::{OpenMode, Session};

    fn indexes(conn: &Connection) -> Vec<(String, String)> {
        conn.prepare(
            "SELECT name, sql FROM sqlite_master WHERE type = 'index' AND sql IS NOT NULL \
             ORDER BY name",
        )
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect()
    }

    #[test]
    fn an_import_drops_the_secondary_indexes_and_the_step_restores_them() {
        let dir = tempfile::tempdir().unwrap();
        let reference = {
            let rw = tempfile::tempdir().unwrap();
            let session = Session::open(rw.path(), OpenMode::ReadWrite).unwrap();
            indexes(session.conn())
        };
        assert!(reference.len() > 50, "{}", reference.len());
        let session = Session::open(dir.path(), OpenMode::Import).unwrap();
        let conn = session.conn();
        // Only unique indexes are left while the import runs.
        let during = indexes(conn);
        assert_ne!(during, Vec::new());
        assert!(
            during
                .iter()
                .all(|(_, sql)| sql.starts_with("CREATE UNIQUE"))
        );
        finalize(conn).unwrap();
        assert_eq!(indexes(conn), reference);
        // Idempotent.
        finalize(conn).unwrap();
        assert_eq!(indexes(conn), reference);
        assert!(
            crate::query::get_meta(conn, META_KEY).unwrap().is_none(),
            "definitions forgotten"
        );
    }

    #[test]
    fn only_index_definitions_are_executed() {
        let dir = tempfile::tempdir().unwrap();
        let session = Session::open(dir.path(), OpenMode::ReadWrite).unwrap();
        let conn = session.conn();
        for sql in [
            "DROP TABLE flows",
            "CREATE INDEX x ON flows (src_ip); DROP TABLE flows",
        ] {
            conn.execute(
                "INSERT INTO meta (key, value) VALUES (?1, ?2) \
                 ON CONFLICT (key) DO UPDATE SET value = excluded.value",
                params![META_KEY, serde_json::to_string(&[("x", sql)]).unwrap()],
            )
            .unwrap();
            assert!(finalize(conn).is_err(), "{sql}");
            let flows: i64 = conn
                .query_row(
                    "SELECT count(*) FROM sqlite_master WHERE name = 'flows'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(flows, 1, "{sql}");
        }
    }
}
