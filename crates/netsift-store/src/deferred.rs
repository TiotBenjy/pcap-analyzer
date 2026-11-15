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
/// transaction. Returns the number of indexes dropped. The indexes of the tables that the
/// end-of-import steps fill ([`crate::finalize::Finalizer::fills`]) stay: those tables are empty
/// during the import, and a step may name its index (`INDEXED BY`) even when `indexes` failed.
pub(crate) fn defer(conn: &Connection) -> Result<usize> {
    let filled: Vec<&str> = crate::finalize::SESSION_FINALIZERS
        .iter()
        .flat_map(|f| f.fills.iter().copied())
        .collect();
    let defs: Vec<(String, String)> = conn
        .prepare(
            "SELECT name, sql, tbl_name FROM sqlite_master WHERE type = 'index' \
             AND sql IS NOT NULL AND sql NOT LIKE 'CREATE UNIQUE %' ORDER BY name",
        )?
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?
        .into_iter()
        .filter(|(_, _, table)| !filled.contains(&table.as_str()))
        .map(|(name, sql, _)| (name, sql))
        .collect();
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
        // A definition recorded by an older build whose table or column a later migration
        // removed (migrations drop indexes with `IF EXISTS`, see `schema.rs`): skipped, or the
        // step would fail at every opening and hold back the steps that come after it.
        match conn.prepare(&sql) {
            Ok(mut stmt) => {
                stmt.execute([])?;
            }
            Err(e) if is_missing_object(&e) => {
                tracing::warn!(index = %name, "deferred index skipped: {e}");
            }
            Err(e) => return Err(e.into()),
        }
    }
    conn.execute("DELETE FROM meta WHERE key = ?1", [META_KEY])?;
    Ok(())
}

/// Error of a statement naming a table or column that does not exist.
fn is_missing_object(e: &rusqlite::Error) -> bool {
    let text = e.to_string();
    text.contains("no such table") || text.contains("no such column")
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
        // Only unique indexes, and those of the tables the steps fill, are left while the
        // import runs.
        let during = indexes(conn);
        assert_ne!(during, Vec::new());
        assert!(
            during
                .iter()
                .all(|(name, sql)| sql.starts_with("CREATE UNIQUE")
                    || name.starts_with("network_")
                    || name.starts_with("dns_pairs")
                    || name.starts_with("server_")
                    || name.starts_with("open_port_hosts")),
            "{during:?}"
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
    fn definitions_of_removed_tables_are_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let session = Session::open(dir.path(), OpenMode::ReadWrite).unwrap();
        let conn = session.conn();
        let defs = [
            ("gone_idx", "CREATE INDEX gone_idx ON gone_table (x)"),
            (
                "flows_gone",
                "CREATE INDEX flows_gone ON flows (gone_column)",
            ),
            ("flows_kept", "CREATE INDEX flows_kept ON flows (src_port)"),
        ];
        conn.execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2)",
            params![META_KEY, serde_json::to_string(&defs).unwrap()],
        )
        .unwrap();
        finalize(conn).unwrap();
        let names: Vec<String> = indexes(conn).into_iter().map(|(n, _)| n).collect();
        assert!(names.contains(&"flows_kept".to_owned()));
        assert!(!names.contains(&"flows_gone".to_owned()));
        assert!(crate::query::get_meta(conn, META_KEY).unwrap().is_none());
    }

    #[test]
    fn indexes_of_tables_filled_by_steps_are_kept() {
        let dir = tempfile::tempdir().unwrap();
        let session = Session::open(dir.path(), OpenMode::Import).unwrap();
        let names: Vec<String> = indexes(session.conn())
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        assert!(
            names.contains(&"network_hosts_bytes".to_owned()),
            "{names:?}"
        );
        assert!(!names.contains(&"flows_src_ip".to_owned()), "{names:?}");
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
