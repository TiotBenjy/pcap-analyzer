//! Versioned SQL migrations.
//!
//! Each migration is an embedded SQL file applied once, in registry order, inside its own
//! `BEGIN IMMEDIATE` transaction. Applied versions are recorded in `schema_migrations`
//! (a dedicated table rather than `user_version`, so that a migration merged later with a
//! lower number than an already-applied one is still detected and applied).

use std::collections::BTreeSet;

use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

use crate::error::{Result, StoreError};
use crate::time::now_ns;

/// One embedded migration.
#[derive(Debug, Clone, Copy)]
pub struct Migration {
    /// Number of the `NNNN_<name>.sql` file; unique, strictly increasing in a registry.
    pub version: u32,
    /// Short name (the `<name>` of the file).
    pub name: &'static str,
    /// SQL script (several statements, no transaction control).
    pub sql: &'static str,
}

/// A family of migrations for one kind of database file.
#[derive(Debug, Clone, Copy)]
pub struct MigrationSet {
    /// Human-readable kind, used in errors ("session", "catalog").
    pub kind: &'static str,
    /// SQLite `application_id` stamped in the header of files of this kind.
    pub application_id: i32,
    /// Migrations sorted by strictly increasing version.
    pub migrations: &'static [Migration],
}

const CREATE_TABLE: &str = "CREATE TABLE IF NOT EXISTS schema_migrations (
    version    INTEGER PRIMARY KEY,
    name       TEXT NOT NULL,
    applied_ns INTEGER NOT NULL
)";

/// Applies all pending migrations. Returns the versions applied by this call (empty when the
/// schema was already up to date).
pub fn migrate(conn: &mut Connection, set: &MigrationSet) -> Result<Vec<u32>> {
    migrate_with(conn, set, |_, _| Ok(()))
}

/// [`migrate`], calling `on_applied` inside the transaction of each migration it applies, with
/// the names of the tables that migration created (sorted; shadow tables of virtual tables are
/// left out). Bookkeeping written there commits
/// atomically with the migration, so concurrent callers never apply nor record it twice.
pub fn migrate_with<F>(
    conn: &mut Connection,
    set: &MigrationSet,
    mut on_applied: F,
) -> Result<Vec<u32>>
where
    F: FnMut(&Transaction<'_>, &[String]) -> Result<()>,
{
    check_application_id(conn, set, true)?;
    conn.execute_batch(CREATE_TABLE)?;
    check_not_newer(conn, set)?;

    let mut applied = Vec::new();
    for m in set.migrations {
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let done: Option<u32> = tx
            .query_row(
                "SELECT version FROM schema_migrations WHERE version = ?1",
                [m.version],
                |r| r.get(0),
            )
            .optional()?;
        if done.is_some() {
            continue; // dropping `tx` rolls back the (empty) transaction
        }
        let before = table_names(&tx)?;
        tx.execute_batch(m.sql)
            .map_err(|source| StoreError::Migration {
                version: m.version,
                name: m.name,
                source,
            })?;
        let created: Vec<String> = table_names(&tx)?.difference(&before).cloned().collect();
        on_applied(&tx, &created)?;
        tx.execute(
            "INSERT INTO schema_migrations (version, name, applied_ns) VALUES (?1, ?2, ?3)",
            params![m.version, m.name, now_ns()],
        )?;
        tx.commit()?;
        applied.push(m.version);
    }
    Ok(applied)
}

/// Verifies, without writing, that the schema matches this build exactly.
pub fn check_current(conn: &Connection, set: &MigrationSet) -> Result<()> {
    check_application_id(conn, set, false)?;
    let has_table: bool = conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations')",
        [],
        |r| r.get(0),
    )?;
    let applied = if has_table {
        check_not_newer(conn, set)?;
        applied_versions(conn)?
    } else {
        Vec::new()
    };
    if let Some(m) = set
        .migrations
        .iter()
        .find(|m| !applied.contains(&m.version))
    {
        return Err(StoreError::SchemaOutdated { version: m.version });
    }
    Ok(())
}

/// Versions recorded in `schema_migrations`, ascending.
pub fn applied_versions(conn: &Connection) -> Result<Vec<u32>> {
    let mut stmt = conn.prepare("SELECT version FROM schema_migrations ORDER BY version")?;
    let rows = stmt.query_map([], |r| r.get(0))?;
    Ok(rows.collect::<rusqlite::Result<Vec<u32>>>()?)
}

/// Names of the tables of the database: ordinary and virtual tables, without the internal
/// `sqlite_*` tables nor the shadow tables of virtual tables (FTS5 `*_data`, `*_idx`...).
fn table_names(conn: &Connection) -> Result<BTreeSet<String>> {
    let mut stmt = conn.prepare(
        "SELECT name FROM pragma_table_list WHERE schema = 'main' \
         AND type IN ('table', 'virtual') AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\'",
    )?;
    let rows = stmt.query_map([], |r| r.get(0))?;
    Ok(rows.collect::<rusqlite::Result<BTreeSet<String>>>()?)
}

fn check_not_newer(conn: &Connection, set: &MigrationSet) -> Result<()> {
    let applied = applied_versions(conn)?;
    match applied
        .iter()
        .rev()
        .find(|v| !set.migrations.iter().any(|m| m.version == **v))
    {
        Some(&version) => Err(StoreError::SchemaTooNew { version }),
        None => Ok(()),
    }
}

/// A fresh file has `application_id` 0 and no table: it is stamped when `stamp` is set.
fn check_application_id(conn: &Connection, set: &MigrationSet, stamp: bool) -> Result<()> {
    let id: i32 = conn.query_row("PRAGMA application_id", [], |r| r.get(0))?;
    if id == set.application_id {
        return Ok(());
    }
    let tables: i64 = conn.query_row(
        "SELECT count(*) FROM sqlite_master WHERE type = 'table'",
        [],
        |r| r.get(0),
    )?;
    if id != 0 || tables != 0 {
        return Err(StoreError::ForeignDatabase { expected: set.kind });
    }
    if stamp {
        conn.pragma_update(None, "application_id", set.application_id)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const V1: Migration = Migration {
        version: 1,
        name: "one",
        sql: "CREATE TABLE t1 (a INTEGER);",
    };
    const V2: Migration = Migration {
        version: 2,
        name: "two",
        sql: "CREATE TABLE t2 (b INTEGER); INSERT INTO t1 VALUES (42);",
    };
    const V100: Migration = Migration {
        version: 100,
        name: "late",
        sql: "CREATE TABLE t100 (c INTEGER);",
    };
    const BROKEN: Migration = Migration {
        version: 3,
        name: "broken",
        sql: "CREATE TABLE t3 (x INTEGER); THIS IS NOT SQL;",
    };

    fn set(migrations: &'static [Migration]) -> MigrationSet {
        MigrationSet {
            kind: "test",
            application_id: 0x7465_7374,
            migrations,
        }
    }

    #[test]
    fn applies_in_order_once() {
        let mut conn = Connection::open_in_memory().unwrap();
        assert_eq!(migrate(&mut conn, &set(&[V1, V2])).unwrap(), vec![1, 2]);
        assert_eq!(
            migrate(&mut conn, &set(&[V1, V2])).unwrap(),
            Vec::<u32>::new()
        );
        let n: i64 = conn
            .query_row("SELECT count(*) FROM t1", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1, "migration 2 must not run twice");
        assert_eq!(applied_versions(&conn).unwrap(), vec![1, 2]);
    }

    #[test]
    fn applies_a_lower_numbered_migration_merged_later() {
        let mut conn = Connection::open_in_memory().unwrap();
        migrate(&mut conn, &set(&[V1, V100])).unwrap();
        assert_eq!(migrate(&mut conn, &set(&[V1, V2, V100])).unwrap(), vec![2]);
        check_current(&conn, &set(&[V1, V2, V100])).unwrap();
    }

    #[test]
    fn migrate_with_reports_created_tables_inside_the_transaction() {
        let mut conn = Connection::open_in_memory().unwrap();
        let mut seen = Vec::new();
        let applied = migrate_with(&mut conn, &set(&[V1, V2, V100]), |tx, created| {
            assert!(
                !tx.is_autocommit(),
                "called inside the migration transaction"
            );
            seen.push(created.to_vec());
            Ok(())
        })
        .unwrap();
        assert_eq!(applied, vec![1, 2, 100]);
        assert_eq!(seen, vec![vec!["t1"], vec!["t2"], vec!["t100"]]);

        // A failing callback rolls its migration back.
        let mut conn = Connection::open_in_memory().unwrap();
        migrate(&mut conn, &set(&[V1])).unwrap();
        let err = migrate_with(&mut conn, &set(&[V1, V2]), |_, _| {
            Err(StoreError::InvalidValue {
                field: "test",
                reason: "refused",
            })
        })
        .unwrap_err();
        assert!(matches!(err, StoreError::InvalidValue { .. }), "{err}");
        assert_eq!(applied_versions(&conn).unwrap(), vec![1]);
    }

    #[test]
    fn refuses_a_newer_schema() {
        let mut conn = Connection::open_in_memory().unwrap();
        migrate(&mut conn, &set(&[V1, V2, V100])).unwrap();
        let err = migrate(&mut conn, &set(&[V1, V2])).unwrap_err();
        assert!(
            matches!(err, StoreError::SchemaTooNew { version: 100 }),
            "{err}"
        );
        let err = check_current(&conn, &set(&[V1])).unwrap_err();
        assert!(
            matches!(err, StoreError::SchemaTooNew { version: 100 }),
            "{err}"
        );
    }

    #[test]
    fn check_reports_pending_migrations() {
        let mut conn = Connection::open_in_memory().unwrap();
        migrate(&mut conn, &set(&[V1])).unwrap();
        let err = check_current(&conn, &set(&[V1, V2])).unwrap_err();
        assert!(
            matches!(err, StoreError::SchemaOutdated { version: 2 }),
            "{err}"
        );
    }

    #[test]
    fn failed_migration_is_rolled_back() {
        let mut conn = Connection::open_in_memory().unwrap();
        let err = migrate(&mut conn, &set(&[V1, BROKEN])).unwrap_err();
        assert!(
            matches!(err, StoreError::Migration { version: 3, .. }),
            "{err}"
        );
        assert_eq!(applied_versions(&conn).unwrap(), vec![1]);
        let t3: bool = conn
            .query_row(
                "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE name = 't3')",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(!t3, "partial migration must be rolled back");
    }

    #[test]
    fn refuses_foreign_databases() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE other (x)").unwrap();
        let err = migrate(&mut conn, &set(&[V1])).unwrap_err();
        assert!(matches!(err, StoreError::ForeignDatabase { .. }), "{err}");

        let mut conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "application_id", 1234).unwrap();
        let err = migrate(&mut conn, &set(&[V1])).unwrap_err();
        assert!(matches!(err, StoreError::ForeignDatabase { .. }), "{err}");
    }
}
