//! Upgrade of sessions created by an older build (`Session::open_upgrading`, ADR-013).

use std::sync::Barrier;

use super::*;
use crate::migrate::{Migration, applied_versions};
use crate::schema::SESSION_MIGRATIONS;
use crate::traffic::count_rows;

const LATER: Migration = Migration {
    version: 9001,
    name: "later",
    sql: "CREATE TABLE later_items (id INTEGER PRIMARY KEY, name TEXT NOT NULL); \
          CREATE INDEX later_items_name ON later_items (name);",
};
const LATEST: Migration = Migration {
    version: 9002,
    name: "latest",
    sql: "CREATE TABLE latest_items (id INTEGER PRIMARY KEY); \
          ALTER TABLE later_items ADD COLUMN extra TEXT;",
};
const BROKEN: Migration = Migration {
    version: 9003,
    name: "broken",
    sql: "CREATE TABLE broken_items (x INTEGER); THIS IS NOT SQL;",
};

/// The real session migrations followed by `extra` (leaked: a registry is `'static`).
fn set(extra: &[Migration]) -> MigrationSet {
    let mut all = SESSION_MIGRATIONS.to_vec();
    all.extend_from_slice(extra);
    MigrationSet {
        migrations: Box::leak(all.into_boxed_slice()),
        ..SESSION_SCHEMA
    }
}

/// A session database as written by a build whose registry is `set`, with imported data.
fn create(dir: &Path, set: &MigrationSet) {
    std::fs::create_dir_all(dir).unwrap();
    let mut conn = Connection::open(dir.join(SESSION_DB)).unwrap();
    configure_writable(&conn, PAGE_SIZE).unwrap();
    migrate_session(&mut conn, set).unwrap();
    conn.execute_batch(
        "INSERT INTO meta (key, value) VALUES ('stats.packets', '42'); \
         INSERT INTO chunks (id, path, linktypes) VALUES (0, 'a.pcap', '[1]');",
    )
    .unwrap();
}

fn versions(set: &MigrationSet) -> Vec<u32> {
    set.migrations.iter().map(|m| m.version).collect()
}

fn added(conn: &Connection) -> Vec<String> {
    tables_added_after_import(conn)
        .unwrap()
        .into_iter()
        .collect()
}

#[test]
fn an_older_session_is_migrated_then_opened_read_only() {
    let tmp = tempfile::tempdir().unwrap();
    let old = set(&[]);
    let new = set(&[LATER, LATEST]);
    create(tmp.path(), &old);

    // A plain read-only opening refuses it.
    let err = {
        let conn = open_read_only(&tmp.path().join(SESSION_DB)).unwrap();
        check_current(&conn, &new).unwrap_err()
    };
    assert!(
        matches!(err, StoreError::SchemaOutdated { version: 9001 }),
        "{err}"
    );

    let session =
        Session::open_finished_with(tmp.path().to_path_buf(), &new, Upgrade::Apply).unwrap();
    assert_eq!(session.mode(), OpenMode::ReadOnly);
    let conn = session.conn();
    assert_eq!(applied_versions(conn).unwrap(), versions(&new));
    assert_eq!(added(conn), ["later_items", "latest_items"]);
    // Imported data is kept; the new tables exist but count as "not run".
    assert_eq!(
        get_meta(conn, "stats.packets").unwrap().as_deref(),
        Some("42")
    );
    assert_eq!(count_rows(conn, "chunks").unwrap(), Some(1));
    assert_eq!(count_rows(conn, "later_items").unwrap(), None);
    assert_eq!(count_rows(conn, "latest_items").unwrap(), None);
    let extra: i64 = conn
        .query_row(
            "SELECT count(*) FROM pragma_table_info('later_items') WHERE name = 'extra'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(extra, 1, "ALTER of the later migration applied");
    assert!(conn.execute("DELETE FROM chunks", []).is_err(), "read-only");
    drop(session);

    // Reopening is a no-op.
    let session =
        Session::open_finished_with(tmp.path().to_path_buf(), &new, Upgrade::Apply).unwrap();
    assert_eq!(applied_versions(session.conn()).unwrap(), versions(&new));
    assert_eq!(added(session.conn()), ["later_items", "latest_items"]);
}

#[test]
fn an_up_to_date_session_is_opened_without_writing() {
    let tmp = tempfile::tempdir().unwrap();
    let current = set(&[LATER]);
    create(tmp.path(), &current);
    let session =
        Session::open_finished_with(tmp.path().to_path_buf(), &current, Upgrade::Apply).unwrap();
    assert_eq!(added(session.conn()), Vec::<String>::new());
    assert_eq!(count_rows(session.conn(), "later_items").unwrap(), Some(0));
    // The production registry: a session created by this build needs nothing.
    let tmp = tempfile::tempdir().unwrap();
    drop(Session::open(tmp.path(), OpenMode::Import).unwrap());
    let session = Session::open_upgrading(tmp.path()).unwrap();
    assert_eq!(added(session.conn()), Vec::<String>::new());
}

#[test]
fn concurrent_openings_migrate_once() {
    let tmp = tempfile::tempdir().unwrap();
    create(tmp.path(), &set(&[]));
    let new = set(&[LATER, LATEST]);
    let barrier = Barrier::new(8);
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..8)
            .map(|_| {
                scope.spawn(|| {
                    barrier.wait();
                    Session::open_finished_with(tmp.path().to_path_buf(), &new, Upgrade::Apply)
                        .map(|s| (applied_versions(s.conn()).unwrap(), added(s.conn())))
                })
            })
            .collect();
        for handle in handles {
            let (applied, added) = handle.join().unwrap().unwrap();
            assert_eq!(applied, versions(&new));
            assert_eq!(added, ["later_items", "latest_items"]);
        }
    });
    let conn = open_read_only(&tmp.path().join(SESSION_DB)).unwrap();
    let rows: i64 = conn
        .query_row("SELECT count(*) FROM schema_migrations", [], |r| r.get(0))
        .unwrap();
    assert_eq!(rows, i64::try_from(versions(&new).len()).unwrap());
}

#[test]
fn a_newer_session_is_refused_untouched() {
    let tmp = tempfile::tempdir().unwrap();
    create(tmp.path(), &set(&[LATER]));
    let err = Session::open_finished_with(tmp.path().to_path_buf(), &set(&[]), Upgrade::Apply)
        .unwrap_err();
    assert!(
        matches!(err, StoreError::SchemaTooNew { version: 9001 }),
        "{err}"
    );
    let conn = open_read_only(&tmp.path().join(SESSION_DB)).unwrap();
    assert_eq!(applied_versions(&conn).unwrap(), versions(&set(&[LATER])));
}

#[test]
fn a_failed_upgrade_is_reported_and_rolled_back() {
    let tmp = tempfile::tempdir().unwrap();
    create(tmp.path(), &set(&[]));
    let err = Session::open_finished_with(
        tmp.path().to_path_buf(),
        &set(&[LATER, BROKEN]),
        Upgrade::Apply,
    )
    .unwrap_err();
    match &err {
        StoreError::UpgradeFailed(inner) => {
            assert!(
                matches!(**inner, StoreError::Migration { version: 9003, .. }),
                "{inner}"
            );
        }
        other => panic!("unexpected error: {other}"),
    }
    // The migrations before the broken one are kept (each one is its own transaction).
    let conn = open_read_only(&tmp.path().join(SESSION_DB)).unwrap();
    assert_eq!(applied_versions(&conn).unwrap(), versions(&set(&[LATER])));
    assert_eq!(added(&conn), ["later_items"]);
    let broken: bool = conn
        .query_row(
            "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE name = 'broken_items')",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(!broken);
}

#[test]
fn a_fresh_session_records_nothing_and_an_import_clears_the_record() {
    let tmp = tempfile::tempdir().unwrap();
    // Creation then import, as `Catalog::create` and the engine do.
    drop(Session::open(tmp.path(), OpenMode::ReadWrite).unwrap());
    let session = Session::open(tmp.path(), OpenMode::Import).unwrap();
    assert_eq!(added(session.conn()), Vec::<String>::new());
    session
        .conn()
        .execute(
            "INSERT INTO meta (key, value) VALUES (?1, 'hosts')",
            [TABLES_ADDED_AFTER_IMPORT],
        )
        .unwrap();
    drop(session);
    // An empty session is imported again: every table gets filled from now on.
    let session = Session::open(tmp.path(), OpenMode::Import).unwrap();
    assert_eq!(added(session.conn()), Vec::<String>::new());
}

#[test]
fn a_missing_database_is_not_created() {
    let tmp = tempfile::tempdir().unwrap();
    let err = Session::open_upgrading(tmp.path().join("gone")).unwrap_err();
    assert!(matches!(err, StoreError::Io { .. }), "{err}");
    assert!(!tmp.path().join("gone").exists());
}

/// Only the core migration, as written by builds before the first analyzer migration.
fn core_only() -> MigrationSet {
    MigrationSet {
        migrations: Box::leak(
            SESSION_MIGRATIONS
                .iter()
                .filter(|m| m.version < 100)
                .copied()
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        ),
        ..SESSION_SCHEMA
    }
}

#[test]
fn a_core_only_session_gets_the_real_analyzer_migrations() {
    let tmp = tempfile::tempdir().unwrap();
    create(tmp.path(), &core_only());
    let session = Session::open_upgrading(tmp.path()).unwrap();
    let conn = session.conn();
    assert_eq!(applied_versions(conn).unwrap(), versions(&SESSION_SCHEMA));
    assert!(applied_versions(conn).unwrap().contains(&400));
    let added = added(conn);
    // Connections and open ports (0400); later analyzer migrations add their own tables.
    for table in ["conversations", "host_traffic", "open_ports"] {
        assert!(added.iter().any(|t| t == table), "{table} in {added:?}");
    }
    for core in [
        "meta",
        "chunks",
        "flows",
        "hosts",
        "timeseries",
        "anomalies",
    ] {
        assert!(!added.iter().any(|t| t == core), "{core} in {added:?}");
    }
    assert_eq!(count_rows(conn, "conversations").unwrap(), None);
    assert_eq!(count_rows(conn, "open_ports").unwrap(), None);
    assert_eq!(count_rows(conn, "flows").unwrap(), Some(0));
    assert_eq!(count_rows(conn, "hosts").unwrap(), Some(0));
    let index: bool = conn
        .query_row(
            "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'index' AND name = 'flows_service')",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(index, "index of migration 0400 on a core table");
}

#[test]
fn a_refused_upgrade_leaves_the_session_untouched() {
    let tmp = tempfile::tempdir().unwrap();
    create(tmp.path(), &set(&[]));
    let new = set(&[LATER]);
    let err =
        Session::open_finished_with(tmp.path().to_path_buf(), &new, Upgrade::Refuse).unwrap_err();
    assert!(matches!(err, StoreError::UpgradeNeeded), "{err}");
    let conn = open_read_only(&tmp.path().join(SESSION_DB)).unwrap();
    assert_eq!(applied_versions(&conn).unwrap(), versions(&set(&[])));
    // An up-to-date session opens normally under the same policy.
    let session =
        Session::open_finished_with(tmp.path().to_path_buf(), &set(&[]), Upgrade::Refuse).unwrap();
    assert_eq!(session.mode(), OpenMode::ReadOnly);
}

#[test]
fn shadow_tables_of_virtual_tables_are_not_recorded() {
    const FTS: Migration = Migration {
        version: 9004,
        name: "fts",
        sql: "CREATE VIRTUAL TABLE later_fts USING fts5(name);",
    };
    let tmp = tempfile::tempdir().unwrap();
    create(tmp.path(), &set(&[]));
    let session =
        Session::open_finished_with(tmp.path().to_path_buf(), &set(&[FTS]), Upgrade::Apply)
            .unwrap();
    assert_eq!(added(session.conn()), ["later_fts"]);
    assert_eq!(count_rows(session.conn(), "later_fts").unwrap(), None);
}

#[test]
fn a_lock_timeout_is_reported_as_busy() {
    let tmp = tempfile::tempdir().unwrap();
    create(tmp.path(), &set(&[]));
    let path = tmp.path().join(SESSION_DB);
    let holder = Connection::open(&path).unwrap();
    holder.execute_batch("BEGIN IMMEDIATE").unwrap();
    let mut waiter = Connection::open(&path).unwrap();
    waiter.busy_timeout(Duration::ZERO).unwrap();
    let err = StoreError::from(
        waiter
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap_err(),
    );
    assert!(is_busy(&err), "{err}");
    assert!(!is_busy(&StoreError::UpgradeNeeded));
    holder.execute_batch("ROLLBACK").unwrap();
}

#[test]
fn an_smb_view_added_on_upgrade_is_reported_as_not_run() {
    // A session written by a build that predates SMB: every migration but 0500.
    let old_migrations: Vec<Migration> = SESSION_MIGRATIONS
        .iter()
        .filter(|m| m.version != 500)
        .copied()
        .collect();
    let old = MigrationSet {
        migrations: Box::leak(old_migrations.into_boxed_slice()),
        ..SESSION_SCHEMA
    };
    let new = set(&[]);
    let tmp = tempfile::tempdir().unwrap();
    create(tmp.path(), &old);

    let session =
        Session::open_finished_with(tmp.path().to_path_buf(), &new, Upgrade::Apply).unwrap();
    let conn = session.conn();
    // The 0500 tables and the `smb_items` view are recorded as added after the import.
    let marker = added(conn);
    for relation in ["smb_announces", "smb_sessions", "smb_items"] {
        assert!(
            marker.iter().any(|t| t == relation),
            "{relation} in {marker:?}"
        );
    }
    // So the module reports "not run" (None), not "0 rows" — the view must not escape the marker.
    assert_eq!(count_rows(conn, "smb_items").unwrap(), None);
    assert_eq!(count_rows(conn, "smb_announces").unwrap(), None);
    assert_eq!(count_rows(conn, "smb_sessions").unwrap(), None);
}
