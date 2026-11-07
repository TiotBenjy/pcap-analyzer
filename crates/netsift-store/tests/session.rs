//! Session opening: layout, pragmas, migrations, read-only mode, schema snapshot.

use netsift_store::migrate::applied_versions;
use netsift_store::schema::SESSION_MIGRATIONS;
use netsift_store::{OpenMode, Session, StoreError};
use rusqlite::Connection;

fn pragma<T: rusqlite::types::FromSql>(conn: &Connection, name: &str) -> T {
    conn.query_row(&format!("PRAGMA {name}"), [], |r| r.get(0))
        .unwrap()
}

#[test]
fn creates_layout_with_expected_pragmas() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("sessions").join("s1");
    let session = Session::open(&dir, OpenMode::Import).unwrap();
    assert!(dir.join("session.db").is_file());
    assert!(session.blobs_dir().is_dir());
    assert!(session.thumbs_dir().is_dir());

    let conn = session.conn();
    assert_eq!(pragma::<i64>(conn, "page_size"), 8192);
    assert_eq!(pragma::<String>(conn, "journal_mode"), "wal");
    assert_eq!(pragma::<i64>(conn, "foreign_keys"), 1);
    assert_eq!(
        pragma::<i64>(conn, "synchronous"),
        1,
        "NORMAL during import"
    );
    assert!(pragma::<i64>(conn, "busy_timeout") > 0);
    drop(session);

    let session = Session::open(&dir, OpenMode::ReadWrite).unwrap();
    assert_eq!(
        pragma::<i64>(session.conn(), "synchronous"),
        2,
        "FULL outside import"
    );
    assert_eq!(pragma::<i64>(session.conn(), "page_size"), 8192);
}

#[test]
fn migrations_are_idempotent_on_reopen() {
    let tmp = tempfile::tempdir().unwrap();
    let all: Vec<u32> = SESSION_MIGRATIONS.iter().map(|m| m.version).collect();
    let session = Session::open(tmp.path(), OpenMode::Import).unwrap();
    assert_eq!(applied_versions(session.conn()).unwrap(), all);
    session
        .conn()
        .execute("INSERT INTO meta (key, value) VALUES ('k', 'v')", [])
        .unwrap();
    drop(session);
    for mode in [OpenMode::Import, OpenMode::ReadWrite, OpenMode::ReadOnly] {
        let session = Session::open(tmp.path(), mode).unwrap();
        assert_eq!(applied_versions(session.conn()).unwrap(), all);
        let v: String = session
            .conn()
            .query_row("SELECT value FROM meta WHERE key = 'k'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, "v", "data kept across reopenings ({mode:?})");
    }
}

#[test]
fn refuses_a_schema_newer_than_the_binary() {
    let tmp = tempfile::tempdir().unwrap();
    let session = Session::open(tmp.path(), OpenMode::Import).unwrap();
    session
        .conn()
        .execute(
            "INSERT INTO schema_migrations (version, name, applied_ns) VALUES (9999, 'future', 0)",
            [],
        )
        .unwrap();
    drop(session);
    for mode in [OpenMode::Import, OpenMode::ReadWrite, OpenMode::ReadOnly] {
        let err = Session::open(tmp.path(), mode).unwrap_err();
        assert!(
            matches!(err, StoreError::SchemaTooNew { version: 9999 }),
            "{mode:?}: {err}"
        );
        assert!(err.to_string().contains("newer NetSift"));
    }
}

#[test]
fn read_only_mode_never_creates_nor_writes() {
    let tmp = tempfile::tempdir().unwrap();
    let missing = tmp.path().join("missing");
    assert!(matches!(
        Session::open(&missing, OpenMode::ReadOnly).unwrap_err(),
        StoreError::Io { .. }
    ));
    assert!(!missing.exists());

    drop(Session::open(tmp.path(), OpenMode::Import).unwrap());
    let ro = Session::open(tmp.path(), OpenMode::ReadOnly).unwrap();
    assert!(
        ro.conn()
            .execute("INSERT INTO meta (key, value) VALUES ('k', 'v')", [])
            .is_err()
    );
}

#[test]
fn refuses_a_foreign_database() {
    let tmp = tempfile::tempdir().unwrap();
    let conn = Connection::open(tmp.path().join("session.db")).unwrap();
    conn.execute_batch("CREATE TABLE unrelated (x)").unwrap();
    drop(conn);
    let err = Session::open(tmp.path(), OpenMode::Import).unwrap_err();
    assert!(matches!(err, StoreError::ForeignDatabase { .. }), "{err}");
}

#[test]
fn schema_snapshot() {
    let tmp = tempfile::tempdir().unwrap();
    let session = Session::open(tmp.path(), OpenMode::Import).unwrap();
    let mut stmt = session
        .conn()
        .prepare(
            "SELECT type, name, sql FROM sqlite_master \
             WHERE name NOT LIKE 'sqlite_%' ORDER BY tbl_name, type DESC, name",
        )
        .unwrap();
    let schema = stmt
        .query_map([], |r| {
            Ok(format!(
                "-- {} {}\n{};\n",
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?.unwrap_or_default()
            ))
        })
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap()
        .join("\n");
    insta::assert_snapshot!(schema);
}

#[test]
fn import_mode_refuses_a_session_with_data() {
    let tmp = tempfile::tempdir().unwrap();
    let session = Session::open(tmp.path(), OpenMode::Import).unwrap();
    session
        .conn()
        .execute(
            "INSERT INTO timeseries (bucket_s, proto, bytes, packets) VALUES (1, 'dns', 1, 1)",
            [],
        )
        .unwrap();
    drop(session);
    let err = Session::open(tmp.path(), OpenMode::Import).unwrap_err();
    assert!(matches!(err, StoreError::SessionNotEmpty), "{err}");
    // Other modes still open it.
    Session::open(tmp.path(), OpenMode::ReadWrite).unwrap();
    Session::open(tmp.path(), OpenMode::ReadOnly).unwrap();
}
