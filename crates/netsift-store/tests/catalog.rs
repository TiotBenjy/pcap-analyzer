//! Catalog CRUD.

use std::path::PathBuf;

use netsift_store::{Catalog, OpenMode, SessionId, SessionState, StoreError};

#[test]
fn create_get_list() {
    let tmp = tempfile::tempdir().unwrap();
    let catalog = Catalog::open(tmp.path()).unwrap();
    assert!(tmp.path().join("catalog.db").is_file());
    assert!(tmp.path().join("sessions").is_dir());
    assert_eq!(catalog.list().unwrap().len(), 0);

    let sources = vec![
        PathBuf::from("/captures/a_00001_20260101000000.pcapng"),
        PathBuf::from("/captures/a_00002_20260101001000.pcapng"),
    ];
    let a = catalog.create("  first  ", &sources, 1234).unwrap();
    assert_eq!(a.name, "first");
    assert_eq!(a.sources, sources);
    assert_eq!(a.state, SessionState::Importing);
    assert_eq!(a.state_detail, None);
    assert_eq!(a.source_bytes, 1234);
    assert_eq!(a.session_bytes, 0);
    assert_eq!(a.created_ns, a.updated_ns);
    assert!(a.created_ns > 0);
    assert_eq!(catalog.get(&a.id).unwrap().as_ref(), Some(&a));

    std::thread::sleep(std::time::Duration::from_millis(2));
    let b = catalog.create("second", &[], 0).unwrap();
    assert!(b.id > a.id, "ids sort by creation time");
    let ids: Vec<SessionId> = catalog.list().unwrap().into_iter().map(|s| s.id).collect();
    assert_eq!(ids, vec![b.id, a.id.clone()], "newest first");

    // Reopening the catalog keeps everything.
    drop(catalog);
    let catalog = Catalog::open(tmp.path()).unwrap();
    assert_eq!(catalog.list().unwrap().len(), 2);
    assert_eq!(catalog.get(&a.id).unwrap().unwrap(), a);
}

#[test]
fn rename_state_and_sizes() {
    let tmp = tempfile::tempdir().unwrap();
    let catalog = Catalog::open(tmp.path()).unwrap();
    let s = catalog.create("name", &[], 0).unwrap();

    catalog.rename(&s.id, "renamed").unwrap();
    catalog
        .set_state(&s.id, SessionState::Failed, Some("disk full"))
        .unwrap();
    catalog.set_sizes(&s.id, 10, 20).unwrap();
    let got = catalog.get(&s.id).unwrap().unwrap();
    assert_eq!(got.name, "renamed");
    assert_eq!(got.state, SessionState::Failed);
    assert_eq!(got.state_detail.as_deref(), Some("disk full"));
    assert_eq!((got.source_bytes, got.session_bytes), (10, 20));
    assert!(got.updated_ns >= got.created_ns);

    for state in [
        SessionState::Ready,
        SessionState::Incomplete,
        SessionState::Importing,
    ] {
        catalog.set_state(&s.id, state, None).unwrap();
        let got = catalog.get(&s.id).unwrap().unwrap();
        assert_eq!(got.state, state);
        assert_eq!(got.state_detail, None);
        assert_eq!(state.as_str().parse::<SessionState>().unwrap(), state);
    }

    for bad in ["", "   ", "a\nb", &"x".repeat(300)] {
        assert!(matches!(
            catalog.rename(&s.id, bad).unwrap_err(),
            StoreError::InvalidValue { field: "name", .. }
        ));
    }
}

#[test]
fn unknown_sessions_are_reported() {
    let tmp = tempfile::tempdir().unwrap();
    let catalog = Catalog::open(tmp.path()).unwrap();
    let ghost = SessionId::generate();
    assert_eq!(catalog.get(&ghost).unwrap(), None);
    for err in [
        catalog.rename(&ghost, "x").unwrap_err(),
        catalog
            .set_state(&ghost, SessionState::Ready, None)
            .unwrap_err(),
        catalog.set_sizes(&ghost, 1, 1).unwrap_err(),
        catalog.delete(&ghost).unwrap_err(),
        catalog.open_session(&ghost, OpenMode::Import).unwrap_err(),
    ] {
        assert!(matches!(err, StoreError::SessionNotFound(_)), "{err}");
    }
}

#[test]
fn create_makes_an_empty_session_ready_for_import() {
    let tmp = tempfile::tempdir().unwrap();
    let catalog = Catalog::open(tmp.path()).unwrap();
    let s = catalog.create("new", &[], 0).unwrap();
    let dir = catalog.session_dir(&s.id);
    assert!(dir.join("session.db").is_file());
    assert!(dir.join("blobs").is_dir());
    drop(catalog.open_session(&s.id, OpenMode::Import).unwrap());
    drop(catalog.open_session(&s.id, OpenMode::ReadOnly).unwrap());
}

#[test]
fn open_session_does_not_recreate_missing_files() {
    let tmp = tempfile::tempdir().unwrap();
    let catalog = Catalog::open(tmp.path()).unwrap();
    let no_db = catalog.create("no-db", &[], 0).unwrap();
    std::fs::remove_file(catalog.session_dir(&no_db.id).join("session.db")).unwrap();
    let no_dir = catalog.create("no-dir", &[], 0).unwrap();
    std::fs::remove_dir_all(catalog.session_dir(&no_dir.id)).unwrap();
    for id in [&no_db.id, &no_dir.id] {
        for mode in [OpenMode::Import, OpenMode::ReadWrite, OpenMode::ReadOnly] {
            let err = catalog.open_session(id, mode).unwrap_err();
            assert!(
                matches!(err, StoreError::SessionFilesMissing { .. }),
                "{err}"
            );
        }
    }
    assert!(!catalog.session_dir(&no_db.id).join("session.db").exists());
    assert!(!catalog.session_dir(&no_dir.id).exists());
}

#[test]
fn trash_left_by_an_interrupted_delete_is_cleaned_at_opening() {
    let tmp = tempfile::tempdir().unwrap();
    let leftover = tmp
        .path()
        .join("sessions")
        .join(".trash")
        .join("01ARZ3NDEKTSV4RRFFQ69G5FAV");
    std::fs::create_dir_all(leftover.join("blobs")).unwrap();
    std::fs::write(leftover.join("session.db"), b"x").unwrap();
    let catalog = Catalog::open(tmp.path()).unwrap();
    assert!(!leftover.exists());
    assert_eq!(catalog.list().unwrap().len(), 0);
}

#[test]
fn delete_removes_the_session_directory() {
    let tmp = tempfile::tempdir().unwrap();
    let catalog = Catalog::open(tmp.path()).unwrap();
    let keep = catalog.create("keep", &[], 0).unwrap();
    let gone = catalog.create("gone", &[], 0).unwrap();

    let session = catalog.open_session(&gone.id, OpenMode::Import).unwrap();
    std::fs::write(session.blobs_dir().join("blob"), b"data").unwrap();
    drop(session);
    let gone_dir = catalog.session_dir(&gone.id);
    assert!(gone_dir.join("session.db").is_file());

    catalog.delete(&gone.id).unwrap();
    assert!(!gone_dir.exists());
    assert!(
        !tmp.path()
            .join("sessions/.trash")
            .join(gone.id.as_str())
            .exists()
    );
    assert_eq!(catalog.get(&gone.id).unwrap(), None);
    assert!(catalog.session_dir(&keep.id).join("session.db").is_file());
    assert_eq!(catalog.list().unwrap().len(), 1);

    // A session whose directory has disappeared can be deleted too.
    let empty = catalog.create("empty", &[], 0).unwrap();
    std::fs::remove_dir_all(catalog.session_dir(&empty.id)).unwrap();
    catalog.delete(&empty.id).unwrap();
    assert_eq!(catalog.list().unwrap().len(), 1);
}
