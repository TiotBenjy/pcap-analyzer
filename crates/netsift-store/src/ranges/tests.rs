//! Range databases on hand-made sessions: content of a build, cache (one build per range, LRU,
//! fingerprint), cancellation. The views over a real import are tested in `netsift-api`
//! (`range/aggregate_tests.rs`, spread fixture).

use std::sync::Arc;
use std::time::Duration;

use super::*;
use crate::session::OpenMode;

const S: i64 = 1_000_000_000;

struct Env {
    _tmp: tempfile::TempDir,
    session: Session,
    dir: PathBuf,
}

/// A session with three hosts, a DNS server with an open port, and flows at 10 s, 100 s and
/// 1 000 s, plus one flow spanning all of them.
fn env() -> Env {
    let tmp = tempfile::tempdir().unwrap();
    let session = Session::open(tmp.path().join("s"), OpenMode::ReadWrite).unwrap();
    let conn = session.conn();
    conn.execute_batch(&format!(
        "INSERT INTO hosts (ip, category, first_ts, last_ts) VALUES
             ('10.0.0.1', 'private', {a}, {e}), ('10.0.0.2', 'private', {a}, {e}),
             ('10.0.0.3', 'private', {c}, {c2});
         INSERT INTO flows (id, transport, src_ip, src_port, dst_ip, dst_port, first_ts, last_ts,
                            bytes_fwd, bytes_rev, packets_fwd, packets_rev, app_proto) VALUES
             (1, 17, '10.0.0.1', 5000, '10.0.0.2', 53, {a}, {a}, 60, 100, 1, 1, 'dns'),
             (2, 6, '10.0.0.1', 5001, '10.0.0.2', 80, {b}, {b}, 500, 5000, 5, 6, 'http'),
             (3, 17, '10.0.0.3', 5002, '10.0.0.2', 53, {c}, {c2}, 70, 110, 1, 1, 'dns'),
             (4, 6, '10.0.0.1', 5003, '10.0.0.2', 9999, {a}, {e}, 7, 8, 1, 1, NULL);
         INSERT INTO conversations (id, src_ip, dst_ip, first_ts, last_ts, bytes_fwd, bytes_rev,
                                    packets_fwd, packets_rev, flows, dns_bytes_fwd, dns_bytes_rev,
                                    dns_flows, protocols) VALUES
             (7, '10.0.0.1', '10.0.0.2', {a}, {e}, 567, 5108, 7, 8, 3, 60, 100, 1,
              '[\"dns\",\"http\",\"tcp\"]'),
             (9, '10.0.0.3', '10.0.0.2', {c}, {c2}, 70, 110, 1, 1, 1, 70, 110, 1, '[\"dns\"]');
         INSERT INTO open_ports (ip, transport, port, evidence, first_ts, last_ts) VALUES
             ('10.0.0.2', 17, 53, 'udp_reply', {a}, {c2}),
             ('10.0.0.2', 6, 80, 'syn_ack', {b}, {b});
         INSERT INTO meta (key, value) VALUES ('stats.first_ts', '{a}'), ('stats.last_ts', '{e}'),
             ('stats.packets', '19');",
        a = 10 * S,
        b = 100 * S,
        c = 1_000 * S,
        c2 = 1_000 * S + 5,
        e = 2_000 * S,
    ))
    .unwrap();
    crate::finalize::run_finalizers(conn).unwrap();
    let dir = tmp.path().join("ranges");
    Env {
        _tmp: tmp,
        session,
        dir,
    }
}

/// What a thread needs to open the session and its range databases.
fn paths(env: &Env, cache: &Arc<RangeCache>) -> (PathBuf, PathBuf, Arc<RangeCache>) {
    (
        env.session.dir().to_path_buf(),
        env.dir.clone(),
        Arc::clone(cache),
    )
}

fn range(from_s: i64, to_s: i64) -> TimeRange {
    TimeRange::new(from_s * S, to_s * S).unwrap()
}

fn files(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
}

fn count(conn: &Connection, sql: &str) -> i64 {
    conn.query_row(sql, [], |r| r.get(0)).unwrap()
}

#[test]
fn a_build_derives_the_tables_of_the_range() {
    let env = env();
    let cache = RangeCache::new();
    // Around the second burst: the HTTP flow and the long one.
    let view = cache
        .open(&env.session, &env.dir, range(50, 150), &CancelFlag::new())
        .unwrap();
    let conn = view.conn();
    assert!(is_range_db(conn).unwrap());
    assert!(!is_range_db(env.session.conn()).unwrap());
    let (id, bytes_fwd, flows, protocols): (i64, i64, i64, String) = conn
        .query_row(
            "SELECT id, bytes_fwd, flows, protocols FROM conversations",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .unwrap();
    // The id of the session conversation, the flows of the range counted in full.
    assert_eq!((id, bytes_fwd, flows), (7, 507, 2));
    assert_eq!(protocols, r#"["http","tcp"]"#);
    assert_eq!(count(conn, "SELECT count(*) FROM conversations"), 1);
    // Hosts active in the range only; their traffic from the conversations.
    assert_eq!(count(conn, "SELECT count(*) FROM hosts"), 2);
    assert_eq!(
        count(
            conn,
            "SELECT bytes_received FROM host_traffic WHERE ip = '10.0.0.2'"
        ),
        507
    );
    // Open ports seen in the range, with the clients of its flows.
    assert_eq!(count(conn, "SELECT count(*) FROM open_ports"), 2);
    assert_eq!(
        count(
            conn,
            "SELECT clients FROM open_port_clients WHERE port = 80"
        ),
        1
    );
    assert_eq!(
        count(
            conn,
            "SELECT count(*) FROM open_port_clients WHERE port = 53"
        ),
        0
    );
    // Tables of the session not held by the range database are read from the session.
    assert_eq!(count(conn, "SELECT count(*) FROM flows"), 4);
    // The steps are done in its copy of `meta`; the network tables are filled.
    assert!(crate::finalize::step_done(conn, "network").unwrap());
    assert_eq!(count(conn, "SELECT count(*) FROM network_hosts"), 2);
    assert_eq!(view.range(), range(50, 150));
    // The session itself is untouched.
    assert_eq!(
        count(
            env.session.conn(),
            "SELECT bytes_fwd FROM conversations WHERE id = 7"
        ),
        567
    );
}

#[test]
fn a_range_covering_the_session_rebuilds_the_session_tables() {
    let env = env();
    let cache = RangeCache::new();
    let view = cache
        .open(&env.session, &env.dir, range(0, 5_000), &CancelFlag::new())
        .unwrap();
    for (table, columns) in [
        (
            "conversations",
            "id, src_ip, dst_ip, first_ts, last_ts, bytes_fwd, bytes_rev, packets_fwd, \
             packets_rev, flows, dns_bytes_fwd, dns_bytes_rev, dns_flows, protocols",
        ),
        ("hosts", "*"),
        ("open_ports", "*"),
        ("open_port_hosts", "*"),
        ("conversation_categories", "*"),
        ("server_evidence", "*"),
        ("server_roles", "*"),
        ("server_ranks", "*"),
        ("network_hosts", "*"),
        ("network_edges", "*"),
        ("network_protocols", "*"),
    ] {
        let rows = |schema: &str| -> Vec<String> {
            let mut stmt = view
                .conn()
                .prepare(&format!(
                    "SELECT json_array({columns}) FROM {schema}.{table} ORDER BY 1"
                ))
                .unwrap();
            stmt.query_map([], |r| r.get::<_, String>(0))
                .unwrap()
                .map(Result::unwrap)
                .collect()
        };
        assert_eq!(rows("main"), rows(ATTACHED), "{table}");
    }
}

#[test]
fn the_cache_keeps_the_last_four_ranges() {
    let env = env();
    let cache = RangeCache::new();
    let cancel = CancelFlag::new();
    let open = |r: TimeRange| {
        cache.open(&env.session, &env.dir, r, &cancel).unwrap();
    };
    for i in 0..4 {
        open(range(20 + i, 1_500));
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(files(&env.dir).len(), 4);
    assert_eq!(cache.builds(), 4);
    // Reused: no new build, and it becomes the most recent.
    open(range(20, 1_500));
    assert_eq!(cache.builds(), 4);
    std::thread::sleep(Duration::from_millis(5));
    open(range(30, 1_500));
    assert_eq!(cache.builds(), 5);
    let names = files(&env.dir);
    assert_eq!(names.len(), 4, "{names:?}");
    // The least recently used one (21 s) is gone, the reused one (20 s) is kept.
    let has = |from: i64| {
        names
            .iter()
            .any(|n| n.starts_with(&format!("{}_", from * S)))
    };
    assert!(has(20) && has(30) && !has(21), "{names:?}");
}

#[test]
fn ranges_differing_outside_the_session_share_a_database() {
    let env = env();
    let cache = RangeCache::new();
    let cancel = CancelFlag::new();
    let a = cache
        .open(&env.session, &env.dir, range(-100, 150), &cancel)
        .unwrap();
    let b = cache
        .open(&env.session, &env.dir, range(0, 150), &cancel)
        .unwrap();
    assert_eq!(a.range(), b.range());
    assert_eq!(a.range().from_ns(), 10 * S);
    assert_eq!(cache.builds(), 1);
    // Outside the session: one empty database for all.
    let c = cache
        .open(&env.session, &env.dir, range(3_000, 4_000), &cancel)
        .unwrap();
    assert_eq!(count(c.conn(), "SELECT count(*) FROM conversations"), 0);
    assert_eq!(count(c.conn(), "SELECT count(*) FROM hosts"), 0);
    cache
        .open(&env.session, &env.dir, range(5_000, 6_000), &cancel)
        .unwrap();
    assert_eq!(cache.builds(), 2);
}

#[test]
fn a_changed_session_gets_a_new_database() {
    let env = env();
    let cache = RangeCache::new();
    let cancel = CancelFlag::new();
    cache
        .open(&env.session, &env.dir, range(50, 150), &cancel)
        .unwrap();
    // A replayed step (new marker) changes the fingerprint.
    env.session
        .conn()
        .execute(
            "UPDATE meta SET value = value || ',extra:1' WHERE key = 'finalizers'",
            [],
        )
        .unwrap();
    cache
        .open(&env.session, &env.dir, range(50, 150), &cancel)
        .unwrap();
    assert_eq!(cache.builds(), 2);
    assert_eq!(files(&env.dir).len(), 2);
}

#[test]
fn concurrent_requests_share_one_build() {
    let env = env();
    let cache = Arc::new(RangeCache::new());
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let (sdir, rdir, cache) = paths(&env, &cache);
            std::thread::spawn(move || {
                let session = Session::open(sdir, OpenMode::ReadOnly).unwrap();
                let view = cache
                    .open(&session, &rdir, range(50, 150), &CancelFlag::new())
                    .unwrap();
                count(view.conn(), "SELECT count(*) FROM conversations")
            })
        })
        .collect();
    for t in threads {
        assert_eq!(t.join().unwrap(), 1);
    }
    assert_eq!(cache.builds(), 1);
    assert_eq!(files(&env.dir).len(), 1);
}

/// Adds `n` short flows between distinct pairs, spread over the session: a build that lasts.
fn many_flows(session: &Session, n: i64) {
    session
        .conn()
        .execute(
            &format!(
                "WITH RECURSIVE k(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM k WHERE i < {n})
                 INSERT INTO flows (id, transport, src_ip, src_port, dst_ip, dst_port, first_ts,
                                    last_ts, bytes_fwd, bytes_rev, packets_fwd, packets_rev)
                 SELECT 100 + i, 6, '10.1.' || (i / 250) || '.' || (i % 250), 4000,
                        '10.2.' || (i % 97) || '.1', 443, {a} + i * 1000, {a} + i * 1000 + 10,
                        10, 10, 1, 1 FROM k",
                a = 20 * S
            ),
            [],
        )
        .unwrap();
}

#[test]
fn a_cancelled_request_does_not_build() {
    let env = env();
    let cache = RangeCache::new();
    let cancel = CancelFlag::new();
    cancel.cancel();
    let err = cache
        .open(&env.session, &env.dir, range(50, 150), &cancel)
        .unwrap_err();
    assert!(matches!(err, StoreError::Cancelled), "{err}");
    assert_eq!(cache.builds(), 0);
    assert_eq!(files(&env.dir), Vec::<String>::new());
}

#[test]
fn a_build_stops_when_every_request_is_gone_and_goes_on_for_the_others() {
    let env = env();
    many_flows(&env.session, 60_000);
    let cache = Arc::new(RangeCache::new());

    // Alone: interrupted, nothing kept.
    let cancel = CancelFlag::new();
    let stopper = {
        let cancel = cancel.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(30));
            cancel.cancel();
        })
    };
    let err = cache
        .open(&env.session, &env.dir, range(15, 1_500), &cancel)
        .unwrap_err();
    stopper.join().unwrap();
    assert!(matches!(err, StoreError::Cancelled), "{err}");
    assert!(files(&env.dir).is_empty(), "{:?}", files(&env.dir));

    // Two requests, the first one leaves: the second one gets the database.
    let first = CancelFlag::new();
    let builder = {
        let ((sdir, rdir, cache), first) = (paths(&env, &cache), first.clone());
        std::thread::spawn(move || {
            let session = Session::open(sdir, OpenMode::ReadOnly).unwrap();
            cache
                .open(&session, &rdir, range(15, 1_500), &first)
                .map(|_| ())
        })
    };
    std::thread::sleep(Duration::from_millis(10));
    let second = CancelFlag::new();
    let waiter = {
        let ((sdir, rdir, cache), second) = (paths(&env, &cache), second.clone());
        std::thread::spawn(move || {
            let session = Session::open(sdir, OpenMode::ReadOnly).unwrap();
            cache
                .open(&session, &rdir, range(15, 1_500), &second)
                .map(|v| count(v.conn(), "SELECT count(*) FROM conversations"))
        })
    };
    std::thread::sleep(Duration::from_millis(10));
    first.cancel();
    let _ = builder.join().unwrap();
    assert!(waiter.join().unwrap().unwrap() > 1_000);
    assert_eq!(files(&env.dir).len(), 1);
}

#[test]
fn session_paths_become_read_only_uris() {
    assert_eq!(
        sqlite_uri(Path::new("/data/a b/s?#%.db")),
        "file:/data/a%20b/s%3F%23%25.db?mode=ro"
    );
    #[cfg(windows)]
    assert_eq!(
        sqlite_uri(Path::new(r"C:\Users\x\session.db")),
        "file:/C:/Users/x/session.db?mode=ro"
    );
    // Relative paths are resolved from the working directory.
    let relative = sqlite_uri(Path::new("data/session.db"));
    assert!(relative.starts_with("file:/") && relative.ends_with("/data/session.db?mode=ro"));
}

#[test]
fn partial_files_of_dead_builds_are_removed() {
    let env = env();
    let cache = RangeCache::new();
    std::fs::create_dir_all(&env.dir).unwrap();
    std::fs::write(env.dir.join("1_2_00.db.partial"), b"x").unwrap();
    cache
        .open(&env.session, &env.dir, range(50, 150), &CancelFlag::new())
        .unwrap();
    assert_eq!(files(&env.dir).len(), 1);
    assert!(
        Path::new(&files(&env.dir)[0])
            .extension()
            .is_some_and(|e| e == EXTENSION)
    );
}
