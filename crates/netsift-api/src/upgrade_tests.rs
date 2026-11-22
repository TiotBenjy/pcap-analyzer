//! Sessions created by another build: upgraded on opening, refused when newer (ADR-013).
//!
//! The migration path itself is covered in `netsift-store` (`session/tests.rs`) with a
//! registry extended in the test; here the API mapping of each outcome is checked.

use std::path::PathBuf;

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderValue, Request, StatusCode, header};
use netsift_engine::{CancelToken, IngestOptions, ingest};
use netsift_fixtures::scenarios::{Kind, generate};
use netsift_fixtures::{Encoding, encode};
use netsift_store::{
    Catalog, OpenMode, Session, SessionId, SessionState as StoreState, StoreError,
};
use serde_json::Value;
use tower::ServiceExt;

use crate::{ApiConfig, DEFAULT_MAX_IMPORTS, build};

const TOKEN: &str = "upgrade-token";
const PROBLEM: &str = "application/problem+json";

struct Env {
    _tmp: tempfile::TempDir,
    data: PathBuf,
    captures: PathBuf,
    app: Router,
}

impl Env {
    /// Server over a temporary data directory; `read_only` refuses upgrades.
    fn new(read_only: bool) -> Self {
        let tmp = tempfile::TempDir::new().unwrap();
        let data = tmp.path().join("data");
        let captures = tmp.path().join("captures");
        std::fs::create_dir_all(&captures).unwrap();
        let config = ApiConfig {
            token: TOKEN.to_owned(),
            data_dir: data.clone(),
            captures_roots: vec![captures.clone()],
            read_only,
            cors_origins: vec![HeaderValue::from_static("tauri://localhost")],
            allow_any_path: false,
            max_imports: DEFAULT_MAX_IMPORTS,
            geoip_fallback_path: None,
        };
        let (app, _) = build(config, IngestOptions::default());
        Self {
            _tmp: tmp,
            data,
            captures,
            app,
        }
    }

    fn catalog(&self) -> Catalog {
        Catalog::open(&self.data).unwrap()
    }

    /// True when the session still lacks a migration (a strict read-only opening refuses it).
    fn outdated(&self, id: &SessionId) -> bool {
        let dir = self.catalog().session_dir(id);
        matches!(
            Session::open(dir, OpenMode::ReadOnly),
            Err(StoreError::SchemaOutdated { .. })
        )
    }

    async fn get(&self, uri: &str) -> (StatusCode, Option<String>, Value) {
        let req = Request::get(uri)
            .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
            .body(Body::empty())
            .unwrap();
        let res = self.app.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let kind = res
            .headers()
            .get(header::CONTENT_TYPE)
            .map(|v| v.to_str().unwrap().to_owned());
        let bytes = axum::body::to_bytes(res.into_body(), 16 * 1024 * 1024)
            .await
            .unwrap();
        (status, kind, serde_json::from_slice(&bytes).unwrap())
    }

    /// Imports a small DNS capture (blocking ingest, like `netsift ingest`).
    fn import(&self) -> SessionId {
        let path = self.captures.join("dns.pcap");
        let packets = generate(Kind::Dns, 4, 1);
        std::fs::write(&path, encode(&packets, &Encoding::pcap()).unwrap()).unwrap();
        let options = IngestOptions {
            name: Some("dns".to_owned()),
            ..IngestOptions::default()
        };
        ingest(
            &self.catalog(),
            &path,
            &options,
            &CancelToken::new(),
            &mut |_| {},
        )
        .unwrap()
        .session
    }

    /// Imports the demo traffic plus the servers showcase (every role), on one shard.
    fn import_showcase(&self) -> SessionId {
        let path = self.captures.join("demo.pcap");
        if !path.exists() {
            let mut packets = generate(Kind::Demo, 3, 1);
            let start = packets.last().map_or(0, |p| p.ts_ns) + 1_000_000_000;
            let mut sc = netsift_fixtures::Scenario::starting_at(start);
            netsift_fixtures::servers::servers_showcase(&mut sc);
            packets.extend(sc.into_packets());
            std::fs::write(&path, encode(&packets, &Encoding::pcap()).unwrap()).unwrap();
        }
        let options = IngestOptions {
            name: Some("demo".to_owned()),
            shards: Some(1),
            ..IngestOptions::default()
        };
        ingest(
            &self.catalog(),
            &path,
            &options,
            &CancelToken::new(),
            &mut |_| {},
        )
        .unwrap()
        .session
    }

    /// Asserts that `paths` (relative to the session) answer the same for both sessions, ids
    /// aside.
    async fn same_answers(&self, want_id: &SessionId, got_id: &SessionId, paths: &[&str]) {
        for path in paths {
            let uri = |id: &SessionId| format!("/api/v1/sessions/{id}/{path}");
            let (status, _, want) = self.get(&uri(want_id)).await;
            assert_eq!(status, StatusCode::OK, "{path}: {want}");
            let (status, _, got) = self.get(&uri(got_id)).await;
            assert_eq!(status, StatusCode::OK, "{path}: {got}");
            let (got, want) = (
                serde_json::to_string_pretty(&without_ids(got)).unwrap(),
                serde_json::to_string_pretty(&without_ids(want)).unwrap(),
            );
            let first_difference = got
                .lines()
                .zip(want.lines())
                .enumerate()
                .find(|(_, (a, b))| a != b)
                .map(|(n, (a, b))| format!("line {n}: {a} | {b}"));
            assert_eq!(got, want, "{path}: {first_difference:?}");
        }
    }

    /// Runs `sql` on the session database, as another build would have left it.
    fn tamper(&self, id: &SessionId, sql: &str) {
        let session = Session::open(self.catalog().session_dir(id), OpenMode::ReadWrite).unwrap();
        session.conn().execute_batch(sql).unwrap();
    }
}

/// Undoes migration 0400 (connections and open ports): the session looks imported by a build
/// that predates it.
const BEFORE_0400: &str = "DROP INDEX flows_service; DROP TABLE conversations; \
    DROP TABLE host_traffic; DROP TABLE open_ports; \
    DELETE FROM schema_migrations WHERE version = 400;";
/// Undoes migration 0500 (SMB), including the `smb_items` view: the session looks imported by a
/// build that predates SMB.
const BEFORE_0500: &str = "DROP VIEW smb_items; DROP TABLE smb_announces; \
    DROP TABLE smb_sessions; DELETE FROM schema_migrations WHERE version = 500;";
/// Undoes migration 0600 (credentials): the session looks imported by a build that predates the
/// Credentials view.
const BEFORE_0600: &str =
    "DROP TABLE credentials; DELETE FROM schema_migrations WHERE version = 600;";
/// Undoes migration 0700 (objects) and its end-of-import step: the session looks imported by a
/// build that predates the Pictures view.
const BEFORE_0700: &str = "DROP VIEW pictures; DROP TABLE objects; \
    DELETE FROM schema_migrations WHERE version = 700; \
    UPDATE meta SET value = replace(value, ',objects:1', '') WHERE key = 'finalizers';";
/// Undoes migrations 0800 (servers) and 0801 (materialized roles), views included: the session
/// looks imported by a build that predates the Servers view.
const BEFORE_0800: &str = "DROP TABLE server_roles; DROP TABLE server_evidence; \
    DROP VIEW server_roles_source; DROP VIEW server_evidence_source; \
    DROP INDEX dns_messages_responder; DROP INDEX http_transactions_server; \
    DROP TABLE dhcp_messages; DROP TABLE ntp_responses; DROP TABLE kerberos_replies; \
    DELETE FROM schema_migrations WHERE version IN (800, 801);";
/// Forgets the core migration: the session looks created by a build that lacked it, and the
/// upgrade fails because its tables already exist.
const FORGET_CORE: &str = "DELETE FROM schema_migrations WHERE version = 1;";
/// A migration unknown to this build, as a newer NetSift would have recorded it.
const FROM_THE_FUTURE: &str =
    "INSERT INTO schema_migrations (version, name, applied_ns) VALUES (99999, 'future', 0);";

fn assert_problem(status: StatusCode, kind: Option<&str>, json: &Value, want: (StatusCode, &str)) {
    assert_eq!(status, want.0, "{json}");
    assert_eq!(kind, Some(PROBLEM));
    assert_eq!(
        json["type"],
        format!("urn:netsift:problem:{}", want.1),
        "{json}"
    );
    assert_eq!(json["status"], want.0.as_u16());
}

fn module_ids(summary: &Value) -> Vec<&str> {
    summary["modules"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["id"].as_str().unwrap())
        .collect()
}

#[tokio::test]
async fn an_older_session_is_upgraded_with_its_new_modules_not_run() {
    let env = Env::new(false);
    let id = env.import();
    let (status, _, before) = env.get(&format!("/api/v1/sessions/{id}/summary")).await;
    assert_eq!(status, StatusCode::OK, "{before}");
    env.tamper(&id, BEFORE_0400);
    assert!(env.outdated(&id));

    let (status, _, summary) = env.get(&format!("/api/v1/sessions/{id}/summary")).await;
    assert_eq!(status, StatusCode::OK, "{summary}");
    assert!(!env.outdated(&id), "migrated by the read");
    // Tables of 0400 exist again but are empty because their analyzers did not run: their
    // modules are absent (the UI shows them as "not run"), not listed with 0 rows.
    let modules = module_ids(&summary);
    assert!(modules.contains(&"hosts"), "{modules:?}");
    assert!(!modules.contains(&"connections"), "{modules:?}");
    assert!(!modules.contains(&"openPorts"), "{modules:?}");
    for field in [
        "packets",
        "bytes",
        "flow_count",
        "host_count",
        "chunk_count",
    ] {
        assert_eq!(summary[field], before[field], "{field}");
    }
    // The views of these modules answer too.
    let (status, _, json) = env.get(&format!("/api/v1/sessions/{id}/timeseries")).await;
    assert_eq!(status, StatusCode::OK, "{json}");
}

#[tokio::test]
async fn an_smb_view_added_on_upgrade_is_not_listed_as_run() {
    // The `smb_items` view backs the SMB module card: added on upgrade, it must report "not run"
    // (absent from modules), not "0 rows", for a session imported before SMB existed.
    let env = Env::new(false);
    let id = env.import();
    env.tamper(&id, BEFORE_0500);
    assert!(env.outdated(&id));

    let (status, _, summary) = env.get(&format!("/api/v1/sessions/{id}/summary")).await;
    assert_eq!(status, StatusCode::OK, "{summary}");
    assert!(!env.outdated(&id), "migrated by the read");
    assert!(!module_ids(&summary).contains(&"smb"), "{summary}");
}

#[tokio::test]
async fn credentials_added_on_upgrade_are_not_analyzed() {
    // A session imported before P3.7: the module is absent (not run) and the stats answer
    // `analyzed: false`.
    let env = Env::new(false);
    let id = env.import();
    env.tamper(&id, BEFORE_0600);
    assert!(env.outdated(&id));

    let (status, _, summary) = env.get(&format!("/api/v1/sessions/{id}/summary")).await;
    assert_eq!(status, StatusCode::OK, "{summary}");
    assert!(!env.outdated(&id), "migrated by the read");
    assert!(!module_ids(&summary).contains(&"credentials"), "{summary}");
    let (status, _, json) = env
        .get(&format!("/api/v1/sessions/{id}/credentials/stats"))
        .await;
    assert_eq!(status, StatusCode::OK, "{json}");
    assert_eq!(json["analyzed"], false);
    assert_eq!(json["total"], 0);
}

#[tokio::test]
async fn servers_added_on_upgrade_are_not_analyzed() {
    // A session imported before the Servers view: the module is absent (not run) and the view
    // answers `analyzed: false` without listing the DNS servers its old tables could show.
    let env = Env::new(false);
    let id = env.import();
    env.tamper(&id, BEFORE_0800);
    assert!(env.outdated(&id));

    let (status, _, summary) = env.get(&format!("/api/v1/sessions/{id}/summary")).await;
    assert_eq!(status, StatusCode::OK, "{summary}");
    assert!(!env.outdated(&id), "migrated by the read");
    assert!(module_ids(&summary).contains(&"dns"), "{summary}");
    assert!(!module_ids(&summary).contains(&"servers"), "{summary}");
    let (status, _, json) = env.get(&format!("/api/v1/sessions/{id}/servers")).await;
    assert_eq!(status, StatusCode::OK, "{json}");
    assert_eq!(json["analyzed"], false);
    let roles = json["roles"].as_array().unwrap();
    assert_eq!(roles.len(), 7);
    assert!(roles.iter().all(|r| r["total"] == 0), "{json}");
}

#[tokio::test]
async fn pictures_added_on_upgrade_are_not_listed_as_run() {
    // A session imported before P3.6 never stored bodies: its Pictures module is "not run".
    let env = Env::new(false);
    let id = env.import();
    env.tamper(&id, BEFORE_0700);
    assert!(env.outdated(&id));

    let (status, _, summary) = env.get(&format!("/api/v1/sessions/{id}/summary")).await;
    assert_eq!(status, StatusCode::OK, "{summary}");
    assert!(!env.outdated(&id), "migrated by the read");
    assert!(!module_ids(&summary).contains(&"pictures"), "{summary}");
    let (status, _, json) = env.get(&format!("/api/v1/sessions/{id}/objects")).await;
    assert_eq!(status, StatusCode::OK, "{json}");
}

#[tokio::test]
async fn a_read_only_server_refuses_to_upgrade() {
    let env = Env::new(true);
    let id = env.import();
    env.tamper(&id, BEFORE_0400);
    for path in ["summary", "timeseries", "chunks"] {
        let (status, kind, json) = env.get(&format!("/api/v1/sessions/{id}/{path}")).await;
        assert_problem(
            status,
            kind.as_deref(),
            &json,
            (StatusCode::CONFLICT, "session-upgrade-needed"),
        );
    }
    let (status, _, json) = env.get(&format!("/api/v1/sessions/{id}")).await;
    assert_eq!(status, StatusCode::OK, "{json}");
    assert!(env.outdated(&id), "never written by a read-only server");
}

#[tokio::test]
async fn a_newer_session_is_a_409_problem() {
    for read_only in [false, true] {
        let env = Env::new(read_only);
        let id = env.import();
        env.tamper(&id, FROM_THE_FUTURE);
        for path in ["summary", "timeseries", "chunks", "anomalies"] {
            let (status, kind, json) = env.get(&format!("/api/v1/sessions/{id}/{path}")).await;
            assert_problem(
                status,
                kind.as_deref(),
                &json,
                (StatusCode::CONFLICT, "session-too-new"),
            );
        }
        // Listing still works (figures unavailable).
        let (status, _, json) = env.get(&format!("/api/v1/sessions/{id}")).await;
        assert_eq!(status, StatusCode::OK, "{json}");
    }
}

#[tokio::test]
async fn a_failed_upgrade_is_an_explicit_problem() {
    let env = Env::new(false);
    let id = env.import();
    env.tamper(&id, FORGET_CORE);
    for path in ["summary", "timeseries", "chunks"] {
        let (status, kind, json) = env.get(&format!("/api/v1/sessions/{id}/{path}")).await;
        assert_problem(
            status,
            kind.as_deref(),
            &json,
            (StatusCode::INTERNAL_SERVER_ERROR, "session-upgrade-failed"),
        );
        // Store details (paths, SQL) stay in the log.
        assert!(json.get("detail").is_none(), "{json}");
    }
    let (status, _, json) = env.get(&format!("/api/v1/sessions/{id}")).await;
    assert_eq!(status, StatusCode::OK, "{json}");
}

#[tokio::test]
async fn a_session_being_imported_is_never_upgraded() {
    let env = Env::new(false);
    let id = env.import();
    env.tamper(&id, BEFORE_0400);
    env.catalog()
        .set_state(&id, StoreState::Importing, None)
        .unwrap();
    // Strict read-only opening: an outdated schema is a conflict.
    let (status, kind, json) = env.get(&format!("/api/v1/sessions/{id}/chunks")).await;
    assert_problem(
        status,
        kind.as_deref(),
        &json,
        (StatusCode::CONFLICT, "conflict"),
    );
    let (status, kind, json) = env.get(&format!("/api/v1/sessions/{id}/summary")).await;
    assert_problem(
        status,
        kind.as_deref(),
        &json,
        (StatusCode::CONFLICT, "conflict"),
    );
    let (status, _, json) = env.get(&format!("/api/v1/sessions/{id}")).await;
    assert_eq!(status, StatusCode::OK, "{json}");
    assert_eq!(json["state"], "importing");
    assert!(env.outdated(&id), "not migrated while importing");
}

#[test]
fn a_busy_session_is_a_retryable_503() {
    use axum::response::IntoResponse;
    let res = crate::ApiError::from(StoreError::SessionBusy).into_response();
    assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(res.headers()[header::RETRY_AFTER], "1");
    assert_eq!(res.headers()[header::CONTENT_TYPE], PROBLEM);
    let res = crate::ApiError::from(StoreError::UpgradeNeeded).into_response();
    assert_eq!(res.status(), StatusCode::CONFLICT);
}

/// What an import interrupted after its last record and before its end-of-import steps leaves:
/// no step recorded, the secondary indexes dropped (except those of the tables the steps fill),
/// the search indexes, materialized roles and traffic rollups empty (ADR-023).
const BEFORE_STEPS: &str = "DELETE FROM meta WHERE key IN \
    ('finalizers', 'timeseries.total_bytes', 'timeseries.total_packets'); \
    INSERT INTO http_transactions_fts (http_transactions_fts) VALUES ('delete-all'); \
    INSERT INTO http_headers_fts (http_headers_fts) VALUES ('delete-all'); \
    INSERT INTO dns_fts (dns_fts) VALUES ('delete-all'); \
    DELETE FROM server_evidence; DELETE FROM server_roles; DELETE FROM server_ranks; \
    DELETE FROM conversation_categories; DELETE FROM open_port_hosts; \
    DELETE FROM timeseries_minute; DELETE FROM timeseries_hour;";

/// Removes every `id` key (session ids differ between the two imports).
fn without_ids(mut v: Value) -> Value {
    match &mut v {
        Value::Object(map) => {
            map.remove("id");
            for value in map.values_mut() {
                *value = without_ids(value.take());
            }
        }
        Value::Array(items) => {
            for value in items.iter_mut() {
                *value = without_ids(value.take());
            }
        }
        _ => {}
    }
    v
}

#[tokio::test]
async fn an_import_without_its_steps_reads_the_same_data_read_only() {
    // A read-only server never runs the pending steps: every view must read their sources.
    let env = Env::new(true);
    let import = || env.import_showcase();
    let finished = import();
    let interrupted = import();
    // The finished session reads the tables of its steps (not empty, so the comparison holds).
    let session = Session::open(env.catalog().session_dir(&finished), OpenMode::ReadOnly).unwrap();
    for table in ["server_ranks", "conversation_categories", "open_port_hosts"] {
        let rows: i64 = session
            .conn()
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
            .unwrap();
        assert!(rows > 0, "{table}");
    }
    drop(session);
    let session =
        Session::open(env.catalog().session_dir(&interrupted), OpenMode::ReadWrite).unwrap();
    let conn = session.conn();
    conn.execute_batch(BEFORE_STEPS).unwrap();
    let deferred: Vec<String> = conn
        .prepare(
            "SELECT name FROM sqlite_master WHERE type = 'index' AND sql NOT LIKE 'CREATE UNIQUE%' \
             AND tbl_name NOT LIKE 'network\\_%' ESCAPE '\\' AND tbl_name NOT IN \
             ('dns_pairs', 'server_evidence', 'server_roles', 'open_port_hosts')",
        )
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert!(deferred.len() > 50);
    for name in deferred {
        conn.execute_batch(&format!("DROP INDEX \"{name}\""))
            .unwrap();
    }
    drop(session);

    env.same_answers(
        &finished,
        &interrupted,
        &[
            "summary",
            "timeseries?points=500",
            "tls/stats",
            "tls/sessions?limit=100",
            "servers",
            "servers?role=http&limit=1",
            "servers?category=private",
            "network/graph",
            "network/node/192.168.1.1",
            "http/stats",
            "http/transactions?limit=100&q=example",
            "http/headers?limit=100&q=nginx",
            "dns/messages?limit=100&q=example",
            "connections?limit=100&category=private",
            "connections?limit=3&category=public",
            "connections?limit=3&category=multicast,broadcast&sort=first_ts",
            "connections?limit=100&category=private&protocol=dns",
            "open-ports?limit=100",
            "open-ports?limit=2&category=private",
            "open-ports?limit=100&category=public,multicast",
        ],
    )
    .await;
    // Nothing was written: the steps are still pending.
    let session =
        Session::open(env.catalog().session_dir(&interrupted), OpenMode::ReadOnly).unwrap();
    assert!(!netsift_store::finalize::finalizers_complete(session.conn()).unwrap());
}

/// What `main` before P4.8 leaves: no migrations 0402 and 0802, the roles of the step `servers`
/// in version 2, and no steps `connections` nor `ports`.
const BEFORE_0802: &str = "DROP TABLE server_ranks; DROP TABLE conversation_categories; \
    DROP TABLE open_port_hosts; DELETE FROM schema_migrations WHERE version IN (402, 802); \
    UPDATE meta SET value = replace(replace(replace(value, 'servers:3', 'servers:2'), \
        ',connections:1', ''), ',ports:1', '') WHERE key = 'finalizers';";

/// Paths of the views that P4.8 reads from tables of its steps.
const P48_PATHS: &[&str] = &[
    "summary",
    "servers",
    "servers?role=http&limit=1",
    "servers?category=private",
    "network/graph",
    "connections?limit=100&category=private",
    "connections?limit=3&category=public",
    "connections?limit=3&category=multicast,broadcast&sort=first_ts",
    "connections/stats",
    "open-ports?limit=100",
    "open-ports?limit=2&category=private",
];

fn markers(env: &Env, id: &SessionId) -> Vec<String> {
    let session = Session::open(env.catalog().session_dir(id), OpenMode::ReadOnly).unwrap();
    netsift_store::finalize::finalizers_done(session.conn()).unwrap()
}

#[tokio::test]
async fn a_session_of_the_previous_build_gets_the_ranks_and_counts_at_its_opening() {
    let env = Env::new(false);
    let current = env.import_showcase();
    let previous = env.import_showcase();
    env.tamper(&previous, BEFORE_0802);
    assert!(env.outdated(&previous));
    // First opening: migrations 0402 and 0802, then the steps `servers` (v3), `connections`
    // and `ports`; same answers as a session imported by this build.
    env.same_answers(&current, &previous, P48_PATHS).await;
    assert!(!env.outdated(&previous));
    let done = markers(&env, &previous);
    for step in ["servers:3", "connections:1", "ports:1"] {
        assert!(done.contains(&step.to_owned()), "{step}: {done:?}");
    }
    assert!(!done.contains(&"servers:2".to_owned()));
}

#[tokio::test]
async fn roles_of_version_2_are_read_while_the_ranks_are_missing() {
    // Migration 0802 applied but the step `servers` v3 not done (failed, or a read-only server):
    // the roles come from the tables of version 2, the ranks are computed at read time.
    let env = Env::new(true);
    let current = env.import_showcase();
    let partial = env.import_showcase();
    env.tamper(
        &partial,
        "DELETE FROM server_ranks; UPDATE meta SET value = replace(value, 'servers:3', \
         'servers:2') WHERE key = 'finalizers';",
    );
    env.same_answers(&current, &partial, P48_PATHS).await;
    let session = Session::open(env.catalog().session_dir(&partial), OpenMode::ReadOnly).unwrap();
    let conn = session.conn();
    assert!(netsift_store::finalize::step_done_since(conn, "servers", 2).unwrap());
    assert!(!netsift_store::finalize::step_done(conn, "servers").unwrap());
    let ranks: i64 = conn
        .query_row("SELECT count(*) FROM server_ranks", [], |r| r.get(0))
        .unwrap();
    assert_eq!(ranks, 0, "a read-only server writes nothing");
}

/// Undoes migrations 0003, 0101, 0202 and 0302 (time filter): the session looks imported by a
/// build that predates them, header lines without their time.
const BEFORE_TIME_RANGES: &str = "DROP INDEX http_headers_name; \
    ALTER TABLE http_headers DROP COLUMN ts; \
    CREATE INDEX http_headers_name ON http_headers (name_lc, transaction_id); \
    DROP INDEX flows_long; DROP INDEX dns_messages_pair_cover; \
    DROP INDEX http_transactions_status_ts; \
    DELETE FROM schema_migrations WHERE version IN (3, 101, 202, 302);";

#[tokio::test]
async fn a_session_of_the_previous_build_answers_time_ranges_after_its_opening() {
    let env = Env::new(false);
    let current = env.import_showcase();
    let previous = env.import_showcase();
    env.tamper(&previous, BEFORE_TIME_RANGES);
    assert!(env.outdated(&previous));
    let (_, _, summary) = env
        .get(&format!("/api/v1/sessions/{current}/summary"))
        .await;
    let first = summary["first_ts_us"].as_i64().unwrap();
    // The second of the three demo rounds (one second apart).
    let range = format!("from_us={}&to_us={}", first + 900_000, first + 1_900_000);
    let paths: Vec<String> = [
        "summary",
        "dns/stats",
        "dns/messages",
        "http/stats",
        "http/headers/stats",
        "tls/stats",
        "smb/stats",
        "credentials/stats",
        "objects/stats",
    ]
    .iter()
    .map(|p| format!("{p}?{range}"))
    .collect();
    let refs: Vec<&str> = paths.iter().map(String::as_str).collect();
    // First opening: the migrations fill the time of the header lines; same answers as a
    // session imported by this build.
    env.same_answers(&current, &previous, &refs).await;
    assert!(!env.outdated(&previous));
    let (_, _, headers) = env
        .get(&format!(
            "/api/v1/sessions/{previous}/http/headers/stats?{range}"
        ))
        .await;
    assert!(headers["header_count"].as_u64().unwrap() > 0, "{headers}");
}
