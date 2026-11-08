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
use netsift_store::session::TABLES_ADDED_AFTER_IMPORT;
use netsift_store::{Catalog, OpenMode, Session, SessionId, SessionState as StoreState};
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
    fn new() -> Self {
        let tmp = tempfile::TempDir::new().unwrap();
        let data = tmp.path().join("data");
        let captures = tmp.path().join("captures");
        std::fs::create_dir_all(&captures).unwrap();
        let config = ApiConfig {
            token: TOKEN.to_owned(),
            data_dir: data.clone(),
            captures_roots: vec![captures.clone()],
            // Upgrading is schema maintenance, allowed on a read-only server too.
            read_only: true,
            cors_origins: vec![HeaderValue::from_static("tauri://localhost")],
            allow_any_path: false,
            max_imports: DEFAULT_MAX_IMPORTS,
            geoip_path: None,
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

    /// Runs `sql` on the session database, as another build would have left it.
    fn tamper(&self, id: &SessionId, sql: &str) {
        let session = Session::open(self.catalog().session_dir(id), OpenMode::ReadWrite).unwrap();
        session.conn().execute_batch(sql).unwrap();
    }
}

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

#[tokio::test]
async fn tables_added_after_the_import_are_reported_as_not_run() {
    let env = Env::new();
    let id = env.import();
    let (status, _, before) = env.get(&format!("/api/v1/sessions/{id}/summary")).await;
    assert_eq!(status, StatusCode::OK, "{before}");
    assert!(before["host_count"].as_u64().unwrap() > 0);

    // What an upgrade leaves when a later migration created the `hosts` table.
    env.tamper(
        &id,
        &format!("INSERT INTO meta (key, value) VALUES ('{TABLES_ADDED_AFTER_IMPORT}', 'hosts');"),
    );
    let (status, _, summary) = env.get(&format!("/api/v1/sessions/{id}/summary")).await;
    assert_eq!(status, StatusCode::OK, "{summary}");
    // The module is absent (the UI shows it as "not run"), not listed with 0 rows.
    let modules: Vec<&str> = summary["modules"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["id"].as_str().unwrap())
        .collect();
    assert_eq!(modules, ["connections"]);
    assert_eq!(summary["packets"], before["packets"]);
    assert_eq!(summary["flow_count"], before["flow_count"]);
}

#[tokio::test]
async fn a_newer_session_is_a_409_problem() {
    let env = Env::new();
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

#[tokio::test]
async fn a_failed_upgrade_is_an_explicit_problem() {
    let env = Env::new();
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
    let env = Env::new();
    let id = env.import();
    env.tamper(&id, FORGET_CORE);
    env.catalog()
        .set_state(&id, StoreState::Importing, None)
        .unwrap();
    // Plain read-only opening: an outdated schema is a conflict, no upgrade is attempted
    // (it would report `session-upgrade-failed`).
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
}
