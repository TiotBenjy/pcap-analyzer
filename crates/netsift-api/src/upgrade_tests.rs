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
/// Undoes migration 0700 (objects) and its end-of-import step: the session looks imported by a
/// build that predates the Pictures view.
const BEFORE_0700: &str = "DROP VIEW pictures; DROP TABLE objects; \
    DELETE FROM schema_migrations WHERE version = 700; \
    UPDATE meta SET value = replace(value, ',objects:1', '') WHERE key = 'finalizers';";
/// Undoes migration 0800 (servers), views included: the session looks imported by a build that
/// predates the Servers view.
const BEFORE_0800: &str = "DROP VIEW server_roles; DROP VIEW server_evidence; \
    DROP INDEX dns_messages_responder; DROP INDEX http_transactions_server; \
    DROP TABLE dhcp_messages; DROP TABLE ntp_responses; DROP TABLE kerberos_replies; \
    DELETE FROM schema_migrations WHERE version = 800;";
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
