//! Route tests of the Save PCAP export, on imported synthetic captures.

use std::path::{Path, PathBuf};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, HeaderValue, Request, StatusCode, header};
use netsift_engine::{CancelToken, IngestOptions, ingest};
use netsift_fixtures::scenarios::{Kind, generate};
use netsift_fixtures::{Encoding, Naming, SplitBy, SplitOptions, split_to_dir};
use netsift_store::Catalog;
use serde_json::{Value, json};
use tower::ServiceExt;

use super::EXPORTS_DIR;
use crate::{ApiConfig, DEFAULT_MAX_IMPORTS, build};

const TOKEN: &str = "exports-token";

struct Env {
    _tmp: tempfile::TempDir,
    data: PathBuf,
    captures: PathBuf,
    app: Router,
}

impl Env {
    fn new(read_only: bool) -> Self {
        let tmp = tempfile::TempDir::new().unwrap();
        let data = tmp.path().join("data");
        let captures = tmp.path().join("captures");
        std::fs::create_dir_all(&captures).unwrap();
        Self::at(tmp, data, captures, read_only)
    }

    fn at(tmp: tempfile::TempDir, data: PathBuf, captures: PathBuf, read_only: bool) -> Self {
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

    fn exports(&self) -> PathBuf {
        self.data.join(EXPORTS_DIR)
    }

    async fn raw(&self, method: &str, uri: &str, body: &Value) -> (StatusCode, HeaderMap, Vec<u8>) {
        let builder = Request::builder()
            .method(method)
            .uri(uri)
            .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"));
        let req = if body.is_null() {
            builder.body(Body::empty()).unwrap()
        } else {
            builder
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap()
        };
        let res = self.app.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let headers = res.headers().clone();
        let bytes = axum::body::to_bytes(res.into_body(), 64 * 1024 * 1024)
            .await
            .unwrap();
        (status, headers, bytes.to_vec())
    }

    async fn call(&self, method: &str, uri: &str, body: &Value) -> (StatusCode, Value) {
        let (status, headers, bytes) = self.raw(method, uri, body).await;
        if status.is_client_error() || status.is_server_error() {
            assert_eq!(headers[header::CONTENT_TYPE], "application/problem+json");
        }
        (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
    }

    /// Imports demo traffic split in chunks; returns the session id and the chunk files.
    fn import(&self) -> (String, Vec<PathBuf>) {
        let dir = self.captures.join("run");
        let opts = SplitOptions::new(SplitBy::Packets(40), Naming::Dumpcap)
            .with_encoding(Encoding::pcapng());
        let files = split_to_dir(&dir, &generate(Kind::Demo, 4, 3), &opts)
            .unwrap()
            .1;
        let report = ingest(
            &Catalog::open(&self.data).unwrap(),
            &dir,
            &IngestOptions::default(),
            &CancelToken::new(),
            &mut |_| {},
        )
        .unwrap();
        (report.session.to_string(), files)
    }

    /// Starts an export and waits for its end.
    async fn export(&self, session: &str, body: &Value) -> Value {
        let (status, job) = self
            .call("POST", &format!("/api/v1/sessions/{session}/exports/pcap"), body)
            .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{job}");
        let id = job["id"].as_str().unwrap().to_owned();
        for _ in 0..1500 {
            let (status, job) = self.call("GET", &format!("/api/v1/exports/{id}"), &Value::Null).await;
            assert_eq!(status, StatusCode::OK);
            if job["state"] != "running" {
                return job;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("export did not end");
    }
}

fn files_in(dir: &Path) -> Vec<String> {
    let Ok(listing) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut names: Vec<String> = listing
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

fn is_server_name(name: &str, scope: &str) -> bool {
    let Some(rest) = name
        .strip_prefix("netsift-")
        .and_then(|r| r.strip_suffix(".pcapng"))
    else {
        return false;
    };
    let parts: Vec<&str> = rest.splitn(2, '-').collect();
    let [session, tail] = parts.as_slice() else {
        return false;
    };
    session.len() == 8
        && tail.starts_with(scope)
        && rest
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

#[tokio::test]
async fn session_export_writes_the_file_and_serves_it_as_an_attachment() {
    let env = Env::new(false);
    let (session, _) = env.import();
    let job = env.export(&session, &json!({ "scope": "session" })).await;
    assert_eq!(job["state"], "done", "{job}");
    assert_eq!(job["scope"], "session");
    assert_eq!(job["session_id"], session.as_str());
    let name = job["file_name"].as_str().unwrap();
    assert!(is_server_name(name, "session"), "{name}");
    assert_eq!(files_in(&env.exports()), [name]);
    let on_disk = std::fs::read(env.exports().join(name)).unwrap();
    assert_eq!(job["bytes_written"], on_disk.len());
    assert!(job["packets"].as_u64().unwrap() > 100);
    assert_eq!(job["bytes_read"], job["bytes_total"]);
    assert_eq!(
        PathBuf::from(job["path"].as_str().unwrap()),
        env.exports().join(name)
    );
    assert_eq!(
        PathBuf::from(job["folder"].as_str().unwrap()),
        env.exports()
    );

    let id = job["id"].as_str().unwrap();
    let (status, headers, body) = env
        .raw("GET", &format!("/api/v1/exports/{id}/file"), &Value::Null)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers[header::CONTENT_TYPE], "application/octet-stream");
    assert_eq!(
        headers[header::CONTENT_DISPOSITION],
        format!("attachment; filename=\"{name}\"").as_str()
    );
    assert_eq!(headers[header::CONTENT_SECURITY_POLICY], "sandbox");
    assert_eq!(headers[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
    assert_eq!(headers[header::CONTENT_LENGTH], on_disk.len().to_string().as_str());
    assert_eq!(body, on_disk);

    let (status, list) = env
        .call("GET", &format!("/api/v1/sessions/{session}/exports"), &Value::Null)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(list[0]["id"], id);

    // Cancelling a finished export changes nothing.
    let (status, again) = env
        .call("POST", &format!("/api/v1/exports/{id}/cancel"), &Value::Null)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(again["state"], "done");
}

#[tokio::test]
async fn flow_and_range_exports_from_the_connections_listing() {
    let env = Env::new(false);
    let (session, _) = env.import();
    let (_, conversations) = env
        .call("GET", &format!("/api/v1/sessions/{session}/connections"), &Value::Null)
        .await;
    let conversation = conversations["items"][0]["id"].as_str().unwrap();
    let (status, flows) = env
        .call(
            "GET",
            &format!("/api/v1/sessions/{session}/connections/{conversation}/flows"),
            &Value::Null,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{flows}");
    let flow = &flows["items"][0];
    let flow_id = flow["id"].as_str().unwrap();
    let job = env
        .export(&session, &json!({ "scope": "flow", "flow_id": flow_id }))
        .await;
    assert_eq!(job["state"], "done", "{job}");
    assert_eq!(job["packets"], flow["packets_total"]);
    assert!(is_server_name(job["file_name"].as_str().unwrap(), "flow-"));
    assert_eq!(job["flow_id"], flow_id);

    let (from, to) = (flow["first_ts_us"].as_i64().unwrap(), flow["last_ts_us"].as_i64().unwrap());
    let job = env
        .export(&session, &json!({ "scope": "range", "from_us": from, "to_us": to }))
        .await;
    assert_eq!(job["state"], "done", "{job}");
    assert!(job["packets"].as_u64().unwrap() >= flow["packets_total"].as_u64().unwrap());
    assert_eq!(job["from_us"], from);

    for uri in [
        format!("/api/v1/sessions/{session}/connections/999999/flows"),
        format!("/api/v1/sessions/{session}/connections/x/flows"),
    ] {
        let (status, _) = env.call("GET", &uri, &Value::Null).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{uri}");
    }
}

#[tokio::test]
async fn invalid_requests_are_problems_and_the_name_is_never_the_clients() {
    let env = Env::new(false);
    let (session, _) = env.import();
    let start = format!("/api/v1/sessions/{session}/exports/pcap");
    for (body, status, kind) in [
        (json!({ "scope": "everything" }), StatusCode::BAD_REQUEST, "bad-request"),
        (json!({ "scope": "flow", "flow_id": "abc" }), StatusCode::BAD_REQUEST, "bad-request"),
        (
            json!({ "scope": "flow", "flow_id": i64::MAX.to_string() }),
            StatusCode::NOT_FOUND,
            "not-found",
        ),
        (
            json!({ "scope": "range", "from_us": 10, "to_us": 5 }),
            StatusCode::BAD_REQUEST,
            "bad-request",
        ),
    ] {
        let (got, json) = env.call("POST", &start, &body).await;
        assert_eq!(got, status, "{body}: {json}");
        assert_eq!(json["type"], format!("urn:netsift:problem:{kind}"), "{body}");
    }
    assert_eq!(files_in(&env.exports()), Vec::<String>::new());

    // Names or paths sent by the client are ignored.
    let evil = env.captures.join("evil.pcapng");
    let job = env
        .export(
            &session,
            &json!({
                "scope": "session",
                "file_name": "../../evil.pcapng",
                "path": evil.to_str().unwrap(),
                "folder": env.captures.to_str().unwrap(),
            }),
        )
        .await;
    assert_eq!(job["state"], "done", "{job}");
    let name = job["file_name"].as_str().unwrap();
    assert!(is_server_name(name, "session"), "{name}");
    assert_eq!(files_in(&env.exports()), [name]);
    assert!(!evil.exists());

    let unknown = "01JC0000000000000000000000";
    for (method, uri) in [
        ("POST", format!("/api/v1/sessions/{unknown}/exports/pcap")),
        ("GET", format!("/api/v1/exports/{unknown}")),
        ("GET", format!("/api/v1/exports/{unknown}/file")),
        ("POST", format!("/api/v1/exports/{unknown}/cancel")),
        ("GET", "/api/v1/exports/..%2F..%2Fetc".to_owned()),
    ] {
        let (status, _) = env.call(method, &uri, &json!({ "scope": "session" })).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{method} {uri}");
    }
}

#[tokio::test]
async fn missing_or_modified_sources_are_409_without_a_file() {
    let env = Env::new(false);
    let (session, files) = env.import();
    let start = format!("/api/v1/sessions/{session}/exports/pcap");
    let last = files.last().unwrap();
    let saved = std::fs::read(last).unwrap();
    std::fs::remove_file(last).unwrap();
    let (status, json) = env.call("POST", &start, &json!({ "scope": "session" })).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(json["type"], "urn:netsift:problem:export-source-missing");
    let name = last.file_name().unwrap().to_str().unwrap();
    let detail = json["detail"].as_str().unwrap();
    assert!(detail.contains(name), "{detail}");
    assert!(!detail.contains(env.captures.to_str().unwrap()), "{detail}");

    let mut changed = saved;
    changed.push(0);
    std::fs::write(last, &changed).unwrap();
    let (status, json) = env.call("POST", &start, &json!({ "scope": "session" })).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(json["type"], "urn:netsift:problem:export-source-modified");
    let left: Vec<String> = files_in(&env.exports());
    assert_eq!(left, Vec::<String>::new());
}

#[tokio::test]
async fn read_only_servers_refuse_exports() {
    let env = Env::new(true);
    let (session, _) = env.import();
    let (status, json) = env
        .call(
            "POST",
            &format!("/api/v1/sessions/{session}/exports/pcap"),
            &json!({ "scope": "session" }),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(json["type"], "urn:netsift:problem:read-only");
    let (status, list) = env
        .call("GET", &format!("/api/v1/sessions/{session}/exports"), &Value::Null)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(list, json!([]));
}

#[test]
fn interrupted_exports_are_removed_at_startup() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data = tmp.path().join("data");
    let exports = data.join(EXPORTS_DIR);
    std::fs::create_dir_all(&exports).unwrap();
    std::fs::write(exports.join("netsift-a-session-b.pcapng.part"), b"x").unwrap();
    std::fs::write(exports.join("kept.pcapng"), b"x").unwrap();
    let captures = tmp.path().join("captures");
    let env = Env::at(tmp, data, captures, false);
    assert_eq!(files_in(&env.exports()), ["kept.pcapng"]);
}
