use std::path::Path;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use netsift_capture::source::{CaptureError, CaptureInfo, PacketSource, RawPacket, ReadWarning};
use netsift_fixtures::scenarios::{Kind, generate};
use netsift_fixtures::{Encoding, Naming, SplitBy, SplitOptions, split_to_dir};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tower::ServiceExt;

use super::*;

const TOKEN: &str = "s3cret-token";
const BEARER: &str = "Bearer s3cret-token";
/// A well-formed session id that exists nowhere.
const UNKNOWN_ID: &str = "01JC0000000000000000000000";

fn config() -> ApiConfig {
    ApiConfig {
        token: TOKEN.to_owned(),
        data_dir: PathBuf::from("/nonexistent"),
        captures_roots: vec![],
        read_only: true,
        cors_origins: vec![HeaderValue::from_static("tauri://localhost")],
        allow_any_path: false,
    }
}

async fn read(res: axum::response::Response) -> (StatusCode, axum::http::HeaderMap, Value) {
    let status = res.status();
    let headers = res.headers().clone();
    let bytes = axum::body::to_bytes(res.into_body(), 16 * 1024 * 1024)
        .await
        .unwrap();
    let json = if bytes.is_empty() {
        Value::Null
    } else if headers
        .get(header::CONTENT_TYPE)
        .is_some_and(|v| v == "text/event-stream")
    {
        Value::String(String::from_utf8(bytes.to_vec()).unwrap())
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    (status, headers, json)
}

async fn send(req: Request<Body>) -> (StatusCode, axum::http::HeaderMap, Value) {
    read(router(config()).oneshot(req).await.unwrap()).await
}

fn get(uri: &str) -> Request<Body> {
    Request::get(uri).body(Body::empty()).unwrap()
}

/// Authenticated request, with a JSON body when `body` is not null.
fn req(method: &str, uri: &str, body: &Value) -> Request<Body> {
    let builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, BEARER);
    if body.is_null() {
        builder.body(Body::empty()).unwrap()
    } else {
        builder
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }
}

/// Server over a temporary data directory and captures root.
struct Env {
    tmp: tempfile::TempDir,
    app: Router,
    state: Arc<AppState>,
}

impl Env {
    fn new(read_only: bool, allow_any_path: bool, ingest: IngestOptions) -> Self {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join("captures")).unwrap();
        let config = ApiConfig {
            data_dir: tmp.path().join("data"),
            captures_roots: vec![tmp.path().join("captures")],
            read_only,
            allow_any_path,
            ..config()
        };
        let (app, state) = build(config, ingest);
        Self { tmp, app, state }
    }

    fn writable() -> Self {
        Self::new(false, false, default_ingest_options())
    }

    fn captures(&self) -> PathBuf {
        std::fs::canonicalize(self.tmp.path().join("captures")).unwrap()
    }

    async fn call(&self, method: &str, uri: &str, body: &Value) -> (StatusCode, Value) {
        let (status, _, json) = read(
            self.app
                .clone()
                .oneshot(req(method, uri, body))
                .await
                .unwrap(),
        )
        .await;
        (status, json)
    }

    /// Imports `path` and returns the session id.
    async fn import(&self, path: &Path) -> String {
        let (status, json) = self
            .call(
                "POST",
                "/api/v1/sessions/import",
                &json!({ "path": path.to_str().unwrap() }),
            )
            .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{json}");
        json["session_id"].as_str().unwrap().to_owned()
    }

    /// Reads the event stream of a session to its end.
    async fn events(&self, id: &str) -> Vec<(String, Value)> {
        let uri = format!("/api/v1/sessions/{id}/events");
        let fut = self.call("GET", &uri, &Value::Null);
        let (status, body) = tokio::time::timeout(Duration::from_secs(60), fut)
            .await
            .expect("event stream did not end");
        assert_eq!(status, StatusCode::OK);
        parse_sse(body.as_str().unwrap())
    }
}

fn parse_sse(text: &str) -> Vec<(String, Value)> {
    text.split("\n\n")
        .filter_map(|block| {
            let mut name = None;
            let mut data = String::new();
            for line in block.lines() {
                if let Some(v) = line.strip_prefix("event:") {
                    name = Some(v.trim().to_owned());
                } else if let Some(v) = line.strip_prefix("data:") {
                    data.push_str(v.trim_start());
                }
            }
            Some((name?, serde_json::from_str(&data).unwrap()))
        })
        .collect()
}

/// Writes `files` dumpcap chunks of the demo scenario into `dir`.
fn write_chunks(dir: &Path, prefix: &str, rounds: usize) -> Vec<PathBuf> {
    let opts = SplitOptions::new(SplitBy::Packets(40), Naming::Dumpcap)
        .with_prefix(prefix)
        .with_encoding(Encoding::pcapng());
    split_to_dir(dir, &generate(Kind::Demo, rounds, 3), &opts)
        .unwrap()
        .1
}

/// Content of every file under `dir`, for before/after comparisons.
fn snapshot(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut out: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| {
            let p = e.unwrap().path();
            let bytes = std::fs::read(&p).unwrap();
            (p, bytes)
        })
        .collect();
    out.sort();
    out
}

/// Packet source slowed down to make cancellations deterministic.
struct Slow(Box<dyn PacketSource>);

impl PacketSource for Slow {
    fn info(&self) -> &CaptureInfo {
        self.0.info()
    }
    fn next_packet(&mut self) -> Result<Option<RawPacket>, CaptureError> {
        std::thread::sleep(Duration::from_millis(5));
        self.0.next_packet()
    }
    fn bytes_read(&self) -> u64 {
        self.0.bytes_read()
    }
    fn warnings(&self) -> &[ReadWarning] {
        self.0.warnings()
    }
}

fn slow_ingest() -> IngestOptions {
    let opener: Arc<netsift_capture::chunkset::Opener> = Arc::new(|path: &Path| {
        let inner = netsift_capture::reader::open(path)?;
        Ok(Box::new(Slow(inner)) as Box<dyn PacketSource>)
    });
    IngestOptions {
        opener: Some(opener),
        shards: Some(2),
        ..default_ingest_options()
    }
}

fn catalog_state(env: &Env, id: &str) -> netsift_store::SessionState {
    let catalog = Catalog::open(env.tmp.path().join("data")).unwrap();
    catalog.get(&id.parse().unwrap()).unwrap().unwrap().state
}

// ---------------------------------------------------------------------------------------------

#[test]
fn smoke() {
    assert_eq!(CRATE_NAME, "netsift-api");
}

#[tokio::test]
async fn health_is_public() {
    let (status, _, json) = send(get("/api/v1/health")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["status"], "ok");
    assert_eq!(json["version"], env!("CARGO_PKG_VERSION"));
}

#[tokio::test]
async fn protected_routes_require_the_token() {
    let (status, headers, json) = send(get("/api/v1/server-info")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(headers[header::CONTENT_TYPE], "application/problem+json");
    assert_eq!(headers[header::WWW_AUTHENTICATE], "Bearer");
    assert_eq!(json["status"], 401);

    let wrong = Request::get("/api/v1/server-info")
        .header(header::AUTHORIZATION, "Bearer nope")
        .body(Body::empty())
        .unwrap();
    assert_eq!(send(wrong).await.0, StatusCode::UNAUTHORIZED);

    let (status, _, json) = send(req("GET", "/api/v1/server-info", &Value::Null)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["read_only"], true);
    assert_eq!(json["can_browse"], false);
}

/// Every route of the contract table.
fn contract_routes() -> Vec<(&'static str, String)> {
    let id = UNKNOWN_ID;
    vec![
        ("GET", "/api/v1/sessions".to_owned()),
        ("GET", format!("/api/v1/sessions/{id}")),
        ("PATCH", format!("/api/v1/sessions/{id}")),
        ("DELETE", format!("/api/v1/sessions/{id}")),
        ("POST", "/api/v1/sessions/import/scan".to_owned()),
        ("POST", "/api/v1/sessions/import".to_owned()),
        ("POST", format!("/api/v1/sessions/{id}/cancel")),
        ("GET", format!("/api/v1/sessions/{id}/events")),
        ("GET", format!("/api/v1/sessions/{id}/chunks")),
        ("GET", format!("/api/v1/sessions/{id}/anomalies")),
        ("GET", "/api/v1/fs/browse".to_owned()),
    ]
}

#[tokio::test]
async fn every_route_requires_the_token() {
    for (method, uri) in contract_routes() {
        let r = Request::builder()
            .method(method)
            .uri(&uri)
            .body(Body::empty())
            .unwrap();
        let (status, headers, _) = send(r).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{method} {uri}");
        assert_eq!(headers[header::CONTENT_TYPE], "application/problem+json");
    }
}

#[tokio::test]
async fn mutating_routes_are_refused_in_read_only_mode() {
    let env = Env::new(true, false, default_ingest_options());
    let body = json!({ "path": "/x", "name": "n" });
    for (method, uri) in contract_routes() {
        if method == "GET" {
            continue;
        }
        let (status, json) = env.call(method, &uri, &body).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{method} {uri}");
        assert_eq!(json["type"], "urn:netsift:problem:read-only");
    }
    // Reading still works.
    let (status, json) = env.call("GET", "/api/v1/sessions", &Value::Null).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["items"], json!([]));
}

#[tokio::test]
async fn mutating_routes_refuse_cross_site_requests() {
    let env = Env::writable();
    for (method, uri) in contract_routes() {
        if method == "GET" {
            continue;
        }
        for (name, value) in [
            ("sec-fetch-site", "cross-site"),
            ("origin", "http://evil.example"),
        ] {
            let r = Request::builder()
                .method(method)
                .uri(&uri)
                .header(header::AUTHORIZATION, BEARER)
                .header(header::HOST, "127.0.0.1:7878")
                .header(name, value)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"path":"/x","name":"n"}"#))
                .unwrap();
            let (status, _, json) = read(env.app.clone().oneshot(r).await.unwrap()).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{method} {uri} {name}");
            assert_eq!(json["type"], "urn:netsift:problem:forbidden");
        }
    }
    // The desktop webview origin is allowed even though the browser tags it cross-site.
    let r = Request::delete(format!("/api/v1/sessions/{UNKNOWN_ID}"))
        .header(header::AUTHORIZATION, BEARER)
        .header("origin", "tauri://localhost")
        .header("sec-fetch-site", "cross-site")
        .body(Body::empty())
        .unwrap();
    let (status, _, _) = read(env.app.clone().oneshot(r).await.unwrap()).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn unknown_sessions_and_paths_are_404() {
    let env = Env::writable();
    for (method, uri) in contract_routes() {
        if !uri.contains(UNKNOWN_ID) {
            continue;
        }
        let body = json!({ "name": "n" });
        for uri in [uri.clone(), uri.replace(UNKNOWN_ID, "not-an-id")] {
            let (status, json) = env.call(method, &uri, &body).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{method} {uri}");
            assert_eq!(json["type"], "urn:netsift:problem:not-found");
        }
    }
    let missing = env.captures().join("missing");
    for uri in ["/api/v1/sessions/import/scan", "/api/v1/sessions/import"] {
        let (status, _) = env
            .call("POST", uri, &json!({ "path": missing.to_str().unwrap() }))
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{uri}");
    }
    let (status, _) = env
        .call(
            "GET",
            &format!("/api/v1/fs/browse?path={}", missing.display()),
            &Value::Null,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    // No captures root configured: no browser.
    let (status, _, _) = send(req("GET", "/api/v1/fs/browse", &Value::Null)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn malformed_requests_are_problem_json_400() {
    let env = Env::writable();
    let r = Request::post("/api/v1/sessions/import/scan")
        .header(header::AUTHORIZATION, BEARER)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from("{not json"))
        .unwrap();
    let (status, headers, json) = read(env.app.clone().oneshot(r).await.unwrap()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(headers[header::CONTENT_TYPE], "application/problem+json");
    assert_eq!(json["type"], "urn:netsift:problem:bad-request");
    let (status, _) = env
        .call("GET", "/api/v1/sessions?limit=abc", &Value::Null)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = env
        .call("GET", "/api/v1/sessions?cursor=zz", &Value::Null)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    for path in ["relative/path", "/a/../b", ""] {
        let (status, _) = env
            .call(
                "POST",
                "/api/v1/sessions/import/scan",
                &json!({ "path": path }),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{path}");
    }
}

#[tokio::test]
async fn scan_lists_two_groups_and_skipped_files() {
    let env = Env::writable();
    let dir = env.captures().join("mixed");
    write_chunks(&dir, "alpha", 4);
    write_chunks(&dir, "beta", 4);
    std::fs::write(dir.join("notes.txt"), "not a capture at all").unwrap();
    std::fs::write(dir.join("empty.bin"), b"").unwrap();
    let (status, json) = env
        .call(
            "POST",
            "/api/v1/sessions/import/scan",
            &json!({ "path": dir.to_str().unwrap() }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{json}");
    let scan: contract::ScanResponse = serde_json::from_value(json).unwrap();
    assert_eq!(scan.path, dir.to_str().unwrap());
    assert_eq!(scan.groups.len(), 2);
    let prefixes: Vec<&str> = scan.groups.iter().map(|g| g.prefix.as_str()).collect();
    assert_eq!(prefixes, ["alpha", "beta"]);
    for g in &scan.groups {
        assert_eq!(g.pattern, contract::GroupPattern::Dumpcap);
        assert!(g.file_count > 1 && g.total_bytes > 0);
        // Microseconds (ADR-008), not nanoseconds.
        let first = g.first_ts_us.unwrap();
        assert!((1_000_000_000_000_000..10_000_000_000_000_000).contains(&first));
        assert!(g.last_ts_us.unwrap() > first);
    }
    let mut skipped: Vec<(String, String)> = scan
        .skipped
        .into_iter()
        .map(|s| (s.name, s.reason))
        .collect();
    skipped.sort();
    assert_eq!(
        skipped,
        [
            ("empty.bin".to_owned(), "empty".to_owned()),
            ("notes.txt".to_owned(), "unrecognized".to_owned())
        ]
    );

    // A missing chunk is announced before the import.
    let paths = write_chunks(&env.captures().join("holed"), "cap", 6);
    std::fs::remove_file(&paths[2]).unwrap();
    let (_, json) = env
        .call(
            "POST",
            "/api/v1/sessions/import/scan",
            &json!({ "path": env.captures().join("holed").to_str().unwrap() }),
        )
        .await;
    let codes: Vec<&str> = json["groups"][0]["anomalies"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["code"].as_str().unwrap())
        .collect();
    assert!(codes.contains(&"missing_sequence"), "{codes:?}");

    // Importing a folder of two groups needs a choice; a subset of several is refused.
    let (status, json) = env
        .call(
            "POST",
            "/api/v1/sessions/import",
            &json!({ "path": dir.to_str().unwrap() }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{json}");
    let (status, _) = env
        .call(
            "POST",
            "/api/v1/sessions/import",
            &json!({ "path": dir.to_str().unwrap(), "group_ids": [5] }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn scan_and_import_stay_inside_the_roots_unless_desktop() {
    let env = Env::writable();
    let outside = env.tmp.path().join("outside");
    write_chunks(&outside, "cap", 2);
    let body = json!({ "path": outside.to_str().unwrap() });
    for uri in ["/api/v1/sessions/import/scan", "/api/v1/sessions/import"] {
        let (status, json) = env.call("POST", uri, &body).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{uri}");
        assert_eq!(json["type"], "urn:netsift:problem:forbidden");
    }
    let desktop = Env::new(false, true, default_ingest_options());
    let (status, json) = desktop
        .call("POST", "/api/v1/sessions/import/scan", &body)
        .await;
    assert_eq!(status, StatusCode::OK, "{json}");
    assert_eq!(json["groups"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn import_end_to_end_with_events_pages_and_rename() {
    let env = Env::writable();
    let run = env.captures().join("run1");
    let paths = write_chunks(&run, "cap", 6);
    let id = env.import(&run).await;

    let events = env.events(&id).await;
    let (last_name, last) = events.last().unwrap();
    assert_eq!(last_name, "done", "{events:?}");
    assert_eq!(last["type"], "done");
    assert_eq!(last["state"], "ready");
    assert!(last["packets"].as_u64().unwrap() > 0);
    assert!(last["flows"].as_u64().unwrap() > 0);
    for (name, data) in &events {
        assert_eq!(data["type"], name.as_str());
        if name == "progress" {
            assert_eq!(data["chunk_count"], paths.len());
            assert!(data["bytes_done"].as_u64() <= data["bytes_total"].as_u64());
        }
    }
    // A client connecting after the end gets the final event at once.
    let again = env.events(&id).await;
    assert_eq!(again.last().unwrap().1, *last);

    let (status, summary) = env
        .call("GET", &format!("/api/v1/sessions/{id}"), &Value::Null)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(summary["state"], "ready");
    assert_eq!(summary["name"], "cap");
    assert_eq!(summary["packets"], last["packets"]);
    assert_eq!(summary["chunk_count"], paths.len());
    assert_eq!(summary["sources"], json!([run.to_str().unwrap()]));
    let first = summary["first_ts_us"].as_i64().unwrap();
    assert!((1_000_000_000_000_000..10_000_000_000_000_000).contains(&first));
    assert!(summary["last_ts_us"].as_i64().unwrap() > first);

    // Keyset pages of chunks.
    let (status, page) = env
        .call(
            "GET",
            &format!("/api/v1/sessions/{id}/chunks?limit=4"),
            &Value::Null,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(page["items"].as_array().unwrap().len(), 4);
    assert_eq!(page["total_estimate"], paths.len());
    assert_eq!(page["items"][0]["state"], "ok");
    assert_eq!(page["items"][0]["format"], "pcapng");
    let cursor = page["next_cursor"].as_str().unwrap();
    let (_, rest) = env
        .call(
            "GET",
            &format!("/api/v1/sessions/{id}/chunks?limit=1000&cursor={cursor}"),
            &Value::Null,
        )
        .await;
    assert_eq!(rest["items"].as_array().unwrap().len(), paths.len() - 4);
    assert_eq!(rest["next_cursor"], Value::Null);
    let (status, anomalies) = env
        .call(
            "GET",
            &format!("/api/v1/sessions/{id}/anomalies"),
            &Value::Null,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(anomalies["items"].is_array());

    // Rename, then a second session to page the list.
    let (status, renamed) = env
        .call(
            "PATCH",
            &format!("/api/v1/sessions/{id}"),
            &json!({ "name": " Renamed " }),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(renamed["name"], "Renamed");
    let (status, _) = env
        .call(
            "PATCH",
            &format!("/api/v1/sessions/{id}"),
            &json!({ "name": "" }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let second = env.import(&run).await;
    env.events(&second).await;
    let (_, page) = env
        .call("GET", "/api/v1/sessions?limit=1", &Value::Null)
        .await;
    assert_eq!(page["total_estimate"], 2);
    assert_eq!(page["items"][0]["id"], second.as_str());
    let cursor = page["next_cursor"].as_str().unwrap();
    let (_, page) = env
        .call(
            "GET",
            &format!("/api/v1/sessions?limit=1&cursor={cursor}"),
            &Value::Null,
        )
        .await;
    assert_eq!(page["items"][0]["id"], id.as_str());
    assert_eq!(page["next_cursor"], Value::Null);
}

#[tokio::test]
async fn cancelled_import_is_incomplete() {
    let env = Env::new(false, false, slow_ingest());
    let run = env.captures().join("slow");
    write_chunks(&run, "cap", 20);
    let id = env.import(&run).await;
    let (status, _) = env
        .call(
            "POST",
            &format!("/api/v1/sessions/{id}/cancel"),
            &Value::Null,
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let events = env.events(&id).await;
    let (name, last) = events.last().unwrap();
    assert_eq!(name, "done");
    assert_eq!(last["state"], "incomplete");
    assert_eq!(
        catalog_state(&env, &id),
        netsift_store::SessionState::Incomplete
    );
    // Still browsable.
    let (status, page) = env
        .call(
            "GET",
            &format!("/api/v1/sessions/{id}/chunks"),
            &Value::Null,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_ne!(page["items"], json!([]));
}

#[tokio::test]
async fn delete_removes_the_session_but_never_the_sources() {
    let env = Env::writable();
    let run = env.captures().join("keep");
    write_chunks(&run, "cap", 4);
    let before = snapshot(&run);
    let id = env.import(&run).await;
    env.events(&id).await;
    let session_dir = env.tmp.path().join("data/sessions").join(&id);
    assert!(session_dir.is_dir());

    let (status, body) = env
        .call("DELETE", &format!("/api/v1/sessions/{id}"), &Value::Null)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(body, Value::Null);
    assert!(!session_dir.exists());
    assert_eq!(snapshot(&run), before);
    let (status, _) = env
        .call("GET", &format!("/api/v1/sessions/{id}"), &Value::Null)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn running_import_cannot_be_deleted() {
    let env = Env::new(false, false, slow_ingest());
    let run = env.captures().join("busy");
    write_chunks(&run, "cap", 20);
    let id = env.import(&run).await;
    let (status, json) = env
        .call("DELETE", &format!("/api/v1/sessions/{id}"), &Value::Null)
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{json}");
    env.call(
        "POST",
        &format!("/api/v1/sessions/{id}/cancel"),
        &Value::Null,
    )
    .await;
    env.events(&id).await;
    let (status, _) = env
        .call("DELETE", &format!("/api/v1/sessions/{id}"), &Value::Null)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

#[cfg(unix)]
#[tokio::test]
async fn browse_stays_inside_the_roots() {
    let env = Env::writable();
    let root = env.captures();
    std::fs::create_dir_all(root.join("b_dir/inner")).unwrap();
    std::fs::create_dir_all(root.join("a_dir")).unwrap();
    std::fs::write(root.join("file.pcap"), b"0123456789abcdef").unwrap();
    std::fs::write(root.join(".hidden"), b"x").unwrap();
    let secret = env.tmp.path().join("secret");
    std::fs::create_dir_all(&secret).unwrap();
    std::fs::write(secret.join("passwords.txt"), b"x").unwrap();
    std::os::unix::fs::symlink(&secret, root.join("escape")).unwrap();
    std::os::unix::fs::symlink(root.join("a_dir"), root.join("inside_link")).unwrap();
    let _socket = std::os::unix::net::UnixListener::bind(root.join("special.sock")).unwrap();

    let (status, json) = env.call("GET", "/api/v1/fs/browse", &Value::Null).await;
    assert_eq!(status, StatusCode::OK, "{json}");
    let listing: contract::BrowseResponse = serde_json::from_value(json).unwrap();
    assert_eq!(listing.path, root.to_str().unwrap());
    assert_eq!(listing.parent, None);
    assert_eq!(listing.roots, [root.to_str().unwrap()]);
    let names: Vec<(&str, bool, u64)> = listing
        .entries
        .iter()
        .map(|e| (e.name.as_str(), e.is_dir, e.size))
        .collect();
    assert_eq!(
        names,
        [
            ("a_dir", true, 0),
            ("b_dir", true, 0),
            ("inside_link", true, 0),
            ("file.pcap", false, 16)
        ]
    );

    let inner = root.join("b_dir/inner");
    let (status, json) = env
        .call(
            "GET",
            &format!("/api/v1/fs/browse?path={}", inner.display()),
            &Value::Null,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["parent"], root.join("b_dir").to_str().unwrap());

    let traversal = format!("{}/b_dir/../..", root.display());
    let (status, _) = env
        .call(
            "GET",
            &format!("/api/v1/fs/browse?path={traversal}"),
            &Value::Null,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    for path in [
        root.join("escape"),
        env.tmp.path().to_path_buf(),
        PathBuf::from("/"),
    ] {
        let (status, json) = env
            .call(
                "GET",
                &format!("/api/v1/fs/browse?path={}", path.display()),
                &Value::Null,
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{}", path.display());
        assert_eq!(json["type"], "urn:netsift:problem:forbidden");
    }
    // A symlink leading outside cannot be imported either.
    let (status, _) = env
        .call(
            "POST",
            "/api/v1/sessions/import/scan",
            &json!({ "path": root.join("escape").to_str().unwrap() }),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn shutdown_ends_streams_and_cancels_imports() {
    let env = Env::new(false, false, slow_ingest());
    let run = env.captures().join("long");
    write_chunks(&run, "cap", 20);
    let id = env.import(&run).await;
    let app = env.app.clone();
    let uri = format!("/api/v1/sessions/{id}/events");
    let stream = tokio::spawn(async move {
        let res = app.oneshot(req("GET", &uri, &Value::Null)).await.unwrap();
        read(res).await
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    env.state.begin_shutdown();
    let (status, _, _) = tokio::time::timeout(Duration::from_secs(5), stream)
        .await
        .expect("the SSE stream did not end at shutdown")
        .unwrap();
    assert_eq!(status, StatusCode::OK);
    assert!(env.state.wait_imports(IMPORT_GRACE).await);
    assert_eq!(
        catalog_state(&env, &id),
        netsift_store::SessionState::Incomplete
    );
    let (status, json) = env
        .call(
            "POST",
            "/api/v1/sessions/import",
            &json!({ "path": run.to_str().unwrap() }),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{json}");
}

/// Minimal HTTP/1.1 exchange over a raw socket; returns the response head and body so far.
async fn raw_request(addr: std::net::SocketAddr, head: &str, body: &str) -> String {
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let request = format!(
        "{head}\r\nHost: {addr}\r\nAuthorization: {BEARER}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    String::from_utf8_lossy(&buf).into_owned()
}

#[tokio::test]
async fn serve_shutdown_is_bounded_with_open_streams() {
    let env = Env::new(false, false, slow_ingest());
    let run = env.captures().join("served");
    write_chunks(&run, "cap", 20);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let app = (env.app.clone(), Arc::clone(&env.state));
    let server = tokio::spawn(serve_with(listener, app, async {
        let _ = rx.await;
    }));

    let body = json!({ "path": run.to_str().unwrap() }).to_string();
    let response = raw_request(addr, "POST /api/v1/sessions/import HTTP/1.1", &body).await;
    assert!(response.starts_with("HTTP/1.1 202"), "{response}");
    let id = response
        .split("\"session_id\":\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .unwrap()
        .to_owned();
    let events = tokio::spawn(async move {
        raw_request(
            addr,
            &format!("GET /api/v1/sessions/{id}/events HTTP/1.1"),
            "",
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    let started = std::time::Instant::now();
    tx.send(()).unwrap();
    tokio::time::timeout(SHUTDOWN_GRACE + IMPORT_GRACE, server)
        .await
        .expect("serve did not stop")
        .unwrap()
        .unwrap();
    assert!(started.elapsed() < SHUTDOWN_GRACE + IMPORT_GRACE);
    let streamed = events.await.unwrap();
    assert!(streamed.starts_with("HTTP/1.1 200"), "{streamed}");
    assert!(streamed.contains("text/event-stream"));
    let catalog = Catalog::open(env.tmp.path().join("data")).unwrap();
    let sessions = catalog.list().unwrap();
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].state, netsift_store::SessionState::Incomplete);
}

#[tokio::test]
async fn unknown_routes_are_problem_json_404() {
    for uri in ["/api/v1/nope", "/elsewhere"] {
        let (status, headers, json) = send(get(uri)).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{uri}");
        assert_eq!(headers[header::CONTENT_TYPE], "application/problem+json");
        assert_eq!(json["type"], "urn:netsift:problem:not-found");
    }
}

#[tokio::test]
async fn cors_allows_only_configured_origins() {
    let preflight = |origin: &'static str| {
        Request::builder()
            .method("OPTIONS")
            .uri("/api/v1/server-info")
            .header(header::ORIGIN, origin)
            .header(header::ACCESS_CONTROL_REQUEST_METHOD, "GET")
            .header(header::ACCESS_CONTROL_REQUEST_HEADERS, "authorization")
            .body(Body::empty())
            .unwrap()
    };
    let (_, headers, _) = send(preflight("tauri://localhost")).await;
    assert_eq!(
        headers[header::ACCESS_CONTROL_ALLOW_ORIGIN],
        "tauri://localhost"
    );
    let (_, headers, _) = send(preflight("http://evil.example")).await;
    assert!(headers.get(header::ACCESS_CONTROL_ALLOW_ORIGIN).is_none());
}

#[tokio::test]
async fn serve_binds_and_shuts_down() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(serve(listener, config(), async {
        let _ = rx.await;
    }));
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"GET /api/v1/health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    assert!(String::from_utf8_lossy(&buf).starts_with("HTTP/1.1 200"));
    tx.send(()).unwrap();
    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn wrong_method_is_problem_json_405() {
    let req = Request::post("/api/v1/health").body(Body::empty()).unwrap();
    let (status, headers, json) = send(req).await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(headers[header::CONTENT_TYPE], "application/problem+json");
    assert_eq!(json["type"], "urn:netsift:problem:method-not-allowed");
}

#[test]
fn debug_never_prints_the_token() {
    let printed = format!("{:?}", config());
    assert!(!printed.contains("s3cret-token"));
    assert!(printed.contains("<redacted>"));
}
