//! Database updates against a local HTTP server standing for download.db-ip.com (never the
//! real network), and from files. Databases are synthetic (`netsift_geo::test_util`).

use std::collections::HashMap;
use std::convert::Infallible;
use std::io::Write as _;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{Path as UrlPath, State};
use axum::http::{HeaderMap, HeaderValue, Request, StatusCode, header};
use axum::response::{IntoResponse, Response};
use flate2::Compression;
use flate2::write::GzEncoder;
use netsift_engine::IngestOptions;
use netsift_geo::test_util::MmdbBuilder;
use serde_json::{Value, json};
use tokio::sync::mpsc;
use tower::ServiceExt;

use super::download::{self, DownloadError, Source};
use super::*;
use crate::{ApiConfig, DEFAULT_MAX_IMPORTS, build};

const TOKEN: &str = "geoip-token";

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

/// Country database mapping the control address 8.8.8.8 (and 81/8) to `code`.
fn db(code: &str) -> Vec<u8> {
    MmdbBuilder::new()
        .network(ip("8.8.8.0"), 24, code)
        .network(ip("81.0.0.0"), 8, code)
        .build()
}

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut enc = GzEncoder::new(Vec::new(), Compression::fast());
    enc.write_all(bytes).unwrap();
    enc.finish().unwrap()
}

fn month_files() -> [String; 2] {
    download::months(SystemTime::now()).map(download::file_name)
}

// ---------------------------------------------------------------------------------------------
// Local upstream server

#[derive(Clone)]
enum Reply {
    Body(Vec<u8>),
    Status(StatusCode),
    Redirect(String),
    /// Body streamed from a channel, without `Content-Length`.
    Stream(Arc<Mutex<Option<mpsc::Receiver<Bytes>>>>),
}

#[derive(Default)]
struct Upstream {
    replies: Mutex<HashMap<String, Reply>>,
    /// Requested file names and request headers.
    hits: Mutex<Vec<(String, HeaderMap)>>,
}

async fn upstream_file(
    UrlPath(name): UrlPath<String>,
    headers: HeaderMap,
    State(up): State<Arc<Upstream>>,
) -> Response {
    up.hits.lock().unwrap().push((name.clone(), headers));
    let reply = up.replies.lock().unwrap().get(&name).cloned();
    match reply {
        None => StatusCode::NOT_FOUND.into_response(),
        Some(Reply::Body(bytes)) => bytes.into_response(),
        Some(Reply::Status(code)) => code.into_response(),
        Some(Reply::Redirect(to)) => (StatusCode::FOUND, [(header::LOCATION, to)]).into_response(),
        Some(Reply::Stream(rx)) => {
            let rx = rx.lock().unwrap().take().unwrap();
            let stream = futures_util::stream::unfold(rx, |mut rx| async move {
                rx.recv().await.map(|b| (Ok::<_, Infallible>(b), rx))
            });
            Body::from_stream(stream).into_response()
        }
    }
}

/// Starts the upstream server; returns its address.
async fn serve_upstream(up: &Arc<Upstream>) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new()
        .route("/free/{name}", axum::routing::get(upstream_file))
        .with_state(Arc::clone(up));
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

fn source(addr: SocketAddr) -> Source {
    Source {
        base: format!("http://{addr}/free/"),
        allow_http: true,
    }
}

// ---------------------------------------------------------------------------------------------
// API under test

struct Env {
    tmp: tempfile::TempDir,
    app: Router,
    state: Arc<AppState>,
    up: Arc<Upstream>,
}

impl Env {
    async fn new(read_only: bool, bundled: Option<Vec<u8>>) -> Self {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join("captures")).unwrap();
        let bundled_path = bundled.map(|bytes| {
            let path = tmp.path().join("bundle").join(netsift_geo::DB_FILE_NAME);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, bytes).unwrap();
            path
        });
        let config = ApiConfig {
            token: TOKEN.to_owned(),
            data_dir: tmp.path().join("data"),
            captures_roots: vec![tmp.path().join("captures")],
            read_only,
            cors_origins: vec![HeaderValue::from_static("tauri://localhost")],
            allow_any_path: false,
            max_imports: DEFAULT_MAX_IMPORTS,
            geoip_fallback_path: bundled_path,
        };
        let (app, state) = build(config, IngestOptions::default());
        let up = Arc::new(Upstream::default());
        state.geoip.set_source(source(serve_upstream(&up).await));
        Self {
            tmp,
            app,
            state,
            up,
        }
    }

    fn reply(&self, name: &str, reply: Reply) {
        self.up
            .replies
            .lock()
            .unwrap()
            .insert(name.to_owned(), reply);
    }

    fn user_path(&self) -> PathBuf {
        netsift_geo::default_path(&self.tmp.path().join("data"))
    }

    fn captures(&self) -> PathBuf {
        std::fs::canonicalize(self.tmp.path().join("captures")).unwrap()
    }

    async fn call(&self, method: &str, uri: &str, body: &Value) -> (StatusCode, HeaderMap, Value) {
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
        let bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
            .await
            .unwrap();
        let json = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap()
        };
        (status, headers, json)
    }

    async fn download(&self) -> (StatusCode, HeaderMap, Value) {
        self.call("POST", "/api/v1/geoip/download", &Value::Null)
            .await
    }

    async fn import(&self, path: &Path) -> (StatusCode, HeaderMap, Value) {
        self.call(
            "POST",
            "/api/v1/geoip/import",
            &json!({ "path": path.to_str().unwrap() }),
        )
        .await
    }

    async fn server_geoip(&self) -> Value {
        let (status, _, json) = self.call("GET", "/api/v1/server-info", &Value::Null).await;
        assert_eq!(status, StatusCode::OK);
        json["geoip"].clone()
    }

    /// Country of 8.8.8.8 in the database the next import would get.
    fn next_import_country(&self) -> Option<String> {
        let (db, _) = self.state.geoip.current();
        db?.country(ip("8.8.8.8")).map(|c| c.to_string())
    }

    fn install_user(&self, code: &str) {
        let path = self.user_path();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, db(code)).unwrap();
    }
}

/// A problem document of `kind` that names no file.
fn assert_problem(env: &Env, (status, headers, json): &(StatusCode, HeaderMap, Value), kind: &str) {
    assert_eq!(
        headers[header::CONTENT_TYPE],
        "application/problem+json",
        "{status} {json}"
    );
    assert_eq!(
        json["type"],
        format!("urn:netsift:problem:{kind}"),
        "{json}"
    );
    let text = json.to_string();
    let tmp = env.tmp.path().to_string_lossy();
    assert!(!text.contains(tmp.as_ref()), "path leaked: {text}");
    assert!(!text.contains(".mmdb"), "file name leaked: {text}");
}

// ---------------------------------------------------------------------------------------------
// Download

#[tokio::test]
async fn downloads_the_current_month_with_a_generic_user_agent() {
    let env = Env::new(false, None).await;
    let [current, _] = month_files();
    env.reply(&current, Reply::Body(gzip(&db("FR"))));
    assert_eq!(env.next_import_country(), None);

    let (status, _, json) = env.download().await;
    assert_eq!(status, StatusCode::OK, "{json}");
    assert_eq!(json["status"], "available");
    assert_eq!(json["source"], "user");
    assert_eq!(json["built_at_us"], 1_700_000_000_000_000_i64);
    assert_eq!(json["size_bytes"], db("FR").len());
    assert!(json["installed_at_us"].is_i64());
    assert_eq!(std::fs::read(env.user_path()).unwrap(), db("FR"));
    // Hot reload: the next import gets the new database, and /server-info agrees.
    assert_eq!(env.next_import_country().as_deref(), Some("FR"));
    assert_eq!(env.server_geoip().await, json);

    let hits = env.up.hits.lock().unwrap();
    assert_eq!(hits.len(), 1);
    let (name, headers) = &hits[0];
    assert_eq!(name, &current);
    let agent = headers[header::USER_AGENT].to_str().unwrap();
    assert_eq!(agent, concat!("NetSift/", env!("CARGO_PKG_VERSION")));
    for h in [header::COOKIE, header::AUTHORIZATION, header::REFERER] {
        assert!(!headers.contains_key(&h), "{h} sent");
    }
}

#[tokio::test]
async fn falls_back_to_the_previous_month_on_404() {
    let env = Env::new(false, None).await;
    let [current, previous] = month_files();
    env.reply(&previous, Reply::Body(gzip(&db("DE"))));
    let (status, _, json) = env.download().await;
    assert_eq!(status, StatusCode::OK, "{json}");
    assert_eq!(env.next_import_country().as_deref(), Some("DE"));
    let names: Vec<_> = env
        .up
        .hits
        .lock()
        .unwrap()
        .iter()
        .map(|h| h.0.clone())
        .collect();
    assert_eq!(names, [current, previous]);
}

#[tokio::test]
async fn failures_keep_the_current_database() {
    let env = Env::new(false, None).await;
    env.install_user("FR");
    let [current, previous] = month_files();

    // Neither month published.
    let res = env.download().await;
    assert_eq!(res.0, StatusCode::BAD_GATEWAY);
    assert_problem(&env, &res, "geoip-download-failed");

    // Server error: no fallback to the previous month.
    env.reply(&current, Reply::Status(StatusCode::INTERNAL_SERVER_ERROR));
    env.reply(&previous, Reply::Body(gzip(&db("DE"))));
    let res = env.download().await;
    assert_eq!(res.0, StatusCode::BAD_GATEWAY);
    assert_problem(&env, &res, "geoip-download-failed");

    // Invalid contents: an HTML page, broken gzip, a database of another kind, one without
    // any control answer.
    let invalid = [
        b"<html>maintenance</html>".to_vec(),
        gzip(b"not a database"),
        gzip(&db("DE"))[..30].to_vec(),
        gzip(
            &MmdbBuilder::new()
                .database_type("DBIP-City-Lite")
                .network(ip("8.8.8.0"), 24, "DE")
                .build(),
        ),
        gzip(&MmdbBuilder::new().network(ip("81.0.0.0"), 8, "DE").build()),
    ];
    for body in invalid {
        env.reply(&current, Reply::Body(body));
        let res = env.download().await;
        assert_eq!(res.0, StatusCode::UNPROCESSABLE_ENTITY, "{}", res.2);
        assert_problem(&env, &res, "geoip-invalid");
    }

    assert_eq!(std::fs::read(env.user_path()).unwrap(), db("FR"));
    assert_eq!(env.next_import_country().as_deref(), Some("FR"));
    let files: Vec<_> = std::fs::read_dir(env.user_path().parent().unwrap())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(files, [netsift_geo::DB_FILE_NAME], "temporary files left");
}

#[tokio::test]
async fn redirections_stay_on_the_same_origin() {
    let env = Env::new(false, None).await;
    let [current, _] = month_files();
    let base = env.state.geoip.source().base;

    // Same origin: followed.
    env.reply(&current, Reply::Redirect(format!("{base}mirror.gz")));
    env.reply("mirror.gz", Reply::Body(gzip(&db("FR"))));
    let (status, _, json) = env.download().await;
    assert_eq!(status, StatusCode::OK, "{json}");

    // Another host (same server reached as `localhost`): refused, never requested.
    let other = base.replace("127.0.0.1", "localhost");
    env.reply(&current, Reply::Redirect(format!("{other}other.gz")));
    env.reply("other.gz", Reply::Body(gzip(&db("DE"))));
    let res = env.download().await;
    assert_problem(&env, &res, "geoip-download-failed");
    assert!(
        !env.up
            .hits
            .lock()
            .unwrap()
            .iter()
            .any(|h| h.0 == "other.gz")
    );

    // Redirection loop: bounded.
    env.reply(&current, Reply::Redirect(format!("{base}{current}")));
    let res = env.download().await;
    assert_problem(&env, &res, "geoip-download-failed");
    assert_eq!(env.next_import_country().as_deref(), Some("FR"));
}

#[tokio::test]
async fn the_body_size_is_bounded_while_receiving() {
    let up = Arc::new(Upstream::default());
    let source = source(serve_upstream(&up).await);
    let [current, _] = month_files();
    let fetch = |max| download::fetch(&source, SystemTime::now(), max, |_, _| {});

    // Announced size above the bound.
    up.replies
        .lock()
        .unwrap()
        .insert(current.clone(), Reply::Body(vec![0; 2_000]));
    assert!(matches!(fetch(1_000).await, Err(DownloadError::TooLarge)));
    assert_eq!(fetch(2_000).await.unwrap().len(), 2_000);

    // No announced size: stopped as soon as the bound is crossed.
    let (tx, rx) = mpsc::channel(4);
    up.replies.lock().unwrap().insert(
        current.clone(),
        Reply::Stream(Arc::new(Mutex::new(Some(rx)))),
    );
    tx.send(Bytes::from(vec![0; 800])).await.unwrap();
    tx.send(Bytes::from(vec![0; 800])).await.unwrap();
    // The sender stays open: the client must not wait for the end of the body.
    let result = tokio::time::timeout(Duration::from_secs(10), fetch(1_000))
        .await
        .unwrap();
    assert!(matches!(result, Err(DownloadError::TooLarge)));
    drop(tx);
}

#[tokio::test]
async fn too_large_maps_to_its_own_problem() {
    assert!(matches!(
        install_error(GeoError::TooLarge),
        ApiError::GeoipTooLarge
    ));
    let env = Env::new(false, None).await;
    let big = env.captures().join("big.mmdb");
    std::fs::File::create(&big)
        .unwrap()
        .set_len(netsift_geo::MAX_DB_BYTES + 1)
        .unwrap();
    let res = env.import(&big).await;
    assert_eq!(res.0, StatusCode::PAYLOAD_TOO_LARGE);
    assert_problem(&env, &res, "geoip-too-large");
}

#[tokio::test]
async fn progress_is_reported_and_one_update_runs_at_a_time() {
    let env = Env::new(false, None).await;
    let [current, _] = month_files();
    let body = gzip(&db("FR"));
    let (tx, rx) = mpsc::channel(4);
    env.reply(&current, Reply::Stream(Arc::new(Mutex::new(Some(rx)))));
    let (status, _, json) = env.call("GET", "/api/v1/geoip/update", &Value::Null).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        json,
        json!({ "phase": "idle", "received_bytes": 0, "total_bytes": null })
    );

    let app = env.app.clone();
    let running = tokio::spawn(async move {
        let req = Request::post("/api/v1/geoip/download")
            .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
            .body(Body::empty())
            .unwrap();
        app.oneshot(req).await.unwrap().status()
    });
    let (first, rest) = body.split_at(10);
    tx.send(Bytes::copy_from_slice(first)).await.unwrap();
    let mut seen = Value::Null;
    for _ in 0..200 {
        seen = env
            .call("GET", "/api/v1/geoip/update", &Value::Null)
            .await
            .2;
        if seen["received_bytes"] == 10 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        seen,
        json!({ "phase": "downloading", "received_bytes": 10, "total_bytes": null })
    );

    // A second update while the first runs: refused, download or import alike.
    let res = env.download().await;
    assert_eq!(res.0, StatusCode::CONFLICT);
    assert_problem(&env, &res, "geoip-update-running");
    let file = env.captures().join("db.mmdb");
    std::fs::write(&file, db("DE")).unwrap();
    let res = env.import(&file).await;
    assert_problem(&env, &res, "geoip-update-running");

    tx.send(Bytes::copy_from_slice(rest)).await.unwrap();
    drop(tx);
    assert_eq!(running.await.unwrap(), StatusCode::OK);
    assert_eq!(env.next_import_country().as_deref(), Some("FR"));
    let (_, _, json) = env.call("GET", "/api/v1/geoip/update", &Value::Null).await;
    assert_eq!(json["phase"], "idle");
    // Released: the next update may run.
    assert_eq!(env.import(&file).await.0, StatusCode::OK);
}

// ---------------------------------------------------------------------------------------------
// Import from a file

#[tokio::test]
async fn imports_raw_and_gzip_files_inside_the_roots() {
    let env = Env::new(false, None).await;
    let raw = env.captures().join("country.mmdb");
    std::fs::write(&raw, db("FR")).unwrap();
    let (status, _, json) = env.import(&raw).await;
    assert_eq!(status, StatusCode::OK, "{json}");
    assert_eq!(json["source"], "user");
    assert_eq!(env.next_import_country().as_deref(), Some("FR"));

    let gz = env.captures().join("country.mmdb.gz");
    std::fs::write(&gz, gzip(&db("DE"))).unwrap();
    assert_eq!(env.import(&gz).await.0, StatusCode::OK);
    assert_eq!(env.next_import_country().as_deref(), Some("DE"));
    assert_eq!(std::fs::read(env.user_path()).unwrap(), db("DE"));
    // The chosen file is copied, never moved.
    assert!(gz.is_file());
}

#[tokio::test]
async fn refused_files_keep_the_current_database() {
    let env = Env::new(false, None).await;
    env.install_user("FR");

    let garbage = env.captures().join("garbage.mmdb");
    std::fs::write(&garbage, b"not a database").unwrap();
    let res = env.import(&garbage).await;
    assert_eq!(res.0, StatusCode::UNPROCESSABLE_ENTITY);
    assert_problem(&env, &res, "geoip-invalid");

    let res = env.import(&env.captures()).await;
    assert_eq!(res.0, StatusCode::BAD_REQUEST);
    assert_problem(&env, &res, "bad-request");

    let res = env.import(&env.captures().join("missing.mmdb")).await;
    assert_eq!(res.0, StatusCode::NOT_FOUND);

    // Outside the allowed roots (dev web mode).
    let outside = env.tmp.path().join("outside.mmdb");
    std::fs::write(&outside, db("DE")).unwrap();
    let res = env.import(&outside).await;
    assert_eq!(res.0, StatusCode::FORBIDDEN);
    assert_problem(&env, &res, "forbidden");

    let res = env
        .call(
            "POST",
            "/api/v1/geoip/import",
            &json!({ "path": "relative.mmdb" }),
        )
        .await;
    assert_eq!(res.0, StatusCode::BAD_REQUEST);

    assert_eq!(std::fs::read(env.user_path()).unwrap(), db("FR"));
    assert_eq!(env.next_import_country().as_deref(), Some("FR"));
}

#[tokio::test]
async fn updates_are_refused_on_a_read_only_server() {
    let env = Env::new(true, None).await;
    let [current, _] = month_files();
    env.reply(&current, Reply::Body(gzip(&db("FR"))));
    let file = env.captures().join("db.mmdb");
    std::fs::write(&file, db("FR")).unwrap();

    let res = env.download().await;
    assert_eq!(res.0, StatusCode::FORBIDDEN);
    assert_problem(&env, &res, "read-only");
    let res = env.import(&file).await;
    assert_problem(&env, &res, "read-only");
    // Nothing was requested upstream nor written.
    assert!(env.up.hits.lock().unwrap().is_empty());
    assert!(!env.user_path().exists());
    // The progress stays readable.
    assert_eq!(
        env.call("GET", "/api/v1/geoip/update", &Value::Null)
            .await
            .0,
        StatusCode::OK
    );
}

// ---------------------------------------------------------------------------------------------
// Sources and hot reload

#[tokio::test]
async fn the_user_copy_takes_precedence_over_the_bundled_one() {
    let env = Env::new(false, Some(db("US"))).await;
    let geoip = env.server_geoip().await;
    assert_eq!(geoip["source"], "bundled");
    assert_eq!(env.next_import_country().as_deref(), Some("US"));

    // An unusable user copy does not hide the bundled one.
    let user = env.user_path();
    std::fs::create_dir_all(user.parent().unwrap()).unwrap();
    std::fs::write(&user, b"broken").unwrap();
    assert_eq!(env.server_geoip().await["source"], "bundled");

    let file = env.captures().join("db.mmdb");
    std::fs::write(&file, db("FR")).unwrap();
    assert_eq!(env.import(&file).await.0, StatusCode::OK);
    assert_eq!(env.server_geoip().await["source"], "user");
    assert_eq!(env.next_import_country().as_deref(), Some("FR"));
    // The bundled copy is never written.
    assert_eq!(
        std::fs::read(
            env.tmp
                .path()
                .join("bundle")
                .join(netsift_geo::DB_FILE_NAME)
        )
        .unwrap(),
        db("US")
    );
}

#[tokio::test]
async fn a_running_import_keeps_the_database_it_started_with() {
    let env = Env::new(false, None).await;
    env.install_user("FR");
    let (started_with, _) = env.state.geoip.current();
    let started_with = started_with.unwrap();

    let file = env.captures().join("db.mmdb");
    std::fs::write(&file, db("DE")).unwrap();
    assert_eq!(env.import(&file).await.0, StatusCode::OK);

    assert_eq!(started_with.country(ip("8.8.8.8")).unwrap().as_str(), "FR");
    assert_eq!(env.next_import_country().as_deref(), Some("DE"));
}

#[cfg(unix)]
#[tokio::test]
async fn a_file_replaced_behind_the_server_with_the_same_size_and_time_is_noticed() {
    let env = Env::new(false, None).await;
    env.install_user("FR");
    assert_eq!(env.next_import_country().as_deref(), Some("FR"));
    let user = env.user_path();
    let modified = std::fs::metadata(&user).unwrap().modified().unwrap();

    // Same size and modification time, new inode (replaced by a rename, as `./x.sh geoip` does).
    let next = user.with_extension("next");
    std::fs::write(&next, db("DE")).unwrap();
    std::fs::File::options()
        .write(true)
        .open(&next)
        .unwrap()
        .set_modified(modified)
        .unwrap();
    std::fs::rename(&next, &user).unwrap();
    assert_eq!(
        std::fs::metadata(&user).unwrap().len(),
        db("FR").len() as u64
    );
    assert_eq!(env.next_import_country().as_deref(), Some("DE"));
}

#[tokio::test]
async fn interrupted_update_files_are_removed_at_startup_unless_read_only() {
    for read_only in [true, false] {
        let tmp = tempfile::TempDir::new().unwrap();
        let data = tmp.path().join("data");
        let user = netsift_geo::default_path(&data);
        std::fs::create_dir_all(user.parent().unwrap()).unwrap();
        std::fs::write(&user, db("FR")).unwrap();
        let orphan = user.with_file_name(format!(".{}.1.2.0.tmp", netsift_geo::DB_FILE_NAME));
        std::fs::write(&orphan, b"partial").unwrap();
        let config = ApiConfig {
            token: TOKEN.to_owned(),
            data_dir: data,
            captures_roots: vec![],
            read_only,
            cors_origins: vec![],
            allow_any_path: false,
            max_imports: DEFAULT_MAX_IMPORTS,
            geoip_fallback_path: None,
        };
        let _ = build(config, IngestOptions::default());
        assert_eq!(orphan.exists(), read_only, "read_only = {read_only}");
        assert_eq!(std::fs::read(&user).unwrap(), db("FR"));
    }
}
