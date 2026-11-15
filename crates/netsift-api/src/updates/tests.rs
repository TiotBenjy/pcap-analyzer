//! Update check and download against a local HTTP server standing for api.github.com and
//! github.com (never the real network).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::{Path as UrlPath, State};
use axum::http::{HeaderMap, HeaderValue, Request, header};
use axum::response::{IntoResponse, Response};
use netsift_engine::IngestOptions;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use tower::ServiceExt;

use super::*;
use crate::{ApiConfig, DEFAULT_MAX_IMPORTS, build};

const TOKEN: &str = "update-token";
const NEWER: &str = "v999.0.0";
const APPIMAGE: &str = "NetSift_999.0.0_amd64.AppImage";
const DEB: &str = "NetSift_999.0.0_amd64.deb";
const RPM: &str = "NetSift-999.0.0-1.x86_64.rpm";
const SETUP: &str = "NetSift_999.0.0_x64-setup.exe";
const DMG: &str = "NetSift_999.0.0_universal.dmg";

// ---------------------------------------------------------------------------------------------
// Local upstream server

#[derive(Clone)]
enum Reply {
    Body(Vec<u8>),
    Status(StatusCode),
    Redirect(String),
    /// Announces `.1` bytes, sends `.0`, then never ends.
    Stall(Vec<u8>, usize),
}

#[derive(Default)]
struct Upstream {
    replies: Mutex<HashMap<String, Reply>>,
    /// Requested paths and request headers.
    hits: Mutex<Vec<(String, HeaderMap)>>,
}

async fn upstream(
    UrlPath(path): UrlPath<String>,
    headers: HeaderMap,
    State(up): State<Arc<Upstream>>,
) -> Response {
    up.hits.lock().unwrap().push((path.clone(), headers));
    let reply = up.replies.lock().unwrap().get(&path).cloned();
    match reply {
        None => StatusCode::NOT_FOUND.into_response(),
        Some(Reply::Body(bytes)) => bytes.into_response(),
        Some(Reply::Status(code)) => code.into_response(),
        Some(Reply::Redirect(to)) => (StatusCode::FOUND, [(header::LOCATION, to)]).into_response(),
        Some(Reply::Stall(first, total)) => {
            use futures_util::StreamExt as _;
            let stream = futures_util::stream::once(async move {
                Ok::<_, std::convert::Infallible>(axum::body::Bytes::from(first))
            })
            .chain(futures_util::stream::pending());
            (
                [(header::CONTENT_LENGTH, total.to_string())],
                Body::from_stream(stream),
            )
                .into_response()
        }
    }
}

async fn serve_upstream(up: &Arc<Upstream>) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new()
        .route("/{*path}", axum::routing::get(upstream))
        .with_state(Arc::clone(up));
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

fn sha256_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    Sha256::digest(bytes)
        .iter()
        .fold(String::new(), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

// ---------------------------------------------------------------------------------------------
// API under test

struct Env {
    tmp: tempfile::TempDir,
    app: Router,
    state: Arc<AppState>,
    up: Arc<Upstream>,
    addr: SocketAddr,
}

/// Desktop server (`allow_any_path`) unless `web`.
async fn env_with(web: bool, settings: &str) -> Env {
    let tmp = tempfile::TempDir::new().unwrap();
    let data = tmp.path().join("data");
    std::fs::create_dir_all(&data).unwrap();
    std::fs::write(data.join(crate::settings::FILE_NAME), settings).unwrap();
    let config = ApiConfig {
        token: TOKEN.to_owned(),
        data_dir: data,
        captures_roots: Vec::new(),
        read_only: false,
        cors_origins: vec![HeaderValue::from_static("tauri://localhost")],
        allow_any_path: !web,
        max_imports: DEFAULT_MAX_IMPORTS,
        geoip_fallback_path: None,
    };
    let (app, state) = build(config, IngestOptions::default());
    let up = Arc::new(Upstream::default());
    let addr = serve_upstream(&up).await;
    let updates = state.online.get::<Updates>();
    let local = Policy::new(&["127.0.0.1"]).local_http_for_tests();
    updates.set_source(Source {
        latest_url: format!("http://{addr}/repos/o/r/releases/latest"),
        release_prefix: format!("http://{addr}/o/r/releases/"),
        check_policy: local.clone(),
        download_policy: local,
    });
    updates.set_platform(Platform {
        os: "linux",
        arch: "x86_64",
        installed: Some(PackageFormat::Deb),
    });
    Env {
        tmp,
        app,
        state,
        up,
        addr,
    }
}

async fn env() -> Env {
    env_with(false, "{}").await
}

impl Env {
    fn reply(&self, path: &str, reply: Reply) {
        self.up
            .replies
            .lock()
            .unwrap()
            .insert(path.to_owned(), reply);
    }

    fn hits(&self) -> Vec<String> {
        self.up
            .hits
            .lock()
            .unwrap()
            .iter()
            .map(|h| h.0.clone())
            .collect()
    }

    fn asset_url(&self, name: &str) -> String {
        format!("http://{}/o/r/releases/download/{NEWER}/{name}", self.addr)
    }

    fn asset_path(name: &str) -> String {
        format!("o/r/releases/download/{NEWER}/{name}")
    }

    /// Publishes `tag` with `files` (name, contents) and their `SHA256SUMS.txt`.
    fn publish(&self, tag: &str, files: &[(&str, &[u8])]) {
        let sums = files.iter().fold(String::new(), |mut s, (name, body)| {
            s.push_str(&sha256_hex(body));
            s.push_str("  ");
            s.push_str(name);
            s.push('\n');
            s
        });
        for (name, body) in files {
            self.reply(&Self::asset_path(name), Reply::Body(body.to_vec()));
        }
        self.reply(
            &Self::asset_path(SUMS_NAME),
            Reply::Body(sums.clone().into_bytes()),
        );
        let mut assets: Vec<Value> = files
            .iter()
            .map(|(name, body)| self.asset_json(name, body.len()))
            .collect();
        assets.push(self.asset_json(SUMS_NAME, sums.len()));
        self.release_json(&json!({
            "tag_name": tag,
            "draft": false,
            "prerelease": false,
            "html_url": format!("http://{}/o/r/releases/tag/{tag}", self.addr),
            "name": format!("NetSift {tag} \u{2014} Faster\u{202e} imports\n"),
            "body": "## Fixes\n\n- <b>one</b>",
            "assets": assets,
            "author": { "login": "someone" },
        }));
    }

    fn asset_json(&self, name: &str, size: usize) -> Value {
        json!({
            "name": name,
            "size": size,
            "browser_download_url": self.asset_url(name),
            "content_type": "application/octet-stream",
        })
    }

    fn release_json(&self, release: &Value) {
        self.reply(
            "repos/o/r/releases/latest",
            Reply::Body(release.to_string().into_bytes()),
        );
    }

    async fn call(&self, method: &str, uri: &str, body: &Value) -> (StatusCode, Value) {
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
        let bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
            .await
            .unwrap();
        let json = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap()
        };
        (status, json)
    }

    async fn check(&self) -> (StatusCode, Value) {
        self.call("POST", "/api/v1/updates/check", &Value::Null)
            .await
    }

    async fn download(&self, asset: &str, path: &str) -> (StatusCode, Value) {
        self.call(
            "POST",
            "/api/v1/updates/download",
            &json!({ "asset": asset, "path": path }),
        )
        .await
    }

    /// Waits for the download to end; returns its final state.
    async fn finished(&self) -> Value {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let (_, state) = self
                    .call("GET", "/api/v1/updates/download", &Value::Null)
                    .await;
                if state["phase"] != "downloading" {
                    return state;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap()
    }

    fn dest(&self, name: &str) -> PathBuf {
        self.tmp.path().join("downloads").join(name)
    }

    fn downloads(&self) -> Vec<String> {
        let mut names: Vec<_> = std::fs::read_dir(self.tmp.path().join("downloads"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }
}

fn linux_files() -> Vec<(&'static str, &'static [u8])> {
    vec![
        (APPIMAGE, b"appimage-bytes"),
        (DEB, b"deb-bytes"),
        (RPM, b"rpm-bytes"),
        (SETUP, b"setup-bytes"),
        (DMG, b"dmg-bytes"),
    ]
}

// ---------------------------------------------------------------------------------------------
// Check

#[tokio::test]
async fn a_newer_release_is_reported_with_its_installers_and_plain_notes() {
    let env = env().await;
    env.publish(NEWER, &linux_files());
    let (status, body) = env.check().await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "available");
    assert_eq!(body["current_version"], CURRENT_VERSION);
    assert_eq!(body["latest_version"], "999.0.0");
    let release = &body["release"];
    assert_eq!(release["version"], "999.0.0");
    // Plain text, as published: never rendered by the UI.
    assert_eq!(release["notes"], "## Fixes\n\n- <b>one</b>");
    assert_eq!(release["notes_truncated"], false);
    // The title of the release name, without its control characters.
    assert_eq!(
        release["name"],
        format!("NetSift {NEWER} \u{2014} Faster imports")
    );
    assert_eq!(release["title"], "Faster imports");
    assert_eq!(
        release["html_url"],
        format!("http://{}/o/r/releases/tag/{NEWER}", env.addr)
    );
    // Installed from a .deb: offered first; other systems' installers left out.
    assert_eq!(
        release["installers"],
        json!([
            { "name": DEB, "size": 9, "format": "deb" },
            { "name": APPIMAGE, "size": 14, "format": "appimage" },
            { "name": RPM, "size": 9, "format": "rpm" },
        ])
    );
    assert_eq!(release["format_known"], true);

    // One request, with the headers GitHub asks for and nothing personal.
    let hits = env.up.hits.lock().unwrap().clone();
    assert_eq!(hits.len(), 1);
    let (path, headers) = &hits[0];
    assert_eq!(path, "repos/o/r/releases/latest");
    assert_eq!(headers[header::ACCEPT], "application/vnd.github+json");
    assert!(
        headers[header::USER_AGENT]
            .to_str()
            .unwrap()
            .starts_with("NetSift/")
    );
    assert!(!headers.contains_key(header::COOKIE));
    assert!(!headers.contains_key(header::AUTHORIZATION));

    // Kept for the banner and for the downloads.
    let (_, state) = env.call("GET", "/api/v1/updates", &Value::Null).await;
    assert_eq!(state["check"], body);
    assert_eq!(state["checking"], false);
    assert_eq!(state["can_download"], true);
    assert_eq!(state["current_version"], CURRENT_VERSION);
}

#[tokio::test]
async fn an_unknown_install_format_offers_the_default_first() {
    let env = env().await;
    env.state.online.get::<Updates>().set_platform(Platform {
        os: "windows",
        arch: "x86_64",
        installed: Some(PackageFormat::Msi),
    });
    // What the desktop app passes when Tauri does not know the bundle type.
    set_install_format(&env.state, None);
    env.publish(NEWER, &linux_files());
    let (_, body) = env.check().await;
    assert_eq!(body["release"]["installers"][0]["name"], SETUP);
    assert_eq!(body["release"]["format_known"], false);
}

#[tokio::test]
async fn equal_older_draft_and_prerelease_versions_are_up_to_date() {
    let env = env().await;
    for (tag, draft, prerelease, latest) in [
        (
            format!("v{CURRENT_VERSION}"),
            false,
            false,
            json!(CURRENT_VERSION),
        ),
        ("v0.0.1".to_owned(), false, false, json!("0.0.1")),
        (NEWER.to_owned(), true, false, Value::Null),
        (NEWER.to_owned(), false, true, Value::Null),
        ("v999.0.0-rc.1".to_owned(), false, false, Value::Null),
    ] {
        env.release_json(&json!({
            "tag_name": tag, "draft": draft, "prerelease": prerelease, "body": null, "assets": []
        }));
        let (status, body) = env.check().await;
        assert_eq!(status, StatusCode::OK, "{tag}: {body}");
        assert_eq!(body["status"], "up_to_date", "{tag}");
        assert_eq!(body["latest_version"], latest, "{tag}");
        assert_eq!(body["release"], Value::Null, "{tag}");
    }
    // No release published yet: 404, up to date.
    env.reply(
        "repos/o/r/releases/latest",
        Reply::Status(StatusCode::NOT_FOUND),
    );
    let (status, body) = env.check().await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "up_to_date");
    assert_eq!(body["latest_version"], Value::Null);
}

#[tokio::test]
async fn a_failed_check_is_reported_and_keeps_the_previous_result() {
    let env = env().await;
    env.publish(NEWER, &linux_files());
    assert_eq!(env.check().await.0, StatusCode::OK);

    for reply in [
        Reply::Status(StatusCode::FORBIDDEN),
        Reply::Body(b"<html>secret-marker</html>".to_vec()),
        Reply::Redirect("http://localhost:1/elsewhere".to_owned()),
    ] {
        env.reply("repos/o/r/releases/latest", reply);
        let (status, body) = env.check().await;
        assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
        assert_eq!(body["type"], "urn:netsift:problem:update-check-failed");
        assert!(!body.to_string().contains("secret-marker"));
    }
    let (_, state) = env.call("GET", "/api/v1/updates", &Value::Null).await;
    assert_eq!(state["check"]["status"], "available");
}

#[tokio::test]
async fn foreign_urls_in_the_release_are_dropped() {
    let env = env().await;
    env.release_json(&json!({
        "tag_name": NEWER,
        "html_url": "https://evil.example/release",
        "body": "notes",
        "assets": [
            { "name": DEB, "size": 3, "browser_download_url": "https://evil.example/x.deb" },
            { "name": SUMS_NAME, "size": 3, "browser_download_url": "https://evil.example/sums" },
        ],
    }));
    let (_, body) = env.check().await;
    assert_eq!(body["status"], "available");
    assert_eq!(body["release"]["html_url"], Value::Null);
    assert_eq!(body["release"]["installers"], json!([]));
    // No name in the JSON: no title either.
    assert_eq!(body["release"]["name"], Value::Null);
    assert_eq!(body["release"]["title"], Value::Null);
}

// ---------------------------------------------------------------------------------------------
// Startup

#[tokio::test]
async fn the_startup_check_runs_only_when_enabled() {
    // Off (default): no request at all.
    let env = env_with(false, "{}").await;
    env.publish(NEWER, &linux_files());
    for handle in crate::online::spawn_startup_checks(&env.state) {
        handle.await.unwrap();
    }
    assert_eq!(env.hits(), Vec::<String>::new());
    let (_, state) = env.call("GET", "/api/v1/updates", &Value::Null).await;
    assert_eq!(state["check"], Value::Null);

    // On: one request, result kept for the banner.
    let env = env_with(false, r#"{"online":{"update_check":true}}"#).await;
    env.publish(NEWER, &linux_files());
    for handle in crate::online::spawn_startup_checks(&env.state) {
        handle.await.unwrap();
    }
    assert_eq!(env.hits(), ["repos/o/r/releases/latest"]);
    let (_, state) = env.call("GET", "/api/v1/updates", &Value::Null).await;
    assert_eq!(state["check"]["status"], "available");

    // On, but the network fails: silent, nothing kept.
    let env = env_with(false, r#"{"online":{"update_check":true}}"#).await;
    env.reply(
        "repos/o/r/releases/latest",
        Reply::Status(StatusCode::INTERNAL_SERVER_ERROR),
    );
    for handle in crate::online::spawn_startup_checks(&env.state) {
        handle.await.unwrap();
    }
    let (_, state) = env.call("GET", "/api/v1/updates", &Value::Null).await;
    assert_eq!(state["check"], Value::Null);
}

// ---------------------------------------------------------------------------------------------
// Download

#[tokio::test]
async fn an_installer_is_downloaded_checked_and_saved() {
    let env = env().await;
    env.publish(NEWER, &linux_files());
    env.check().await;
    std::fs::create_dir_all(env.tmp.path().join("downloads")).unwrap();
    let dest = env.dest("NetSift-new.deb");
    // An existing file (overwrite confirmed in the save dialog) is replaced.
    std::fs::write(&dest, b"old").unwrap();

    let (status, body) = env.download(DEB, dest.to_str().unwrap()).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(body["phase"], "downloading");
    assert_eq!(body["asset"], DEB);
    let done = env.finished().await;
    assert_eq!(done["phase"], "done", "{done}");
    assert_eq!(done["path"], dest.to_str().unwrap());
    assert_eq!(done["received_bytes"], 9);
    assert_eq!(done["error"], Value::Null);
    assert_eq!(std::fs::read(&dest).unwrap(), b"deb-bytes");
    assert_eq!(env.downloads(), ["NetSift-new.deb"]);
    // Checksums first, then the installer.
    assert_eq!(
        env.hits()[1..],
        [Env::asset_path(SUMS_NAME), Env::asset_path(DEB)]
    );

    // Through the redirection of github.com to its asset storage (same policy).
    env.reply(
        &Env::asset_path(APPIMAGE),
        Reply::Redirect(format!("http://{}/storage/appimage", env.addr)),
    );
    env.reply("storage/appimage", Reply::Body(b"appimage-bytes".to_vec()));
    let dest = env.dest("a.AppImage");
    assert_eq!(
        env.download(APPIMAGE, dest.to_str().unwrap()).await.0,
        StatusCode::ACCEPTED
    );
    assert_eq!(env.finished().await["phase"], "done");
    assert_eq!(std::fs::read(&dest).unwrap(), b"appimage-bytes");
}

#[tokio::test]
async fn a_checksum_mismatch_leaves_no_file() {
    let env = env().await;
    env.publish(NEWER, &linux_files());
    env.check().await;
    // The served file differs from the published checksum.
    env.reply(&Env::asset_path(DEB), Reply::Body(b"tampered".to_vec()));
    std::fs::create_dir_all(env.tmp.path().join("downloads")).unwrap();
    let dest = env.dest("x.deb");
    assert_eq!(
        env.download(DEB, dest.to_str().unwrap()).await.0,
        StatusCode::ACCEPTED
    );
    let state = env.finished().await;
    assert_eq!(state["phase"], "failed");
    assert_eq!(state["error"], "checksum_mismatch");
    assert_eq!(state["path"], Value::Null);
    assert_eq!(env.downloads(), Vec::<String>::new());
}

#[tokio::test]
async fn a_missing_checksum_downloads_nothing() {
    let env = env().await;
    env.publish(NEWER, &linux_files());
    env.check().await;
    std::fs::create_dir_all(env.tmp.path().join("downloads")).unwrap();

    // SHA256SUMS.txt without the installer.
    env.reply(
        &Env::asset_path(SUMS_NAME),
        Reply::Body(format!("{}  other\n", "a".repeat(64)).into_bytes()),
    );
    let dest = env.dest("x.deb");
    env.download(DEB, dest.to_str().unwrap()).await;
    let state = env.finished().await;
    assert_eq!(state["error"], "checksum_missing");
    assert!(!env.hits().contains(&Env::asset_path(DEB)));

    // No SHA256SUMS.txt in the release at all.
    env.release_json(&json!({
        "tag_name": NEWER,
        "assets": [env.asset_json(DEB, 9)],
    }));
    env.check().await;
    env.download(DEB, dest.to_str().unwrap()).await;
    let state = env.finished().await;
    assert_eq!(state["error"], "checksum_missing");
    assert!(!env.hits().contains(&Env::asset_path(DEB)));
    assert_eq!(env.downloads(), Vec::<String>::new());
}

#[tokio::test]
async fn a_larger_file_than_announced_is_refused() {
    let env = env().await;
    let big = vec![7_u8; usize::try_from(SIZE_MARGIN).unwrap() + 100];
    env.publish(NEWER, &[(DEB, &big)]);
    // Announce a tiny size in the JSON.
    env.release_json(&json!({
        "tag_name": NEWER,
        "assets": [env.asset_json(DEB, 10), env.asset_json(SUMS_NAME, 100)],
    }));
    env.check().await;
    std::fs::create_dir_all(env.tmp.path().join("downloads")).unwrap();
    env.download(DEB, env.dest("x.deb").to_str().unwrap()).await;
    let state = env.finished().await;
    assert_eq!(state["error"], "too_large");
    assert_eq!(env.downloads(), Vec::<String>::new());
}

#[tokio::test]
async fn bad_destinations_and_assets_are_refused_before_any_request() {
    let env = env().await;
    env.publish(NEWER, &linux_files());
    env.check().await;
    let downloads = env.tmp.path().join("downloads");
    std::fs::create_dir_all(downloads.join("folder")).unwrap();
    let ok = env.dest("x.deb");
    let ok = ok.to_str().unwrap();
    let before = env.hits().len();

    for path in [
        "relative/x.deb".to_owned(),
        String::new(),
        format!("{}/../x.deb", downloads.display()),
        format!("{}/missing/x.deb", downloads.display()),
        downloads.join("folder").to_string_lossy().into_owned(),
        "/".to_owned(),
    ] {
        let (status, body) = env.download(DEB, &path).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{path}: {body}");
        assert_eq!(
            body["type"], "urn:netsift:problem:update-path-invalid",
            "{path}"
        );
    }
    // Not an installer of this platform, the checksum file, a URL, an unknown name.
    for asset in [
        SETUP,
        SUMS_NAME,
        "https://evil.example/x.deb",
        "NetSift_1.0.0_amd64.deb",
    ] {
        let (status, body) = env.download(asset, ok).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{asset}: {body}");
        assert_eq!(body["type"], "urn:netsift:problem:update-asset-unknown");
    }
    // Unknown fields (a URL given directly) are refused.
    let (status, _) = env
        .call(
            "POST",
            "/api/v1/updates/download",
            &json!({ "asset": DEB, "path": ok, "url": "https://evil.example" }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(env.hits().len(), before);
    assert_eq!(env.downloads(), ["folder"]);
    let (_, state) = env
        .call("GET", "/api/v1/updates/download", &Value::Null)
        .await;
    assert_eq!(state["phase"], "idle");
}

#[tokio::test]
async fn downloads_need_a_check_and_the_desktop_app() {
    let env = env().await;
    env.publish(NEWER, &linux_files());
    std::fs::create_dir_all(env.tmp.path().join("downloads")).unwrap();
    let dest = env.dest("x.deb");
    let (status, body) = env.download(DEB, dest.to_str().unwrap()).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["type"], "urn:netsift:problem:update-not-checked");

    let web = env_with(true, "{}").await;
    web.publish(NEWER, &linux_files());
    web.check().await;
    let (_, state) = web.call("GET", "/api/v1/updates", &Value::Null).await;
    assert_eq!(state["can_download"], false);
    let (status, body) = web.download(DEB, dest.to_str().unwrap()).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        body["type"],
        "urn:netsift:problem:update-download-unavailable"
    );
    assert_eq!(web.hits(), ["repos/o/r/releases/latest"]);
}

#[tokio::test]
async fn one_download_at_a_time_and_none_after_shutdown() {
    let env = env().await;
    env.publish(NEWER, &linux_files());
    env.check().await;
    std::fs::create_dir_all(env.tmp.path().join("downloads")).unwrap();
    let updates = env.state.online.get::<Updates>();
    let guard = DownloadGuard::begin(&updates).unwrap();
    let (status, body) = env.download(DEB, env.dest("x.deb").to_str().unwrap()).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["type"], "urn:netsift:problem:update-download-running");
    drop(guard);

    // A download cut by the shutdown is reported as interrupted, without a file.
    env.state.begin_shutdown();
    env.download(DEB, env.dest("x.deb").to_str().unwrap()).await;
    let state = env.finished().await;
    assert_eq!(state["phase"], "failed");
    assert_eq!(state["error"], "interrupted");
    assert_eq!(env.downloads(), Vec::<String>::new());
}

#[tokio::test]
async fn the_shutdown_waits_for_the_download_to_remove_its_temporary_file() {
    let env = env().await;
    let body = vec![1_u8; 1_000];
    env.publish(NEWER, &[(DEB, &body)]);
    env.check().await;
    // The installer starts, then stalls.
    env.reply(&Env::asset_path(DEB), Reply::Stall(vec![1_u8; 100], 1_000));
    std::fs::create_dir_all(env.tmp.path().join("downloads")).unwrap();
    env.download(DEB, env.dest("x.deb").to_str().unwrap()).await;
    tokio::time::timeout(Duration::from_secs(10), async {
        while !env.downloads().iter().any(|n| {
            std::path::Path::new(n)
                .extension()
                .is_some_and(|e| e == "part")
        }) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();

    env.state.begin_shutdown();
    assert!(env.state.wait_imports(Duration::from_secs(5)).await);
    // Removed before the server returns, not at some later point.
    assert_eq!(env.downloads(), Vec::<String>::new());
    let (_, state) = env
        .call("GET", "/api/v1/updates/download", &Value::Null)
        .await;
    assert_eq!(state["phase"], "failed");
    assert_eq!(state["error"], "interrupted");
}

// ---------------------------------------------------------------------------------------------
// Production values

#[test]
fn production_source_is_the_github_repository_of_the_workspace() {
    let source = Source::default();
    assert_eq!(REPOSITORY, "https://github.com/TiotBenjy/pcap-analyzer");
    assert_eq!(
        source.latest_url,
        "https://api.github.com/repos/TiotBenjy/pcap-analyzer/releases/latest"
    );
    assert_eq!(
        source.download_prefix(),
        "https://github.com/TiotBenjy/pcap-analyzer/releases/download/"
    );
    Outbound::new(source.check_policy).unwrap();
    Outbound::new(source.download_policy).unwrap();
}
