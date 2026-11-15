//! Settings file and routes.

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderValue, Request, StatusCode, header};
use netsift_engine::IngestOptions;
use serde_json::{Value, json};
use tower::ServiceExt;

use super::*;
use crate::{ApiConfig, DEFAULT_MAX_IMPORTS, build};

const TOKEN: &str = "settings-token";

struct Env {
    tmp: tempfile::TempDir,
    app: Router,
    state: Arc<AppState>,
}

impl Env {
    /// Server whose data directory holds `file` as `settings.json` (none if `None`).
    fn new(read_only: bool, file: Option<&[u8]>) -> Self {
        let tmp = tempfile::TempDir::new().unwrap();
        let data_dir = tmp.path().join("data");
        if let Some(bytes) = file {
            std::fs::create_dir_all(&data_dir).unwrap();
            std::fs::write(data_dir.join(FILE_NAME), bytes).unwrap();
        }
        let (app, state) = build(config(data_dir, read_only), IngestOptions::default());
        Self { tmp, app, state }
    }

    fn path(&self) -> PathBuf {
        self.tmp.path().join("data").join(FILE_NAME)
    }

    fn file(&self) -> Value {
        serde_json::from_slice(&std::fs::read(self.path()).unwrap()).unwrap()
    }

    /// Settings a new server would read from the data directory.
    fn reloaded(&self) -> Settings {
        SettingsStore::load(&self.tmp.path().join("data")).get()
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

    async fn get(&self) -> Value {
        let (status, json) = self.call("GET", "/api/v1/settings", &Value::Null).await;
        assert_eq!(status, StatusCode::OK, "{json}");
        json
    }

    async fn put(&self, body: &Value) -> (StatusCode, Value) {
        self.call("PUT", "/api/v1/settings", body).await
    }

    async fn dismiss(&self, id: &str, key: &str) -> (StatusCode, Value) {
        self.call(
            "PUT",
            &format!("/api/v1/settings/notices/{id}"),
            &json!({ "key": key }),
        )
        .await
    }
}

fn config(data_dir: PathBuf, read_only: bool) -> ApiConfig {
    ApiConfig {
        token: TOKEN.to_owned(),
        data_dir,
        captures_roots: Vec::new(),
        read_only,
        cors_origins: vec![HeaderValue::from_static("tauri://localhost")],
        allow_any_path: false,
        max_imports: DEFAULT_MAX_IMPORTS,
        geoip_fallback_path: None,
    }
}

fn defaults() -> Value {
    json!({
        "online": { "geoip_check": false, "update_check": false },
        "dismissed_notices": [],
    })
}

#[tokio::test]
async fn online_settings_are_off_by_default_and_nothing_is_written() {
    let env = Env::new(false, None);
    assert_eq!(env.get().await, defaults());
    assert_eq!(env.state.settings.get(), Settings::default());
    assert!(!env.path().exists());
    // An unchanged value writes nothing either.
    let (status, json) = env
        .put(&json!({ "online": { "geoip_check": false } }))
        .await;
    assert_eq!(status, StatusCode::OK, "{json}");
    assert!(!env.path().exists());
}

#[tokio::test]
async fn changes_are_partial_persisted_and_read_back() {
    let env = Env::new(false, None);
    let (status, json) = env
        .put(&json!({ "online": { "update_check": true } }))
        .await;
    assert_eq!(status, StatusCode::OK, "{json}");
    assert_eq!(
        json["online"],
        json!({ "geoip_check": false, "update_check": true })
    );

    let (_, json) = env.put(&json!({ "online": { "geoip_check": true } })).await;
    assert_eq!(
        json["online"],
        json!({ "geoip_check": true, "update_check": true })
    );
    let (_, json) = env.put(&json!({})).await;
    assert_eq!(
        json["online"],
        json!({ "geoip_check": true, "update_check": true })
    );

    assert_eq!(env.file(), env.get().await);
    assert!(env.reloaded().online.geoip_check);
    assert!(env.reloaded().online.update_check);
    // Atomic write: no temporary file left.
    let names: Vec<_> = std::fs::read_dir(env.path().parent().unwrap())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("settings"))
        .collect();
    assert_eq!(names, [FILE_NAME]);
}

#[tokio::test]
async fn malformed_changes_are_refused() {
    let env = Env::new(false, None);
    for body in [
        json!({ "online": { "geoip_check": "yes" } }),
        json!({ "online": { "unknown": true } }),
        json!({ "theme": "dark" }),
        json!(1),
    ] {
        let (status, json) = env.put(&body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}: {json}");
        assert_eq!(json["type"], "urn:netsift:problem:bad-request");
    }
    assert!(!env.path().exists());
}

#[tokio::test]
async fn unusable_files_fall_back_to_the_defaults_and_are_replaced() {
    let oversized = format!(
        r#"{{"online":{{"geoip_check":true}},"pad":"{}"}}"#,
        "x".repeat(70_000)
    );
    let files: [&[u8]; 5] = [
        b"{not json",
        b"",
        br#"{"online":{"geoip_check":"yes"}}"#,
        b"[1,2]",
        oversized.as_bytes(),
    ];
    for file in files {
        let env = Env::new(false, Some(file));
        assert_eq!(env.get().await, defaults());
        let (status, _) = env
            .put(&json!({ "online": { "update_check": true } }))
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            env.file()["online"],
            json!({ "geoip_check": false, "update_check": true })
        );
    }
}

/// `[id, key]` pairs of a dismissal list, in order.
fn pairs(list: &Value) -> Vec<(String, String)> {
    list.as_array()
        .unwrap()
        .iter()
        .map(|n| {
            (
                n["id"].as_str().unwrap().to_owned(),
                n["key"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

fn owned(list: &[(&str, &str)]) -> Vec<(String, String)> {
    list.iter()
        .map(|(a, b)| ((*a).to_owned(), (*b).to_owned()))
        .collect()
}

#[tokio::test]
async fn valid_files_keep_their_valid_parts() {
    let mut notices = vec![
        json!({ "id": "geoip", "key": "2026-10" }),
        json!({ "id": "Bad Id", "key": "1" }),
        json!({ "id": "update", "key": "v 1" }),
    ];
    for i in 0..40 {
        notices.push(json!({ "id": format!("n{i:02}"), "key": "k" }));
    }
    // Repeated id: the last entry wins.
    notices.push(json!({ "id": "geoip", "key": "2026-11" }));
    let file = json!({
        "online": { "update_check": true },
        "dismissed_notices": notices,
        "future_field": 1,
    });
    let env = Env::new(false, Some(file.to_string().as_bytes()));
    let settings = env.state.settings.get();
    assert!(settings.online.update_check);
    assert!(!settings.online.geoip_check);
    let list = &settings.dismissed_notices;
    assert_eq!(list.len(), MAX_DISMISSED);
    // The most recent ones are kept, in order.
    let last = list.last().unwrap();
    assert_eq!((last.id.as_str(), last.key.as_str()), ("geoip", "2026-11"));
    assert_eq!(list.first().unwrap().id, "n09");
    assert_eq!(list.iter().filter(|n| n.id == "geoip").count(), 1);
    assert!(!list.iter().any(|n| n.id == "Bad Id" || n.id == "update"));
}

#[tokio::test]
async fn notices_stay_dismissed_until_their_key_changes() {
    let env = Env::new(false, None);
    let (status, json) = env.dismiss("geoip", "2026-11").await;
    assert_eq!(status, StatusCode::OK, "{json}");
    assert_eq!(
        pairs(&json["dismissed_notices"]),
        owned(&[("geoip", "2026-11")])
    );
    env.dismiss("update", "0.2.0").await;
    let (_, json) = env.dismiss("geoip", "2026-12").await;
    // A new dismissal moves the notice to the end (most recent).
    assert_eq!(
        pairs(&json["dismissed_notices"]),
        owned(&[("update", "0.2.0"), ("geoip", "2026-12")])
    );
    assert_eq!(env.reloaded().dismissed_notices.len(), 2);
    // Dismissals and online settings do not overwrite each other.
    env.put(&json!({ "online": { "geoip_check": true } })).await;
    assert_eq!(
        pairs(&env.file()["dismissed_notices"]),
        owned(&[("update", "0.2.0"), ("geoip", "2026-12")])
    );
    assert_eq!(env.file()["online"]["geoip_check"], true);

    for (id, key) in [
        ("Geoip", "1"),
        ("-x", "1"),
        ("a%2Fb", "1"),
        ("geoip", ""),
        ("geoip", "a b"),
        ("geoip", "<script>"),
    ] {
        let (status, json) = env.dismiss(id, key).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{id} {key}: {json}");
    }
    let long = "k".repeat(MAX_KEY_LEN + 1);
    assert_eq!(env.dismiss("geoip", &long).await.0, StatusCode::BAD_REQUEST);
    let (status, _) = env
        .call(
            "PUT",
            "/api/v1/settings/notices/geoip",
            &json!({ "key": "1", "extra": 1 }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn the_least_recently_dismissed_notice_is_forgotten_past_the_bound() {
    let env = Env::new(false, None);
    for i in 0..MAX_DISMISSED {
        assert_eq!(env.dismiss(&format!("n{i}"), "1").await.0, StatusCode::OK);
    }
    // Dismissed again: becomes the most recent, so n1 is now the oldest.
    env.dismiss("n0", "2").await;
    let (status, json) = env.dismiss("one-more", "1").await;
    assert_eq!(status, StatusCode::OK, "{json}");
    let list = pairs(&json["dismissed_notices"]);
    assert_eq!(list.len(), MAX_DISMISSED);
    assert!(!list.iter().any(|(id, _)| id == "n1"));
    assert_eq!(list.first().unwrap().0, "n2");
    assert_eq!(
        list[MAX_DISMISSED - 2..],
        owned(&[("n0", "2"), ("one-more", "1")])
    );
    assert_eq!(env.reloaded().dismissed_notices.len(), MAX_DISMISSED);
}

#[tokio::test]
async fn settings_routes_require_the_token() {
    let env = Env::new(false, None);
    for (method, uri) in [
        ("GET", "/api/v1/settings"),
        ("PUT", "/api/v1/settings"),
        ("PUT", "/api/v1/settings/notices/geoip"),
    ] {
        let req = Request::builder()
            .method(method)
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"key":"1"}"#))
            .unwrap();
        let res = env.app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "{method} {uri}");
    }
    assert!(!env.path().exists());
}

#[tokio::test]
async fn read_only_servers_report_but_never_change_the_settings() {
    let env = Env::new(true, Some(br#"{"online":{"geoip_check":true}}"#));
    assert_eq!(env.get().await["online"]["geoip_check"], true);
    let (status, json) = env
        .put(&json!({ "online": { "geoip_check": false } }))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{json}");
    assert_eq!(json["type"], "urn:netsift:problem:read-only");
    assert_eq!(env.dismiss("geoip", "1").await.0, StatusCode::FORBIDDEN);
    assert_eq!(env.file()["online"]["geoip_check"], true);
}

#[tokio::test]
async fn a_failed_write_changes_nothing() {
    // A directory where the file should be: unreadable (defaults) and not replaceable.
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(data_dir.join(FILE_NAME)).unwrap();
    let (app, state) = build(config(data_dir.clone(), false), IngestOptions::default());
    let env = Env { tmp, app, state };
    assert_eq!(env.get().await, defaults());
    let (status, json) = env.put(&json!({ "online": { "geoip_check": true } })).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{json}");
    assert_eq!(env.get().await, defaults());
    assert_eq!(temp_files(&data_dir), Vec::<String>::new());
}

/// Temporary files of the settings left in `dir`.
fn temp_files(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with(FILE_NAME) && Path::new(n).extension() == Some("tmp".as_ref()))
        .collect()
}

#[tokio::test]
async fn malformed_dismissed_notices_only_lose_themselves() {
    let file = json!({
        "online": { "geoip_check": true },
        "dismissed_notices": [
            { "id": "x" },
            1,
            "geoip",
            null,
            { "id": 3, "key": "1" },
            { "id": "update", "key": "0.2.0", "extra": true },
            [],
            { "id": "geoip", "key": "2026-11" },
        ],
    });
    let env = Env::new(false, Some(file.to_string().as_bytes()));
    let settings = env.state.settings.get();
    assert!(settings.online.geoip_check);
    assert_eq!(
        settings
            .dismissed_notices
            .iter()
            .map(|n| (n.id.clone(), n.key.clone()))
            .collect::<Vec<_>>(),
        owned(&[("update", "0.2.0"), ("geoip", "2026-11")])
    );

    // A list that is not an array: no dismissal, online settings kept.
    for list in [
        json!(1),
        json!("geoip"),
        json!({ "id": "geoip", "key": "1" }),
    ] {
        let file = json!({ "online": { "update_check": true }, "dismissed_notices": list });
        let env = Env::new(false, Some(file.to_string().as_bytes()));
        let settings = env.state.settings.get();
        assert!(settings.online.update_check, "{list}");
        assert!(settings.dismissed_notices.is_empty(), "{list}");
    }
}

#[test]
fn temporary_files_have_unique_names() {
    let dir = Path::new("/data");
    let a = temp_path(dir);
    let b = temp_path(dir);
    assert_ne!(a, b);
    for p in [&a, &b] {
        let name = p.file_name().unwrap().to_str().unwrap();
        assert!(
            name.starts_with(&format!("{FILE_NAME}.{}-", std::process::id())),
            "{name}"
        );
        assert_eq!(p.extension(), Some("tmp".as_ref()), "{name}");
        assert_eq!(p.parent(), Some(dir));
    }
}

/// A link planted where the old fixed temporary name was is neither followed nor truncated.
#[cfg(unix)]
#[tokio::test]
async fn writes_never_go_through_a_planted_link() {
    let env = Env::new(false, None);
    let dir = env.tmp.path().join("data");
    std::fs::create_dir_all(&dir).unwrap();
    let victim = env.tmp.path().join("victim");
    std::fs::write(&victim, b"keep me").unwrap();
    std::os::unix::fs::symlink(&victim, dir.join("settings.json.tmp")).unwrap();

    let (status, json) = env.put(&json!({ "online": { "geoip_check": true } })).await;
    assert_eq!(status, StatusCode::OK, "{json}");
    assert_eq!(std::fs::read(&victim).unwrap(), b"keep me");
    assert!(env.reloaded().online.geoip_check);
    // The planted link stays; no temporary file of ours is left.
    assert!(dir.join("settings.json.tmp").is_symlink());
    assert_eq!(temp_files(&dir), ["settings.json.tmp"]);
}

#[tokio::test]
async fn the_desktop_webview_may_send_put() {
    let env = Env::new(false, None);
    let req = Request::builder()
        .method("OPTIONS")
        .uri("/api/v1/settings")
        .header(header::ORIGIN, "tauri://localhost")
        .header(header::ACCESS_CONTROL_REQUEST_METHOD, "PUT")
        .header(
            header::ACCESS_CONTROL_REQUEST_HEADERS,
            "authorization,content-type",
        )
        .body(Body::empty())
        .unwrap();
    let res = env.app.clone().oneshot(req).await.unwrap();
    let methods = res.headers()[header::ACCESS_CONTROL_ALLOW_METHODS]
        .to_str()
        .unwrap()
        .to_owned();
    assert!(methods.contains("PUT"), "{methods}");
}

#[test]
fn ids_and_keys_are_restricted() {
    for id in ["geoip", "update", "geoip-prompt", "a.b_c", "0"] {
        assert!(valid_id(id), "{id}");
    }
    for id in ["", "Geoip", "-a", "a b", "a/b", &"a".repeat(MAX_ID_LEN + 1)] {
        assert!(!valid_id(id), "{id}");
    }
    for key in [
        "2026-11",
        "0.2.0",
        "v1.0.0-rc.1+build",
        "2026-11-01T00:00:00Z",
    ] {
        assert!(valid_key(key), "{key}");
    }
    for key in ["", "a b", "é", "a/b"] {
        assert!(!valid_key(key), "{key}");
    }
}
