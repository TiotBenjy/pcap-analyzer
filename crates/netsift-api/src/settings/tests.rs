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
        "dismissed_notices": {},
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

#[tokio::test]
async fn valid_files_keep_their_valid_parts() {
    let mut notices = serde_json::Map::new();
    notices.insert("geoip".into(), json!("2026-11"));
    notices.insert("Bad Id".into(), json!("1"));
    notices.insert("update".into(), json!("v 1"));
    for i in 0..40 {
        notices.insert(format!("n{i:02}"), json!("k"));
    }
    let file = json!({
        "online": { "update_check": true },
        "dismissed_notices": notices,
        "future_field": 1,
    });
    let env = Env::new(false, Some(file.to_string().as_bytes()));
    let settings = env.state.settings.get();
    assert!(settings.online.update_check);
    assert!(!settings.online.geoip_check);
    let map = &settings.dismissed_notices;
    assert_eq!(map.len(), MAX_DISMISSED);
    assert_eq!(map.get("geoip").map(String::as_str), Some("2026-11"));
    assert!(!map.contains_key("Bad Id"));
    assert!(!map.contains_key("update"));
}

#[tokio::test]
async fn notices_stay_dismissed_until_their_key_changes() {
    let env = Env::new(false, None);
    let (status, json) = env.dismiss("geoip", "2026-11").await;
    assert_eq!(status, StatusCode::OK, "{json}");
    assert_eq!(json["dismissed_notices"], json!({ "geoip": "2026-11" }));
    let (_, json) = env.dismiss("update", "0.2.0").await;
    let (_, json2) = env.dismiss("geoip", "2026-12").await;
    assert_eq!(json["dismissed_notices"]["update"], "0.2.0");
    assert_eq!(
        json2["dismissed_notices"],
        json!({ "geoip": "2026-12", "update": "0.2.0" })
    );
    assert_eq!(env.reloaded().dismissed_notices.len(), 2);
    // Dismissals and online settings do not overwrite each other.
    env.put(&json!({ "online": { "geoip_check": true } })).await;
    assert_eq!(env.file()["dismissed_notices"]["geoip"], "2026-12");
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

    // Bounded.
    for i in 0..MAX_DISMISSED - 2 {
        assert_eq!(env.dismiss(&format!("n{i}"), "1").await.0, StatusCode::OK);
    }
    assert_eq!(
        env.dismiss("one-more", "1").await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(env.dismiss("geoip", "2027-01").await.0, StatusCode::OK);
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
    assert!(!data_dir.join(TEMP_NAME).exists());
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
