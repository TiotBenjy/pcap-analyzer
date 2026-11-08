use std::path::PathBuf;

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, HeaderValue, Request, StatusCode, header};
use netsift_engine::{CancelToken, IngestOptions, ingest};
use netsift_fixtures::images::{GALLERY_OBJECTS, gallery};
use netsift_fixtures::scenario::Scenario;
use netsift_fixtures::{Encoding, encode};
use netsift_store::{Catalog, OpenMode};
use serde_json::Value;
use tower::ServiceExt;

use super::*;
use crate::{ApiConfig, DEFAULT_MAX_IMPORTS, build};

const TOKEN: &str = "objects-token";

struct Env {
    _tmp: tempfile::TempDir,
    data: PathBuf,
    app: Router,
    id: String,
}

impl Env {
    /// API over one session holding the HTTP gallery.
    fn gallery() -> Self {
        let tmp = tempfile::TempDir::new().unwrap();
        let data = tmp.path().join("data");
        let captures = tmp.path().join("captures");
        std::fs::create_dir_all(&captures).unwrap();
        let mut sc = Scenario::new();
        gallery(&mut sc);
        let path = captures.join("gallery.pcap");
        std::fs::write(&path, encode(sc.packets(), &Encoding::pcap()).unwrap()).unwrap();
        let catalog = Catalog::open(&data).unwrap();
        let report = ingest(
            &catalog,
            &path,
            &IngestOptions::default(),
            &CancelToken::new(),
            &mut |_| {},
        )
        .unwrap();
        let config = ApiConfig {
            token: TOKEN.to_owned(),
            data_dir: data.clone(),
            captures_roots: vec![captures],
            read_only: true,
            cors_origins: vec![HeaderValue::from_static("tauri://localhost")],
            allow_any_path: false,
            max_imports: DEFAULT_MAX_IMPORTS,
            geoip_fallback_path: None,
        };
        let (app, _) = build(config, IngestOptions::default());
        Self {
            _tmp: tmp,
            data,
            app,
            id: report.session.to_string(),
        }
    }

    async fn raw(&self, path: &str) -> (StatusCode, HeaderMap, Vec<u8>) {
        let req = Request::get(format!("/api/v1/sessions/{}{path}", self.id))
            .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
            .body(Body::empty())
            .unwrap();
        let res = self.app.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let headers = res.headers().clone();
        let bytes = axum::body::to_bytes(res.into_body(), 1 << 24)
            .await
            .unwrap();
        (status, headers, bytes.to_vec())
    }

    async fn json(&self, path: &str) -> Value {
        let (status, _, body) = self.raw(path).await;
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(status, StatusCode::OK, "{path}: {json}");
        json
    }

    fn session(&self) -> Session {
        Catalog::open(&self.data)
            .unwrap()
            .open_session(&self.id.parse().unwrap(), OpenMode::ReadOnly)
            .unwrap()
    }

    /// The object first downloaded from `uri`.
    async fn by_uri(&self, uri: &str) -> Value {
        let q = uri.replace('?', "%3F").replace('=', "%3D");
        let page = self.json(&format!("/objects?q={q}")).await;
        page["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["uri"] == uri)
            .cloned()
            .unwrap_or_else(|| panic!("{uri} not found in {page}"))
    }
}

fn items(page: &Value) -> Vec<&Value> {
    page["items"].as_array().unwrap().iter().collect()
}

#[tokio::test]
async fn stats_and_filtered_pages() {
    let env = Env::gallery();
    let st = env.json("/objects/stats").await;
    assert_eq!(st["count"], GALLERY_OBJECTS);
    assert_eq!(
        st["occurrences"],
        GALLERY_OBJECTS + 1,
        "one image downloaded twice"
    );
    assert_eq!(st["types"][0]["mime"], "image/png");
    let hosts: Vec<&str> = st["hosts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| h["host"].as_str().unwrap())
        .collect();
    assert_eq!(hosts, ["images.example.test", "cdn.example.test"]);

    let all = env.json("/objects?limit=5").await;
    assert_eq!(items(&all).len(), 5);
    assert_eq!(all["total_estimate"], GALLERY_OBJECTS);
    let next = all["next_cursor"].as_str().unwrap();
    let rest = env.json(&format!("/objects?limit=100&cursor={next}")).await;
    assert_eq!(items(&rest).len(), GALLERY_OBJECTS - 5);

    let jpegs = env.json("/objects?type=image/jpeg").await;
    assert_eq!(jpegs["total_estimate"], 3);
    let cdn = env.json("/objects?host=cdn.example.test").await;
    assert_eq!(cdn["total_estimate"], 5);
    let search = env.json("/objects?q=GALLERY%2Fd").await;
    assert_eq!(search["total_estimate"], 2, "dusk.jpg and dunes.webp");
    let large = env
        .json("/objects?sort=size&order=desc&min_size=10000")
        .await;
    let sizes: Vec<u64> = items(&large)
        .iter()
        .map(|o| o["size"].as_u64().unwrap())
        .collect();
    assert!(sizes.windows(2).all(|w| w[0] >= w[1]), "{sizes:?}");
    assert!(sizes.iter().all(|s| *s >= 10_000));

    let first = &items(&all)[0];
    assert_eq!(first["uri"], "/gallery/harbour.jpg");
    assert_eq!(
        first["url"],
        "http://images.example.test/gallery/harbour.jpg"
    );
    assert_eq!(first["width"], 640);
    assert_eq!(first["thumb"], "ready");
    let name = first["file_name"].as_str().unwrap();
    assert_eq!(name.len(), "harbour-".len() + 12 + ".jpg".len(), "{name}");
    assert!(name.starts_with("harbour-"), "{name}");
    assert_eq!(&name[name.len() - 4..], ".jpg");

    // Hostile parameters.
    let long = "a".repeat(300);
    assert_eq!(
        env.raw(&format!("/objects?q={long}")).await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        env.raw("/objects?cursor=zz").await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        env.raw("/objects?sort=evil").await.0,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn the_original_is_a_sandboxed_attachment() {
    let env = Env::gallery();
    let svg = env.by_uri("/brand/logo.svg").await;
    assert_eq!(svg["thumb"], "none");
    let sha = svg["sha256"].as_str().unwrap();
    let (status, headers, body) = env.raw(&format!("/objects/{sha}")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.starts_with(b"<?xml"));
    assert_eq!(headers[header::CONTENT_TYPE], "application/octet-stream");
    assert_eq!(headers[header::CONTENT_SECURITY_POLICY], "sandbox");
    assert_eq!(headers[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
    assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    let disposition = headers[header::CONTENT_DISPOSITION].to_str().unwrap();
    assert!(
        disposition.starts_with("attachment; filename=\"logo-"),
        "{disposition}"
    );
    assert!(disposition.ends_with(".svg\""), "{disposition}");
    // An SVG has neither thumbnail nor preview: it is never rasterized.
    assert_eq!(
        env.raw(&format!("/objects/{sha}/thumb")).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        env.raw(&format!("/objects/{sha}/preview")).await.0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn thumbnails_and_previews_are_our_png() {
    let env = Env::gallery();
    let photo = env.by_uri("/gallery/panorama.png").await;
    let sha = photo["sha256"].as_str().unwrap().to_owned();
    let (status, headers, png) = env.raw(&format!("/objects/{sha}/thumb")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers[header::CONTENT_TYPE], "image/png");
    assert_eq!(headers[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
    let img = image::load_from_memory(&png).unwrap();
    assert_eq!((img.width(), img.height()), (320, 85));
    let (status, _, preview) = env.raw(&format!("/objects/{sha}/preview")).await;
    assert_eq!(status, StatusCode::OK);
    let img = image::load_from_memory(&preview).unwrap();
    assert_eq!((img.width(), img.height()), (900, 240), "never enlarged");

    // A removed thumbnail is rendered on demand.
    let session = env.session();
    std::fs::remove_file(session.thumb_path(&sha).unwrap()).unwrap();
    let (status, _, again) = env.raw(&format!("/objects/{sha}/thumb")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(again, png);

    // The truncated JPEG has no thumbnail, but can be downloaded.
    let cut = env.by_uri("/broken/cut.jpg").await;
    assert_eq!(cut["thumb"], "failed");
    let cut_sha = cut["sha256"].as_str().unwrap();
    assert_eq!(
        env.raw(&format!("/objects/{cut_sha}/thumb")).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        env.raw(&format!("/objects/{cut_sha}")).await.0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn invalid_digests_traversal_and_damaged_blobs_are_refused() {
    let env = Env::gallery();
    for bad in [
        "zz",
        "..%2F..%2Fsession.db",
        "%2E%2E",
        &"A".repeat(64),
        &"0".repeat(64),
        &format!("{}%2F..", "a".repeat(62)),
    ] {
        for suffix in ["", "/thumb", "/preview"] {
            let (status, _, _) = env.raw(&format!("/objects/{bad}{suffix}")).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{bad}{suffix}");
        }
    }
    // A blob cut short is never served (nor rendered).
    let photo = env.by_uri("/gallery/night.png").await;
    let sha = photo["sha256"].as_str().unwrap();
    let session = env.session();
    let blob = session.blob_path(sha).unwrap();
    let data = std::fs::read(&blob).unwrap();
    std::fs::write(&blob, &data[..data.len() / 2]).unwrap();
    std::fs::remove_file(session.thumb_path(sha).unwrap()).unwrap();
    assert_eq!(
        env.raw(&format!("/objects/{sha}")).await.0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        env.raw(&format!("/objects/{sha}/thumb")).await.0,
        StatusCode::CONFLICT
    );
    // Without the token: refused.
    let req = Request::get(format!("/api/v1/sessions/{}/objects/{sha}", env.id))
        .body(Body::empty())
        .unwrap();
    let res = env.app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[test]
fn file_names_are_sanitized() {
    let row = |uri: Option<&str>, mime: &str| ObjectRow {
        id: 1,
        sha256: "0123456789abcdef".repeat(4),
        size: 1,
        mime: mime.to_owned(),
        declared_type: None,
        width: None,
        height: None,
        thumb: "ready".to_owned(),
        occurrences: 1,
        first_ts: 0,
        last_ts: 0,
        flow_id: 1,
        seq: 0,
        client_ip: "10.0.0.1".to_owned(),
        server_ip: "10.0.0.2".to_owned(),
        server_port: 80,
        host: Some("h.test".to_owned()),
        uri: uri.map(ToOwned::to_owned),
    };
    assert_eq!(
        file_name(&row(Some("/a/photo.JPG?x=1"), "image/jpeg")),
        "photo-0123456789ab.jpg"
    );
    assert_eq!(
        file_name(&row(Some("/x/\"evil\";.html"), "image/png")),
        "evil-0123456789ab.png"
    );
    assert_eq!(
        file_name(&row(Some("/"), "image/gif")),
        "object-0123456789ab.gif"
    );
    assert_eq!(
        file_name(&row(None, "text/plain")),
        "object-0123456789ab.bin"
    );
    assert_eq!(
        url(&row(Some("/a.png"), "image/png")).as_deref(),
        Some("http://h.test/a.png")
    );
    assert_eq!(
        url(&row(Some("http://other.test/b.png"), "image/png")).as_deref(),
        Some("http://other.test/b.png")
    );
    assert_eq!(url(&row(Some("*"), "image/png")), None);
}
