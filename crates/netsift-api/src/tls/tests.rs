use std::path::PathBuf;

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, HeaderValue, Request, StatusCode, header};
use netsift_engine::{CancelToken, IngestOptions, ingest};
use netsift_fixtures::scenario::Scenario;
use netsift_fixtures::scenarios;
use netsift_fixtures::{Encoding, encode};
use netsift_store::{Catalog, OpenMode};
use serde_json::Value;
use tower::ServiceExt;

use super::*;
use crate::{ApiConfig, DEFAULT_MAX_IMPORTS, build};

const TOKEN: &str = "tls-token";

struct Env {
    _tmp: tempfile::TempDir,
    data: PathBuf,
    app: Router,
    id: String,
}

impl Env {
    /// API over one session holding the TLS showcase.
    fn showcase() -> Self {
        let tmp = tempfile::TempDir::new().unwrap();
        let data = tmp.path().join("data");
        let captures = tmp.path().join("captures");
        std::fs::create_dir_all(&captures).unwrap();
        let mut sc = Scenario::new();
        scenarios::tls_showcase(&mut sc);
        let path = captures.join("tls.pcap");
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

    async fn status(&self, path: &str) -> StatusCode {
        self.raw(path).await.0
    }

    fn blob_path(&self, sha256: &str) -> PathBuf {
        let catalog = Catalog::open(&self.data).unwrap();
        let session = catalog
            .open_session(&self.id.parse().unwrap(), OpenMode::ReadOnly)
            .unwrap();
        session.blob_path(sha256).unwrap()
    }

    fn blob(&self, sha256: &str) -> Vec<u8> {
        std::fs::read(self.blob_path(sha256)).unwrap()
    }
}

fn snis(page: &Value) -> Vec<String> {
    page["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["sni"].as_str().unwrap().to_owned())
        .collect()
}

#[tokio::test]
async fn stats_of_the_showcase() {
    let env = Env::showcase();
    let st = env.json("/tls/stats").await;
    assert_eq!(st["sessions"], 8);
    assert_eq!(st["weak_sessions"], 3);
    assert_eq!(st["cert_issue_sessions"], 3);
    assert_eq!(st["encrypted_cert_sessions"], 2);
    assert_eq!(st["certificates"], 5);
    assert_eq!(st["other_versions"], 0);
    assert_eq!(
        st["versions"],
        serde_json::json!([
            { "version": 771, "count": 3 },
            { "version": null, "count": 2 },
            { "version": 772, "count": 2 },
            { "version": 769, "count": 1 },
        ])
    );
    let suites = st["suites"].as_array().unwrap();
    assert_eq!(suites.len(), 6);
    let rc4 = suites.iter().find(|s| s["suite"] == 5).unwrap();
    assert_eq!(rc4["name"], "TLS_RSA_WITH_RC4_128_SHA");
    assert_eq!(rc4["weak"], "rc4");
    let cells: u64 = st["matrix"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["count"].as_u64().unwrap())
        .sum();
    assert_eq!(cells, 6, "every session with a ServerHello");
    assert_eq!(st["sni"].as_array().unwrap().len(), 8);
}

#[tokio::test]
async fn sessions_pages_and_filters() {
    let env = Env::showcase();
    let all = env.json("/tls/sessions?order=asc").await;
    assert_eq!(all["total_estimate"], 8);
    assert_eq!(
        snis(&all),
        vec![
            "www.example.test",
            "api.example.test",
            "shop.example.test",
            "legacy.example.test",
            "printer.example.test",
            "intranet.example.test",
            "blocked.example.test",
            "refused.example.test",
        ]
    );
    let first = &all["items"][0];
    assert_eq!(first["version"], 772);
    assert_eq!(first["cert_status"], "encrypted");
    assert_eq!(first["alpn_offered"], serde_json::json!(["h2", "http/1.1"]));
    assert!(first["ja4"].as_str().unwrap().starts_with("t13d0809h2_"));
    assert_eq!(first["ja3_hash"].as_str().unwrap().len(), 32);
    let legacy = &all["items"][3];
    assert_eq!(
        legacy["cert_issues"],
        serde_json::json!(["expired", "self_signed"])
    );
    assert_eq!(
        legacy["alert"],
        serde_json::json!({ "level": 2, "description": 42, "from": "client" })
    );
    assert_eq!(legacy["leaf_subject_cn"], "legacy.example.test");

    // Newest first by default, paginated.
    let p1 = env.json("/tls/sessions?limit=3").await;
    assert_eq!(snis(&p1)[0], "refused.example.test");
    let cursor = p1["next_cursor"].as_str().unwrap();
    let p2 = env
        .json(&format!("/tls/sessions?limit=3&cursor={cursor}"))
        .await;
    assert_eq!(snis(&p2)[0], "printer.example.test");

    let count = |v: &Value| v["items"].as_array().unwrap().len();
    assert_eq!(count(&env.json("/tls/sessions?weak=true").await), 3);
    assert_eq!(count(&env.json("/tls/sessions?version=771").await), 3);
    assert_eq!(count(&env.json("/tls/sessions?suite=4865").await), 1);
    assert_eq!(count(&env.json("/tls/sessions?cert_issues=true").await), 3);
    let q = env.json("/tls/sessions?q=SHOP").await;
    assert_eq!(snis(&q), vec!["shop.example.test"]);
    assert_eq!(q["total_estimate"], 1);
    assert_eq!(count(&env.json("/tls/sessions?q=192.168.1.20").await), 2);

    assert_eq!(
        env.status("/tls/sessions?version=abc").await,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        env.status(&format!("/tls/sessions?q={}", "x".repeat(300)))
            .await,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        env.status("/tls/sessions?cursor=zz").await,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn session_detail_with_hellos_and_chain() {
    let env = Env::showcase();
    let page = env.json("/tls/sessions?q=shop").await;
    let id = page["items"][0]["id"].as_str().unwrap().to_owned();
    let d = env.json(&format!("/tls/sessions/{id}")).await;
    assert_eq!(d["session"]["sni"], "shop.example.test");
    let ch = &d["client_hello"];
    assert_eq!(ch["legacy_version"], 771);
    assert_eq!(ch["random"].as_str().unwrap().len(), 64);
    let suites = ch["cipher_suites"].as_array().unwrap();
    assert_eq!(suites[0]["name"], "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256");
    assert_eq!(suites[0]["grease"], false);
    let exts: Vec<&str> = ch["extensions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["name"].as_str().unwrap())
        .collect();
    assert_eq!(exts[0], "server_name");
    assert!(exts.contains(&"application_layer_protocol_negotiation"));
    assert_eq!(ch["groups"][0]["name"], "x25519");
    assert_eq!(
        d["server_hello"]["cipher_suite"]["name"],
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    );
    let chain = d["certificates"].as_array().unwrap();
    assert_eq!(chain.len(), 2);
    assert_eq!(chain[0]["subject_cn"], "shop.example.test");
    assert_eq!(chain[0]["issuer_cn"], "NetSift Test CA");
    assert_eq!(
        chain[0]["san"],
        serde_json::json!(["DNS:shop.example.test"])
    );
    assert_eq!(chain[0]["expired"], false);
    assert_eq!(chain[0]["downloadable"], true);
    assert_eq!(chain[1]["is_ca"], true);

    // TLS 1.3 session: decoded GREASE values, no certificate.
    let page = env.json("/tls/sessions?q=www.example").await;
    let id = page["items"][0]["id"].as_str().unwrap().to_owned();
    let d = env.json(&format!("/tls/sessions/{id}")).await;
    assert_eq!(d["client_hello"]["cipher_suites"][0]["grease"], true);
    assert_eq!(
        d["client_hello"]["supported_versions"][1]["name"],
        "TLS 1.3"
    );
    assert_eq!(d["server_hello"]["selected_version"], 772);
    assert_eq!(d["certificates"], serde_json::json!([]));

    assert_eq!(env.status("/tls/sessions/42").await, StatusCode::NOT_FOUND);
    assert_eq!(env.status("/tls/sessions/x").await, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn certificates_and_downloads() {
    let env = Env::showcase();
    let list = env.json("/tls/certificates").await;
    assert_eq!(list["total_estimate"], 5);
    let items = list["items"].as_array().unwrap();
    let cns: Vec<&str> = items
        .iter()
        .map(|c| c["certificate"]["subject_cn"].as_str().unwrap())
        .collect();
    assert_eq!(
        cns,
        vec![
            "intranet.example.test",
            "legacy.example.test",
            "NetSift Test CA",
            "printer.example.test",
            "shop.example.test",
        ]
    );
    let legacy = &items[1];
    assert_eq!(legacy["certificate"]["expired"], true);
    assert_eq!(legacy["sessions"], 1);
    let problems = env.json("/tls/certificates?problems=true").await;
    assert_eq!(problems["total_estimate"], 3, "CA root not counted");
    let q = env.json("/tls/certificates?q=Test%20CA").await;
    assert_eq!(q["total_estimate"], 2, "the CA and the leaf it issued");

    let shop = &items[4]["certificate"];
    let sha = shop["sha256"].as_str().unwrap();
    let one = env.json(&format!("/tls/certificates/{sha}")).await;
    assert_eq!(one["subject_cn"], "shop.example.test");

    let (status, headers, der) = env.raw(&format!("/tls/certificates/{sha}/der")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(der, env.blob(sha));
    assert_eq!(headers[header::CONTENT_TYPE], "application/pkix-cert");
    assert_eq!(
        headers[header::CONTENT_DISPOSITION],
        format!(
            "attachment; filename=\"shop.example.test-{}.der\"",
            &sha[..12]
        )
    );
    assert_eq!(headers[header::CONTENT_SECURITY_POLICY], "sandbox");
    assert_eq!(headers[header::X_CONTENT_TYPE_OPTIONS], "nosniff");

    let (status, headers, pem) = env.raw(&format!("/tls/certificates/{sha}/pem")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers[header::CONTENT_SECURITY_POLICY], "sandbox");
    let pem = String::from_utf8(pem).unwrap();
    assert_eq!(pem, to_pem(&der));
    assert!(pem.starts_with("-----BEGIN CERTIFICATE-----\nMII"));

    // A truncated blob is refused, not served.
    std::fs::write(env.blob_path(sha), &der[..10]).unwrap();
    assert_eq!(
        env.status(&format!("/tls/certificates/{sha}/der")).await,
        StatusCode::CONFLICT
    );

    for bad in [
        "/tls/certificates/zz/der".to_owned(),
        "/tls/certificates/..%2F..%2Fsession.db/der".to_owned(),
        format!("/tls/certificates/{}/der", "0".repeat(64)),
        format!("/tls/certificates/{}", "A".repeat(64)),
    ] {
        assert_eq!(env.status(&bad).await, StatusCode::NOT_FOUND, "{bad}");
    }
}

#[test]
fn pem_and_file_names() {
    let pem = to_pem(b"hello");
    assert_eq!(
        pem,
        "-----BEGIN CERTIFICATE-----\naGVsbG8=\n-----END CERTIFICATE-----\n"
    );
    let long = to_pem(&[0xff; 100]);
    let lines: Vec<&str> = long.lines().collect();
    assert_eq!(lines[1].len(), 64);
    assert_eq!(lines.len(), 5);
    let mut row = CertificateRow {
        sha256: "ab".repeat(32),
        subject_cn: Some("a b/../\"c\".example".to_owned()),
        ..CertificateRow::default()
    };
    assert_eq!(
        file_name(&row, "der"),
        "a_b_..__c_.example-abababababab.der"
    );
    row.subject_cn = None;
    assert_eq!(file_name(&row, "pem"), "certificate-abababababab.pem");
    row.subject_cn = Some("..".to_owned());
    assert_eq!(file_name(&row, "pem"), "certificate-abababababab.pem");
}
